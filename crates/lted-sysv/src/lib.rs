//! Minimal audited System V IPC adapter for the stock `liblted.so` ABI.
//!
//! All `unsafe` code in the replacement is intentionally concentrated here.
//! The public API owns the shared-memory attachment and semaphore set through
//! RAII and exposes only bounds-checked byte copies plus the recovered daemon
//! semaphore operations.

use std::{ffi::CString, io, os::unix::ffi::OsStrExt, path::Path, ptr};

use lted_proto::SHARED_CONTEXT_LEN;

const IPC_CREATE_EXCLUSIVE_MODE: libc::c_int = libc::IPC_CREAT | libc::IPC_EXCL | 0o666;
const SEMAPHORE_COUNT: libc::c_int = 2;

#[repr(C)]
union Semun {
    val: libc::c_int,
    buf: *mut libc::semid_ds,
    array: *mut libc::c_ushort,
}

/// One OEM per-client shared context plus its two-semaphore handoff set.
pub struct ClientContext {
    shmid: libc::c_int,
    semid: libc::c_int,
    address: usize,
}

impl ClientContext {
    /// Create exactly the resources expected by stock `liblted.so` after the
    /// `0x8101` open response.
    ///
    /// Both resources use `ftok(seed_path, client_id)`. The shared segment is
    /// `0x9780` bytes and both objects are created with `IPC_CREAT|IPC_EXCL|0666`.
    /// The two semaphore values are initialized to `[0, 0]`.
    ///
    /// # Errors
    /// Returns an OS error from `ftok`, `shmget`, `semget`, `shmat`, or
    /// `semctl(SETALL)`. Partially-created resources are removed before return.
    pub fn create(seed_path: &Path, client_id: u8) -> io::Result<Self> {
        let key = key_for(seed_path, client_id)?;
        let shared_memory_id =
            unsafe { libc::shmget(key, SHARED_CONTEXT_LEN, IPC_CREATE_EXCLUSIVE_MODE) };
        if shared_memory_id < 0 {
            return Err(io::Error::last_os_error());
        }

        let semaphore_id = unsafe { libc::semget(key, SEMAPHORE_COUNT, IPC_CREATE_EXCLUSIVE_MODE) };
        if semaphore_id < 0 {
            let error = io::Error::last_os_error();
            remove_shm(shared_memory_id);
            return Err(error);
        }

        let address = unsafe { libc::shmat(shared_memory_id, ptr::null(), 0) };
        if address == (-1_isize) as *mut libc::c_void {
            let error = io::Error::last_os_error();
            remove_sem(semaphore_id);
            remove_shm(shared_memory_id);
            return Err(error);
        }

        let context = Self {
            shmid: shared_memory_id,
            semid: semaphore_id,
            address: address as usize,
        };
        if let Err(error) = context.set_all_zero() {
            drop(context);
            return Err(error);
        }
        Ok(context)
    }

    #[must_use]
    pub const fn shmid(&self) -> libc::c_int {
        self.shmid
    }

    #[must_use]
    pub const fn semid(&self) -> libc::c_int {
        self.semid
    }

    /// OEM server-side request entry operation:
    /// `wait sem0 == 0; sem0 += 1` atomically.
    ///
    /// # Errors
    /// Returns the OS error from `semop`.
    pub fn daemon_acquire(&self) -> io::Result<()> {
        let mut ops = [sembuf(0, 0, 0), sembuf(0, 1, 0)];
        self.semop(&mut ops)
    }

    /// OEM server-side request completion operation:
    /// `sem0 -= 1; sem1 += 1` atomically.
    ///
    /// # Errors
    /// Returns the OS error from `semop`.
    pub fn daemon_release(&self) -> io::Result<()> {
        let mut ops = [sembuf(0, -1, 0), sembuf(1, 1, 0)];
        self.semop(&mut ops)
    }

    /// Copy bytes into the shared context without exposing a Rust reference to
    /// memory that is also mapped by the stock client process.
    ///
    /// The caller must obey the recovered semaphore protocol when the client is
    /// live.
    ///
    /// # Errors
    /// Returns `InvalidInput` when `offset + data.len()` exceeds `0x9780`.
    pub fn write(&mut self, offset: usize, data: &[u8]) -> io::Result<()> {
        let range = checked_range(offset, data.len())?;
        unsafe {
            ptr::copy_nonoverlapping(
                data.as_ptr(),
                (self.address as *mut u8).add(range.start),
                data.len(),
            );
        }
        Ok(())
    }

    /// Copy bytes out of the shared context without exposing a Rust reference
    /// to the shared mapping.
    ///
    /// The caller must obey the recovered semaphore protocol when the client is
    /// live.
    ///
    /// # Errors
    /// Returns `InvalidInput` when `offset + output.len()` exceeds `0x9780`.
    pub fn read(&self, offset: usize, output: &mut [u8]) -> io::Result<()> {
        let range = checked_range(offset, output.len())?;
        unsafe {
            ptr::copy_nonoverlapping(
                (self.address as *const u8).add(range.start),
                output.as_mut_ptr(),
                output.len(),
            );
        }
        Ok(())
    }

    /// Write the big-endian 32-bit `lte_api_ret`/similar scalar representation
    /// used by the ARM BE8 stock ABI.
    ///
    /// # Errors
    /// Returns the same bounds error as [`Self::write`].
    pub fn write_i32_be(&mut self, offset: usize, value: i32) -> io::Result<()> {
        self.write(offset, &value.to_be_bytes())
    }

    fn set_all_zero(&self) -> io::Result<()> {
        let mut values = [0_u16; 2];
        let arg = Semun {
            array: values.as_mut_ptr(),
        };
        let result = unsafe { libc::semctl(self.semid, 0, libc::SETALL, arg) };
        cvt_zero(result)
    }

    fn semop(&self, ops: &mut [libc::sembuf]) -> io::Result<()> {
        let result = unsafe { libc::semop(self.semid, ops.as_mut_ptr(), ops.len()) };
        cvt_zero(result)
    }
}

impl Drop for ClientContext {
    fn drop(&mut self) {
        unsafe {
            libc::shmdt(self.address as *const libc::c_void);
        }
        remove_shm(self.shmid);
        remove_sem(self.semid);
    }
}

/// Derive the exact System V key used by both sides of the OEM client ABI.
///
/// # Errors
/// Returns `InvalidInput` for a pathname containing NUL, or the OS error from
/// `ftok`.
pub fn key_for(seed_path: &Path, client_id: u8) -> io::Result<libc::key_t> {
    let path = CString::new(seed_path.as_os_str().as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "System V ftok seed path contains NUL",
        )
    })?;
    let key = unsafe { libc::ftok(path.as_ptr(), libc::c_int::from(client_id)) };
    if key == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(key)
    }
}

fn checked_range(offset: usize, len: usize) -> io::Result<std::ops::Range<usize>> {
    let Some(end) = offset.checked_add(len) else {
        return Err(bounds_error());
    };
    if end > SHARED_CONTEXT_LEN {
        return Err(bounds_error());
    }
    Ok(offset..end)
}

fn bounds_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "shared-context access exceeds recovered 0x9780-byte ABI",
    )
}

const fn sembuf(
    sem_num: libc::c_ushort,
    sem_op: libc::c_short,
    sem_flg: libc::c_short,
) -> libc::sembuf {
    libc::sembuf {
        sem_num,
        sem_op,
        sem_flg,
    }
}

fn cvt_zero(result: libc::c_int) -> io::Result<()> {
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn remove_shm(shmid: libc::c_int) {
    unsafe {
        libc::shmctl(shmid, libc::IPC_RMID, ptr::null_mut());
    }
}

fn remove_sem(semid: libc::c_int) {
    unsafe {
        libc::semctl(semid, 0, libc::IPC_RMID);
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs::{self, File},
        path::PathBuf,
        process,
        sync::atomic::{AtomicU64, Ordering},
    };

    use lted_proto::SHARED_CONTEXT_LEN;

    use super::{ClientContext, Semun, key_for, sembuf};

    const SEM_UNDO_FLAG: libc::c_short = 0x0800;

    static NEXT_SEED: AtomicU64 = AtomicU64::new(0);

    struct Seed(PathBuf);

    impl Seed {
        fn new() -> Self {
            let suffix = NEXT_SEED.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("wf830-lted-sysv-{}-{suffix}", process::id()));
            let _ = fs::remove_file(&path);
            File::create(&path).unwrap_or_else(|_| std::process::abort());
            Self(path)
        }
    }

    impl Drop for Seed {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    fn sem_value(semid: libc::c_int, number: libc::c_int) -> libc::c_int {
        let value = unsafe { libc::semctl(semid, number, libc::GETVAL) };
        if value < 0 {
            std::process::abort();
        }
        value
    }

    fn client_wait(context: &ClientContext) {
        let mut ops = [sembuf(1, -1, 0), sembuf(0, 1, SEM_UNDO_FLAG)];
        let result = unsafe { libc::semop(context.semid(), ops.as_mut_ptr(), ops.len()) };
        if result != 0 {
            std::process::abort();
        }
    }

    fn client_done(context: &ClientContext) {
        let mut ops = [sembuf(0, -1, SEM_UNDO_FLAG)];
        let result = unsafe { libc::semop(context.semid(), ops.as_mut_ptr(), ops.len()) };
        if result != 0 {
            std::process::abort();
        }
    }

    #[test]
    fn resources_are_discoverable_by_the_stock_lookup_flags() {
        let seed = Seed::new();
        let context = ClientContext::create(&seed.0, 7).unwrap_or_else(|_| std::process::abort());
        let key = key_for(&seed.0, 7).unwrap_or_else(|_| std::process::abort());
        let shared_memory_lookup = unsafe { libc::shmget(key, SHARED_CONTEXT_LEN, 0) };
        let semaphore_lookup = unsafe { libc::semget(key, 2, 0o666) };
        assert_eq!(shared_memory_lookup, context.shmid());
        assert_eq!(semaphore_lookup, context.semid());
    }

    #[test]
    fn recovered_two_semaphore_handoff_returns_to_zero_zero() {
        let seed = Seed::new();
        let context = ClientContext::create(&seed.0, 8).unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            (sem_value(context.semid(), 0), sem_value(context.semid(), 1)),
            (0, 0)
        );

        context
            .daemon_acquire()
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            (sem_value(context.semid(), 0), sem_value(context.semid(), 1)),
            (1, 0)
        );
        context
            .daemon_release()
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            (sem_value(context.semid(), 0), sem_value(context.semid(), 1)),
            (0, 1)
        );

        client_wait(&context);
        assert_eq!(
            (sem_value(context.semid(), 0), sem_value(context.semid(), 1)),
            (1, 0)
        );
        client_done(&context);
        assert_eq!(
            (sem_value(context.semid(), 0), sem_value(context.semid(), 1)),
            (0, 0)
        );
    }

    #[test]
    fn byte_access_is_bounds_checked_and_be_scalar_is_explicit() {
        let seed = Seed::new();
        let mut context =
            ClientContext::create(&seed.0, 9).unwrap_or_else(|_| std::process::abort());
        context
            .write(4, &[1, 2, 3])
            .unwrap_or_else(|_| std::process::abort());
        context
            .write_i32_be(0x524, -2)
            .unwrap_or_else(|_| std::process::abort());

        let mut bytes = [0_u8; 3];
        context
            .read(4, &mut bytes)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(bytes, [1, 2, 3]);
        let mut scalar = [0_u8; 4];
        context
            .read(0x524, &mut scalar)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(scalar, (-2_i32).to_be_bytes());

        assert!(context.write(SHARED_CONTEXT_LEN, &[1]).is_err());
        assert!(
            context
                .read(SHARED_CONTEXT_LEN - 1, &mut [0_u8; 2])
                .is_err()
        );
    }

    #[test]
    fn setall_union_layout_accepts_the_kernel_abi() {
        let mut values = [0_u16; 2];
        let _arg = Semun {
            array: values.as_mut_ptr(),
        };
    }
}
