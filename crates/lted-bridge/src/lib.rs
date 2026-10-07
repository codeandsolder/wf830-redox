//! Translation layer from the recovered stock `lted` client ABI to typed GCT
//! modem requests.
//!
//! Synchronous SDK-call completion and asynchronous modem callbacks are two
//! separate paths in the OEM design. This crate currently implements the
//! synchronous half for the zero-parameter P0 calls whose wire mapping is fully
//! proven.

use std::{io, io::Write};

use gct_lapi::EmptyRequest;
use gct_runtime::{Modem, ModemCommand, SendCommandError};
use lted_compat::Server;
use lted_proto::{SdkApiRequest, SdkCommand};

/// Offset of `lte_api_ret` inside the recovered 38,784-byte
/// `lted_client_context`.
pub const LTE_API_RET_OFFSET: usize = 0x524;

#[derive(Debug)]
pub enum HandleError {
    Ipc(io::Error),
    UnsupportedCommand(u16),
    UnexpectedParameters { command: u16, actual: usize },
    Send(SendCommandError),
}

impl std::fmt::Display for HandleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ipc(error) => write!(f, "lted IPC error: {error}"),
            Self::UnsupportedCommand(command) => {
                write!(f, "unsupported recovered lted SDK command {command}")
            }
            Self::UnexpectedParameters { command, actual } => write!(
                f,
                "lted SDK command {command} expected zero parameters, got {actual} bytes"
            ),
            Self::Send(error) => write!(f, "modem send failed: {error:?}"),
        }
    }
}

impl std::error::Error for HandleError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Ipc(error) => Some(error),
            Self::UnsupportedCommand(_) | Self::UnexpectedParameters { .. } | Self::Send(_) => None,
        }
    }
}

impl From<io::Error> for HandleError {
    fn from(value: io::Error) -> Self {
        Self::Ipc(value)
    }
}

impl From<SendCommandError> for HandleError {
    fn from(value: SendCommandError) -> Self {
        Self::Send(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandledCall {
    pub command: SdkCommand,
    pub device_id: u32,
    pub bytes_written: usize,
}

/// Execute one stock SDK request and complete the OEM semaphore/shm synchronous
/// return path.
///
/// The recovered OEM sequence is preserved: acquire the daemon semaphore,
/// clear `lte_api_ret`, attempt the LAPI send, store `0` on success or `1` on
/// failure, then release the daemon semaphore. A logical/send failure is still
/// returned to the caller after the stock client has been unblocked with status
/// `1`.
///
/// # Errors
/// Returns [`HandleError`] for an unused client slot, System V IPC failure,
/// an unsupported/not-yet-translated command, unexpected legacy parameters, or
/// a modem encode/write failure.
pub fn handle_sdk_api<T: Write>(
    server: &mut Server,
    modem: &mut Modem<T>,
    client_id: u8,
    request: SdkApiRequest<'_>,
) -> Result<HandledCall, HandleError> {
    let context = server.client_context(client_id)?;
    context.daemon_acquire()?;
    if let Err(error) = context.write_i32_be(LTE_API_RET_OFFSET, 0) {
        let _ = context.daemon_release();
        return Err(error.into());
    }

    let dispatch = dispatch_zero_parameter(modem, request);
    let status = i32::from(dispatch.is_err());
    let status_result = context.write_i32_be(LTE_API_RET_OFFSET, status);
    let release_result = context.daemon_release();

    status_result?;
    release_result?;
    dispatch
}

fn dispatch_zero_parameter<T: Write>(
    modem: &mut Modem<T>,
    request: SdkApiRequest<'_>,
) -> Result<HandledCall, HandleError> {
    let command = request
        .known_command()
        .map_err(|_| HandleError::UnsupportedCommand(request.command))?;
    let empty = match command {
        SdkCommand::PsInit => EmptyRequest::PsInit,
        SdkCommand::Online => EmptyRequest::Online,
        SdkCommand::Offline => EmptyRequest::Offline,
        SdkCommand::PlmnList => EmptyRequest::PlmnList,
        _ => return Err(HandleError::UnsupportedCommand(request.command)),
    };
    if !request.params.is_empty() {
        return Err(HandleError::UnexpectedParameters {
            command: request.command,
            actual: request.params.len(),
        });
    }
    let bytes_written = modem.send_command(ModemCommand::Empty(empty))?;
    Ok(HandledCall {
        command,
        device_id: request.device_id,
        bytes_written,
    })
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::{self, Cursor, Write},
        os::unix::net::UnixDatagram,
        path::PathBuf,
        process,
        sync::atomic::{AtomicU64, Ordering},
    };

    use gct_runtime::Modem;
    use gct_transport::HciIo;
    use lted_compat::Server;
    use lted_proto::{ApiOpenRequest, ApiOpenResponse, Packet, SdkApiRequest, SdkCommand};

    use super::{HandleError, LTE_API_RET_OFFSET, handle_sdk_api};

    static NEXT_TEST_DIR: AtomicU64 = AtomicU64::new(0);

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let suffix = NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("wf830-lted-bridge-{}-{suffix}", process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir(&path).unwrap_or_else(|_| std::process::abort());
            Self(path)
        }

        fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn open_client(server: &mut Server, dir: &TestDir) -> (UnixDatagram, u8) {
        let peer_path = dir.join("peer");
        let client = UnixDatagram::bind(&peer_path).unwrap_or_else(|_| std::process::abort());
        let mut open = [0_u8; 8];
        let len = (ApiOpenRequest {
            client_identity: Some(0x1234),
        })
        .encode(&mut open)
        .unwrap_or_else(|_| std::process::abort());
        client
            .send_to(&open[..len], server.common_path())
            .unwrap_or_else(|_| std::process::abort());
        let opened = server
            .accept_open_once()
            .unwrap_or_else(|_| std::process::abort())
            .unwrap_or_else(|| std::process::abort());
        let mut response = [0_u8; 5];
        let (len, source) = client
            .recv_from(&mut response)
            .unwrap_or_else(|_| std::process::abort());
        let packet = Packet::parse(&response[..len]).unwrap_or_else(|_| std::process::abort());
        let response = ApiOpenResponse::parse(packet).unwrap_or_else(|_| std::process::abort());
        assert_eq!(response.client_id, opened.id);
        let source = source
            .as_pathname()
            .unwrap_or_else(|| std::process::abort());
        client
            .connect(source)
            .unwrap_or_else(|_| std::process::abort());
        (client, opened.id)
    }

    fn read_api_ret(server: &mut Server, id: u8) -> i32 {
        let mut bytes = [0_u8; 4];
        server
            .client_context(id)
            .unwrap_or_else(|_| std::process::abort())
            .read(LTE_API_RET_OFFSET, &mut bytes)
            .unwrap_or_else(|_| std::process::abort());
        i32::from_be_bytes(bytes)
    }

    fn bind_server(dir: &TestDir) -> Server {
        Server::bind_paths(dir.join("daemon"), dir.join("client-"))
            .unwrap_or_else(|_| std::process::abort())
    }

    #[test]
    fn stock_style_ps_init_reaches_modem_and_completes_shm_return() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (client, id) = open_client(&mut server, &dir);
        let request = SdkApiRequest {
            command: SdkCommand::PsInit as u16,
            device_id: 0x1122_3344,
            params: &[],
        };
        let mut frame = [0_u8; 12];
        let len = request
            .encode(&mut frame)
            .unwrap_or_else(|_| std::process::abort());
        client
            .send(&frame[..len])
            .unwrap_or_else(|_| std::process::abort());

        let mut received = [0_u8; 32];
        let len = server
            .recv_from_client(id, &mut received)
            .unwrap_or_else(|_| std::process::abort());
        let packet = Packet::parse(&received[..len]).unwrap_or_else(|_| std::process::abort());
        let parsed = SdkApiRequest::parse(packet).unwrap_or_else(|_| std::process::abort());
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let handled = handle_sdk_api(&mut server, &mut modem, id, parsed)
            .unwrap_or_else(|_| std::process::abort());

        assert_eq!(handled.command, SdkCommand::PsInit);
        assert_eq!(handled.device_id, 0x1122_3344);
        assert_eq!(handled.bytes_written, 4);
        assert_eq!(read_api_ret(&mut server, id), 0);
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            vec![0x31, 0x2e, 0x00, 0x00]
        );
    }

    #[test]
    fn all_recovered_zero_parameter_calls_map_to_exact_hci_frames() {
        let cases = [
            (SdkCommand::PlmnList, [0x31, 0x0b, 0x00, 0x00]),
            (SdkCommand::Online, [0x31, 0x21, 0x00, 0x00]),
            (SdkCommand::Offline, [0x31, 0x23, 0x00, 0x00]),
            (SdkCommand::PsInit, [0x31, 0x2e, 0x00, 0x00]),
        ];
        for (index, (command, expected)) in cases.into_iter().enumerate() {
            let dir = TestDir::new();
            let mut server = bind_server(&dir);
            let (_client, id) = open_client(&mut server, &dir);
            let transport = HciIo::new(Cursor::new(Vec::new()));
            let mut modem = Modem::new(transport);
            let request = SdkApiRequest {
                command: command as u16,
                device_id: u32::try_from(index).unwrap_or_else(|_| std::process::abort()),
                params: &[],
            };
            handle_sdk_api(&mut server, &mut modem, id, request)
                .unwrap_or_else(|_| std::process::abort());
            assert_eq!(read_api_ret(&mut server, id), 0);
            assert_eq!(modem.into_transport().into_inner().into_inner(), expected);
        }
    }

    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "test failure"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn failed_modem_write_returns_one_to_stock_client() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (_client, id) = open_client(&mut server, &dir);
        let mut modem = Modem::new(HciIo::new(FailingWriter));
        let request = SdkApiRequest {
            command: SdkCommand::Online as u16,
            device_id: 1,
            params: &[],
        };
        assert!(matches!(
            handle_sdk_api(&mut server, &mut modem, id, request),
            Err(HandleError::Send(_))
        ));
        assert_eq!(read_api_ret(&mut server, id), 1);
    }

    #[test]
    fn unsupported_call_is_released_with_failure_status() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (_client, id) = open_client(&mut server, &dir);
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let params = [0_u8; 352];
        let request = SdkApiRequest {
            command: SdkCommand::Attach as u16,
            device_id: 1,
            params: &params,
        };
        assert!(matches!(
            handle_sdk_api(&mut server, &mut modem, id, request),
            Err(HandleError::UnsupportedCommand(value)) if value == SdkCommand::Attach as u16
        ));
        assert_eq!(read_api_ret(&mut server, id), 1);
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn unexpected_legacy_payload_is_rejected_before_modem_write() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (_client, id) = open_client(&mut server, &dir);
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let request = SdkApiRequest {
            command: SdkCommand::PsInit as u16,
            device_id: 1,
            params: &[0xaa],
        };
        assert!(matches!(
            handle_sdk_api(&mut server, &mut modem, id, request),
            Err(HandleError::UnexpectedParameters {
                command,
                actual: 1,
            }) if command == SdkCommand::PsInit as u16
        ));
        assert_eq!(read_api_ret(&mut server, id), 1);
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            Vec::<u8>::new()
        );
    }
}
