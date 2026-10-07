//! Safe UNIX-datagram compatibility layer for stock `liblted.so` clients.
//!
//! This crate owns only the local socket lifecycle and handshake. The legacy
//! System V shared-memory/semaphore ABI is intentionally kept out of this layer.

use std::{
    ffi::OsString,
    fs, io,
    os::unix::{
        fs::FileTypeExt,
        net::{SocketAddr, UnixDatagram},
    },
    path::{Path, PathBuf},
};

use lted_proto::{
    ApiOpenRequest, ApiOpenResponse, COMMON_SOCKET_PATH, MAX_CLIENTS, PRIVATE_SOCKET_PREFIX, Packet,
};
use lted_sysv::ClientContext;

pub const REJECTED_CLIENT_ID: u8 = 0xff;
const OPEN_FRAME_MAX: usize = 8;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Protocol,
    UnnamedPeer,
}

impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "{error}"),
            Self::Protocol => f.write_str("invalid lted API-open datagram"),
            Self::UnnamedPeer => f.write_str("lted API-open peer has no pathname"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Protocol | Self::UnnamedPeer => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenedClient {
    pub id: u8,
    pub identity: Option<u16>,
    pub socket_path: PathBuf,
}

struct Client {
    identity: Option<u16>,
    socket_path: PathBuf,
    socket: UnixDatagram,
    context: ClientContext,
}

/// Bound compatibility server for the common OEM endpoint and its private
/// per-client datagram sockets.
pub struct Server {
    common_path: PathBuf,
    private_prefix: PathBuf,
    common: UnixDatagram,
    clients: Vec<Option<Client>>,
}

impl Server {
    /// Bind the exact stock endpoints under `/var/tmp`.
    ///
    /// # Errors
    /// Returns an I/O error when the common UNIX datagram endpoint cannot be
    /// prepared or bound.
    pub fn bind_oem() -> io::Result<Self> {
        Self::bind_paths(COMMON_SOCKET_PATH, PRIVATE_SOCKET_PREFIX)
    }

    /// Bind alternate paths, primarily for deterministic tests and recovery
    /// tooling that must not collide with a live OEM daemon.
    ///
    /// `private_prefix` is a pathname prefix; decimal client IDs are appended
    /// without a separator, matching `/var/tmp/lted-client-%d`.
    ///
    /// # Errors
    /// Returns an I/O error when the common endpoint cannot be prepared/bound.
    pub fn bind_paths(
        common_path: impl AsRef<Path>,
        private_prefix: impl AsRef<Path>,
    ) -> io::Result<Self> {
        let common_path = common_path.as_ref().to_path_buf();
        remove_stale_socket(&common_path)?;
        let common = UnixDatagram::bind(&common_path)?;
        let clients = (0..MAX_CLIENTS).map(|_| None).collect();
        Ok(Self {
            common_path,
            private_prefix: private_prefix.as_ref().to_path_buf(),
            common,
            clients,
        })
    }

    #[must_use]
    pub fn common_path(&self) -> &Path {
        &self.common_path
    }

    /// Borrow the common UNIX datagram socket for external readiness polling.
    #[must_use]
    pub const fn common_socket(&self) -> &UnixDatagram {
        &self.common
    }

    #[must_use]
    pub fn client_count(&self) -> usize {
        self.clients.iter().flatten().count()
    }

    /// Snapshot the currently allocated client IDs in ascending slot order.
    #[must_use]
    pub fn client_ids(&self) -> Vec<u8> {
        self.clients
            .iter()
            .enumerate()
            .filter_map(|(index, client)| {
                client.as_ref()?;
                u8::try_from(index).ok()
            })
            .collect()
    }

    #[must_use]
    pub fn client_identity(&self, id: u8) -> Option<Option<u16>> {
        self.clients
            .get(usize::from(id))
            .and_then(Option::as_ref)
            .map(|client| client.identity)
    }

    #[must_use]
    pub fn client_socket_path(&self, id: u8) -> Option<&Path> {
        self.clients
            .get(usize::from(id))
            .and_then(Option::as_ref)
            .map(|client| client.socket_path.as_path())
    }

    /// Borrow one allocated private client socket for external readiness polling.
    ///
    /// # Errors
    /// Returns `NotFound` for an unused client ID.
    pub fn client_socket(&self, id: u8) -> io::Result<&UnixDatagram> {
        self.client(id).map(|client| &client.socket)
    }

    /// Receive and complete one common-socket API-open handshake.
    ///
    /// A full table deliberately returns a successful `0x8101` response with
    /// client ID `0xff`, matching the OEM daemon and stock client's rejection
    /// path. In that case this method returns `Ok(None)`.
    ///
    /// # Errors
    /// Returns [`Error`] for malformed open datagrams, unnamed UNIX peers, or
    /// socket failures.
    pub fn accept_open_once(&mut self) -> Result<Option<OpenedClient>, Error> {
        let mut frame = [0_u8; OPEN_FRAME_MAX];
        let (len, peer) = self.common.recv_from(&mut frame)?;
        let peer_path = pathname(&peer)?.to_path_buf();
        let packet = Packet::parse(&frame[..len]).map_err(|_| Error::Protocol)?;
        let request = ApiOpenRequest::parse(packet).map_err(|_| Error::Protocol)?;

        let Some(id) = self.first_free_id() else {
            Self::send_open_response(&self.common, &peer_path, REJECTED_CLIENT_ID)?;
            return Ok(None);
        };

        let socket_path = private_path(&self.private_prefix, id);
        remove_stale_socket(&socket_path)?;
        let socket = UnixDatagram::bind(&socket_path)?;
        socket.connect(&peer_path)?;
        let context = match ClientContext::create(&self.common_path, id) {
            Ok(context) => context,
            Err(error) => {
                drop(socket);
                let _ = fs::remove_file(&socket_path);
                Self::send_open_response(&self.common, &peer_path, REJECTED_CLIENT_ID)?;
                return Err(Error::Io(error));
            }
        };
        Self::send_connected_open_response(&socket, id)?;

        let opened = OpenedClient {
            id,
            identity: request.client_identity,
            socket_path: socket_path.clone(),
        };
        self.clients[usize::from(id)] = Some(Client {
            identity: request.client_identity,
            socket_path,
            socket,
            context,
        });
        Ok(Some(opened))
    }

    /// Borrow the per-client shared-memory/semaphore context.
    ///
    /// # Errors
    /// Returns `NotFound` for an unused client ID.
    pub fn client_context(&mut self, id: u8) -> io::Result<&mut ClientContext> {
        self.clients
            .get_mut(usize::from(id))
            .and_then(Option::as_mut)
            .map(|client| &mut client.context)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "lted client slot is unused"))
    }

    /// Receive one datagram from an already-open private client socket.
    ///
    /// # Errors
    /// Returns `NotFound` for an unused client ID or the underlying socket I/O
    /// error.
    pub fn recv_from_client(&self, id: u8, output: &mut [u8]) -> io::Result<usize> {
        let client = self.client(id)?;
        client.socket.recv(output)
    }

    /// Send one complete datagram to an already-connected stock client.
    ///
    /// # Errors
    /// Returns `NotFound` for an unused client ID or the underlying socket I/O
    /// error.
    pub fn send_to_client(&self, id: u8, frame: &[u8]) -> io::Result<usize> {
        let client = self.client(id)?;
        client.socket.send(frame)
    }

    /// Remove a client slot and its private endpoint.
    ///
    /// Returns whether an allocated slot existed.
    pub fn remove_client(&mut self, id: u8) -> bool {
        let Some(slot) = self.clients.get_mut(usize::from(id)) else {
            return false;
        };
        let Some(client) = slot.take() else {
            return false;
        };
        let _ = fs::remove_file(client.socket_path);
        true
    }

    fn client(&self, id: u8) -> io::Result<&Client> {
        self.clients
            .get(usize::from(id))
            .and_then(Option::as_ref)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "lted client slot is unused"))
    }

    fn first_free_id(&self) -> Option<u8> {
        self.clients
            .iter()
            .position(Option::is_none)
            .and_then(|index| u8::try_from(index).ok())
    }

    fn send_open_response(socket: &UnixDatagram, peer_path: &Path, id: u8) -> Result<(), Error> {
        let mut response = [0_u8; 5];
        let len = ApiOpenResponse { client_id: id }
            .encode(&mut response)
            .map_err(|_| Error::Protocol)?;
        socket.send_to(&response[..len], peer_path)?;
        Ok(())
    }

    fn send_connected_open_response(socket: &UnixDatagram, id: u8) -> Result<(), Error> {
        let mut response = [0_u8; 5];
        let len = ApiOpenResponse { client_id: id }
            .encode(&mut response)
            .map_err(|_| Error::Protocol)?;
        socket.send(&response[..len])?;
        Ok(())
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        for client in self.clients.iter_mut().filter_map(Option::take) {
            let _ = fs::remove_file(client.socket_path);
        }
        let _ = fs::remove_file(&self.common_path);
    }
}

fn pathname(address: &SocketAddr) -> Result<&Path, Error> {
    address.as_pathname().ok_or(Error::UnnamedPeer)
}

fn private_path(prefix: &Path, id: u8) -> PathBuf {
    let mut path: OsString = prefix.as_os_str().to_owned();
    path.push(id.to_string());
    PathBuf::from(path)
}

fn remove_stale_socket(path: &Path) -> io::Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if !metadata.file_type().is_socket() {
        return Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            format!("refusing to replace non-socket path {}", path.display()),
        ));
    }

    let probe = UnixDatagram::unbound()?;
    match probe.connect(path) {
        Ok(()) => Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            format!("UNIX datagram endpoint {} is active", path.display()),
        )),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
            ) =>
        {
            fs::remove_file(path)
        }
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::net::UnixDatagram,
        path::{Path, PathBuf},
        process,
        sync::atomic::{AtomicU64, Ordering},
    };

    use lted_proto::{ApiOpenRequest, ApiOpenResponse, Packet};

    use super::{MAX_CLIENTS, REJECTED_CLIENT_ID, Server, private_path};

    static NEXT_TEST_DIR: AtomicU64 = AtomicU64::new(0);

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let suffix = NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("wf830-lted-compat-{}-{suffix}", process::id()));
            let _ = fs::remove_dir_all(&path);
            if fs::create_dir(&path).is_err() {
                std::process::abort();
            }
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

    fn open_client(
        server: &mut Server,
        dir: &TestDir,
        number: usize,
        identity: u16,
    ) -> (UnixDatagram, PathBuf, u8, PathBuf) {
        let client_path = dir.join(&format!("peer-{number}"));
        let client = UnixDatagram::bind(&client_path).unwrap_or_else(|_| std::process::abort());
        let mut request = [0_u8; 8];
        let request_len = (ApiOpenRequest {
            client_identity: Some(identity),
        })
        .encode(&mut request)
        .unwrap_or_else(|_| std::process::abort());
        if client
            .send_to(&request[..request_len], server.common_path())
            .is_err()
        {
            std::process::abort();
        }
        let opened = server
            .accept_open_once()
            .unwrap_or_else(|_| std::process::abort())
            .unwrap_or_else(|| std::process::abort());
        let mut response = [0_u8; 5];
        let (len, source) = client
            .recv_from(&mut response)
            .unwrap_or_else(|_| std::process::abort());
        let packet = Packet::parse(&response[..len]).unwrap_or_else(|_| std::process::abort());
        let parsed = ApiOpenResponse::parse(packet).unwrap_or_else(|_| std::process::abort());
        assert_eq!(parsed.client_id, opened.id);
        let source_path = source
            .as_pathname()
            .map_or_else(|| std::process::abort(), Path::to_path_buf);
        (client, client_path, opened.id, source_path)
    }

    #[test]
    fn active_common_socket_is_never_unlinked() {
        let dir = TestDir::new();
        let common = dir.join("daemon");
        let _active = UnixDatagram::bind(&common).unwrap_or_else(|_| std::process::abort());
        let error = Server::bind_paths(&common, dir.join("client-"))
            .err()
            .unwrap_or_else(|| std::process::abort());
        assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse);
        assert!(common.exists());
    }

    #[test]
    fn orphaned_common_socket_is_reclaimed() {
        let dir = TestDir::new();
        let common = dir.join("daemon");
        {
            let _orphan = UnixDatagram::bind(&common).unwrap_or_else(|_| std::process::abort());
        }
        assert!(common.exists());
        let server = Server::bind_paths(&common, dir.join("client-"))
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(server.common_path(), common);
    }

    #[test]
    fn non_socket_common_path_is_never_deleted() {
        let dir = TestDir::new();
        let common = dir.join("daemon");
        fs::write(&common, b"do not delete").unwrap_or_else(|_| std::process::abort());
        let error = Server::bind_paths(&common, dir.join("client-"))
            .err()
            .unwrap_or_else(|| std::process::abort());
        assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse);
        assert_eq!(
            fs::read(&common).unwrap_or_else(|_| std::process::abort()),
            b"do not delete"
        );
    }

    #[test]
    fn private_socket_path_matches_oem_percent_d_shape() {
        assert_eq!(
            private_path(Path::new("/var/tmp/lted-client-"), 12),
            Path::new("/var/tmp/lted-client-12")
        );
    }

    #[test]
    fn open_response_originates_from_private_socket_and_preserves_identity() {
        let dir = TestDir::new();
        let common = dir.join("daemon");
        let prefix = dir.join("client-");
        let mut server =
            Server::bind_paths(&common, &prefix).unwrap_or_else(|_| std::process::abort());

        let (client, _client_path, id, source_path) = open_client(&mut server, &dir, 0, 0x1234);
        assert_eq!(id, 0);
        assert_eq!(source_path, private_path(&prefix, id));
        assert_eq!(server.client_identity(id), Some(Some(0x1234)));
        assert_eq!(server.client_count(), 1);
        let context = server
            .client_context(id)
            .unwrap_or_else(|_| std::process::abort());
        assert!(context.shmid() >= 0);
        assert!(context.semid() >= 0);

        if client.connect(&source_path).is_err() {
            std::process::abort();
        }
        assert!(matches!(server.send_to_client(id, b"ok"), Ok(2)));
        let mut reply = [0_u8; 2];
        assert!(matches!(client.recv(&mut reply), Ok(2)));
        assert_eq!(&reply, b"ok");
    }

    #[test]
    fn full_table_returns_ff_from_common_socket() {
        let dir = TestDir::new();
        let common = dir.join("daemon");
        let prefix = dir.join("client-");
        let mut server =
            Server::bind_paths(&common, &prefix).unwrap_or_else(|_| std::process::abort());
        let mut clients = Vec::new();
        for index in 0..MAX_CLIENTS {
            let opened = open_client(
                &mut server,
                &dir,
                index,
                u16::try_from(index).unwrap_or_else(|_| std::process::abort()),
            );
            assert_eq!(usize::from(opened.2), index);
            clients.push(opened);
        }
        assert_eq!(server.client_count(), MAX_CLIENTS);

        let peer_path = dir.join("overflow-peer");
        let overflow = UnixDatagram::bind(&peer_path).unwrap_or_else(|_| std::process::abort());
        let mut request = [0_u8; 8];
        let request_len = (ApiOpenRequest {
            client_identity: Some(0xbeef),
        })
        .encode(&mut request)
        .unwrap_or_else(|_| std::process::abort());
        if overflow
            .send_to(&request[..request_len], server.common_path())
            .is_err()
        {
            std::process::abort();
        }
        assert!(matches!(server.accept_open_once(), Ok(None)));

        let mut response = [0_u8; 5];
        let (len, source) = overflow
            .recv_from(&mut response)
            .unwrap_or_else(|_| std::process::abort());
        let packet = Packet::parse(&response[..len]).unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            ApiOpenResponse::parse(packet),
            Ok(ApiOpenResponse {
                client_id: REJECTED_CLIENT_ID,
            })
        );
        assert_eq!(source.as_pathname(), Some(common.as_path()));
        assert_eq!(server.client_count(), MAX_CLIENTS);
        drop(clients);
    }

    #[test]
    fn removing_client_reuses_lowest_slot_and_unlinks_private_socket() {
        let dir = TestDir::new();
        let common = dir.join("daemon");
        let prefix = dir.join("client-");
        let mut server =
            Server::bind_paths(&common, &prefix).unwrap_or_else(|_| std::process::abort());
        let first = open_client(&mut server, &dir, 0, 1);
        let second = open_client(&mut server, &dir, 1, 2);
        assert_eq!(first.2, 0);
        assert_eq!(second.2, 1);
        let first_private = private_path(&prefix, 0);
        assert!(first_private.exists());
        assert!(server.remove_client(0));
        assert!(!first_private.exists());

        let third = open_client(&mut server, &dir, 2, 3);
        assert_eq!(third.2, 0);
    }
}
