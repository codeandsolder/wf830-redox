//! Translation layer from the recovered stock `lted` client ABI to typed GCT
//! modem requests.
//!
//! Synchronous SDK-call completion and asynchronous modem callbacks are two
//! separate paths in the OEM design. This crate currently implements the
//! synchronous half for the zero-parameter P0 calls whose wire mapping is fully
//! proven.

use std::{io, io::Write};

use gct_lapi::{
    EmptyRequest, PlmnInfoDecodeError, PlmnListResponse, ResultResponse, ResultResponseKind,
};
use gct_runtime::{
    Modem, ModemCommand, ModemEvent, PendingRequests, ResponseKey, SendCommandError,
    SendTrackedCommandError,
};
use lted_compat::Server;
use lted_proto::{SdkApiRequest, SdkCallback, SdkCallbackKind, SdkCommand};

/// Offset of `lte_api_ret` inside the recovered 38,784-byte
/// `lted_client_context`.
pub const LTE_API_RET_OFFSET: usize = 0x524;
/// One-byte `LTED_GetPSInitComplete` return slot in the stock shared context.
pub const PS_INIT_COMPLETE_OFFSET: usize = 0x528;

#[derive(Debug)]
pub enum HandleError {
    Ipc(io::Error),
    UnsupportedCommand(u16),
    UnexpectedParameters { command: u16, actual: usize },
    UnknownDevice { requested: u32, expected: u32 },
    PlmnList(PlmnInfoDecodeError),
    Send(SendCommandError),
    Tracked(SendTrackedCommandError),
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
            Self::UnknownDevice {
                requested,
                expected,
            } => write!(
                f,
                "lted SDK request addressed device {requested}, expected {expected}"
            ),
            Self::PlmnList(error) => write!(f, "invalid PLMN-list response: {error:?}"),
            Self::Send(error) => write!(f, "modem send failed: {error:?}"),
            Self::Tracked(error) => write!(f, "tracked modem send failed: {error:?}"),
        }
    }
}

impl std::error::Error for HandleError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Ipc(error) => Some(error),
            Self::UnsupportedCommand(_)
            | Self::UnexpectedParameters { .. }
            | Self::UnknownDevice { .. }
            | Self::PlmnList(_)
            | Self::Send(_)
            | Self::Tracked(_) => None,
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

impl From<SendTrackedCommandError> for HandleError {
    fn from(value: SendTrackedCommandError) -> Self {
        Self::Tracked(value)
    }
}

const MAX_PLMN_RECORDS: usize = 32;
const STOCK_PLMN_RECORD_LEN: usize = 11;
const STOCK_PLMN_PREFIX_LEN: usize = 5;
const MAX_PLMN_CALLBACK_DATA_LEN: usize =
    STOCK_PLMN_PREFIX_LEN + MAX_PLMN_RECORDS * STOCK_PLMN_RECORD_LEN;
const MAX_PLMN_CALLBACK_FRAME_LEN: usize = 12 + MAX_PLMN_CALLBACK_DATA_LEN;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandledCall {
    pub command: SdkCommand,
    pub device_id: u32,
    pub bytes_written: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BroadcastReport {
    pub registered_clients: usize,
    pub sent_clients: usize,
}

/// Broadcast one of the three proven four-byte result callbacks to every stock
/// client that has the corresponding `cb_rsp[]` function slot registered.
///
/// The callback payload is the original big-endian four-byte modem result, and
/// the local `0x8107` envelope carries the supplied OEM device ID.
///
/// # Errors
/// Returns [`HandleError::Ipc`] for shared-context or UNIX-datagram failures.
pub fn broadcast_result_callback(
    server: &mut Server,
    kind: ResultResponseKind,
    device_id: u32,
    response: ResultResponse,
) -> Result<BroadcastReport, HandleError> {
    let callback_kind = match kind {
        ResultResponseKind::Online => SdkCallbackKind::Online,
        ResultResponseKind::Offline => SdkCallbackKind::Offline,
        ResultResponseKind::PsInit => SdkCallbackKind::PsInit,
    };
    let mut frame = [0_u8; 16];
    let data = response.result.to_be_bytes();
    let frame_len = SdkCallback {
        callback_id: callback_kind.callback_id(),
        device_id,
        data: &data,
    }
    .encode(&mut frame)
    .map_err(|_| {
        HandleError::Ipc(io::Error::new(
            io::ErrorKind::InvalidData,
            "fixed-size result callback failed to encode",
        ))
    })?;

    let mut report = BroadcastReport::default();
    for client_id in server.client_ids() {
        let registered = server
            .client_context(client_id)?
            .read_u32_be(callback_kind.registration_offset())?
            != 0;
        if !registered {
            continue;
        }
        report.registered_clients += 1;
        server.send_to_client(client_id, &frame[..frame_len])?;
        report.sent_clients += 1;
    }
    Ok(report)
}

/// Materialize and broadcast stock callback 45 (`PLMN List`).
///
/// The live daemon sends exactly `5 + 11*N` callback-data bytes: one
/// `search_complete` byte, a big-endian `u32` record count, then `N` records
/// laid out as `plmn_id[3] | priority:u32be | status:u32be`.
///
/// # Errors
/// Returns [`HandleError::PlmnList`] for a malformed semantic record stream,
/// or [`HandleError::Ipc`] for callback encoding/shared-context/socket errors.
pub fn broadcast_plmn_list_callback(
    server: &mut Server,
    device_id: u32,
    response: PlmnListResponse<'_>,
) -> Result<BroadcastReport, HandleError> {
    let mut data = [0_u8; MAX_PLMN_CALLBACK_DATA_LEN];
    data[0] = response.search_complete;
    let mut count = 0_u32;
    let mut offset = STOCK_PLMN_PREFIX_LEN;
    let mut records = response.records();
    while let Some(record) = records.next_record().map_err(HandleError::PlmnList)? {
        data[offset..offset + 3].copy_from_slice(&record.plmn_id);
        data[offset + 3..offset + 7].copy_from_slice(&record.priority.to_be_bytes());
        data[offset + 7..offset + 11].copy_from_slice(&record.status.to_be_bytes());
        offset += STOCK_PLMN_RECORD_LEN;
        count += 1;
    }
    data[1..5].copy_from_slice(&count.to_be_bytes());

    let callback_kind = SdkCallbackKind::PlmnList;
    let mut frame = [0_u8; MAX_PLMN_CALLBACK_FRAME_LEN];
    let frame_len = SdkCallback {
        callback_id: callback_kind.callback_id(),
        device_id,
        data: &data[..offset],
    }
    .encode(&mut frame)
    .map_err(|_| {
        HandleError::Ipc(io::Error::new(
            io::ErrorKind::InvalidData,
            "bounded PLMN-list callback failed to encode",
        ))
    })?;

    let mut report = BroadcastReport::default();
    for client_id in server.client_ids() {
        let registered = server
            .client_context(client_id)?
            .read_u32_be(callback_kind.registration_offset())?
            != 0;
        if !registered {
            continue;
        }
        report.registered_clients += 1;
        server.send_to_client(client_id, &frame[..frame_len])?;
        report.sent_clients += 1;
    }
    Ok(report)
}

/// Per-physical-modem compatibility state.
///
/// The stock SDK resolves every request through `device_find(handle, device_id)`
/// and response handlers pass `device->device_id` back as the first callback
/// argument. The replacement therefore binds one stable OEM device ID to one
/// modem runtime instead of inventing request-side callback tokens.
#[derive(Debug, Eq, PartialEq)]
pub struct DeviceBridge {
    device_id: u32,
    pending: PendingRequests,
    init_complete: bool,
}

impl DeviceBridge {
    #[must_use]
    pub const fn new(device_id: u32) -> Self {
        Self {
            device_id,
            pending: PendingRequests::new(),
            init_complete: false,
        }
    }

    #[must_use]
    pub const fn device_id(&self) -> u32 {
        self.device_id
    }

    #[must_use]
    pub const fn pending_count(&self) -> usize {
        self.pending.len()
    }

    #[must_use]
    pub const fn init_complete(&self) -> bool {
        self.init_complete
    }

    /// Execute one stock SDK request and complete the OEM semaphore/shm
    /// synchronous return path.
    ///
    /// The recovered OEM sequence is preserved: acquire the daemon semaphore,
    /// clear `lte_api_ret`, attempt the LAPI send, store `0` on success or `1`
    /// on failure, then release the daemon semaphore. Result-family requests are
    /// tracked before touching GLIF so a second indistinguishable request cannot
    /// steal the eventual callback.
    ///
    /// # Errors
    /// Returns [`HandleError`] for an unused client slot, System V IPC failure,
    /// a request for another physical device, an unsupported/not-yet-translated
    /// command, unexpected legacy parameters, or a modem encode/write/pending
    /// failure.
    pub fn handle_sdk_api<T: Write>(
        &mut self,
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

        let dispatch = if request.device_id == self.device_id {
            match request.known_command() {
                Ok(SdkCommand::GetPsInitComplete) => {
                    if request.params.is_empty() {
                        context.write(PS_INIT_COMPLETE_OFFSET, &[u8::from(self.init_complete)])?;
                        Ok(HandledCall {
                            command: SdkCommand::GetPsInitComplete,
                            device_id: request.device_id,
                            bytes_written: 0,
                        })
                    } else {
                        Err(HandleError::UnexpectedParameters {
                            command: request.command,
                            actual: request.params.len(),
                        })
                    }
                }
                Ok(_) => self.dispatch_zero_parameter(modem, request),
                Err(_) => Err(HandleError::UnsupportedCommand(request.command)),
            }
        } else {
            Err(HandleError::UnknownDevice {
                requested: request.device_id,
                expected: self.device_id,
            })
        };
        let status = i32::from(dispatch.is_err());
        let status_result = context.write_i32_be(LTE_API_RET_OFFSET, status);
        let release_result = context.daemon_release();

        status_result?;
        release_result?;
        dispatch
    }

    /// Route one decoded modem event through the asynchronous stock callback
    /// path implemented so far.
    ///
    /// Four-byte Online/Offline/PSInit result responses and multipart PLMN-list
    /// responses are handled here. An event without a matching tracked request
    /// is ignored, matching the replacement's conservative correlation policy.
    ///
    /// # Errors
    /// Returns [`HandleError::Ipc`] when broadcasting to a subscribed stock
    /// client fails.
    pub fn handle_modem_event(
        &mut self,
        server: &mut Server,
        event: &ModemEvent<'_>,
    ) -> Result<Option<BroadcastReport>, HandleError> {
        match event {
            ModemEvent::Result { kind, response } => {
                let key = ResponseKey::Result(*kind);
                if !self.pending.remove(key) {
                    return Ok(None);
                }
                broadcast_result_callback(server, *kind, self.device_id, *response).map(Some)
            }
            ModemEvent::PlmnList(response) => {
                let key = ResponseKey::PlmnList;
                if !self.pending.contains(key) {
                    return Ok(None);
                }
                let report = broadcast_plmn_list_callback(server, self.device_id, *response)?;
                if response.search_complete != 0 {
                    self.pending.remove(key);
                }
                Ok(Some(report))
            }
            _ => Ok(None),
        }
    }

    fn dispatch_zero_parameter<T: Write>(
        &mut self,
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
            SdkCommand::GetPsInitComplete => {
                return Err(HandleError::UnsupportedCommand(request.command));
            }
            _ => return Err(HandleError::UnsupportedCommand(request.command)),
        };
        if !request.params.is_empty() {
            return Err(HandleError::UnexpectedParameters {
                command: request.command,
                actual: request.params.len(),
            });
        }
        let modem_command = ModemCommand::Empty(empty);
        let bytes_written = modem.send_tracked_command(&mut self.pending, modem_command)?;
        Ok(HandledCall {
            command,
            device_id: request.device_id,
            bytes_written,
        })
    }
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

    use gct_lapi::{ResultResponse, ResultResponseKind};
    use gct_runtime::{Modem, ModemEvent};
    use gct_transport::HciIo;
    use lted_compat::Server;
    use lted_proto::{
        ApiOpenRequest, ApiOpenResponse, Packet, SdkApiRequest, SdkCallback, SdkCallbackKind,
        SdkCommand,
    };

    use super::{
        BroadcastReport, DeviceBridge, HandleError, LTE_API_RET_OFFSET, PS_INIT_COMPLETE_OFFSET,
        broadcast_result_callback,
    };

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

    fn open_client(server: &mut Server, dir: &TestDir, number: usize) -> (UnixDatagram, u8) {
        let peer_path = dir.join(&format!("peer-{number}"));
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

    fn route_one_hci(
        bridge: &mut DeviceBridge,
        server: &mut Server,
        frame: Vec<u8>,
    ) -> Option<BroadcastReport> {
        let transport = HciIo::new(Cursor::new(frame));
        let mut modem = Modem::new(transport);
        let mut routed = None;
        modem
            .poll_events_once(|event| {
                let Ok(event) = event else {
                    std::process::abort();
                };
                routed = bridge
                    .handle_modem_event(server, &event)
                    .unwrap_or_else(|_| std::process::abort());
            })
            .unwrap_or_else(|_| std::process::abort());
        routed
    }

    #[test]
    fn get_ps_init_complete_is_local_and_uses_recovered_shared_byte() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (_client, id) = open_client(&mut server, &dir, 0);
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(1);
        let request = SdkApiRequest {
            command: SdkCommand::GetPsInitComplete as u16,
            device_id: 1,
            params: &[],
        };

        let handled = bridge
            .handle_sdk_api(&mut server, &mut modem, id, request)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(handled.command, SdkCommand::GetPsInitComplete);
        assert_eq!(handled.bytes_written, 0);
        assert_eq!(read_api_ret(&mut server, id), 0);
        let mut value = [0xff_u8; 1];
        server
            .client_context(id)
            .unwrap_or_else(|_| std::process::abort())
            .read(PS_INIT_COMPLETE_OFFSET, &mut value)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(value, [0]);
        assert!(!bridge.init_complete());
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn stock_style_ps_init_reaches_modem_and_completes_shm_return() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (client, id) = open_client(&mut server, &dir, 0);
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
        let mut bridge = DeviceBridge::new(0x1122_3344);
        let handled = bridge
            .handle_sdk_api(&mut server, &mut modem, id, parsed)
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
            let (_client, id) = open_client(&mut server, &dir, 0);
            let transport = HciIo::new(Cursor::new(Vec::new()));
            let mut modem = Modem::new(transport);
            let device_id = u32::try_from(index).unwrap_or_else(|_| std::process::abort());
            let mut bridge = DeviceBridge::new(device_id);
            let request = SdkApiRequest {
                command: command as u16,
                device_id,
                params: &[],
            };
            bridge
                .handle_sdk_api(&mut server, &mut modem, id, request)
                .unwrap_or_else(|_| std::process::abort());
            assert_eq!(read_api_ret(&mut server, id), 0);
            assert_eq!(modem.into_transport().into_inner().into_inner(), expected);
        }
    }

    #[test]
    fn plmn_list_callback_matches_stock_layout_and_releases_only_terminal_fragment() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (client, id) = open_client(&mut server, &dir, 0);
        server
            .client_context(id)
            .unwrap_or_else(|_| std::process::abort())
            .write_u32_be(SdkCallbackKind::PlmnList.registration_offset(), 1)
            .unwrap_or_else(|_| std::process::abort());

        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(0x1122_3344);
        let request = SdkApiRequest {
            command: SdkCommand::PlmnList as u16,
            device_id: 0x1122_3344,
            params: &[],
        };
        bridge
            .handle_sdk_api(&mut server, &mut modem, id, request)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(bridge.pending_count(), 1);
        assert!(matches!(
            bridge.handle_sdk_api(&mut server, &mut modem, id, request),
            Err(HandleError::Tracked(_))
        ));
        assert_eq!(read_api_ret(&mut server, id), 1);

        let partial = vec![
            0xb1, 0x0c, 0x00, 0x12, 0x00, 0x12, 0x03, 0x62, 0xf0, 0x10, 0x13, 0x04, 0x00, 0x00,
            0x00, 0x07, 0x14, 0x04, 0x00, 0x00, 0x00, 0x09,
        ];
        assert_eq!(
            route_one_hci(&mut bridge, &mut server, partial),
            Some(BroadcastReport {
                registered_clients: 1,
                sent_clients: 1,
            })
        );
        assert_eq!(bridge.pending_count(), 1);

        let mut frame = [0_u8; 64];
        let len = client
            .recv(&mut frame)
            .unwrap_or_else(|_| std::process::abort());
        let packet = Packet::parse(&frame[..len]).unwrap_or_else(|_| std::process::abort());
        let callback = SdkCallback::parse(packet).unwrap_or_else(|_| std::process::abort());
        assert_eq!(callback.callback_id, 45);
        assert_eq!(callback.device_id, 0x1122_3344);
        assert_eq!(
            callback.data,
            &[
                0x00, 0x00, 0x00, 0x00, 0x01, 0x62, 0xf0, 0x10, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00,
                0x00, 0x09,
            ]
        );

        let terminal = vec![
            0xb1, 0x0c, 0x00, 0x23, 0x01, 0x14, 0x04, 0x00, 0x00, 0x00, 0x03, 0x12, 0x03, 0x21,
            0x43, 0x65, 0x13, 0x04, 0x00, 0x00, 0x00, 0x02, 0x12, 0x03, 0x13, 0x37, 0x42, 0x13,
            0x04, 0x00, 0x00, 0x00, 0x05, 0x14, 0x04, 0x00, 0x00, 0x00, 0x06,
        ];
        assert_eq!(
            route_one_hci(&mut bridge, &mut server, terminal),
            Some(BroadcastReport {
                registered_clients: 1,
                sent_clients: 1,
            })
        );
        assert_eq!(bridge.pending_count(), 0);

        let len = client
            .recv(&mut frame)
            .unwrap_or_else(|_| std::process::abort());
        let packet = Packet::parse(&frame[..len]).unwrap_or_else(|_| std::process::abort());
        let callback = SdkCallback::parse(packet).unwrap_or_else(|_| std::process::abort());
        assert_eq!(callback.callback_id, 45);
        assert_eq!(callback.device_id, 0x1122_3344);
        assert_eq!(
            callback.data,
            &[
                0x01, 0x00, 0x00, 0x00, 0x02, 0x21, 0x43, 0x65, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
                0x00, 0x03, 0x13, 0x37, 0x42, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x06,
            ]
        );

        bridge
            .handle_sdk_api(&mut server, &mut modem, id, request)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(read_api_ret(&mut server, id), 0);
        assert_eq!(bridge.pending_count(), 1);
    }

    #[test]
    fn result_callback_reaches_only_registered_stock_clients() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (registered_client, registered_id) = open_client(&mut server, &dir, 0);
        let (unregistered_client, _unregistered_id) = open_client(&mut server, &dir, 1);
        server
            .client_context(registered_id)
            .unwrap_or_else(|_| std::process::abort())
            .write_u32_be(SdkCallbackKind::Online.registration_offset(), 0x1234_5678)
            .unwrap_or_else(|_| std::process::abort());

        let report = broadcast_result_callback(
            &mut server,
            ResultResponseKind::Online,
            0x1122_3344,
            ResultResponse {
                result: 0xaabb_ccdd,
            },
        )
        .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            report,
            BroadcastReport {
                registered_clients: 1,
                sent_clients: 1,
            }
        );

        let mut frame = [0_u8; 16];
        let len = registered_client
            .recv(&mut frame)
            .unwrap_or_else(|_| std::process::abort());
        let packet = Packet::parse(&frame[..len]).unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            SdkCallback::parse(packet),
            Ok(SdkCallback {
                callback_id: 59,
                device_id: 0x1122_3344,
                data: &[0xaa, 0xbb, 0xcc, 0xdd],
            })
        );

        unregistered_client
            .set_nonblocking(true)
            .unwrap_or_else(|_| std::process::abort());
        let mut nothing = [0_u8; 16];
        let Err(error) = unregistered_client.recv(&mut nothing) else {
            std::process::abort();
        };
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn each_result_kind_uses_its_recovered_callback_id_and_slot() {
        let cases = [
            (ResultResponseKind::Online, SdkCallbackKind::Online, 59),
            (ResultResponseKind::Offline, SdkCallbackKind::Offline, 62),
            (ResultResponseKind::PsInit, SdkCallbackKind::PsInit, 68),
        ];
        for (number, (kind, callback_kind, callback_id)) in cases.into_iter().enumerate() {
            let dir = TestDir::new();
            let mut server = bind_server(&dir);
            let (client, id) = open_client(&mut server, &dir, number);
            server
                .client_context(id)
                .unwrap_or_else(|_| std::process::abort())
                .write_u32_be(callback_kind.registration_offset(), 1)
                .unwrap_or_else(|_| std::process::abort());
            broadcast_result_callback(&mut server, kind, 7, ResultResponse { result: 9 })
                .unwrap_or_else(|_| std::process::abort());
            let mut frame = [0_u8; 16];
            let len = client
                .recv(&mut frame)
                .unwrap_or_else(|_| std::process::abort());
            let packet = Packet::parse(&frame[..len]).unwrap_or_else(|_| std::process::abort());
            let callback = SdkCallback::parse(packet).unwrap_or_else(|_| std::process::abort());
            assert_eq!(callback.callback_id, callback_id);
            assert_eq!(callback.device_id, 7);
            assert_eq!(callback.data, 9_u32.to_be_bytes());
        }
    }

    #[test]
    fn result_response_uses_stable_device_id_and_releases_pending_family() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (client, id) = open_client(&mut server, &dir, 0);
        server
            .client_context(id)
            .unwrap_or_else(|_| std::process::abort())
            .write_u32_be(SdkCallbackKind::Online.registration_offset(), 1)
            .unwrap_or_else(|_| std::process::abort());
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(0x1122_3344);
        let request = SdkApiRequest {
            command: SdkCommand::Online as u16,
            device_id: 0x1122_3344,
            params: &[],
        };
        bridge
            .handle_sdk_api(&mut server, &mut modem, id, request)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(bridge.pending_count(), 1);

        let duplicate = bridge.handle_sdk_api(&mut server, &mut modem, id, request);
        assert!(matches!(duplicate, Err(HandleError::Tracked(_))));
        assert_eq!(read_api_ret(&mut server, id), 1);
        assert_eq!(bridge.pending_count(), 1);

        let event = ModemEvent::Result {
            kind: ResultResponseKind::Online,
            response: ResultResponse { result: 7 },
        };
        let report = bridge
            .handle_modem_event(&mut server, &event)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            report,
            Some(BroadcastReport {
                registered_clients: 1,
                sent_clients: 1,
            })
        );
        assert_eq!(bridge.pending_count(), 0);

        let mut frame = [0_u8; 16];
        let len = client
            .recv(&mut frame)
            .unwrap_or_else(|_| std::process::abort());
        let packet = Packet::parse(&frame[..len]).unwrap_or_else(|_| std::process::abort());
        let callback = SdkCallback::parse(packet).unwrap_or_else(|_| std::process::abort());
        assert_eq!(callback.callback_id, 59);
        assert_eq!(callback.device_id, 0x1122_3344);
        assert_eq!(callback.data, 7_u32.to_be_bytes());

        bridge
            .handle_sdk_api(&mut server, &mut modem, id, request)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(read_api_ret(&mut server, id), 0);
    }

    #[test]
    fn request_for_another_physical_device_fails_before_glif_write() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (_client, id) = open_client(&mut server, &dir, 0);
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(7);
        let request = SdkApiRequest {
            command: SdkCommand::PsInit as u16,
            device_id: 8,
            params: &[],
        };
        assert!(matches!(
            bridge.handle_sdk_api(&mut server, &mut modem, id, request),
            Err(HandleError::UnknownDevice {
                requested: 8,
                expected: 7,
            })
        ));
        assert_eq!(read_api_ret(&mut server, id), 1);
        assert_eq!(bridge.pending_count(), 0);
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            Vec::<u8>::new()
        );
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
        let (_client, id) = open_client(&mut server, &dir, 0);
        let mut modem = Modem::new(HciIo::new(FailingWriter));
        let mut bridge = DeviceBridge::new(1);
        let request = SdkApiRequest {
            command: SdkCommand::Online as u16,
            device_id: 1,
            params: &[],
        };
        assert!(matches!(
            bridge.handle_sdk_api(&mut server, &mut modem, id, request),
            Err(HandleError::Tracked(_))
        ));
        assert_eq!(read_api_ret(&mut server, id), 1);
    }

    #[test]
    fn unsupported_call_is_released_with_failure_status() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (_client, id) = open_client(&mut server, &dir, 0);
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(1);
        let params = [0_u8; 352];
        let request = SdkApiRequest {
            command: SdkCommand::Attach as u16,
            device_id: 1,
            params: &params,
        };
        assert!(matches!(
            bridge.handle_sdk_api(&mut server, &mut modem, id, request),
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
        let (_client, id) = open_client(&mut server, &dir, 0);
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(1);
        let request = SdkApiRequest {
            command: SdkCommand::PsInit as u16,
            device_id: 1,
            params: &[0xaa],
        };
        assert!(matches!(
            bridge.handle_sdk_api(&mut server, &mut modem, id, request),
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
