//! Minimal modem runtime over the proven GCT GLIF transport.
//!
//! This crate intentionally stops below the OEM `lted` compatibility layer.
//! It owns byte-stream buffering, the live SDK startup handshake and dispatch
//! of complete borrowed HCI packets. Higher layers can build request/response
//! correlation and client APIs without duplicating transport state.

use std::{
    fs::{self, File},
    io::{self, Read, Write},
    path::Path,
};

use gct_hci::{EncodeError, Header, Packet, public_opcode, recovered_opcode};
use gct_lapi::{
    AtCommand, AtCommandExt, AtCommandFromDevice, AtCommandFromDeviceExt, AttachEncodeError,
    AttachExtEncodeError, AttachExtRequest, AttachExtResponse, AttachRequest, AttachResponse,
    AttachResponseDecodeError, DetachRequest, DetachRequiredIndication, DetachResponse,
    EmmControlDecodeError, EmmControlReport, EmmControlResponse, EmmNiReattachControlRequest,
    EmmReattachControlReport, EmmTimerControlRequest, EmmTimerStartRequest, EmptyRequest,
    IccidReadRequest, IccidReadResponse, LcsControlRequest, LppControlRequest, MiscReadDecodeError,
    MiscReadResponse, MobileIdReadRequest, MobileIdReadResponse, MsisdnReadRequest,
    MsisdnReadResponse, PdnConnectExtRequest, PdnConnectExtResponse, PdnConnectRequest,
    PdnConnectResponse, PdnDisconnectRequest, PdnDisconnectResponse, PdnEncodeError,
    PdnResponseDecodeError, PlmnListResponse, PlmnSearchDecodeError, PlmnSearchExtEncodeError,
    PlmnSearchExtRequest, PlmnSearchRequest, PlmnSearchResponse, PlmnSearchStopRequest,
    PlmnSearchStopResponse, PsmControlRequest, ResponseDecodeError, ResultResponse,
    ResultResponseKind, RrcCapabilityGetRequest, RrcCapabilityGetResponse, RrcCapabilitySetRequest,
    RrcCapabilitySetResponse, SetProtocolInfoRequest, SetProtocolInfoResponse,
    TemperatureReadRequest, TemperatureReadResponse, UeModeChangeRequest, UeModeChangeResponse,
    UiccAuthenticateEncodeError, UiccAuthenticateRequest, UiccFixedRequest, UiccFixedRequestError,
    UiccPinCommandRequest, UiccPinEncodeError, UiccPinStatusRequest, UiccReadBinaryRequest,
    UiccReadRecordRequest, UiccResponse, UiccResponseDecodeError, UiccStatusRequest, uicc_control,
};
use gct_transport::{
    GlifTransport, HciIo, HciStreamDecoder, MAX_HCI_FRAME_LEN, OEM_READ_BUFFER_LEN,
};

/// Linux interface selected by the OEM startup detector.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StartupInterface {
    pub name: String,
    pub modem_index: u32,
}

/// Parse one interface name accepted by the clean form of the OEM detector.
///
/// Live P4 scans `/proc/net/dev` for `lte%dpdn%d` and only initializes entries
/// whose PDN index is zero. The clean parser deliberately requires the whole
/// interface name to match instead of accepting trailing garbage after the
/// second decimal number as `sscanf` would.
#[must_use]
pub fn parse_startup_interface_name(name: &str) -> Option<StartupInterface> {
    let rest = name.strip_prefix("lte")?;
    let (modem, pdn) = rest.split_once("pdn")?;
    if modem.is_empty() || pdn.is_empty() || !modem.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    if !pdn.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let modem_index = modem.parse::<u32>().ok()?;
    let pdn_index = pdn.parse::<u32>().ok()?;
    if pdn_index != 0 {
        return None;
    }
    Some(StartupInterface {
        name: name.to_owned(),
        modem_index,
    })
}

/// Find the first OEM primary LTE interface in already-read `/proc/net/dev`
/// text, preserving kernel listing order.
#[must_use]
pub fn find_startup_interface(net_dev: &str) -> Option<StartupInterface> {
    net_dev.lines().find_map(|line| {
        let (name, _) = line.split_once(':')?;
        parse_startup_interface_name(name.trim())
    })
}

/// Discover the first `lteNpdn0` interface exactly as required before the OEM
/// SDK starts its modem receive thread.
///
/// The historical SDK then issues private ioctl `0x8d10/7` on this interface.
/// The recovered live driver implementation only copies two zero bytes back and
/// returns success, so the clean safe runtime treats successful interface
/// discovery as the meaningful readiness condition and does not reproduce that
/// no-op pointer-bearing ioctl.
///
/// # Errors
/// Returns an I/O error when `/proc/net/dev` cannot be read, or `NotFound` when
/// no primary LTE interface is present.
pub fn discover_startup_interface() -> io::Result<StartupInterface> {
    let net_dev = fs::read_to_string("/proc/net/dev")?;
    find_startup_interface(&net_dev).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "no OEM LTE primary interface matching lteNpdn0",
        )
    })
}

/// Verify a caller-selected startup interface against the live kernel table and
/// the recovered OEM `lteNpdn0` naming grammar.
///
/// # Errors
/// Returns `InvalidInput` for a non-primary/non-OEM name, an I/O error if the
/// kernel interface table cannot be read, or `NotFound` if the named interface
/// is not currently present.
pub fn verify_startup_interface(name: &str) -> io::Result<StartupInterface> {
    let parsed = parse_startup_interface_name(name).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "startup interface must match lteNpdn0",
        )
    })?;
    let net_dev = fs::read_to_string("/proc/net/dev")?;
    let present = net_dev.lines().any(|line| {
        line.split_once(':')
            .is_some_and(|(candidate, _)| candidate.trim() == name)
    });
    if !present {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("startup interface {name} is not present"),
        ));
    }
    Ok(parsed)
}

/// Result of one blocking read/dispatch iteration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PollOutcome {
    /// Raw bytes returned by the underlying GLIF read.
    pub bytes_read: usize,
    /// Complete HCI packets dispatched from this read plus any buffered suffix.
    pub packets_dispatched: usize,
}

/// Typed inbound events for the proven Stage-2/P0 modem surface.
///
/// Unknown opcodes are deliberately preserved as raw borrowed packets. A
/// malformed packet carrying a *known* opcode is instead returned as
/// [`EventDecodeError`], so protocol drift cannot silently masquerade as an
/// unsupported event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModemEvent<'a> {
    Attach(AttachResponse<'a>),
    AttachExt(AttachExtResponse<'a>),
    Detach(DetachResponse),
    DetachRequired(DetachRequiredIndication),
    PdnConnect(PdnConnectResponse<'a>),
    PdnConnectExt(PdnConnectExtResponse<'a>),
    PdnDisconnect(PdnDisconnectResponse<'a>),
    PlmnSearch(PlmnSearchResponse<'a>),
    PlmnSearchStop(PlmnSearchStopResponse),
    PlmnList(PlmnListResponse<'a>),
    MobileIdRead(MobileIdReadResponse<'a>),
    IccidRead(IccidReadResponse<'a>),
    MsisdnRead(MsisdnReadResponse<'a>),
    TemperatureRead(TemperatureReadResponse),
    UeModeChange(UeModeChangeResponse),
    EmmNiReattachControl {
        result: u32,
    },
    EmmReattachControlReport(EmmReattachControlReport),
    MiscReadFailure {
        read_result: u16,
    },
    Result {
        kind: ResultResponseKind,
        response: ResultResponse,
    },
    At(AtCommandFromDevice<'a>),
    AtExt(AtCommandFromDeviceExt<'a>),
    Uicc(UiccResponse<'a>),
    RrcCapabilitySet(RrcCapabilitySetResponse<'a>),
    RrcCapabilityGet(RrcCapabilityGetResponse<'a>),
    SetProtocolInfo(SetProtocolInfoResponse<'a>),
    Unknown(Packet<'a>),
}

/// Failure while decoding a packet whose opcode belongs to the proven P0
/// surface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventDecodeError {
    Response(ResponseDecodeError),
    Attach(AttachResponseDecodeError),
    Pdn(PdnResponseDecodeError),
    PlmnSearch(PlmnSearchDecodeError),
    MiscRead(MiscReadDecodeError),
    Uicc(UiccResponseDecodeError),
    EmmControl(EmmControlDecodeError),
}

/// Typed outbound commands with fully recovered request encoders.
///
/// Request families remain absent until their executable wire grammar is
/// independently recovered; known opcode adjacency alone is not sufficient.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModemCommand<'a> {
    Attach(AttachRequest<'a>),
    AttachExt(AttachExtRequest<'a>),
    Detach(DetachRequest),
    PdnConnect(PdnConnectRequest<'a>),
    PdnConnectExt(PdnConnectExtRequest<'a>),
    PdnDisconnect(PdnDisconnectRequest<'a>),
    PlmnSearch(PlmnSearchRequest),
    PlmnSearchExt(PlmnSearchExtRequest<'a>),
    PlmnSearchStop(PlmnSearchStopRequest),
    MobileIdRead(MobileIdReadRequest),
    IccidRead(IccidReadRequest),
    MsisdnRead(MsisdnReadRequest),
    TemperatureRead(TemperatureReadRequest),
    UeModeChange(UeModeChangeRequest),
    EmmTimerControl(EmmTimerControlRequest),
    EmmTimerStart(EmmTimerStartRequest),
    PsmControl(PsmControlRequest),
    LcsControl(LcsControlRequest),
    LppControl(LppControlRequest),
    EmmNiReattachControl(EmmNiReattachControlRequest),
    Empty(EmptyRequest),
    At(AtCommand<'a>),
    AtExt(AtCommandExt<'a>),
    UiccStatus(UiccStatusRequest),
    UiccFixed(UiccFixedRequest<'a>),
    UiccReadBinary(UiccReadBinaryRequest),
    UiccReadRecord(UiccReadRecordRequest),
    UiccAuthenticate(UiccAuthenticateRequest<'a>),
    UiccPinStatus(UiccPinStatusRequest),
    UiccPinCommand(UiccPinCommandRequest<'a>),
    RrcCapabilitySet(RrcCapabilitySetRequest<'a>),
    RrcCapabilityGet(RrcCapabilityGetRequest),
    SetProtocolInfo(SetProtocolInfoRequest<'a>),
}

/// Identity available on both sides of a proven request/response exchange.
///
/// Exact transaction IDs are used only where the recovered modem response
/// actually carries them. Families without a wire identity deliberately use a
/// family-level key, preventing two indistinguishable requests from being
/// tracked concurrently.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseKey {
    Attach(u8),
    AttachExt,
    Detach,
    PdnConnect(u8),
    PdnConnectExt,
    PdnDisconnect(u8),
    PlmnSearch,
    PlmnSearchStop(u8),
    PlmnList,
    MiscRead,
    UeModeChange,
    EmmNiReattachControl,
    Result(ResultResponseKind),
    Uicc(u16),
    RrcCapabilitySet(u16),
    RrcCapabilityGet(u16),
    SetProtocolInfo(u16),
}

impl ModemCommand<'_> {
    /// Response identity recoverable for this command.
    ///
    /// AT commands intentionally return `None`: their response stream has no
    /// recovered request identifier and may produce multiple asynchronous AT
    /// chunks.
    #[must_use]
    pub const fn response_key(self) -> Option<ResponseKey> {
        match self {
            Self::Attach(request) => Some(ResponseKey::Attach(request.transaction_id)),
            Self::AttachExt(_) => Some(ResponseKey::AttachExt),
            Self::Detach(_) => Some(ResponseKey::Detach),
            Self::PdnConnect(request) => Some(ResponseKey::PdnConnect(request.transaction_id)),
            Self::PdnConnectExt(_) => Some(ResponseKey::PdnConnectExt),
            Self::PdnDisconnect(request) => {
                Some(ResponseKey::PdnDisconnect(request.transaction_id))
            }
            Self::PlmnSearch(_) | Self::PlmnSearchExt(_) => Some(ResponseKey::PlmnSearch),
            Self::PlmnSearchStop(request) => Some(ResponseKey::PlmnSearchStop(request.search_type)),
            Self::MobileIdRead(_)
            | Self::IccidRead(_)
            | Self::MsisdnRead(_)
            | Self::TemperatureRead(_) => Some(ResponseKey::MiscRead),
            Self::UeModeChange(_) => Some(ResponseKey::UeModeChange),
            Self::EmmNiReattachControl(_) => Some(ResponseKey::EmmNiReattachControl),
            Self::Empty(EmptyRequest::PlmnList) => Some(ResponseKey::PlmnList),
            Self::Empty(EmptyRequest::Online) => {
                Some(ResponseKey::Result(ResultResponseKind::Online))
            }
            Self::Empty(EmptyRequest::Offline) => {
                Some(ResponseKey::Result(ResultResponseKind::Offline))
            }
            Self::Empty(EmptyRequest::PsInit) => {
                Some(ResponseKey::Result(ResultResponseKind::PsInit))
            }
            Self::At(_)
            | Self::AtExt(_)
            | Self::EmmTimerControl(_)
            | Self::EmmTimerStart(_)
            | Self::PsmControl(_)
            | Self::LcsControl(_)
            | Self::LppControl(_) => None,
            Self::UiccStatus(_) => Some(ResponseKey::Uicc(uicc_control::STATUS)),
            Self::UiccFixed(request) => Some(ResponseKey::Uicc(request.kind())),
            Self::UiccReadBinary(_) => Some(ResponseKey::Uicc(uicc_control::READ_BINARY)),
            Self::UiccReadRecord(_) => Some(ResponseKey::Uicc(uicc_control::READ_RECORD)),
            Self::UiccAuthenticate(_) => Some(ResponseKey::Uicc(uicc_control::AUTHENTICATE)),
            Self::UiccPinStatus(_) => Some(ResponseKey::Uicc(uicc_control::PIN_STATUS)),
            Self::UiccPinCommand(_) => Some(ResponseKey::Uicc(uicc_control::PIN_COMMAND)),
            Self::RrcCapabilitySet(request) => Some(ResponseKey::RrcCapabilitySet(request.type_id)),
            Self::RrcCapabilityGet(request) => Some(ResponseKey::RrcCapabilityGet(request.type_id)),
            Self::SetProtocolInfo(request) => Some(ResponseKey::SetProtocolInfo(request.type_id)),
        }
    }
}

impl ModemEvent<'_> {
    /// Request identity carried or implied by this inbound event.
    ///
    /// Matching does not imply completion: PLMN search/list responses can be
    /// multipart, so pending lifetime remains an explicit higher-layer choice.
    #[must_use]
    pub const fn response_key(&self) -> Option<ResponseKey> {
        match self {
            Self::Attach(response) => Some(ResponseKey::Attach(response.transaction_id)),
            Self::AttachExt(_) => Some(ResponseKey::AttachExt),
            Self::DetachRequired(_)
            | Self::At(_)
            | Self::AtExt(_)
            | Self::EmmReattachControlReport(_)
            | Self::Unknown(_) => None,
            Self::Detach(_) => Some(ResponseKey::Detach),
            Self::PdnConnect(response) => Some(ResponseKey::PdnConnect(response.transaction_id)),
            Self::PdnConnectExt(_) => Some(ResponseKey::PdnConnectExt),
            Self::PdnDisconnect(response) => {
                Some(ResponseKey::PdnDisconnect(response.transaction_id))
            }
            Self::PlmnSearch(_) => Some(ResponseKey::PlmnSearch),
            Self::PlmnSearchStop(response) => {
                Some(ResponseKey::PlmnSearchStop(response.search_type))
            }
            Self::PlmnList(_) => Some(ResponseKey::PlmnList),
            Self::MobileIdRead(_)
            | Self::IccidRead(_)
            | Self::MsisdnRead(_)
            | Self::TemperatureRead(_)
            | Self::MiscReadFailure { .. } => Some(ResponseKey::MiscRead),
            Self::UeModeChange(_) => Some(ResponseKey::UeModeChange),
            Self::EmmNiReattachControl { .. } => Some(ResponseKey::EmmNiReattachControl),
            Self::Result { kind, .. } => Some(ResponseKey::Result(*kind)),
            Self::Uicc(response) => Some(ResponseKey::Uicc(response.kind)),
            Self::RrcCapabilitySet(response) => {
                Some(ResponseKey::RrcCapabilitySet(response.type_id))
            }
            Self::RrcCapabilityGet(response) => {
                Some(ResponseKey::RrcCapabilityGet(response.type_id))
            }
            Self::SetProtocolInfo(response) => Some(ResponseKey::SetProtocolInfo(response.type_id)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PendingError {
    AlreadyPending(ResponseKey),
}

/// Conservative ledger of response identities currently in flight.
///
/// It never guesses when an exchange is terminal. Callers can match events and
/// explicitly remove a key once the command-specific state machine proves the
/// exchange complete.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct PendingRequests {
    keys: Vec<ResponseKey>,
}

impl PendingRequests {
    #[must_use]
    pub const fn new() -> Self {
        Self { keys: Vec::new() }
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.keys.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    #[must_use]
    pub fn contains(&self, key: ResponseKey) -> bool {
        self.keys.contains(&key)
    }

    /// # Errors
    /// Returns [`PendingError::AlreadyPending`] for an indistinguishable
    /// request already in flight.
    pub fn try_insert(&mut self, key: ResponseKey) -> Result<(), PendingError> {
        if self.contains(key) {
            return Err(PendingError::AlreadyPending(key));
        }
        self.keys.push(key);
        Ok(())
    }

    pub fn remove(&mut self, key: ResponseKey) -> bool {
        let Some(index) = self.keys.iter().position(|candidate| *candidate == key) else {
            return false;
        };
        self.keys.remove(index);
        true
    }

    #[must_use]
    pub fn matching_event(&self, event: &ModemEvent<'_>) -> Option<ResponseKey> {
        let key = event.response_key()?;
        self.contains(key).then_some(key)
    }

    fn insert_unchecked(&mut self, key: ResponseKey) {
        self.keys.push(key);
    }
}

/// Encoding failure from one of the proven typed request families.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandEncodeError {
    Hci(EncodeError),
    Attach(AttachEncodeError),
    AttachExt(AttachExtEncodeError),
    Pdn(PdnEncodeError),
    PlmnSearchExt(PlmnSearchExtEncodeError),
    UiccAuthenticate(UiccAuthenticateEncodeError),
    UiccFixed(UiccFixedRequestError),
    UiccPin(UiccPinEncodeError),
}

impl From<EncodeError> for CommandEncodeError {
    fn from(value: EncodeError) -> Self {
        Self::Hci(value)
    }
}

impl From<AttachEncodeError> for CommandEncodeError {
    fn from(value: AttachEncodeError) -> Self {
        Self::Attach(value)
    }
}

impl From<AttachExtEncodeError> for CommandEncodeError {
    fn from(value: AttachExtEncodeError) -> Self {
        Self::AttachExt(value)
    }
}

impl From<PdnEncodeError> for CommandEncodeError {
    fn from(value: PdnEncodeError) -> Self {
        Self::Pdn(value)
    }
}

impl From<PlmnSearchExtEncodeError> for CommandEncodeError {
    fn from(value: PlmnSearchExtEncodeError) -> Self {
        Self::PlmnSearchExt(value)
    }
}

impl From<UiccAuthenticateEncodeError> for CommandEncodeError {
    fn from(value: UiccAuthenticateEncodeError) -> Self {
        Self::UiccAuthenticate(value)
    }
}

impl From<UiccFixedRequestError> for CommandEncodeError {
    fn from(value: UiccFixedRequestError) -> Self {
        Self::UiccFixed(value)
    }
}

impl From<UiccPinEncodeError> for CommandEncodeError {
    fn from(value: UiccPinEncodeError) -> Self {
        Self::UiccPin(value)
    }
}

/// Failure while encoding or writing a typed modem command.
#[derive(Debug)]
pub enum SendCommandError {
    Encode(CommandEncodeError),
    Io(io::Error),
}

impl From<CommandEncodeError> for SendCommandError {
    fn from(value: CommandEncodeError) -> Self {
        Self::Encode(value)
    }
}

impl From<io::Error> for SendCommandError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// Failure while checking pending identity or sending a tracked command.
#[derive(Debug)]
pub enum SendTrackedCommandError {
    Pending(PendingError),
    Send(SendCommandError),
}

impl From<PendingError> for SendTrackedCommandError {
    fn from(value: PendingError) -> Self {
        Self::Pending(value)
    }
}

impl From<SendCommandError> for SendTrackedCommandError {
    fn from(value: SendCommandError) -> Self {
        Self::Send(value)
    }
}

/// Encode one typed command into caller-owned storage.
///
/// # Errors
/// Returns the command family's validated encoding error. No bytes are written
/// beyond the returned encoded prefix.
pub fn encode_command(
    command: ModemCommand<'_>,
    output: &mut [u8],
) -> Result<usize, CommandEncodeError> {
    match command {
        ModemCommand::Attach(request) => Ok(request.encode(output)?),
        ModemCommand::AttachExt(request) => Ok(request.encode(output)?),
        ModemCommand::Detach(request) => Ok(request.encode(output)?),
        ModemCommand::PdnConnect(request) => Ok(request.encode(output)?),
        ModemCommand::PdnConnectExt(request) => Ok(request.encode(output)?),
        ModemCommand::PdnDisconnect(request) => Ok(request.encode(output)?),
        ModemCommand::PlmnSearch(request) => Ok(request.encode(output)?),
        ModemCommand::PlmnSearchExt(request) => Ok(request.encode(output)?),
        ModemCommand::PlmnSearchStop(request) => Ok(request.encode(output)?),
        ModemCommand::MobileIdRead(request) => Ok(request.encode(output)?),
        ModemCommand::IccidRead(request) => Ok(request.encode(output)?),
        ModemCommand::MsisdnRead(request) => Ok(request.encode(output)?),
        ModemCommand::TemperatureRead(request) => Ok(request.encode(output)?),
        ModemCommand::UeModeChange(request) => Ok(request.encode(output)?),
        ModemCommand::EmmTimerControl(request) => Ok(request.encode(output)?),
        ModemCommand::EmmTimerStart(request) => Ok(request.encode(output)?),
        ModemCommand::PsmControl(request) => Ok(request.encode(output)?),
        ModemCommand::LcsControl(request) => Ok(request.encode(output)?),
        ModemCommand::LppControl(request) => Ok(request.encode(output)?),
        ModemCommand::EmmNiReattachControl(request) => Ok(request.encode(output)?),
        ModemCommand::Empty(request) => Ok(request.encode(output)?),
        ModemCommand::At(request) => Ok(request.encode(output)?),
        ModemCommand::AtExt(request) => Ok(request.encode(output)?),
        ModemCommand::UiccStatus(request) => Ok(request.encode(output)?),
        ModemCommand::UiccFixed(request) => Ok(request.encode(output)?),
        ModemCommand::UiccReadBinary(request) => Ok(request.encode(output)?),
        ModemCommand::UiccReadRecord(request) => Ok(request.encode(output)?),
        ModemCommand::UiccAuthenticate(request) => Ok(request.encode(output)?),
        ModemCommand::UiccPinStatus(request) => Ok(request.encode(output)?),
        ModemCommand::UiccPinCommand(request) => Ok(request.encode(output)?),
        ModemCommand::RrcCapabilitySet(request) => Ok(request.encode(output)?),
        ModemCommand::RrcCapabilityGet(request) => Ok(request.encode(output)?),
        ModemCommand::SetProtocolInfo(request) => Ok(request.encode(output)?),
    }
}

impl From<AttachResponseDecodeError> for EventDecodeError {
    fn from(value: AttachResponseDecodeError) -> Self {
        Self::Attach(value)
    }
}

impl From<ResponseDecodeError> for EventDecodeError {
    fn from(value: ResponseDecodeError) -> Self {
        Self::Response(value)
    }
}

impl From<PdnResponseDecodeError> for EventDecodeError {
    fn from(value: PdnResponseDecodeError) -> Self {
        Self::Pdn(value)
    }
}

impl From<PlmnSearchDecodeError> for EventDecodeError {
    fn from(value: PlmnSearchDecodeError) -> Self {
        Self::PlmnSearch(value)
    }
}

impl From<MiscReadDecodeError> for EventDecodeError {
    fn from(value: MiscReadDecodeError) -> Self {
        Self::MiscRead(value)
    }
}

impl From<UiccResponseDecodeError> for EventDecodeError {
    fn from(value: UiccResponseDecodeError) -> Self {
        Self::Uicc(value)
    }
}

/// Decode one complete HCI packet into the proven typed P0 surface.
///
/// Unknown opcodes remain available through [`ModemEvent::Unknown`]. Known
/// opcodes must satisfy their recovered wire grammar.
///
/// # Errors
/// Returns [`EventDecodeError`] when a packet uses a known opcode but violates
/// the corresponding recovered response layout.
pub fn decode_event(packet: Packet<'_>) -> Result<ModemEvent<'_>, EventDecodeError> {
    match packet.header.command {
        recovered_opcode::ATTACH_RESPONSE => Ok(ModemEvent::Attach(AttachResponse::parse(packet)?)),
        recovered_opcode::ATTACH_RESPONSE_EXT => {
            Ok(ModemEvent::AttachExt(AttachExtResponse::parse(packet)?))
        }
        recovered_opcode::DETACH_RESPONSE => Ok(ModemEvent::Detach(DetachResponse::parse(packet)?)),
        recovered_opcode::DETACH_REQUIRED_INDICATION => Ok(ModemEvent::DetachRequired(
            DetachRequiredIndication::parse(packet)?,
        )),
        recovered_opcode::PDN_CONNECT_RESPONSE => {
            Ok(ModemEvent::PdnConnect(PdnConnectResponse::parse(packet)?))
        }
        recovered_opcode::PDN_CONNECT_RESPONSE_EXT => Ok(ModemEvent::PdnConnectExt(
            PdnConnectExtResponse::parse(packet)?,
        )),
        recovered_opcode::PDN_DISCONNECT_RESPONSE => Ok(ModemEvent::PdnDisconnect(
            PdnDisconnectResponse::parse(packet)?,
        )),
        recovered_opcode::PLMN_SEARCH_RESPONSE => {
            Ok(ModemEvent::PlmnSearch(PlmnSearchResponse::parse(packet)?))
        }
        recovered_opcode::PLMN_SEARCH_STOP_RESPONSE => Ok(ModemEvent::PlmnSearchStop(
            PlmnSearchStopResponse::parse(packet)?,
        )),
        recovered_opcode::PLMN_LIST_RESPONSE => {
            Ok(ModemEvent::PlmnList(PlmnListResponse::parse(packet)?))
        }
        recovered_opcode::ONLINE_RESPONSE => Ok(ModemEvent::Result {
            kind: ResultResponseKind::Online,
            response: ResultResponse::parse(ResultResponseKind::Online, packet)?,
        }),
        recovered_opcode::OFFLINE_RESPONSE => Ok(ModemEvent::Result {
            kind: ResultResponseKind::Offline,
            response: ResultResponse::parse(ResultResponseKind::Offline, packet)?,
        }),
        recovered_opcode::PS_INIT_RESPONSE => Ok(ModemEvent::Result {
            kind: ResultResponseKind::PsInit,
            response: ResultResponse::parse(ResultResponseKind::PsInit, packet)?,
        }),
        public_opcode::LTE_AT_CMD_FROM_DEVICE => {
            Ok(ModemEvent::At(AtCommandFromDevice::parse(packet)?))
        }
        public_opcode::LTE_AT_CMD_FROM_DEVICE_EXT => {
            Ok(ModemEvent::AtExt(AtCommandFromDeviceExt::parse(packet)?))
        }
        recovered_opcode::UICC_RESPONSE => Ok(ModemEvent::Uicc(UiccResponse::parse(packet)?)),
        recovered_opcode::UE_MODE_CHANGE_RESPONSE => Ok(ModemEvent::UeModeChange(
            UeModeChangeResponse::parse(packet)?,
        )),
        recovered_opcode::EMM_CONTROL_RESPONSE => {
            match EmmControlResponse::parse(packet).map_err(EventDecodeError::EmmControl)? {
                EmmControlResponse::NiReattach { result } => {
                    Ok(ModemEvent::EmmNiReattachControl { result })
                }
                EmmControlResponse::Unsupported { .. } => Ok(ModemEvent::Unknown(packet)),
            }
        }
        recovered_opcode::EMM_CONTROL_REPORT => match EmmControlReport::parse(packet)
            .map_err(EventDecodeError::EmmControl)?
        {
            EmmControlReport::Reattach(report) => Ok(ModemEvent::EmmReattachControlReport(report)),
            EmmControlReport::Unsupported { .. } => Ok(ModemEvent::Unknown(packet)),
        },
        recovered_opcode::RRC_CAPABILITY_CONTROL_RESPONSE => Ok(ModemEvent::RrcCapabilitySet(
            RrcCapabilitySetResponse::parse(packet)?,
        )),
        recovered_opcode::RRC_CAPABILITY_CONTROL_GET_RESPONSE => Ok(ModemEvent::RrcCapabilityGet(
            RrcCapabilityGetResponse::parse(packet)?,
        )),
        recovered_opcode::SET_PROTOCOL_INFO_RESPONSE => Ok(ModemEvent::SetProtocolInfo(
            SetProtocolInfoResponse::parse(packet)?,
        )),
        recovered_opcode::MISC_READ_RESPONSE => match MiscReadResponse::parse(packet)? {
            MiscReadResponse::MobileId(response) => Ok(ModemEvent::MobileIdRead(response)),
            MiscReadResponse::Iccid(response) => Ok(ModemEvent::IccidRead(response)),
            MiscReadResponse::Msisdn(response) => Ok(ModemEvent::MsisdnRead(response)),
            MiscReadResponse::Temperature(response) => Ok(ModemEvent::TemperatureRead(response)),
            MiscReadResponse::Failure { read_result } => {
                Ok(ModemEvent::MiscReadFailure { read_result })
            }
            MiscReadResponse::UnsupportedSuccess => Ok(ModemEvent::Unknown(packet)),
        },
        _ => Ok(ModemEvent::Unknown(packet)),
    }
}

/// Core modem runtime over an arbitrary bidirectional transport.
pub struct Modem<T> {
    transport: HciIo<T>,
    decoder: HciStreamDecoder,
    read_buffer: Vec<u8>,
    tx_buffer: Vec<u8>,
}

impl<T> Modem<T> {
    /// Construct a runtime using the live SDK's observed 32 KiB read size.
    #[must_use]
    pub fn new(transport: HciIo<T>) -> Self {
        Self {
            transport,
            decoder: HciStreamDecoder::new(),
            read_buffer: vec![0_u8; OEM_READ_BUFFER_LEN],
            tx_buffer: vec![0_u8; MAX_HCI_FRAME_LEN],
        }
    }

    /// Recover the underlying transport.
    #[must_use]
    pub fn into_transport(self) -> HciIo<T> {
        self.transport
    }

    /// Borrow the underlying transport.
    #[must_use]
    pub const fn transport(&self) -> &HciIo<T> {
        &self.transport
    }

    /// Mutably borrow the underlying transport.
    pub const fn transport_mut(&mut self) -> &mut HciIo<T> {
        &mut self.transport
    }

    /// Number of bytes retained because the final HCI frame is incomplete.
    #[must_use]
    pub const fn pending_rx_bytes(&self) -> usize {
        self.decoder.pending_len()
    }
}

impl Modem<File> {
    /// Open `/dev/glif0` and create the runtime.
    ///
    /// # Errors
    /// Returns the underlying [`io::Error`] when the character device cannot
    /// be opened read/write.
    pub fn open_default() -> io::Result<Self> {
        GlifTransport::open_default().map(Self::new)
    }

    /// Open a GLIF-compatible character device and create the runtime.
    ///
    /// # Errors
    /// Returns the underlying [`io::Error`] when `path` cannot be opened
    /// read/write.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        GlifTransport::open(path).map(Self::new)
    }
}

impl<T: Write> Modem<T> {
    /// Send the zero-payload `0x3337` command emitted by the live P4 SDK after
    /// its GLIF readiness probe.
    ///
    /// No matching response handler exists in the SDK dispatch table, so this
    /// is intentionally modeled as a fire-and-forget startup handshake.
    ///
    /// # Errors
    /// Returns the underlying transport [`io::Error`] if all four bytes cannot
    /// be written.
    pub fn send_startup_handshake(&mut self) -> io::Result<()> {
        let frame = Header {
            command: recovered_opcode::SDK_STARTUP_HANDSHAKE,
            payload_len: 0,
        }
        .encode();
        self.transport.write_bytes(&frame)
    }

    /// Write one caller-encoded HCI frame or batch unchanged.
    ///
    /// Typed LAPI encoders remain responsible for producing the wire bytes;
    /// this runtime does not silently normalize or rewrite requests.
    ///
    /// # Errors
    /// Returns the underlying transport [`io::Error`] if all bytes cannot be
    /// written.
    pub fn send_bytes(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.transport.write_bytes(bytes)
    }

    /// Encode and write one proven typed modem command using the runtime's
    /// reusable maximum-size HCI frame buffer.
    ///
    /// Encoding completes before the transport is touched, so validation
    /// failures cannot result in partial command writes.
    ///
    /// # Errors
    /// Returns [`SendCommandError::Encode`] for a rejected request shape or
    /// [`SendCommandError::Io`] if the encoded frame cannot be written fully.
    pub fn send_command(&mut self, command: ModemCommand<'_>) -> Result<usize, SendCommandError> {
        let encoded = encode_command(command, &mut self.tx_buffer)?;
        self.transport.write_bytes(&self.tx_buffer[..encoded])?;
        Ok(encoded)
    }

    /// Send a typed command while reserving its recoverable response identity.
    ///
    /// Duplicate checking happens before GLIF is touched. The key is inserted
    /// only after a successful full write.
    ///
    /// # Errors
    /// Returns a pending-identity collision or the normal encode/write error.
    pub fn send_tracked_command(
        &mut self,
        pending: &mut PendingRequests,
        command: ModemCommand<'_>,
    ) -> Result<usize, SendTrackedCommandError> {
        let key = command.response_key();
        if let Some(key) = key
            && pending.contains(key)
        {
            return Err(PendingError::AlreadyPending(key).into());
        }
        let written = self.send_command(command)?;
        if let Some(key) = key {
            pending.insert_unchecked(key);
        }
        Ok(written)
    }
}

impl<T: Read> Modem<T> {
    /// Perform one blocking transport read and dispatch every complete HCI
    /// packet made available by it.
    ///
    /// A partial trailing packet stays in the decoder until a later call.
    /// A zero-byte read is reported as such and dispatches no new packet.
    ///
    /// # Errors
    /// Returns the underlying [`io::Error`] from the GLIF read.
    pub fn poll_once<F>(&mut self, dispatch: F) -> io::Result<PollOutcome>
    where
        F: FnMut(Packet<'_>),
    {
        let bytes_read = self.transport.read_chunk(&mut self.read_buffer)?;
        let packets_dispatched = self.decoder.feed(&self.read_buffer[..bytes_read], dispatch);
        Ok(PollOutcome {
            bytes_read,
            packets_dispatched,
        })
    }

    /// Perform one blocking read and decode every complete packet into the
    /// proven typed P0 event surface.
    ///
    /// Decode failures are delivered to `dispatch` alongside valid events so
    /// one malformed event does not discard later complete frames from the
    /// same GLIF read.
    ///
    /// # Errors
    /// Returns the underlying [`io::Error`] from the GLIF read.
    pub fn poll_events_once<F>(&mut self, mut dispatch: F) -> io::Result<PollOutcome>
    where
        F: for<'a> FnMut(Result<ModemEvent<'a>, EventDecodeError>),
    {
        self.poll_once(|packet| dispatch(decode_event(packet)))
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use gct_hci::{Header, Packet, public_opcode, recovered_opcode};
    use gct_lapi::{
        AtCommand, AtCommandExt, AtCommandFromDevice, AttachExtProfile, AttachExtRequest,
        EmmNiReattachControlRequest, EmmTimerControlRequest, EmmTimerStartRequest, EmptyRequest,
        IccidReadRequest, LcsControlRequest, LppControlRequest, MobileIdReadRequest,
        MsisdnReadRequest, PcoInfo, PinData, PlmnSearchExtRequest, PlmnSearchRequest,
        PlmnSearchStopRequest, PsmControlRequest, ResponseDecodeError, ResultResponseKind,
        RrcCapabilityGetRequest, RrcCapabilitySetRequest, SetProtocolInfoRequest,
        TemperatureReadRequest, UiccPinCommandRequest,
    };
    use gct_transport::HciIo;

    use super::{
        CommandEncodeError, EventDecodeError, Modem, ModemCommand, ModemEvent, PendingError,
        PendingRequests, PollOutcome, ResponseKey, SendCommandError, SendTrackedCommandError,
        decode_event, encode_command,
    };

    #[test]
    fn startup_interface_parser_accepts_only_primary_oem_names() {
        assert_eq!(
            super::parse_startup_interface_name("lte0pdn0"),
            Some(super::StartupInterface {
                name: "lte0pdn0".to_owned(),
                modem_index: 0,
            })
        );
        assert_eq!(
            super::parse_startup_interface_name("lte12pdn0"),
            Some(super::StartupInterface {
                name: "lte12pdn0".to_owned(),
                modem_index: 12,
            })
        );
        assert_eq!(super::parse_startup_interface_name("lte0pdn1"), None);
        assert_eq!(super::parse_startup_interface_name("ltepdn0"), None);
        assert_eq!(super::parse_startup_interface_name("lte0pdn"), None);
        assert_eq!(super::parse_startup_interface_name("xlte0pdn0"), None);
        assert_eq!(super::parse_startup_interface_name("lte0pdn0junk"), None);
    }

    #[test]
    fn startup_interface_discovery_preserves_proc_listing_order() {
        let net_dev = "Inter-| Receive | Transmit\n\
                        face |bytes |bytes\n\
                         lo: 1 2\n\
                    lte3pdn1: 3 4\n\
                        eth0: 5 6\n\
                    lte2pdn0: 7 8\n\
                    lte0pdn0: 9 10\n";
        assert_eq!(
            super::find_startup_interface(net_dev),
            Some(super::StartupInterface {
                name: "lte2pdn0".to_owned(),
                modem_index: 2,
            })
        );
    }

    #[test]
    fn startup_interface_discovery_ignores_non_interface_text() {
        let net_dev = "header lte0pdn0 without colon\neth0: lte4pdn0 1 2\n";
        assert_eq!(super::find_startup_interface(net_dev), None);
    }

    #[test]
    fn startup_handshake_matches_live_p4_bytes() {
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        assert!(matches!(modem.send_startup_handshake(), Ok(())));
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            vec![0x33, 0x37, 0x00, 0x00]
        );
    }

    #[test]
    fn typed_send_encodes_multiple_command_families_into_one_reused_buffer() {
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);

        assert!(matches!(
            modem.send_command(ModemCommand::Empty(EmptyRequest::Online)),
            Ok(4)
        ));
        assert!(matches!(
            modem.send_command(ModemCommand::At(AtCommand::new(b"AT"))),
            Ok(7)
        ));

        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            vec![
                0x31, 0x21, 0x00, 0x00, // ONLINE
                0x33, 0x07, 0x00, 0x03, b'A', b'T', b'\n', // AT
            ]
        );
    }

    #[test]
    fn mobile_id_read_uses_shared_misc_family_for_send_success_and_failure() {
        let request = ModemCommand::MobileIdRead(MobileIdReadRequest { mobile_id_type: 3 });
        assert_eq!(request.response_key(), Some(ResponseKey::MiscRead));
        let mut encoded = [0_u8; 16];
        assert_eq!(encode_command(request, &mut encoded), Ok(9));
        assert_eq!(
            &encoded[..9],
            &[0x31, 0x45, 0x00, 0x05, 0x00, 0x01, 0x00, 0x01, 0x03]
        );

        let success_payload = [
            0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x03, 0x00, 0x05, b'1', b'2', b'3', b'4', b'5',
        ];
        let success = decode_event(Packet {
            header: Header {
                command: recovered_opcode::MISC_READ_RESPONSE,
                payload_len: 14,
            },
            payload: &success_payload,
        })
        .unwrap_or_else(|_| std::process::abort());
        assert_eq!(success.response_key(), Some(ResponseKey::MiscRead));
        assert!(matches!(
            success,
            ModemEvent::MobileIdRead(response)
                if response.id_type == 3 && response.result == 0 && response.id == b"12345"
        ));

        let failure_payload = [0x00, 0x07];
        let failure = decode_event(Packet {
            header: Header {
                command: recovered_opcode::MISC_READ_RESPONSE,
                payload_len: 2,
            },
            payload: &failure_payload,
        })
        .unwrap_or_else(|_| std::process::abort());
        assert_eq!(failure, ModemEvent::MiscReadFailure { read_result: 7 });
        assert_eq!(failure.response_key(), Some(ResponseKey::MiscRead));
    }

    #[test]
    fn runtime_tracks_extended_attach_as_single_family() {
        let profile = AttachExtProfile {
            ip_alloc: 0,
            apn_class: 0,
            apn: b"",
            pdn_type: 0,
            username: b"",
            password: b"",
            auth_flag: 0,
            pco: PcoInfo {
                first_pco: 0,
                second_pco: 0,
                n_pco: 0,
                first_os_pco: 0,
                second_os_pco: 0,
                third_os_pco: 0,
            },
        };
        let request = AttachExtRequest {
            optional_info: 0,
            primary: profile,
            retry: profile,
        };
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut pending = PendingRequests::new();

        assert!(matches!(
            modem.send_tracked_command(&mut pending, ModemCommand::AttachExt(request)),
            Ok(5)
        ));
        assert!(pending.contains(ResponseKey::AttachExt));
        assert!(matches!(
            modem.send_tracked_command(&mut pending, ModemCommand::AttachExt(request)),
            Err(SendTrackedCommandError::Pending(
                PendingError::AlreadyPending(ResponseKey::AttachExt)
            ))
        ));
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            vec![0x31, 0x65, 0x00, 0x01, 0x00]
        );
    }

    #[test]
    fn dormant_ext_search_response_is_not_promoted_without_live_product_wiring() {
        let packet = Packet {
            header: Header {
                command: recovered_opcode::PLMN_SEARCH_RESPONSE_EXT_DORMANT,
                payload_len: 0,
            },
            payload: &[],
        };
        assert_eq!(decode_event(packet), Ok(ModemEvent::Unknown(packet)));
    }

    #[test]
    fn extended_attach_response_matches_family_key() {
        let payload = [
            0, 1, 0, 2, 0x12, 0x34, 0x56, 0x78, 9, 10, 1, 2, 3, 4, 5, 0x20, 1, 7, 0x57, 0, 0x58, 0,
        ];
        let packet = Packet {
            header: Header {
                command: recovered_opcode::ATTACH_RESPONSE_EXT,
                payload_len: 22,
            },
            payload: &payload,
        };
        let Ok(event) = decode_event(packet) else {
            return;
        };
        assert_eq!(event.response_key(), Some(ResponseKey::AttachExt));
    }

    #[test]
    fn runtime_routes_extended_at_and_tracks_search_stop_by_type() {
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut pending = PendingRequests::new();

        assert!(matches!(
            modem.send_command(ModemCommand::AtExt(AtCommandExt::new(4, b"ATI"))),
            Ok(9)
        ));
        assert!(matches!(
            modem.send_tracked_command(
                &mut pending,
                ModemCommand::PlmnSearchStop(PlmnSearchStopRequest { search_type: 2 }),
            ),
            Ok(5)
        ));
        assert!(pending.contains(ResponseKey::PlmnSearchStop(2)));

        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            vec![
                0x33, 0x23, 0x00, 0x05, 4, b'A', b'T', b'I', b'\n', 0x31, 0x27, 0x00, 0x01, 2,
            ]
        );
    }

    #[test]
    fn extended_plmn_search_shares_normal_search_family_key() {
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut pending = PendingRequests::new();
        let request = PlmnSearchExtRequest {
            selection_mode: 0,
            operation_mode: 0,
            mcc: [0; 3],
            mnc: [0; 3],
            roaming_option: 2,
            list_count: 0,
            list_data: &[],
            power_scan: false,
        };
        assert!(matches!(
            modem.send_tracked_command(&mut pending, ModemCommand::PlmnSearchExt(request)),
            Ok(8)
        ));
        assert!(pending.contains(ResponseKey::PlmnSearch));

        let normal = PlmnSearchRequest {
            search_mode: 0,
            mcc: [0; 3],
            mnc: [0; 3],
            emergency_mode: 0,
            roaming_option: 0,
        };
        assert!(matches!(
            modem.send_tracked_command(&mut pending, ModemCommand::PlmnSearch(normal)),
            Err(SendTrackedCommandError::Pending(
                PendingError::AlreadyPending(ResponseKey::PlmnSearch)
            ))
        ));
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            vec![0x31, 0x5a, 0x00, 0x04, 0x00, 0x00, 0x63, 0x02]
        );
    }

    #[test]
    fn stop_response_matches_tracked_search_type() {
        let payload = [2, 0, 0, 0, 0];
        let packet = Packet {
            header: Header {
                command: recovered_opcode::PLMN_SEARCH_STOP_RESPONSE,
                payload_len: 5,
            },
            payload: &payload,
        };
        let event = decode_event(packet);
        let Ok(event) = event else {
            return;
        };
        assert_eq!(event.response_key(), Some(ResponseKey::PlmnSearchStop(2)));
    }

    #[test]
    fn typed_send_validates_before_touching_transport() {
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let oversized_pin = [b'1'; 9];
        let request = UiccPinCommandRequest {
            pin_type: 1,
            pin_command: 2,
            old_pin: PinData {
                code: &oversized_pin,
            },
            new_pin: PinData { code: b"" },
        };

        assert!(matches!(
            modem.send_command(ModemCommand::UiccPinCommand(request)),
            Err(SendCommandError::Encode(CommandEncodeError::UiccPin(_)))
        ));
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn normal_attach_event_exposes_wire_transaction_identity() {
        let payload = [
            0x00, 0x01, 0x00, 0x02, 0x12, 0x34, 0x56, 0x78, 0x09, 0x0a, 1, 2, 3, 4, 5, 0x20, 0x01,
            0x2a,
        ];
        let packet = Packet {
            header: Header {
                command: recovered_opcode::ATTACH_RESPONSE,
                payload_len: 18,
            },
            payload: &payload,
        };
        let event = decode_event(packet);
        let Ok(event) = event else {
            return;
        };
        assert_eq!(event.response_key(), Some(ResponseKey::Attach(0x2a)));
    }

    #[test]
    fn pending_ledger_distinguishes_exact_ids_but_rejects_family_duplicates() {
        let mut pending = PendingRequests::new();
        assert_eq!(pending.try_insert(ResponseKey::PdnConnect(1)), Ok(()));
        assert_eq!(pending.try_insert(ResponseKey::PdnConnect(2)), Ok(()));
        assert_eq!(pending.try_insert(ResponseKey::PlmnSearch), Ok(()));
        assert_eq!(
            pending.try_insert(ResponseKey::PlmnSearch),
            Err(PendingError::AlreadyPending(ResponseKey::PlmnSearch))
        );
        assert_eq!(pending.len(), 3);
        assert!(pending.remove(ResponseKey::PdnConnect(1)));
        assert!(!pending.remove(ResponseKey::PdnConnect(99)));
    }

    #[test]
    fn tracked_send_rejects_duplicate_before_writing_and_requires_explicit_completion() {
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut pending = PendingRequests::new();

        assert!(matches!(
            modem.send_tracked_command(&mut pending, ModemCommand::Empty(EmptyRequest::Online)),
            Ok(4)
        ));
        assert!(matches!(
            modem.send_tracked_command(&mut pending, ModemCommand::Empty(EmptyRequest::Online)),
            Err(SendTrackedCommandError::Pending(
                PendingError::AlreadyPending(ResponseKey::Result(ResultResponseKind::Online))
            ))
        ));
        assert_eq!(pending.len(), 1);
        assert!(pending.remove(ResponseKey::Result(ResultResponseKind::Online)));
        assert!(matches!(
            modem.send_tracked_command(&mut pending, ModemCommand::Empty(EmptyRequest::Online)),
            Ok(4)
        ));
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            vec![0x31, 0x21, 0x00, 0x00, 0x31, 0x21, 0x00, 0x00,]
        );
    }

    #[test]
    fn request_only_emm_controls_have_no_response_key() {
        let mut timer_bytes = [0_u8; 12];
        assert_eq!(
            encode_command(
                ModemCommand::EmmTimerControl(EmmTimerControlRequest {
                    timer_id: 0x1234,
                    timer_value_unit: 5,
                    timer_value: 6,
                }),
                &mut timer_bytes,
            ),
            Ok(12)
        );
        assert_eq!(
            timer_bytes,
            [
                0x31, 0x55, 0x00, 0x08, 0x00, 0x07, 0x00, 0x04, 0x12, 0x34, 5, 6
            ]
        );
        assert_eq!(
            ModemCommand::EmmTimerControl(EmmTimerControlRequest {
                timer_id: 1,
                timer_value_unit: 2,
                timer_value: 3,
            })
            .response_key(),
            None
        );
        for command in [
            ModemCommand::EmmTimerStart(EmmTimerStartRequest { params: [1, 2, 3] }),
            ModemCommand::PsmControl(PsmControlRequest {
                ctrl_cmd: 1,
                t3324_timer_value_unit: 2,
                t3324_timer_value: 3,
                ext_t3412_timer_value_unit: 4,
                ext_t3412_timer_value: 5,
            }),
            ModemCommand::LcsControl(LcsControlRequest { mode: 6 }),
            ModemCommand::LppControl(LppControlRequest { mode: 7 }),
        ] {
            assert_eq!(command.response_key(), None);
        }
    }

    #[test]
    fn emm_control_tracking_and_decode_match_live_family_semantics() {
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut pending = PendingRequests::new();
        let command = ModemCommand::EmmNiReattachControl(EmmNiReattachControlRequest {
            control: 0x1122_3344,
        });
        assert!(matches!(
            modem.send_tracked_command(&mut pending, command),
            Ok(12)
        ));
        assert!(pending.contains(ResponseKey::EmmNiReattachControl));
        assert!(matches!(
            modem.send_tracked_command(&mut pending, command),
            Err(SendTrackedCommandError::Pending(
                PendingError::AlreadyPending(ResponseKey::EmmNiReattachControl)
            ))
        ));
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            vec![
                0x31, 0x55, 0x00, 0x08, 0x00, 0x0b, 0x00, 0x04, 0x11, 0x22, 0x33, 0x44
            ]
        );

        let ni_payload = [0, 0, 0, 11, 0, 4, 0x11, 0x22, 0x33, 0x44];
        let ni_packet = Packet {
            header: Header {
                command: recovered_opcode::EMM_CONTROL_RESPONSE,
                payload_len: 10,
            },
            payload: &ni_payload,
        };
        assert_eq!(
            decode_event(ni_packet),
            Ok(ModemEvent::EmmNiReattachControl {
                result: 0x1122_3344
            })
        );

        let report_payload = [0x12, 0x34, 0, 11, 0, 4, 0xaa, 0xbb, 0xcc, 0xdd];
        let report_packet = Packet {
            header: Header {
                command: recovered_opcode::EMM_CONTROL_REPORT,
                payload_len: 10,
            },
            payload: &report_payload,
        };
        assert_eq!(
            decode_event(report_packet),
            Ok(ModemEvent::EmmReattachControlReport(
                gct_lapi::EmmReattachControlReport {
                    prefix: 0x1234,
                    value: 0xaabb_ccdd,
                }
            ))
        );

        for kind in [7_u8, 8, 9, 10, 13] {
            let ignored_ack = [0, 0, 0, kind, 0, 4, 0, 0, 0, 1];
            let packet = Packet {
                header: Header {
                    command: recovered_opcode::EMM_CONTROL_RESPONSE,
                    payload_len: 10,
                },
                payload: &ignored_ack,
            };
            assert_eq!(decode_event(packet), Ok(ModemEvent::Unknown(packet)));
        }
    }

    #[test]
    fn msisdn_read_shares_misc_family_key_and_decodes_subtype_three() {
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut pending = PendingRequests::new();
        assert!(matches!(
            modem.send_tracked_command(&mut pending, ModemCommand::MsisdnRead(MsisdnReadRequest),),
            Ok(8)
        ));
        assert!(pending.contains(ResponseKey::MiscRead));
        assert!(matches!(
            modem.send_tracked_command(&mut pending, ModemCommand::IccidRead(IccidReadRequest)),
            Err(SendTrackedCommandError::Pending(
                PendingError::AlreadyPending(ResponseKey::MiscRead)
            ))
        ));
        assert!(matches!(
            modem.send_tracked_command(
                &mut pending,
                ModemCommand::TemperatureRead(TemperatureReadRequest),
            ),
            Err(SendTrackedCommandError::Pending(
                PendingError::AlreadyPending(ResponseKey::MiscRead)
            ))
        ));
        assert!(matches!(
            modem.send_tracked_command(
                &mut pending,
                ModemCommand::MobileIdRead(MobileIdReadRequest { mobile_id_type: 1 }),
            ),
            Err(SendTrackedCommandError::Pending(
                PendingError::AlreadyPending(ResponseKey::MiscRead)
            ))
        ));
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            vec![0x31, 0x45, 0, 4, 0, 3, 0, 0]
        );

        let mut payload = vec![0, 0, 0, 3, 0x01, 0x02, 0, 1];
        payload.extend_from_slice(&[0x5a; 256]);
        let packet = Packet {
            header: Header {
                command: recovered_opcode::MISC_READ_RESPONSE,
                payload_len: u16::try_from(payload.len()).unwrap_or_else(|_| std::process::abort()),
            },
            payload: &payload,
        };
        let Ok(ModemEvent::MsisdnRead(response)) = decode_event(packet) else {
            std::process::abort();
        };
        assert_eq!(response.num_msisdn(), 1);
        assert_eq!(
            ModemEvent::MsisdnRead(response).response_key(),
            Some(ResponseKey::MiscRead)
        );
    }

    #[test]
    fn ue_mode_change_is_tracked_and_decoded_as_one_family() {
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut pending = PendingRequests::new();
        let command = ModemCommand::UeModeChange(gct_lapi::UeModeChangeRequest { mode: 3 });
        assert!(matches!(
            modem.send_tracked_command(&mut pending, command),
            Ok(5)
        ));
        assert!(pending.contains(ResponseKey::UeModeChange));
        assert!(matches!(
            modem.send_tracked_command(&mut pending, command),
            Err(SendTrackedCommandError::Pending(
                PendingError::AlreadyPending(ResponseKey::UeModeChange)
            ))
        ));
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            vec![0x31, 0x18, 0x00, 0x01, 3]
        );

        let payload = [0x7f];
        let packet = Packet {
            header: Header {
                command: recovered_opcode::UE_MODE_CHANGE_RESPONSE,
                payload_len: 1,
            },
            payload: &payload,
        };
        assert_eq!(
            decode_event(packet),
            Ok(ModemEvent::UeModeChange(gct_lapi::UeModeChangeResponse {
                result: 0x7f,
            }))
        );
    }

    #[test]
    fn rrc_capability_tracks_by_type_and_decodes_both_response_families() {
        let set = ModemCommand::RrcCapabilitySet(RrcCapabilitySetRequest {
            type_id: 18,
            data: &[0xaa],
        });
        let get = ModemCommand::RrcCapabilityGet(RrcCapabilityGetRequest { type_id: 4 });
        assert_eq!(set.response_key(), Some(ResponseKey::RrcCapabilitySet(18)));
        assert_eq!(get.response_key(), Some(ResponseKey::RrcCapabilityGet(4)));

        let set_payload = [0, 0, 0, 0, 0, 18];
        let set_packet = Packet {
            header: Header {
                command: recovered_opcode::RRC_CAPABILITY_CONTROL_RESPONSE,
                payload_len: 6,
            },
            payload: &set_payload,
        };
        let Ok(set_event) = decode_event(set_packet) else {
            std::process::abort();
        };
        assert_eq!(
            set_event.response_key(),
            Some(ResponseKey::RrcCapabilitySet(18))
        );

        let get_payload = [0, 0, 0, 4, 0, 1, 7];
        let get_packet = Packet {
            header: Header {
                command: recovered_opcode::RRC_CAPABILITY_CONTROL_GET_RESPONSE,
                payload_len: 7,
            },
            payload: &get_payload,
        };
        let Ok(get_event) = decode_event(get_packet) else {
            std::process::abort();
        };
        assert_eq!(
            get_event.response_key(),
            Some(ResponseKey::RrcCapabilityGet(4))
        );
    }

    #[test]
    fn set_protocol_info_tracks_exact_type_and_decodes_live_response() {
        let command = ModemCommand::SetProtocolInfo(SetProtocolInfoRequest {
            type_id: 8,
            data: &[0x55],
        });
        assert_eq!(
            command.response_key(),
            Some(ResponseKey::SetProtocolInfo(8))
        );

        let payload = [0, 0, 0, 8, 0, 1, 0x55];
        let packet = Packet {
            header: Header {
                command: recovered_opcode::SET_PROTOCOL_INFO_RESPONSE,
                payload_len: 7,
            },
            payload: &payload,
        };
        let Ok(event) = decode_event(packet) else {
            std::process::abort();
        };
        assert_eq!(event.response_key(), Some(ResponseKey::SetProtocolInfo(8)));
    }

    #[test]
    fn typed_dispatch_keeps_unknown_distinct_from_malformed_known() {
        let unknown_payload = [0xaa, 0xbb];
        let unknown_packet = Packet {
            header: Header {
                command: 0xbeef,
                payload_len: 2,
            },
            payload: &unknown_payload,
        };
        assert_eq!(
            decode_event(unknown_packet),
            Ok(ModemEvent::Unknown(unknown_packet))
        );

        let malformed_payload = [0, 0, 0];
        let malformed_packet = Packet {
            header: Header {
                command: recovered_opcode::DETACH_REQUIRED_INDICATION,
                payload_len: 3,
            },
            payload: &malformed_payload,
        };
        assert_eq!(
            decode_event(malformed_packet),
            Err(EventDecodeError::Response(
                ResponseDecodeError::UnexpectedLength {
                    expected: 4,
                    actual: 3,
                }
            ))
        );
    }

    #[test]
    fn typed_dispatch_decodes_at_event_without_copying() {
        let payload = b"OK\r\n";
        let packet = Packet {
            header: Header {
                command: public_opcode::LTE_AT_CMD_FROM_DEVICE,
                payload_len: 4,
            },
            payload,
        };
        assert_eq!(
            decode_event(packet),
            Ok(ModemEvent::At(AtCommandFromDevice { command: payload }))
        );
    }

    #[test]
    fn one_poll_dispatches_a_concatenated_hci_batch() {
        let bytes = vec![
            0xb3, 0x08, 0x00, 0x02, b'O', b'K', 0xb3, 0x24, 0x00, 0x02, 0x03, b'X',
        ];
        let transport = HciIo::new(Cursor::new(bytes));
        let mut modem = Modem::new(transport);
        let mut seen = Vec::new();
        let outcome = modem.poll_once(|packet| {
            seen.push((packet.header.command, packet.payload.to_vec()));
        });

        assert!(matches!(
            outcome,
            Ok(PollOutcome {
                bytes_read: 12,
                packets_dispatched: 2,
            })
        ));
        assert_eq!(
            seen,
            vec![
                (public_opcode::LTE_AT_CMD_FROM_DEVICE, b"OK".to_vec()),
                (public_opcode::LTE_AT_CMD_FROM_DEVICE_EXT, vec![0x03, b'X'],),
            ]
        );
        assert_eq!(modem.pending_rx_bytes(), 0);
    }
}
