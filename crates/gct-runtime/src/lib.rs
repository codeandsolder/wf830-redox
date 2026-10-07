//! Minimal modem runtime over the proven GCT GLIF transport.
//!
//! This crate intentionally stops below the OEM `lted` compatibility layer.
//! It owns byte-stream buffering, the live SDK startup handshake and dispatch
//! of complete borrowed HCI packets. Higher layers can build request/response
//! correlation and client APIs without duplicating transport state.

use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

use gct_hci::{EncodeError, Header, Packet, public_opcode, recovered_opcode};
use gct_lapi::{
    AtCommand, AtCommandFromDevice, AtCommandFromDeviceExt, AttachEncodeError, AttachRequest,
    AttachResponseKind, AttachResponsePrefix, DetachRequest, DetachRequiredIndication,
    DetachResponse, EmptyRequest, PdnConnectExtRequest, PdnConnectExtResponse, PdnConnectRequest,
    PdnConnectResponse, PdnDisconnectRequest, PdnDisconnectResponse, PdnEncodeError,
    PdnResponseDecodeError, PlmnListResponse, PlmnSearchDecodeError, PlmnSearchRequest,
    PlmnSearchResponse, ResponseDecodeError, ResultResponse, ResultResponseKind,
    UiccAuthenticateEncodeError, UiccAuthenticateRequest, UiccPinCommandRequest,
    UiccPinEncodeError, UiccPinStatusRequest, UiccReadBinaryRequest, UiccReadRecordRequest,
    UiccResponse, UiccResponseDecodeError, UiccStatusRequest,
};
use gct_transport::{
    GlifTransport, HciIo, HciStreamDecoder, MAX_HCI_FRAME_LEN, OEM_READ_BUFFER_LEN,
};

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
    Attach {
        kind: AttachResponseKind,
        response: AttachResponsePrefix<'a>,
    },
    Detach(DetachResponse),
    DetachRequired(DetachRequiredIndication),
    PdnConnect(PdnConnectResponse<'a>),
    PdnConnectExt(PdnConnectExtResponse<'a>),
    PdnDisconnect(PdnDisconnectResponse<'a>),
    PlmnSearch(PlmnSearchResponse<'a>),
    PlmnList(PlmnListResponse<'a>),
    Result {
        kind: ResultResponseKind,
        response: ResultResponse,
    },
    At(AtCommandFromDevice<'a>),
    AtExt(AtCommandFromDeviceExt<'a>),
    Uicc(UiccResponse<'a>),
    Unknown(Packet<'a>),
}

/// Failure while decoding a packet whose opcode belongs to the proven P0
/// surface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventDecodeError {
    Response(ResponseDecodeError),
    Pdn(PdnResponseDecodeError),
    PlmnSearch(PlmnSearchDecodeError),
    Uicc(UiccResponseDecodeError),
}

/// Typed outbound commands with fully recovered request encoders.
///
/// Known-but-not-yet-recovered request families are deliberately absent. In
/// particular, this does not invent encoders for extended attach, extended AT
/// or PLMN-search-stop merely because their opcodes are known.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModemCommand<'a> {
    Attach(AttachRequest<'a>),
    Detach(DetachRequest),
    PdnConnect(PdnConnectRequest<'a>),
    PdnConnectExt(PdnConnectExtRequest<'a>),
    PdnDisconnect(PdnDisconnectRequest<'a>),
    PlmnSearch(PlmnSearchRequest),
    Empty(EmptyRequest),
    At(AtCommand<'a>),
    UiccStatus(UiccStatusRequest),
    UiccReadBinary(UiccReadBinaryRequest),
    UiccReadRecord(UiccReadRecordRequest),
    UiccAuthenticate(UiccAuthenticateRequest<'a>),
    UiccPinStatus(UiccPinStatusRequest),
    UiccPinCommand(UiccPinCommandRequest<'a>),
}

/// Encoding failure from one of the proven typed request families.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandEncodeError {
    Hci(EncodeError),
    Attach(AttachEncodeError),
    Pdn(PdnEncodeError),
    UiccAuthenticate(UiccAuthenticateEncodeError),
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

impl From<PdnEncodeError> for CommandEncodeError {
    fn from(value: PdnEncodeError) -> Self {
        Self::Pdn(value)
    }
}

impl From<UiccAuthenticateEncodeError> for CommandEncodeError {
    fn from(value: UiccAuthenticateEncodeError) -> Self {
        Self::UiccAuthenticate(value)
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
        ModemCommand::Detach(request) => Ok(request.encode(output)?),
        ModemCommand::PdnConnect(request) => Ok(request.encode(output)?),
        ModemCommand::PdnConnectExt(request) => Ok(request.encode(output)?),
        ModemCommand::PdnDisconnect(request) => Ok(request.encode(output)?),
        ModemCommand::PlmnSearch(request) => Ok(request.encode(output)?),
        ModemCommand::Empty(request) => Ok(request.encode(output)?),
        ModemCommand::At(request) => Ok(request.encode(output)?),
        ModemCommand::UiccStatus(request) => Ok(request.encode(output)?),
        ModemCommand::UiccReadBinary(request) => Ok(request.encode(output)?),
        ModemCommand::UiccReadRecord(request) => Ok(request.encode(output)?),
        ModemCommand::UiccAuthenticate(request) => Ok(request.encode(output)?),
        ModemCommand::UiccPinStatus(request) => Ok(request.encode(output)?),
        ModemCommand::UiccPinCommand(request) => Ok(request.encode(output)?),
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
        recovered_opcode::ATTACH_RESPONSE => Ok(ModemEvent::Attach {
            kind: AttachResponseKind::Normal,
            response: AttachResponsePrefix::parse(AttachResponseKind::Normal, packet)?,
        }),
        recovered_opcode::ATTACH_RESPONSE_EXT => Ok(ModemEvent::Attach {
            kind: AttachResponseKind::Extended,
            response: AttachResponsePrefix::parse(AttachResponseKind::Extended, packet)?,
        }),
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
        AtCommand, AtCommandFromDevice, EmptyRequest, PinData, ResponseDecodeError,
        UiccPinCommandRequest,
    };
    use gct_transport::HciIo;

    use super::{
        CommandEncodeError, EventDecodeError, Modem, ModemCommand, ModemEvent, PollOutcome,
        SendCommandError, decode_event,
    };

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
