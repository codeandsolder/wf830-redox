#![no_std]

//! Audited representation of the OEM `lted` local IPC framing.
//!
//! Stock clients use connected UNIX datagram sockets after a one-shot common
//! socket handshake. Every datagram starts with a four-byte big-endian
//! `{event, payload_len}` header. SDK requests then carry a second recovered
//! envelope: `{command: u16, inner_len: u16, device_id: u32, params...}`.

pub const HEADER_LEN: usize = 4;
pub const SDK_ENVELOPE_PREFIX_LEN: usize = 8;
pub const COMMON_SOCKET_PATH: &str = "/var/tmp/lted-daemon";
pub const PRIVATE_SOCKET_PREFIX: &str = "/var/tmp/lted-client-";
pub const SHARED_CONTEXT_LEN: usize = 0x9780;
pub const MAX_CLIENTS: usize = 15;
pub const CALLBACK_REGISTRATION_BASE: usize = 4;
pub const CALLBACK_REGISTRATION_STRIDE: usize = 8;
pub const CALLBACK_REGISTRATION_COUNT: usize = 164;

/// Callback IDs and their recovered `lted_client_context.cb_rsp[]` slots for
/// the first P0 compatibility surface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SdkCallbackKind {
    Attach,
    AttachExt,
    Detach,
    PdnConnect,
    PdnConnectExt,
    PdnDisconnect,
    PlmnSearch,
    PlmnSearchStop,
    PlmnList,
    Online,
    Offline,
    PsInit,
    AtCommandFromDevice,
    AtCommandFromDeviceExt,
    UiccFromDevice,
}

impl SdkCallbackKind {
    #[must_use]
    pub const fn callback_id(self) -> u16 {
        match self {
            Self::Attach => 26,
            Self::AttachExt => 28,
            Self::Detach => 30,
            Self::PdnConnect => 33,
            Self::PdnConnectExt => 35,
            Self::PdnDisconnect => 37,
            Self::PlmnSearch => 41,
            Self::PlmnSearchStop => 64,
            Self::PlmnList => 45,
            Self::Online => 59,
            Self::Offline => 62,
            Self::PsInit => 68,
            Self::AtCommandFromDevice => 126,
            Self::AtCommandFromDeviceExt => 128,
            Self::UiccFromDevice => 148,
        }
    }

    #[must_use]
    pub const fn registration_index(self) -> usize {
        match self {
            Self::Attach => 2,
            Self::AttachExt => 3,
            Self::Detach => 4,
            Self::PdnConnect => 6,
            Self::PdnConnectExt => 7,
            Self::PdnDisconnect => 8,
            Self::PlmnSearch => 9,
            Self::PlmnSearchStop => 20,
            Self::PlmnList => 11,
            Self::Online => 18,
            Self::Offline => 19,
            Self::PsInit => 22,
            Self::AtCommandFromDevice => 60,
            Self::AtCommandFromDeviceExt => 61,
            Self::UiccFromDevice => 71,
        }
    }

    #[must_use]
    pub const fn registration_offset(self) -> usize {
        CALLBACK_REGISTRATION_BASE + self.registration_index() * CALLBACK_REGISTRATION_STRIDE
    }
}

/// Top-level `lted` client/server event identifiers proven from the live P4
/// daemon and stock `liblted.so`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum Event {
    ApiOpen = 0x0100,
    ApiClose = 0x0102,
    HciToClient = 0x0105,
    SdkApi = 0x0106,
    CliCommand = 0x010a,
    ApiOpenResponse = 0x8101,
    SdkCallback = 0x8107,
}

impl TryFrom<u16> for Event {
    type Error = UnknownEvent;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0100 => Ok(Self::ApiOpen),
            0x0102 => Ok(Self::ApiClose),
            0x0105 => Ok(Self::HciToClient),
            0x0106 => Ok(Self::SdkApi),
            0x010a => Ok(Self::CliCommand),
            0x8101 => Ok(Self::ApiOpenResponse),
            0x8107 => Ok(Self::SdkCallback),
            _ => Err(UnknownEvent(value)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnknownEvent(pub u16);

/// SDK API command identifiers taken from the inner `htons()` performed by
/// each live stock `LTED_*` wrapper. These are not the adjacent server enum
/// values and must not be inferred from them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum SdkCommand {
    GetPsInitComplete = 0,
    Attach = 25,
    AttachExt = 27,
    Detach = 29,
    PdnConnect = 32,
    PdnConnectExt = 34,
    PdnDisconnect = 36,
    PlmnSearch = 40,
    PlmnList = 44,
    Online = 58,
    Offline = 60,
    PlmnSearchStop = 63,
    PsInit = 67,
    AtCommand = 125,
    AtCommandExt = 127,
    UiccRequest = 147,
}

impl TryFrom<u16> for SdkCommand {
    type Error = UnknownSdkCommand;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::GetPsInitComplete),
            25 => Ok(Self::Attach),
            27 => Ok(Self::AttachExt),
            29 => Ok(Self::Detach),
            32 => Ok(Self::PdnConnect),
            34 => Ok(Self::PdnConnectExt),
            36 => Ok(Self::PdnDisconnect),
            40 => Ok(Self::PlmnSearch),
            44 => Ok(Self::PlmnList),
            58 => Ok(Self::Online),
            60 => Ok(Self::Offline),
            63 => Ok(Self::PlmnSearchStop),
            67 => Ok(Self::PsInit),
            125 => Ok(Self::AtCommand),
            127 => Ok(Self::AtCommandExt),
            147 => Ok(Self::UiccRequest),
            _ => Err(UnknownSdkCommand(value)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnknownSdkCommand(pub u16);

/// Four-byte big-endian local IPC header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    pub event: u16,
    pub payload_len: u16,
}

impl Header {
    #[must_use]
    pub const fn encode(self) -> [u8; HEADER_LEN] {
        let event = self.event.to_be_bytes();
        let len = self.payload_len.to_be_bytes();
        [event[0], event[1], len[0], len[1]]
    }

    #[must_use]
    pub const fn decode(bytes: [u8; HEADER_LEN]) -> Self {
        Self {
            event: u16::from_be_bytes([bytes[0], bytes[1]]),
            payload_len: u16::from_be_bytes([bytes[2], bytes[3]]),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketDecodeError {
    TruncatedHeader { actual: usize },
    LengthMismatch { declared: usize, actual: usize },
}

/// One complete local UNIX-datagram frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Packet<'a> {
    pub header: Header,
    pub payload: &'a [u8],
}

impl<'a> Packet<'a> {
    /// Parse one whole datagram; trailing bytes are rejected rather than
    /// silently treated as another frame because UNIX datagram boundaries are
    /// part of this protocol.
    ///
    /// # Errors
    /// Returns [`PacketDecodeError`] for a short header or a payload whose
    /// actual size differs from the declared 16-bit length.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, PacketDecodeError> {
        let Some(header_bytes) = bytes.get(..HEADER_LEN) else {
            return Err(PacketDecodeError::TruncatedHeader {
                actual: bytes.len(),
            });
        };
        let header = Header::decode([
            header_bytes[0],
            header_bytes[1],
            header_bytes[2],
            header_bytes[3],
        ]);
        let payload = &bytes[HEADER_LEN..];
        let declared = usize::from(header.payload_len);
        if payload.len() != declared {
            return Err(PacketDecodeError::LengthMismatch {
                declared,
                actual: payload.len(),
            });
        }
        Ok(Self { header, payload })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncodeError {
    PayloadTooLong,
    NoSpace,
}

/// Encode one complete local IPC datagram into caller-owned storage.
///
/// # Errors
/// Returns [`EncodeError::PayloadTooLong`] when the payload does not fit the
/// recovered u16 length field, or [`EncodeError::NoSpace`] when `output` is too
/// small.
pub fn encode_packet(event: u16, payload: &[u8], output: &mut [u8]) -> Result<usize, EncodeError> {
    let payload_len = u16::try_from(payload.len()).map_err(|_| EncodeError::PayloadTooLong)?;
    let total = HEADER_LEN
        .checked_add(payload.len())
        .ok_or(EncodeError::PayloadTooLong)?;
    let Some(dst) = output.get_mut(..total) else {
        return Err(EncodeError::NoSpace);
    };
    dst[..HEADER_LEN].copy_from_slice(&Header { event, payload_len }.encode());
    dst[HEADER_LEN..].copy_from_slice(payload);
    Ok(total)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageDecodeError {
    WrongEvent { expected: u16, actual: u16 },
    UnexpectedLength { expected: usize, actual: usize },
    InvalidOpenLength(usize),
    SdkEnvelopeTooShort(usize),
    SdkEnvelopeLengthMismatch { declared: usize, actual: usize },
}

fn expect_event(packet: Packet<'_>, expected: Event) -> Result<&[u8], MessageDecodeError> {
    if packet.header.event != expected as u16 {
        return Err(MessageDecodeError::WrongEvent {
            expected: expected as u16,
            actual: packet.header.event,
        });
    }
    Ok(packet.payload)
}

/// API-open request sent to `/var/tmp/lted-daemon`.
///
/// Stock `liblted.so` always sends four identity bytes but truncates its u32
/// API argument to u16 before serialization. The server independently truncates
/// the received u32 to its low 16 bits. A zero-length identity is also accepted
/// by the OEM daemon, so the recovered type preserves that shape.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApiOpenRequest {
    pub client_identity: Option<u16>,
}

impl ApiOpenRequest {
    /// Parse the stock zero- or four-byte API-open payload.
    ///
    /// # Errors
    /// Returns [`MessageDecodeError`] for another event or any payload length
    /// other than zero/four.
    pub fn parse(packet: Packet<'_>) -> Result<Self, MessageDecodeError> {
        let payload = expect_event(packet, Event::ApiOpen)?;
        match payload {
            [] => Ok(Self {
                client_identity: None,
            }),
            [_, _, high, low] => Ok(Self {
                client_identity: Some(u16::from_be_bytes([*high, *low])),
            }),
            _ => Err(MessageDecodeError::InvalidOpenLength(payload.len())),
        }
    }

    /// Encode the canonical stock-client form. `None` encodes the alternate
    /// zero-payload shape accepted by the daemon.
    ///
    /// # Errors
    /// Returns [`EncodeError::NoSpace`] when `output` is too small.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, EncodeError> {
        match self.client_identity {
            None => encode_packet(Event::ApiOpen as u16, &[], output),
            Some(identity) => {
                let identity = identity.to_be_bytes();
                encode_packet(
                    Event::ApiOpen as u16,
                    &[0, 0, identity[0], identity[1]],
                    output,
                )
            }
        }
    }
}

/// One-byte client slot returned by the daemon in event `0x8101`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApiOpenResponse {
    pub client_id: u8,
}

impl ApiOpenResponse {
    /// # Errors
    /// Returns [`MessageDecodeError`] for another event or a payload not exactly
    /// one byte long.
    pub fn parse(packet: Packet<'_>) -> Result<Self, MessageDecodeError> {
        let payload = expect_event(packet, Event::ApiOpenResponse)?;
        let [client_id] = payload else {
            return Err(MessageDecodeError::UnexpectedLength {
                expected: 1,
                actual: payload.len(),
            });
        };
        Ok(Self {
            client_id: *client_id,
        })
    }

    /// # Errors
    /// Returns [`EncodeError::NoSpace`] when `output` is too small.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, EncodeError> {
        encode_packet(Event::ApiOpenResponse as u16, &[self.client_id], output)
    }
}

/// Validate the zero-payload API-close event.
///
/// # Errors
/// Returns [`MessageDecodeError`] for another event or a non-empty payload.
pub fn parse_api_close(packet: Packet<'_>) -> Result<(), MessageDecodeError> {
    let payload = expect_event(packet, Event::ApiClose)?;
    if !payload.is_empty() {
        return Err(MessageDecodeError::UnexpectedLength {
            expected: 0,
            actual: payload.len(),
        });
    }
    Ok(())
}

fn parse_sdk_envelope(
    packet: Packet<'_>,
    expected: Event,
) -> Result<(u16, u32, &[u8]), MessageDecodeError> {
    let payload = expect_event(packet, expected)?;
    if payload.len() < SDK_ENVELOPE_PREFIX_LEN {
        return Err(MessageDecodeError::SdkEnvelopeTooShort(payload.len()));
    }
    let code = u16::from_be_bytes([payload[0], payload[1]]);
    let declared = usize::from(u16::from_be_bytes([payload[2], payload[3]]));
    let actual = payload.len() - 4;
    if declared != actual {
        return Err(MessageDecodeError::SdkEnvelopeLengthMismatch { declared, actual });
    }
    let device_id = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
    Ok((code, device_id, &payload[SDK_ENVELOPE_PREFIX_LEN..]))
}

fn encode_sdk_envelope(
    event: Event,
    code: u16,
    device_id: u32,
    data: &[u8],
    output: &mut [u8],
) -> Result<usize, EncodeError> {
    let inner_len = 4usize
        .checked_add(data.len())
        .ok_or(EncodeError::PayloadTooLong)?;
    let inner_len_u16 = u16::try_from(inner_len).map_err(|_| EncodeError::PayloadTooLong)?;
    let outer_len = 4usize
        .checked_add(inner_len)
        .ok_or(EncodeError::PayloadTooLong)?;
    let outer_len_u16 = u16::try_from(outer_len).map_err(|_| EncodeError::PayloadTooLong)?;
    let total = HEADER_LEN
        .checked_add(outer_len)
        .ok_or(EncodeError::PayloadTooLong)?;
    let Some(dst) = output.get_mut(..total) else {
        return Err(EncodeError::NoSpace);
    };

    dst[..HEADER_LEN].copy_from_slice(
        &Header {
            event: event as u16,
            payload_len: outer_len_u16,
        }
        .encode(),
    );
    dst[4..6].copy_from_slice(&code.to_be_bytes());
    dst[6..8].copy_from_slice(&inner_len_u16.to_be_bytes());
    dst[8..12].copy_from_slice(&device_id.to_be_bytes());
    dst[12..].copy_from_slice(data);
    Ok(total)
}

/// Parsed inner SDK API request. Unknown command values remain available in
/// `command`; dispatch policy belongs above the wire codec.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SdkApiRequest<'a> {
    pub command: u16,
    pub device_id: u32,
    pub params: &'a [u8],
}

impl<'a> SdkApiRequest<'a> {
    /// Decode event `0x0106` and validate both the outer and inner lengths.
    ///
    /// # Errors
    /// Returns [`MessageDecodeError`] for another event, an inner envelope
    /// shorter than `{command,len,device_id}`, or an inconsistent inner length.
    pub fn parse(packet: Packet<'a>) -> Result<Self, MessageDecodeError> {
        let (command, device_id, params) = parse_sdk_envelope(packet, Event::SdkApi)?;
        Ok(Self {
            command,
            device_id,
            params,
        })
    }

    /// Encode the exact stock wrapper envelope.
    ///
    /// # Errors
    /// Returns [`EncodeError::PayloadTooLong`] when either recovered 16-bit
    /// length cannot represent the request, or [`EncodeError::NoSpace`] when
    /// `output` is too small.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, EncodeError> {
        encode_sdk_envelope(
            Event::SdkApi,
            self.command,
            self.device_id,
            self.params,
            output,
        )
    }

    /// Narrow the raw command only when it belongs to the recovered typed subset.
    ///
    /// # Errors
    /// Returns [`UnknownSdkCommand`] for a syntactically valid request whose command
    /// has not been recovered into [`SdkCommand`].
    pub fn known_command(self) -> Result<SdkCommand, UnknownSdkCommand> {
        SdkCommand::try_from(self.command)
    }
}

/// SDK callback delivered by the daemon in event `0x8107`.
///
/// The callback wire envelope is byte-for-byte the same shape as an SDK API
/// request: `{callback_id: u16, inner_len: u16, device_id: u32, data...}`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SdkCallback<'a> {
    pub callback_id: u16,
    pub device_id: u32,
    pub data: &'a [u8],
}

impl<'a> SdkCallback<'a> {
    /// # Errors
    /// Returns [`MessageDecodeError`] for another event or an inconsistent
    /// inner callback envelope.
    pub fn parse(packet: Packet<'a>) -> Result<Self, MessageDecodeError> {
        let (callback_id, device_id, data) = parse_sdk_envelope(packet, Event::SdkCallback)?;
        Ok(Self {
            callback_id,
            device_id,
            data,
        })
    }

    /// # Errors
    /// Returns [`EncodeError`] if a recovered 16-bit length overflows or the
    /// caller-provided output buffer is too small.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, EncodeError> {
        encode_sdk_envelope(
            Event::SdkCallback,
            self.callback_id,
            self.device_id,
            self.data,
            output,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ApiOpenRequest, ApiOpenResponse, Event, Header, MessageDecodeError, Packet,
        PacketDecodeError, SdkApiRequest, SdkCallback, SdkCallbackKind, SdkCommand,
        parse_api_close,
    };

    #[test]
    fn sdk_api_header_uses_big_endian_length() {
        let header = Header {
            event: Event::SdkApi as u16,
            payload_len: 0x123,
        };
        assert_eq!(header.encode(), [0x01, 0x06, 0x01, 0x23]);
        assert_eq!(Header::decode(header.encode()), header);
    }

    #[test]
    fn datagram_parser_requires_exact_declared_length() {
        assert_eq!(
            Packet::parse(&[0x01, 0x02, 0x00]),
            Err(PacketDecodeError::TruncatedHeader { actual: 3 })
        );
        assert_eq!(
            Packet::parse(&[0x01, 0x02, 0x00, 0x01]),
            Err(PacketDecodeError::LengthMismatch {
                declared: 1,
                actual: 0,
            })
        );
        assert_eq!(
            Packet::parse(&[0x01, 0x02, 0x00, 0x00, 0xff]),
            Err(PacketDecodeError::LengthMismatch {
                declared: 0,
                actual: 1,
            })
        );
    }

    #[test]
    fn critical_sdk_commands_match_stock_wrapper_wire_values() {
        assert_eq!(SdkCommand::try_from(25), Ok(SdkCommand::Attach));
        assert_eq!(SdkCommand::try_from(67), Ok(SdkCommand::PsInit));
        assert_eq!(SdkCommand::try_from(125), Ok(SdkCommand::AtCommand));
        assert_eq!(SdkCommand::try_from(147), Ok(SdkCommand::UiccRequest));
        assert!(SdkCommand::try_from(0xffff).is_err());
    }

    #[test]
    fn api_open_matches_stock_client_and_server_truncation() {
        let request = ApiOpenRequest {
            client_identity: Some(0x1234),
        };
        let mut frame = [0_u8; 8];
        assert_eq!(request.encode(&mut frame), Ok(8));
        assert_eq!(frame, [0x01, 0x00, 0x00, 0x04, 0, 0, 0x12, 0x34]);
        let Ok(packet) = Packet::parse(&frame) else {
            return;
        };
        assert_eq!(ApiOpenRequest::parse(packet), Ok(request));

        let noncanonical = [0x01, 0x00, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef];
        let Ok(packet) = Packet::parse(&noncanonical) else {
            return;
        };
        assert_eq!(
            ApiOpenRequest::parse(packet),
            Ok(ApiOpenRequest {
                client_identity: Some(0xbeef)
            })
        );
        let empty = [0x01, 0x00, 0x00, 0x00];
        let Ok(packet) = Packet::parse(&empty) else {
            return;
        };
        assert_eq!(
            ApiOpenRequest::parse(packet),
            Ok(ApiOpenRequest {
                client_identity: None
            })
        );
    }

    #[test]
    fn api_open_response_and_close_are_exact() {
        let response = ApiOpenResponse { client_id: 7 };
        let mut frame = [0_u8; 5];
        assert_eq!(response.encode(&mut frame), Ok(5));
        assert_eq!(frame, [0x81, 0x01, 0x00, 0x01, 7]);
        let Ok(packet) = Packet::parse(&frame) else {
            return;
        };
        assert_eq!(ApiOpenResponse::parse(packet), Ok(response));

        let close_frame = [0x01, 0x02, 0x00, 0x00];
        let Ok(close) = Packet::parse(&close_frame) else {
            return;
        };
        assert_eq!(parse_api_close(close), Ok(()));
        let bad_frame = [0x01, 0x02, 0x00, 0x01, 9];
        let Ok(bad) = Packet::parse(&bad_frame) else {
            return;
        };
        assert_eq!(
            parse_api_close(bad),
            Err(MessageDecodeError::UnexpectedLength {
                expected: 0,
                actual: 1,
            })
        );
    }

    #[test]
    fn ps_init_sdk_api_matches_stock_liblted_frame() {
        let request = SdkApiRequest {
            command: SdkCommand::PsInit as u16,
            device_id: 0x1122_3344,
            params: &[],
        };
        let mut frame = [0_u8; 12];
        assert_eq!(request.encode(&mut frame), Ok(12));
        assert_eq!(
            frame,
            [
                0x01, 0x06, 0x00, 0x08, // outer event + len
                0x00, 0x43, 0x00, 0x04, // command + inner len
                0x11, 0x22, 0x33, 0x44, // device id
            ]
        );
        let Ok(packet) = Packet::parse(&frame) else {
            return;
        };
        let Ok(parsed) = SdkApiRequest::parse(packet) else {
            return;
        };
        assert_eq!(parsed, request);
        assert_eq!(parsed.known_command(), Ok(SdkCommand::PsInit));
    }

    #[test]
    fn get_ps_init_complete_matches_stock_local_query_frame() {
        let request = SdkApiRequest {
            command: SdkCommand::GetPsInitComplete as u16,
            device_id: 1,
            params: &[],
        };
        let mut frame = [0_u8; 12];
        assert_eq!(request.encode(&mut frame), Ok(12));
        assert_eq!(
            frame,
            [
                0x01, 0x06, 0x00, 0x08, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01,
            ]
        );
        let Ok(packet) = Packet::parse(&frame) else {
            return;
        };
        let Ok(parsed) = SdkApiRequest::parse(packet) else {
            return;
        };
        assert_eq!(parsed.known_command(), Ok(SdkCommand::GetPsInitComplete));
    }

    #[test]
    fn attach_sdk_api_length_matches_360_byte_stock_payload() {
        let params = [0_u8; 352];
        let request = SdkApiRequest {
            command: SdkCommand::Attach as u16,
            device_id: 1,
            params: &params,
        };
        let mut frame = [0_u8; 364];
        assert_eq!(request.encode(&mut frame), Ok(364));
        assert_eq!(
            &frame[..12],
            &[0x01, 0x06, 0x01, 0x68, 0x00, 0x19, 0x01, 0x64, 0, 0, 0, 1]
        );
        let Ok(packet) = Packet::parse(&frame) else {
            return;
        };
        assert_eq!(SdkApiRequest::parse(packet), Ok(request));
    }

    #[test]
    fn recovered_callback_registration_slots_match_oem_jump_table() {
        assert_eq!(SdkCallbackKind::Attach.callback_id(), 26);
        assert_eq!(SdkCallbackKind::Attach.registration_offset(), 0x14);
        assert_eq!(SdkCallbackKind::AttachExt.callback_id(), 28);
        assert_eq!(SdkCallbackKind::AttachExt.registration_offset(), 0x1c);
        assert_eq!(SdkCallbackKind::Detach.callback_id(), 30);
        assert_eq!(SdkCallbackKind::Detach.registration_offset(), 0x24);
        assert_eq!(SdkCallbackKind::PdnConnect.callback_id(), 33);
        assert_eq!(SdkCallbackKind::PdnConnect.registration_offset(), 0x34);
        assert_eq!(SdkCallbackKind::PdnConnectExt.callback_id(), 35);
        assert_eq!(SdkCallbackKind::PdnConnectExt.registration_offset(), 0x3c);
        assert_eq!(SdkCallbackKind::PdnDisconnect.callback_id(), 37);
        assert_eq!(SdkCallbackKind::PdnDisconnect.registration_offset(), 0x44);
        assert_eq!(SdkCallbackKind::PlmnSearch.callback_id(), 41);
        assert_eq!(SdkCallbackKind::PlmnSearch.registration_offset(), 0x4c);
        assert_eq!(SdkCallbackKind::PlmnSearchStop.callback_id(), 64);
        assert_eq!(SdkCallbackKind::PlmnSearchStop.registration_offset(), 0xa4);
        assert_eq!(SdkCallbackKind::PlmnList.callback_id(), 45);
        assert_eq!(SdkCallbackKind::PlmnList.registration_offset(), 0x5c);
        assert_eq!(SdkCallbackKind::Online.callback_id(), 59);
        assert_eq!(SdkCallbackKind::Online.registration_offset(), 0x94);
        assert_eq!(SdkCallbackKind::Offline.callback_id(), 62);
        assert_eq!(SdkCallbackKind::Offline.registration_offset(), 0x9c);
        assert_eq!(SdkCallbackKind::PsInit.callback_id(), 68);
        assert_eq!(SdkCallbackKind::PsInit.registration_offset(), 0xb4);
        assert_eq!(SdkCallbackKind::AtCommandFromDevice.callback_id(), 126);
        assert_eq!(
            SdkCallbackKind::AtCommandFromDevice.registration_offset(),
            0x1e4
        );
        assert_eq!(SdkCallbackKind::AtCommandFromDeviceExt.callback_id(), 128);
        assert_eq!(
            SdkCallbackKind::AtCommandFromDeviceExt.registration_offset(),
            0x1ec
        );
        assert_eq!(SdkCallbackKind::UiccFromDevice.callback_id(), 148);
        assert_eq!(SdkCallbackKind::UiccFromDevice.registration_offset(), 0x23c);
    }

    #[test]
    fn sdk_callback_uses_the_same_recovered_inner_envelope() {
        let callback = SdkCallback {
            callback_id: 22,
            device_id: 0x1122_3344,
            data: &[0xaa, 0xbb, 0xcc],
        };
        let mut frame = [0_u8; 15];
        assert_eq!(callback.encode(&mut frame), Ok(15));
        assert_eq!(
            frame,
            [
                0x81, 0x07, 0x00, 0x0b, // outer event + len
                0x00, 0x16, 0x00, 0x07, // callback id + inner len
                0x11, 0x22, 0x33, 0x44, // device id
                0xaa, 0xbb, 0xcc,
            ]
        );
        let Ok(packet) = Packet::parse(&frame) else {
            return;
        };
        assert_eq!(SdkCallback::parse(packet), Ok(callback));
    }

    #[test]
    fn sdk_api_rejects_inner_length_mismatch_and_preserves_unknown_commands() {
        let bad = [0x01, 0x06, 0x00, 0x08, 0x12, 0x34, 0x00, 0x05, 0, 0, 0, 1];
        let Ok(packet) = Packet::parse(&bad) else {
            return;
        };
        assert_eq!(
            SdkApiRequest::parse(packet),
            Err(MessageDecodeError::SdkEnvelopeLengthMismatch {
                declared: 5,
                actual: 4
            })
        );

        let unknown = [0x01, 0x06, 0x00, 0x08, 0x12, 0x34, 0x00, 0x04, 0, 0, 0, 1];
        let Ok(packet) = Packet::parse(&unknown) else {
            return;
        };
        let Ok(parsed) = SdkApiRequest::parse(packet) else {
            return;
        };
        assert_eq!(parsed.command, 0x1234);
        assert!(parsed.known_command().is_err());
    }
}
