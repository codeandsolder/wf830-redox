//! Shared LAPI response helpers, nested PDN-info grammar, and generic result commands.

use gct_hci::{
    EncodeError, Packet, Tlv, TlvCursor, TlvDecodeError, encode_packet, recovered_opcode,
};

/// The two outer container tags consumed by the OEM `ATTACH_PDN_RSP_INFO`
/// parser. The SDK accepts either tag in either of its two container slots and
/// dispatches their contents through the same inner field table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PdnInfoContainerKind {
    F0,
    F2,
}

impl TryFrom<u8> for PdnInfoContainerKind {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0xf0 => Ok(Self::F0),
            0xf2 => Ok(Self::F2),
            other => Err(other),
        }
    }
}

/// One borrowed nested PDN-info container.
pub struct PdnInfoContainer<'a> {
    pub kind: PdnInfoContainerKind,
    fields: TlvCursor<'a>,
}

impl<'a> PdnInfoContainer<'a> {
    /// Cursor over the inner `[type,len,payload]` fields.
    #[must_use]
    pub fn fields(self) -> TlvCursor<'a> {
        self.fields
    }
}

/// Cursor over the at-most-two contiguous `0xf0`/`0xf2` containers consumed by
/// the OEM nested PDN parser.
pub struct PdnInfoContainers<'a> {
    cursor: TlvCursor<'a>,
    count: u8,
}

impl<'a> PdnInfoContainers<'a> {
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self {
            cursor: TlvCursor::new(bytes),
            count: 0,
        }
    }

    #[must_use]
    pub const fn remaining(&self) -> &'a [u8] {
        self.cursor.remaining()
    }

    /// Decode the next OEM-recognized PDN container without swallowing the
    /// enclosing response's first non-container TLV.
    ///
    /// # Errors
    /// Returns [`TlvDecodeError`] for a truncated recognized container.
    pub fn next_container(&mut self) -> Result<Option<PdnInfoContainer<'a>>, TlvDecodeError> {
        if self.count >= 2 {
            return Ok(None);
        }
        let remaining = self.cursor.remaining();
        let Some(&kind_byte) = remaining.first() else {
            return Ok(None);
        };
        let Ok(kind) = PdnInfoContainerKind::try_from(kind_byte) else {
            return Ok(None);
        };
        let Some(container) = self.cursor.next_tlv()? else {
            return Ok(None);
        };
        self.count += 1;
        Ok(Some(PdnInfoContainer {
            kind,
            fields: TlvCursor::new(container.payload),
        }))
    }
}

/// `QoS` word selected by nested PDN TLVs `0x40..=0x44`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QosField {
    Qci,
    MaxBitRateUl,
    MaxBitRateDl,
    GuaranteedBitRateUl,
    GuaranteedBitRateDl,
}

/// Semantic view of one inner field accepted by the OEM PDN-info dispatcher.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PdnInfoField<'a> {
    AccessPointName(&'a [u8]),
    PdnType(u8),
    PdnTypeCause(u32),
    Ipv4Address([u8; 4]),
    Ipv4DnsPrimary([u8; 4]),
    Ipv4DnsSecondary([u8; 4]),
    Ipv6DnsPrimary([u8; 16]),
    Ipv6DnsSecondary([u8; 16]),
    Ipv6InterfaceId([u8; 8]),
    PcscfIpv6 {
        index: u8,
        address: [u8; 16],
    },
    PcscfIpv4 {
        index: u8,
        address: [u8; 4],
    },
    Qos {
        field: QosField,
        value: u32,
    },
    /// Field kind not present in the recovered first-match dispatch table.
    Unknown(Tlv<'a>),
}

/// Semantic PDN field has a length inconsistent with its recovered target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PdnInfoFieldLengthError {
    pub kind: u8,
    pub expected: usize,
    pub actual: usize,
}

fn exact_array<const N: usize>(tlv: Tlv<'_>) -> Result<[u8; N], PdnInfoFieldLengthError> {
    <[u8; N]>::try_from(tlv.payload).map_err(|_| PdnInfoFieldLengthError {
        kind: tlv.kind,
        expected: N,
        actual: tlv.payload.len(),
    })
}

fn exact_u8(tlv: Tlv<'_>) -> Result<u8, PdnInfoFieldLengthError> {
    exact_array::<1>(tlv).map(|bytes| bytes[0])
}

fn exact_u32(tlv: Tlv<'_>) -> Result<u32, PdnInfoFieldLengthError> {
    exact_array::<4>(tlv).map(u32::from_be_bytes)
}

impl<'a> PdnInfoField<'a> {
    /// Interpret one inner TLV using the recovered first-match dispatch table.
    ///
    /// The OEM table contains two entries for `0x22`; its dispatcher returns
    /// after the first match, making the second (`opspec`) handler unreachable.
    /// Effective firmware behavior therefore maps `0x22` to P-CSCF IPv4 #3.
    ///
    /// # Errors
    /// Returns [`PdnInfoFieldLengthError`] for malformed known fields.
    pub fn parse(tlv: Tlv<'a>) -> Result<Self, PdnInfoFieldLengthError> {
        let field = match tlv.kind {
            0x04 => {
                if tlv.payload.len() > 128 {
                    return Err(PdnInfoFieldLengthError {
                        kind: 0x04,
                        expected: 128,
                        actual: tlv.payload.len(),
                    });
                }
                Self::AccessPointName(tlv.payload)
            }
            0x05 => Self::PdnType(exact_u8(tlv)?),
            0x06 => Self::PdnTypeCause(exact_u32(tlv)?),
            0x07 => Self::Ipv4Address(exact_array(tlv)?),
            0x08 => Self::Ipv4DnsPrimary(exact_array(tlv)?),
            0x09 => Self::Ipv4DnsSecondary(exact_array(tlv)?),
            0x0a => Self::Ipv6DnsPrimary(exact_array(tlv)?),
            0x0b => Self::Ipv6DnsSecondary(exact_array(tlv)?),
            0x0c => Self::Ipv6InterfaceId(exact_array(tlv)?),
            0x0d..=0x11 => Self::PcscfIpv6 {
                index: tlv.kind - 0x0c,
                address: exact_array(tlv)?,
            },
            0x1f => Self::PcscfIpv4 {
                index: 1,
                address: exact_array(tlv)?,
            },
            0x21 => Self::PcscfIpv4 {
                index: 2,
                address: exact_array(tlv)?,
            },
            0x22 => Self::PcscfIpv4 {
                index: 3,
                address: exact_array(tlv)?,
            },
            0x40..=0x44 => {
                let qos = match tlv.kind {
                    0x40 => QosField::Qci,
                    0x41 => QosField::MaxBitRateUl,
                    0x42 => QosField::MaxBitRateDl,
                    0x43 => QosField::GuaranteedBitRateUl,
                    _ => QosField::GuaranteedBitRateDl,
                };
                Self::Qos {
                    field: qos,
                    value: exact_u32(tlv)?,
                }
            }
            _ => Self::Unknown(tlv),
        };
        Ok(field)
    }
}

/// Error returned when a proven response prefix does not match its wire
/// contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseDecodeError {
    /// The HCI packet carries another command/event opcode.
    UnexpectedOpcode { expected: u16, actual: u16 },
    /// A fixed-size response contains too few or too many bytes.
    UnexpectedLength { expected: usize, actual: usize },
    /// A response with optional trailing fields is shorter than its proven
    /// fixed prefix.
    TruncatedPrefix { minimum: usize, actual: usize },
}

pub(crate) fn response_payload(
    packet: Packet<'_>,
    expected_opcode: u16,
) -> Result<&[u8], ResponseDecodeError> {
    if packet.header.command != expected_opcode {
        return Err(ResponseDecodeError::UnexpectedOpcode {
            expected: expected_opcode,
            actual: packet.header.command,
        });
    }
    Ok(packet.payload)
}

pub(crate) fn exact_payload(
    packet: Packet<'_>,
    expected_opcode: u16,
    expected_len: usize,
) -> Result<&[u8], ResponseDecodeError> {
    let payload = response_payload(packet, expected_opcode)?;
    if payload.len() != expected_len {
        return Err(ResponseDecodeError::UnexpectedLength {
            expected: expected_len,
            actual: payload.len(),
        });
    }
    Ok(payload)
}

pub(crate) fn prefix_payload(
    packet: Packet<'_>,
    expected_opcode: u16,
    minimum_len: usize,
) -> Result<&[u8], ResponseDecodeError> {
    let payload = response_payload(packet, expected_opcode)?;
    if payload.len() < minimum_len {
        return Err(ResponseDecodeError::TruncatedPrefix {
            minimum: minimum_len,
            actual: payload.len(),
        });
    }
    Ok(payload)
}

pub(crate) const fn be_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

pub(crate) const fn be_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

/// Four-byte result response shared by Online, Offline and PS Init.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResultResponse {
    pub result: u32,
}

/// Selects one of the three independently registered SDK callbacks that share
/// the same four-byte wire response layout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResultResponseKind {
    Online,
    Offline,
    PsInit,
}

impl ResultResponseKind {
    #[must_use]
    pub const fn opcode(self) -> u16 {
        match self {
            Self::Online => recovered_opcode::ONLINE_RESPONSE,
            Self::Offline => recovered_opcode::OFFLINE_RESPONSE,
            Self::PsInit => recovered_opcode::PS_INIT_RESPONSE,
        }
    }
}

impl ResultResponse {
    /// Decode the exact four-byte response used by Online, Offline or PS Init.
    ///
    /// # Errors
    ///
    /// Returns [`ResponseDecodeError`] for the wrong HCI opcode or any payload
    /// length other than four bytes.
    pub fn parse(
        kind: ResultResponseKind,
        packet: Packet<'_>,
    ) -> Result<Self, ResponseDecodeError> {
        let payload = exact_payload(packet, kind.opcode(), 4)?;
        Ok(Self {
            result: be_u32(payload, 0),
        })
    }
}

/// Request with only the four-byte HCI header and no payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EmptyRequest {
    /// Put the packet service online.
    Online,
    /// Put the packet service offline.
    Offline,
    /// Initialize packet-service state.
    PsInit,
    /// Request a PLMN list.
    PlmnList,
}

impl EmptyRequest {
    /// Exact recovered modem-wire opcode.
    #[must_use]
    pub const fn opcode(self) -> u16 {
        match self {
            Self::Online => recovered_opcode::ONLINE_REQUEST,
            Self::Offline => recovered_opcode::OFFLINE_REQUEST,
            Self::PsInit => recovered_opcode::PS_INIT_REQUEST,
            Self::PlmnList => recovered_opcode::PLMN_LIST_REQUEST,
        }
    }

    /// Encode the complete HCI frame.
    ///
    /// # Errors
    ///
    /// Returns [`EncodeError::NoSpace`] when `output` is shorter than four
    /// bytes.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, EncodeError> {
        encode_packet(self.opcode(), &[], output)
    }
}

/// Fixed-order field in one of the recovered PDN response grammars.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PdnResponseField {
    TransactionId,
    ApnClass,
    ApnNetworkIdentifier,
    RequestedApnNetworkIdentifier,
    ReceivedApnNetworkIdentifier,
}

/// Error returned while decoding the recovered ordered portion of a PDN
/// response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PdnResponseDecodeError {
    Response(ResponseDecodeError),
    Tlv(TlvDecodeError),
    MissingField(PdnResponseField),
    UnexpectedKind {
        field: PdnResponseField,
        expected: u8,
        actual: u8,
    },
    UnexpectedFieldLength {
        field: PdnResponseField,
        expected: usize,
        actual: usize,
    },
    FieldTooLong {
        field: PdnResponseField,
        maximum: usize,
        actual: usize,
    },
}

impl From<ResponseDecodeError> for PdnResponseDecodeError {
    fn from(value: ResponseDecodeError) -> Self {
        Self::Response(value)
    }
}

impl From<TlvDecodeError> for PdnResponseDecodeError {
    fn from(value: TlvDecodeError) -> Self {
        Self::Tlv(value)
    }
}

/// One fixed-order TLV whose destination is known from DWARF but whose tag is
/// not validated by the OEM helper.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrderedPdnTlv<'a> {
    pub kind: u8,
    pub payload: &'a [u8],
}

pub(crate) fn required_pdn_tlv<'a>(
    cursor: &mut TlvCursor<'a>,
    field: PdnResponseField,
) -> Result<Tlv<'a>, PdnResponseDecodeError> {
    cursor
        .next_tlv()?
        .ok_or(PdnResponseDecodeError::MissingField(field))
}

pub(crate) fn exact_pdn_field(
    field: PdnResponseField,
    payload: &[u8],
    expected: usize,
) -> Result<(), PdnResponseDecodeError> {
    if payload.len() != expected {
        return Err(PdnResponseDecodeError::UnexpectedFieldLength {
            field,
            expected,
            actual: payload.len(),
        });
    }
    Ok(())
}

pub(crate) fn bounded_pdn_field(
    field: PdnResponseField,
    payload: &[u8],
    maximum: usize,
) -> Result<(), PdnResponseDecodeError> {
    if payload.len() > maximum {
        return Err(PdnResponseDecodeError::FieldTooLong {
            field,
            maximum,
            actual: payload.len(),
        });
    }
    Ok(())
}

pub(crate) fn split_initial_pdn_info(bytes: &[u8]) -> Result<(&[u8], &[u8]), TlvDecodeError> {
    let mut containers = PdnInfoContainers::new(bytes);
    while containers.next_container()?.is_some() {}
    let remaining = containers.remaining();
    let consumed = bytes.len() - remaining.len();
    Ok((&bytes[..consumed], remaining))
}

/// APN class values recovered from the B014 `ltetype.h` DWARF.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ApnType {
    Internet = 0,
    Ims = 1,
    Admin = 2,
    App = 3,
    Emergency = 4,
    Reserved1 = 5,
    Reserved2 = 6,
    Reserved3 = 7,
    NotSet = 0xff,
}

impl ApnType {
    /// Translate the host-side APN class into the live Polish P4 modem value.
    ///
    /// B014 accepted three additional mappings which the live P4 SDK removed.
    /// This deliberately follows the live target: Emergency/Reserved2/
    /// Reserved3/NotSet map to zero rather than B014's historical values.
    #[must_use]
    pub const fn p4_wire_value(self) -> u8 {
        match self {
            Self::Internet => 3,
            Self::Ims => 1,
            Self::Admin => 2,
            Self::App => 4,
            Self::Reserved1 => 6,
            Self::Emergency | Self::Reserved2 | Self::Reserved3 | Self::NotSet => 0,
        }
    }
}

/// Three rate/connection limits sent in attach TLV `0x71`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PdnConnectionControl {
    pub max_conn: u16,
    pub max_conn_t: u16,
    pub wait_time: u16,
}

/// Compact packet-configuration option block used by extended PDN connect.
///
/// The old C structure is nine bytes. The three 16-bit protocol identifiers are
/// converted to device byte order before the block is sent as TLV `0x21`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PcoInfo {
    pub first_pco: u8,
    pub second_pco: u8,
    pub n_pco: u8,
    pub first_os_pco: u16,
    pub second_os_pco: u16,
    pub third_os_pco: u16,
}

impl PcoInfo {
    #[must_use]
    pub(crate) const fn wire_bytes(self) -> [u8; 9] {
        let first = self.first_os_pco.to_be_bytes();
        let second = self.second_os_pco.to_be_bytes();
        let third = self.third_os_pco.to_be_bytes();
        [
            self.first_pco,
            self.second_pco,
            self.n_pco,
            first[0],
            first[1],
            second[0],
            second[1],
            third[0],
            third[1],
        ]
    }
}
