#![no_std]

//! Typed codecs for the small GCT LAPI subset needed to bring up the WF830.
//!
//! This is a clean implementation from recovered wire behavior. It does not
//! expose the historical OEM C ABI and intentionally omits commands until
//! their payload format is proven.

use gct_hci::{
    EncodeError, HEADER_LEN, Header, Packet, Tlv, TlvCursor, TlvDecodeError, TlvError, TlvWriter,
    encode_packet, public_opcode, recovered_opcode,
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

fn response_payload(
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

fn exact_payload(
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

fn prefix_payload(
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

const fn be_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

const fn be_u32(bytes: &[u8], offset: usize) -> u32 {
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

/// Exact eight-byte detach response recovered from `LAPI` response handler
/// `0xb104` and `_DETACH_RSP_INFO` DWARF.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DetachResponse {
    pub result: u32,
    pub deregister_cause1: u16,
    pub deregister_cause2: u16,
}

impl DetachResponse {
    /// Decode an exact detach response.
    ///
    /// # Errors
    ///
    /// Returns [`ResponseDecodeError`] for the wrong opcode or payload length.
    pub fn parse(packet: Packet<'_>) -> Result<Self, ResponseDecodeError> {
        let payload = exact_payload(packet, recovered_opcode::DETACH_RESPONSE, 8)?;
        Ok(Self {
            result: be_u32(payload, 0),
            deregister_cause1: be_u16(payload, 4),
            deregister_cause2: be_u16(payload, 6),
        })
    }
}

/// Network-initiated detach-required indication `0xb16a`.
///
/// Both B014 and live P4 allocate exactly four bytes, convert the payload with
/// `D4H`, and pass it to the callback structure whose sole DWARF field is
/// `detach_type: u32`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DetachRequiredIndication {
    pub detach_type: u32,
}

impl DetachRequiredIndication {
    /// Decode the exact four-byte detach-required indication.
    ///
    /// # Errors
    /// Returns [`ResponseDecodeError`] for another opcode or any payload size
    /// other than four bytes.
    pub fn parse(packet: Packet<'_>) -> Result<Self, ResponseDecodeError> {
        let payload = exact_payload(packet, recovered_opcode::DETACH_REQUIRED_INDICATION, 4)?;
        Ok(Self {
            detach_type: be_u32(payload, 0),
        })
    }
}

/// Five one-byte LTE network capability flags recovered from `NET_FEATURE_INFO`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetworkFeatureInfo {
    pub ims_voice_over_ps: u8,
    pub emc_bc: u8,
    pub epc_lcs: u8,
    pub sc_lcs: u8,
    pub ext_sr: u8,
}

/// Normal and extended attach responses share the same first 15 wire bytes,
/// even though the historical callback structures place fields differently.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttachResponsePrefix<'a> {
    pub register_result1: u16,
    pub register_result2: u16,
    pub default_eps_id: u16,
    pub eps_id: u16,
    pub data_path: u8,
    pub ip_alloc: u8,
    pub network_features: NetworkFeatureInfo,
    /// Remaining response bytes. These begin at the first parser-managed field
    /// after the common fixed prefix and are intentionally left borrowed until
    /// every nested optional-field grammar is proven.
    pub optional_fields: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachResponseKind {
    Normal,
    Extended,
}

impl AttachResponseKind {
    #[must_use]
    pub const fn opcode(self) -> u16 {
        match self {
            Self::Normal => recovered_opcode::ATTACH_RESPONSE,
            Self::Extended => recovered_opcode::ATTACH_RESPONSE_EXT,
        }
    }
}

/// Error while decoding the recovered ordered portion of a normal attach
/// response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachResponseDecodeError {
    Response(ResponseDecodeError),
    Tlv(TlvDecodeError),
    MissingTransaction,
    UnexpectedTransactionKind { expected: u8, actual: u8 },
    UnexpectedTransactionLength { expected: usize, actual: usize },
    MissingApnNetworkIdentifier,
    ApnNetworkIdentifierTooLong { maximum: usize, actual: usize },
}

impl From<ResponseDecodeError> for AttachResponseDecodeError {
    fn from(value: ResponseDecodeError) -> Self {
        Self::Response(value)
    }
}

impl From<TlvDecodeError> for AttachResponseDecodeError {
    fn from(value: TlvDecodeError) -> Self {
        Self::Tlv(value)
    }
}

/// One emergency number decoded from Attach response field `0xf4`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EmergencyNumber<'a> {
    pub category: u8,
    pub number: &'a [u8],
}

/// Malformed packed emergency-number list.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EmergencyNumberDecodeError {
    ZeroLength,
    NumberTooLong { maximum: usize, actual: usize },
    TruncatedRecord { expected: usize, actual: usize },
    TooManyRecords { maximum: usize },
}

/// Borrowed emergency-number list carried by Attach response field `0xf4`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EmergencyNumberList<'a> {
    payload: &'a [u8],
}

impl<'a> EmergencyNumberList<'a> {
    #[must_use]
    pub const fn records(self) -> EmergencyNumberCursor<'a> {
        EmergencyNumberCursor {
            remaining: self.payload,
            count: 0,
        }
    }

    fn validate(self) -> Result<(), EmergencyNumberDecodeError> {
        let mut records = self.records();
        while records.next_record()?.is_some() {}
        Ok(())
    }
}

/// Allocation-free iterator over packed emergency-number records.
pub struct EmergencyNumberCursor<'a> {
    remaining: &'a [u8],
    count: u8,
}

impl<'a> EmergencyNumberCursor<'a> {
    /// Decode the next `[len, category, number[len-1]]` record.
    ///
    /// # Errors
    /// Returns [`EmergencyNumberDecodeError`] when a record would exceed the
    /// 92-byte historical number slot, the payload is truncated, `len` is zero,
    /// or more than 14 records would overflow the legacy callback array.
    pub fn next_record(
        &mut self,
    ) -> Result<Option<EmergencyNumber<'a>>, EmergencyNumberDecodeError> {
        if self.remaining.is_empty() {
            return Ok(None);
        }
        if self.count >= 14 {
            return Err(EmergencyNumberDecodeError::TooManyRecords { maximum: 14 });
        }
        let len = usize::from(self.remaining[0]);
        if len == 0 {
            return Err(EmergencyNumberDecodeError::ZeroLength);
        }
        let number_len = len - 1;
        if number_len > 92 {
            return Err(EmergencyNumberDecodeError::NumberTooLong {
                maximum: 92,
                actual: number_len,
            });
        }
        let total = 1 + len;
        if self.remaining.len() < total {
            return Err(EmergencyNumberDecodeError::TruncatedRecord {
                expected: total,
                actual: self.remaining.len(),
            });
        }
        let record = EmergencyNumber {
            category: self.remaining[1],
            number: &self.remaining[2..total],
        };
        self.remaining = &self.remaining[total..];
        self.count += 1;
        Ok(Some(record))
    }
}

/// Recovered semantic field in the descriptor-managed normal Attach suffix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachTailField<'a> {
    LowerLayerReason(u8),
    EpsAttachResult(u8),
    EsmCause(u8),
    Ipv4LinkMtu(u16),
    OperatorPco(&'a [u8]),
    T3402(u32),
    ApnAmbr { uplink: u32, downlink: u32 },
    EmergencyNumbers(EmergencyNumberList<'a>),
    Msisdn(&'a [u8]),
    Unknown(Tlv<'a>),
}

/// Malformed recognized field in the normal Attach suffix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachTailDecodeError {
    Tlv(TlvDecodeError),
    UnexpectedLength {
        kind: u8,
        expected: usize,
        actual: usize,
    },
    FieldTooLong {
        kind: u8,
        maximum: usize,
        actual: usize,
    },
    Emergency(EmergencyNumberDecodeError),
}

impl From<TlvDecodeError> for AttachTailDecodeError {
    fn from(value: TlvDecodeError) -> Self {
        Self::Tlv(value)
    }
}

impl From<EmergencyNumberDecodeError> for AttachTailDecodeError {
    fn from(value: EmergencyNumberDecodeError) -> Self {
        Self::Emergency(value)
    }
}

/// Cursor over the descriptor-managed normal Attach suffix.
pub struct AttachTailCursor<'a> {
    cursor: TlvCursor<'a>,
}

impl<'a> AttachTailCursor<'a> {
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self {
            cursor: TlvCursor::new(bytes),
        }
    }

    /// Decode one field using the live P4 normal-Attach descriptor table.
    ///
    /// # Errors
    /// Returns [`AttachTailDecodeError`] for malformed TLV framing or a known
    /// field whose payload cannot fit its recovered legacy destination.
    pub fn next_field(&mut self) -> Result<Option<AttachTailField<'a>>, AttachTailDecodeError> {
        let Some(tlv) = self.cursor.next_tlv()? else {
            return Ok(None);
        };
        let exact = |expected: usize| {
            if tlv.payload.len() == expected {
                Ok(())
            } else {
                Err(AttachTailDecodeError::UnexpectedLength {
                    kind: tlv.kind,
                    expected,
                    actual: tlv.payload.len(),
                })
            }
        };
        let one = || -> Result<u8, AttachTailDecodeError> {
            exact(1)?;
            Ok(tlv.payload[0])
        };
        let field = match tlv.kind {
            0x58 => AttachTailField::LowerLayerReason(one()?),
            0x59 => AttachTailField::EpsAttachResult(one()?),
            0x5a => AttachTailField::EsmCause(one()?),
            0x5b => {
                exact(2)?;
                AttachTailField::Ipv4LinkMtu(u16::from_be_bytes([tlv.payload[0], tlv.payload[1]]))
            }
            0x5d => {
                if tlv.payload.len() > 100 {
                    return Err(AttachTailDecodeError::FieldTooLong {
                        kind: tlv.kind,
                        maximum: 100,
                        actual: tlv.payload.len(),
                    });
                }
                AttachTailField::OperatorPco(tlv.payload)
            }
            0x5e => {
                exact(4)?;
                AttachTailField::T3402(be_u32(tlv.payload, 0))
            }
            0xf3 => {
                exact(8)?;
                AttachTailField::ApnAmbr {
                    uplink: be_u32(tlv.payload, 0),
                    downlink: be_u32(tlv.payload, 4),
                }
            }
            0xf4 => {
                let list = EmergencyNumberList {
                    payload: tlv.payload,
                };
                list.validate()?;
                AttachTailField::EmergencyNumbers(list)
            }
            0xf8 => {
                if tlv.payload.len() > 21 {
                    return Err(AttachTailDecodeError::FieldTooLong {
                        kind: tlv.kind,
                        maximum: 21,
                        actual: tlv.payload.len(),
                    });
                }
                AttachTailField::Msisdn(tlv.payload)
            }
            _ => AttachTailField::Unknown(tlv),
        };
        Ok(Some(field))
    }
}

/// Fully split normal Attach response `0xb102`.
///
/// Live P4 consumes the common 15-byte prefix, mandatory transaction TLV, one
/// APN TLV by position, at most two contiguous `0xf0`/`0xf2` PDN-info
/// containers, then a descriptor-driven tail. The APN helper does not inspect
/// its tag, so the clean parser intentionally preserves that positional
/// behavior while bounding the historical 64-byte destination.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttachResponse<'a> {
    pub register_result1: u16,
    pub register_result2: u16,
    pub default_eps_id: u16,
    pub eps_id: u16,
    pub data_path: u8,
    pub ip_alloc: u8,
    pub network_features: NetworkFeatureInfo,
    pub transaction_id: u8,
    pub apn_ni: OrderedPdnTlv<'a>,
    initial_pdn_info: &'a [u8],
    trailing_fields: &'a [u8],
}

impl<'a> AttachResponse<'a> {
    /// Decode the complete recovered normal-Attach response layout.
    ///
    /// # Errors
    /// Returns [`AttachResponseDecodeError`] for the wrong opcode, malformed
    /// fixed prefix/transaction/APN TLV, an APN longer than 64 bytes, or broken
    /// framing in one of the initial PDN containers.
    pub fn parse(packet: Packet<'a>) -> Result<Self, AttachResponseDecodeError> {
        let prefix = AttachResponsePrefix::parse(AttachResponseKind::Normal, packet)?;
        let mut cursor = TlvCursor::new(prefix.optional_fields);
        let transaction = cursor
            .next_tlv()?
            .ok_or(AttachResponseDecodeError::MissingTransaction)?;
        if transaction.kind != 0x20 {
            return Err(AttachResponseDecodeError::UnexpectedTransactionKind {
                expected: 0x20,
                actual: transaction.kind,
            });
        }
        if transaction.payload.len() != 1 {
            return Err(AttachResponseDecodeError::UnexpectedTransactionLength {
                expected: 1,
                actual: transaction.payload.len(),
            });
        }
        let apn = cursor
            .next_tlv()?
            .ok_or(AttachResponseDecodeError::MissingApnNetworkIdentifier)?;
        if apn.payload.len() > 64 {
            return Err(AttachResponseDecodeError::ApnNetworkIdentifierTooLong {
                maximum: 64,
                actual: apn.payload.len(),
            });
        }
        let (initial_pdn_info, trailing_fields) = split_initial_pdn_info(cursor.remaining())?;

        Ok(Self {
            register_result1: prefix.register_result1,
            register_result2: prefix.register_result2,
            default_eps_id: prefix.default_eps_id,
            eps_id: prefix.eps_id,
            data_path: prefix.data_path,
            ip_alloc: prefix.ip_alloc,
            network_features: prefix.network_features,
            transaction_id: transaction.payload[0],
            apn_ni: OrderedPdnTlv {
                kind: apn.kind,
                payload: apn.payload,
            },
            initial_pdn_info,
            trailing_fields,
        })
    }

    #[must_use]
    pub const fn pdn_info_containers(&self) -> PdnInfoContainers<'a> {
        PdnInfoContainers::new(self.initial_pdn_info)
    }

    #[must_use]
    pub const fn trailing_fields(&self) -> AttachTailCursor<'a> {
        AttachTailCursor::new(self.trailing_fields)
    }
}

impl<'a> AttachResponsePrefix<'a> {
    /// Decode the proven 15-byte common attach-response prefix and borrow the
    /// parser-managed suffix.
    ///
    /// # Errors
    ///
    /// Returns [`ResponseDecodeError`] for the wrong opcode or a payload shorter
    /// than the common prefix.
    pub fn parse(
        kind: AttachResponseKind,
        packet: Packet<'a>,
    ) -> Result<Self, ResponseDecodeError> {
        let payload = prefix_payload(packet, kind.opcode(), 15)?;
        Ok(Self {
            register_result1: be_u16(payload, 0),
            register_result2: be_u16(payload, 2),
            default_eps_id: be_u16(payload, 4),
            eps_id: be_u16(payload, 6),
            data_path: payload[8],
            ip_alloc: payload[9],
            network_features: NetworkFeatureInfo {
                ims_voice_over_ps: payload[10],
                emc_bc: payload[11],
                epc_lcs: payload[12],
                sc_lcs: payload[13],
                ext_sr: payload[14],
            },
            optional_fields: &payload[15..],
        })
    }

    /// Cursor over the still-unclassified optional suffix. This is useful for
    /// the portions already known to use the common GCT TLV grammar while the
    /// nested vendor parser is being reconstructed.
    #[must_use]
    pub const fn optional_tlvs(&self) -> TlvCursor<'a> {
        TlvCursor::new(self.optional_fields)
    }
}

/// Fully split extended-attach response `0xb166`.
///
/// Live P4 consumes three fixed-order TLVs after the common 15-byte attach
/// prefix: APN class, requested APN-NI and received APN-NI. It then runs the
/// shared at-most-two `0xf0`/`0xf2` nested PDN/QoS parser and ignores any
/// suffix after those initial containers. The clean representation preserves
/// that ignored suffix for diagnostics rather than silently discarding it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttachExtResponse<'a> {
    pub register_result1: u16,
    pub register_result2: u16,
    pub default_eps_id: u16,
    pub eps_id: u16,
    pub data_path: u8,
    pub ip_alloc: u8,
    pub network_features: NetworkFeatureInfo,
    pub apn_class_kind: u8,
    pub apn_class: u8,
    pub requested_apn_ni: OrderedPdnTlv<'a>,
    pub received_apn_ni: OrderedPdnTlv<'a>,
    initial_pdn_info: &'a [u8],
    pub unparsed_suffix: &'a [u8],
}

impl<'a> AttachExtResponse<'a> {
    /// Decode the complete recovered live-P4 extended-attach response layout.
    ///
    /// # Errors
    /// Returns [`PdnResponseDecodeError`] for malformed ordered TLVs or nested
    /// container framing.
    pub fn parse(packet: Packet<'a>) -> Result<Self, PdnResponseDecodeError> {
        let prefix = AttachResponsePrefix::parse(AttachResponseKind::Extended, packet)?;
        let mut cursor = TlvCursor::new(prefix.optional_fields);

        let apn_class = required_pdn_tlv(&mut cursor, PdnResponseField::ApnClass)?;
        exact_pdn_field(PdnResponseField::ApnClass, apn_class.payload, 1)?;
        let requested =
            required_pdn_tlv(&mut cursor, PdnResponseField::RequestedApnNetworkIdentifier)?;
        bounded_pdn_field(
            PdnResponseField::RequestedApnNetworkIdentifier,
            requested.payload,
            64,
        )?;
        let received =
            required_pdn_tlv(&mut cursor, PdnResponseField::ReceivedApnNetworkIdentifier)?;
        bounded_pdn_field(
            PdnResponseField::ReceivedApnNetworkIdentifier,
            received.payload,
            64,
        )?;
        let (initial_pdn_info, unparsed_suffix) = split_initial_pdn_info(cursor.remaining())?;

        Ok(Self {
            register_result1: prefix.register_result1,
            register_result2: prefix.register_result2,
            default_eps_id: prefix.default_eps_id,
            eps_id: prefix.eps_id,
            data_path: prefix.data_path,
            ip_alloc: prefix.ip_alloc,
            network_features: prefix.network_features,
            apn_class_kind: apn_class.kind,
            apn_class: apn_class.payload[0],
            requested_apn_ni: OrderedPdnTlv {
                kind: requested.kind,
                payload: requested.payload,
            },
            received_apn_ni: OrderedPdnTlv {
                kind: received.kind,
                payload: received.payload,
            },
            initial_pdn_info,
            unparsed_suffix,
        })
    }

    #[must_use]
    pub const fn pdn_info_containers(&self) -> PdnInfoContainers<'a> {
        PdnInfoContainers::new(self.initial_pdn_info)
    }
}

/// Proven ten-byte fixed prefix of normal PDN-connect response `0xb106`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PdnConnectResponsePrefix<'a> {
    pub result: u16,
    pub reject_cause1: u16,
    pub reject_cause2: u16,
    pub default_eps_id: u16,
    pub data_path: u8,
    pub ip_alloc: u8,
    pub optional_fields: &'a [u8],
}

impl<'a> PdnConnectResponsePrefix<'a> {
    /// Decode the normal PDN-connect fixed prefix.
    ///
    /// # Errors
    ///
    /// Returns [`ResponseDecodeError`] for the wrong opcode or a payload shorter
    /// than ten bytes.
    pub fn parse(packet: Packet<'a>) -> Result<Self, ResponseDecodeError> {
        let payload = prefix_payload(packet, recovered_opcode::PDN_CONNECT_RESPONSE, 10)?;
        Ok(Self {
            result: be_u16(payload, 0),
            reject_cause1: be_u16(payload, 2),
            reject_cause2: be_u16(payload, 4),
            default_eps_id: be_u16(payload, 6),
            data_path: payload[8],
            ip_alloc: payload[9],
            optional_fields: &payload[10..],
        })
    }

    #[must_use]
    pub const fn optional_tlvs(&self) -> TlvCursor<'a> {
        TlvCursor::new(self.optional_fields)
    }
}

/// Proven twelve-byte fixed prefix of extended PDN-connect response `0xb168`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PdnConnectExtResponsePrefix<'a> {
    pub result: u16,
    pub reject_cause1: u16,
    pub reject_cause2: u16,
    pub default_eps_id: u16,
    pub data_path: u8,
    pub ip_alloc: u8,
    pub throttle_time: u16,
    pub optional_fields: &'a [u8],
}

impl<'a> PdnConnectExtResponsePrefix<'a> {
    /// Decode the extended PDN-connect fixed prefix.
    ///
    /// # Errors
    ///
    /// Returns [`ResponseDecodeError`] for the wrong opcode or a payload shorter
    /// than twelve bytes.
    pub fn parse(packet: Packet<'a>) -> Result<Self, ResponseDecodeError> {
        let payload = prefix_payload(packet, recovered_opcode::PDN_CONNECT_RESPONSE_EXT, 12)?;
        Ok(Self {
            result: be_u16(payload, 0),
            reject_cause1: be_u16(payload, 2),
            reject_cause2: be_u16(payload, 4),
            default_eps_id: be_u16(payload, 6),
            data_path: payload[8],
            ip_alloc: payload[9],
            throttle_time: be_u16(payload, 10),
            optional_fields: &payload[12..],
        })
    }

    #[must_use]
    pub const fn optional_tlvs(&self) -> TlvCursor<'a> {
        TlvCursor::new(self.optional_fields)
    }
}

/// Proven eight-byte fixed prefix of PDN-disconnect response `0xb108`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PdnDisconnectResponsePrefix<'a> {
    pub result: u16,
    pub reject_cause1: u16,
    pub reject_cause2: u16,
    pub default_eps_id: u16,
    pub optional_fields: &'a [u8],
}

impl<'a> PdnDisconnectResponsePrefix<'a> {
    /// Decode the PDN-disconnect fixed prefix.
    ///
    /// # Errors
    ///
    /// Returns [`ResponseDecodeError`] for the wrong opcode or a payload shorter
    /// than eight bytes.
    pub fn parse(packet: Packet<'a>) -> Result<Self, ResponseDecodeError> {
        let payload = prefix_payload(packet, recovered_opcode::PDN_DISCONNECT_RESPONSE, 8)?;
        Ok(Self {
            result: be_u16(payload, 0),
            reject_cause1: be_u16(payload, 2),
            reject_cause2: be_u16(payload, 4),
            default_eps_id: be_u16(payload, 6),
            optional_fields: &payload[8..],
        })
    }

    #[must_use]
    pub const fn optional_tlvs(&self) -> TlvCursor<'a> {
        TlvCursor::new(self.optional_fields)
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

fn required_pdn_tlv<'a>(
    cursor: &mut TlvCursor<'a>,
    field: PdnResponseField,
) -> Result<Tlv<'a>, PdnResponseDecodeError> {
    cursor
        .next_tlv()?
        .ok_or(PdnResponseDecodeError::MissingField(field))
}

fn exact_pdn_field(
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

fn bounded_pdn_field(
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

fn split_initial_pdn_info(bytes: &[u8]) -> Result<(&[u8], &[u8]), TlvDecodeError> {
    let mut containers = PdnInfoContainers::new(bytes);
    while containers.next_container()?.is_some() {}
    let remaining = containers.remaining();
    let consumed = bytes.len() - remaining.len();
    Ok((&bytes[..consumed], remaining))
}

/// Fully split normal PDN-connect response `0xb106`.
///
/// The OEM handler consumes a mandatory transaction TLV, then an APN TLV by
/// position, then up to two nested `0xf0`/`0xf2` containers. Remaining fields
/// are handled by a descriptor-driven trailing dispatcher.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PdnConnectResponse<'a> {
    pub result: u16,
    pub reject_cause1: u16,
    pub reject_cause2: u16,
    pub default_eps_id: u16,
    pub data_path: u8,
    pub ip_alloc: u8,
    pub transaction_id: u8,
    pub apn_ni: OrderedPdnTlv<'a>,
    initial_pdn_info: &'a [u8],
    trailing_fields: &'a [u8],
}

impl<'a> PdnConnectResponse<'a> {
    /// Decode the complete recovered normal PDN response layout.
    ///
    /// # Errors
    /// Returns [`PdnResponseDecodeError`] for a malformed fixed prefix,
    /// mandatory transaction field, APN field, or nested container framing.
    pub fn parse(packet: Packet<'a>) -> Result<Self, PdnResponseDecodeError> {
        let prefix = PdnConnectResponsePrefix::parse(packet)?;
        let mut cursor = TlvCursor::new(prefix.optional_fields);

        let transaction = required_pdn_tlv(&mut cursor, PdnResponseField::TransactionId)?;
        if transaction.kind != 0x20 {
            return Err(PdnResponseDecodeError::UnexpectedKind {
                field: PdnResponseField::TransactionId,
                expected: 0x20,
                actual: transaction.kind,
            });
        }
        exact_pdn_field(PdnResponseField::TransactionId, transaction.payload, 1)?;

        let apn = required_pdn_tlv(&mut cursor, PdnResponseField::ApnNetworkIdentifier)?;
        bounded_pdn_field(PdnResponseField::ApnNetworkIdentifier, apn.payload, 64)?;

        let (initial_pdn_info, trailing_fields) = split_initial_pdn_info(cursor.remaining())?;
        Ok(Self {
            result: prefix.result,
            reject_cause1: prefix.reject_cause1,
            reject_cause2: prefix.reject_cause2,
            default_eps_id: prefix.default_eps_id,
            data_path: prefix.data_path,
            ip_alloc: prefix.ip_alloc,
            transaction_id: transaction.payload[0],
            apn_ni: OrderedPdnTlv {
                kind: apn.kind,
                payload: apn.payload,
            },
            initial_pdn_info,
            trailing_fields,
        })
    }

    #[must_use]
    pub const fn pdn_info_containers(&self) -> PdnInfoContainers<'a> {
        PdnInfoContainers::new(self.initial_pdn_info)
    }

    #[must_use]
    pub const fn trailing_fields(&self) -> PdnConnectTailCursor<'a> {
        PdnConnectTailCursor::new(self.trailing_fields)
    }
}

/// Recovered semantic field in the trailing normal-PDN dispatcher.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PdnConnectTailField<'a> {
    Ipv4LinkMtu(u16),
    OperatorPco(&'a [u8]),
    /// Extra `0xf0` container parsed by the same inner PDN field dispatcher.
    PdnInfo(&'a [u8]),
    ApnAmbr {
        uplink: u32,
        downlink: u32,
    },
    Unknown(Tlv<'a>),
}

impl<'a> PdnConnectTailField<'a> {
    /// Return the inner TLV cursor for the descriptor-managed extra PDN-info
    /// field. Other tail variants have no nested PDN payload.
    #[must_use]
    pub fn pdn_info_fields(self) -> Option<TlvCursor<'a>> {
        match self {
            Self::PdnInfo(bytes) => Some(TlvCursor::new(bytes)),
            Self::Ipv4LinkMtu(_)
            | Self::OperatorPco(_)
            | Self::ApnAmbr { .. }
            | Self::Unknown(_) => None,
        }
    }
}

/// Malformed field in the descriptor-driven normal-PDN suffix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PdnConnectTailDecodeError {
    Tlv(TlvDecodeError),
    UnexpectedLength {
        kind: u8,
        expected: usize,
        actual: usize,
    },
    FieldTooLong {
        kind: u8,
        maximum: usize,
        actual: usize,
    },
}

impl From<TlvDecodeError> for PdnConnectTailDecodeError {
    fn from(value: TlvDecodeError) -> Self {
        Self::Tlv(value)
    }
}

/// Cursor over the descriptor-driven suffix of a normal PDN response.
pub struct PdnConnectTailCursor<'a> {
    cursor: TlvCursor<'a>,
}

impl<'a> PdnConnectTailCursor<'a> {
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self {
            cursor: TlvCursor::new(bytes),
        }
    }

    #[must_use]
    pub const fn remaining(&self) -> &'a [u8] {
        self.cursor.remaining()
    }

    /// Decode one trailing field using the four recovered OEM descriptors.
    /// Unknown TLVs are preserved instead of discarded.
    ///
    /// # Errors
    /// Returns an error for malformed TLV framing or a known field with a
    /// length that would overflow or mis-size the historical destination.
    pub fn next_field(
        &mut self,
    ) -> Result<Option<PdnConnectTailField<'a>>, PdnConnectTailDecodeError> {
        let Some(tlv) = self.cursor.next_tlv()? else {
            return Ok(None);
        };
        let field = match tlv.kind {
            0x5b => {
                if tlv.payload.len() != 2 {
                    return Err(PdnConnectTailDecodeError::UnexpectedLength {
                        kind: tlv.kind,
                        expected: 2,
                        actual: tlv.payload.len(),
                    });
                }
                PdnConnectTailField::Ipv4LinkMtu(u16::from_be_bytes([
                    tlv.payload[0],
                    tlv.payload[1],
                ]))
            }
            0x5d => {
                if tlv.payload.len() > 100 {
                    return Err(PdnConnectTailDecodeError::FieldTooLong {
                        kind: tlv.kind,
                        maximum: 100,
                        actual: tlv.payload.len(),
                    });
                }
                PdnConnectTailField::OperatorPco(tlv.payload)
            }
            0xf0 => PdnConnectTailField::PdnInfo(tlv.payload),
            0xf3 => {
                if tlv.payload.len() != 8 {
                    return Err(PdnConnectTailDecodeError::UnexpectedLength {
                        kind: tlv.kind,
                        expected: 8,
                        actual: tlv.payload.len(),
                    });
                }
                PdnConnectTailField::ApnAmbr {
                    uplink: be_u32(tlv.payload, 0),
                    downlink: be_u32(tlv.payload, 4),
                }
            }
            _ => PdnConnectTailField::Unknown(tlv),
        };
        Ok(Some(field))
    }
}

/// Fully split extended PDN-connect response `0xb168`.
///
/// Unlike the normal response, the SDK does not use a transaction ID here.
/// It consumes three fixed-order TLVs into `apn_class`, requested APN and
/// received APN destinations, then runs the shared nested PDN parser. The OEM
/// ignores bytes after those initial containers; this representation keeps
/// them borrowed as `unparsed_suffix` instead.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PdnConnectExtResponse<'a> {
    pub result: u16,
    pub reject_cause1: u16,
    pub reject_cause2: u16,
    pub default_eps_id: u16,
    pub data_path: u8,
    pub ip_alloc: u8,
    pub throttle_time: u16,
    pub apn_class_kind: u8,
    pub apn_class: u8,
    pub requested_apn_ni: OrderedPdnTlv<'a>,
    pub received_apn_ni: OrderedPdnTlv<'a>,
    initial_pdn_info: &'a [u8],
    pub unparsed_suffix: &'a [u8],
}

impl<'a> PdnConnectExtResponse<'a> {
    /// Decode the complete recovered extended PDN response layout.
    ///
    /// # Errors
    /// Returns [`PdnResponseDecodeError`] for malformed ordered TLVs or nested
    /// container framing.
    pub fn parse(packet: Packet<'a>) -> Result<Self, PdnResponseDecodeError> {
        let prefix = PdnConnectExtResponsePrefix::parse(packet)?;
        let mut cursor = TlvCursor::new(prefix.optional_fields);

        let apn_class = required_pdn_tlv(&mut cursor, PdnResponseField::ApnClass)?;
        exact_pdn_field(PdnResponseField::ApnClass, apn_class.payload, 1)?;
        let requested =
            required_pdn_tlv(&mut cursor, PdnResponseField::RequestedApnNetworkIdentifier)?;
        bounded_pdn_field(
            PdnResponseField::RequestedApnNetworkIdentifier,
            requested.payload,
            64,
        )?;
        let received =
            required_pdn_tlv(&mut cursor, PdnResponseField::ReceivedApnNetworkIdentifier)?;
        bounded_pdn_field(
            PdnResponseField::ReceivedApnNetworkIdentifier,
            received.payload,
            64,
        )?;

        let (initial_pdn_info, unparsed_suffix) = split_initial_pdn_info(cursor.remaining())?;
        Ok(Self {
            result: prefix.result,
            reject_cause1: prefix.reject_cause1,
            reject_cause2: prefix.reject_cause2,
            default_eps_id: prefix.default_eps_id,
            data_path: prefix.data_path,
            ip_alloc: prefix.ip_alloc,
            throttle_time: prefix.throttle_time,
            apn_class_kind: apn_class.kind,
            apn_class: apn_class.payload[0],
            requested_apn_ni: OrderedPdnTlv {
                kind: requested.kind,
                payload: requested.payload,
            },
            received_apn_ni: OrderedPdnTlv {
                kind: received.kind,
                payload: received.payload,
            },
            initial_pdn_info,
            unparsed_suffix,
        })
    }

    #[must_use]
    pub const fn pdn_info_containers(&self) -> PdnInfoContainers<'a> {
        PdnInfoContainers::new(self.initial_pdn_info)
    }
}

/// Fully split PDN-disconnect response `0xb108`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PdnDisconnectResponse<'a> {
    pub result: u16,
    pub reject_cause1: u16,
    pub reject_cause2: u16,
    pub default_eps_id: u16,
    pub transaction_id: u8,
    trailing_fields: &'a [u8],
}

impl<'a> PdnDisconnectResponse<'a> {
    /// Decode the fixed prefix and mandatory transaction field.
    ///
    /// # Errors
    /// Returns [`PdnResponseDecodeError`] for malformed prefix or transaction
    /// TLV framing.
    pub fn parse(packet: Packet<'a>) -> Result<Self, PdnResponseDecodeError> {
        let prefix = PdnDisconnectResponsePrefix::parse(packet)?;
        let mut cursor = TlvCursor::new(prefix.optional_fields);
        let transaction = required_pdn_tlv(&mut cursor, PdnResponseField::TransactionId)?;
        if transaction.kind != 0x20 {
            return Err(PdnResponseDecodeError::UnexpectedKind {
                field: PdnResponseField::TransactionId,
                expected: 0x20,
                actual: transaction.kind,
            });
        }
        exact_pdn_field(PdnResponseField::TransactionId, transaction.payload, 1)?;
        Ok(Self {
            result: prefix.result,
            reject_cause1: prefix.reject_cause1,
            reject_cause2: prefix.reject_cause2,
            default_eps_id: prefix.default_eps_id,
            transaction_id: transaction.payload[0],
            trailing_fields: cursor.remaining(),
        })
    }

    #[must_use]
    pub const fn trailing_fields(&self) -> PdnDisconnectFieldCursor<'a> {
        PdnDisconnectFieldCursor::new(self.trailing_fields)
    }
}

/// Field accepted by the descriptor-driven PDN-disconnect suffix parser.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PdnDisconnectField<'a> {
    ApnNetworkIdentifier(&'a [u8]),
    OperatorPco(&'a [u8]),
    Unknown(Tlv<'a>),
}

/// Error while decoding one known PDN-disconnect trailing field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PdnDisconnectFieldDecodeError {
    Tlv(TlvDecodeError),
    FieldTooLong {
        kind: u8,
        maximum: usize,
        actual: usize,
    },
}

impl From<TlvDecodeError> for PdnDisconnectFieldDecodeError {
    fn from(value: TlvDecodeError) -> Self {
        Self::Tlv(value)
    }
}

pub struct PdnDisconnectFieldCursor<'a> {
    cursor: TlvCursor<'a>,
}

impl<'a> PdnDisconnectFieldCursor<'a> {
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self {
            cursor: TlvCursor::new(bytes),
        }
    }

    #[must_use]
    pub const fn remaining(&self) -> &'a [u8] {
        self.cursor.remaining()
    }

    /// Decode one disconnect suffix field while preserving unknown TLVs.
    ///
    /// # Errors
    /// Returns an error for malformed framing or a field larger than the
    /// recovered historical destination.
    pub fn next_field(
        &mut self,
    ) -> Result<Option<PdnDisconnectField<'a>>, PdnDisconnectFieldDecodeError> {
        let Some(tlv) = self.cursor.next_tlv()? else {
            return Ok(None);
        };
        let field = match tlv.kind {
            0x57 => {
                if tlv.payload.len() > 64 {
                    return Err(PdnDisconnectFieldDecodeError::FieldTooLong {
                        kind: tlv.kind,
                        maximum: 64,
                        actual: tlv.payload.len(),
                    });
                }
                PdnDisconnectField::ApnNetworkIdentifier(tlv.payload)
            }
            0x5d => {
                if tlv.payload.len() > 100 {
                    return Err(PdnDisconnectFieldDecodeError::FieldTooLong {
                        kind: tlv.kind,
                        maximum: 100,
                        actual: tlv.payload.len(),
                    });
                }
                PdnDisconnectField::OperatorPco(tlv.payload)
            }
            _ => PdnDisconnectField::Unknown(tlv),
        };
        Ok(Some(field))
    }
}

/// One semantic PLMN record assembled from the three TLVs used by GCT.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlmnInfo {
    pub plmn_id: [u8; 3],
    pub priority: u32,
    pub status: u32,
}

/// Field names in one recovered PLMN record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlmnInfoField {
    PlmnId,
    Priority,
    Status,
}

/// Error while assembling one PLMN record from its TLV stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlmnInfoDecodeError {
    Tlv(TlvDecodeError),
    UnknownKind(u8),
    UnexpectedLength {
        kind: u8,
        expected: usize,
        actual: usize,
    },
    DuplicateField(PlmnInfoField),
    IncompleteRecord,
    TooManyRecords,
}

impl From<TlvDecodeError> for PlmnInfoDecodeError {
    fn from(value: TlvDecodeError) -> Self {
        Self::Tlv(value)
    }
}

/// Allocation-free cursor over GCT PLMN records.
///
/// The OEM parser writes into `PLMN_INFO[32]`, but one record is not an
/// eleven-byte wire struct. It is exactly three TLVs: `0x12` PLMN ID (3
/// bytes), `0x13` priority (BE u32) and `0x14` status (BE u32). The old code
/// accepts those three tags in any order and advances to the next destination
/// after three recognized fields. The clean parser keeps that order
/// independence while requiring each semantic field exactly once.
pub struct PlmnInfoCursor<'a> {
    cursor: TlvCursor<'a>,
    records: u8,
}

impl<'a> PlmnInfoCursor<'a> {
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self {
            cursor: TlvCursor::new(bytes),
            records: 0,
        }
    }

    #[must_use]
    pub const fn remaining(&self) -> &'a [u8] {
        self.cursor.remaining()
    }

    /// Decode one complete PLMN record.
    ///
    /// # Errors
    /// Returns [`PlmnInfoDecodeError`] for malformed TLV framing, unknown or
    /// duplicate record fields, wrong fixed widths, an incomplete record, or
    /// more than the 32 records provisioned by the historical SDK.
    pub fn next_record(&mut self) -> Result<Option<PlmnInfo>, PlmnInfoDecodeError> {
        if self.cursor.remaining().is_empty() {
            return Ok(None);
        }
        if self.records >= 32 {
            return Err(PlmnInfoDecodeError::TooManyRecords);
        }

        let mut plmn_id = None;
        let mut priority = None;
        let mut status = None;
        for _ in 0..3 {
            let Some(tlv) = self.cursor.next_tlv()? else {
                return Err(PlmnInfoDecodeError::IncompleteRecord);
            };
            match tlv.kind {
                0x12 => {
                    let Ok(value) = <[u8; 3]>::try_from(tlv.payload) else {
                        return Err(PlmnInfoDecodeError::UnexpectedLength {
                            kind: tlv.kind,
                            expected: 3,
                            actual: tlv.payload.len(),
                        });
                    };
                    if plmn_id.replace(value).is_some() {
                        return Err(PlmnInfoDecodeError::DuplicateField(PlmnInfoField::PlmnId));
                    }
                }
                0x13 => {
                    let Ok(value) = <[u8; 4]>::try_from(tlv.payload) else {
                        return Err(PlmnInfoDecodeError::UnexpectedLength {
                            kind: tlv.kind,
                            expected: 4,
                            actual: tlv.payload.len(),
                        });
                    };
                    if priority.replace(u32::from_be_bytes(value)).is_some() {
                        return Err(PlmnInfoDecodeError::DuplicateField(PlmnInfoField::Priority));
                    }
                }
                0x14 => {
                    let Ok(value) = <[u8; 4]>::try_from(tlv.payload) else {
                        return Err(PlmnInfoDecodeError::UnexpectedLength {
                            kind: tlv.kind,
                            expected: 4,
                            actual: tlv.payload.len(),
                        });
                    };
                    if status.replace(u32::from_be_bytes(value)).is_some() {
                        return Err(PlmnInfoDecodeError::DuplicateField(PlmnInfoField::Status));
                    }
                }
                other => return Err(PlmnInfoDecodeError::UnknownKind(other)),
            }
        }

        let (Some(plmn_id), Some(priority), Some(status)) = (plmn_id, priority, status) else {
            return Err(PlmnInfoDecodeError::IncompleteRecord);
        };
        self.records += 1;
        Ok(Some(PlmnInfo {
            plmn_id,
            priority,
            status,
        }))
    }
}

/// Borrowed SIB1 PLMN-list payload from search-response TLV `0x26`.
///
/// The old destination is 49 bytes (`count` + 48 payload bytes). The OEM
/// clamps larger TLVs by mutating their length byte; this clean parser rejects
/// that malformed shape instead. A zero-length payload is representable because
/// the historical destination was zero-initialized before a zero-byte copy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Sib1PlmnList<'a> {
    pub count: u8,
    pub packed_plmn: &'a [u8],
}

/// Error returned while decoding a complete PLMN search response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlmnSearchDecodeError {
    Response(ResponseDecodeError),
    Tlv(TlvDecodeError),
    UnexpectedMetadataLength {
        kind: u8,
        expected: usize,
        actual: usize,
    },
    Sib1PlmnTooLong {
        maximum: usize,
        actual: usize,
    },
    MissingMetadata(u8),
}

impl From<ResponseDecodeError> for PlmnSearchDecodeError {
    fn from(value: ResponseDecodeError) -> Self {
        Self::Response(value)
    }
}

impl From<TlvDecodeError> for PlmnSearchDecodeError {
    fn from(value: TlvDecodeError) -> Self {
        Self::Tlv(value)
    }
}

/// Decoded fixed prefix and borrowed record stream of PLMN-search response
/// `0xb10a`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlmnSearchResponse<'a> {
    pub result: u32,
    pub selection_mode: u8,
    pub selected_plmn_id: [u8; 3],
    pub next_index: u16,
    pub network_interval: u16,
    pub remaining_count: i8,
    pub band: u16,
    pub cell_id: u16,
    pub frequency: u32,
    pub tac: [u8; 2],
    pub bit28_cell_id: u32,
    pub plmn_priority: Option<u32>,
    pub sib1_plmn: Option<Sib1PlmnList<'a>>,
    records: &'a [u8],
}

impl<'a> PlmnSearchResponse<'a> {
    /// Decode the recovered 27-byte fixed prefix plus the two contextual
    /// success-only metadata TLVs at the head of the remaining stream.
    ///
    /// # Errors
    /// Returns [`PlmnSearchDecodeError`] for the wrong opcode, truncated fixed
    /// prefix or malformed contextual `0x13`/`0x26` metadata.
    pub fn parse(packet: Packet<'a>) -> Result<Self, PlmnSearchDecodeError> {
        let payload = prefix_payload(packet, recovered_opcode::PLMN_SEARCH_RESPONSE, 27)?;
        let result = be_u32(payload, 0);
        let mut cursor = TlvCursor::new(&payload[27..]);
        let mut plmn_priority = None;
        let mut sib1_plmn = None;

        if result == 0 {
            if cursor.remaining().first() == Some(&0x13) {
                let tlv = cursor
                    .next_tlv()?
                    .ok_or(PlmnSearchDecodeError::MissingMetadata(0x13))?;
                let Ok(bytes) = <[u8; 4]>::try_from(tlv.payload) else {
                    return Err(PlmnSearchDecodeError::UnexpectedMetadataLength {
                        kind: tlv.kind,
                        expected: 4,
                        actual: tlv.payload.len(),
                    });
                };
                plmn_priority = Some(u32::from_be_bytes(bytes));
            }
            if cursor.remaining().first() == Some(&0x26) {
                let tlv = cursor
                    .next_tlv()?
                    .ok_or(PlmnSearchDecodeError::MissingMetadata(0x26))?;
                if tlv.payload.len() > 49 {
                    return Err(PlmnSearchDecodeError::Sib1PlmnTooLong {
                        maximum: 49,
                        actual: tlv.payload.len(),
                    });
                }
                let (count, packed_plmn) = match tlv.payload.split_first() {
                    Some((&count, rest)) => (count, rest),
                    None => (0, &[][..]),
                };
                sib1_plmn = Some(Sib1PlmnList { count, packed_plmn });
            }
        }

        Ok(Self {
            result,
            selection_mode: payload[4],
            selected_plmn_id: [payload[5], payload[6], payload[7]],
            next_index: be_u16(payload, 8),
            network_interval: be_u16(payload, 10),
            remaining_count: payload[12].cast_signed(),
            band: be_u16(payload, 13),
            cell_id: be_u16(payload, 15),
            frequency: be_u32(payload, 17),
            tac: [payload[21], payload[22]],
            bit28_cell_id: be_u32(payload, 23),
            plmn_priority,
            sib1_plmn,
            records: cursor.remaining(),
        })
    }

    #[must_use]
    pub const fn records(&self) -> PlmnInfoCursor<'a> {
        PlmnInfoCursor::new(self.records)
    }
}

/// PLMN-list response `0xb10c`: one `search_complete` byte followed by the
/// shared PLMN-info TLV stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlmnListResponse<'a> {
    pub search_complete: u8,
    records: &'a [u8],
}

impl<'a> PlmnListResponse<'a> {
    /// Decode the list-response prefix and borrow its PLMN record stream.
    ///
    /// # Errors
    /// Returns [`ResponseDecodeError`] for the wrong opcode or an empty
    /// payload.
    pub fn parse(packet: Packet<'a>) -> Result<Self, ResponseDecodeError> {
        let payload = prefix_payload(packet, recovered_opcode::PLMN_LIST_RESPONSE, 1)?;
        Ok(Self {
            search_complete: payload[0],
            records: &payload[1..],
        })
    }

    #[must_use]
    pub const fn records(&self) -> PlmnInfoCursor<'a> {
        PlmnInfoCursor::new(self.records)
    }
}

/// Typed PLMN-search request `0x3109`.
///
/// `search_mode == 0` makes the SDK send the wildcard PLMN bytes `ff ff ff`.
/// Other modes pack caller-provided MCC/MNC nibbles into the same three-byte
/// representation used by the live P4 implementation. `mnc[2] = 0x0f` is the
/// conventional filler for a two-digit MNC; the codec deliberately does not
/// invent digit validation absent from the OEM encoder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlmnSearchRequest {
    pub search_mode: u8,
    pub mcc: [u8; 3],
    pub mnc: [u8; 3],
    pub emergency_mode: u8,
    pub roaming_option: u8,
}

impl PlmnSearchRequest {
    /// Encode the exact ten-byte search payload recovered from B014 and live
    /// P4, including TLVs `0x62` and `0x63`.
    ///
    /// # Errors
    /// Returns [`EncodeError::NoSpace`] when `output` is shorter than the
    /// fourteen-byte HCI frame.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, EncodeError> {
        let mut payload = [0_u8; 10];
        payload[0] = self.search_mode;
        if self.search_mode == 0 {
            payload[1..4].fill(0xff);
        } else {
            payload[1] = (self.mcc[1] << 4) | self.mcc[0];
            payload[2] = (self.mnc[2] << 4) | self.mcc[2];
            payload[3] = (self.mnc[1] << 4) | self.mnc[0];
        }
        payload[4..7].copy_from_slice(&[0x62, 0x01, self.emergency_mode]);
        payload[7..10].copy_from_slice(&[0x63, 0x01, self.roaming_option]);
        encode_packet(recovered_opcode::PLMN_SEARCH_REQUEST, &payload, output)
    }
}

/// Live-P4 extended PLMN-search request (`0x315a`).
///
/// The historical stock object is 1,292 bytes, but the P4 SDK serializes only
/// the fields represented here. Shipped P4 profiles set `earfcn_ext=1`, so
/// list element types 2/4 carry 32-bit EARFCNs unchanged on the modem wire.
/// `fastScanOption`, ECI and the 1,020-byte reserved area are not read by the
/// live serializer and deliberately do not exist in this clean representation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlmnSearchExtRequest<'a> {
    pub selection_mode: u8,
    pub operation_mode: u8,
    pub mcc: [u8; 3],
    pub mnc: [u8; 3],
    pub roaming_option: u8,
    pub list_count: u8,
    pub list_data: &'a [u8],
    pub power_scan: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlmnSearchExtEncodeError {
    ListTooLong {
        maximum: usize,
        actual: usize,
    },
    TruncatedElementHeader {
        index: usize,
        remaining: usize,
    },
    UnsupportedElementType {
        index: usize,
        kind: u8,
    },
    TruncatedElement {
        index: usize,
        kind: u8,
        expected: usize,
        remaining: usize,
    },
    ListLengthMismatch {
        declared: usize,
        consumed: usize,
    },
    Hci(EncodeError),
}

impl From<EncodeError> for PlmnSearchExtEncodeError {
    fn from(value: EncodeError) -> Self {
        Self::Hci(value)
    }
}

impl PlmnSearchExtRequest<'_> {
    fn validated_list_len(self) -> Result<usize, PlmnSearchExtEncodeError> {
        if self.list_count == 0 {
            return Ok(0);
        }
        if self.list_data.len() > 255 {
            return Err(PlmnSearchExtEncodeError::ListTooLong {
                maximum: 255,
                actual: self.list_data.len(),
            });
        }
        let mut offset = 0_usize;
        for index in 0..usize::from(self.list_count) {
            let remaining = self.list_data.len().saturating_sub(offset);
            if remaining < 2 {
                return Err(PlmnSearchExtEncodeError::TruncatedElementHeader { index, remaining });
            }
            let kind = self.list_data[offset];
            let count = usize::from(self.list_data[offset + 1]);
            let item_width = match kind {
                2 => 4_usize, // 32-bit EARFCN (P4 earfcn_ext=1)
                3 => 1_usize, // band byte
                4 => 8_usize, // start/end 32-bit EARFCN pair
                _ => {
                    return Err(PlmnSearchExtEncodeError::UnsupportedElementType { index, kind });
                }
            };
            let body_len = count.checked_mul(item_width).ok_or(
                PlmnSearchExtEncodeError::TruncatedElement {
                    index,
                    kind,
                    expected: usize::MAX,
                    remaining: remaining.saturating_sub(2),
                },
            )?;
            let element_len = 2_usize.checked_add(body_len).ok_or(
                PlmnSearchExtEncodeError::TruncatedElement {
                    index,
                    kind,
                    expected: usize::MAX,
                    remaining,
                },
            )?;
            if element_len > remaining {
                return Err(PlmnSearchExtEncodeError::TruncatedElement {
                    index,
                    kind,
                    expected: element_len,
                    remaining,
                });
            }
            offset += element_len;
        }
        if offset != self.list_data.len() {
            return Err(PlmnSearchExtEncodeError::ListLengthMismatch {
                declared: self.list_data.len(),
                consumed: offset,
            });
        }
        Ok(offset)
    }

    /// Encode exactly the fields read by live P4 `LAPI_PLMNSearchExtRequest`.
    ///
    /// Payload grammar is `selection_mode | operation_mode`, followed by
    /// `0x63 | roaming` for selection modes 0/2 or `0x64 | packed_plmn[3]`
    /// otherwise. A non-empty scan list is `0x65 | len | list_data`, and
    /// `power_scan` appends `0x66 | 1`.
    ///
    /// # Errors
    /// Returns [`PlmnSearchExtEncodeError`] for a malformed fixed-list grammar
    /// or insufficient destination space.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, PlmnSearchExtEncodeError> {
        let list_len = self.validated_list_len()?;
        let mut payload = [0_u8; 265];
        let mut used = 0_usize;
        payload[used] = self.selection_mode;
        payload[used + 1] = self.operation_mode;
        used += 2;

        if matches!(self.selection_mode, 0 | 2) {
            payload[used] = 0x63;
            payload[used + 1] = self.roaming_option;
            used += 2;
        } else {
            payload[used] = 0x64;
            payload[used + 1] = (self.mcc[1] << 4) | self.mcc[0];
            payload[used + 2] = (self.mnc[2] << 4) | self.mcc[2];
            payload[used + 3] = (self.mnc[1] << 4) | self.mnc[0];
            used += 4;
        }

        if self.list_count != 0 {
            let list_len_u8 =
                u8::try_from(list_len).map_err(|_| PlmnSearchExtEncodeError::ListTooLong {
                    maximum: 255,
                    actual: list_len,
                })?;
            payload[used] = 0x65;
            payload[used + 1] = list_len_u8;
            payload[used + 2..used + 2 + list_len].copy_from_slice(self.list_data);
            used += 2 + list_len;
        }

        if self.power_scan {
            payload[used] = 0x66;
            payload[used + 1] = 1;
            used += 2;
        }

        Ok(encode_packet(
            recovered_opcode::PLMN_SEARCH_REQUEST_EXT,
            &payload[..used],
            output,
        )?)
    }
}

/// Mobile-ID read request carried by the shared `0x3145` read-info command.
///
/// Live P4 `LAPI_MobileIDReadRequest` emits a five-byte payload containing two
/// SDK-generated big-endian words (`1`, `1`) followed by the caller's one-byte
/// `mobile_id_type`. The same HCI opcode is shared by adjacent identity/status
/// reads, so the subtype words are part of the typed request rather than being
/// inferred from opcode adjacency.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MobileIdReadRequest {
    pub mobile_id_type: u8,
}

impl MobileIdReadRequest {
    /// Encode exact live-P4 bytes `31 45 00 05 00 01 00 01 <type>`.
    ///
    /// # Errors
    /// Returns [`EncodeError::NoSpace`] when `output` is shorter than nine
    /// bytes.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, EncodeError> {
        encode_packet(
            recovered_opcode::MISC_READ_REQUEST,
            &[0x00, 0x01, 0x00, 0x01, self.mobile_id_type],
            output,
        )
    }
}

/// One successful Mobile-ID chunk recovered from shared response `0xb146`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MobileIdReadResponse<'a> {
    pub read_result: u16,
    pub id_type: u8,
    pub result: u8,
    pub id: &'a [u8],
}

/// Decoded shape of the shared `0xb146` read-info response relevant to the
/// currently proven compatibility surface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MiscReadResponse<'a> {
    /// Top-level nonzero result. Live SDK exits before dispatching any subtype
    /// callback, so no subtype identity exists on this path.
    Failure {
        read_result: u16,
    },
    MobileId(MobileIdReadResponse<'a>),
    /// Successful response containing only not-yet-modeled read subtypes.
    UnsupportedSuccess,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MiscReadDecodeError {
    Response(ResponseDecodeError),
    TruncatedChunkHeader {
        offset: usize,
        actual: usize,
    },
    TruncatedChunk {
        subtype: u16,
        declared: usize,
        actual: usize,
    },
    MobileIdBodyTooShort {
        actual: usize,
    },
    MobileIdChunkTooLong {
        actual: usize,
    },
    MobileIdEmbeddedLength {
        declared: usize,
        available: usize,
    },
}

impl From<ResponseDecodeError> for MiscReadDecodeError {
    fn from(value: ResponseDecodeError) -> Self {
        Self::Response(value)
    }
}

impl<'a> MiscReadResponse<'a> {
    /// Decode the live-P4 shared read response and extract Mobile-ID subtype 1.
    ///
    /// Wire grammar on success is `read_result:u16 == 0`, followed by zero or
    /// more chunks `subtype:u16 | len:u16 | body[len]`. Mobile ID is subtype 1
    /// with body `id_type:u8 | result:u8 | len:u8 | id...`. The SDK's
    /// historical object has a 16-byte ID array; overlong or truncated bodies
    /// are rejected before they can become stock callbacks.
    ///
    /// # Errors
    /// Returns [`MiscReadDecodeError`] for the wrong opcode, a truncated chunk
    /// envelope/body, or an unsafe Mobile-ID length.
    pub fn parse(packet: Packet<'a>) -> Result<Self, MiscReadDecodeError> {
        let payload = prefix_payload(packet, recovered_opcode::MISC_READ_RESPONSE, 2)?;
        let read_result = be_u16(payload, 0);
        if read_result != 0 {
            return Ok(Self::Failure { read_result });
        }

        let mut offset = 2_usize;
        while offset < payload.len() {
            let remaining = payload.len() - offset;
            if remaining < 4 {
                return Err(MiscReadDecodeError::TruncatedChunkHeader {
                    offset,
                    actual: remaining,
                });
            }
            let subtype = be_u16(payload, offset);
            let declared = usize::from(be_u16(payload, offset + 2));
            let body_start = offset + 4;
            let available = payload.len() - body_start;
            if declared > available {
                return Err(MiscReadDecodeError::TruncatedChunk {
                    subtype,
                    declared,
                    actual: available,
                });
            }
            let body = &payload[body_start..body_start + declared];
            if subtype == 1 {
                if body.len() < 3 {
                    return Err(MiscReadDecodeError::MobileIdBodyTooShort { actual: body.len() });
                }
                let slot_payload = body.len() - 3;
                if slot_payload > 16 {
                    return Err(MiscReadDecodeError::MobileIdChunkTooLong {
                        actual: slot_payload,
                    });
                }
                let id_len = usize::from(body[2]);
                if id_len > slot_payload || id_len > 16 {
                    return Err(MiscReadDecodeError::MobileIdEmbeddedLength {
                        declared: id_len,
                        available: slot_payload.min(16),
                    });
                }
                return Ok(Self::MobileId(MobileIdReadResponse {
                    read_result,
                    id_type: body[0],
                    result: body[1],
                    id: &body[3..3 + id_len],
                }));
            }
            offset = body_start + declared;
        }
        Ok(Self::UnsupportedSuccess)
    }
}

/// EMM timer-control request carried by shared command `0x3155` discriminator 7.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EmmTimerControlRequest {
    pub timer_id: u16,
    pub timer_value_unit: u8,
    pub timer_value: u8,
}

impl EmmTimerControlRequest {
    /// Encode the exact eight-byte live-P4 payload
    /// `00 07 00 04 <timer_id:u16> <unit:u8> <value:u8>`.
    ///
    /// # Errors
    /// Returns [`EncodeError::NoSpace`] when `output` is shorter than 12 bytes.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, EncodeError> {
        let timer_id = self.timer_id.to_be_bytes();
        encode_packet(
            recovered_opcode::EMM_CONTROL_REQUEST,
            &[
                0x00,
                0x07,
                0x00,
                0x04,
                timer_id[0],
                timer_id[1],
                self.timer_value_unit,
                self.timer_value,
            ],
            output,
        )
    }
}

/// Power-saving-mode control request carried by shared command `0x3155`
/// discriminator 8.
///
/// B014 DWARF names the exact six-byte object `_PSM_CTRL_REQ`; live P4
/// `LAPI_PSMctrlRequest` consumes the same fields and width.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PsmControlRequest {
    pub ctrl_cmd: u16,
    pub t3324_timer_value_unit: u8,
    pub t3324_timer_value: u8,
    pub ext_t3412_timer_value_unit: u8,
    pub ext_t3412_timer_value: u8,
}

impl PsmControlRequest {
    /// Encode exact live-P4 bytes
    /// `00 08 00 06 <ctrl:u16> <T3324 unit,value> <ext-T3412 unit,value>`.
    ///
    /// # Errors
    /// Returns [`EncodeError::NoSpace`] when `output` is shorter than 14 bytes.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, EncodeError> {
        let ctrl_cmd = self.ctrl_cmd.to_be_bytes();
        encode_packet(
            recovered_opcode::EMM_CONTROL_REQUEST,
            &[
                0x00,
                0x08,
                0x00,
                0x06,
                ctrl_cmd[0],
                ctrl_cmd[1],
                self.t3324_timer_value_unit,
                self.t3324_timer_value,
                self.ext_t3412_timer_value_unit,
                self.ext_t3412_timer_value,
            ],
            output,
        )
    }
}

/// LCS control request carried by shared command `0x3155` discriminator 9.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LcsControlRequest {
    pub mode: u32,
}

impl LcsControlRequest {
    /// Encode exact live-P4 bytes `00 09 00 04 <mode:u32>`.
    ///
    /// # Errors
    /// Returns [`EncodeError::NoSpace`] when `output` is shorter than 12 bytes.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, EncodeError> {
        let mode = self.mode.to_be_bytes();
        encode_packet(
            recovered_opcode::EMM_CONTROL_REQUEST,
            &[0x00, 0x09, 0x00, 0x04, mode[0], mode[1], mode[2], mode[3]],
            output,
        )
    }
}

/// LPP control request carried by shared command `0x3155` discriminator 10.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LppControlRequest {
    pub mode: u32,
}

impl LppControlRequest {
    /// Encode exact live-P4 bytes `00 0a 00 04 <mode:u32>`.
    ///
    /// # Errors
    /// Returns [`EncodeError::NoSpace`] when `output` is shorter than 12 bytes.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, EncodeError> {
        let mode = self.mode.to_be_bytes();
        encode_packet(
            recovered_opcode::EMM_CONTROL_REQUEST,
            &[0x00, 0x0a, 0x00, 0x04, mode[0], mode[1], mode[2], mode[3]],
            output,
        )
    }
}

/// Network-initiated reattach-control request carried by shared command
/// `0x3155` discriminator 11.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EmmNiReattachControlRequest {
    pub control: u32,
}

impl EmmNiReattachControlRequest {
    /// Encode exact live-P4 bytes `00 0b 00 04 <control:u32>`.
    ///
    /// # Errors
    /// Returns [`EncodeError::NoSpace`] when `output` is shorter than 12 bytes.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, EncodeError> {
        let control = self.control.to_be_bytes();
        encode_packet(
            recovered_opcode::EMM_CONTROL_REQUEST,
            &[
                0x00, 0x0b, 0x00, 0x04, control[0], control[1], control[2], control[3],
            ],
            output,
        )
    }
}

/// Malformed shared EMM-control response/report envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EmmControlDecodeError {
    Response(ResponseDecodeError),
    UnexpectedValueLength { expected: u16, actual: u16 },
}

impl From<ResponseDecodeError> for EmmControlDecodeError {
    fn from(value: ResponseDecodeError) -> Self {
        Self::Response(value)
    }
}

fn parse_emm_control_envelope(
    packet: Packet<'_>,
    opcode: u16,
) -> Result<(u16, u16, u32), EmmControlDecodeError> {
    let payload = exact_payload(packet, opcode, 10)?;
    let value_len = be_u16(payload, 4);
    if value_len != 4 {
        return Err(EmmControlDecodeError::UnexpectedValueLength {
            expected: 4,
            actual: value_len,
        });
    }
    Ok((be_u16(payload, 0), be_u16(payload, 2), be_u32(payload, 6)))
}

/// Shared `0xb156` control response. Live P4 only wires discriminator 11 to the
/// NI-reattach stock callback; discriminators 7 (timer), 8 (PSM), 9 (LCS), and
/// 10 (LPP) are deliberately dropped by the SDK switch and remain
/// [`Self::Unsupported`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EmmControlResponse {
    NiReattach { result: u32 },
    Unsupported { kind: u16 },
}

impl EmmControlResponse {
    /// Decode the exact ten-byte shared response envelope.
    ///
    /// # Errors
    /// Returns [`EmmControlDecodeError`] for a malformed opcode/length envelope.
    pub fn parse(packet: Packet<'_>) -> Result<Self, EmmControlDecodeError> {
        let (_prefix, kind, value) =
            parse_emm_control_envelope(packet, recovered_opcode::EMM_CONTROL_RESPONSE)?;
        Ok(if kind == 11 {
            Self::NiReattach { result: value }
        } else {
            Self::Unsupported { kind }
        })
    }
}

/// Live P4 reattach-control report materialized from shared `0xb164`
/// discriminator 11. The SDK callback object is exactly six bytes: the first
/// envelope word followed by the converted four-byte value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EmmReattachControlReport {
    pub prefix: u16,
    pub value: u32,
}

/// Shared `0xb164` report decoder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EmmControlReport {
    Reattach(EmmReattachControlReport),
    Unsupported { kind: u16 },
}

impl EmmControlReport {
    /// Decode the exact ten-byte shared report envelope.
    ///
    /// # Errors
    /// Returns [`EmmControlDecodeError`] for a malformed opcode/length envelope.
    pub fn parse(packet: Packet<'_>) -> Result<Self, EmmControlDecodeError> {
        let (prefix, kind, value) =
            parse_emm_control_envelope(packet, recovered_opcode::EMM_CONTROL_REPORT)?;
        Ok(if kind == 11 {
            Self::Reattach(EmmReattachControlReport { prefix, value })
        } else {
            Self::Unsupported { kind }
        })
    }
}

/// UE-mode-change request `0x3118`.
///
/// Live P4 `LAPI_UeModeChangeRequest` allocates a five-byte HCI frame and copies
/// the caller's single `mode` byte unchanged into the payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UeModeChangeRequest {
    pub mode: u8,
}

impl UeModeChangeRequest {
    /// Encode the exact one-byte UE-mode-change payload.
    ///
    /// # Errors
    /// Returns [`EncodeError::NoSpace`] when `output` is shorter than five bytes.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, EncodeError> {
        encode_packet(
            recovered_opcode::UE_MODE_CHANGE_REQUEST,
            &[self.mode],
            output,
        )
    }
}

/// Exact one-byte UE-mode-change response `0xb14f`.
///
/// The live SDK dispatch-table entry targets handler `0x2628c`, which converts
/// one payload byte and invokes SDK callback 82. B014 DWARF independently names
/// the one-byte response field `result`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UeModeChangeResponse {
    pub result: u8,
}

impl UeModeChangeResponse {
    /// Decode the exact one-byte response.
    ///
    /// # Errors
    /// Returns [`ResponseDecodeError`] for another opcode or any non-one-byte payload.
    pub fn parse(packet: Packet<'_>) -> Result<Self, ResponseDecodeError> {
        let payload = exact_payload(packet, recovered_opcode::UE_MODE_CHANGE_RESPONSE, 1)?;
        Ok(Self { result: payload[0] })
    }
}

/// PLMN-search-stop request `0x3127`.
///
/// B014 DWARF describes `_PLMN_SEARCH_STOP_REQ_PARAM` as one byte named
/// `search_type`; live P4 `LAPI_PLMNSearchStopRequest` allocates a five-byte
/// HCI frame and copies exactly that byte into the payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlmnSearchStopRequest {
    pub search_type: u8,
}

impl PlmnSearchStopRequest {
    /// Encode the exact one-byte stop-search payload.
    ///
    /// # Errors
    /// Returns [`EncodeError::NoSpace`] when `output` is shorter than five
    /// bytes.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, EncodeError> {
        encode_packet(
            recovered_opcode::PLMN_SEARCH_STOP_REQUEST,
            &[self.search_type],
            output,
        )
    }
}

/// PLMN-search-stop response `0xb128`.
///
/// Live P4 handler `0x12228` copies payload byte 0 unchanged and converts bytes
/// 1..5 with `D4H`; B014 DWARF names those fields `search_type:u8` and
/// `result:u32` in a five-byte callback object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlmnSearchStopResponse {
    pub search_type: u8,
    pub result: u32,
}

impl PlmnSearchStopResponse {
    /// Decode the exact five-byte stop-search response.
    ///
    /// # Errors
    /// Returns [`ResponseDecodeError`] for another opcode or a payload whose
    /// length is not exactly five bytes.
    pub fn parse(packet: Packet<'_>) -> Result<Self, ResponseDecodeError> {
        let payload = exact_payload(packet, recovered_opcode::PLMN_SEARCH_STOP_RESPONSE, 5)?;
        Ok(Self {
            search_type: payload[0],
            result: be_u32(payload, 1),
        })
    }
}

/// Recovered UICC control subtypes carried inside HCI request `0x3504` and
/// response `0xb505`.
pub mod uicc_control {
    pub const STATUS: u16 = 0;
    pub const READ_BINARY: u16 = 1;
    pub const READ_RECORD: u16 = 2;
    pub const UPDATE_BINARY: u16 = 3;
    pub const UPDATE_RECORD: u16 = 4;
    pub const AUTHENTICATE: u16 = 5;
    pub const PIN_COMMAND: u16 = 6;
    pub const PIN_STATUS: u16 = 7;
    pub const REMOTE_COMMAND: u16 = 8;
    pub const PIN_REQUIRED: u16 = 9;
    pub const REFRESH: u16 = 10;
    pub const USAT_TERMINAL_PROFILE: u16 = 11;
    pub const USAT_ENVELOPE: u16 = 12;
    pub const USAT_TERMINAL_RESPONSE: u16 = 13;
    pub const POLL_INTERVAL_TIMER: u16 = 14;
}

/// Error while decoding the common UICC response envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UiccResponseDecodeError {
    Response(ResponseDecodeError),
    DataLengthMismatch { declared: usize, actual: usize },
}

impl From<ResponseDecodeError> for UiccResponseDecodeError {
    fn from(value: ResponseDecodeError) -> Self {
        Self::Response(value)
    }
}

/// Common borrowed UICC response envelope.
///
/// The wire order is `result`, `type`, `len`, `data`. B014 DWARF describes the
/// historical callback object in a different host order (`result`, `len`,
/// `type`, `data`); the OEM parser explicitly performs that reshuffle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UiccResponse<'a> {
    pub result: u16,
    pub kind: u16,
    pub data: &'a [u8],
}

impl<'a> UiccResponse<'a> {
    /// Decode the common six-byte UICC response envelope and validate its
    /// embedded data length.
    ///
    /// # Errors
    /// Returns [`UiccResponseDecodeError`] for the wrong HCI opcode, a
    /// truncated envelope, or a declared UICC length that differs from the
    /// bytes actually carried by the HCI packet.
    pub fn parse(packet: Packet<'a>) -> Result<Self, UiccResponseDecodeError> {
        let payload = prefix_payload(packet, recovered_opcode::UICC_RESPONSE, 6)?;
        let declared = usize::from(be_u16(payload, 4));
        let data = &payload[6..];
        if declared != data.len() {
            return Err(UiccResponseDecodeError::DataLengthMismatch {
                declared,
                actual: data.len(),
            });
        }
        Ok(Self {
            result: be_u16(payload, 0),
            kind: be_u16(payload, 2),
            data,
        })
    }
}

/// Error while narrowing the common UICC envelope to a recovered typed
/// response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UiccTypedDecodeError {
    Response(UiccResponseDecodeError),
    FailureResult(u16),
    UnexpectedKind { expected: u16, actual: u16 },
    UnexpectedDataLength { expected: usize, actual: usize },
}

impl From<UiccResponseDecodeError> for UiccTypedDecodeError {
    fn from(value: UiccResponseDecodeError) -> Self {
        Self::Response(value)
    }
}

fn successful_uicc_response(
    packet: Packet<'_>,
    expected_kind: u16,
) -> Result<UiccResponse<'_>, UiccTypedDecodeError> {
    let response = UiccResponse::parse(packet)?;
    if response.result != 0 {
        return Err(UiccTypedDecodeError::FailureResult(response.result));
    }
    if response.kind != expected_kind {
        return Err(UiccTypedDecodeError::UnexpectedKind {
            expected: expected_kind,
            actual: response.kind,
        });
    }
    Ok(response)
}

fn successful_uicc_data(
    packet: Packet<'_>,
    expected_kind: u16,
    expected_len: usize,
) -> Result<&[u8], UiccTypedDecodeError> {
    let response = successful_uicc_response(packet, expected_kind)?;
    if response.data.len() != expected_len {
        return Err(UiccTypedDecodeError::UnexpectedDataLength {
            expected: expected_len,
            actual: response.data.len(),
        });
    }
    Ok(response.data)
}

fn encode_uicc_request(kind: u16, data: &[u8], output: &mut [u8]) -> Result<usize, EncodeError> {
    let data_len = u16::try_from(data.len()).map_err(|_| EncodeError::PayloadTooLong)?;
    let payload_len = data
        .len()
        .checked_add(4)
        .ok_or(EncodeError::PayloadTooLong)?;
    let frame_len = payload_len
        .checked_add(HEADER_LEN)
        .ok_or(EncodeError::PayloadTooLong)?;
    if output.len() < frame_len {
        return Err(EncodeError::NoSpace);
    }
    let payload_len_u16 = u16::try_from(payload_len).map_err(|_| EncodeError::PayloadTooLong)?;
    output[..2].copy_from_slice(&recovered_opcode::UICC_REQUEST.to_be_bytes());
    output[2..4].copy_from_slice(&payload_len_u16.to_be_bytes());
    output[4..6].copy_from_slice(&kind.to_be_bytes());
    output[6..8].copy_from_slice(&data_len.to_be_bytes());
    output[8..frame_len].copy_from_slice(data);
    Ok(frame_len)
}

/// One fixed-width UICC request whose stock bytes are already the proven modem
/// subtype representation.
///
/// This intentionally supports only the two fixed raw-copy families where the
/// live SDK performs no subtype endian conversion. Keeping the original bytes
/// preserves stock padding/dead-slot contents without opening an unrestricted
/// raw UICC escape hatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UiccFixedRequest<'a> {
    kind: u16,
    data: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UiccFixedRequestError {
    UnexpectedLength {
        kind: u16,
        expected: usize,
        actual: usize,
    },
    Hci(EncodeError),
}

impl From<EncodeError> for UiccFixedRequestError {
    fn from(value: EncodeError) -> Self {
        Self::Hci(value)
    }
}

impl<'a> UiccFixedRequest<'a> {
    /// Preserve one exact 36-byte AUTHENTICATE subtype object.
    ///
    /// # Errors
    /// Returns [`UiccFixedRequestError::UnexpectedLength`] unless `data` is
    /// exactly the recovered 36-byte subtype width.
    pub fn authenticate(data: &'a [u8]) -> Result<Self, UiccFixedRequestError> {
        Self::new(uicc_control::AUTHENTICATE, 36, data)
    }

    /// Preserve one exact 20-byte PIN COMMAND subtype object.
    ///
    /// # Errors
    /// Returns [`UiccFixedRequestError::UnexpectedLength`] unless `data` is
    /// exactly the recovered 20-byte subtype width.
    pub fn pin_command(data: &'a [u8]) -> Result<Self, UiccFixedRequestError> {
        Self::new(uicc_control::PIN_COMMAND, 20, data)
    }

    fn new(kind: u16, expected: usize, data: &'a [u8]) -> Result<Self, UiccFixedRequestError> {
        if data.len() != expected {
            return Err(UiccFixedRequestError::UnexpectedLength {
                kind,
                expected,
                actual: data.len(),
            });
        }
        Ok(Self { kind, data })
    }

    #[must_use]
    pub const fn kind(self) -> u16 {
        self.kind
    }

    /// Encode the preserved fixed subtype under the common UICC envelope.
    ///
    /// # Errors
    /// Returns [`UiccFixedRequestError::Hci`] when the destination buffer is
    /// too short.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, UiccFixedRequestError> {
        Ok(encode_uicc_request(self.kind, self.data, output)?)
    }
}

/// UICC READ BINARY request (`type 1`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UiccReadBinaryRequest {
    pub app_type: u8,
    pub fid: u32,
    pub offset: u16,
    pub length: u16,
}

impl UiccReadBinaryRequest {
    /// Encode the nine-byte subtype payload recovered from `lted` and live P4.
    ///
    /// # Errors
    /// Returns [`EncodeError::NoSpace`] when the output buffer is too short.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, EncodeError> {
        let mut data = [0_u8; 9];
        data[0] = self.app_type;
        data[1..5].copy_from_slice(&self.fid.to_be_bytes());
        data[5..7].copy_from_slice(&self.offset.to_be_bytes());
        data[7..9].copy_from_slice(&self.length.to_be_bytes());
        encode_uicc_request(uicc_control::READ_BINARY, &data, output)
    }
}

/// UICC READ RECORD request (`type 2`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UiccReadRecordRequest {
    pub app_type: u8,
    pub fid: u32,
    pub record_index: u8,
}

impl UiccReadRecordRequest {
    /// Encode the six-byte subtype payload recovered from `lted` and live P4.
    ///
    /// # Errors
    /// Returns [`EncodeError::NoSpace`] when the output buffer is too short.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, EncodeError> {
        let mut data = [0_u8; 6];
        data[0] = self.app_type;
        data[1..5].copy_from_slice(&self.fid.to_be_bytes());
        data[5] = self.record_index;
        encode_uicc_request(uicc_control::READ_RECORD, &data, output)
    }
}

/// Error while decoding a variable-length UICC file-read response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UiccFileDecodeError {
    Typed(UiccTypedDecodeError),
    TruncatedData { minimum: usize, actual: usize },
    EmbeddedLengthMismatch { declared: usize, actual: usize },
}

impl From<UiccTypedDecodeError> for UiccFileDecodeError {
    fn from(value: UiccTypedDecodeError) -> Self {
        Self::Typed(value)
    }
}

/// Borrowed successful READ BINARY response (`type 1`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UiccReadBinaryResponse<'a> {
    pub uicc_return: u8,
    pub app_type: u8,
    pub fid: u32,
    pub sw1: u8,
    pub sw2: u8,
    pub data: &'a [u8],
}

impl<'a> UiccReadBinaryResponse<'a> {
    /// Decode the ten-byte fixed READ BINARY prefix and borrow exactly the
    /// number of bytes declared by its BE `len` field.
    ///
    /// # Errors
    /// Returns [`UiccFileDecodeError`] for a failed/wrong outer UICC response,
    /// a truncated subtype prefix, or an embedded data length mismatch.
    pub fn parse(packet: Packet<'a>) -> Result<Self, UiccFileDecodeError> {
        let response = successful_uicc_response(packet, uicc_control::READ_BINARY)?;
        if response.data.len() < 10 {
            return Err(UiccFileDecodeError::TruncatedData {
                minimum: 10,
                actual: response.data.len(),
            });
        }
        let declared = usize::from(be_u16(response.data, 8));
        let data = &response.data[10..];
        if declared != data.len() {
            return Err(UiccFileDecodeError::EmbeddedLengthMismatch {
                declared,
                actual: data.len(),
            });
        }
        Ok(Self {
            uicc_return: response.data[0],
            app_type: response.data[1],
            fid: be_u32(response.data, 2),
            sw1: response.data[6],
            sw2: response.data[7],
            data,
        })
    }
}

/// Borrowed successful READ RECORD response (`type 2`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UiccReadRecordResponse<'a> {
    pub uicc_return: u8,
    pub app_type: u8,
    pub fid: u32,
    pub sw1: u8,
    pub sw2: u8,
    pub record_index: u8,
    /// Total bytes returned in `data`, not `record_count * record_size`.
    pub length: u8,
    pub record_count: u8,
    pub data: &'a [u8],
}

impl<'a> UiccReadRecordResponse<'a> {
    /// Decode the eleven-byte READ RECORD prefix and borrow its payload.
    ///
    /// Live P4 `ind_uicc_from_device` exposes `len * record_num` bytes when
    /// `record_idx == 0` (the all-records form), and exactly `len` bytes for a
    /// specific record. The parser validates the same shape against the bytes
    /// actually carried by the modem response.
    ///
    /// # Errors
    /// Returns [`UiccFileDecodeError`] for a failed/wrong outer UICC response,
    /// a truncated subtype prefix, or an embedded data length mismatch.
    pub fn parse(packet: Packet<'a>) -> Result<Self, UiccFileDecodeError> {
        let response = successful_uicc_response(packet, uicc_control::READ_RECORD)?;
        if response.data.len() < 11 {
            return Err(UiccFileDecodeError::TruncatedData {
                minimum: 11,
                actual: response.data.len(),
            });
        }
        let record_len = usize::from(response.data[9]);
        let record_count = usize::from(response.data[10]);
        let expected = if response.data[8] == 0 {
            record_len.checked_mul(record_count).ok_or(
                UiccFileDecodeError::EmbeddedLengthMismatch {
                    declared: usize::MAX,
                    actual: response.data.len().saturating_sub(11),
                },
            )?
        } else {
            record_len
        };
        let data = &response.data[11..];
        if expected != data.len() {
            return Err(UiccFileDecodeError::EmbeddedLengthMismatch {
                declared: expected,
                actual: data.len(),
            });
        }
        Ok(Self {
            uicc_return: response.data[0],
            app_type: response.data[1],
            fid: be_u32(response.data, 2),
            sw1: response.data[6],
            sw2: response.data[7],
            record_index: response.data[8],
            length: response.data[9],
            record_count: response.data[10],
            data,
        })
    }
}

/// Error while encoding UICC authentication input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UiccAuthenticateEncodeError {
    FieldTooLong {
        field: UiccAuthenticateField,
        maximum: usize,
        actual: usize,
    },
    Hci(EncodeError),
}

impl From<EncodeError> for UiccAuthenticateEncodeError {
    fn from(value: EncodeError) -> Self {
        Self::Hci(value)
    }
}

/// Variable-length fields in the recovered authentication request/response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UiccAuthenticateField {
    Rand,
    Auth,
    Res,
    Ck,
    Ik,
    Auts,
    Sres,
    Kc,
}

/// UICC AUTHENTICATE request (`type 5`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UiccAuthenticateRequest<'a> {
    pub app_type: u8,
    pub rand: &'a [u8],
    pub auth: &'a [u8],
    pub gsm_auth_selection: u8,
}

impl UiccAuthenticateRequest<'_> {
    /// Encode the exact 36-byte subtype object copied raw by B014 and live P4.
    /// `rand` and `auth` occupy fixed 16-byte slots preceded by one-byte
    /// lengths; unused bytes are zero-filled.
    ///
    /// # Errors
    /// Returns [`UiccAuthenticateEncodeError::FieldTooLong`] when RAND or AUTH
    /// exceed the recovered 16-byte capacity, or the wrapped HCI error if the
    /// caller's output buffer is too short.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, UiccAuthenticateEncodeError> {
        if self.rand.len() > 16 {
            return Err(UiccAuthenticateEncodeError::FieldTooLong {
                field: UiccAuthenticateField::Rand,
                maximum: 16,
                actual: self.rand.len(),
            });
        }
        if self.auth.len() > 16 {
            return Err(UiccAuthenticateEncodeError::FieldTooLong {
                field: UiccAuthenticateField::Auth,
                maximum: 16,
                actual: self.auth.len(),
            });
        }

        let mut data = [0_u8; 36];
        data[0] = self.app_type;
        data[1] = u8::try_from(self.rand.len()).map_err(|_| {
            UiccAuthenticateEncodeError::FieldTooLong {
                field: UiccAuthenticateField::Rand,
                maximum: 16,
                actual: self.rand.len(),
            }
        })?;
        data[2..2 + self.rand.len()].copy_from_slice(self.rand);
        data[18] = u8::try_from(self.auth.len()).map_err(|_| {
            UiccAuthenticateEncodeError::FieldTooLong {
                field: UiccAuthenticateField::Auth,
                maximum: 16,
                actual: self.auth.len(),
            }
        })?;
        data[19..19 + self.auth.len()].copy_from_slice(self.auth);
        data[35] = self.gsm_auth_selection;
        Ok(encode_uicc_request(
            uicc_control::AUTHENTICATE,
            &data,
            output,
        )?)
    }
}

/// Error while decoding the fixed 86-byte UICC authentication result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UiccAuthenticateDecodeError {
    Typed(UiccTypedDecodeError),
    FieldTooLong {
        field: UiccAuthenticateField,
        maximum: usize,
        actual: usize,
    },
}

impl From<UiccTypedDecodeError> for UiccAuthenticateDecodeError {
    fn from(value: UiccTypedDecodeError) -> Self {
        Self::Typed(value)
    }
}

fn bounded_auth_field(
    data: &[u8],
    field: UiccAuthenticateField,
    length_offset: usize,
    data_offset: usize,
    maximum: usize,
) -> Result<&[u8], UiccAuthenticateDecodeError> {
    let actual = usize::from(data[length_offset]);
    if actual > maximum {
        return Err(UiccAuthenticateDecodeError::FieldTooLong {
            field,
            maximum,
            actual,
        });
    }
    Ok(&data[data_offset..data_offset + actual])
}

/// Borrowed successful UICC AUTHENTICATE response (`type 5`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UiccAuthenticateResponse<'a> {
    pub uicc_return: u8,
    pub app_type: u8,
    pub auth_return: u8,
    pub res: &'a [u8],
    pub ck: &'a [u8],
    pub ik: &'a [u8],
    pub auts: &'a [u8],
    pub sres: &'a [u8],
    pub kc: &'a [u8],
    pub gsm_auth_result: u8,
}

impl<'a> UiccAuthenticateResponse<'a> {
    /// Decode the raw 86-byte type-5 result while exposing only the declared
    /// bytes from each fixed-capacity authentication slot.
    ///
    /// # Errors
    /// Returns [`UiccAuthenticateDecodeError`] for outer UICC failure/wrong
    /// subtype/size or an embedded length larger than its recovered buffer.
    pub fn parse(packet: Packet<'a>) -> Result<Self, UiccAuthenticateDecodeError> {
        let data = successful_uicc_data(packet, uicc_control::AUTHENTICATE, 86)?;
        Ok(Self {
            uicc_return: data[0],
            app_type: data[1],
            auth_return: data[2],
            res: bounded_auth_field(data, UiccAuthenticateField::Res, 3, 4, 16)?,
            ck: bounded_auth_field(data, UiccAuthenticateField::Ck, 20, 21, 16)?,
            ik: bounded_auth_field(data, UiccAuthenticateField::Ik, 37, 38, 16)?,
            auts: bounded_auth_field(data, UiccAuthenticateField::Auts, 54, 55, 16)?,
            sres: bounded_auth_field(data, UiccAuthenticateField::Sres, 71, 72, 4)?,
            kc: bounded_auth_field(data, UiccAuthenticateField::Kc, 76, 77, 8)?,
            gsm_auth_result: data[85],
        })
    }
}

/// UICC-status request (`type 0`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UiccStatusRequest {
    pub app_type: u8,
}

impl UiccStatusRequest {
    /// Encode the one-byte status request proven by `lted` and live P4.
    ///
    /// # Errors
    /// Returns [`EncodeError::NoSpace`] when `output` is shorter than nine
    /// bytes.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, EncodeError> {
        encode_uicc_request(uicc_control::STATUS, &[self.app_type], output)
    }
}

/// Successful status response (`type 0`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UiccStatusResponse {
    pub uicc_status: u8,
    pub app_type: u8,
}

impl UiccStatusResponse {
    /// Decode a successful two-byte status response.
    ///
    /// # Errors
    /// Returns [`UiccTypedDecodeError`] for outer failure, another subtype or
    /// a status payload whose size differs from the recovered DWARF layout.
    pub fn parse(packet: Packet<'_>) -> Result<Self, UiccTypedDecodeError> {
        let data = successful_uicc_data(packet, uicc_control::STATUS, 2)?;
        Ok(Self {
            uicc_status: data[0],
            app_type: data[1],
        })
    }
}

/// UICC PIN-status request (`type 7`). The OEM always emits a zero-length
/// subtype payload.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UiccPinStatusRequest;

impl UiccPinStatusRequest {
    /// Encode the exact eight-byte HCI frame used by B014 and P4.
    ///
    /// # Errors
    /// Returns [`EncodeError::NoSpace`] when `output` is shorter than eight
    /// bytes.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, EncodeError> {
        encode_uicc_request(uicc_control::PIN_STATUS, &[], output)
    }
}

/// One three-byte PIN status triplet embedded in the type-7 response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PinStatus {
    pub status: u8,
    pub pin_retries: u8,
    pub puk_retries: u8,
}

const fn pin_status(bytes: &[u8], offset: usize) -> PinStatus {
    PinStatus {
        status: bytes[offset],
        pin_retries: bytes[offset + 1],
        puk_retries: bytes[offset + 2],
    }
}

/// Successful PIN-status response (`type 7`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UiccPinStatusResponse {
    pub uicc_return: u8,
    pub global_pin: u8,
    pub application: PinStatus,
    pub universal: PinStatus,
    pub local: PinStatus,
}

impl UiccPinStatusResponse {
    /// Decode the eleven-byte type-7 response described by B014 DWARF and
    /// copied raw by both SDK response parsers.
    ///
    /// # Errors
    /// Returns [`UiccTypedDecodeError`] for outer failure, another subtype or
    /// the wrong payload size.
    pub fn parse(packet: Packet<'_>) -> Result<Self, UiccTypedDecodeError> {
        let data = successful_uicc_data(packet, uicc_control::PIN_STATUS, 11)?;
        Ok(Self {
            uicc_return: data[0],
            global_pin: data[1],
            application: pin_status(data, 2),
            universal: pin_status(data, 5),
            local: pin_status(data, 8),
        })
    }
}

/// One PIN/PUK string in the type-6 command request. The recovered SDK stores
/// one length byte followed by an eight-byte fixed-capacity code buffer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PinData<'a> {
    pub code: &'a [u8],
}

/// Error while encoding a typed PIN command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UiccPinEncodeError {
    PinTooLong { maximum: usize, actual: usize },
    Hci(EncodeError),
}

impl From<EncodeError> for UiccPinEncodeError {
    fn from(value: EncodeError) -> Self {
        Self::Hci(value)
    }
}

fn encode_pin_data(pin: PinData<'_>, output: &mut [u8; 9]) -> Result<(), UiccPinEncodeError> {
    if pin.code.len() > 8 {
        return Err(UiccPinEncodeError::PinTooLong {
            maximum: 8,
            actual: pin.code.len(),
        });
    }
    output[0] = u8::try_from(pin.code.len()).map_err(|_| UiccPinEncodeError::PinTooLong {
        maximum: 8,
        actual: pin.code.len(),
    })?;
    output[1..=pin.code.len()].copy_from_slice(pin.code);
    Ok(())
}

/// UICC PIN command (`type 6`). `pin_type` and `pin_command` are intentionally
/// kept as recovered wire values: the available DWARF names the fields but
/// does not provide a trustworthy enum for their value domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UiccPinCommandRequest<'a> {
    pub pin_type: u8,
    pub pin_command: u8,
    pub old_pin: PinData<'a>,
    pub new_pin: PinData<'a>,
}

impl UiccPinCommandRequest<'_> {
    /// Encode the exact twenty-byte type-6 payload copied by the live SDK.
    ///
    /// # Errors
    /// Returns [`UiccPinEncodeError::PinTooLong`] for a PIN/PUK longer than
    /// eight bytes or [`UiccPinEncodeError::Hci`] if the output buffer is too
    /// short.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, UiccPinEncodeError> {
        let mut data = [0_u8; 20];
        data[0] = self.pin_type;
        data[1] = self.pin_command;
        let mut old = [0_u8; 9];
        let mut new = [0_u8; 9];
        encode_pin_data(self.old_pin, &mut old)?;
        encode_pin_data(self.new_pin, &mut new)?;
        data[2..11].copy_from_slice(&old);
        data[11..20].copy_from_slice(&new);
        Ok(encode_uicc_request(
            uicc_control::PIN_COMMAND,
            &data,
            output,
        )?)
    }
}

/// Successful five-byte response to UICC PIN command (`type 6`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UiccPinCommandResponse {
    pub uicc_return: u8,
    pub pin_type: u8,
    pub pin_command: u8,
    pub pin_retries: u8,
    pub puk_retries: u8,
}

impl UiccPinCommandResponse {
    /// Decode the raw five-byte type-6 response copied by the OEM parser.
    ///
    /// # Errors
    /// Returns [`UiccTypedDecodeError`] for outer failure, another subtype or
    /// the wrong payload size.
    pub fn parse(packet: Packet<'_>) -> Result<Self, UiccTypedDecodeError> {
        let data = successful_uicc_data(packet, uicc_control::PIN_COMMAND, 5)?;
        Ok(Self {
            uicc_return: data[0],
            pin_type: data[1],
            pin_command: data[2],
            pin_retries: data[3],
            puk_retries: data[4],
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

/// Positioning capability bits from the original `POS_LOC_INFO` structure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Positioning {
    pub lpp: bool,
    pub lcs: bool,
}

/// Three rate/connection limits sent in attach TLV `0x71`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PdnConnectionControl {
    pub max_conn: u16,
    pub max_conn_t: u16,
    pub wait_time: u16,
}

/// Field whose original fixed-size C buffer constrains clean attach input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachField {
    Apn,
    Username,
    Password,
    OperatorPco,
}

/// Error returned by the clean attach encoder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachEncodeError {
    /// A variable-length field exceeds the maximum proven OEM storage size.
    FieldTooLong(AttachField),
    /// One of the PDN connection-control limits is outside the range accepted
    /// unchanged by the live SDK.
    PdnControlOutOfRange,
    /// Caller-owned output storage is too small.
    NoSpace,
}

impl From<TlvError> for AttachEncodeError {
    fn from(value: TlvError) -> Self {
        match value {
            TlvError::NoSpace | TlvError::PayloadTooLong => Self::NoSpace,
        }
    }
}

/// Clean representation of the normal GCT attach request (`0x3101`).
///
/// Member names and original offsets come from the symbol-rich B014 `lted`
/// DWARF. Wire order and APN mapping are cross-checked against the live Polish
/// P4 `libltesdk.so`. This type intentionally does not preserve the 352-byte C
/// ABI structure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttachRequest<'a> {
    /// OEM `optional_info` byte. Zero suppresses every optional TLV.
    pub optional_info: u8,
    pub transaction_id: u8,
    pub apn: &'a [u8],
    pub pdn_type: u8,
    pub ip_alloc: u8,
    pub username: &'a [u8],
    pub password: &'a [u8],
    pub auth_flag: u8,
    pub general_pco: Option<u16>,
    pub operator_pco: Option<&'a [u8]>,
    pub req_apn_type: ApnType,
    pub attach_type: u8,
    pub request_type: u8,
    pub emergency_mode: u8,
    pub positioning: Positioning,
    pub nas_sig_low_priority_ind: u8,
    pub pdn_control: PdnConnectionControl,
    pub secure_pco: u8,
}

impl AttachRequest<'_> {
    /// Encode the exact normal-attach HCI frame expected by the live P4 SDK.
    ///
    /// # Errors
    ///
    /// Returns [`AttachEncodeError::FieldTooLong`] when a string/PCO input is
    /// larger than its proven OEM field, [`AttachEncodeError::PdnControlOutOfRange`]
    /// for values the OEM SDK would silently rewrite to defaults, or
    /// [`AttachEncodeError::NoSpace`] if `output` cannot hold the frame.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, AttachEncodeError> {
        if self.apn.len() > 99 {
            return Err(AttachEncodeError::FieldTooLong(AttachField::Apn));
        }
        if self.username.len() > 63 {
            return Err(AttachEncodeError::FieldTooLong(AttachField::Username));
        }
        if self.password.len() > 63 {
            return Err(AttachEncodeError::FieldTooLong(AttachField::Password));
        }
        if self.operator_pco.is_some_and(|pco| pco.len() > 100) {
            return Err(AttachEncodeError::FieldTooLong(AttachField::OperatorPco));
        }
        if self.pdn_control.max_conn > 1023
            || self.pdn_control.max_conn_t > 3000
            || self.pdn_control.wait_time > 1023
        {
            return Err(AttachEncodeError::PdnControlOutOfRange);
        }

        let Some(payload) = output.get_mut(HEADER_LEN..) else {
            return Err(AttachEncodeError::NoSpace);
        };
        let Some(optional_info) = payload.first_mut() else {
            return Err(AttachEncodeError::NoSpace);
        };
        *optional_info = self.optional_info;

        let payload_len = if self.optional_info == 0 {
            1
        } else {
            let Some(tlv_storage) = payload.get_mut(1..) else {
                return Err(AttachEncodeError::NoSpace);
            };
            let mut tlv = TlvWriter::new(tlv_storage);
            tlv.push_raw(0x20, &[self.transaction_id])?;
            tlv.push_raw(0x02, self.username)?;
            tlv.push_raw(0x03, self.password)?;
            tlv.push_raw(0x04, self.apn)?;
            tlv.push_raw(0x1e, &[self.auth_flag])?;
            tlv.push_raw(0x05, &[self.pdn_type])?;
            tlv.push_raw(0x01, &[self.ip_alloc])?;
            if let Some(general_pco) = self.general_pco {
                tlv.push_u16(0x5c, general_pco)?;
            }
            if let Some(operator_pco) = self.operator_pco {
                tlv.push_raw(0x5d, operator_pco)?;
            }
            tlv.push_raw(0x5f, &[self.attach_type])?;
            tlv.push_raw(0x60, &[self.request_type])?;
            tlv.push_raw(0x70, &[self.req_apn_type.p4_wire_value()])?;
            tlv.push_raw(0x62, &[self.emergency_mode])?;
            tlv.push_raw(
                0xf5,
                &[
                    u8::from(self.positioning.lpp),
                    u8::from(self.positioning.lcs),
                ],
            )?;
            tlv.push_raw(0xf6, &[self.nas_sig_low_priority_ind])?;

            let mut pdn_control = [0_u8; 6];
            pdn_control[..2].copy_from_slice(&self.pdn_control.max_conn.to_be_bytes());
            pdn_control[2..4].copy_from_slice(&self.pdn_control.max_conn_t.to_be_bytes());
            pdn_control[4..].copy_from_slice(&self.pdn_control.wait_time.to_be_bytes());
            tlv.push_raw(0x71, &pdn_control)?;
            tlv.push_raw(0xf7, &[self.secure_pco])?;
            1 + tlv.len()
        };

        let payload_len_u16 = u16::try_from(payload_len).map_err(|_| AttachEncodeError::NoSpace)?;
        output[..HEADER_LEN].copy_from_slice(
            &Header {
                command: recovered_opcode::ATTACH_REQUEST,
                payload_len: payload_len_u16,
            }
            .encode(),
        );
        Ok(HEADER_LEN + payload_len)
    }
}

/// Variable-sized field in one of the two extended-attach PDN profiles.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachExtField {
    PrimaryApn,
    PrimaryUsername,
    PrimaryPassword,
    RetryApn,
    RetryUsername,
    RetryPassword,
}

/// Error returned by the recovered extended-attach encoder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachExtEncodeError {
    FieldTooLong(AttachExtField),
    NoSpace,
}

impl From<TlvError> for AttachExtEncodeError {
    fn from(value: TlvError) -> Self {
        match value {
            TlvError::NoSpace | TlvError::PayloadTooLong => Self::NoSpace,
        }
    }
}

/// One PDN profile carried by extended attach (`0x3165`).
///
/// The OEM ABI stores two copies of this logical shape at unrelated offsets in
/// a 484-byte C structure. The clean type keeps only fields proven to be
/// serialized by the live P4 encoder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttachExtProfile<'a> {
    pub ip_alloc: u8,
    pub apn_class: u8,
    pub apn: &'a [u8],
    pub pdn_type: u8,
    pub username: &'a [u8],
    pub password: &'a [u8],
    pub auth_flag: u8,
    pub pco: PcoInfo,
}

/// Clean representation of the live extended-attach request (`0x3165`).
///
/// `optional_info == 0` sends only that single byte. Otherwise the modem gets
/// a complete primary profile followed by a complete retry profile. The OEM
/// `req_apn_type` member is deliberately absent: live P4 copies it into SDK
/// bookkeeping state but never serializes it into this HCI request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttachExtRequest<'a> {
    pub optional_info: u8,
    pub primary: AttachExtProfile<'a>,
    pub retry: AttachExtProfile<'a>,
}

impl AttachExtRequest<'_> {
    fn validate_profile(
        profile: AttachExtProfile<'_>,
        apn: AttachExtField,
        username: AttachExtField,
        password: AttachExtField,
    ) -> Result<(), AttachExtEncodeError> {
        if profile.apn.len() > 99 {
            return Err(AttachExtEncodeError::FieldTooLong(apn));
        }
        if profile.username.len() > 63 {
            return Err(AttachExtEncodeError::FieldTooLong(username));
        }
        if profile.password.len() > 63 {
            return Err(AttachExtEncodeError::FieldTooLong(password));
        }
        Ok(())
    }

    fn encode_profile(
        profile: AttachExtProfile<'_>,
        tlv: &mut TlvWriter<'_>,
    ) -> Result<(), AttachExtEncodeError> {
        tlv.push_raw(0x01, &[profile.ip_alloc])?;
        tlv.push_raw(0x20, &[profile.apn_class])?;
        tlv.push_raw(0x04, profile.apn)?;
        tlv.push_raw(0x05, &[profile.pdn_type])?;
        tlv.push_raw(0x02, profile.username)?;
        tlv.push_raw(0x03, profile.password)?;
        tlv.push_raw(0x1e, &[profile.auth_flag])?;
        tlv.push_raw(0x21, &profile.pco.wire_bytes())?;
        Ok(())
    }

    /// Encode the exact live-P4 extended-attach frame.
    ///
    /// # Errors
    /// Returns [`AttachExtEncodeError::FieldTooLong`] for a serialized string
    /// exceeding its recovered fixed C capacity, or
    /// [`AttachExtEncodeError::NoSpace`] when `output` is too small.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, AttachExtEncodeError> {
        let Some(payload) = output.get_mut(HEADER_LEN..) else {
            return Err(AttachExtEncodeError::NoSpace);
        };
        let Some(optional_info) = payload.first_mut() else {
            return Err(AttachExtEncodeError::NoSpace);
        };
        *optional_info = self.optional_info;

        let payload_len = if self.optional_info == 0 {
            1
        } else {
            Self::validate_profile(
                self.primary,
                AttachExtField::PrimaryApn,
                AttachExtField::PrimaryUsername,
                AttachExtField::PrimaryPassword,
            )?;
            Self::validate_profile(
                self.retry,
                AttachExtField::RetryApn,
                AttachExtField::RetryUsername,
                AttachExtField::RetryPassword,
            )?;
            let mut tlv = TlvWriter::new(&mut payload[1..]);
            Self::encode_profile(self.primary, &mut tlv)?;
            Self::encode_profile(self.retry, &mut tlv)?;
            1 + tlv.len()
        };

        let payload_len_u16 =
            u16::try_from(payload_len).map_err(|_| AttachExtEncodeError::NoSpace)?;
        output[..HEADER_LEN].copy_from_slice(
            &Header {
                command: recovered_opcode::ATTACH_REQUEST_EXT,
                payload_len: payload_len_u16,
            }
            .encode(),
        );
        Ok(HEADER_LEN + payload_len)
    }
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
    const fn wire_bytes(self) -> [u8; 9] {
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

/// Variable-sized field rejected by the clean PDN codecs when it exceeds the
/// maximum size proven by the OEM structures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PdnField {
    Apn,
    Username,
    Password,
    OperatorPco,
    ApnNi,
}

/// Error returned by a typed PDN request encoder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PdnEncodeError {
    FieldTooLong(PdnField),
    /// The normal-connect connection-control triplet is outside the range the
    /// live SDK accepts unchanged.
    PdnControlOutOfRange,
    /// Caller-owned output storage is too small.
    NoSpace,
}

impl From<TlvError> for PdnEncodeError {
    fn from(value: TlvError) -> Self {
        match value {
            TlvError::NoSpace | TlvError::PayloadTooLong => Self::NoSpace,
        }
    }
}

/// Clean representation of normal PDN connectivity request `0x3105`.
///
/// The live P4 wire payload begins with `request_type, optional_info`, then an
/// always-present transaction TLV (`0x20`) and APN TLV (`0x04`). The remaining
/// configuration TLVs are conditional on `optional_info != 0`; requested APN
/// type (`0x70`) is always emitted last.
///
/// The historical SDK generated `transaction_id` through its private
/// `tid_list_add()` state. The clean codec makes that state explicit by taking
/// the already-allocated transaction ID from its caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PdnConnectRequest<'a> {
    pub request_type: u8,
    pub optional_info: u8,
    pub transaction_id: u8,
    pub apn: &'a [u8],
    pub pdn_type: u8,
    pub ip_alloc: u8,
    pub username: &'a [u8],
    pub password: &'a [u8],
    pub auth_flag: u8,
    pub general_pco: Option<u16>,
    pub operator_pco: Option<&'a [u8]>,
    pub req_apn_type: ApnType,
    pub nas_sig_low_priority_ind: u8,
    pub pdn_control: PdnConnectionControl,
    pub secure_pco: u8,
}

impl PdnConnectRequest<'_> {
    /// Encode the normal PDN-connect HCI frame using live-P4 semantics.
    ///
    /// # Errors
    ///
    /// Returns [`PdnEncodeError::FieldTooLong`] for fields exceeding their
    /// proven OEM bounds, [`PdnEncodeError::PdnControlOutOfRange`] instead of
    /// reproducing the SDK's silent normalization, or
    /// [`PdnEncodeError::NoSpace`] if `output` is too small.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, PdnEncodeError> {
        if self.apn.len() > 99 {
            return Err(PdnEncodeError::FieldTooLong(PdnField::Apn));
        }
        if self.optional_info != 0 {
            if self.username.len() > 99 {
                return Err(PdnEncodeError::FieldTooLong(PdnField::Username));
            }
            if self.password.len() > 99 {
                return Err(PdnEncodeError::FieldTooLong(PdnField::Password));
            }
            if self.operator_pco.is_some_and(|pco| pco.len() > 100) {
                return Err(PdnEncodeError::FieldTooLong(PdnField::OperatorPco));
            }
            if self.pdn_control.max_conn > 1023
                || self.pdn_control.max_conn_t > 3000
                || self.pdn_control.wait_time > 1023
            {
                return Err(PdnEncodeError::PdnControlOutOfRange);
            }
        }

        let Some(payload) = output.get_mut(HEADER_LEN..) else {
            return Err(PdnEncodeError::NoSpace);
        };
        let Some(base) = payload.get_mut(..2) else {
            return Err(PdnEncodeError::NoSpace);
        };
        base.copy_from_slice(&[self.request_type, self.optional_info]);

        let Some(tlv_storage) = payload.get_mut(2..) else {
            return Err(PdnEncodeError::NoSpace);
        };
        let mut tlv = TlvWriter::new(tlv_storage);
        tlv.push_raw(0x20, &[self.transaction_id])?;
        tlv.push_raw(0x04, self.apn)?;

        if self.optional_info != 0 {
            tlv.push_raw(0x02, self.username)?;
            tlv.push_raw(0x03, self.password)?;
            tlv.push_raw(0x05, &[self.pdn_type])?;
            tlv.push_raw(0x1e, &[self.auth_flag])?;
            tlv.push_raw(0x01, &[self.ip_alloc])?;
            if let Some(general_pco) = self.general_pco {
                tlv.push_u16(0x5c, general_pco)?;
            }
            if let Some(operator_pco) = self.operator_pco {
                tlv.push_raw(0x5d, operator_pco)?;
            }
            tlv.push_raw(0xf6, &[self.nas_sig_low_priority_ind])?;

            let mut pdn_control = [0_u8; 6];
            pdn_control[..2].copy_from_slice(&self.pdn_control.max_conn.to_be_bytes());
            pdn_control[2..4].copy_from_slice(&self.pdn_control.max_conn_t.to_be_bytes());
            pdn_control[4..].copy_from_slice(&self.pdn_control.wait_time.to_be_bytes());
            tlv.push_raw(0x71, &pdn_control)?;
            tlv.push_raw(0xf7, &[self.secure_pco])?;
        }

        tlv.push_raw(0x70, &[self.req_apn_type.p4_wire_value()])?;
        let payload_len = 2 + tlv.len();
        let payload_len_u16 = u16::try_from(payload_len).map_err(|_| PdnEncodeError::NoSpace)?;
        output[..HEADER_LEN].copy_from_slice(
            &Header {
                command: recovered_opcode::PDN_CONNECT_REQUEST,
                payload_len: payload_len_u16,
            }
            .encode(),
        );
        Ok(HEADER_LEN + payload_len)
    }
}

/// Clean representation of extended PDN connectivity request `0x3167`.
///
/// B014 and the live P4 implementation are instruction-shape equivalent for
/// this encoder. The OEM structure also carried `req_apn_type`, but the live
/// encoder never serializes it; it was SDK bookkeeping and is intentionally
/// absent from this wire type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PdnConnectExtRequest<'a> {
    pub request_type: u8,
    pub optional_info: u8,
    pub apn: &'a [u8],
    pub ip_alloc: u8,
    pub apn_class: u8,
    pub pdn_type: u8,
    pub username: &'a [u8],
    pub password: &'a [u8],
    pub auth_flag: u8,
    pub pco: PcoInfo,
}

impl PdnConnectExtRequest<'_> {
    /// Encode the extended PDN-connect HCI frame.
    ///
    /// # Errors
    ///
    /// Returns [`PdnEncodeError::FieldTooLong`] for fields exceeding the
    /// original safe C string capacity or [`PdnEncodeError::NoSpace`] if the
    /// caller-owned output buffer is too small.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, PdnEncodeError> {
        if self.apn.len() > 99 {
            return Err(PdnEncodeError::FieldTooLong(PdnField::Apn));
        }
        if self.optional_info != 0 {
            if self.username.len() > 63 {
                return Err(PdnEncodeError::FieldTooLong(PdnField::Username));
            }
            if self.password.len() > 63 {
                return Err(PdnEncodeError::FieldTooLong(PdnField::Password));
            }
        }

        let Some(payload) = output.get_mut(HEADER_LEN..) else {
            return Err(PdnEncodeError::NoSpace);
        };
        let Some(base) = payload.get_mut(..2) else {
            return Err(PdnEncodeError::NoSpace);
        };
        base.copy_from_slice(&[self.request_type, self.optional_info]);

        let Some(tlv_storage) = payload.get_mut(2..) else {
            return Err(PdnEncodeError::NoSpace);
        };
        let mut tlv = TlvWriter::new(tlv_storage);
        tlv.push_raw(0x04, self.apn)?;
        if self.optional_info != 0 {
            tlv.push_raw(0x20, &[self.apn_class])?;
            tlv.push_raw(0x02, self.username)?;
            tlv.push_raw(0x03, self.password)?;
            tlv.push_raw(0x05, &[self.pdn_type])?;
            tlv.push_raw(0x1e, &[self.auth_flag])?;
            tlv.push_raw(0x01, &[self.ip_alloc])?;
            tlv.push_raw(0x21, &self.pco.wire_bytes())?;
        }

        let payload_len = 2 + tlv.len();
        let payload_len_u16 = u16::try_from(payload_len).map_err(|_| PdnEncodeError::NoSpace)?;
        output[..HEADER_LEN].copy_from_slice(
            &Header {
                command: recovered_opcode::PDN_CONNECT_REQUEST_EXT,
                payload_len: payload_len_u16,
            }
            .encode(),
        );
        Ok(HEADER_LEN + payload_len)
    }
}

/// Clean representation of PDN disconnect request `0x3107`.
///
/// The SDK generates the transaction ID internally; the clean protocol codec
/// accepts it explicitly. The APN network identifier is encoded as the
/// message-specific `0x57, len, bytes...` field rather than through the common
/// TLV helper, matching the live P4 implementation exactly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PdnDisconnectRequest<'a> {
    pub default_eps_id: u16,
    pub transaction_id: u8,
    pub apn_ni: &'a [u8],
}

impl PdnDisconnectRequest<'_> {
    /// Encode the PDN-disconnect HCI frame.
    ///
    /// # Errors
    ///
    /// Returns [`PdnEncodeError::FieldTooLong`] when `apn_ni` exceeds the
    /// 64-byte recovered `APN_NI` capacity or [`PdnEncodeError::NoSpace`] when
    /// the destination buffer is too small.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, PdnEncodeError> {
        if self.apn_ni.len() > 64 {
            return Err(PdnEncodeError::FieldTooLong(PdnField::ApnNi));
        }

        let payload_len = 7_usize
            .checked_add(self.apn_ni.len())
            .ok_or(PdnEncodeError::NoSpace)?;
        let payload_len_u16 = u16::try_from(payload_len).map_err(|_| PdnEncodeError::NoSpace)?;
        let total = HEADER_LEN
            .checked_add(payload_len)
            .ok_or(PdnEncodeError::NoSpace)?;
        let Some(dst) = output.get_mut(..total) else {
            return Err(PdnEncodeError::NoSpace);
        };

        dst[..HEADER_LEN].copy_from_slice(
            &Header {
                command: recovered_opcode::PDN_DISCONNECT_REQUEST,
                payload_len: payload_len_u16,
            }
            .encode(),
        );
        let payload = &mut dst[HEADER_LEN..];
        payload[..2].copy_from_slice(&self.default_eps_id.to_be_bytes());
        payload[2..5].copy_from_slice(&[0x20, 0x01, self.transaction_id]);
        payload[5] = 0x57;
        payload[6] = u8::try_from(self.apn_ni.len()).map_err(|_| PdnEncodeError::NoSpace)?;
        payload[7..].copy_from_slice(self.apn_ni);
        Ok(total)
    }
}

/// Raw four-byte detach payload used by `LAPI_DetachRequest`.
///
/// The B014 SDK copies exactly four caller bytes, converts them with `H4D()`,
/// and sends them as the entire HCI payload. The semantic subdivision of this
/// word is deliberately not represented until recovered from callers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DetachRequest {
    raw: u32,
}

impl DetachRequest {
    /// Construct from the exact host-side 32-bit value consumed by the OEM SDK.
    #[must_use]
    pub const fn from_raw(raw: u32) -> Self {
        Self { raw }
    }

    /// Return the preserved host-side value.
    #[must_use]
    pub const fn raw(self) -> u32 {
        self.raw
    }

    /// Encode the complete detach HCI frame.
    ///
    /// # Errors
    ///
    /// Returns [`EncodeError::NoSpace`] when `output` is shorter than eight
    /// bytes.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, EncodeError> {
        encode_packet(
            recovered_opcode::DETACH_REQUEST,
            &self.raw.to_be_bytes(),
            output,
        )
    }
}

/// Raw AT command sent to the modem through HCI `0x3307`.
///
/// The OEM SDK accepts a pointer/length pair, copies exactly that byte range,
/// and appends one line-feed byte. The safe Rust API accepts only the borrowed
/// command bytes; no C ABI compatibility is retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AtCommand<'a> {
    command: &'a [u8],
}

impl<'a> AtCommand<'a> {
    /// Construct an AT command from the exact bytes to precede the SDK-added LF.
    #[must_use]
    pub const fn new(command: &'a [u8]) -> Self {
        Self { command }
    }

    /// Encode the complete modem HCI frame.
    ///
    /// # Errors
    ///
    /// Returns [`EncodeError::PayloadTooLong`] when the command plus forced LF
    /// exceeds the 16-bit HCI payload length, or [`EncodeError::NoSpace`] when
    /// `output` is too small.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, EncodeError> {
        let payload_len = self
            .command
            .len()
            .checked_add(1)
            .ok_or(EncodeError::PayloadTooLong)?;
        let payload_len_u16 =
            u16::try_from(payload_len).map_err(|_| EncodeError::PayloadTooLong)?;
        let total = HEADER_LEN
            .checked_add(payload_len)
            .ok_or(EncodeError::PayloadTooLong)?;
        let Some(dst) = output.get_mut(..total) else {
            return Err(EncodeError::NoSpace);
        };

        dst[..HEADER_LEN].copy_from_slice(
            &Header {
                command: public_opcode::LTE_AT_CMD_TO_DEVICE,
                payload_len: payload_len_u16,
            }
            .encode(),
        );
        let command_end = HEADER_LEN + self.command.len();
        dst[HEADER_LEN..command_end].copy_from_slice(self.command);
        dst[command_end] = b'\n';
        Ok(total)
    }
}

/// Extended AT command sent through HCI `0x3323`.
///
/// B014 DWARF describes the historical input as
/// `{channel:u8, cmd:*const u8, length:u32}`. Live P4 copies `channel` first,
/// then exactly `length` command bytes, then appends one line-feed byte.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AtCommandExt<'a> {
    pub channel: u8,
    command: &'a [u8],
}

impl<'a> AtCommandExt<'a> {
    /// Construct an extended AT command for one recovered channel byte.
    #[must_use]
    pub const fn new(channel: u8, command: &'a [u8]) -> Self {
        Self { channel, command }
    }

    /// Encode `[channel, command..., LF]` under HCI `0x3323`.
    ///
    /// # Errors
    /// Returns [`EncodeError::PayloadTooLong`] when channel + command + LF
    /// exceeds the 16-bit HCI payload length, or [`EncodeError::NoSpace`] when
    /// `output` is too small.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, EncodeError> {
        let payload_len = self
            .command
            .len()
            .checked_add(2)
            .ok_or(EncodeError::PayloadTooLong)?;
        let payload_len_u16 =
            u16::try_from(payload_len).map_err(|_| EncodeError::PayloadTooLong)?;
        let total = HEADER_LEN
            .checked_add(payload_len)
            .ok_or(EncodeError::PayloadTooLong)?;
        let Some(dst) = output.get_mut(..total) else {
            return Err(EncodeError::NoSpace);
        };

        dst[..HEADER_LEN].copy_from_slice(
            &Header {
                command: public_opcode::LTE_AT_CMD_TO_DEVICE_EXT,
                payload_len: payload_len_u16,
            }
            .encode(),
        );
        dst[HEADER_LEN] = self.channel;
        let command_start = HEADER_LEN + 1;
        let command_end = command_start + self.command.len();
        dst[command_start..command_end].copy_from_slice(self.command);
        dst[command_end] = b'\n';
        Ok(total)
    }
}

/// Raw AT bytes delivered by modem HCI event `0xb308`.
///
/// The SDK constructs its historical `{cmd pointer, length}` callback object
/// directly from the HCI payload pointer and payload length. No prefix,
/// terminator stripping or character conversion occurs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AtCommandFromDevice<'a> {
    pub command: &'a [u8],
}

impl<'a> AtCommandFromDevice<'a> {
    /// Borrow the complete AT payload exactly as delivered by the modem.
    ///
    /// # Errors
    /// Returns [`ResponseDecodeError`] when the packet opcode is not `0xb308`.
    pub fn parse(packet: Packet<'a>) -> Result<Self, ResponseDecodeError> {
        let command = response_payload(packet, public_opcode::LTE_AT_CMD_FROM_DEVICE)?;
        Ok(Self { command })
    }
}

/// Extended AT bytes delivered by modem HCI event `0xb324`.
///
/// The first payload byte is the channel. The remaining bytes are exposed as
/// the AT command. The OEM subtracts one from the packet length without first
/// checking for an empty payload; the Rust parser rejects that underflow shape.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AtCommandFromDeviceExt<'a> {
    pub channel: u8,
    pub command: &'a [u8],
}

impl<'a> AtCommandFromDeviceExt<'a> {
    /// Decode the one-byte channel prefix and borrow the remaining AT bytes.
    ///
    /// # Errors
    /// Returns [`ResponseDecodeError`] for another opcode or a payload shorter
    /// than the recovered one-byte channel prefix.
    pub fn parse(packet: Packet<'a>) -> Result<Self, ResponseDecodeError> {
        let payload = prefix_payload(packet, public_opcode::LTE_AT_CMD_FROM_DEVICE_EXT, 1)?;
        Ok(Self {
            channel: payload[0],
            command: &payload[1..],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ApnType, AtCommand, AttachEncodeError, AttachExtResponse, AttachField, AttachRequest,
        AttachResponse, AttachResponseDecodeError, AttachResponseKind, AttachResponsePrefix,
        AttachTailField, DetachRequest, DetachResponse, EmptyRequest, NetworkFeatureInfo, PcoInfo,
        PdnConnectExtRequest, PdnConnectExtResponsePrefix, PdnConnectRequest,
        PdnConnectResponsePrefix, PdnConnectionControl, PdnDisconnectRequest,
        PdnDisconnectResponsePrefix, PdnEncodeError, PdnField, PdnInfoContainerKind,
        PdnInfoContainers, PdnInfoField, PdnInfoFieldLengthError, Positioning, QosField,
        ResponseDecodeError, ResultResponse, ResultResponseKind,
    };
    use gct_hci::{Header, Packet, Tlv};

    #[test]
    fn empty_requests_match_oem_four_byte_frames() {
        let cases = [
            (EmptyRequest::Online, [0x31, 0x21, 0x00, 0x00]),
            (EmptyRequest::Offline, [0x31, 0x23, 0x00, 0x00]),
            (EmptyRequest::PsInit, [0x31, 0x2e, 0x00, 0x00]),
            (EmptyRequest::PlmnList, [0x31, 0x0b, 0x00, 0x00]),
        ];

        for (request, expected) in cases {
            let mut output = [0_u8; 4];
            assert_eq!(request.encode(&mut output), Ok(4));
            assert_eq!(output, expected);
        }
    }

    #[test]
    fn p4_apn_mapping_preserves_live_policy_delta() {
        assert_eq!(ApnType::Internet.p4_wire_value(), 3);
        assert_eq!(ApnType::Ims.p4_wire_value(), 1);
        assert_eq!(ApnType::Admin.p4_wire_value(), 2);
        assert_eq!(ApnType::App.p4_wire_value(), 4);
        assert_eq!(ApnType::Emergency.p4_wire_value(), 0);
        assert_eq!(ApnType::Reserved1.p4_wire_value(), 6);
        assert_eq!(ApnType::Reserved2.p4_wire_value(), 0);
        assert_eq!(ApnType::Reserved3.p4_wire_value(), 0);
        assert_eq!(ApnType::NotSet.p4_wire_value(), 0);
    }

    #[test]
    fn minimal_attach_is_header_plus_optional_info_byte() {
        let request = AttachRequest {
            optional_info: 0,
            transaction_id: 9,
            apn: b"ignored",
            pdn_type: 3,
            ip_alloc: 1,
            username: b"ignored",
            password: b"ignored",
            auth_flag: 2,
            general_pco: None,
            operator_pco: None,
            req_apn_type: ApnType::Internet,
            attach_type: 1,
            request_type: 2,
            emergency_mode: 0,
            positioning: Positioning {
                lpp: true,
                lcs: true,
            },
            nas_sig_low_priority_ind: 1,
            pdn_control: PdnConnectionControl {
                max_conn: 20,
                max_conn_t: 300,
                wait_time: 0,
            },
            secure_pco: 1,
        };
        let mut output = [0_u8; 5];
        assert_eq!(request.encode(&mut output), Ok(5));
        assert_eq!(output, [0x31, 0x01, 0x00, 0x01, 0x00]);
    }

    #[test]
    fn attach_tlvs_follow_live_sdk_order() {
        let request = AttachRequest {
            optional_info: 1,
            transaction_id: 7,
            apn: b"internet",
            pdn_type: 3,
            ip_alloc: 1,
            username: b"u",
            password: b"p",
            auth_flag: 2,
            general_pco: Some(0x1234),
            operator_pco: Some(&[0xaa, 0xbb]),
            req_apn_type: ApnType::Internet,
            attach_type: 4,
            request_type: 5,
            emergency_mode: 0,
            positioning: Positioning {
                lpp: true,
                lcs: false,
            },
            nas_sig_low_priority_ind: 1,
            pdn_control: PdnConnectionControl {
                max_conn: 20,
                max_conn_t: 300,
                wait_time: 10,
            },
            secure_pco: 1,
        };
        let mut output = [0_u8; 96];
        assert_eq!(request.encode(&mut output), Ok(71));
        let encoded = &output[..71];
        assert_eq!(&encoded[..4], &[0x31, 0x01, 0x00, 0x43]);
        assert_eq!(encoded[4], 1);
        assert!(encoded[5..].windows(3).any(|x| x == [0x20, 0x01, 0x07]));
        assert!(encoded[5..].windows(3).any(|x| x == [0x70, 0x01, 0x03]));
        assert!(
            encoded[5..]
                .windows(4)
                .any(|x| x == [0x5c, 0x02, 0x12, 0x34])
        );
        assert!(
            encoded[5..]
                .windows(8)
                .any(|x| x == [0x71, 0x06, 0x00, 0x14, 0x01, 0x2c, 0x00, 0x0a])
        );
    }

    #[test]
    fn attach_rejects_old_c_buffer_overflows_and_hidden_normalization() {
        let base = AttachRequest {
            optional_info: 1,
            transaction_id: 0,
            apn: &[b'a'; 100],
            pdn_type: 0,
            ip_alloc: 0,
            username: b"",
            password: b"",
            auth_flag: 0,
            general_pco: None,
            operator_pco: None,
            req_apn_type: ApnType::Internet,
            attach_type: 0,
            request_type: 0,
            emergency_mode: 0,
            positioning: Positioning {
                lpp: false,
                lcs: false,
            },
            nas_sig_low_priority_ind: 0,
            pdn_control: PdnConnectionControl {
                max_conn: 20,
                max_conn_t: 300,
                wait_time: 0,
            },
            secure_pco: 0,
        };
        let mut output = [0_u8; 512];
        assert_eq!(
            base.encode(&mut output),
            Err(AttachEncodeError::FieldTooLong(AttachField::Apn))
        );

        let invalid_control = AttachRequest {
            apn: b"ok",
            pdn_control: PdnConnectionControl {
                max_conn: 1024,
                max_conn_t: 300,
                wait_time: 0,
            },
            ..base
        };
        assert_eq!(
            invalid_control.encode(&mut output),
            Err(AttachEncodeError::PdnControlOutOfRange)
        );
    }

    #[test]
    fn normal_attach_response_splits_ordered_apn_and_typed_tail() {
        let payload = [
            0x00, 0x01, 0x00, 0x02, 0x12, 0x34, 0x56, 0x78, 0x09, 0x0a, 1, 2, 3, 4, 5, 0x20, 0x01,
            0x7f, // transaction
            0x04, 0x02, b'a', b'p', // positional APN helper
            0x58, 0x01, 0x21, // lower-layer reason
            0x5d, 0x02, 0xaa, 0xbb, // operator PCO
        ];
        let response = AttachResponse::parse(packet(0xb102, &payload));
        let Ok(response) = response else {
            return;
        };
        assert_eq!(response.transaction_id, 0x7f);
        assert_eq!(response.register_result1, 1);
        assert_eq!(response.default_eps_id, 0x1234);
        assert_eq!(response.apn_ni.kind, 0x04);
        assert_eq!(response.apn_ni.payload, b"ap");
        let mut trailing = response.trailing_fields();
        assert_eq!(
            trailing.next_field(),
            Ok(Some(AttachTailField::LowerLayerReason(0x21)))
        );
        assert_eq!(
            trailing.next_field(),
            Ok(Some(AttachTailField::OperatorPco(&[0xaa, 0xbb])))
        );
        assert_eq!(trailing.next_field(), Ok(None));
    }

    #[test]
    fn normal_attach_emergency_list_preserves_packed_record_grammar() {
        let payload = [
            0, 1, 0, 2, 0, 3, 0, 4, 5, 6, 7, 8, 9, 10, 11, 0x20, 1, 9, 0x04, 0, 0xf4,
            0x07, // seven packed bytes follow
            0x03, 0x01, b'1', b'1', // len=3: category + two number bytes
            0x02, 0x02, b'9', // len=2: category + one number byte
        ];
        let Ok(response) = AttachResponse::parse(packet(0xb102, &payload)) else {
            return;
        };
        let mut tail = response.trailing_fields();
        let Ok(Some(AttachTailField::EmergencyNumbers(list))) = tail.next_field() else {
            return;
        };
        let mut records = list.records();
        let Ok(Some(first)) = records.next_record() else {
            return;
        };
        assert_eq!(first.category, 1);
        assert_eq!(first.number, b"11");
        let Ok(Some(second)) = records.next_record() else {
            return;
        };
        assert_eq!(second.category, 2);
        assert_eq!(second.number, b"9");
        assert_eq!(records.next_record(), Ok(None));
    }

    #[test]
    fn normal_attach_response_rejects_missing_or_malformed_transaction() {
        let prefix = [
            0x00, 0x01, 0x00, 0x02, 0x12, 0x34, 0x56, 0x78, 0x09, 0x0a, 1, 2, 3, 4, 5,
        ];
        assert_eq!(
            AttachResponse::parse(packet(0xb102, &prefix)),
            Err(AttachResponseDecodeError::MissingTransaction)
        );

        let mut wrong_kind = prefix.to_vec();
        wrong_kind.extend_from_slice(&[0x21, 0x01, 0x07]);
        assert_eq!(
            AttachResponse::parse(packet(0xb102, &wrong_kind)),
            Err(AttachResponseDecodeError::UnexpectedTransactionKind {
                expected: 0x20,
                actual: 0x21,
            })
        );

        let mut wrong_len = prefix.to_vec();
        wrong_len.extend_from_slice(&[0x20, 0x02, 0x07, 0x08]);
        assert_eq!(
            AttachResponse::parse(packet(0xb102, &wrong_len)),
            Err(AttachResponseDecodeError::UnexpectedTransactionLength {
                expected: 1,
                actual: 2,
            })
        );

        let mut missing_apn = prefix.to_vec();
        missing_apn.extend_from_slice(&[0x20, 0x01, 0x07]);
        assert_eq!(
            AttachResponse::parse(packet(0xb102, &missing_apn)),
            Err(AttachResponseDecodeError::MissingApnNetworkIdentifier)
        );

        let mut oversized_apn = prefix.to_vec();
        oversized_apn.extend_from_slice(&[0x20, 0x01, 0x07, 0x04, 65]);
        oversized_apn.extend_from_slice(&[0xaa; 65]);
        assert_eq!(
            AttachResponse::parse(packet(0xb102, &oversized_apn)),
            Err(AttachResponseDecodeError::ApnNetworkIdentifierTooLong {
                maximum: 64,
                actual: 65,
            })
        );
    }

    #[test]
    fn nested_pdn_containers_stop_before_enclosing_suffix() {
        let bytes = [
            0xf0, 0x09, 0x07, 0x04, 10, 20, 30, 40, 0x05, 0x01, 3, 0xf2, 0x06, 0x40, 0x04, 0, 0, 0,
            9, 0x5d, 0x00,
        ];
        let mut containers = PdnInfoContainers::new(&bytes);
        let Ok(Some(first)) = containers.next_container() else {
            return;
        };
        assert_eq!(first.kind, PdnInfoContainerKind::F0);
        let mut fields = first.fields();
        let Ok(Some(first_tlv)) = fields.next_tlv() else {
            return;
        };
        assert_eq!(
            PdnInfoField::parse(first_tlv),
            Ok(PdnInfoField::Ipv4Address([10, 20, 30, 40]))
        );
        let Ok(Some(second_tlv)) = fields.next_tlv() else {
            return;
        };
        assert_eq!(
            PdnInfoField::parse(second_tlv),
            Ok(PdnInfoField::PdnType(3))
        );
        assert!(matches!(fields.next_tlv(), Ok(None)));

        let Ok(Some(second)) = containers.next_container() else {
            return;
        };
        assert_eq!(second.kind, PdnInfoContainerKind::F2);
        let mut qos_fields = second.fields();
        let Ok(Some(qos_tlv)) = qos_fields.next_tlv() else {
            return;
        };
        assert_eq!(
            PdnInfoField::parse(qos_tlv),
            Ok(PdnInfoField::Qos {
                field: QosField::Qci,
                value: 9
            })
        );
        assert!(matches!(containers.next_container(), Ok(None)));
        assert_eq!(containers.remaining(), &[0x5d, 0x00]);
    }

    #[test]
    fn pdn_inner_dispatch_maps_recovered_fields() {
        assert_eq!(
            PdnInfoField::parse(Tlv {
                kind: 0x08,
                payload: &[1, 1, 1, 1]
            }),
            Ok(PdnInfoField::Ipv4DnsPrimary([1, 1, 1, 1]))
        );
        assert_eq!(
            PdnInfoField::parse(Tlv {
                kind: 0x0d,
                payload: &[1; 16]
            }),
            Ok(PdnInfoField::PcscfIpv6 {
                index: 1,
                address: [1; 16]
            })
        );
        assert_eq!(
            PdnInfoField::parse(Tlv {
                kind: 0x22,
                payload: &[2, 3, 4, 5]
            }),
            Ok(PdnInfoField::PcscfIpv4 {
                index: 3,
                address: [2, 3, 4, 5]
            })
        );
        assert_eq!(
            PdnInfoField::parse(Tlv {
                kind: 0x44,
                payload: &[0, 0, 1, 0]
            }),
            Ok(PdnInfoField::Qos {
                field: QosField::GuaranteedBitRateDl,
                value: 256
            })
        );
    }

    #[test]
    fn pdn_inner_dispatch_rejects_bad_known_lengths_and_preserves_unknowns() {
        assert_eq!(
            PdnInfoField::parse(Tlv {
                kind: 0x07,
                payload: &[1, 2, 3]
            }),
            Err(PdnInfoFieldLengthError {
                kind: 0x07,
                expected: 4,
                actual: 3
            })
        );
        let unknown = Tlv {
            kind: 0xee,
            payload: &[1, 2],
        };
        assert_eq!(
            PdnInfoField::parse(unknown),
            Ok(PdnInfoField::Unknown(unknown))
        );
    }

    fn packet(command: u16, payload: &[u8]) -> Packet<'_> {
        Packet {
            header: Header {
                command,
                payload_len: u16::try_from(payload.len()).unwrap_or(u16::MAX),
            },
            payload,
        }
    }

    #[test]
    fn simple_result_responses_are_one_big_endian_word() {
        for (kind, opcode) in [
            (ResultResponseKind::Online, 0xb122),
            (ResultResponseKind::Offline, 0xb124),
            (ResultResponseKind::PsInit, 0xb12f),
        ] {
            assert_eq!(
                ResultResponse::parse(kind, packet(opcode, &[0x11, 0x22, 0x33, 0x44])),
                Ok(ResultResponse {
                    result: 0x1122_3344,
                })
            );
        }
    }

    #[test]
    fn detach_response_is_exact_eight_byte_structure() {
        let payload = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        assert_eq!(
            DetachResponse::parse(packet(0xb104, &payload)),
            Ok(DetachResponse {
                result: 0x1122_3344,
                deregister_cause1: 0x5566,
                deregister_cause2: 0x7788,
            })
        );
    }

    #[test]
    fn attach_prefix_is_shared_by_normal_and_extended_wire_responses() {
        let payload = [
            0x00, 0x01, 0x00, 0x02, 0x12, 0x34, 0x56, 0x78, 0x09, 0x0a, 1, 2, 3, 4, 5, 0x20, 0x01,
            0x7f,
        ];
        let expected = AttachResponsePrefix {
            register_result1: 1,
            register_result2: 2,
            default_eps_id: 0x1234,
            eps_id: 0x5678,
            data_path: 9,
            ip_alloc: 10,
            network_features: NetworkFeatureInfo {
                ims_voice_over_ps: 1,
                emc_bc: 2,
                epc_lcs: 3,
                sc_lcs: 4,
                ext_sr: 5,
            },
            optional_fields: &[0x20, 0x01, 0x7f],
        };
        let normal =
            AttachResponsePrefix::parse(AttachResponseKind::Normal, packet(0xb102, &payload));
        let extended =
            AttachResponsePrefix::parse(AttachResponseKind::Extended, packet(0xb166, &payload));
        assert_eq!(normal, Ok(expected));
        assert_eq!(extended, Ok(expected));
        let mut tlvs = expected.optional_tlvs();
        assert_eq!(
            tlvs.next_tlv(),
            Ok(Some(Tlv {
                kind: 0x20,
                payload: &[0x7f],
            }))
        );
    }

    #[test]
    fn extended_attach_response_splits_ordered_apns_nested_pdn_and_ignored_suffix() {
        let payload = [
            0x00, 0x01, 0x00, 0x02, 0x12, 0x34, 0x56, 0x78, 0x09, 0x0a, 1, 2, 3, 4, 5, 0x20, 0x01,
            0x07, 0x57, 0x03, b'i', b'm', b's', 0x58, 0x03, b'n', b'e', b't', 0xf0, 0x14, 0x04,
            0x03, b'p', b'd', b'n', 0x05, 0x01, 0x02, 0x07, 0x04, 192, 168, 1, 2, 0x40, 0x04, 0, 0,
            0, 9, 0xaa, 0x00,
        ];
        let Ok(response) = AttachExtResponse::parse(packet(0xb166, &payload)) else {
            return;
        };
        assert_eq!(response.register_result1, 1);
        assert_eq!(response.register_result2, 2);
        assert_eq!(response.default_eps_id, 0x1234);
        assert_eq!(response.eps_id, 0x5678);
        assert_eq!(response.data_path, 9);
        assert_eq!(response.ip_alloc, 10);
        assert_eq!(response.apn_class_kind, 0x20);
        assert_eq!(response.apn_class, 7);
        assert_eq!(response.requested_apn_ni.kind, 0x57);
        assert_eq!(response.requested_apn_ni.payload, b"ims");
        assert_eq!(response.received_apn_ni.kind, 0x58);
        assert_eq!(response.received_apn_ni.payload, b"net");
        assert_eq!(response.unparsed_suffix, &[0xaa, 0x00]);

        let mut containers = response.pdn_info_containers();
        let Ok(Some(container)) = containers.next_container() else {
            return;
        };
        assert_eq!(container.kind, PdnInfoContainerKind::F0);
        let mut fields = container.fields();
        let Ok(Some(apn)) = fields.next_tlv() else {
            return;
        };
        let Ok(Some(pdn_type)) = fields.next_tlv() else {
            return;
        };
        let Ok(Some(ipv4)) = fields.next_tlv() else {
            return;
        };
        let Ok(Some(qos)) = fields.next_tlv() else {
            return;
        };
        assert_eq!(
            PdnInfoField::parse(apn),
            Ok(PdnInfoField::AccessPointName(b"pdn"))
        );
        assert_eq!(PdnInfoField::parse(pdn_type), Ok(PdnInfoField::PdnType(2)));
        assert_eq!(
            PdnInfoField::parse(ipv4),
            Ok(PdnInfoField::Ipv4Address([192, 168, 1, 2]))
        );
        assert_eq!(
            PdnInfoField::parse(qos),
            Ok(PdnInfoField::Qos {
                field: QosField::Qci,
                value: 9
            })
        );
        assert_eq!(fields.next_tlv(), Ok(None));
        assert!(matches!(containers.next_container(), Ok(None)));
    }

    #[test]
    fn pdn_response_prefixes_keep_optional_suffix_borrowed() {
        let normal = [
            0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x12, 0x34, 0x05, 0x06, 0x57, 0x01, b'x',
        ];
        assert_eq!(
            PdnConnectResponsePrefix::parse(packet(0xb106, &normal)),
            Ok(PdnConnectResponsePrefix {
                result: 1,
                reject_cause1: 2,
                reject_cause2: 3,
                default_eps_id: 0x1234,
                data_path: 5,
                ip_alloc: 6,
                optional_fields: &[0x57, 0x01, b'x'],
            })
        );

        let extended = [
            0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x12, 0x34, 0x05, 0x06, 0x07, 0x08, 0x57, 0x00,
        ];
        assert_eq!(
            PdnConnectExtResponsePrefix::parse(packet(0xb168, &extended)),
            Ok(PdnConnectExtResponsePrefix {
                result: 1,
                reject_cause1: 2,
                reject_cause2: 3,
                default_eps_id: 0x1234,
                data_path: 5,
                ip_alloc: 6,
                throttle_time: 0x0708,
                optional_fields: &[0x57, 0x00],
            })
        );

        let disconnect = [0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x12, 0x34, 0x5d, 0x00];
        assert_eq!(
            PdnDisconnectResponsePrefix::parse(packet(0xb108, &disconnect)),
            Ok(PdnDisconnectResponsePrefix {
                result: 1,
                reject_cause1: 2,
                reject_cause2: 3,
                default_eps_id: 0x1234,
                optional_fields: &[0x5d, 0x00],
            })
        );
    }

    #[test]
    fn response_parsers_reject_wrong_opcode_and_short_prefix() {
        assert_eq!(
            DetachResponse::parse(packet(0xb106, &[0; 8])),
            Err(ResponseDecodeError::UnexpectedOpcode {
                expected: 0xb104,
                actual: 0xb106,
            })
        );
        assert_eq!(
            PdnConnectResponsePrefix::parse(packet(0xb106, &[0; 9])),
            Err(ResponseDecodeError::TruncatedPrefix {
                minimum: 10,
                actual: 9,
            })
        );
        assert_eq!(
            ResultResponse::parse(ResultResponseKind::Online, packet(0xb122, &[0; 3])),
            Err(ResponseDecodeError::UnexpectedLength {
                expected: 4,
                actual: 3,
            })
        );
    }

    #[test]
    fn minimal_pdn_connect_keeps_required_fields() {
        let request = PdnConnectRequest {
            request_type: 7,
            optional_info: 0,
            transaction_id: 9,
            apn: b"x",
            pdn_type: 3,
            ip_alloc: 1,
            username: &[b'u'; 100],
            password: &[b'p'; 100],
            auth_flag: 2,
            general_pco: None,
            operator_pco: None,
            req_apn_type: ApnType::Internet,
            nas_sig_low_priority_ind: 1,
            pdn_control: PdnConnectionControl {
                max_conn: 65_535,
                max_conn_t: 65_535,
                wait_time: 65_535,
            },
            secure_pco: 1,
        };
        let mut output = [0_u8; 15];
        assert_eq!(request.encode(&mut output), Ok(15));
        assert_eq!(
            output,
            [
                0x31, 0x05, 0x00, 0x0b, 0x07, 0x00, 0x20, 0x01, 0x09, 0x04, 0x01, b'x', 0x70, 0x01,
                0x03,
            ]
        );
    }

    #[test]
    fn normal_pdn_connect_follows_live_tlv_order() {
        let request = PdnConnectRequest {
            request_type: 2,
            optional_info: 1,
            transaction_id: 7,
            apn: b"internet",
            pdn_type: 3,
            ip_alloc: 1,
            username: b"u",
            password: b"p",
            auth_flag: 2,
            general_pco: Some(0x1234),
            operator_pco: Some(&[0xaa, 0xbb]),
            req_apn_type: ApnType::Internet,
            nas_sig_low_priority_ind: 1,
            pdn_control: PdnConnectionControl {
                max_conn: 20,
                max_conn_t: 300,
                wait_time: 10,
            },
            secure_pco: 1,
        };
        let mut output = [0_u8; 64];
        assert_eq!(request.encode(&mut output), Ok(59));
        let encoded = &output[..59];
        assert_eq!(&encoded[..6], &[0x31, 0x05, 0x00, 0x37, 0x02, 0x01]);
        assert!(encoded[6..].windows(3).any(|x| x == [0x20, 0x01, 0x07]));
        assert!(
            encoded[6..]
                .windows(4)
                .any(|x| x == [0x5c, 0x02, 0x12, 0x34])
        );
        assert!(
            encoded[6..]
                .windows(8)
                .any(|x| x == [0x71, 0x06, 0x00, 0x14, 0x01, 0x2c, 0x00, 0x0a])
        );
        assert_eq!(&encoded[encoded.len() - 3..], &[0x70, 0x01, 0x03]);
    }

    #[test]
    fn extended_attach_matches_live_two_profile_wire_order() {
        let primary = super::AttachExtProfile {
            ip_alloc: 1,
            apn_class: 7,
            apn: b"ims",
            pdn_type: 3,
            username: b"u",
            password: b"p",
            auth_flag: 2,
            pco: PcoInfo {
                first_pco: 0x11,
                second_pco: 0x22,
                n_pco: 3,
                first_os_pco: 0x1234,
                second_os_pco: 0x5678,
                third_os_pco: 0x9abc,
            },
        };
        let retry = super::AttachExtProfile {
            ip_alloc: 2,
            apn_class: 8,
            apn: b"r",
            pdn_type: 4,
            username: b"",
            password: b"",
            auth_flag: 1,
            pco: PcoInfo {
                first_pco: 0,
                second_pco: 0,
                n_pco: 0,
                first_os_pco: 0,
                second_os_pco: 0,
                third_os_pco: 0,
            },
        };
        let request = super::AttachExtRequest {
            optional_info: 1,
            primary,
            retry,
        };
        let mut output = [0_u8; 69];
        assert_eq!(request.encode(&mut output), Ok(69));
        assert_eq!(
            output,
            [
                0x31, 0x65, 0x00, 0x41, 0x01, 0x01, 0x01, 0x01, 0x20, 0x01, 0x07, 0x04, 0x03, b'i',
                b'm', b's', 0x05, 0x01, 0x03, 0x02, 0x01, b'u', 0x03, 0x01, b'p', 0x1e, 0x01, 0x02,
                0x21, 0x09, 0x11, 0x22, 0x03, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0x01, 0x01, 0x02,
                0x20, 0x01, 0x08, 0x04, 0x01, b'r', 0x05, 0x01, 0x04, 0x02, 0x00, 0x03, 0x00, 0x1e,
                0x01, 0x01, 0x21, 0x09, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ]
        );
    }

    #[test]
    fn extended_attach_optional_zero_is_exact_five_byte_frame() {
        let oversized_apn = [b'a'; 100];
        let oversized_credential = [b'x'; 64];
        let ignored = super::AttachExtProfile {
            ip_alloc: 0xff,
            apn_class: 0xff,
            apn: &oversized_apn,
            pdn_type: 0xff,
            username: &oversized_credential,
            password: &oversized_credential,
            auth_flag: 0xff,
            pco: PcoInfo {
                first_pco: 0xff,
                second_pco: 0xff,
                n_pco: 0xff,
                first_os_pco: 0xffff,
                second_os_pco: 0xffff,
                third_os_pco: 0xffff,
            },
        };
        let mut output = [0_u8; 5];
        assert_eq!(
            super::AttachExtRequest {
                optional_info: 0,
                primary: ignored,
                retry: ignored,
            }
            .encode(&mut output),
            Ok(5)
        );
        assert_eq!(output, [0x31, 0x65, 0x00, 0x01, 0x00]);
    }

    #[test]
    fn extended_attach_rejects_serialized_profile_overflow() {
        let oversized_apn = [b'a'; 100];
        let pco = PcoInfo {
            first_pco: 0,
            second_pco: 0,
            n_pco: 0,
            first_os_pco: 0,
            second_os_pco: 0,
            third_os_pco: 0,
        };
        let primary = super::AttachExtProfile {
            ip_alloc: 0,
            apn_class: 0,
            apn: &oversized_apn,
            pdn_type: 0,
            username: b"",
            password: b"",
            auth_flag: 0,
            pco,
        };
        let retry = super::AttachExtProfile {
            apn: b"ok",
            ..primary
        };
        let mut output = [0_u8; 512];
        assert_eq!(
            super::AttachExtRequest {
                optional_info: 1,
                primary,
                retry,
            }
            .encode(&mut output),
            Err(super::AttachExtEncodeError::FieldTooLong(
                super::AttachExtField::PrimaryApn
            ))
        );
    }

    #[test]
    fn minimal_extended_pdn_connect_is_base_plus_apn() {
        let request = PdnConnectExtRequest {
            request_type: 1,
            optional_info: 0,
            apn: b"ims",
            ip_alloc: 0xff,
            apn_class: 0xff,
            pdn_type: 0xff,
            username: &[b'u'; 64],
            password: &[b'p'; 64],
            auth_flag: 0xff,
            pco: PcoInfo {
                first_pco: 0xff,
                second_pco: 0xff,
                n_pco: 0xff,
                first_os_pco: 0xffff,
                second_os_pco: 0xffff,
                third_os_pco: 0xffff,
            },
        };
        let mut output = [0_u8; 11];
        assert_eq!(request.encode(&mut output), Ok(11));
        assert_eq!(
            output,
            [
                0x31, 0x67, 0x00, 0x07, 0x01, 0x00, 0x04, 0x03, b'i', b'm', b's'
            ]
        );
    }

    #[test]
    fn extended_pdn_connect_encodes_pco_words_big_endian() {
        let request = PdnConnectExtRequest {
            request_type: 2,
            optional_info: 1,
            apn: b"internet",
            ip_alloc: 1,
            apn_class: 7,
            pdn_type: 3,
            username: b"u",
            password: b"p",
            auth_flag: 2,
            pco: PcoInfo {
                first_pco: 0x11,
                second_pco: 0x22,
                n_pco: 3,
                first_os_pco: 0x1234,
                second_os_pco: 0x5678,
                third_os_pco: 0x9abc,
            },
        };
        let mut output = [0_u8; 48];
        assert_eq!(request.encode(&mut output), Ok(45));
        let encoded = &output[..45];
        assert_eq!(&encoded[..6], &[0x31, 0x67, 0x00, 0x29, 0x02, 0x01]);
        assert!(encoded.windows(11).any(|x| x
            == [
                0x21, 0x09, 0x11, 0x22, 0x03, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc
            ]));
    }

    #[test]
    fn pdn_disconnect_matches_live_message_specific_apn_field() {
        let request = PdnDisconnectRequest {
            default_eps_id: 0x1234,
            transaction_id: 7,
            apn_ni: b"internet",
        };
        let mut output = [0_u8; 19];
        assert_eq!(request.encode(&mut output), Ok(19));
        assert_eq!(
            output,
            [
                0x31, 0x07, 0x00, 0x0f, 0x12, 0x34, 0x20, 0x01, 0x07, 0x57, 0x08, b'i', b'n', b't',
                b'e', b'r', b'n', b'e', b't',
            ]
        );
    }

    #[test]
    fn pdn_codecs_reject_only_serialized_oversize_fields() {
        let mut output = [0_u8; 512];
        let normal = PdnConnectRequest {
            request_type: 0,
            optional_info: 1,
            transaction_id: 0,
            apn: b"ok",
            pdn_type: 0,
            ip_alloc: 0,
            username: &[b'u'; 100],
            password: b"",
            auth_flag: 0,
            general_pco: None,
            operator_pco: None,
            req_apn_type: ApnType::Internet,
            nas_sig_low_priority_ind: 0,
            pdn_control: PdnConnectionControl {
                max_conn: 20,
                max_conn_t: 300,
                wait_time: 0,
            },
            secure_pco: 0,
        };
        assert_eq!(
            normal.encode(&mut output),
            Err(PdnEncodeError::FieldTooLong(PdnField::Username))
        );

        let disconnect = PdnDisconnectRequest {
            default_eps_id: 1,
            transaction_id: 1,
            apn_ni: &[b'a'; 65],
        };
        assert_eq!(
            disconnect.encode(&mut output),
            Err(PdnEncodeError::FieldTooLong(PdnField::ApnNi))
        );
    }

    #[test]
    fn at_command_adds_the_oem_line_feed() {
        let mut output = [0_u8; 7];
        assert_eq!(AtCommand::new(b"AT").encode(&mut output), Ok(7));
        assert_eq!(output, [0x33, 0x07, 0x00, 0x03, b'A', b'T', b'\n']);
    }

    #[test]
    fn detach_is_header_plus_one_big_endian_word() {
        let mut output = [0_u8; 8];
        let request = DetachRequest::from_raw(0x1122_3344);
        assert_eq!(request.encode(&mut output), Ok(8));
        assert_eq!(output, [0x31, 0x03, 0x00, 0x04, 0x11, 0x22, 0x33, 0x44]);
    }

    #[test]
    fn full_normal_pdn_response_follows_recovered_parser_pipeline() {
        let payload = [
            0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x12, 0x34, 0x05, 0x06, 0x20, 0x01, 0x07, 0x57,
            0x08, b'i', b'n', b't', b'e', b'r', b'n', b'e', b't', 0xf0, 0x06, 0x07, 0x04, 10, 20,
            30, 40, 0xf2, 0x06, 0x40, 0x04, 0, 0, 0, 9, 0x5b, 0x02, 0x05, 0xdc, 0x5d, 0x02, 0xaa,
            0xbb, 0xf0, 0x06, 0x08, 0x04, 1, 1, 1, 1, 0xf3, 0x08, 0, 0, 0, 100, 0, 0, 0, 200, 0xee,
            0x01, 0xff,
        ];
        let Ok(response) = super::PdnConnectResponse::parse(packet(0xb106, &payload)) else {
            return;
        };
        assert_eq!(response.result, 1);
        assert_eq!(response.default_eps_id, 0x1234);
        assert_eq!(response.transaction_id, 7);
        assert_eq!(response.apn_ni.kind, 0x57);
        assert_eq!(response.apn_ni.payload, b"internet");

        let mut containers = response.pdn_info_containers();
        let Ok(Some(first)) = containers.next_container() else {
            return;
        };
        assert_eq!(first.kind, PdnInfoContainerKind::F0);
        let mut first_fields = first.fields();
        let Ok(Some(first_tlv)) = first_fields.next_tlv() else {
            return;
        };
        assert_eq!(
            PdnInfoField::parse(first_tlv),
            Ok(PdnInfoField::Ipv4Address([10, 20, 30, 40]))
        );
        let Ok(Some(second)) = containers.next_container() else {
            return;
        };
        assert_eq!(second.kind, PdnInfoContainerKind::F2);
        let mut second_fields = second.fields();
        let Ok(Some(qos_tlv)) = second_fields.next_tlv() else {
            return;
        };
        assert_eq!(
            PdnInfoField::parse(qos_tlv),
            Ok(PdnInfoField::Qos {
                field: QosField::Qci,
                value: 9,
            })
        );
        assert!(matches!(containers.next_container(), Ok(None)));

        let mut tail = response.trailing_fields();
        assert_eq!(
            tail.next_field(),
            Ok(Some(super::PdnConnectTailField::Ipv4LinkMtu(1500)))
        );
        assert_eq!(
            tail.next_field(),
            Ok(Some(super::PdnConnectTailField::OperatorPco(&[0xaa, 0xbb])))
        );
        assert_eq!(
            tail.next_field(),
            Ok(Some(super::PdnConnectTailField::PdnInfo(&[
                0x08, 0x04, 1, 1, 1, 1
            ])))
        );
        assert_eq!(
            tail.next_field(),
            Ok(Some(super::PdnConnectTailField::ApnAmbr {
                uplink: 100,
                downlink: 200,
            }))
        );
        assert_eq!(
            tail.next_field(),
            Ok(Some(super::PdnConnectTailField::Unknown(Tlv {
                kind: 0xee,
                payload: &[0xff],
            })))
        );
        assert_eq!(tail.next_field(), Ok(None));
    }

    #[test]
    fn extended_pdn_response_preserves_unchecked_tags_and_ignored_suffix() {
        let payload = [
            0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x12, 0x34, 0x05, 0x06, 0x07, 0x08, 0x20, 0x01,
            0x07, 0x57, 0x03, b'i', b'm', b's', 0x58, 0x03, b'n', b'e', b't', 0xf0, 0x03, 0x05,
            0x01, 0x03, 0xaa, 0x00,
        ];
        let Ok(response) = super::PdnConnectExtResponse::parse(packet(0xb168, &payload)) else {
            return;
        };
        assert_eq!(response.throttle_time, 0x0708);
        assert_eq!(response.apn_class_kind, 0x20);
        assert_eq!(response.apn_class, 7);
        assert_eq!(response.requested_apn_ni.kind, 0x57);
        assert_eq!(response.requested_apn_ni.payload, b"ims");
        assert_eq!(response.received_apn_ni.kind, 0x58);
        assert_eq!(response.received_apn_ni.payload, b"net");
        assert_eq!(response.unparsed_suffix, &[0xaa, 0x00]);

        let mut containers = response.pdn_info_containers();
        let Ok(Some(container)) = containers.next_container() else {
            return;
        };
        let mut fields = container.fields();
        let Ok(Some(tlv)) = fields.next_tlv() else {
            return;
        };
        assert_eq!(PdnInfoField::parse(tlv), Ok(PdnInfoField::PdnType(3)));
    }

    #[test]
    fn disconnect_response_decodes_descriptor_suffix_and_unknowns() {
        let payload = [
            0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x12, 0x34, 0x20, 0x01, 0x09, 0x57, 0x08, b'i',
            b'n', b't', b'e', b'r', b'n', b'e', b't', 0x5d, 0x02, 0xaa, 0xbb, 0xee, 0x00,
        ];
        let Ok(response) = super::PdnDisconnectResponse::parse(packet(0xb108, &payload)) else {
            return;
        };
        assert_eq!(response.transaction_id, 9);
        let mut fields = response.trailing_fields();
        assert_eq!(
            fields.next_field(),
            Ok(Some(super::PdnDisconnectField::ApnNetworkIdentifier(
                b"internet"
            )))
        );
        assert_eq!(
            fields.next_field(),
            Ok(Some(super::PdnDisconnectField::OperatorPco(&[0xaa, 0xbb])))
        );
        assert_eq!(
            fields.next_field(),
            Ok(Some(super::PdnDisconnectField::Unknown(Tlv {
                kind: 0xee,
                payload: &[],
            })))
        );
        assert_eq!(fields.next_field(), Ok(None));
    }

    #[test]
    fn full_pdn_response_parsers_reject_unsafe_oem_shapes() {
        let wrong_transaction = [
            0, 1, 0, 2, 0, 3, 0x12, 0x34, 5, 6, 0x21, 0x01, 7, 0x57, 0x00,
        ];
        assert_eq!(
            super::PdnConnectResponse::parse(packet(0xb106, &wrong_transaction)),
            Err(super::PdnResponseDecodeError::UnexpectedKind {
                field: super::PdnResponseField::TransactionId,
                expected: 0x20,
                actual: 0x21,
            })
        );

        let bad_apn_class = [
            0, 1, 0, 2, 0, 3, 0x12, 0x34, 5, 6, 7, 8, 0x20, 0x02, 1, 2, 0x57, 0x00, 0x58, 0x00,
        ];
        assert_eq!(
            super::PdnConnectExtResponse::parse(packet(0xb168, &bad_apn_class)),
            Err(super::PdnResponseDecodeError::UnexpectedFieldLength {
                field: super::PdnResponseField::ApnClass,
                expected: 1,
                actual: 2,
            })
        );

        let truncated_nested = [
            0, 1, 0, 2, 0, 3, 0x12, 0x34, 5, 6, 0x20, 0x01, 7, 0x57, 0x00, 0xf0, 0x04, 0x07, 0x04,
        ];
        assert_eq!(
            super::PdnConnectResponse::parse(packet(0xb106, &truncated_nested)),
            Err(super::PdnResponseDecodeError::Tlv(
                gct_hci::TlvDecodeError::TruncatedPayload {
                    declared: 4,
                    actual: 2,
                }
            ))
        );
    }

    #[test]
    fn plmn_search_request_matches_live_p4_packing() {
        let automatic = super::PlmnSearchRequest {
            search_mode: 0,
            mcc: [2, 6, 0],
            mnc: [0, 1, 0x0f],
            emergency_mode: 1,
            roaming_option: 2,
        };
        let mut automatic_wire = [0_u8; 14];
        assert_eq!(automatic.encode(&mut automatic_wire), Ok(14));
        assert_eq!(
            automatic_wire,
            [
                0x31, 0x09, 0x00, 0x0a, 0x00, 0xff, 0xff, 0xff, 0x62, 0x01, 0x01, 0x63, 0x01, 0x02,
            ]
        );

        let manual = super::PlmnSearchRequest {
            search_mode: 1,
            mcc: [2, 6, 0],
            mnc: [0, 1, 0x0f],
            emergency_mode: 3,
            roaming_option: 4,
        };
        let mut manual_wire = [0_u8; 14];
        assert_eq!(manual.encode(&mut manual_wire), Ok(14));
        assert_eq!(
            manual_wire,
            [
                0x31, 0x09, 0x00, 0x0a, 0x01, 0x62, 0xf0, 0x10, 0x62, 0x01, 0x03, 0x63, 0x01, 0x04,
            ]
        );

        let mut short = [0_u8; 13];
        assert_eq!(
            manual.encode(&mut short),
            Err(gct_hci::EncodeError::NoSpace)
        );
    }

    #[test]
    fn plmn_search_ext_matches_live_p4_no_list_and_extended_earfcn_list() {
        let mut wire = [0_u8; 300];
        let no_list = super::PlmnSearchExtRequest {
            selection_mode: 0,
            operation_mode: 0,
            mcc: [0; 3],
            mnc: [0; 3],
            roaming_option: 2,
            list_count: 0,
            list_data: &[],
            power_scan: false,
        };
        assert_eq!(no_list.encode(&mut wire), Ok(8));
        assert_eq!(
            &wire[..8],
            &[0x31, 0x5a, 0x00, 0x04, 0x00, 0x00, 0x63, 0x02]
        );

        let list = [
            2, 2, 0x00, 0x00, 0x0a, 0x28, 0x00, 0x00, 0x09, 0xc4, 3, 2, 3, 5, 4, 1, 0x00, 0x00,
            0x09, 0xc4, 0x00, 0x00, 0x0a, 0x28,
        ];
        let manual = super::PlmnSearchExtRequest {
            selection_mode: 1,
            operation_mode: 1,
            mcc: [2, 6, 0],
            mnc: [0, 1, 0x0f],
            roaming_option: 9,
            list_count: 3,
            list_data: &list,
            power_scan: true,
        };
        assert_eq!(manual.encode(&mut wire), Ok(38));
        assert_eq!(
            &wire[..10],
            &[0x31, 0x5a, 0x00, 0x22, 0x01, 0x01, 0x64, 0x62, 0xf0, 0x10]
        );
        assert_eq!(&wire[10..12], &[0x65, 24]);
        assert_eq!(&wire[12..36], &list);
        assert_eq!(&wire[36..38], &[0x66, 1]);
    }

    #[test]
    fn plmn_search_ext_rejects_malformed_fixed_scan_lists() {
        let mut wire = [0_u8; 300];
        let bad_type = [9, 0];
        let request = super::PlmnSearchExtRequest {
            selection_mode: 0,
            operation_mode: 0,
            mcc: [0; 3],
            mnc: [0; 3],
            roaming_option: 0,
            list_count: 1,
            list_data: &bad_type,
            power_scan: false,
        };
        assert_eq!(
            request.encode(&mut wire),
            Err(super::PlmnSearchExtEncodeError::UnsupportedElementType { index: 0, kind: 9 })
        );

        let truncated = [2, 1, 0, 0, 0];
        let request = super::PlmnSearchExtRequest {
            list_data: &truncated,
            ..request
        };
        assert_eq!(
            request.encode(&mut wire),
            Err(super::PlmnSearchExtEncodeError::TruncatedElement {
                index: 0,
                kind: 2,
                expected: 6,
                remaining: 5,
            })
        );
    }

    #[test]
    fn mobile_id_read_matches_shared_live_p4_request_and_response_grammar() {
        let mut request = [0_u8; 9];
        assert_eq!(
            super::MobileIdReadRequest { mobile_id_type: 3 }.encode(&mut request),
            Ok(9)
        );
        assert_eq!(
            request,
            [0x31, 0x45, 0x00, 0x05, 0x00, 0x01, 0x00, 0x01, 0x03]
        );

        let success = [
            0x00, 0x00, // top-level read_result
            0x00, 0x01, 0x00, 0x08, // Mobile-ID subtype + body length
            0x03, 0x00, 0x05, b'1', b'2', b'3', b'4', b'5',
        ];
        assert_eq!(
            super::MiscReadResponse::parse(packet(
                super::recovered_opcode::MISC_READ_RESPONSE,
                &success,
            )),
            Ok(super::MiscReadResponse::MobileId(
                super::MobileIdReadResponse {
                    read_result: 0,
                    id_type: 3,
                    result: 0,
                    id: b"12345",
                }
            ))
        );

        assert_eq!(
            super::MiscReadResponse::parse(packet(
                super::recovered_opcode::MISC_READ_RESPONSE,
                &[0x00, 0x07],
            )),
            Ok(super::MiscReadResponse::Failure { read_result: 7 })
        );

        let unsupported = [0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0xaa];
        assert_eq!(
            super::MiscReadResponse::parse(packet(
                super::recovered_opcode::MISC_READ_RESPONSE,
                &unsupported,
            )),
            Ok(super::MiscReadResponse::UnsupportedSuccess)
        );
    }

    #[test]
    fn mobile_id_read_rejects_unsafe_or_truncated_shared_chunks() {
        let overlong = [
            0x00, 0x00, 0x00, 0x01, 0x00, 0x14, 1, 0, 17, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
            13, 14, 15, 16, 17,
        ];
        assert_eq!(
            super::MiscReadResponse::parse(packet(
                super::recovered_opcode::MISC_READ_RESPONSE,
                &overlong,
            )),
            Err(super::MiscReadDecodeError::MobileIdChunkTooLong { actual: 17 })
        );

        let truncated = [0x00, 0x00, 0x00, 0x01, 0x00, 0x05, 1, 0, 2, 0xaa];
        assert_eq!(
            super::MiscReadResponse::parse(packet(
                super::recovered_opcode::MISC_READ_RESPONSE,
                &truncated,
            )),
            Err(super::MiscReadDecodeError::TruncatedChunk {
                subtype: 1,
                declared: 5,
                actual: 4,
            })
        );
    }

    #[test]
    fn plmn_search_stop_matches_live_request_and_response_layouts() {
        let mut request = [0_u8; 5];
        assert_eq!(
            super::PlmnSearchStopRequest { search_type: 3 }.encode(&mut request),
            Ok(5)
        );
        assert_eq!(request, [0x31, 0x27, 0x00, 0x01, 0x03]);

        assert_eq!(
            super::PlmnSearchStopResponse::parse(packet(
                super::recovered_opcode::PLMN_SEARCH_STOP_RESPONSE,
                &[3, 0x12, 0x34, 0x56, 0x78],
            )),
            Ok(super::PlmnSearchStopResponse {
                search_type: 3,
                result: 0x1234_5678,
            })
        );
        assert_eq!(
            super::PlmnSearchStopResponse::parse(packet(
                super::recovered_opcode::PLMN_SEARCH_STOP_RESPONSE,
                &[3, 0, 0, 0],
            )),
            Err(super::ResponseDecodeError::UnexpectedLength {
                expected: 5,
                actual: 4,
            })
        );
    }

    #[test]
    fn plmn_list_response_assembles_three_tlvs_per_record() {
        let payload = [
            0x01, 0x12, 0x03, 0x62, 0xf0, 0x10, 0x13, 0x04, 0, 0, 0, 7, 0x14, 0x04, 0, 0, 0, 9,
            0x14, 0x04, 0, 0, 0, 3, 0x12, 0x03, 0x21, 0x43, 0x65, 0x13, 0x04, 0, 0, 0, 2,
        ];
        let Ok(response) = super::PlmnListResponse::parse(packet(0xb10c, &payload)) else {
            return;
        };
        assert_eq!(response.search_complete, 1);
        let mut records = response.records();
        assert_eq!(
            records.next_record(),
            Ok(Some(super::PlmnInfo {
                plmn_id: [0x62, 0xf0, 0x10],
                priority: 7,
                status: 9,
            }))
        );
        assert_eq!(
            records.next_record(),
            Ok(Some(super::PlmnInfo {
                plmn_id: [0x21, 0x43, 0x65],
                priority: 2,
                status: 3,
            }))
        );
        assert_eq!(records.next_record(), Ok(None));
    }

    #[test]
    fn plmn_search_response_splits_fixed_metadata_and_records() {
        let payload = [
            0x00, 0x00, 0x00, 0x00, 0x02, 0x62, 0xf0, 0x10, 0x00, 0x11, 0x00, 0x1e, 0xfe, 0x00,
            0x03, 0x12, 0x34, 0x00, 0x00, 0x18, 0x9c, 0xaa, 0xbb, 0x01, 0x23, 0x45, 0x67, 0x13,
            0x04, 0x00, 0x00, 0x00, 0x07, 0x26, 0x04, 0x01, 0x62, 0xf0, 0x10, 0x12, 0x03, 0x62,
            0xf0, 0x10, 0x13, 0x04, 0x00, 0x00, 0x00, 0x01, 0x14, 0x04, 0x00, 0x00, 0x00, 0x02,
        ];
        let Ok(response) = super::PlmnSearchResponse::parse(packet(0xb10a, &payload)) else {
            return;
        };
        assert_eq!(response.result, 0);
        assert_eq!(response.selection_mode, 2);
        assert_eq!(response.selected_plmn_id, [0x62, 0xf0, 0x10]);
        assert_eq!(response.next_index, 0x11);
        assert_eq!(response.network_interval, 30);
        assert_eq!(response.remaining_count, -2);
        assert_eq!(response.band, 3);
        assert_eq!(response.cell_id, 0x1234);
        assert_eq!(response.frequency, 6300);
        assert_eq!(response.tac, [0xaa, 0xbb]);
        assert_eq!(response.bit28_cell_id, 0x0123_4567);
        assert_eq!(response.plmn_priority, Some(7));
        assert_eq!(
            response.sib1_plmn,
            Some(super::Sib1PlmnList {
                count: 1,
                packed_plmn: &[0x62, 0xf0, 0x10],
            })
        );

        let mut records = response.records();
        assert_eq!(
            records.next_record(),
            Ok(Some(super::PlmnInfo {
                plmn_id: [0x62, 0xf0, 0x10],
                priority: 1,
                status: 2,
            }))
        );
        assert_eq!(records.next_record(), Ok(None));
    }

    #[test]
    fn plmn_parsers_reject_ambiguous_or_unsafe_vendor_shapes() {
        let duplicate = [
            1, 0x12, 0x03, 1, 2, 3, 0x12, 0x03, 4, 5, 6, 0x14, 0x04, 0, 0, 0, 1,
        ];
        let Ok(response) = super::PlmnListResponse::parse(packet(0xb10c, &duplicate)) else {
            return;
        };
        let mut records = response.records();
        assert_eq!(
            records.next_record(),
            Err(super::PlmnInfoDecodeError::DuplicateField(
                super::PlmnInfoField::PlmnId
            ))
        );

        let mut oversized_sib1 = [0_u8; 79];
        oversized_sib1[27] = 0x26;
        oversized_sib1[28] = 50;
        assert_eq!(
            super::PlmnSearchResponse::parse(packet(0xb10a, &oversized_sib1)),
            Err(super::PlmnSearchDecodeError::Sib1PlmnTooLong {
                maximum: 49,
                actual: 50,
            })
        );

        let short_priority = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x13,
            0x03, 1, 2, 3,
        ];
        assert_eq!(
            super::PlmnSearchResponse::parse(packet(0xb10a, &short_priority)),
            Err(super::PlmnSearchDecodeError::UnexpectedMetadataLength {
                kind: 0x13,
                expected: 4,
                actual: 3,
            })
        );
    }

    #[test]
    fn uicc_status_and_pin_status_requests_match_live_wire_frames() {
        let mut status = [0_u8; 9];
        assert_eq!(
            super::UiccStatusRequest { app_type: 2 }.encode(&mut status),
            Ok(9)
        );
        assert_eq!(
            status,
            [0x35, 0x04, 0x00, 0x05, 0x00, 0x00, 0x00, 0x01, 0x02]
        );

        let mut pin_status = [0_u8; 8];
        assert_eq!(super::UiccPinStatusRequest.encode(&mut pin_status), Ok(8));
        assert_eq!(pin_status, [0x35, 0x04, 0x00, 0x04, 0x00, 0x07, 0x00, 0x00]);
    }

    #[test]
    fn uicc_response_envelope_uses_result_type_len_wire_order() {
        let payload = [0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x05, 0x02];
        assert_eq!(
            super::UiccResponse::parse(packet(0xb505, &payload)),
            Ok(super::UiccResponse {
                result: 0,
                kind: super::uicc_control::STATUS,
                data: &[0x05, 0x02],
            })
        );
        assert_eq!(
            super::UiccStatusResponse::parse(packet(0xb505, &payload)),
            Ok(super::UiccStatusResponse {
                uicc_status: 5,
                app_type: 2,
            })
        );

        let mismatched = [0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x05, 0x02];
        assert_eq!(
            super::UiccResponse::parse(packet(0xb505, &mismatched)),
            Err(super::UiccResponseDecodeError::DataLengthMismatch {
                declared: 3,
                actual: 2,
            })
        );
    }

    #[test]
    fn uicc_pin_status_and_command_responses_match_dwarf_layouts() {
        let pin_status = [
            0x00, 0x00, 0x00, 0x07, 0x00, 0x0b, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
        ];
        assert_eq!(
            super::UiccPinStatusResponse::parse(packet(0xb505, &pin_status)),
            Ok(super::UiccPinStatusResponse {
                uicc_return: 1,
                global_pin: 2,
                application: super::PinStatus {
                    status: 3,
                    pin_retries: 4,
                    puk_retries: 5,
                },
                universal: super::PinStatus {
                    status: 6,
                    pin_retries: 7,
                    puk_retries: 8,
                },
                local: super::PinStatus {
                    status: 9,
                    pin_retries: 10,
                    puk_retries: 11,
                },
            })
        );

        let pin_command = [0x00, 0x00, 0x00, 0x06, 0x00, 0x05, 1, 2, 3, 4, 5];
        assert_eq!(
            super::UiccPinCommandResponse::parse(packet(0xb505, &pin_command)),
            Ok(super::UiccPinCommandResponse {
                uicc_return: 1,
                pin_type: 2,
                pin_command: 3,
                pin_retries: 4,
                puk_retries: 5,
            })
        );
    }

    #[test]
    fn uicc_pin_command_request_is_bounded_and_zero_pads_fixed_pin_data() {
        let request = super::UiccPinCommandRequest {
            pin_type: 1,
            pin_command: 2,
            old_pin: super::PinData { code: b"1234" },
            new_pin: super::PinData { code: b"" },
        };
        let mut wire = [0_u8; 28];
        assert_eq!(request.encode(&mut wire), Ok(28));
        assert_eq!(
            wire,
            [
                0x35, 0x04, 0x00, 0x18, 0x00, 0x06, 0x00, 0x14, 0x01, 0x02, 0x04, b'1', b'2', b'3',
                b'4', 0, 0, 0, 0, 0x00, 0, 0, 0, 0, 0, 0, 0, 0,
            ]
        );

        let too_long = super::UiccPinCommandRequest {
            pin_type: 1,
            pin_command: 2,
            old_pin: super::PinData { code: b"123456789" },
            new_pin: super::PinData { code: b"" },
        };
        assert_eq!(
            too_long.encode(&mut wire),
            Err(super::UiccPinEncodeError::PinTooLong {
                maximum: 8,
                actual: 9,
            })
        );
    }

    #[test]
    fn typed_uicc_response_rejects_outer_failure_before_interpreting_data() {
        let payload = [0x00, 0x05, 0x00, 0x07, 0x00, 0x00];
        assert_eq!(
            super::UiccPinStatusResponse::parse(packet(0xb505, &payload)),
            Err(super::UiccTypedDecodeError::FailureResult(5))
        );
    }

    #[test]
    fn uicc_read_requests_match_recovered_big_endian_layouts() {
        let binary = super::UiccReadBinaryRequest {
            app_type: 2,
            fid: 0x6f07,
            offset: 0x0123,
            length: 0x0040,
        };
        let mut binary_wire = [0_u8; 17];
        assert_eq!(binary.encode(&mut binary_wire), Ok(17));
        assert_eq!(
            binary_wire,
            [
                0x35, 0x04, 0x00, 0x0d, 0x00, 0x01, 0x00, 0x09, 0x02, 0x00, 0x00, 0x6f, 0x07, 0x01,
                0x23, 0x00, 0x40,
            ]
        );

        let record = super::UiccReadRecordRequest {
            app_type: 1,
            fid: 0x6f3a,
            record_index: 7,
        };
        let mut record_wire = [0_u8; 14];
        assert_eq!(record.encode(&mut record_wire), Ok(14));
        assert_eq!(
            record_wire,
            [
                0x35, 0x04, 0x00, 0x0a, 0x00, 0x02, 0x00, 0x06, 0x01, 0x00, 0x00, 0x6f, 0x3a, 0x07,
            ]
        );
    }

    #[test]
    fn uicc_read_binary_response_borrows_exact_embedded_length() {
        let payload = [
            0x00, 0x00, 0x00, 0x01, 0x00, 0x0e, 0x00, 0x02, 0x00, 0x00, 0x6f, 0x07, 0x90, 0x00,
            0x00, 0x04, 0xde, 0xad, 0xbe, 0xef,
        ];
        assert_eq!(
            super::UiccReadBinaryResponse::parse(packet(0xb505, &payload)),
            Ok(super::UiccReadBinaryResponse {
                uicc_return: 0,
                app_type: 2,
                fid: 0x6f07,
                sw1: 0x90,
                sw2: 0x00,
                data: &[0xde, 0xad, 0xbe, 0xef],
            })
        );

        let bad_inner_len = [
            0x00, 0x00, 0x00, 0x01, 0x00, 0x0d, 0x00, 0x02, 0x00, 0x00, 0x6f, 0x07, 0x90, 0x00,
            0x00, 0x04, 0xde, 0xad, 0xbe,
        ];
        assert_eq!(
            super::UiccReadBinaryResponse::parse(packet(0xb505, &bad_inner_len)),
            Err(super::UiccFileDecodeError::EmbeddedLengthMismatch {
                declared: 4,
                actual: 3,
            })
        );
    }

    #[test]
    fn uicc_read_record_response_distinguishes_one_record_from_all_records() {
        let one = [
            0x00, 0x00, 0x00, 0x02, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x6f, 0x3a, 0x90, 0x00,
            0x07, 0x05, 0x02, 1, 2, 3, 4, 5,
        ];
        assert_eq!(
            super::UiccReadRecordResponse::parse(packet(0xb505, &one)),
            Ok(super::UiccReadRecordResponse {
                uicc_return: 0,
                app_type: 1,
                fid: 0x6f3a,
                sw1: 0x90,
                sw2: 0x00,
                record_index: 7,
                length: 5,
                record_count: 2,
                data: &[1, 2, 3, 4, 5],
            })
        );

        let all = [
            0x00, 0x00, 0x00, 0x02, 0x00, 0x11, 0x00, 0x01, 0x00, 0x00, 0x6f, 0x3a, 0x90, 0x00,
            0x00, 0x03, 0x02, 1, 2, 3, 4, 5, 6,
        ];
        assert_eq!(
            super::UiccReadRecordResponse::parse(packet(0xb505, &all)),
            Ok(super::UiccReadRecordResponse {
                uicc_return: 0,
                app_type: 1,
                fid: 0x6f3a,
                sw1: 0x90,
                sw2: 0x00,
                record_index: 0,
                length: 3,
                record_count: 2,
                data: &[1, 2, 3, 4, 5, 6],
            })
        );

        let truncated_all = [
            0x00, 0x00, 0x00, 0x02, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x6f, 0x3a, 0x90, 0x00,
            0x00, 0x03, 0x02, 1, 2, 3, 4, 5,
        ];
        assert_eq!(
            super::UiccReadRecordResponse::parse(packet(0xb505, &truncated_all)),
            Err(super::UiccFileDecodeError::EmbeddedLengthMismatch {
                declared: 6,
                actual: 5,
            })
        );
    }

    #[test]
    fn uicc_fixed_requests_preserve_every_stock_subtype_byte() {
        let mut authenticate = [0xa5_u8; 36];
        authenticate[0] = 2;
        authenticate[1] = 1;
        authenticate[2] = 0x11;
        authenticate[18] = 1;
        authenticate[19] = 0x22;
        authenticate[35] = 1;
        let mut wire = [0_u8; 44];
        assert_eq!(
            super::UiccFixedRequest::authenticate(&authenticate)
                .and_then(|request| request.encode(&mut wire)),
            Ok(44)
        );
        assert_eq!(
            &wire[..8],
            &[0x35, 0x04, 0x00, 0x28, 0x00, 0x05, 0x00, 0x24]
        );
        assert_eq!(&wire[8..], &authenticate);

        let pin = [0x5a_u8; 20];
        let mut wire = [0_u8; 28];
        assert_eq!(
            super::UiccFixedRequest::pin_command(&pin)
                .and_then(|request| request.encode(&mut wire)),
            Ok(28)
        );
        assert_eq!(
            &wire[..8],
            &[0x35, 0x04, 0x00, 0x18, 0x00, 0x06, 0x00, 0x14]
        );
        assert_eq!(&wire[8..], &pin);
    }

    #[test]
    fn uicc_authenticate_request_zero_pads_fixed_slots_and_bounds_inputs() {
        let request = super::UiccAuthenticateRequest {
            app_type: 2,
            rand: &[1, 2, 3],
            auth: &[0xaa, 0xbb],
            gsm_auth_selection: 1,
        };
        let mut wire = [0_u8; 44];
        assert_eq!(request.encode(&mut wire), Ok(44));
        assert_eq!(
            &wire[..8],
            &[0x35, 0x04, 0x00, 0x28, 0x00, 0x05, 0x00, 0x24]
        );
        assert_eq!(wire[8], 2);
        assert_eq!(wire[9], 3);
        assert_eq!(&wire[10..13], &[1, 2, 3]);
        assert!(wire[13..26].iter().all(|&byte| byte == 0));
        assert_eq!(wire[26], 2);
        assert_eq!(&wire[27..29], &[0xaa, 0xbb]);
        assert!(wire[29..43].iter().all(|&byte| byte == 0));
        assert_eq!(wire[43], 1);

        let too_long = [0_u8; 17];
        assert_eq!(
            super::UiccAuthenticateRequest {
                app_type: 2,
                rand: &too_long,
                auth: &[],
                gsm_auth_selection: 0,
            }
            .encode(&mut wire),
            Err(super::UiccAuthenticateEncodeError::FieldTooLong {
                field: super::UiccAuthenticateField::Rand,
                maximum: 16,
                actual: 17,
            })
        );
    }

    #[test]
    fn uicc_authenticate_response_exposes_declared_authentication_material() {
        let mut payload = [0_u8; 92];
        payload[..6].copy_from_slice(&[0x00, 0x00, 0x00, 0x05, 0x00, 0x56]);
        let data = &mut payload[6..];
        data[0] = 1;
        data[1] = 2;
        data[2] = 3;
        data[3] = 2;
        data[4..6].copy_from_slice(&[0x10, 0x11]);
        data[20] = 1;
        data[21] = 0x20;
        data[37] = 2;
        data[38..40].copy_from_slice(&[0x30, 0x31]);
        data[54] = 1;
        data[55] = 0x40;
        data[71] = 4;
        data[72..76].copy_from_slice(&[0x50, 0x51, 0x52, 0x53]);
        data[76] = 3;
        data[77..80].copy_from_slice(&[0x60, 0x61, 0x62]);
        data[85] = 7;

        assert_eq!(
            super::UiccAuthenticateResponse::parse(packet(0xb505, &payload)),
            Ok(super::UiccAuthenticateResponse {
                uicc_return: 1,
                app_type: 2,
                auth_return: 3,
                res: &[0x10, 0x11],
                ck: &[0x20],
                ik: &[0x30, 0x31],
                auts: &[0x40],
                sres: &[0x50, 0x51, 0x52, 0x53],
                kc: &[0x60, 0x61, 0x62],
                gsm_auth_result: 7,
            })
        );
    }

    #[test]
    fn uicc_authenticate_response_rejects_embedded_lengths_beyond_slots() {
        let mut payload = [0_u8; 92];
        payload[..6].copy_from_slice(&[0x00, 0x00, 0x00, 0x05, 0x00, 0x56]);
        payload[6 + 71] = 5;
        assert_eq!(
            super::UiccAuthenticateResponse::parse(packet(0xb505, &payload)),
            Err(super::UiccAuthenticateDecodeError::FieldTooLong {
                field: super::UiccAuthenticateField::Sres,
                maximum: 4,
                actual: 5,
            })
        );
    }

    #[test]
    fn detach_required_indication_is_one_big_endian_word() {
        assert_eq!(
            super::DetachRequiredIndication::parse(packet(0xb16a, &[0x01, 0x23, 0x45, 0x67])),
            Ok(super::DetachRequiredIndication {
                detach_type: 0x0123_4567,
            })
        );
        assert_eq!(
            super::DetachRequiredIndication::parse(packet(0xb16a, &[0, 0, 1])),
            Err(super::ResponseDecodeError::UnexpectedLength {
                expected: 4,
                actual: 3,
            })
        );
    }

    #[test]
    fn psm_lcs_lpp_control_requests_match_exact_live_p4_bytes() {
        let mut psm = [0_u8; 14];
        assert_eq!(
            super::PsmControlRequest {
                ctrl_cmd: 0x1234,
                t3324_timer_value_unit: 5,
                t3324_timer_value: 6,
                ext_t3412_timer_value_unit: 7,
                ext_t3412_timer_value: 8,
            }
            .encode(&mut psm),
            Ok(14)
        );
        assert_eq!(
            psm,
            [
                0x31, 0x55, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x06, 0x12, 0x34, 5, 6, 7, 8
            ]
        );

        let mut lcs = [0_u8; 12];
        assert_eq!(
            super::LcsControlRequest { mode: 0x1122_3344 }.encode(&mut lcs),
            Ok(12)
        );
        assert_eq!(lcs, [0x31, 0x55, 0, 8, 0, 9, 0, 4, 0x11, 0x22, 0x33, 0x44]);
        let mut lpp = [0_u8; 12];
        assert_eq!(
            super::LppControlRequest { mode: 0x1122_3344 }.encode(&mut lpp),
            Ok(12)
        );
        assert_eq!(lpp, [0x31, 0x55, 0, 8, 0, 10, 0, 4, 0x11, 0x22, 0x33, 0x44]);
    }

    #[test]
    fn emm_control_requests_and_live_envelopes_match_exact_bytes() {
        let mut timer = [0_u8; 12];
        assert_eq!(
            super::EmmTimerControlRequest {
                timer_id: 0x1234,
                timer_value_unit: 5,
                timer_value: 6,
            }
            .encode(&mut timer),
            Ok(12)
        );
        assert_eq!(
            timer,
            [
                0x31, 0x55, 0x00, 0x08, 0x00, 0x07, 0x00, 0x04, 0x12, 0x34, 5, 6
            ]
        );

        let mut ni = [0_u8; 12];
        assert_eq!(
            super::EmmNiReattachControlRequest {
                control: 0x1122_3344
            }
            .encode(&mut ni),
            Ok(12)
        );
        assert_eq!(
            ni,
            [
                0x31, 0x55, 0x00, 0x08, 0x00, 0x0b, 0x00, 0x04, 0x11, 0x22, 0x33, 0x44
            ]
        );

        let ni_response = [0x00, 0x00, 0x00, 0x0b, 0x00, 0x04, 0x11, 0x22, 0x33, 0x44];
        assert_eq!(
            super::EmmControlResponse::parse(packet(0xb156, &ni_response)),
            Ok(super::EmmControlResponse::NiReattach {
                result: 0x1122_3344
            })
        );
        let timer_response = [0x00, 0x00, 0x00, 0x07, 0x00, 0x04, 0, 0, 0, 1];
        assert_eq!(
            super::EmmControlResponse::parse(packet(0xb156, &timer_response)),
            Ok(super::EmmControlResponse::Unsupported { kind: 7 })
        );
        for kind in [8_u8, 9, 10] {
            let response = [0, 0, 0, kind, 0, 4, 0, 0, 0, 1];
            assert_eq!(
                super::EmmControlResponse::parse(packet(0xb156, &response)),
                Ok(super::EmmControlResponse::Unsupported {
                    kind: u16::from(kind)
                })
            );
        }

        let report = [0x12, 0x34, 0x00, 0x0b, 0x00, 0x04, 0xaa, 0xbb, 0xcc, 0xdd];
        assert_eq!(
            super::EmmControlReport::parse(packet(0xb164, &report)),
            Ok(super::EmmControlReport::Reattach(
                super::EmmReattachControlReport {
                    prefix: 0x1234,
                    value: 0xaabb_ccdd,
                }
            ))
        );

        let bad_value_len = [0x00, 0x00, 0x00, 0x0b, 0x00, 0x03, 1, 2, 3, 4];
        assert_eq!(
            super::EmmControlResponse::parse(packet(0xb156, &bad_value_len)),
            Err(super::EmmControlDecodeError::UnexpectedValueLength {
                expected: 4,
                actual: 3,
            })
        );
        assert_eq!(
            super::EmmControlResponse::parse(packet(0xb156, &ni_response[..9])),
            Err(super::EmmControlDecodeError::Response(
                super::ResponseDecodeError::UnexpectedLength {
                    expected: 10,
                    actual: 9,
                }
            ))
        );
    }

    #[test]
    fn ue_mode_change_has_exact_one_byte_request_and_response() {
        let mut output = [0_u8; 5];
        assert_eq!(
            super::UeModeChangeRequest { mode: 7 }.encode(&mut output),
            Ok(5)
        );
        assert_eq!(output, [0x31, 0x18, 0x00, 0x01, 7]);
        assert_eq!(
            super::UeModeChangeResponse::parse(packet(0xb14f, &[9])),
            Ok(super::UeModeChangeResponse { result: 9 })
        );
        assert_eq!(
            super::UeModeChangeResponse::parse(packet(0xb14f, &[9, 0])),
            Err(super::ResponseDecodeError::UnexpectedLength {
                expected: 1,
                actual: 2,
            })
        );
    }

    #[test]
    fn at_from_device_borrows_the_entire_raw_payload() {
        assert_eq!(
            super::AtCommandFromDevice::parse(packet(0xb308, b"\r\nOK\r\n")),
            Ok(super::AtCommandFromDevice {
                command: b"\r\nOK\r\n",
            })
        );
        assert_eq!(
            super::AtCommandFromDevice::parse(packet(0xb308, &[])),
            Ok(super::AtCommandFromDevice { command: &[] })
        );
    }

    #[test]
    fn extended_at_to_device_matches_live_channel_command_lf_layout() {
        static OVERSIZED: [u8; 65_534] = [0; 65_534];

        let command = super::AtCommandExt::new(7, b"AT");
        let mut output = [0_u8; 8];
        assert_eq!(command.encode(&mut output), Ok(8));
        assert_eq!(output, [0x33, 0x23, 0x00, 0x04, 7, b'A', b'T', b'\n']);

        assert_eq!(
            super::AtCommandExt::new(1, &OVERSIZED).encode(&mut []),
            Err(gct_hci::EncodeError::PayloadTooLong)
        );
    }

    #[test]
    fn extended_at_from_device_splits_channel_from_raw_command() {
        assert_eq!(
            super::AtCommandFromDeviceExt::parse(packet(0xb324, &[7, b'O', b'K'])),
            Ok(super::AtCommandFromDeviceExt {
                channel: 7,
                command: b"OK",
            })
        );
        assert_eq!(
            super::AtCommandFromDeviceExt::parse(packet(0xb324, &[])),
            Err(super::ResponseDecodeError::TruncatedPrefix {
                minimum: 1,
                actual: 0,
            })
        );
    }
}
