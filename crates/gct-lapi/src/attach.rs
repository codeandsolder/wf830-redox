//! Attach/detach request and response codecs, including extended attach.

use gct_hci::{
    EncodeError, HEADER_LEN, Header, Packet, Tlv, TlvCursor, TlvDecodeError, TlvError, TlvWriter,
    encode_packet, recovered_opcode,
};

use crate::common::{
    ApnType, OrderedPdnTlv, PcoInfo, PdnConnectionControl, PdnInfoContainers,
    PdnResponseDecodeError, PdnResponseField, ResponseDecodeError, be_u16, be_u32,
    bounded_pdn_field, exact_payload, exact_pdn_field, prefix_payload, required_pdn_tlv,
    split_initial_pdn_info,
};

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

/// Positioning capability bits from the original `POS_LOC_INFO` structure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Positioning {
    pub lpp: bool,
    pub lcs: bool,
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
