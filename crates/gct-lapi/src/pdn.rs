//! PDN connectivity request/response codecs and shared PDN response grammar.

use gct_hci::{
    HEADER_LEN, Header, Packet, Tlv, TlvCursor, TlvDecodeError, TlvError, TlvWriter,
    recovered_opcode,
};

use crate::common::{
    ApnType, OrderedPdnTlv, PcoInfo, PdnConnectionControl, PdnInfoContainers,
    PdnResponseDecodeError, PdnResponseField, ResponseDecodeError, be_u16, be_u32,
    bounded_pdn_field, exact_pdn_field, prefix_payload, required_pdn_tlv, split_initial_pdn_info,
};

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
