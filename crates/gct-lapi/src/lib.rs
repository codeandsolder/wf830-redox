#![no_std]

//! Typed codecs for the small GCT LAPI subset needed to bring up the WF830.
//!
//! This is a clean implementation from recovered wire behavior. It does not
//! expose the historical OEM C ABI and intentionally omits commands until
//! their payload format is proven.

use gct_hci::{
    EncodeError, HEADER_LEN, Header, Packet, TlvCursor, TlvError, TlvWriter, encode_packet,
    public_opcode, recovered_opcode,
};

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

#[cfg(test)]
mod tests {
    use super::{
        ApnType, AtCommand, AttachEncodeError, AttachField, AttachRequest, AttachResponseKind,
        AttachResponsePrefix, DetachRequest, DetachResponse, EmptyRequest, NetworkFeatureInfo,
        PcoInfo, PdnConnectExtRequest, PdnConnectExtResponsePrefix, PdnConnectRequest,
        PdnConnectResponsePrefix, PdnConnectionControl, PdnDisconnectRequest,
        PdnDisconnectResponsePrefix, PdnEncodeError, PdnField, Positioning, ResponseDecodeError,
        ResultResponse, ResultResponseKind,
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
}
