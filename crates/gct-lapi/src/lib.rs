#![no_std]

//! Typed encoders for the small GCT LAPI subset needed to bring up the WF830.
//!
//! This is a clean implementation from recovered wire behavior. It does not
//! expose the historical OEM C ABI and intentionally omits commands until
//! their payload format is proven.

use gct_hci::{
    EncodeError, HEADER_LEN, Header, TlvError, TlvWriter, encode_packet, public_opcode,
    recovered_opcode,
};

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
        ApnType, AtCommand, AttachEncodeError, AttachField, AttachRequest, DetachRequest,
        EmptyRequest, PdnConnectionControl, Positioning,
    };

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
