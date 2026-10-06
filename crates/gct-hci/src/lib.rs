#![no_std]

//! Wire primitives for the GCT `GDM724x` host-control interface.
//!
//! This crate deliberately contains only facts backed by either the upstream
//! Linux `gdm724x` staging driver or direct reverse engineering of the WF830
//! `libltesdk.so`. It is not an ABI-compatibility layer for the OEM SDK.

/// Size of the common GCT HCI header.
pub const HEADER_LEN: usize = 4;

/// Error returned while decoding a GCT HCI packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeError {
    /// Fewer than four bytes were supplied.
    TruncatedHeader,
    /// The declared payload length does not match the supplied buffer.
    LengthMismatch {
        /// Payload length declared in the header.
        declared: usize,
        /// Payload bytes actually present.
        actual: usize,
    },
}

/// Error returned while encoding a GCT HCI packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncodeError {
    /// The payload cannot be represented by the 16-bit HCI length field.
    PayloadTooLong,
    /// The caller-provided output buffer has insufficient space.
    NoSpace,
}

/// The common four-byte GCT HCI header.
///
/// The Linux staging driver defines both fields as device-endian 16-bit
/// integers. GDM7243 devices use big-endian HCI framing, so the serialized
/// representation is network byte order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    /// HCI command or event identifier.
    pub command: u16,
    /// Number of payload bytes following the header.
    pub payload_len: u16,
}

impl Header {
    /// Decode a four-byte big-endian HCI header.
    #[must_use]
    pub const fn decode(bytes: [u8; HEADER_LEN]) -> Self {
        Self {
            command: u16::from_be_bytes([bytes[0], bytes[1]]),
            payload_len: u16::from_be_bytes([bytes[2], bytes[3]]),
        }
    }

    /// Encode this header in the modem wire byte order.
    #[must_use]
    pub const fn encode(self) -> [u8; HEADER_LEN] {
        let command = self.command.to_be_bytes();
        let len = self.payload_len.to_be_bytes();
        [command[0], command[1], len[0], len[1]]
    }
}

/// A borrowed, length-checked HCI packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Packet<'a> {
    /// Decoded packet header.
    pub header: Header,
    /// Packet payload, excluding the four-byte header.
    pub payload: &'a [u8],
}

impl<'a> Packet<'a> {
    /// Parse one exact HCI packet from `bytes`.
    ///
    /// Extra trailing bytes are rejected. Stream framing belongs in the
    /// transport layer and must not be silently accepted here.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::TruncatedHeader`] for buffers shorter than the
    /// common header, or [`DecodeError::LengthMismatch`] when the declared
    /// payload length does not exactly match the supplied bytes.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, DecodeError> {
        let Some(header_bytes) = bytes.get(..HEADER_LEN) else {
            return Err(DecodeError::TruncatedHeader);
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
            return Err(DecodeError::LengthMismatch {
                declared,
                actual: payload.len(),
            });
        }

        Ok(Self { header, payload })
    }
}

/// Encode one complete HCI packet into caller-owned storage.
///
/// # Errors
///
/// Returns [`EncodeError::PayloadTooLong`] when `payload` does not fit the
/// 16-bit length field and [`EncodeError::NoSpace`] when `output` is too small.
pub fn encode_packet(
    command: u16,
    payload: &[u8],
    output: &mut [u8],
) -> Result<usize, EncodeError> {
    let payload_len = u16::try_from(payload.len()).map_err(|_| EncodeError::PayloadTooLong)?;
    let total = HEADER_LEN
        .checked_add(payload.len())
        .ok_or(EncodeError::PayloadTooLong)?;
    let Some(dst) = output.get_mut(..total) else {
        return Err(EncodeError::NoSpace);
    };

    dst[..HEADER_LEN].copy_from_slice(
        &Header {
            command,
            payload_len,
        }
        .encode(),
    );
    dst[HEADER_LEN..].copy_from_slice(payload);
    Ok(total)
}

/// Error returned while appending a recovered GCT TLV.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlvError {
    /// The payload cannot be represented by the one-byte TLV length field.
    PayloadTooLong,
    /// The caller-provided output buffer has insufficient space.
    NoSpace,
}

/// Allocation-free writer for the TLV format used by WF830 LAPI requests.
///
/// Reverse engineering of the shared `libltesdk.so` encoder at B014 address
/// `0x3f2f4` shows a two-byte header (`type`, `len`) followed by the payload.
/// The OEM helper has raw, 16-bit device-endian, and 32-bit device-endian
/// paths; the GDM7243 target uses big-endian device order.
pub struct TlvWriter<'a> {
    buffer: &'a mut [u8],
    len: usize,
}

impl<'a> TlvWriter<'a> {
    /// Create a TLV writer over caller-owned storage.
    pub const fn new(buffer: &'a mut [u8]) -> Self {
        Self { buffer, len: 0 }
    }

    /// Number of bytes written so far.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether no TLVs have been written yet.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Return the encoded prefix of the backing buffer.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buffer[..self.len]
    }

    /// Append one raw TLV.
    ///
    /// # Errors
    ///
    /// Returns [`TlvError::PayloadTooLong`] for payloads longer than 255 bytes
    /// and [`TlvError::NoSpace`] when the output buffer is too small.
    pub fn push_raw(&mut self, tlv_type: u8, payload: &[u8]) -> Result<(), TlvError> {
        let payload_len = u8::try_from(payload.len()).map_err(|_| TlvError::PayloadTooLong)?;
        let total = payload
            .len()
            .checked_add(2)
            .ok_or(TlvError::PayloadTooLong)?;
        let end = self.len.checked_add(total).ok_or(TlvError::NoSpace)?;
        let Some(dst) = self.buffer.get_mut(self.len..end) else {
            return Err(TlvError::NoSpace);
        };

        dst[0] = tlv_type;
        dst[1] = payload_len;
        dst[2..].copy_from_slice(payload);
        self.len = end;
        Ok(())
    }

    /// Append a 16-bit integer in GDM7243 device byte order.
    ///
    /// # Errors
    ///
    /// Returns [`TlvError::NoSpace`] when the output buffer is too small.
    pub fn push_u16(&mut self, tlv_type: u8, value: u16) -> Result<(), TlvError> {
        self.push_raw(tlv_type, &value.to_be_bytes())
    }

    /// Append a 32-bit integer in GDM7243 device byte order.
    ///
    /// # Errors
    ///
    /// Returns [`TlvError::NoSpace`] when the output buffer is too small.
    pub fn push_u32(&mut self, tlv_type: u8, value: u32) -> Result<(), TlvError> {
        self.push_raw(tlv_type, &value.to_be_bytes())
    }
}

/// HCI opcodes published in the Linux `gdm724x` staging driver.
pub mod public_opcode {
    pub const LTE_GET_INFORMATION: u16 = 0x3002;
    pub const LTE_GET_INFORMATION_RESULT: u16 = 0xb003;
    pub const LTE_LINK_ON_OFF_INDICATION: u16 = 0xb133;
    pub const LTE_PDN_TABLE_IND: u16 = 0xb143;
    pub const LTE_TX_SDU: u16 = 0x3200;
    pub const LTE_RX_SDU: u16 = 0xb201;
    pub const LTE_TX_MULTI_SDU: u16 = 0x3202;
    pub const LTE_RX_MULTI_SDU: u16 = 0xb203;
    pub const LTE_DL_SDU_FLOW_CONTROL: u16 = 0x3305;
    pub const LTE_UL_SDU_FLOW_CONTROL: u16 = 0xb306;
    pub const LTE_AT_CMD_TO_DEVICE: u16 = 0x3307;
    pub const LTE_AT_CMD_FROM_DEVICE: u16 = 0xb308;
    pub const LTE_SDIO_DM_SEND_PKT: u16 = 0x3312;
    pub const LTE_SDIO_DM_RECV_PKT: u16 = 0xb313;
    pub const LTE_NV_RESTORE_REQUEST: u16 = 0xb30c;
    pub const LTE_NV_RESTORE_RESPONSE: u16 = 0x330d;
    pub const LTE_NV_SAVE_REQUEST: u16 = 0xb30e;
    pub const LTE_NV_SAVE_RESPONSE: u16 = 0x330f;
    pub const LTE_AT_CMD_TO_DEVICE_EXT: u16 = 0x3323;
    pub const LTE_AT_CMD_FROM_DEVICE_EXT: u16 = 0xb324;
}

/// Modem-wire request opcodes recovered directly from the WF830/B014 SDK.
///
/// These values come from the constant passed through `H2D()` by the named
/// `LAPI_*` function in `libltesdk.so`. Keeping this list intentionally small
/// prevents old speculative catalogs from becoming executable ABI.
pub mod recovered_opcode {
    pub const ATTACH_REQUEST: u16 = 0x3101;
    pub const ATTACH_REQUEST_EXT: u16 = 0x3165;
    pub const DETACH_REQUEST: u16 = 0x3103;
    pub const PDN_CONNECT_REQUEST: u16 = 0x3105;
    pub const PDN_CONNECT_REQUEST_EXT: u16 = 0x3167;
    pub const PDN_DISCONNECT_REQUEST: u16 = 0x3107;
    pub const PLMN_SEARCH_REQUEST: u16 = 0x3109;
    pub const PLMN_LIST_REQUEST: u16 = 0x310b;
    pub const ONLINE_REQUEST: u16 = 0x3121;
    pub const OFFLINE_REQUEST: u16 = 0x3123;
    pub const PS_INIT_REQUEST: u16 = 0x312e;
    pub const UICC_REQUEST: u16 = 0x3504;

    // Response values below are proven by the `decode_hci_packet` dispatch
    // table at B014 virtual address 0x89f6c.
    pub const ATTACH_RESPONSE: u16 = 0xb102;
    pub const ATTACH_RESPONSE_EXT: u16 = 0xb166;
    pub const DETACH_RESPONSE: u16 = 0xb104;
    pub const PDN_CONNECT_RESPONSE: u16 = 0xb106;
    pub const PDN_CONNECT_RESPONSE_EXT: u16 = 0xb168;
    pub const PDN_DISCONNECT_RESPONSE: u16 = 0xb108;
    pub const PLMN_SEARCH_RESPONSE: u16 = 0xb10a;
    pub const PLMN_LIST_RESPONSE: u16 = 0xb10c;
    pub const ONLINE_RESPONSE: u16 = 0xb122;
    pub const OFFLINE_RESPONSE: u16 = 0xb124;
    pub const PS_INIT_RESPONSE: u16 = 0xb12f;
    pub const UICC_RESPONSE: u16 = 0xb505;
}

#[cfg(test)]
mod tests {
    use super::{
        DecodeError, EncodeError, Header, Packet, TlvError, TlvWriter, encode_packet, public_opcode,
    };

    #[test]
    fn at_command_header_matches_linux_driver_wire_order() {
        let header = Header {
            command: public_opcode::LTE_AT_CMD_TO_DEVICE,
            payload_len: 3,
        };
        assert_eq!(header.encode(), [0x33, 0x07, 0x00, 0x03]);
        assert_eq!(Header::decode(header.encode()), header);
    }

    #[test]
    fn packet_parser_checks_declared_length() {
        let bytes = [0x33, 0x07, 0x00, 0x03, b'A', b'T', b'\r'];
        let packet = Packet::parse(&bytes);
        assert_eq!(
            packet,
            Ok(Packet {
                header: Header {
                    command: public_opcode::LTE_AT_CMD_TO_DEVICE,
                    payload_len: 3,
                },
                payload: b"AT\r",
            })
        );
    }

    #[test]
    fn packet_parser_rejects_trailing_or_missing_payload() {
        assert_eq!(
            Packet::parse(&[0x33, 0x07, 0x00, 0x02, 0x41]),
            Err(DecodeError::LengthMismatch {
                declared: 2,
                actual: 1,
            })
        );
    }

    #[test]
    fn packet_encoder_matches_parser() {
        let mut output = [0_u8; 7];
        assert_eq!(
            encode_packet(public_opcode::LTE_AT_CMD_TO_DEVICE, b"AT\r", &mut output),
            Ok(7)
        );
        assert_eq!(output, [0x33, 0x07, 0x00, 0x03, b'A', b'T', b'\r']);
        assert_eq!(
            Packet::parse(&output).map(|packet| packet.payload),
            Ok(&b"AT\r"[..])
        );

        let mut short = [0_u8; 6];
        assert_eq!(
            encode_packet(public_opcode::LTE_AT_CMD_TO_DEVICE, b"AT\r", &mut short),
            Err(EncodeError::NoSpace)
        );
    }

    #[test]
    fn recovered_tlv_encoder_matches_observed_layout() {
        let mut storage = [0_u8; 16];
        let mut writer = TlvWriter::new(&mut storage);
        assert_eq!(writer.push_raw(0x20, &[0x7f]), Ok(()));
        assert_eq!(writer.push_u16(0x5c, 0x1234), Ok(()));
        assert_eq!(writer.push_u32(0xf5, 0x1122_3344), Ok(()));
        assert_eq!(
            writer.as_bytes(),
            [
                0x20, 0x01, 0x7f, 0x5c, 0x02, 0x12, 0x34, 0xf5, 0x04, 0x11, 0x22, 0x33, 0x44
            ]
        );
    }

    #[test]
    fn tlv_writer_refuses_overflow() {
        let mut storage = [0_u8; 2];
        let mut writer = TlvWriter::new(&mut storage);
        assert_eq!(writer.push_raw(1, &[1]), Err(TlvError::NoSpace));
    }
}
