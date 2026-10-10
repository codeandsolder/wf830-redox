//! AT command request and modem-to-host indication codecs.

use gct_hci::{EncodeError, HEADER_LEN, Header, Packet, public_opcode};

use crate::common::{ResponseDecodeError, prefix_payload, response_payload};

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
