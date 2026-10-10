//! EMM/NAS control codecs, including power-saving and UE-mode controls.

use gct_hci::{EncodeError, HEADER_LEN, Header, Packet, encode_packet, recovered_opcode};

use crate::common::{ResponseDecodeError, be_u16, be_u32, exact_payload, response_payload};

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

/// Live-only EMM timer-start request carried by shared command `0x3155`
/// discriminator 13.
///
/// The live P4 stock wrapper copies exactly three caller bytes and the live SDK
/// preserves those bytes on the modem wire. No independently named field
/// layout is available, so the fixed-size parameters intentionally remain
/// opaque rather than assigning speculative semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EmmTimerStartRequest {
    pub params: [u8; 3],
}

impl EmmTimerStartRequest {
    /// Encode exact live-P4 bytes `00 0d 00 03 <params[0..3]>`.
    ///
    /// # Errors
    /// Returns [`EncodeError::NoSpace`] when `output` is shorter than 11 bytes.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, EncodeError> {
        encode_packet(
            recovered_opcode::EMM_CONTROL_REQUEST,
            &[
                0x00,
                0x0d,
                0x00,
                0x03,
                self.params[0],
                self.params[1],
                self.params[2],
            ],
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
/// 10 (LPP), and 13 (timer start) are deliberately dropped by the SDK switch and remain
/// [`Self::Unsupported`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EmmControlResponse {
    NiReattach { result: u32 },
    Unsupported { kind: u16 },
}

impl EmmControlResponse {
    /// Decode the live shared response switch.
    ///
    /// Unsupported discriminators are returned after only the four-byte
    /// prefix/discriminator pair has been proven present, matching the live
    /// SDK switch which drops those families before reading their bodies.
    /// Discriminator 11 then requires the exact ten-byte NI-reattach envelope.
    ///
    /// # Errors
    /// Returns [`EmmControlDecodeError`] for a malformed opcode or NI-reattach
    /// envelope.
    pub fn parse(packet: Packet<'_>) -> Result<Self, EmmControlDecodeError> {
        let payload = response_payload(packet, recovered_opcode::EMM_CONTROL_RESPONSE)?;
        if payload.len() < 4 {
            return Err(ResponseDecodeError::TruncatedPrefix {
                minimum: 4,
                actual: payload.len(),
            }
            .into());
        }
        let kind = be_u16(payload, 2);
        if kind != 11 {
            return Ok(Self::Unsupported { kind });
        }
        let (_prefix, _kind, value) =
            parse_emm_control_envelope(packet, recovered_opcode::EMM_CONTROL_RESPONSE)?;
        Ok(Self::NiReattach { result: value })
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

/// Validation failure for the shipped NAS configuration request surface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NasConfigEncodeError {
    TooManyPairs { maximum: usize, actual: usize },
    TruncatedPairs { required: usize, actual: usize },
    UnsupportedTag(u8),
    Hci(EncodeError),
}

impl From<EncodeError> for NasConfigEncodeError {
    fn from(value: EncodeError) -> Self {
        Self::Hci(value)
    }
}

/// Live-P4 NAS configuration setter (`0x3370`).
///
/// The stock local object is `count:u8` plus storage for sixteen `(tag,value)`
/// pairs. The modem wire expands each used pair into `tag | 1 | value`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NasConfigSetRequest<'a> {
    pub count: u8,
    /// Alternating `tag,value` bytes; unused capacity may follow the active pairs.
    pub pairs: &'a [u8],
}

impl NasConfigSetRequest<'_> {
    /// Encode the exact shipped NAS TLV stream.
    ///
    /// # Errors
    /// Rejects more than sixteen pairs, insufficient pair storage, tags outside
    /// the shipped `0x80..=0x8a` set, or insufficient output space.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, NasConfigEncodeError> {
        let count = usize::from(self.count);
        if count > 16 {
            return Err(NasConfigEncodeError::TooManyPairs {
                maximum: 16,
                actual: count,
            });
        }
        let required = count.saturating_mul(2);
        if self.pairs.len() < required {
            return Err(NasConfigEncodeError::TruncatedPairs {
                required,
                actual: self.pairs.len(),
            });
        }
        for pair in self.pairs[..required].as_chunks::<2>().0 {
            if !(0x80..=0x8a).contains(&pair[0]) {
                return Err(NasConfigEncodeError::UnsupportedTag(pair[0]));
            }
        }
        let payload_len = count.saturating_mul(3);
        let payload_len_u16 =
            u16::try_from(payload_len).map_err(|_| EncodeError::PayloadTooLong)?;
        let total = HEADER_LEN
            .checked_add(payload_len)
            .ok_or(EncodeError::PayloadTooLong)?;
        let Some(dst) = output.get_mut(..total) else {
            return Err(EncodeError::NoSpace.into());
        };
        dst[..HEADER_LEN].copy_from_slice(
            &Header {
                command: recovered_opcode::NAS_CONFIG_SET_REQUEST,
                payload_len: payload_len_u16,
            }
            .encode(),
        );
        let mut offset = HEADER_LEN;
        for pair in self.pairs[..required].as_chunks::<2>().0 {
            dst[offset] = pair[0];
            dst[offset + 1] = 1;
            dst[offset + 2] = pair[1];
            offset += 3;
        }
        Ok(total)
    }
}

/// Header-only live-P4 NAS configuration getter (`0x3372`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NasConfigGetRequest;

impl NasConfigGetRequest {
    /// Encode the exact four-byte request.
    ///
    /// # Errors
    /// Returns [`EncodeError::NoSpace`] when `output` is shorter than four bytes.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, EncodeError> {
        encode_packet(recovered_opcode::NAS_CONFIG_GET_REQUEST, &[], output)
    }
}
