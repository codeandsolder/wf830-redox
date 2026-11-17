//! RRC capability and protocol-info request/response codecs.

use gct_hci::{EncodeError, HEADER_LEN, Header, Packet, encode_packet, recovered_opcode};

use crate::common::{ResponseDecodeError, be_u16, response_payload};

/// RRC function-control set request `0x3908`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RrcFunctionSetRequest<'a> {
    pub type_id: u16,
    pub data: &'a [u8],
}

impl RrcFunctionSetRequest<'_> {
    /// Encode `type:u16 | len:u16 | data[len]` exactly as the live SDK.
    ///
    /// # Errors
    /// Returns [`EncodeError`] for an unrepresentable payload or short output buffer.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, EncodeError> {
        encode_common_rrc_function_request(
            recovered_opcode::RRC_FUNCTION_CONTROL_REQUEST,
            self.type_id,
            self.data,
            output,
        )
    }
}

/// RRC function-control get request `0x390f`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RrcFunctionGetRequest {
    pub type_id: u16,
}

impl RrcFunctionGetRequest {
    /// Encode the live four-byte `{type, len=0}` object.
    ///
    /// # Errors
    /// Returns [`EncodeError::NoSpace`] when `output` is too short.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, EncodeError> {
        encode_common_rrc_function_request(
            recovered_opcode::RRC_FUNCTION_CONTROL_GET_REQUEST,
            self.type_id,
            &[],
            output,
        )
    }
}

fn encode_common_rrc_function_request(
    opcode: u16,
    type_id: u16,
    data: &[u8],
    output: &mut [u8],
) -> Result<usize, EncodeError> {
    let data_len = u16::try_from(data.len()).map_err(|_| EncodeError::PayloadTooLong)?;
    let payload_len = 4_usize
        .checked_add(data.len())
        .ok_or(EncodeError::PayloadTooLong)?;
    let payload_len_u16 = u16::try_from(payload_len).map_err(|_| EncodeError::PayloadTooLong)?;
    let total = HEADER_LEN
        .checked_add(payload_len)
        .ok_or(EncodeError::PayloadTooLong)?;
    let Some(dst) = output.get_mut(..total) else {
        return Err(EncodeError::NoSpace);
    };
    dst[..HEADER_LEN].copy_from_slice(
        &Header {
            command: opcode,
            payload_len: payload_len_u16,
        }
        .encode(),
    );
    dst[4..6].copy_from_slice(&type_id.to_be_bytes());
    dst[6..8].copy_from_slice(&data_len.to_be_bytes());
    dst[8..].copy_from_slice(data);
    Ok(total)
}

/// Common live modem response shape for RRC function-control set/get.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RrcFunctionResponse<'a> {
    pub result: u16,
    pub type_id: u16,
    pub data: &'a [u8],
}

// These responses share framing, but the live wire puts len/type in opposite
// orders for set and get. Keep that distinction explicit at the codec boundary.
#[derive(Clone, Copy)]
enum RrcResponseOrder {
    LengthThenType,
    TypeThenLength,
}

fn parse_common_rrc_response<'a>(
    packet: Packet<'a>,
    opcode: u16,
    order: RrcResponseOrder,
) -> Result<(u16, u16, &'a [u8]), ResponseDecodeError> {
    let payload = response_payload(packet, opcode)?;
    if payload.len() < 6 {
        return Err(ResponseDecodeError::TruncatedPrefix {
            minimum: 6,
            actual: payload.len(),
        });
    }
    let (length_offset, type_offset) = match order {
        RrcResponseOrder::LengthThenType => (2, 4),
        RrcResponseOrder::TypeThenLength => (4, 2),
    };
    let declared = usize::from(be_u16(payload, length_offset));
    let expected = 6_usize
        .checked_add(declared)
        .ok_or(ResponseDecodeError::UnexpectedLength {
            expected: usize::MAX,
            actual: payload.len(),
        })?;
    if payload.len() != expected {
        return Err(ResponseDecodeError::UnexpectedLength {
            expected,
            actual: payload.len(),
        });
    }
    Ok((
        be_u16(payload, 0),
        be_u16(payload, type_offset),
        &payload[6..],
    ))
}

impl<'a> RrcFunctionResponse<'a> {
    fn parse_for(packet: Packet<'a>, opcode: u16) -> Result<Self, ResponseDecodeError> {
        let (result, type_id, data) =
            parse_common_rrc_response(packet, opcode, RrcResponseOrder::LengthThenType)?;
        Ok(Self {
            result,
            type_id,
            data,
        })
    }

    /// Decode live response `0xb909` (`result | len | type | data`).
    ///
    /// # Errors
    /// Returns [`ResponseDecodeError`] for another opcode or malformed declared length.
    pub fn parse_set(packet: Packet<'a>) -> Result<Self, ResponseDecodeError> {
        Self::parse_for(packet, recovered_opcode::RRC_FUNCTION_CONTROL_RESPONSE)
    }

    /// Decode live response `0xb910` (`result | len | type | data`).
    ///
    /// # Errors
    /// Returns [`ResponseDecodeError`] for another opcode or malformed declared length.
    pub fn parse_get(packet: Packet<'a>) -> Result<Self, ResponseDecodeError> {
        Self::parse_for(packet, recovered_opcode::RRC_FUNCTION_CONTROL_GET_RESPONSE)
    }
}

/// RRC-capability set request `0x3906`.
///
/// Live P4 `LAPI_RRCCapabilityControlRequest` serializes a common
/// `type:u16 | len:u16 | data[len]` payload for the shipped connection-manager
/// type IDs. Type-specific policy belongs above this wire codec.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RrcCapabilitySetRequest<'a> {
    pub type_id: u16,
    pub data: &'a [u8],
}

impl RrcCapabilitySetRequest<'_> {
    /// Encode the exact common live-P4 RRC-capability set frame.
    ///
    /// # Errors
    /// Returns [`EncodeError::PayloadTooLong`] if `data` plus the four-byte
    /// common prefix cannot fit the HCI u16 payload length, or
    /// [`EncodeError::NoSpace`] when `output` is too small.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, EncodeError> {
        encode_common_rrc_function_request(
            recovered_opcode::RRC_CAPABILITY_CONTROL_REQUEST,
            self.type_id,
            self.data,
            output,
        )
    }
}

/// RRC-capability get request `0x390d`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RrcCapabilityGetRequest {
    pub type_id: u16,
}

impl RrcCapabilityGetRequest {
    /// Encode the exact two-byte type selector consumed by the live SDK.
    ///
    /// # Errors
    /// Returns [`EncodeError::NoSpace`] when `output` is shorter than six bytes.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, EncodeError> {
        encode_packet(
            recovered_opcode::RRC_CAPABILITY_CONTROL_GET_REQUEST,
            &self.type_id.to_be_bytes(),
            output,
        )
    }
}

/// Live `0xb907` RRC-capability set response.
///
/// The SDK normalizes the common header as `result:u16 | len:u16 | type:u16`
/// and preserves any declared trailing bytes. The stock daemon callback uses
/// only the first six bytes, but keeping `data` here preserves modem evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RrcCapabilitySetResponse<'a> {
    pub result: u16,
    pub type_id: u16,
    pub data: &'a [u8],
}

impl<'a> RrcCapabilitySetResponse<'a> {
    /// Decode the exact common set-response envelope.
    ///
    /// # Errors
    /// Returns [`ResponseDecodeError`] for another opcode, a prefix shorter
    /// than six bytes, or a declared data length inconsistent with the frame.
    pub fn parse(packet: Packet<'a>) -> Result<Self, ResponseDecodeError> {
        let (result, type_id, data) = parse_common_rrc_response(
            packet,
            recovered_opcode::RRC_CAPABILITY_CONTROL_RESPONSE,
            RrcResponseOrder::LengthThenType,
        )?;
        Ok(Self {
            result,
            type_id,
            data,
        })
    }
}

/// Live `0xb90e` RRC-capability get response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RrcCapabilityGetResponse<'a> {
    pub result: u16,
    pub type_id: u16,
    pub data: &'a [u8],
}

impl<'a> RrcCapabilityGetResponse<'a> {
    /// Decode `result:u16 | type:u16 | len:u16 | data[len]`.
    ///
    /// # Errors
    /// Returns [`ResponseDecodeError`] for another opcode, a short prefix, or
    /// a declared data length inconsistent with the complete HCI frame.
    pub fn parse(packet: Packet<'a>) -> Result<Self, ResponseDecodeError> {
        let (result, type_id, data) = parse_common_rrc_response(
            packet,
            recovered_opcode::RRC_CAPABILITY_CONTROL_GET_RESPONSE,
            RrcResponseOrder::TypeThenLength,
        )?;
        Ok(Self {
            result,
            type_id,
            data,
        })
    }
}

/// Live-P4 set-protocol-info request `0x3151`.
///
/// `LAPI_SetProtocolInfoRequest` serializes the common modem envelope as
/// `type:u16 | len:u16 | data[len]`. Policy about which product-used type IDs
/// are supported belongs at the compatibility boundary, not in this wire codec.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SetProtocolInfoRequest<'a> {
    pub type_id: u16,
    pub data: &'a [u8],
}

impl SetProtocolInfoRequest<'_> {
    /// Encode the exact live-P4 common set-protocol frame.
    ///
    /// # Errors
    /// Returns [`EncodeError::PayloadTooLong`] when the common prefix plus data
    /// cannot fit the HCI u16 payload length, or [`EncodeError::NoSpace`] when
    /// `output` is too small.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, EncodeError> {
        encode_common_rrc_function_request(
            recovered_opcode::SET_PROTOCOL_INFO_REQUEST,
            self.type_id,
            self.data,
            output,
        )
    }
}

/// Live-P4 set-protocol-info response `0xb152` before daemon-side narrowing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SetProtocolInfoResponse<'a> {
    pub result: u16,
    pub type_id: u16,
    pub data: &'a [u8],
}

impl<'a> SetProtocolInfoResponse<'a> {
    /// Decode `result:u16 | type:u16 | len:u16 | data[len]`.
    ///
    /// # Errors
    /// Returns [`ResponseDecodeError`] for another opcode, a short prefix, or
    /// a declared data length inconsistent with the complete HCI frame.
    pub fn parse(packet: Packet<'a>) -> Result<Self, ResponseDecodeError> {
        let (result, type_id, data) = parse_common_rrc_response(
            packet,
            recovered_opcode::SET_PROTOCOL_INFO_RESPONSE,
            RrcResponseOrder::TypeThenLength,
        )?;
        Ok(Self {
            result,
            type_id,
            data,
        })
    }
}
