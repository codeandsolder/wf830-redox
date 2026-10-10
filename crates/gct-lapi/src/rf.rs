//! RF status-control and measurement-report codecs recovered from live P4.

use gct_hci::{EncodeError, Packet, encode_packet, recovered_opcode};

use crate::common::{ResponseDecodeError, be_u16, exact_payload};

const RF_STATUS_KIND: u16 = 1;
const RF_MEASURE_KIND: u16 = 5;

/// Exact ten-byte `_RF_STATUS_REPORT_CONTROL_REQ_PARAM` from the shipped SDK.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RfStatusReportControlRequest {
    pub on_off: u16,
    pub intval_idle: u16,
    pub intval_connect: u16,
    pub thresh_idle: u16,
    pub thresh_connect: u16,
}

impl RfStatusReportControlRequest {
    /// Encode shared command `0x3155` discriminator 1 and the five big-endian
    /// 16-bit request fields used by live P4.
    ///
    /// # Errors
    /// Returns [`EncodeError::NoSpace`] when `output` is shorter than 18 bytes.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, EncodeError> {
        let on_off = self.on_off.to_be_bytes();
        let intval_idle = self.intval_idle.to_be_bytes();
        let intval_connect = self.intval_connect.to_be_bytes();
        let thresh_idle = self.thresh_idle.to_be_bytes();
        let thresh_connect = self.thresh_connect.to_be_bytes();
        encode_packet(
            recovered_opcode::SHARED_CONTROL_REQUEST,
            &[
                0x00,
                0x01,
                0x00,
                0x0a,
                on_off[0],
                on_off[1],
                intval_idle[0],
                intval_idle[1],
                intval_connect[0],
                intval_connect[1],
                thresh_idle[0],
                thresh_idle[1],
                thresh_connect[0],
                thresh_connect[1],
            ],
            output,
        )
    }
}

/// Exact one-byte `_RF_MEASURE_REPORT_REQ` from the shipped SDK.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RfMeasureReportRequest {
    pub control: u8,
}

impl RfMeasureReportRequest {
    /// Encode shared command `0x3155` discriminator 5.
    ///
    /// # Errors
    /// Returns [`EncodeError::NoSpace`] when `output` is shorter than nine bytes.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, EncodeError> {
        encode_packet(
            recovered_opcode::SHARED_CONTROL_REQUEST,
            &[0x00, 0x05, 0x00, 0x01, self.control],
            output,
        )
    }
}

/// Failure while decoding one RF family inside the shared `0xb156`/`0xb164` envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RfControlDecodeError {
    Response(ResponseDecodeError),
    UnexpectedKind { expected: u16, actual: u16 },
    UnexpectedValueLength { expected: u16, actual: u16 },
}

impl From<ResponseDecodeError> for RfControlDecodeError {
    fn from(value: ResponseDecodeError) -> Self {
        Self::Response(value)
    }
}

fn shared_body<const N: usize>(
    packet: Packet<'_>,
    opcode: u16,
    kind: u16,
) -> Result<(u16, &[u8]), RfControlDecodeError> {
    let payload = exact_payload(packet, opcode, 6 + N)?;
    let actual_kind = be_u16(payload, 2);
    if actual_kind != kind {
        return Err(RfControlDecodeError::UnexpectedKind {
            expected: kind,
            actual: actual_kind,
        });
    }
    let actual_len = be_u16(payload, 4);
    let expected_len = u16::try_from(N).unwrap_or(u16::MAX);
    if actual_len != expected_len {
        return Err(RfControlDecodeError::UnexpectedValueLength {
            expected: expected_len,
            actual: actual_len,
        });
    }
    Ok((be_u16(payload, 0), &payload[6..]))
}

/// Live-P4 `_RF_STATUS_REPORT_CONTROL_RSP_INFO`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RfStatusReportControlResponse {
    pub result: u16,
    pub status: u16,
    pub mode: u16,
    pub prev_rsrp: i16,
    pub cur_rsrp: i16,
    pub thresh: i16,
}

impl RfStatusReportControlResponse {
    /// Decode shared `0xb156` discriminator 1.
    ///
    /// # Errors
    /// Returns [`RfControlDecodeError`] for any opcode, envelope, discriminator,
    /// or length mismatch.
    pub fn parse(packet: Packet<'_>) -> Result<Self, RfControlDecodeError> {
        let (result, body) = shared_body::<10>(
            packet,
            recovered_opcode::SHARED_CONTROL_RESPONSE,
            RF_STATUS_KIND,
        )?;
        Ok(Self {
            result,
            status: be_u16(body, 0),
            mode: be_u16(body, 2),
            prev_rsrp: i16::from_be_bytes([body[4], body[5]]),
            cur_rsrp: i16::from_be_bytes([body[6], body[7]]),
            thresh: i16::from_be_bytes([body[8], body[9]]),
        })
    }
}

/// Live-P4 `_RF_MEASURE_REPORT_RSP_INFO`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RfMeasureReportResponse {
    pub result: u16,
    pub status: u16,
}

impl RfMeasureReportResponse {
    /// Decode shared `0xb156` discriminator 5.
    ///
    /// # Errors
    /// Returns [`RfControlDecodeError`] for any opcode, envelope, discriminator,
    /// or length mismatch.
    pub fn parse(packet: Packet<'_>) -> Result<Self, RfControlDecodeError> {
        let (result, body) = shared_body::<2>(
            packet,
            recovered_opcode::SHARED_CONTROL_RESPONSE,
            RF_MEASURE_KIND,
        )?;
        Ok(Self {
            result,
            status: be_u16(body, 0),
        })
    }
}

/// Live-P4 `_RF_MEASURE_REPORT_IND_INFO`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RfMeasureReportIndication {
    pub result: u16,
    pub rrc_state: u8,
    pub paging_cycle: u8,
    pub rssi: i16,
    pub rsrp: i16,
    pub rsrq: i16,
    pub snr: i16,
}

impl RfMeasureReportIndication {
    /// Decode shared unsolicited `0xb164` discriminator 5.
    ///
    /// # Errors
    /// Returns [`RfControlDecodeError`] for any opcode, envelope, discriminator,
    /// or length mismatch.
    pub fn parse(packet: Packet<'_>) -> Result<Self, RfControlDecodeError> {
        let (result, body) = shared_body::<10>(
            packet,
            recovered_opcode::SHARED_CONTROL_REPORT,
            RF_MEASURE_KIND,
        )?;
        Ok(Self {
            result,
            rrc_state: body[0],
            paging_cycle: body[1],
            rssi: i16::from_be_bytes([body[2], body[3]]),
            rsrp: i16::from_be_bytes([body[4], body[5]]),
            rsrq: i16::from_be_bytes([body[6], body[7]]),
            snr: i16::from_be_bytes([body[8], body[9]]),
        })
    }
}
