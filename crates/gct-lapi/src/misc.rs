//! Shared modem-information and identity/status read codecs.

use gct_hci::{EncodeError, Packet, encode_packet, public_opcode, recovered_opcode};

use crate::common::{ResponseDecodeError, be_u16, prefix_payload, response_payload};

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

/// Temperature read request carried by the shared `0x3145` read-info command.
///
/// Live P4 `LAPI_TemperatureReadRequest` emits subtype 4 with an empty subtype body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TemperatureReadRequest;

impl TemperatureReadRequest {
    /// Encode exact live-P4 bytes `31 45 00 04 00 04 00 00`.
    ///
    /// # Errors
    /// Returns [`EncodeError::NoSpace`] when `output` is shorter than eight bytes.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, EncodeError> {
        encode_packet(
            recovered_opcode::MISC_READ_REQUEST,
            &[0x00, 0x04, 0x00, 0x00],
            output,
        )
    }
}

/// Temperature response recovered from shared response `0xb146` subtype 4.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TemperatureReadResponse {
    pub read_result: u16,
    pub result: u8,
    pub temperature: i8,
}

/// ICCID read request carried by the shared `0x3145` read-info command.
///
/// Live P4 `LAPI_ICCIDReadRequest` emits subtype 2 with an empty subtype body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IccidReadRequest;

impl IccidReadRequest {
    /// Encode exact live-P4 bytes `31 45 00 04 00 02 00 00`.
    ///
    /// # Errors
    /// Returns [`EncodeError::NoSpace`] when `output` is shorter than eight bytes.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, EncodeError> {
        encode_packet(
            recovered_opcode::MISC_READ_REQUEST,
            &[0x00, 0x02, 0x00, 0x00],
            output,
        )
    }
}

/// ICCID response recovered from shared response `0xb146` subtype 2.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IccidReadResponse<'a> {
    pub read_result: u16,
    pub result: u8,
    pub iccid: &'a [u8],
}

/// MSISDN read request carried by the shared `0x3145` read-info command.
///
/// Live P4 `LAPI_MSISDNReadRequest` emits subtype 3 with an empty subtype body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MsisdnReadRequest;

impl MsisdnReadRequest {
    /// Encode exact live-P4 bytes `31 45 00 04 00 03 00 00`.
    ///
    /// # Errors
    /// Returns [`EncodeError::NoSpace`] when `output` is shorter than eight
    /// bytes.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, EncodeError> {
        encode_packet(
            recovered_opcode::MISC_READ_REQUEST,
            &[0x00, 0x03, 0x00, 0x00],
            output,
        )
    }
}

pub const MSISDN_RECORD_LEN: usize = 256;
pub const MAX_MSISDN_RECORDS: usize = 3;

/// Successful or subtype-local-failure MSISDN response recovered from shared
/// response `0xb146` subtype 3.
///
/// `records` contains exactly `num_msisdn * 256` stock record bytes. B014 DWARF
/// proves each record is `{alpha_id_len, alpha_id[241], bcdssc_len, ton_npi,
/// dial_num_ssc[10], cap_cfg2, ext5}`; the raw fixed record is intentionally
/// preserved because the live daemon forwards it byte-for-byte.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MsisdnReadResponse<'a> {
    pub read_result: u16,
    pub result: u8,
    pub records: &'a [u8],
}

impl MsisdnReadResponse<'_> {
    #[must_use]
    pub const fn num_msisdn(self) -> usize {
        self.records.len() / MSISDN_RECORD_LEN
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
    Iccid(IccidReadResponse<'a>),
    Msisdn(MsisdnReadResponse<'a>),
    Temperature(TemperatureReadResponse),
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
    IccidBodyTooShort {
        minimum: usize,
        actual: usize,
    },
    TemperatureBodyTooShort {
        minimum: usize,
        actual: usize,
    },
    MsisdnBodyTooShort {
        minimum: usize,
        actual: usize,
    },
    TooManyMsisdnRecords {
        maximum: usize,
        actual: usize,
    },
    TruncatedMsisdnRecords {
        expected: usize,
        actual: usize,
    },
}

impl From<ResponseDecodeError> for MiscReadDecodeError {
    fn from(value: ResponseDecodeError) -> Self {
        Self::Response(value)
    }
}

fn parse_mobile_id_chunk(
    read_result: u16,
    body: &[u8],
) -> Result<MiscReadResponse<'_>, MiscReadDecodeError> {
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
    Ok(MiscReadResponse::MobileId(MobileIdReadResponse {
        read_result,
        id_type: body[0],
        result: body[1],
        id: &body[3..3 + id_len],
    }))
}

fn parse_iccid_chunk(
    read_result: u16,
    body: &[u8],
) -> Result<MiscReadResponse<'_>, MiscReadDecodeError> {
    const ICCID_BODY_LEN: usize = 11;
    if body.len() < ICCID_BODY_LEN {
        return Err(MiscReadDecodeError::IccidBodyTooShort {
            minimum: ICCID_BODY_LEN,
            actual: body.len(),
        });
    }
    Ok(MiscReadResponse::Iccid(IccidReadResponse {
        read_result,
        result: body[0],
        iccid: &body[1..ICCID_BODY_LEN],
    }))
}

fn parse_temperature_chunk(
    read_result: u16,
    body: &[u8],
) -> Result<MiscReadResponse<'_>, MiscReadDecodeError> {
    const TEMPERATURE_BODY_LEN: usize = 2;
    if body.len() < TEMPERATURE_BODY_LEN {
        return Err(MiscReadDecodeError::TemperatureBodyTooShort {
            minimum: TEMPERATURE_BODY_LEN,
            actual: body.len(),
        });
    }
    Ok(MiscReadResponse::Temperature(TemperatureReadResponse {
        read_result,
        result: body[0],
        temperature: body[1].cast_signed(),
    }))
}

fn parse_msisdn_chunk(
    read_result: u16,
    body: &[u8],
) -> Result<MiscReadResponse<'_>, MiscReadDecodeError> {
    if body.is_empty() {
        return Err(MiscReadDecodeError::MsisdnBodyTooShort {
            minimum: 1,
            actual: 0,
        });
    }
    let result = body[0];
    if result != 0 {
        return Ok(MiscReadResponse::Msisdn(MsisdnReadResponse {
            read_result,
            result,
            records: &[],
        }));
    }
    if body.len() < 2 {
        return Err(MiscReadDecodeError::MsisdnBodyTooShort {
            minimum: 2,
            actual: body.len(),
        });
    }
    let num_msisdn = usize::from(body[1]);
    if num_msisdn > MAX_MSISDN_RECORDS {
        return Err(MiscReadDecodeError::TooManyMsisdnRecords {
            maximum: MAX_MSISDN_RECORDS,
            actual: num_msisdn,
        });
    }
    let records_len = num_msisdn * MSISDN_RECORD_LEN;
    let expected = 2 + records_len;
    if body.len() < expected {
        return Err(MiscReadDecodeError::TruncatedMsisdnRecords {
            expected: records_len,
            actual: body.len().saturating_sub(2),
        });
    }
    Ok(MiscReadResponse::Msisdn(MsisdnReadResponse {
        read_result,
        result,
        records: &body[2..expected],
    }))
}

impl<'a> MiscReadResponse<'a> {
    /// Decode the live-P4 shared read response and extract proven subtypes.
    ///
    /// Wire grammar on success is `read_result:u16 == 0`, followed by zero or
    /// more chunks `subtype:u16 | len:u16 | body[len]`. Mobile ID is subtype 1,
    /// ICCID is subtype 2, MSISDN is subtype 3, and temperature is subtype 4.
    ///
    /// # Errors
    /// Returns [`MiscReadDecodeError`] for the wrong opcode, a truncated chunk
    /// envelope/body, or an unsafe proven subtype payload.
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
            match subtype {
                1 => return parse_mobile_id_chunk(read_result, body),
                2 => return parse_iccid_chunk(read_result, body),
                3 => return parse_msisdn_chunk(read_result, body),
                4 => return parse_temperature_chunk(read_result, body),
                _ => offset = body_start + declared,
            }
        }
        Ok(Self::UnsupportedSuccess)
    }
}

/// Zero-payload live-P4 `LTE_GET_INFORMATION` (`0x3002`) request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceInformationRequest;

impl DeviceInformationRequest {
    /// Encode the exact four-byte HCI request.
    ///
    /// # Errors
    /// Returns `EncodeError::NoSpace` when output is shorter than the HCI header.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, EncodeError> {
        encode_packet(public_opcode::LTE_GET_INFORMATION, &[], output)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceInformationDecodeError {
    Response(ResponseDecodeError),
    TruncatedRecordHeader {
        offset: usize,
        remaining: usize,
    },
    TruncatedRecordValue {
        offset: usize,
        declared: usize,
        remaining: usize,
    },
    KnownFieldTooLong {
        type_id: u8,
        maximum: usize,
        actual: usize,
    },
}

impl From<ResponseDecodeError> for DeviceInformationDecodeError {
    fn from(value: ResponseDecodeError) -> Self {
        Self::Response(value)
    }
}

/// Modem-owned portion of stock `_SYSTEM_VERSION`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceInformationResponse {
    pub fw_revision: [u8; 4],
    pub chip_revision: [u8; 2],
}

impl DeviceInformationResponse {
    /// Decode the live get-information TLV stream. Unknown types are skipped.
    ///
    /// # Errors
    /// Rejects another opcode, truncated TLVs, or a known value larger than its recovered slot.
    pub fn parse(packet: Packet<'_>) -> Result<Self, DeviceInformationDecodeError> {
        let payload = response_payload(packet, public_opcode::LTE_GET_INFORMATION_RESULT)?;
        let mut response = Self {
            fw_revision: [0; 4],
            chip_revision: [0; 2],
        };
        let mut offset = 0_usize;
        while offset < payload.len() {
            let remaining = payload.len() - offset;
            if remaining < 2 {
                return Err(DeviceInformationDecodeError::TruncatedRecordHeader {
                    offset,
                    remaining,
                });
            }
            let type_id = payload[offset];
            let declared = usize::from(payload[offset + 1]);
            let value_offset = offset + 2;
            let remaining_value = payload.len() - value_offset;
            if remaining_value < declared {
                return Err(DeviceInformationDecodeError::TruncatedRecordValue {
                    offset,
                    declared,
                    remaining: remaining_value,
                });
            }
            let value = &payload[value_offset..value_offset + declared];
            match type_id {
                0xa0 => {
                    if declared > response.fw_revision.len() {
                        return Err(DeviceInformationDecodeError::KnownFieldTooLong {
                            type_id,
                            maximum: response.fw_revision.len(),
                            actual: declared,
                        });
                    }
                    response.fw_revision[..declared].copy_from_slice(value);
                }
                0xa1 => {
                    if declared > response.chip_revision.len() {
                        return Err(DeviceInformationDecodeError::KnownFieldTooLong {
                            type_id,
                            maximum: response.chip_revision.len(),
                            actual: declared,
                        });
                    }
                    response.chip_revision[..declared].copy_from_slice(value);
                }
                _ => {}
            }
            offset = value_offset + declared;
        }
        Ok(response)
    }
}
