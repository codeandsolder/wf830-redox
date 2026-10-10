//! PLMN search, extended search, list, and search-stop codecs.

use gct_hci::{EncodeError, Packet, TlvCursor, TlvDecodeError, encode_packet, recovered_opcode};

use crate::common::{ResponseDecodeError, be_u16, be_u32, exact_payload, prefix_payload};

/// Zero-payload selected-PLMN query `0x310f`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuerySelectedPlmnRequest;

impl QuerySelectedPlmnRequest {
    /// Encode the exact empty request.
    ///
    /// # Errors
    /// Returns [`EncodeError::NoSpace`] when `output` is shorter than one HCI header.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, EncodeError> {
        encode_packet(recovered_opcode::QUERY_SELECTED_PLMN_REQUEST, &[], output)
    }
}

/// Live-P4 selected-PLMN response `0xb110`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuerySelectedPlmnResponse {
    pub result: u8,
    pub selected_plmn: [u8; 3],
}

impl QuerySelectedPlmnResponse {
    /// Decode the exact four bytes forwarded by the live SDK/daemon.
    ///
    /// # Errors
    /// Returns [`ResponseDecodeError`] for another opcode or non-four-byte payload.
    pub fn parse(packet: Packet<'_>) -> Result<Self, ResponseDecodeError> {
        let payload = exact_payload(packet, recovered_opcode::QUERY_SELECTED_PLMN_RESPONSE, 4)?;
        Ok(Self {
            result: payload[0],
            selected_plmn: [payload[1], payload[2], payload[3]],
        })
    }
}

/// One semantic PLMN record assembled from the three TLVs used by GCT.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlmnInfo {
    pub plmn_id: [u8; 3],
    pub priority: u32,
    pub status: u32,
}

/// Field names in one recovered PLMN record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlmnInfoField {
    PlmnId,
    Priority,
    Status,
}

/// Error while assembling one PLMN record from its TLV stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlmnInfoDecodeError {
    Tlv(TlvDecodeError),
    UnknownKind(u8),
    UnexpectedLength {
        kind: u8,
        expected: usize,
        actual: usize,
    },
    DuplicateField(PlmnInfoField),
    IncompleteRecord,
    TooManyRecords,
}

impl From<TlvDecodeError> for PlmnInfoDecodeError {
    fn from(value: TlvDecodeError) -> Self {
        Self::Tlv(value)
    }
}

/// Allocation-free cursor over GCT PLMN records.
///
/// The OEM parser writes into `PLMN_INFO[32]`, but one record is not an
/// eleven-byte wire struct. It is exactly three TLVs: `0x12` PLMN ID (3
/// bytes), `0x13` priority (BE u32) and `0x14` status (BE u32). The old code
/// accepts those three tags in any order and advances to the next destination
/// after three recognized fields. The clean parser keeps that order
/// independence while requiring each semantic field exactly once.
pub struct PlmnInfoCursor<'a> {
    cursor: TlvCursor<'a>,
    records: u8,
}

impl<'a> PlmnInfoCursor<'a> {
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self {
            cursor: TlvCursor::new(bytes),
            records: 0,
        }
    }

    #[must_use]
    pub const fn remaining(&self) -> &'a [u8] {
        self.cursor.remaining()
    }

    /// Decode one complete PLMN record.
    ///
    /// # Errors
    /// Returns [`PlmnInfoDecodeError`] for malformed TLV framing, unknown or
    /// duplicate record fields, wrong fixed widths, an incomplete record, or
    /// more than the 32 records provisioned by the historical SDK.
    pub fn next_record(&mut self) -> Result<Option<PlmnInfo>, PlmnInfoDecodeError> {
        if self.cursor.remaining().is_empty() {
            return Ok(None);
        }
        if self.records >= 32 {
            return Err(PlmnInfoDecodeError::TooManyRecords);
        }

        let mut plmn_id = None;
        let mut priority = None;
        let mut status = None;
        for _ in 0..3 {
            let Some(tlv) = self.cursor.next_tlv()? else {
                return Err(PlmnInfoDecodeError::IncompleteRecord);
            };
            match tlv.kind {
                0x12 => {
                    let Ok(value) = <[u8; 3]>::try_from(tlv.payload) else {
                        return Err(PlmnInfoDecodeError::UnexpectedLength {
                            kind: tlv.kind,
                            expected: 3,
                            actual: tlv.payload.len(),
                        });
                    };
                    if plmn_id.replace(value).is_some() {
                        return Err(PlmnInfoDecodeError::DuplicateField(PlmnInfoField::PlmnId));
                    }
                }
                0x13 => {
                    let Ok(value) = <[u8; 4]>::try_from(tlv.payload) else {
                        return Err(PlmnInfoDecodeError::UnexpectedLength {
                            kind: tlv.kind,
                            expected: 4,
                            actual: tlv.payload.len(),
                        });
                    };
                    if priority.replace(u32::from_be_bytes(value)).is_some() {
                        return Err(PlmnInfoDecodeError::DuplicateField(PlmnInfoField::Priority));
                    }
                }
                0x14 => {
                    let Ok(value) = <[u8; 4]>::try_from(tlv.payload) else {
                        return Err(PlmnInfoDecodeError::UnexpectedLength {
                            kind: tlv.kind,
                            expected: 4,
                            actual: tlv.payload.len(),
                        });
                    };
                    if status.replace(u32::from_be_bytes(value)).is_some() {
                        return Err(PlmnInfoDecodeError::DuplicateField(PlmnInfoField::Status));
                    }
                }
                other => return Err(PlmnInfoDecodeError::UnknownKind(other)),
            }
        }

        let (Some(plmn_id), Some(priority), Some(status)) = (plmn_id, priority, status) else {
            return Err(PlmnInfoDecodeError::IncompleteRecord);
        };
        self.records += 1;
        Ok(Some(PlmnInfo {
            plmn_id,
            priority,
            status,
        }))
    }
}

/// Borrowed SIB1 PLMN-list payload from search-response TLV `0x26`.
///
/// The old destination is 49 bytes (`count` + 48 payload bytes). The OEM
/// clamps larger TLVs by mutating their length byte; this clean parser rejects
/// that malformed shape instead. A zero-length payload is representable because
/// the historical destination was zero-initialized before a zero-byte copy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Sib1PlmnList<'a> {
    pub count: u8,
    pub packed_plmn: &'a [u8],
}

/// Error returned while decoding a complete PLMN search response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlmnSearchDecodeError {
    Response(ResponseDecodeError),
    Tlv(TlvDecodeError),
    UnexpectedMetadataLength {
        kind: u8,
        expected: usize,
        actual: usize,
    },
    Sib1PlmnTooLong {
        maximum: usize,
        actual: usize,
    },
    MissingMetadata(u8),
}

impl From<ResponseDecodeError> for PlmnSearchDecodeError {
    fn from(value: ResponseDecodeError) -> Self {
        Self::Response(value)
    }
}

impl From<TlvDecodeError> for PlmnSearchDecodeError {
    fn from(value: TlvDecodeError) -> Self {
        Self::Tlv(value)
    }
}

/// Decoded fixed prefix and borrowed record stream of PLMN-search response
/// `0xb10a`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlmnSearchResponse<'a> {
    pub result: u32,
    pub selection_mode: u8,
    pub selected_plmn_id: [u8; 3],
    pub next_index: u16,
    pub network_interval: u16,
    pub remaining_count: i8,
    pub band: u16,
    pub cell_id: u16,
    pub frequency: u32,
    pub tac: [u8; 2],
    pub bit28_cell_id: u32,
    pub plmn_priority: Option<u32>,
    pub sib1_plmn: Option<Sib1PlmnList<'a>>,
    records: &'a [u8],
}

impl<'a> PlmnSearchResponse<'a> {
    /// Decode the recovered 27-byte fixed prefix plus the two contextual
    /// success-only metadata TLVs at the head of the remaining stream.
    ///
    /// # Errors
    /// Returns [`PlmnSearchDecodeError`] for the wrong opcode, truncated fixed
    /// prefix or malformed contextual `0x13`/`0x26` metadata.
    pub fn parse(packet: Packet<'a>) -> Result<Self, PlmnSearchDecodeError> {
        let payload = prefix_payload(packet, recovered_opcode::PLMN_SEARCH_RESPONSE, 27)?;
        let result = be_u32(payload, 0);
        let mut cursor = TlvCursor::new(&payload[27..]);
        let mut plmn_priority = None;
        let mut sib1_plmn = None;

        if result == 0 {
            if cursor.remaining().first() == Some(&0x13) {
                let tlv = cursor
                    .next_tlv()?
                    .ok_or(PlmnSearchDecodeError::MissingMetadata(0x13))?;
                let Ok(bytes) = <[u8; 4]>::try_from(tlv.payload) else {
                    return Err(PlmnSearchDecodeError::UnexpectedMetadataLength {
                        kind: tlv.kind,
                        expected: 4,
                        actual: tlv.payload.len(),
                    });
                };
                plmn_priority = Some(u32::from_be_bytes(bytes));
            }
            if cursor.remaining().first() == Some(&0x26) {
                let tlv = cursor
                    .next_tlv()?
                    .ok_or(PlmnSearchDecodeError::MissingMetadata(0x26))?;
                if tlv.payload.len() > 49 {
                    return Err(PlmnSearchDecodeError::Sib1PlmnTooLong {
                        maximum: 49,
                        actual: tlv.payload.len(),
                    });
                }
                let (count, packed_plmn) = match tlv.payload.split_first() {
                    Some((&count, rest)) => (count, rest),
                    None => (0, &[][..]),
                };
                sib1_plmn = Some(Sib1PlmnList { count, packed_plmn });
            }
        }

        Ok(Self {
            result,
            selection_mode: payload[4],
            selected_plmn_id: [payload[5], payload[6], payload[7]],
            next_index: be_u16(payload, 8),
            network_interval: be_u16(payload, 10),
            remaining_count: payload[12].cast_signed(),
            band: be_u16(payload, 13),
            cell_id: be_u16(payload, 15),
            frequency: be_u32(payload, 17),
            tac: [payload[21], payload[22]],
            bit28_cell_id: be_u32(payload, 23),
            plmn_priority,
            sib1_plmn,
            records: cursor.remaining(),
        })
    }

    #[must_use]
    pub const fn records(&self) -> PlmnInfoCursor<'a> {
        PlmnInfoCursor::new(self.records)
    }
}

/// PLMN-list response `0xb10c`: one `search_complete` byte followed by the
/// shared PLMN-info TLV stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlmnListResponse<'a> {
    pub search_complete: u8,
    records: &'a [u8],
}

impl<'a> PlmnListResponse<'a> {
    /// Decode the list-response prefix and borrow its PLMN record stream.
    ///
    /// # Errors
    /// Returns [`ResponseDecodeError`] for the wrong opcode or an empty
    /// payload.
    pub fn parse(packet: Packet<'a>) -> Result<Self, ResponseDecodeError> {
        let payload = prefix_payload(packet, recovered_opcode::PLMN_LIST_RESPONSE, 1)?;
        Ok(Self {
            search_complete: payload[0],
            records: &payload[1..],
        })
    }

    #[must_use]
    pub const fn records(&self) -> PlmnInfoCursor<'a> {
        PlmnInfoCursor::new(self.records)
    }
}

/// Typed PLMN-search request `0x3109`.
///
/// `search_mode == 0` makes the SDK send the wildcard PLMN bytes `ff ff ff`.
/// Other modes pack caller-provided MCC/MNC nibbles into the same three-byte
/// representation used by the live P4 implementation. `mnc[2] = 0x0f` is the
/// conventional filler for a two-digit MNC; the codec deliberately does not
/// invent digit validation absent from the OEM encoder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlmnSearchRequest {
    pub search_mode: u8,
    pub mcc: [u8; 3],
    pub mnc: [u8; 3],
    pub emergency_mode: u8,
    pub roaming_option: u8,
}

impl PlmnSearchRequest {
    /// Encode the exact ten-byte search payload recovered from B014 and live
    /// P4, including TLVs `0x62` and `0x63`.
    ///
    /// # Errors
    /// Returns [`EncodeError::NoSpace`] when `output` is shorter than the
    /// fourteen-byte HCI frame.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, EncodeError> {
        let mut payload = [0_u8; 10];
        payload[0] = self.search_mode;
        if self.search_mode == 0 {
            payload[1..4].fill(0xff);
        } else {
            payload[1] = (self.mcc[1] << 4) | self.mcc[0];
            payload[2] = (self.mnc[2] << 4) | self.mcc[2];
            payload[3] = (self.mnc[1] << 4) | self.mnc[0];
        }
        payload[4..7].copy_from_slice(&[0x62, 0x01, self.emergency_mode]);
        payload[7..10].copy_from_slice(&[0x63, 0x01, self.roaming_option]);
        encode_packet(recovered_opcode::PLMN_SEARCH_REQUEST, &payload, output)
    }
}

/// Live-P4 extended PLMN-search request (`0x315a`).
///
/// The historical stock object is 1,292 bytes, but the P4 SDK serializes only
/// the fields represented here. Shipped P4 profiles set `earfcn_ext=1`, so
/// list element types 2/4 carry 32-bit EARFCNs unchanged on the modem wire.
/// `fastScanOption`, ECI and the 1,020-byte reserved area are not read by the
/// live serializer and deliberately do not exist in this clean representation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlmnSearchExtRequest<'a> {
    pub selection_mode: u8,
    pub operation_mode: u8,
    pub mcc: [u8; 3],
    pub mnc: [u8; 3],
    pub roaming_option: u8,
    pub list_count: u8,
    pub list_data: &'a [u8],
    pub power_scan: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlmnSearchExtEncodeError {
    ListTooLong {
        maximum: usize,
        actual: usize,
    },
    TruncatedElementHeader {
        index: usize,
        remaining: usize,
    },
    UnsupportedElementType {
        index: usize,
        kind: u8,
    },
    TruncatedElement {
        index: usize,
        kind: u8,
        expected: usize,
        remaining: usize,
    },
    ListLengthMismatch {
        declared: usize,
        consumed: usize,
    },
    Hci(EncodeError),
}

impl From<EncodeError> for PlmnSearchExtEncodeError {
    fn from(value: EncodeError) -> Self {
        Self::Hci(value)
    }
}

impl PlmnSearchExtRequest<'_> {
    fn validated_list_len(self) -> Result<usize, PlmnSearchExtEncodeError> {
        if self.list_count == 0 {
            return Ok(0);
        }
        if self.list_data.len() > 255 {
            return Err(PlmnSearchExtEncodeError::ListTooLong {
                maximum: 255,
                actual: self.list_data.len(),
            });
        }
        let mut offset = 0_usize;
        for index in 0..usize::from(self.list_count) {
            let remaining = self.list_data.len().saturating_sub(offset);
            if remaining < 2 {
                return Err(PlmnSearchExtEncodeError::TruncatedElementHeader { index, remaining });
            }
            let kind = self.list_data[offset];
            let count = usize::from(self.list_data[offset + 1]);
            let item_width = match kind {
                2 => 4_usize, // 32-bit EARFCN (P4 earfcn_ext=1)
                3 => 1_usize, // band byte
                4 => 8_usize, // start/end 32-bit EARFCN pair
                _ => {
                    return Err(PlmnSearchExtEncodeError::UnsupportedElementType { index, kind });
                }
            };
            let body_len = count.checked_mul(item_width).ok_or(
                PlmnSearchExtEncodeError::TruncatedElement {
                    index,
                    kind,
                    expected: usize::MAX,
                    remaining: remaining.saturating_sub(2),
                },
            )?;
            let element_len = 2_usize.checked_add(body_len).ok_or(
                PlmnSearchExtEncodeError::TruncatedElement {
                    index,
                    kind,
                    expected: usize::MAX,
                    remaining,
                },
            )?;
            if element_len > remaining {
                return Err(PlmnSearchExtEncodeError::TruncatedElement {
                    index,
                    kind,
                    expected: element_len,
                    remaining,
                });
            }
            offset += element_len;
        }
        if offset != self.list_data.len() {
            return Err(PlmnSearchExtEncodeError::ListLengthMismatch {
                declared: self.list_data.len(),
                consumed: offset,
            });
        }
        Ok(offset)
    }

    /// Encode exactly the fields read by live P4 `LAPI_PLMNSearchExtRequest`.
    ///
    /// Payload grammar is `selection_mode | operation_mode`, followed by
    /// `0x63 | roaming` for selection modes 0/2 or `0x64 | packed_plmn[3]`
    /// otherwise. A non-empty scan list is `0x65 | len | list_data`, and
    /// `power_scan` appends `0x66 | 1`.
    ///
    /// # Errors
    /// Returns [`PlmnSearchExtEncodeError`] for a malformed fixed-list grammar
    /// or insufficient destination space.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, PlmnSearchExtEncodeError> {
        let list_len = self.validated_list_len()?;
        let mut payload = [0_u8; 265];
        let mut used = 0_usize;
        payload[used] = self.selection_mode;
        payload[used + 1] = self.operation_mode;
        used += 2;

        if matches!(self.selection_mode, 0 | 2) {
            payload[used] = 0x63;
            payload[used + 1] = self.roaming_option;
            used += 2;
        } else {
            payload[used] = 0x64;
            payload[used + 1] = (self.mcc[1] << 4) | self.mcc[0];
            payload[used + 2] = (self.mnc[2] << 4) | self.mcc[2];
            payload[used + 3] = (self.mnc[1] << 4) | self.mnc[0];
            used += 4;
        }

        if self.list_count != 0 {
            let list_len_u8 =
                u8::try_from(list_len).map_err(|_| PlmnSearchExtEncodeError::ListTooLong {
                    maximum: 255,
                    actual: list_len,
                })?;
            payload[used] = 0x65;
            payload[used + 1] = list_len_u8;
            payload[used + 2..used + 2 + list_len].copy_from_slice(self.list_data);
            used += 2 + list_len;
        }

        if self.power_scan {
            payload[used] = 0x66;
            payload[used + 1] = 1;
            used += 2;
        }

        Ok(encode_packet(
            recovered_opcode::PLMN_SEARCH_REQUEST_EXT,
            &payload[..used],
            output,
        )?)
    }
}

/// PLMN-search-stop request `0x3127`.
///
/// B014 DWARF describes `_PLMN_SEARCH_STOP_REQ_PARAM` as one byte named
/// `search_type`; live P4 `LAPI_PLMNSearchStopRequest` allocates a five-byte
/// HCI frame and copies exactly that byte into the payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlmnSearchStopRequest {
    pub search_type: u8,
}

impl PlmnSearchStopRequest {
    /// Encode the exact one-byte stop-search payload.
    ///
    /// # Errors
    /// Returns [`EncodeError::NoSpace`] when `output` is shorter than five
    /// bytes.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, EncodeError> {
        encode_packet(
            recovered_opcode::PLMN_SEARCH_STOP_REQUEST,
            &[self.search_type],
            output,
        )
    }
}

/// PLMN-search-stop response `0xb128`.
///
/// Live P4 handler `0x12228` copies payload byte 0 unchanged and converts bytes
/// 1..5 with `D4H`; B014 DWARF names those fields `search_type:u8` and
/// `result:u32` in a five-byte callback object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlmnSearchStopResponse {
    pub search_type: u8,
    pub result: u32,
}

impl PlmnSearchStopResponse {
    /// Decode the exact five-byte stop-search response.
    ///
    /// # Errors
    /// Returns [`ResponseDecodeError`] for another opcode or a payload whose
    /// length is not exactly five bytes.
    pub fn parse(packet: Packet<'_>) -> Result<Self, ResponseDecodeError> {
        let payload = exact_payload(packet, recovered_opcode::PLMN_SEARCH_STOP_RESPONSE, 5)?;
        Ok(Self {
            search_type: payload[0],
            result: be_u32(payload, 1),
        })
    }
}
