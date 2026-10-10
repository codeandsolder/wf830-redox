//! UICC request/response codecs for the recovered shipped command surface.

use gct_hci::{EncodeError, HEADER_LEN, Packet, recovered_opcode};

use crate::common::{ResponseDecodeError, be_u16, be_u32, prefix_payload};

/// Recovered UICC control subtypes carried inside HCI request `0x3504` and
/// response `0xb505`.
pub mod uicc_control {
    pub const STATUS: u16 = 0;
    pub const READ_BINARY: u16 = 1;
    pub const READ_RECORD: u16 = 2;
    pub const UPDATE_BINARY: u16 = 3;
    pub const UPDATE_RECORD: u16 = 4;
    pub const AUTHENTICATE: u16 = 5;
    pub const PIN_COMMAND: u16 = 6;
    pub const PIN_STATUS: u16 = 7;
    pub const REMOTE_COMMAND: u16 = 8;
    pub const PIN_REQUIRED: u16 = 9;
    pub const REFRESH: u16 = 10;
    pub const USAT_TERMINAL_PROFILE: u16 = 11;
    pub const USAT_ENVELOPE: u16 = 12;
    pub const USAT_TERMINAL_RESPONSE: u16 = 13;
    pub const POLL_INTERVAL_TIMER: u16 = 14;
}

/// Error while decoding the common UICC response envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UiccResponseDecodeError {
    Response(ResponseDecodeError),
    DataLengthMismatch { declared: usize, actual: usize },
}

impl From<ResponseDecodeError> for UiccResponseDecodeError {
    fn from(value: ResponseDecodeError) -> Self {
        Self::Response(value)
    }
}

/// Common borrowed UICC response envelope.
///
/// The wire order is `result`, `type`, `len`, `data`. B014 DWARF describes the
/// historical callback object in a different host order (`result`, `len`,
/// `type`, `data`); the OEM parser explicitly performs that reshuffle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UiccResponse<'a> {
    pub result: u16,
    pub kind: u16,
    pub data: &'a [u8],
}

impl<'a> UiccResponse<'a> {
    /// Decode the common six-byte UICC response envelope and validate its
    /// embedded data length.
    ///
    /// # Errors
    /// Returns [`UiccResponseDecodeError`] for the wrong HCI opcode, a
    /// truncated envelope, or a declared UICC length that differs from the
    /// bytes actually carried by the HCI packet.
    pub fn parse(packet: Packet<'a>) -> Result<Self, UiccResponseDecodeError> {
        let payload = prefix_payload(packet, recovered_opcode::UICC_RESPONSE, 6)?;
        let declared = usize::from(be_u16(payload, 4));
        let data = &payload[6..];
        if declared != data.len() {
            return Err(UiccResponseDecodeError::DataLengthMismatch {
                declared,
                actual: data.len(),
            });
        }
        Ok(Self {
            result: be_u16(payload, 0),
            kind: be_u16(payload, 2),
            data,
        })
    }
}

/// Error while narrowing the common UICC envelope to a recovered typed
/// response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UiccTypedDecodeError {
    Response(UiccResponseDecodeError),
    FailureResult(u16),
    UnexpectedKind { expected: u16, actual: u16 },
    UnexpectedDataLength { expected: usize, actual: usize },
}

impl From<UiccResponseDecodeError> for UiccTypedDecodeError {
    fn from(value: UiccResponseDecodeError) -> Self {
        Self::Response(value)
    }
}

fn successful_uicc_response(
    packet: Packet<'_>,
    expected_kind: u16,
) -> Result<UiccResponse<'_>, UiccTypedDecodeError> {
    let response = UiccResponse::parse(packet)?;
    if response.result != 0 {
        return Err(UiccTypedDecodeError::FailureResult(response.result));
    }
    if response.kind != expected_kind {
        return Err(UiccTypedDecodeError::UnexpectedKind {
            expected: expected_kind,
            actual: response.kind,
        });
    }
    Ok(response)
}

fn successful_uicc_data(
    packet: Packet<'_>,
    expected_kind: u16,
    expected_len: usize,
) -> Result<&[u8], UiccTypedDecodeError> {
    let response = successful_uicc_response(packet, expected_kind)?;
    if response.data.len() != expected_len {
        return Err(UiccTypedDecodeError::UnexpectedDataLength {
            expected: expected_len,
            actual: response.data.len(),
        });
    }
    Ok(response.data)
}

fn encode_uicc_request(kind: u16, data: &[u8], output: &mut [u8]) -> Result<usize, EncodeError> {
    let data_len = u16::try_from(data.len()).map_err(|_| EncodeError::PayloadTooLong)?;
    let payload_len = data
        .len()
        .checked_add(4)
        .ok_or(EncodeError::PayloadTooLong)?;
    let frame_len = payload_len
        .checked_add(HEADER_LEN)
        .ok_or(EncodeError::PayloadTooLong)?;
    if output.len() < frame_len {
        return Err(EncodeError::NoSpace);
    }
    let payload_len_u16 = u16::try_from(payload_len).map_err(|_| EncodeError::PayloadTooLong)?;
    output[..2].copy_from_slice(&recovered_opcode::UICC_REQUEST.to_be_bytes());
    output[2..4].copy_from_slice(&payload_len_u16.to_be_bytes());
    output[4..6].copy_from_slice(&kind.to_be_bytes());
    output[6..8].copy_from_slice(&data_len.to_be_bytes());
    output[8..frame_len].copy_from_slice(data);
    Ok(frame_len)
}

/// One fixed-width UICC request whose stock bytes are already the proven modem
/// subtype representation.
///
/// This intentionally supports only the two fixed raw-copy families where the
/// live SDK performs no subtype endian conversion. Keeping the original bytes
/// preserves stock padding/dead-slot contents without opening an unrestricted
/// raw UICC escape hatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UiccFixedRequest<'a> {
    kind: u16,
    data: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UiccFixedRequestError {
    UnexpectedLength {
        kind: u16,
        expected: usize,
        actual: usize,
    },
    Hci(EncodeError),
}

impl From<EncodeError> for UiccFixedRequestError {
    fn from(value: EncodeError) -> Self {
        Self::Hci(value)
    }
}

impl<'a> UiccFixedRequest<'a> {
    /// Preserve one exact 36-byte AUTHENTICATE subtype object.
    ///
    /// # Errors
    /// Returns [`UiccFixedRequestError::UnexpectedLength`] unless `data` is
    /// exactly the recovered 36-byte subtype width.
    pub fn authenticate(data: &'a [u8]) -> Result<Self, UiccFixedRequestError> {
        Self::new(uicc_control::AUTHENTICATE, 36, data)
    }

    /// Preserve one exact 20-byte PIN COMMAND subtype object.
    ///
    /// # Errors
    /// Returns [`UiccFixedRequestError::UnexpectedLength`] unless `data` is
    /// exactly the recovered 20-byte subtype width.
    pub fn pin_command(data: &'a [u8]) -> Result<Self, UiccFixedRequestError> {
        Self::new(uicc_control::PIN_COMMAND, 20, data)
    }

    fn new(kind: u16, expected: usize, data: &'a [u8]) -> Result<Self, UiccFixedRequestError> {
        if data.len() != expected {
            return Err(UiccFixedRequestError::UnexpectedLength {
                kind,
                expected,
                actual: data.len(),
            });
        }
        Ok(Self { kind, data })
    }

    #[must_use]
    pub const fn kind(self) -> u16 {
        self.kind
    }

    /// Encode the preserved fixed subtype under the common UICC envelope.
    ///
    /// # Errors
    /// Returns [`UiccFixedRequestError::Hci`] when the destination buffer is
    /// too short.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, UiccFixedRequestError> {
        Ok(encode_uicc_request(self.kind, self.data, output)?)
    }
}

/// UICC READ BINARY request (`type 1`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UiccReadBinaryRequest {
    pub app_type: u8,
    pub fid: u32,
    pub offset: u16,
    pub length: u16,
}

impl UiccReadBinaryRequest {
    /// Encode the nine-byte subtype payload recovered from `lted` and live P4.
    ///
    /// # Errors
    /// Returns [`EncodeError::NoSpace`] when the output buffer is too short.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, EncodeError> {
        let mut data = [0_u8; 9];
        data[0] = self.app_type;
        data[1..5].copy_from_slice(&self.fid.to_be_bytes());
        data[5..7].copy_from_slice(&self.offset.to_be_bytes());
        data[7..9].copy_from_slice(&self.length.to_be_bytes());
        encode_uicc_request(uicc_control::READ_BINARY, &data, output)
    }
}

/// UICC READ RECORD request (`type 2`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UiccReadRecordRequest {
    pub app_type: u8,
    pub fid: u32,
    pub record_index: u8,
}

impl UiccReadRecordRequest {
    /// Encode the six-byte subtype payload recovered from `lted` and live P4.
    ///
    /// # Errors
    /// Returns [`EncodeError::NoSpace`] when the output buffer is too short.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, EncodeError> {
        let mut data = [0_u8; 6];
        data[0] = self.app_type;
        data[1..5].copy_from_slice(&self.fid.to_be_bytes());
        data[5] = self.record_index;
        encode_uicc_request(uicc_control::READ_RECORD, &data, output)
    }
}

/// Error while decoding a variable-length UICC file-read response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UiccFileDecodeError {
    Typed(UiccTypedDecodeError),
    TruncatedData { minimum: usize, actual: usize },
    EmbeddedLengthMismatch { declared: usize, actual: usize },
}

impl From<UiccTypedDecodeError> for UiccFileDecodeError {
    fn from(value: UiccTypedDecodeError) -> Self {
        Self::Typed(value)
    }
}

/// Borrowed successful READ BINARY response (`type 1`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UiccReadBinaryResponse<'a> {
    pub uicc_return: u8,
    pub app_type: u8,
    pub fid: u32,
    pub sw1: u8,
    pub sw2: u8,
    pub data: &'a [u8],
}

impl<'a> UiccReadBinaryResponse<'a> {
    /// Decode the ten-byte fixed READ BINARY prefix and borrow exactly the
    /// number of bytes declared by its BE `len` field.
    ///
    /// # Errors
    /// Returns [`UiccFileDecodeError`] for a failed/wrong outer UICC response,
    /// a truncated subtype prefix, or an embedded data length mismatch.
    pub fn parse(packet: Packet<'a>) -> Result<Self, UiccFileDecodeError> {
        let response = successful_uicc_response(packet, uicc_control::READ_BINARY)?;
        if response.data.len() < 10 {
            return Err(UiccFileDecodeError::TruncatedData {
                minimum: 10,
                actual: response.data.len(),
            });
        }
        let declared = usize::from(be_u16(response.data, 8));
        let data = &response.data[10..];
        if declared != data.len() {
            return Err(UiccFileDecodeError::EmbeddedLengthMismatch {
                declared,
                actual: data.len(),
            });
        }
        Ok(Self {
            uicc_return: response.data[0],
            app_type: response.data[1],
            fid: be_u32(response.data, 2),
            sw1: response.data[6],
            sw2: response.data[7],
            data,
        })
    }
}

/// Borrowed successful READ RECORD response (`type 2`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UiccReadRecordResponse<'a> {
    pub uicc_return: u8,
    pub app_type: u8,
    pub fid: u32,
    pub sw1: u8,
    pub sw2: u8,
    pub record_index: u8,
    /// Total bytes returned in `data`, not `record_count * record_size`.
    pub length: u8,
    pub record_count: u8,
    pub data: &'a [u8],
}

impl<'a> UiccReadRecordResponse<'a> {
    /// Decode the eleven-byte READ RECORD prefix and borrow its payload.
    ///
    /// Live P4 `ind_uicc_from_device` exposes `len * record_num` bytes when
    /// `record_idx == 0` (the all-records form), and exactly `len` bytes for a
    /// specific record. The parser validates the same shape against the bytes
    /// actually carried by the modem response.
    ///
    /// # Errors
    /// Returns [`UiccFileDecodeError`] for a failed/wrong outer UICC response,
    /// a truncated subtype prefix, or an embedded data length mismatch.
    pub fn parse(packet: Packet<'a>) -> Result<Self, UiccFileDecodeError> {
        let response = successful_uicc_response(packet, uicc_control::READ_RECORD)?;
        if response.data.len() < 11 {
            return Err(UiccFileDecodeError::TruncatedData {
                minimum: 11,
                actual: response.data.len(),
            });
        }
        let record_len = usize::from(response.data[9]);
        let record_count = usize::from(response.data[10]);
        let expected = if response.data[8] == 0 {
            record_len.checked_mul(record_count).ok_or(
                UiccFileDecodeError::EmbeddedLengthMismatch {
                    declared: usize::MAX,
                    actual: response.data.len().saturating_sub(11),
                },
            )?
        } else {
            record_len
        };
        let data = &response.data[11..];
        if expected != data.len() {
            return Err(UiccFileDecodeError::EmbeddedLengthMismatch {
                declared: expected,
                actual: data.len(),
            });
        }
        Ok(Self {
            uicc_return: response.data[0],
            app_type: response.data[1],
            fid: be_u32(response.data, 2),
            sw1: response.data[6],
            sw2: response.data[7],
            record_index: response.data[8],
            length: response.data[9],
            record_count: response.data[10],
            data,
        })
    }
}

/// Error while encoding UICC authentication input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UiccAuthenticateEncodeError {
    FieldTooLong {
        field: UiccAuthenticateField,
        maximum: usize,
        actual: usize,
    },
    Hci(EncodeError),
}

impl From<EncodeError> for UiccAuthenticateEncodeError {
    fn from(value: EncodeError) -> Self {
        Self::Hci(value)
    }
}

/// Variable-length fields in the recovered authentication request/response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UiccAuthenticateField {
    Rand,
    Auth,
    Res,
    Ck,
    Ik,
    Auts,
    Sres,
    Kc,
}

/// UICC AUTHENTICATE request (`type 5`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UiccAuthenticateRequest<'a> {
    pub app_type: u8,
    pub rand: &'a [u8],
    pub auth: &'a [u8],
    pub gsm_auth_selection: u8,
}

impl UiccAuthenticateRequest<'_> {
    /// Encode the exact 36-byte subtype object copied raw by B014 and live P4.
    /// `rand` and `auth` occupy fixed 16-byte slots preceded by one-byte
    /// lengths; unused bytes are zero-filled.
    ///
    /// # Errors
    /// Returns [`UiccAuthenticateEncodeError::FieldTooLong`] when RAND or AUTH
    /// exceed the recovered 16-byte capacity, or the wrapped HCI error if the
    /// caller's output buffer is too short.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, UiccAuthenticateEncodeError> {
        if self.rand.len() > 16 {
            return Err(UiccAuthenticateEncodeError::FieldTooLong {
                field: UiccAuthenticateField::Rand,
                maximum: 16,
                actual: self.rand.len(),
            });
        }
        if self.auth.len() > 16 {
            return Err(UiccAuthenticateEncodeError::FieldTooLong {
                field: UiccAuthenticateField::Auth,
                maximum: 16,
                actual: self.auth.len(),
            });
        }

        let mut data = [0_u8; 36];
        data[0] = self.app_type;
        data[1] = u8::try_from(self.rand.len()).map_err(|_| {
            UiccAuthenticateEncodeError::FieldTooLong {
                field: UiccAuthenticateField::Rand,
                maximum: 16,
                actual: self.rand.len(),
            }
        })?;
        data[2..2 + self.rand.len()].copy_from_slice(self.rand);
        data[18] = u8::try_from(self.auth.len()).map_err(|_| {
            UiccAuthenticateEncodeError::FieldTooLong {
                field: UiccAuthenticateField::Auth,
                maximum: 16,
                actual: self.auth.len(),
            }
        })?;
        data[19..19 + self.auth.len()].copy_from_slice(self.auth);
        data[35] = self.gsm_auth_selection;
        Ok(encode_uicc_request(
            uicc_control::AUTHENTICATE,
            &data,
            output,
        )?)
    }
}

/// Error while decoding the fixed 86-byte UICC authentication result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UiccAuthenticateDecodeError {
    Typed(UiccTypedDecodeError),
    FieldTooLong {
        field: UiccAuthenticateField,
        maximum: usize,
        actual: usize,
    },
}

impl From<UiccTypedDecodeError> for UiccAuthenticateDecodeError {
    fn from(value: UiccTypedDecodeError) -> Self {
        Self::Typed(value)
    }
}

fn bounded_auth_field(
    data: &[u8],
    field: UiccAuthenticateField,
    length_offset: usize,
    data_offset: usize,
    maximum: usize,
) -> Result<&[u8], UiccAuthenticateDecodeError> {
    let actual = usize::from(data[length_offset]);
    if actual > maximum {
        return Err(UiccAuthenticateDecodeError::FieldTooLong {
            field,
            maximum,
            actual,
        });
    }
    Ok(&data[data_offset..data_offset + actual])
}

/// Borrowed successful UICC AUTHENTICATE response (`type 5`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UiccAuthenticateResponse<'a> {
    pub uicc_return: u8,
    pub app_type: u8,
    pub auth_return: u8,
    pub res: &'a [u8],
    pub ck: &'a [u8],
    pub ik: &'a [u8],
    pub auts: &'a [u8],
    pub sres: &'a [u8],
    pub kc: &'a [u8],
    pub gsm_auth_result: u8,
}

impl<'a> UiccAuthenticateResponse<'a> {
    /// Decode the raw 86-byte type-5 result while exposing only the declared
    /// bytes from each fixed-capacity authentication slot.
    ///
    /// # Errors
    /// Returns [`UiccAuthenticateDecodeError`] for outer UICC failure/wrong
    /// subtype/size or an embedded length larger than its recovered buffer.
    pub fn parse(packet: Packet<'a>) -> Result<Self, UiccAuthenticateDecodeError> {
        let data = successful_uicc_data(packet, uicc_control::AUTHENTICATE, 86)?;
        Ok(Self {
            uicc_return: data[0],
            app_type: data[1],
            auth_return: data[2],
            res: bounded_auth_field(data, UiccAuthenticateField::Res, 3, 4, 16)?,
            ck: bounded_auth_field(data, UiccAuthenticateField::Ck, 20, 21, 16)?,
            ik: bounded_auth_field(data, UiccAuthenticateField::Ik, 37, 38, 16)?,
            auts: bounded_auth_field(data, UiccAuthenticateField::Auts, 54, 55, 16)?,
            sres: bounded_auth_field(data, UiccAuthenticateField::Sres, 71, 72, 4)?,
            kc: bounded_auth_field(data, UiccAuthenticateField::Kc, 76, 77, 8)?,
            gsm_auth_result: data[85],
        })
    }
}

/// UICC-status request (`type 0`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UiccStatusRequest {
    pub app_type: u8,
}

impl UiccStatusRequest {
    /// Encode the one-byte status request proven by `lted` and live P4.
    ///
    /// # Errors
    /// Returns [`EncodeError::NoSpace`] when `output` is shorter than nine
    /// bytes.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, EncodeError> {
        encode_uicc_request(uicc_control::STATUS, &[self.app_type], output)
    }
}

/// Successful status response (`type 0`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UiccStatusResponse {
    pub uicc_status: u8,
    pub app_type: u8,
}

impl UiccStatusResponse {
    /// Decode a successful two-byte status response.
    ///
    /// # Errors
    /// Returns [`UiccTypedDecodeError`] for outer failure, another subtype or
    /// a status payload whose size differs from the recovered DWARF layout.
    pub fn parse(packet: Packet<'_>) -> Result<Self, UiccTypedDecodeError> {
        let data = successful_uicc_data(packet, uicc_control::STATUS, 2)?;
        Ok(Self {
            uicc_status: data[0],
            app_type: data[1],
        })
    }
}

/// UICC PIN-status request (`type 7`). The OEM always emits a zero-length
/// subtype payload.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UiccPinStatusRequest;

impl UiccPinStatusRequest {
    /// Encode the exact eight-byte HCI frame used by B014 and P4.
    ///
    /// # Errors
    /// Returns [`EncodeError::NoSpace`] when `output` is shorter than eight
    /// bytes.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, EncodeError> {
        encode_uicc_request(uicc_control::PIN_STATUS, &[], output)
    }
}

/// One three-byte PIN status triplet embedded in the type-7 response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PinStatus {
    pub status: u8,
    pub pin_retries: u8,
    pub puk_retries: u8,
}

const fn pin_status(bytes: &[u8], offset: usize) -> PinStatus {
    PinStatus {
        status: bytes[offset],
        pin_retries: bytes[offset + 1],
        puk_retries: bytes[offset + 2],
    }
}

/// Successful PIN-status response (`type 7`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UiccPinStatusResponse {
    pub uicc_return: u8,
    pub global_pin: u8,
    pub application: PinStatus,
    pub universal: PinStatus,
    pub local: PinStatus,
}

impl UiccPinStatusResponse {
    /// Decode the eleven-byte type-7 response described by B014 DWARF and
    /// copied raw by both SDK response parsers.
    ///
    /// # Errors
    /// Returns [`UiccTypedDecodeError`] for outer failure, another subtype or
    /// the wrong payload size.
    pub fn parse(packet: Packet<'_>) -> Result<Self, UiccTypedDecodeError> {
        let data = successful_uicc_data(packet, uicc_control::PIN_STATUS, 11)?;
        Ok(Self {
            uicc_return: data[0],
            global_pin: data[1],
            application: pin_status(data, 2),
            universal: pin_status(data, 5),
            local: pin_status(data, 8),
        })
    }
}

/// One PIN/PUK string in the type-6 command request. The recovered SDK stores
/// one length byte followed by an eight-byte fixed-capacity code buffer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PinData<'a> {
    pub code: &'a [u8],
}

/// Error while encoding a typed PIN command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UiccPinEncodeError {
    PinTooLong { maximum: usize, actual: usize },
    Hci(EncodeError),
}

impl From<EncodeError> for UiccPinEncodeError {
    fn from(value: EncodeError) -> Self {
        Self::Hci(value)
    }
}

fn encode_pin_data(pin: PinData<'_>, output: &mut [u8; 9]) -> Result<(), UiccPinEncodeError> {
    if pin.code.len() > 8 {
        return Err(UiccPinEncodeError::PinTooLong {
            maximum: 8,
            actual: pin.code.len(),
        });
    }
    output[0] = u8::try_from(pin.code.len()).map_err(|_| UiccPinEncodeError::PinTooLong {
        maximum: 8,
        actual: pin.code.len(),
    })?;
    output[1..=pin.code.len()].copy_from_slice(pin.code);
    Ok(())
}

/// UICC PIN command (`type 6`). `pin_type` and `pin_command` are intentionally
/// kept as recovered wire values: the available DWARF names the fields but
/// does not provide a trustworthy enum for their value domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UiccPinCommandRequest<'a> {
    pub pin_type: u8,
    pub pin_command: u8,
    pub old_pin: PinData<'a>,
    pub new_pin: PinData<'a>,
}

impl UiccPinCommandRequest<'_> {
    /// Encode the exact twenty-byte type-6 payload copied by the live SDK.
    ///
    /// # Errors
    /// Returns [`UiccPinEncodeError::PinTooLong`] for a PIN/PUK longer than
    /// eight bytes or [`UiccPinEncodeError::Hci`] if the output buffer is too
    /// short.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, UiccPinEncodeError> {
        let mut data = [0_u8; 20];
        data[0] = self.pin_type;
        data[1] = self.pin_command;
        let mut old = [0_u8; 9];
        let mut new = [0_u8; 9];
        encode_pin_data(self.old_pin, &mut old)?;
        encode_pin_data(self.new_pin, &mut new)?;
        data[2..11].copy_from_slice(&old);
        data[11..20].copy_from_slice(&new);
        Ok(encode_uicc_request(
            uicc_control::PIN_COMMAND,
            &data,
            output,
        )?)
    }
}

/// Successful five-byte response to UICC PIN command (`type 6`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UiccPinCommandResponse {
    pub uicc_return: u8,
    pub pin_type: u8,
    pub pin_command: u8,
    pub pin_retries: u8,
    pub puk_retries: u8,
}

impl UiccPinCommandResponse {
    /// Decode the raw five-byte type-6 response copied by the OEM parser.
    ///
    /// # Errors
    /// Returns [`UiccTypedDecodeError`] for outer failure, another subtype or
    /// the wrong payload size.
    pub fn parse(packet: Packet<'_>) -> Result<Self, UiccTypedDecodeError> {
        let data = successful_uicc_data(packet, uicc_control::PIN_COMMAND, 5)?;
        Ok(Self {
            uicc_return: data[0],
            pin_type: data[1],
            pin_command: data[2],
            pin_retries: data[3],
            puk_retries: data[4],
        })
    }
}
