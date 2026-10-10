//! Pure translation of recovered stock `liblted.so` request-memory images
//! into typed modem requests.
//!
//! This module deliberately has no client sockets, shared-memory completion,
//! modem transport, or daemon state. It is the compatibility boundary for
//! validating and decoding historical local ABI shapes.

use gct_lapi::{
    ApnType, AttachExtProfile, AttachExtRequest, AttachRequest, PcoInfo, PdnConnectExtRequest,
    PdnConnectRequest, PdnConnectionControl, PdnDisconnectRequest, Positioning,
    RrcCapabilityGetRequest, RrcCapabilitySetRequest, SetProtocolInfoRequest, UiccFixedRequest,
    UiccPinStatusRequest, UiccReadBinaryRequest, UiccReadRecordRequest, UiccStatusRequest,
    uicc_control,
};

pub const LEGACY_ATTACH_PARAMS_LEN: usize = 0x160;
use gct_lapi::{
    AttachExtResponse, AttachResponse, AttachTailDecodeError, AttachTailField,
    EmergencyNumberDecodeError, PdnConnectExtResponse, PdnConnectResponse,
    PdnConnectTailDecodeError, PdnConnectTailField, PdnDisconnectField,
    PdnDisconnectFieldDecodeError, PdnDisconnectResponse, PdnInfoContainers, PdnInfoField,
    PdnInfoFieldLengthError, QosField,
};

pub const LEGACY_ATTACH_EXT_PARAMS_LEN: usize = 0x1e4;
pub const LEGACY_PDN_CONNECT_PARAMS_LEN: usize = 0x1a4;
pub const LEGACY_PDN_CONNECT_EXT_PARAMS_LEN: usize = 0x0f4;
pub const LEGACY_PDN_DISCONNECT_FIXED_LEN: usize = 4;
pub const LEGACY_PDN_DISCONNECT_MAX_LEN: usize = 0x44;

/// RRC-capability type IDs exercised by the shipped P4 `lteautocm` binary.
///
/// The live SDK contains a much broader switch, but the replacement deliberately
/// exposes only product-demanded shapes until another callsite is independently
/// proven.
const fn is_shipped_rrc_capability_type(type_id: u16) -> bool {
    matches!(type_id, 1 | 2 | 3 | 4 | 11 | 18 | 20)
}

/// Successful set responses for types 11 and 20 are intentionally rejected by
/// the live SDK response converter; failures still reach callback slot 115.
pub(crate) const fn rrc_capability_set_success_has_callback(type_id: u16) -> bool {
    matches!(type_id, 1 | 2 | 3 | 4 | 18)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacySetProtocolInfoDecodeError {
    Truncated { minimum: usize, actual: usize },
    UnexpectedLength { expected: usize, actual: usize },
    UnsupportedType(u16),
}

/// Decode the shipped, side-effect-free subset of live SDK command 177.
///
/// Live P4 has three shipped callers: type 1 (four data bytes), type 8 (one
/// byte), and type 9. Type 9 is deliberately rejected here because stock
/// `liblted.so` performs substantial filesystem/configuration side effects and
/// rewrites it into modem type 2; reproducing only its final HCI write would be
/// false compatibility.
///
/// # Errors
/// Rejects a short selector, a wrong type-specific object length, or a type not
/// in the proven side-effect-free shipped subset.
pub fn decode_legacy_set_protocol_info(
    params: &[u8],
) -> Result<SetProtocolInfoRequest<'_>, LegacySetProtocolInfoDecodeError> {
    if params.len() < 2 {
        return Err(LegacySetProtocolInfoDecodeError::Truncated {
            minimum: 2,
            actual: params.len(),
        });
    }
    let type_id = u16::from_be_bytes([params[0], params[1]]);
    let expected = match type_id {
        1 => 6,
        8 => 3,
        _ => return Err(LegacySetProtocolInfoDecodeError::UnsupportedType(type_id)),
    };
    if params.len() != expected {
        return Err(LegacySetProtocolInfoDecodeError::UnexpectedLength {
            expected,
            actual: params.len(),
        });
    }
    Ok(SetProtocolInfoRequest {
        type_id,
        data: &params[2..],
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacyRrcCapabilityDecodeError {
    Truncated {
        minimum: usize,
        actual: usize,
    },
    UnexpectedLength {
        expected: usize,
        actual: usize,
    },
    LengthMismatch {
        declared: usize,
        actual: usize,
    },
    UnsupportedType(u16),
    Type4ListTruncated {
        count: u8,
        minimum_data_len: usize,
        actual_data_len: usize,
    },
}

fn validate_rrc_type4_list(data: &[u8]) -> Result<(), LegacyRrcCapabilityDecodeError> {
    let Some(&count) = data.first() else {
        return Err(LegacyRrcCapabilityDecodeError::Type4ListTruncated {
            count: 0,
            minimum_data_len: 1,
            actual_data_len: 0,
        });
    };
    let minimum_data_len = 1_usize.saturating_add(usize::from(count).saturating_mul(2));
    if data.len() < minimum_data_len {
        return Err(LegacyRrcCapabilityDecodeError::Type4ListTruncated {
            count,
            minimum_data_len,
            actual_data_len: data.len(),
        });
    }
    Ok(())
}

/// Decode stock SDK command 220's variable local object.
///
/// Although B014 DWARF describes a five-byte flexible C struct, live
/// `LTED_RRCCapabilityControlRequest` forwards exactly `4 + len` bytes, so a
/// zero-length object is four bytes on the UNIX datagram boundary.
///
/// # Errors
/// Rejects a malformed flexible envelope, an unshipped type ID, or an unsafe
/// type-4 count/list shape before GLIF is touched.
pub fn decode_legacy_rrc_capability_set(
    params: &[u8],
) -> Result<RrcCapabilitySetRequest<'_>, LegacyRrcCapabilityDecodeError> {
    if params.len() < 4 {
        return Err(LegacyRrcCapabilityDecodeError::Truncated {
            minimum: 4,
            actual: params.len(),
        });
    }
    let type_id = u16::from_be_bytes([params[0], params[1]]);
    if !is_shipped_rrc_capability_type(type_id) {
        return Err(LegacyRrcCapabilityDecodeError::UnsupportedType(type_id));
    }
    let declared = usize::from(u16::from_be_bytes([params[2], params[3]]));
    let data = &params[4..];
    if data.len() != declared {
        return Err(LegacyRrcCapabilityDecodeError::LengthMismatch {
            declared,
            actual: data.len(),
        });
    }
    if type_id == 4 {
        validate_rrc_type4_list(data)?;
    }
    Ok(RrcCapabilitySetRequest { type_id, data })
}

/// Decode stock SDK command 222's exact five-byte historical get object.
///
/// Live `LAPI_RRCCapabilityControlGetRequest` consumes only the leading
/// `type:u16`; the historical `len:u16 + data[1]` tail remains local ABI noise.
///
/// # Errors
/// Rejects any non-five-byte object or a type not exercised by shipped
/// `lteautocm`.
pub fn decode_legacy_rrc_capability_get(
    params: &[u8],
) -> Result<RrcCapabilityGetRequest, LegacyRrcCapabilityDecodeError> {
    if params.len() != 5 {
        return Err(LegacyRrcCapabilityDecodeError::UnexpectedLength {
            expected: 5,
            actual: params.len(),
        });
    }
    let type_id = u16::from_be_bytes([params[0], params[1]]);
    if !is_shipped_rrc_capability_type(type_id) {
        return Err(LegacyRrcCapabilityDecodeError::UnsupportedType(type_id));
    }
    Ok(RrcCapabilityGetRequest { type_id })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacyAttachStringField {
    Apn,
    Username,
    Password,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacyAttachDecodeError {
    UnexpectedLength { expected: usize, actual: usize },
    MissingTerminator(LegacyAttachStringField),
    OperatorPcoTooLong { maximum: usize, actual: usize },
}

fn legacy_c_string(
    bytes: &[u8],
    field: LegacyAttachStringField,
) -> Result<&[u8], LegacyAttachDecodeError> {
    let Some(end) = bytes.iter().position(|&byte| byte == 0) else {
        return Err(LegacyAttachDecodeError::MissingTerminator(field));
    };
    Ok(&bytes[..end])
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacyAttachExtStringField {
    PrimaryApn,
    PrimaryUsername,
    PrimaryPassword,
    RetryApn,
    RetryUsername,
    RetryPassword,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacyAttachExtDecodeError {
    UnexpectedLength { expected: usize, actual: usize },
    MissingTerminator(LegacyAttachExtStringField),
}

fn legacy_attach_ext_c_string(
    bytes: &[u8],
    field: LegacyAttachExtStringField,
) -> Result<&[u8], LegacyAttachExtDecodeError> {
    let Some(end) = bytes.iter().position(|&byte| byte == 0) else {
        return Err(LegacyAttachExtDecodeError::MissingTerminator(field));
    };
    Ok(&bytes[..end])
}

const fn legacy_pco_info(bytes: &[u8], offset: usize) -> PcoInfo {
    PcoInfo {
        first_pco: bytes[offset],
        second_pco: bytes[offset + 1],
        n_pco: bytes[offset + 2],
        first_os_pco: u16::from_be_bytes([bytes[offset + 3], bytes[offset + 4]]),
        second_os_pco: u16::from_be_bytes([bytes[offset + 5], bytes[offset + 6]]),
        third_os_pco: u16::from_be_bytes([bytes[offset + 7], bytes[offset + 8]]),
    }
}

const fn empty_attach_ext_profile() -> AttachExtProfile<'static> {
    AttachExtProfile {
        ip_alloc: 0,
        apn_class: 0,
        apn: &[],
        pdn_type: 0,
        username: &[],
        password: &[],
        auth_flag: 0,
        pco: PcoInfo {
            first_pco: 0,
            second_pco: 0,
            n_pco: 0,
            first_os_pco: 0,
            second_os_pco: 0,
            third_os_pco: 0,
        },
    }
}

/// Decode the exact 484-byte stock `_ATTACH_REQ_EXT_PARAM`.
///
/// Live P4 `LTED_AttachRequestEXT` copies the entire object into command 27.
/// `req_apn_type@483` is SDK-local bookkeeping only and is intentionally not
/// represented in the clean modem request. When `optional_info == 0`, the live
/// encoder does not inspect either profile, so dead fixed-string storage is not
/// validated here either.
///
/// # Errors
/// Returns [`LegacyAttachExtDecodeError`] for a wrong object size or an
/// unterminated fixed C string that would be serialized.
pub fn decode_legacy_attach_ext(
    params: &[u8],
) -> Result<AttachExtRequest<'_>, LegacyAttachExtDecodeError> {
    if params.len() != LEGACY_ATTACH_EXT_PARAMS_LEN {
        return Err(LegacyAttachExtDecodeError::UnexpectedLength {
            expected: LEGACY_ATTACH_EXT_PARAMS_LEN,
            actual: params.len(),
        });
    }
    let optional_info = params[0];
    if optional_info == 0 {
        let empty = empty_attach_ext_profile();
        return Ok(AttachExtRequest {
            optional_info,
            primary: empty,
            retry: empty,
        });
    }

    let primary = AttachExtProfile {
        ip_alloc: params[1],
        apn_class: params[2],
        apn: legacy_attach_ext_c_string(&params[3..103], LegacyAttachExtStringField::PrimaryApn)?,
        pdn_type: params[103],
        username: legacy_attach_ext_c_string(
            &params[104..168],
            LegacyAttachExtStringField::PrimaryUsername,
        )?,
        password: legacy_attach_ext_c_string(
            &params[168..232],
            LegacyAttachExtStringField::PrimaryPassword,
        )?,
        auth_flag: params[232],
        pco: legacy_pco_info(params, 233),
    };
    let retry = AttachExtProfile {
        ip_alloc: params[242],
        apn_class: params[243],
        apn: legacy_attach_ext_c_string(&params[244..344], LegacyAttachExtStringField::RetryApn)?,
        pdn_type: params[344],
        username: legacy_attach_ext_c_string(
            &params[345..409],
            LegacyAttachExtStringField::RetryUsername,
        )?,
        password: legacy_attach_ext_c_string(
            &params[409..473],
            LegacyAttachExtStringField::RetryPassword,
        )?,
        auth_flag: params[473],
        pco: legacy_pco_info(params, 474),
    };
    Ok(AttachExtRequest {
        optional_info,
        primary,
        retry,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacyPdnConnectExtStringField {
    Apn,
    Username,
    Password,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacyPdnConnectExtDecodeError {
    UnexpectedLength { expected: usize, actual: usize },
    MissingTerminator(LegacyPdnConnectExtStringField),
}

fn legacy_pdn_ext_c_string(
    bytes: &[u8],
    field: LegacyPdnConnectExtStringField,
) -> Result<&[u8], LegacyPdnConnectExtDecodeError> {
    let Some(end) = bytes.iter().position(|&byte| byte == 0) else {
        return Err(LegacyPdnConnectExtDecodeError::MissingTerminator(field));
    };
    Ok(&bytes[..end])
}

/// Decode the exact 244-byte stock `_PDN_CONNECTIVITY_REQ_EXT_PARAM`.
///
/// Live P4 `LTED_PDNConnRequestEXT` copies all 244 bytes into SDK command 34.
/// The modem encoder always serializes APN, while username/password and the
/// remaining optional fields are read only when `optional_info != 0`.
/// `req_apn_type@243` is SDK-local bookkeeping and is intentionally absent
/// from the clean modem request.
///
/// # Errors
/// Returns [`LegacyPdnConnectExtDecodeError`] for a wrong object size or an
/// unterminated fixed C string that would be serialized.
pub fn decode_legacy_pdn_connect_ext(
    params: &[u8],
) -> Result<PdnConnectExtRequest<'_>, LegacyPdnConnectExtDecodeError> {
    if params.len() != LEGACY_PDN_CONNECT_EXT_PARAMS_LEN {
        return Err(LegacyPdnConnectExtDecodeError::UnexpectedLength {
            expected: LEGACY_PDN_CONNECT_EXT_PARAMS_LEN,
            actual: params.len(),
        });
    }

    let apn = legacy_pdn_ext_c_string(&params[0x002..0x066], LegacyPdnConnectExtStringField::Apn)?;
    let optional_info = params[0x001];
    let (username, password) = if optional_info == 0 {
        (&[][..], &[][..])
    } else {
        (
            legacy_pdn_ext_c_string(
                &params[0x069..0x0a9],
                LegacyPdnConnectExtStringField::Username,
            )?,
            legacy_pdn_ext_c_string(
                &params[0x0a9..0x0e9],
                LegacyPdnConnectExtStringField::Password,
            )?,
        )
    };

    Ok(PdnConnectExtRequest {
        request_type: params[0x000],
        optional_info,
        apn,
        ip_alloc: params[0x066],
        apn_class: params[0x067],
        pdn_type: params[0x068],
        username,
        password,
        auth_flag: params[0x0e9],
        pco: legacy_pco_info(params, 0x0ea),
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacyUiccRequest<'a> {
    Status(UiccStatusRequest),
    ReadBinary(UiccReadBinaryRequest),
    ReadRecord(UiccReadRecordRequest),
    Fixed(UiccFixedRequest<'a>),
    PinStatus(UiccPinStatusRequest),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacyUiccDecodeError {
    TruncatedEnvelope {
        minimum: usize,
        actual: usize,
    },
    LengthMismatch {
        declared: usize,
        actual: usize,
    },
    UnexpectedSubtypeLength {
        kind: u16,
        expected: usize,
        actual: usize,
    },
    UnsupportedKind(u16),
}

fn exact_uicc_subtype_len(
    kind: u16,
    data: &[u8],
    expected: usize,
) -> Result<(), LegacyUiccDecodeError> {
    if data.len() != expected {
        return Err(LegacyUiccDecodeError::UnexpectedSubtypeLength {
            kind,
            expected,
            actual: data.len(),
        });
    }
    Ok(())
}

/// Decode the exact variable local payload produced by stock SDK command 147.
///
/// The stock wrapper copies `type:u16 | len:u16 | data[len]`. Known unsafe C
/// shapes are accepted only at their proven widths. PIN STATUS intentionally
/// ignores any declared local data because live `LAPI_UICCRequest` forcibly
/// sends that subtype with zero modem data length.
///
/// # Errors
/// Returns [`LegacyUiccDecodeError`] for a truncated/inconsistent envelope, a
/// malformed supported subtype or an as-yet unsupported UICC kind.
pub fn decode_legacy_uicc(params: &[u8]) -> Result<LegacyUiccRequest<'_>, LegacyUiccDecodeError> {
    if params.len() < 4 {
        return Err(LegacyUiccDecodeError::TruncatedEnvelope {
            minimum: 4,
            actual: params.len(),
        });
    }
    let kind = u16::from_be_bytes([params[0], params[1]]);
    let declared = usize::from(u16::from_be_bytes([params[2], params[3]]));
    let data = &params[4..];
    if declared != data.len() {
        return Err(LegacyUiccDecodeError::LengthMismatch {
            declared,
            actual: data.len(),
        });
    }

    match kind {
        uicc_control::STATUS => {
            exact_uicc_subtype_len(kind, data, 1)?;
            Ok(LegacyUiccRequest::Status(UiccStatusRequest {
                app_type: data[0],
            }))
        }
        uicc_control::READ_BINARY => {
            exact_uicc_subtype_len(kind, data, 9)?;
            Ok(LegacyUiccRequest::ReadBinary(UiccReadBinaryRequest {
                app_type: data[0],
                fid: u32::from_be_bytes([data[1], data[2], data[3], data[4]]),
                offset: u16::from_be_bytes([data[5], data[6]]),
                length: u16::from_be_bytes([data[7], data[8]]),
            }))
        }
        uicc_control::READ_RECORD => {
            exact_uicc_subtype_len(kind, data, 6)?;
            Ok(LegacyUiccRequest::ReadRecord(UiccReadRecordRequest {
                app_type: data[0],
                fid: u32::from_be_bytes([data[1], data[2], data[3], data[4]]),
                record_index: data[5],
            }))
        }
        uicc_control::AUTHENTICATE => {
            exact_uicc_subtype_len(kind, data, 36)?;
            let request = UiccFixedRequest::authenticate(data).map_err(|_| {
                LegacyUiccDecodeError::UnexpectedSubtypeLength {
                    kind,
                    expected: 36,
                    actual: data.len(),
                }
            })?;
            Ok(LegacyUiccRequest::Fixed(request))
        }
        uicc_control::PIN_COMMAND => {
            exact_uicc_subtype_len(kind, data, 20)?;
            let request = UiccFixedRequest::pin_command(data).map_err(|_| {
                LegacyUiccDecodeError::UnexpectedSubtypeLength {
                    kind,
                    expected: 20,
                    actual: data.len(),
                }
            })?;
            Ok(LegacyUiccRequest::Fixed(request))
        }
        uicc_control::PIN_STATUS => Ok(LegacyUiccRequest::PinStatus(UiccPinStatusRequest)),
        _ => Err(LegacyUiccDecodeError::UnsupportedKind(kind)),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacyPdnConnectStringField {
    Apn,
    Username,
    Password,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacyPdnConnectDecodeError {
    UnexpectedLength { expected: usize, actual: usize },
    MissingTerminator(LegacyPdnConnectStringField),
    OperatorPcoTooLong { maximum: usize, actual: usize },
}

fn legacy_pdn_c_string(
    bytes: &[u8],
    field: LegacyPdnConnectStringField,
) -> Result<&[u8], LegacyPdnConnectDecodeError> {
    let Some(end) = bytes.iter().position(|&byte| byte == 0) else {
        return Err(LegacyPdnConnectDecodeError::MissingTerminator(field));
    };
    Ok(&bytes[..end])
}

const fn legacy_apn_type(value: u8) -> ApnType {
    match value {
        0 => ApnType::Internet,
        1 => ApnType::Ims,
        2 => ApnType::Admin,
        3 => ApnType::App,
        4 => ApnType::Emergency,
        5 => ApnType::Reserved1,
        6 => ApnType::Reserved2,
        7 => ApnType::Reserved3,
        _ => ApnType::NotSet,
    }
}

/// Decode the exact 352-byte stock `_ATTACH_REQ_PARAM` into the clean request.
///
/// The offsets come from B014 DWARF and the fields consumed by live P4
/// `LAPI_AttachRequest` were independently checked in disassembly. Fixed C
/// strings are bounded here instead of reproducing the OEM `strlen` over-read
/// hazard. For non-minimal requests, live `LAPI_AttachRequest` ignores the
/// historical transaction byte at `0x001`, allocates a first-free TID, and
/// overwrites that byte before encoding; the bridge applies that allocation
/// after this structural decode. When `optional_info == 0`, the modem wire
/// request contains only that byte and no TID is allocated, so dead legacy
/// fields are deliberately not validated.
///
/// # Errors
/// Returns [`LegacyAttachDecodeError`] for a wrong legacy structure size,
/// unterminated fixed string, or operator PCO length beyond its 100-byte slot.
pub fn decode_legacy_attach(params: &[u8]) -> Result<AttachRequest<'_>, LegacyAttachDecodeError> {
    if params.len() != LEGACY_ATTACH_PARAMS_LEN {
        return Err(LegacyAttachDecodeError::UnexpectedLength {
            expected: LEGACY_ATTACH_PARAMS_LEN,
            actual: params.len(),
        });
    }

    let optional_info = params[0];
    if optional_info == 0 {
        return Ok(AttachRequest {
            optional_info,
            transaction_id: 0,
            apn: &[],
            pdn_type: 0,
            ip_alloc: 0,
            username: &[],
            password: &[],
            auth_flag: 0,
            general_pco: None,
            operator_pco: None,
            req_apn_type: ApnType::NotSet,
            attach_type: 0,
            request_type: 0,
            emergency_mode: 0,
            positioning: Positioning {
                lpp: false,
                lcs: false,
            },
            nas_sig_low_priority_ind: 0,
            pdn_control: PdnConnectionControl {
                max_conn: 0,
                max_conn_t: 0,
                wait_time: 0,
            },
            secure_pco: 0,
        });
    }

    let apn = legacy_c_string(&params[0x002..0x066], LegacyAttachStringField::Apn)?;
    let username = legacy_c_string(&params[0x068..0x0a8], LegacyAttachStringField::Username)?;
    let password = legacy_c_string(&params[0x0a8..0x0e8], LegacyAttachStringField::Password)?;
    let general_pco =
        (params[0x0e9] != 0).then(|| u16::from_be_bytes([params[0x0ea], params[0x0eb]]));
    let operator_pco = if params[0x0ec] == 0 {
        None
    } else {
        let len = usize::from(params[0x0ed]);
        if len > 100 {
            return Err(LegacyAttachDecodeError::OperatorPcoTooLong {
                maximum: 100,
                actual: len,
            });
        }
        Some(&params[0x0ee..0x0ee + len])
    };

    Ok(AttachRequest {
        optional_info,
        transaction_id: params[0x001],
        apn,
        pdn_type: params[0x066],
        ip_alloc: params[0x067],
        username,
        password,
        auth_flag: params[0x0e8],
        general_pco,
        operator_pco,
        req_apn_type: legacy_apn_type(params[0x152]),
        attach_type: params[0x153],
        request_type: params[0x154],
        emergency_mode: params[0x155],
        positioning: Positioning {
            lpp: params[0x156] == 1,
            lcs: params[0x157] == 1,
        },
        nas_sig_low_priority_ind: params[0x158],
        pdn_control: PdnConnectionControl {
            max_conn: u16::from_be_bytes([params[0x159], params[0x15a]]),
            max_conn_t: u16::from_be_bytes([params[0x15b], params[0x15c]]),
            wait_time: u16::from_be_bytes([params[0x15d], params[0x15e]]),
        },
        secure_pco: params[0x15f],
    })
}

/// Decode the exact 420-byte stock `_PDN_CONNECTIVITY_REQ_PARAM`.
///
/// Live P4 `LAPI_PDNConnRequest` does not trust the structure's historical
/// `transaction_id@0x1a3`: it allocates the first free transaction ID from
/// `1..=253` with `tid_list_add()` and writes that value back into its local
/// structure before encoding. The caller therefore supplies the already
/// allocated ID explicitly here.
///
/// `apn_name` is always consumed, even when `optional_info == 0`; username,
/// password, PCO and connection-control fields are dead in that minimal shape
/// and are deliberately not validated.
///
/// # Errors
/// Returns [`LegacyPdnConnectDecodeError`] for a wrong structure size,
/// unterminated consumed C string, or operator PCO length beyond its 100-byte
/// recovered destination.
pub fn decode_legacy_pdn_connect(
    params: &[u8],
    transaction_id: u8,
) -> Result<PdnConnectRequest<'_>, LegacyPdnConnectDecodeError> {
    if params.len() != LEGACY_PDN_CONNECT_PARAMS_LEN {
        return Err(LegacyPdnConnectDecodeError::UnexpectedLength {
            expected: LEGACY_PDN_CONNECT_PARAMS_LEN,
            actual: params.len(),
        });
    }

    let optional_info = params[0x001];
    let apn = legacy_pdn_c_string(&params[0x002..0x066], LegacyPdnConnectStringField::Apn)?;

    let mut request = PdnConnectRequest {
        request_type: params[0x000],
        optional_info,
        transaction_id,
        apn,
        pdn_type: 0,
        ip_alloc: 0,
        username: &[],
        password: &[],
        auth_flag: 0,
        general_pco: None,
        operator_pco: None,
        req_apn_type: legacy_apn_type(params[0x19a]),
        nas_sig_low_priority_ind: 0,
        pdn_control: PdnConnectionControl {
            max_conn: 0,
            max_conn_t: 0,
            wait_time: 0,
        },
        secure_pco: 0,
    };

    if optional_info == 0 {
        return Ok(request);
    }

    request.pdn_type = params[0x066];
    request.ip_alloc = params[0x067];
    request.username =
        legacy_pdn_c_string(&params[0x068..0x0cc], LegacyPdnConnectStringField::Username)?;
    request.password =
        legacy_pdn_c_string(&params[0x0cc..0x130], LegacyPdnConnectStringField::Password)?;
    request.auth_flag = params[0x130];
    request.general_pco =
        (params[0x131] != 0).then(|| u16::from_be_bytes([params[0x132], params[0x133]]));
    request.operator_pco = if params[0x134] == 0 {
        None
    } else {
        let len = usize::from(params[0x135]);
        if len > 100 {
            return Err(LegacyPdnConnectDecodeError::OperatorPcoTooLong {
                maximum: 100,
                actual: len,
            });
        }
        Some(&params[0x136..0x136 + len])
    };
    request.nas_sig_low_priority_ind = params[0x19b];
    request.pdn_control = PdnConnectionControl {
        max_conn: u16::from_be_bytes([params[0x19c], params[0x19d]]),
        max_conn_t: u16::from_be_bytes([params[0x19e], params[0x19f]]),
        wait_time: u16::from_be_bytes([params[0x1a0], params[0x1a1]]),
    };
    request.secure_pco = params[0x1a2];
    Ok(request)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacyPdnDisconnectDecodeError {
    Truncated { minimum: usize, actual: usize },
    LengthMismatch { expected: usize, actual: usize },
    ApnTooLong { maximum: usize, actual: usize },
}

/// Decode the stock socket representation of `_PDN_DISCONNECT_REQ_PARAM`.
///
/// B014 DWARF fixes the in-process C structure at 68 bytes, but live P4
/// `LTED_PDNDisconnRequest` deliberately sends only the used prefix:
/// `default_eps_id@0`, historical transaction byte at 2, `apn_ni.len@3`, then
/// exactly `apn_ni.len` bytes from offset 4. The bridge therefore requires the
/// stock socket payload to be exactly `4 + apn_len`, not 68 bytes.
///
/// `LAPI_PDNDisconnRequest` then calls
/// `tid_list_add(0x3107, 0xff, default_eps_id, 0)` and overwrites byte 2 with
/// the allocated transaction ID before encoding. The historical socket byte is
/// ignored here and the caller supplies the fresh ID.
///
/// # Errors
/// Returns [`LegacyPdnDisconnectDecodeError`] for a truncated/inconsistent
/// variable stock payload or an APN beyond the recovered 64-byte destination.
pub fn decode_legacy_pdn_disconnect(
    params: &[u8],
    transaction_id: u8,
) -> Result<PdnDisconnectRequest<'_>, LegacyPdnDisconnectDecodeError> {
    if params.len() < LEGACY_PDN_DISCONNECT_FIXED_LEN {
        return Err(LegacyPdnDisconnectDecodeError::Truncated {
            minimum: LEGACY_PDN_DISCONNECT_FIXED_LEN,
            actual: params.len(),
        });
    }
    let apn_len = usize::from(params[0x003]);
    if apn_len > LEGACY_PDN_DISCONNECT_MAX_LEN - LEGACY_PDN_DISCONNECT_FIXED_LEN {
        return Err(LegacyPdnDisconnectDecodeError::ApnTooLong {
            maximum: LEGACY_PDN_DISCONNECT_MAX_LEN - LEGACY_PDN_DISCONNECT_FIXED_LEN,
            actual: apn_len,
        });
    }
    let expected = LEGACY_PDN_DISCONNECT_FIXED_LEN + apn_len;
    if params.len() != expected {
        return Err(LegacyPdnDisconnectDecodeError::LengthMismatch {
            expected,
            actual: params.len(),
        });
    }
    Ok(PdnDisconnectRequest {
        default_eps_id: u16::from_be_bytes([params[0x000], params[0x001]]),
        transaction_id,
        apn_ni: &params[0x004..],
    })
}

// Stock callback data-image materialization.
pub(crate) const STOCK_ATTACH_CALLBACK_DATA_LEN: usize = 0x88b;
pub(crate) const STOCK_ATTACH_CALLBACK_FRAME_LEN: usize = 12 + STOCK_ATTACH_CALLBACK_DATA_LEN;
const ATTACH_PDN_OFFSET: usize = 0x04b;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachCallbackError {
    PdnContainerTlv,
    PdnInnerTlv,
    PdnField(PdnInfoFieldLengthError),
    Tail(AttachTailDecodeError),
    Emergency(EmergencyNumberDecodeError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PdnInfoMaterializeError {
    ContainerTlv,
    InnerTlv,
    Field(PdnInfoFieldLengthError),
}

fn materialize_pdn_info_field(data: &mut [u8], base: usize, field: PdnInfoField<'_>) -> bool {
    match field {
        PdnInfoField::AccessPointName(value) => {
            data[base..base + value.len()].copy_from_slice(value);
        }
        PdnInfoField::PdnType(value) => data[base + 0x080] = value,
        PdnInfoField::PdnTypeCause(value) => {
            data[base + 0x081..base + 0x085].copy_from_slice(&value.to_be_bytes());
        }
        PdnInfoField::Ipv4Address(value) => {
            data[base + 0x085..base + 0x089].copy_from_slice(&value);
        }
        PdnInfoField::Ipv4DnsPrimary(value) => {
            data[base + 0x089..base + 0x08d].copy_from_slice(&value);
        }
        PdnInfoField::Ipv4DnsSecondary(value) => {
            data[base + 0x08d..base + 0x091].copy_from_slice(&value);
        }
        PdnInfoField::Ipv6DnsPrimary(value) => {
            data[base + 0x091..base + 0x0a1].copy_from_slice(&value);
        }
        PdnInfoField::Ipv6DnsSecondary(value) => {
            data[base + 0x0a1..base + 0x0b1].copy_from_slice(&value);
        }
        PdnInfoField::Ipv6InterfaceId(value) => {
            data[base + 0x0b1..base + 0x0b9].copy_from_slice(&value);
        }
        PdnInfoField::PcscfIpv6 { index, address } => {
            let offset = base + 0x0b9 + usize::from(index - 1) * 16;
            data[offset..offset + 16].copy_from_slice(&address);
        }
        PdnInfoField::PcscfIpv4 { index, address } => {
            let offset = base + 0x109 + usize::from(index - 1) * 4;
            data[offset..offset + 4].copy_from_slice(&address);
        }
        PdnInfoField::Qos { field, value } => {
            let word = match field {
                QosField::Qci => 0,
                QosField::MaxBitRateUl => 1,
                QosField::MaxBitRateDl => 2,
                QosField::GuaranteedBitRateUl => 3,
                QosField::GuaranteedBitRateDl => 4,
            };
            let offset = base + 0x216 + word * 4;
            data[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
        }
        PdnInfoField::Unknown(_) => return false,
    }
    true
}

fn materialize_pdn_containers(
    mut containers: PdnInfoContainers<'_>,
    data: &mut [u8],
    base: usize,
) -> Result<(), PdnInfoMaterializeError> {
    let mut stop_after_unknown = false;
    while let Some(container) = containers
        .next_container()
        .map_err(|_| PdnInfoMaterializeError::ContainerTlv)?
    {
        if stop_after_unknown {
            break;
        }
        let mut fields = container.fields();
        while let Some(tlv) = fields
            .next_tlv()
            .map_err(|_| PdnInfoMaterializeError::InnerTlv)?
        {
            let field = PdnInfoField::parse(tlv).map_err(PdnInfoMaterializeError::Field)?;
            if !materialize_pdn_info_field(data, base, field) {
                stop_after_unknown = true;
                break;
            }
        }
    }
    Ok(())
}

fn materialize_attach_pdn(
    response: AttachResponse<'_>,
    data: &mut [u8; STOCK_ATTACH_CALLBACK_DATA_LEN],
) -> Result<(), AttachCallbackError> {
    materialize_pdn_containers(response.pdn_info_containers(), data, ATTACH_PDN_OFFSET).map_err(
        |error| match error {
            PdnInfoMaterializeError::ContainerTlv => AttachCallbackError::PdnContainerTlv,
            PdnInfoMaterializeError::InnerTlv => AttachCallbackError::PdnInnerTlv,
            PdnInfoMaterializeError::Field(error) => AttachCallbackError::PdnField(error),
        },
    )
}

pub(crate) fn materialize_attach_callback(
    response: AttachResponse<'_>,
    data: &mut [u8; STOCK_ATTACH_CALLBACK_DATA_LEN],
) -> Result<(), AttachCallbackError> {
    data.fill(0);
    data[0x000..0x002].copy_from_slice(&response.register_result1.to_be_bytes());
    data[0x002..0x004].copy_from_slice(&response.register_result2.to_be_bytes());
    data[0x004..0x006].copy_from_slice(&response.default_eps_id.to_be_bytes());
    data[0x006..0x008].copy_from_slice(&response.eps_id.to_be_bytes());
    data[0x008] = response.data_path;
    data[0x009] = response.ip_alloc;
    data[0x00a] = u8::try_from(response.apn_ni.payload.len()).unwrap_or(0);
    data[0x00b..0x00b + response.apn_ni.payload.len()].copy_from_slice(response.apn_ni.payload);
    data[0x275] = response.network_features.ims_voice_over_ps;
    data[0x276] = response.network_features.emc_bc;
    data[0x277] = response.network_features.epc_lcs;
    data[0x278] = response.network_features.sc_lcs;
    data[0x279] = response.network_features.ext_sr;
    data[0x27a] = response.transaction_id;

    materialize_attach_pdn(response, data)?;

    let mut tail = response.trailing_fields();
    while let Some(field) = tail.next_field().map_err(AttachCallbackError::Tail)? {
        match field {
            AttachTailField::LowerLayerReason(value) => data[0x27b] = value,
            AttachTailField::EpsAttachResult(value) => data[0x27c] = value,
            AttachTailField::EsmCause(value) => data[0x27d] = value,
            AttachTailField::Ipv4LinkMtu(value) => {
                data[0x27e..0x280].copy_from_slice(&value.to_be_bytes());
            }
            AttachTailField::OperatorPco(value) => {
                if !value.is_empty() {
                    data[0x280] = 1;
                    data[0x281] = u8::try_from(value.len()).unwrap_or(0);
                    data[0x282..0x282 + value.len()].copy_from_slice(value);
                }
            }
            AttachTailField::T3402(value) => {
                data[0x2e6..0x2ea].copy_from_slice(&value.to_be_bytes());
            }
            AttachTailField::ApnAmbr { uplink, downlink } => {
                data[0x2ea..0x2ee].copy_from_slice(&uplink.to_be_bytes());
                data[0x2ee..0x2f2].copy_from_slice(&downlink.to_be_bytes());
            }
            AttachTailField::EmergencyNumbers(list) => {
                let mut count = 0_u8;
                let mut records = list.records();
                while let Some(record) = records
                    .next_record()
                    .map_err(AttachCallbackError::Emergency)?
                {
                    let offset = 0x2f3 + usize::from(count) * 94;
                    data[offset] = u8::try_from(record.number.len() + 1).unwrap_or(0);
                    data[offset + 1] = record.category;
                    data[offset + 2..offset + 2 + record.number.len()]
                        .copy_from_slice(record.number);
                    count += 1;
                }
                data[0x2f2] = count;
            }
            AttachTailField::Msisdn(value) => {
                data[0x875] = u8::try_from(value.len()).unwrap_or(0);
                data[0x876..0x876 + value.len()].copy_from_slice(value);
            }
            AttachTailField::Unknown(_) => {}
        }
    }
    Ok(())
}

pub(crate) const STOCK_ATTACH_EXT_CALLBACK_DATA_LEN: usize = 700;
pub(crate) const STOCK_ATTACH_EXT_CALLBACK_FRAME_LEN: usize =
    12 + STOCK_ATTACH_EXT_CALLBACK_DATA_LEN;
const ATTACH_EXT_PDN_OFFSET: usize = 0x08d;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachExtCallbackError {
    PdnContainerTlv,
    PdnInnerTlv,
    PdnField(PdnInfoFieldLengthError),
}

pub(crate) fn materialize_attach_ext_callback(
    response: AttachExtResponse<'_>,
    data: &mut [u8; STOCK_ATTACH_EXT_CALLBACK_DATA_LEN],
) -> Result<(), AttachExtCallbackError> {
    data.fill(0);
    data[0x000..0x002].copy_from_slice(&response.register_result1.to_be_bytes());
    data[0x002..0x004].copy_from_slice(&response.register_result2.to_be_bytes());
    data[0x004] = u8::try_from(response.requested_apn_ni.payload.len()).unwrap_or(0);
    data[0x005..0x005 + response.requested_apn_ni.payload.len()]
        .copy_from_slice(response.requested_apn_ni.payload);
    data[0x045] = u8::try_from(response.received_apn_ni.payload.len()).unwrap_or(0);
    data[0x046..0x046 + response.received_apn_ni.payload.len()]
        .copy_from_slice(response.received_apn_ni.payload);
    data[0x086..0x088].copy_from_slice(&response.default_eps_id.to_be_bytes());
    data[0x088..0x08a].copy_from_slice(&response.eps_id.to_be_bytes());
    data[0x08a] = response.data_path;
    data[0x08b] = response.ip_alloc;
    data[0x08c] = response.apn_class;
    materialize_pdn_containers(response.pdn_info_containers(), data, ATTACH_EXT_PDN_OFFSET)
        .map_err(|error| match error {
            PdnInfoMaterializeError::ContainerTlv => AttachExtCallbackError::PdnContainerTlv,
            PdnInfoMaterializeError::InnerTlv => AttachExtCallbackError::PdnInnerTlv,
            PdnInfoMaterializeError::Field(error) => AttachExtCallbackError::PdnField(error),
        })?;
    data[0x2b7] = response.network_features.ims_voice_over_ps;
    data[0x2b8] = response.network_features.emc_bc;
    data[0x2b9] = response.network_features.epc_lcs;
    data[0x2ba] = response.network_features.sc_lcs;
    data[0x2bb] = response.network_features.ext_sr;
    Ok(())
}

pub(crate) const STOCK_PDN_CONNECT_CALLBACK_DATA_LEN: usize = 0x2e6;
pub(crate) const STOCK_PDN_CONNECT_CALLBACK_FRAME_LEN: usize =
    12 + STOCK_PDN_CONNECT_CALLBACK_DATA_LEN;
const PDN_CONNECT_PDN_OFFSET: usize = 0x04c;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PdnConnectCallbackError {
    PdnContainerTlv,
    PdnInnerTlv,
    PdnField(PdnInfoFieldLengthError),
    Tail(PdnConnectTailDecodeError),
}

fn map_pdn_connect_materialize_error(error: PdnInfoMaterializeError) -> PdnConnectCallbackError {
    match error {
        PdnInfoMaterializeError::ContainerTlv => PdnConnectCallbackError::PdnContainerTlv,
        PdnInfoMaterializeError::InnerTlv => PdnConnectCallbackError::PdnInnerTlv,
        PdnInfoMaterializeError::Field(error) => PdnConnectCallbackError::PdnField(error),
    }
}

pub(crate) fn materialize_pdn_connect_callback(
    response: PdnConnectResponse<'_>,
    data: &mut [u8; STOCK_PDN_CONNECT_CALLBACK_DATA_LEN],
) -> Result<(), PdnConnectCallbackError> {
    data.fill(0);
    data[0x000..0x002].copy_from_slice(&response.result.to_be_bytes());
    data[0x002..0x004].copy_from_slice(&response.reject_cause1.to_be_bytes());
    data[0x004..0x006].copy_from_slice(&response.reject_cause2.to_be_bytes());
    data[0x006..0x008].copy_from_slice(&response.default_eps_id.to_be_bytes());
    data[0x008] = response.data_path;
    data[0x009] = response.ip_alloc;
    data[0x00a] = response.transaction_id;
    data[0x00b] = u8::try_from(response.apn_ni.payload.len()).unwrap_or(0);
    data[0x00c..0x00c + response.apn_ni.payload.len()].copy_from_slice(response.apn_ni.payload);

    materialize_pdn_containers(response.pdn_info_containers(), data, PDN_CONNECT_PDN_OFFSET)
        .map_err(map_pdn_connect_materialize_error)?;

    let mut tail = response.trailing_fields();
    while let Some(field) = tail.next_field().map_err(PdnConnectCallbackError::Tail)? {
        match field {
            PdnConnectTailField::Ipv4LinkMtu(value) => {
                data[0x276..0x278].copy_from_slice(&value.to_be_bytes());
            }
            PdnConnectTailField::OperatorPco(value) => {
                if !value.is_empty() {
                    data[0x278] = 1;
                    data[0x279] = u8::try_from(value.len()).unwrap_or(0);
                    data[0x27a..0x27a + value.len()].copy_from_slice(value);
                }
            }
            PdnConnectTailField::PdnInfo(_) => {
                let Some(mut fields) = field.pdn_info_fields() else {
                    continue;
                };
                while let Some(tlv) = fields
                    .next_tlv()
                    .map_err(|_| PdnConnectCallbackError::PdnInnerTlv)?
                {
                    let parsed =
                        PdnInfoField::parse(tlv).map_err(PdnConnectCallbackError::PdnField)?;
                    if !materialize_pdn_info_field(data, PDN_CONNECT_PDN_OFFSET, parsed) {
                        break;
                    }
                }
            }
            PdnConnectTailField::ApnAmbr { uplink, downlink } => {
                data[0x2de..0x2e2].copy_from_slice(&uplink.to_be_bytes());
                data[0x2e2..0x2e6].copy_from_slice(&downlink.to_be_bytes());
            }
            PdnConnectTailField::Unknown(_) => {}
        }
    }
    Ok(())
}

pub(crate) const STOCK_PDN_CONNECT_EXT_CALLBACK_DATA_LEN: usize = 0x2b9;
pub(crate) const STOCK_PDN_CONNECT_EXT_CALLBACK_FRAME_LEN: usize =
    12 + STOCK_PDN_CONNECT_EXT_CALLBACK_DATA_LEN;
const PDN_CONNECT_EXT_PDN_OFFSET: usize = 0x08f;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PdnConnectExtCallbackError {
    PdnContainerTlv,
    PdnInnerTlv,
    PdnField(PdnInfoFieldLengthError),
}

pub(crate) fn materialize_pdn_connect_ext_callback(
    response: PdnConnectExtResponse<'_>,
    data: &mut [u8; STOCK_PDN_CONNECT_EXT_CALLBACK_DATA_LEN],
) -> Result<(), PdnConnectExtCallbackError> {
    data.fill(0);
    data[0x000..0x002].copy_from_slice(&response.result.to_be_bytes());
    data[0x002..0x004].copy_from_slice(&response.reject_cause1.to_be_bytes());
    data[0x004..0x006].copy_from_slice(&response.reject_cause2.to_be_bytes());
    data[0x006..0x008].copy_from_slice(&response.default_eps_id.to_be_bytes());
    data[0x008] = response.data_path;
    data[0x009] = response.ip_alloc;
    data[0x00a..0x00c].copy_from_slice(&response.throttle_time.to_be_bytes());
    data[0x00c] = response.apn_class;
    data[0x00d] = u8::try_from(response.requested_apn_ni.payload.len()).unwrap_or(0);
    data[0x00e..0x00e + response.requested_apn_ni.payload.len()]
        .copy_from_slice(response.requested_apn_ni.payload);
    data[0x04e] = u8::try_from(response.received_apn_ni.payload.len()).unwrap_or(0);
    data[0x04f..0x04f + response.received_apn_ni.payload.len()]
        .copy_from_slice(response.received_apn_ni.payload);

    materialize_pdn_containers(
        response.pdn_info_containers(),
        data,
        PDN_CONNECT_EXT_PDN_OFFSET,
    )
    .map_err(|error| match error {
        PdnInfoMaterializeError::ContainerTlv => PdnConnectExtCallbackError::PdnContainerTlv,
        PdnInfoMaterializeError::InnerTlv => PdnConnectExtCallbackError::PdnInnerTlv,
        PdnInfoMaterializeError::Field(error) => PdnConnectExtCallbackError::PdnField(error),
    })?;
    Ok(())
}

pub(crate) const STOCK_PDN_DISCONNECT_CALLBACK_DATA_LEN: usize = 0xb0;
pub(crate) const STOCK_PDN_DISCONNECT_CALLBACK_FRAME_LEN: usize =
    12 + STOCK_PDN_DISCONNECT_CALLBACK_DATA_LEN;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PdnDisconnectCallbackError {
    Tail(PdnDisconnectFieldDecodeError),
}

pub(crate) fn materialize_pdn_disconnect_callback(
    response: PdnDisconnectResponse<'_>,
    data: &mut [u8; STOCK_PDN_DISCONNECT_CALLBACK_DATA_LEN],
) -> Result<(), PdnDisconnectCallbackError> {
    data.fill(0);
    data[0x000..0x002].copy_from_slice(&response.result.to_be_bytes());
    data[0x002..0x004].copy_from_slice(&response.reject_cause1.to_be_bytes());
    data[0x004..0x006].copy_from_slice(&response.reject_cause2.to_be_bytes());
    data[0x006..0x008].copy_from_slice(&response.default_eps_id.to_be_bytes());
    data[0x008] = response.transaction_id;

    let mut tail = response.trailing_fields();
    while let Some(field) = tail
        .next_field()
        .map_err(PdnDisconnectCallbackError::Tail)?
    {
        match field {
            PdnDisconnectField::ApnNetworkIdentifier(value) => {
                data[0x009] = u8::try_from(value.len()).unwrap_or(0);
                data[0x00a..0x00a + value.len()].copy_from_slice(value);
            }
            PdnDisconnectField::OperatorPco(value) => {
                if !value.is_empty() {
                    data[0x04a] = 1;
                    data[0x04b] = u8::try_from(value.len()).unwrap_or(0);
                    data[0x04c..0x04c + value.len()].copy_from_slice(value);
                }
            }
            PdnDisconnectField::Unknown(_) => {}
        }
    }
    Ok(())
}
