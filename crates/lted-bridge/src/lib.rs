//! Translation layer from the recovered stock `lted` client ABI to typed GCT
//! modem requests.
//!
//! Synchronous SDK-call completion and asynchronous modem callbacks are two
//! separate paths in the OEM design. This crate currently implements the
//! synchronous half for the zero-parameter P0 calls whose wire mapping is fully
//! proven.

use std::{io, io::Write};

use gct_lapi::{
    ApnType, AttachExtProfile, AttachExtRequest, AttachExtResponse, AttachRequest, AttachResponse,
    AttachTailDecodeError, AttachTailField, DetachRequest, DetachResponse,
    EmergencyNumberDecodeError, EmptyRequest, PcoInfo, PdnConnectRequest, PdnConnectResponse,
    PdnConnectTailDecodeError, PdnConnectTailField, PdnConnectionControl, PdnDisconnectField,
    PdnDisconnectFieldDecodeError, PdnDisconnectRequest, PdnDisconnectResponse, PdnInfoContainers,
    PdnInfoField, PdnInfoFieldLengthError, PlmnInfoDecodeError, PlmnListResponse,
    PlmnSearchRequest, PlmnSearchResponse, PlmnSearchStopRequest, PlmnSearchStopResponse,
    Positioning, QosField, ResultResponse, ResultResponseKind,
};
use gct_runtime::{
    Modem, ModemCommand, ModemEvent, PendingRequests, ResponseKey, SendCommandError,
    SendTrackedCommandError,
};
use lted_compat::Server;
use lted_proto::{SdkApiRequest, SdkCallback, SdkCallbackKind, SdkCommand};

/// Offset of `lte_api_ret` inside the recovered 38,784-byte
/// `lted_client_context`.
pub const LTE_API_RET_OFFSET: usize = 0x524;
/// One-byte `LTED_GetPSInitComplete` return slot in the stock shared context.
pub const PS_INIT_COMPLETE_OFFSET: usize = 0x528;

#[derive(Debug)]
pub enum HandleError {
    Ipc(io::Error),
    UnsupportedCommand(u16),
    UnexpectedParameters {
        command: u16,
        expected: usize,
        actual: usize,
    },
    UnknownDevice {
        requested: u32,
        expected: u32,
    },
    LegacyAttach(LegacyAttachDecodeError),
    LegacyAttachExt(LegacyAttachExtDecodeError),
    LegacyPdnConnect(LegacyPdnConnectDecodeError),
    LegacyPdnDisconnect(LegacyPdnDisconnectDecodeError),
    AttachCallback(AttachCallbackError),
    AttachExtCallback(AttachExtCallbackError),
    PdnConnectCallback(PdnConnectCallbackError),
    PdnDisconnectCallback(PdnDisconnectCallbackError),
    TransactionIdsExhausted,
    PlmnSearch(PlmnInfoDecodeError),
    PlmnList(PlmnInfoDecodeError),
    Send(SendCommandError),
    Tracked(SendTrackedCommandError),
}

impl std::fmt::Display for HandleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ipc(error) => write!(f, "lted IPC error: {error}"),
            Self::UnsupportedCommand(command) => {
                write!(f, "unsupported recovered lted SDK command {command}")
            }
            Self::UnexpectedParameters {
                command,
                expected,
                actual,
            } => write!(
                f,
                "lted SDK command {command} expected {expected} parameter bytes, got {actual}"
            ),
            Self::UnknownDevice {
                requested,
                expected,
            } => write!(
                f,
                "lted SDK request addressed device {requested}, expected {expected}"
            ),
            Self::LegacyAttach(error) => write!(f, "invalid stock attach request: {error:?}"),
            Self::LegacyAttachExt(error) => {
                write!(f, "invalid stock extended-attach request: {error:?}")
            }
            Self::LegacyPdnConnect(error) => {
                write!(f, "invalid stock PDN-connect request: {error:?}")
            }
            Self::LegacyPdnDisconnect(error) => {
                write!(f, "invalid stock PDN-disconnect request: {error:?}")
            }
            Self::AttachCallback(error) => write!(f, "invalid attach callback payload: {error:?}"),
            Self::AttachExtCallback(error) => {
                write!(f, "invalid extended-attach callback payload: {error:?}")
            }
            Self::PdnConnectCallback(error) => {
                write!(f, "invalid PDN-connect callback payload: {error:?}")
            }
            Self::PdnDisconnectCallback(error) => {
                write!(f, "invalid PDN-disconnect callback payload: {error:?}")
            }
            Self::TransactionIdsExhausted => write!(f, "no free OEM transaction ID in 1..=253"),
            Self::PlmnSearch(error) => write!(f, "invalid PLMN-search response: {error:?}"),
            Self::PlmnList(error) => write!(f, "invalid PLMN-list response: {error:?}"),
            Self::Send(error) => write!(f, "modem send failed: {error:?}"),
            Self::Tracked(error) => write!(f, "tracked modem send failed: {error:?}"),
        }
    }
}

impl std::error::Error for HandleError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Ipc(error) => Some(error),
            Self::UnsupportedCommand(_)
            | Self::UnexpectedParameters { .. }
            | Self::UnknownDevice { .. }
            | Self::LegacyAttach(_)
            | Self::LegacyAttachExt(_)
            | Self::LegacyPdnConnect(_)
            | Self::LegacyPdnDisconnect(_)
            | Self::AttachCallback(_)
            | Self::AttachExtCallback(_)
            | Self::PdnConnectCallback(_)
            | Self::PdnDisconnectCallback(_)
            | Self::TransactionIdsExhausted
            | Self::PlmnSearch(_)
            | Self::PlmnList(_)
            | Self::Send(_)
            | Self::Tracked(_) => None,
        }
    }
}

impl From<io::Error> for HandleError {
    fn from(value: io::Error) -> Self {
        Self::Ipc(value)
    }
}

impl From<SendCommandError> for HandleError {
    fn from(value: SendCommandError) -> Self {
        Self::Send(value)
    }
}

impl From<SendTrackedCommandError> for HandleError {
    fn from(value: SendTrackedCommandError) -> Self {
        Self::Tracked(value)
    }
}

pub const LEGACY_ATTACH_PARAMS_LEN: usize = 0x160;
pub const LEGACY_ATTACH_EXT_PARAMS_LEN: usize = 0x1e4;
pub const LEGACY_PDN_CONNECT_PARAMS_LEN: usize = 0x1a4;
pub const LEGACY_PDN_DISCONNECT_FIXED_LEN: usize = 4;
pub const LEGACY_PDN_DISCONNECT_MAX_LEN: usize = 0x44;

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
/// hazard. When `optional_info == 0`, the modem wire request contains only that
/// byte, so dead legacy fields are deliberately not validated.
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

const STOCK_ATTACH_CALLBACK_DATA_LEN: usize = 0x88b;
const STOCK_ATTACH_CALLBACK_FRAME_LEN: usize = 12 + STOCK_ATTACH_CALLBACK_DATA_LEN;
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

fn materialize_attach_callback(
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

/// Materialize and broadcast stock callback 26 (`Attach`).
///
/// The live daemon sends the complete 2,187-byte `_ATTACH_RSP_INFO` memory
/// image rather than the modem's `0xb102` payload. This function reproduces
/// that big-endian packed image from the clean typed response without defining
/// or exposing the historical C structure.
///
/// # Errors
/// Returns [`HandleError::AttachCallback`] for malformed proven response
/// fields or [`HandleError::Ipc`] for callback/shared-context/socket failures.
pub fn broadcast_attach_callback(
    server: &mut Server,
    device_id: u32,
    response: AttachResponse<'_>,
) -> Result<BroadcastReport, HandleError> {
    let mut data = [0_u8; STOCK_ATTACH_CALLBACK_DATA_LEN];
    materialize_attach_callback(response, &mut data).map_err(HandleError::AttachCallback)?;
    let callback_kind = SdkCallbackKind::Attach;
    let mut frame = [0_u8; STOCK_ATTACH_CALLBACK_FRAME_LEN];
    let frame_len = SdkCallback {
        callback_id: callback_kind.callback_id(),
        device_id,
        data: &data,
    }
    .encode(&mut frame)
    .map_err(|_| {
        HandleError::Ipc(io::Error::new(
            io::ErrorKind::InvalidData,
            "fixed-size Attach callback failed to encode",
        ))
    })?;

    let mut report = BroadcastReport::default();
    for client_id in server.client_ids() {
        let registered = server
            .client_context(client_id)?
            .read_u32_be(callback_kind.registration_offset())?
            != 0;
        if !registered {
            continue;
        }
        report.registered_clients += 1;
        server.send_to_client(client_id, &frame[..frame_len])?;
        report.sent_clients += 1;
    }
    Ok(report)
}

const STOCK_ATTACH_EXT_CALLBACK_DATA_LEN: usize = 700;
const STOCK_ATTACH_EXT_CALLBACK_FRAME_LEN: usize = 12 + STOCK_ATTACH_EXT_CALLBACK_DATA_LEN;
const ATTACH_EXT_PDN_OFFSET: usize = 0x08d;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachExtCallbackError {
    PdnContainerTlv,
    PdnInnerTlv,
    PdnField(PdnInfoFieldLengthError),
}

fn materialize_attach_ext_callback(
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

/// Materialize and broadcast live-P4 stock callback 28 (`Attach EXT`).
///
/// Live P4 sends the exact 700-byte `_ATTACH_RSP_EXT_INFO` image and resolves
/// callback 28 through `cb_rsp[3]` (registration offset `0x1c`).
///
/// # Errors
/// Returns [`HandleError::AttachExtCallback`] for malformed proven nested PDN
/// fields or [`HandleError::Ipc`] for callback/shared-context/socket failures.
pub fn broadcast_attach_ext_callback(
    server: &mut Server,
    device_id: u32,
    response: AttachExtResponse<'_>,
) -> Result<BroadcastReport, HandleError> {
    let mut data = [0_u8; STOCK_ATTACH_EXT_CALLBACK_DATA_LEN];
    materialize_attach_ext_callback(response, &mut data).map_err(HandleError::AttachExtCallback)?;
    let callback_kind = SdkCallbackKind::AttachExt;
    let mut frame = [0_u8; STOCK_ATTACH_EXT_CALLBACK_FRAME_LEN];
    let frame_len = SdkCallback {
        callback_id: callback_kind.callback_id(),
        device_id,
        data: &data,
    }
    .encode(&mut frame)
    .map_err(|_| {
        HandleError::Ipc(io::Error::new(
            io::ErrorKind::InvalidData,
            "fixed-size extended-Attach callback failed to encode",
        ))
    })?;

    let mut report = BroadcastReport::default();
    for client_id in server.client_ids() {
        let registered = server
            .client_context(client_id)?
            .read_u32_be(callback_kind.registration_offset())?
            != 0;
        if !registered {
            continue;
        }
        report.registered_clients += 1;
        server.send_to_client(client_id, &frame[..frame_len])?;
        report.sent_clients += 1;
    }
    Ok(report)
}

const STOCK_DETACH_CALLBACK_DATA_LEN: usize = 8;
const STOCK_DETACH_CALLBACK_FRAME_LEN: usize = 12 + STOCK_DETACH_CALLBACK_DATA_LEN;

/// Materialize and broadcast live-P4 stock callback 30 (`Detach`).
///
/// Live P4 `ind_detach_response` passes callback ID 30 to the stock callback
/// assembler. The callback lookup maps ID 30 to `cb_rsp[4]`, registration
/// offset `0x24`. B014 DWARF fixes `_DETACH_RSP_INFO` at exactly eight bytes.
///
/// # Errors
/// Returns [`HandleError::Ipc`] for callback/shared-context/socket failures.
pub fn broadcast_detach_callback(
    server: &mut Server,
    device_id: u32,
    response: DetachResponse,
) -> Result<BroadcastReport, HandleError> {
    let mut data = [0_u8; STOCK_DETACH_CALLBACK_DATA_LEN];
    data[..4].copy_from_slice(&response.result.to_be_bytes());
    data[4..6].copy_from_slice(&response.deregister_cause1.to_be_bytes());
    data[6..8].copy_from_slice(&response.deregister_cause2.to_be_bytes());

    let callback_kind = SdkCallbackKind::Detach;
    let mut frame = [0_u8; STOCK_DETACH_CALLBACK_FRAME_LEN];
    let frame_len = SdkCallback {
        callback_id: callback_kind.callback_id(),
        device_id,
        data: &data,
    }
    .encode(&mut frame)
    .map_err(|_| {
        HandleError::Ipc(io::Error::new(
            io::ErrorKind::InvalidData,
            "fixed-size Detach callback failed to encode",
        ))
    })?;

    let mut report = BroadcastReport::default();
    for client_id in server.client_ids() {
        let registered = server
            .client_context(client_id)?
            .read_u32_be(callback_kind.registration_offset())?
            != 0;
        if !registered {
            continue;
        }
        report.registered_clients += 1;
        server.send_to_client(client_id, &frame[..frame_len])?;
        report.sent_clients += 1;
    }
    Ok(report)
}

const STOCK_PDN_CONNECT_CALLBACK_DATA_LEN: usize = 0x2e6;
const STOCK_PDN_CONNECT_CALLBACK_FRAME_LEN: usize = 12 + STOCK_PDN_CONNECT_CALLBACK_DATA_LEN;
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

fn materialize_pdn_connect_callback(
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

/// Materialize and broadcast stock callback 33 (`PDNConn`).
///
/// B014 DWARF gives an exact 742-byte `_PDN_CONNECTIVITY_RSP_INFO`. Live P4
/// callback dispatch uses callback ID 33 / `cb_rsp[6]`. The modem's typed
/// `0xb106` response is converted into that historical byte image before the
/// standard local `0x8107` envelope is emitted.
///
/// # Errors
/// Returns [`HandleError::PdnConnectCallback`] for malformed proven response
/// fields or [`HandleError::Ipc`] for callback/shared-context/socket failures.
pub fn broadcast_pdn_connect_callback(
    server: &mut Server,
    device_id: u32,
    response: PdnConnectResponse<'_>,
) -> Result<BroadcastReport, HandleError> {
    let mut data = [0_u8; STOCK_PDN_CONNECT_CALLBACK_DATA_LEN];
    materialize_pdn_connect_callback(response, &mut data)
        .map_err(HandleError::PdnConnectCallback)?;
    let callback_kind = SdkCallbackKind::PdnConnect;
    let mut frame = [0_u8; STOCK_PDN_CONNECT_CALLBACK_FRAME_LEN];
    let frame_len = SdkCallback {
        callback_id: callback_kind.callback_id(),
        device_id,
        data: &data,
    }
    .encode(&mut frame)
    .map_err(|_| {
        HandleError::Ipc(io::Error::new(
            io::ErrorKind::InvalidData,
            "fixed-size PDN-connect callback failed to encode",
        ))
    })?;

    let mut report = BroadcastReport::default();
    for client_id in server.client_ids() {
        let registered = server
            .client_context(client_id)?
            .read_u32_be(callback_kind.registration_offset())?
            != 0;
        if !registered {
            continue;
        }
        report.registered_clients += 1;
        server.send_to_client(client_id, &frame[..frame_len])?;
        report.sent_clients += 1;
    }
    Ok(report)
}

const STOCK_PDN_DISCONNECT_CALLBACK_DATA_LEN: usize = 0xb0;
const STOCK_PDN_DISCONNECT_CALLBACK_FRAME_LEN: usize = 12 + STOCK_PDN_DISCONNECT_CALLBACK_DATA_LEN;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PdnDisconnectCallbackError {
    Tail(PdnDisconnectFieldDecodeError),
}

fn materialize_pdn_disconnect_callback(
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

/// Materialize and broadcast live-P4 stock callback 37 (`PDNDisconn`).
///
/// B014 DWARF gives an exact 176-byte `_PDN_DISCONNECT_RSP_INFO`, and its
/// callback selector maps the disconnect response to client-context offset
/// `0x44` (`cb_rsp[8]`). Live P4 directly passes callback ID 37 to
/// `lted_srv_send_sdk_cb_assemble_hci` (older B014 passes 36 for this family).
/// The modem's typed `0xb108` response is converted into the historical byte
/// image before the standard local `0x8107` envelope is emitted.
///
/// # Errors
/// Returns [`HandleError::PdnDisconnectCallback`] for malformed proven response
/// fields or [`HandleError::Ipc`] for callback/shared-context/socket failures.
pub fn broadcast_pdn_disconnect_callback(
    server: &mut Server,
    device_id: u32,
    response: PdnDisconnectResponse<'_>,
) -> Result<BroadcastReport, HandleError> {
    let mut data = [0_u8; STOCK_PDN_DISCONNECT_CALLBACK_DATA_LEN];
    materialize_pdn_disconnect_callback(response, &mut data)
        .map_err(HandleError::PdnDisconnectCallback)?;
    let callback_kind = SdkCallbackKind::PdnDisconnect;
    let mut frame = [0_u8; STOCK_PDN_DISCONNECT_CALLBACK_FRAME_LEN];
    let frame_len = SdkCallback {
        callback_id: callback_kind.callback_id(),
        device_id,
        data: &data,
    }
    .encode(&mut frame)
    .map_err(|_| {
        HandleError::Ipc(io::Error::new(
            io::ErrorKind::InvalidData,
            "fixed-size PDN-disconnect callback failed to encode",
        ))
    })?;

    let mut report = BroadcastReport::default();
    for client_id in server.client_ids() {
        let registered = server
            .client_context(client_id)?
            .read_u32_be(callback_kind.registration_offset())?
            != 0;
        if !registered {
            continue;
        }
        report.registered_clients += 1;
        server.send_to_client(client_id, &frame[..frame_len])?;
        report.sent_clients += 1;
    }
    Ok(report)
}

const MAX_PLMN_RECORDS: usize = 32;
const STOCK_PLMN_RECORD_LEN: usize = 11;
const STOCK_PLMN_PREFIX_LEN: usize = 5;
const MAX_PLMN_CALLBACK_DATA_LEN: usize =
    STOCK_PLMN_PREFIX_LEN + MAX_PLMN_RECORDS * STOCK_PLMN_RECORD_LEN;
const MAX_PLMN_CALLBACK_FRAME_LEN: usize = 12 + MAX_PLMN_CALLBACK_DATA_LEN;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandledCall {
    pub command: SdkCommand,
    pub device_id: u32,
    pub bytes_written: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BroadcastReport {
    pub registered_clients: usize,
    pub sent_clients: usize,
}

/// Broadcast one of the three proven four-byte result callbacks to every stock
/// client that has the corresponding `cb_rsp[]` function slot registered.
///
/// The callback payload is the original big-endian four-byte modem result, and
/// the local `0x8107` envelope carries the supplied OEM device ID.
///
/// # Errors
/// Returns [`HandleError::Ipc`] for shared-context or UNIX-datagram failures.
pub fn broadcast_result_callback(
    server: &mut Server,
    kind: ResultResponseKind,
    device_id: u32,
    response: ResultResponse,
) -> Result<BroadcastReport, HandleError> {
    let callback_kind = match kind {
        ResultResponseKind::Online => SdkCallbackKind::Online,
        ResultResponseKind::Offline => SdkCallbackKind::Offline,
        ResultResponseKind::PsInit => SdkCallbackKind::PsInit,
    };
    let mut frame = [0_u8; 16];
    let data = response.result.to_be_bytes();
    let frame_len = SdkCallback {
        callback_id: callback_kind.callback_id(),
        device_id,
        data: &data,
    }
    .encode(&mut frame)
    .map_err(|_| {
        HandleError::Ipc(io::Error::new(
            io::ErrorKind::InvalidData,
            "fixed-size result callback failed to encode",
        ))
    })?;

    let mut report = BroadcastReport::default();
    for client_id in server.client_ids() {
        let registered = server
            .client_context(client_id)?
            .read_u32_be(callback_kind.registration_offset())?
            != 0;
        if !registered {
            continue;
        }
        report.registered_clients += 1;
        server.send_to_client(client_id, &frame[..frame_len])?;
        report.sent_clients += 1;
    }
    Ok(report)
}

const STOCK_PLMN_SEARCH_STOP_CALLBACK_DATA_LEN: usize = 5;
const STOCK_PLMN_SEARCH_STOP_CALLBACK_FRAME_LEN: usize =
    12 + STOCK_PLMN_SEARCH_STOP_CALLBACK_DATA_LEN;

/// Materialize and broadcast live-P4 stock callback 64 (`PLMNSearchStop`).
///
/// B014 DWARF fixes `_PLMN_SEARCH_STOP_RSP_INFO` at five bytes:
/// `search_type:u8 | result:u32be`. Live P4 callback lookup maps ID 64 to
/// `cb_rsp[20]`, registration offset `0xa4`.
///
/// # Errors
/// Returns [`HandleError::Ipc`] for callback/shared-context/socket failures.
pub fn broadcast_plmn_search_stop_callback(
    server: &mut Server,
    device_id: u32,
    response: PlmnSearchStopResponse,
) -> Result<BroadcastReport, HandleError> {
    let mut data = [0_u8; STOCK_PLMN_SEARCH_STOP_CALLBACK_DATA_LEN];
    data[0] = response.search_type;
    data[1..5].copy_from_slice(&response.result.to_be_bytes());
    let callback_kind = SdkCallbackKind::PlmnSearchStop;
    let mut frame = [0_u8; STOCK_PLMN_SEARCH_STOP_CALLBACK_FRAME_LEN];
    let frame_len = SdkCallback {
        callback_id: callback_kind.callback_id(),
        device_id,
        data: &data,
    }
    .encode(&mut frame)
    .map_err(|_| {
        HandleError::Ipc(io::Error::new(
            io::ErrorKind::InvalidData,
            "fixed-size PLMN-search-stop callback failed to encode",
        ))
    })?;
    let mut report = BroadcastReport::default();
    for client_id in server.client_ids() {
        let registered = server
            .client_context(client_id)?
            .read_u32_be(callback_kind.registration_offset())?
            != 0;
        if !registered {
            continue;
        }
        report.registered_clients += 1;
        server.send_to_client(client_id, &frame[..frame_len])?;
        report.sent_clients += 1;
    }
    Ok(report)
}

const STOCK_PLMN_SEARCH_CALLBACK_DATA_LEN: usize = 436;
const STOCK_PLMN_SEARCH_CALLBACK_FRAME_LEN: usize = 12 + STOCK_PLMN_SEARCH_CALLBACK_DATA_LEN;
const STOCK_PLMN_SEARCH_RECORDS_OFFSET: usize = 31;
const STOCK_PLMN_SEARCH_PRIORITY_OFFSET: usize = 383;
const STOCK_PLMN_SEARCH_SIB1_OFFSET: usize = 387;

/// Materialize and broadcast live-P4 stock callback 41 (`PLMNSearch`).
///
/// B014 DWARF fixes `_PLMN_SEARCH_RSP_INFO` at 436 bytes. Live P4
/// `ind_plmn_search_response` sends callback ID 41, and its callback lookup maps
/// that selector to `cb_rsp[9]` (registration offset `0x4c`).
///
/// # Errors
/// Returns [`HandleError::PlmnSearch`] for malformed record streams or
/// [`HandleError::Ipc`] for callback/shared-context/socket failures.
pub fn broadcast_plmn_search_callback(
    server: &mut Server,
    device_id: u32,
    response: PlmnSearchResponse<'_>,
) -> Result<BroadcastReport, HandleError> {
    let mut data = [0_u8; STOCK_PLMN_SEARCH_CALLBACK_DATA_LEN];
    data[0..4].copy_from_slice(&response.result.to_be_bytes());
    data[4] = response.selection_mode;
    data[5..8].copy_from_slice(&response.selected_plmn_id);
    data[8..10].copy_from_slice(&response.next_index.to_be_bytes());
    data[10..12].copy_from_slice(&response.network_interval.to_be_bytes());
    data[12] = response.remaining_count.to_be_bytes()[0];
    data[13..15].copy_from_slice(&response.band.to_be_bytes());
    data[15..17].copy_from_slice(&response.cell_id.to_be_bytes());
    data[17..21].copy_from_slice(&response.frequency.to_be_bytes());
    data[21..23].copy_from_slice(&response.tac);
    data[23..27].copy_from_slice(&response.bit28_cell_id.to_be_bytes());

    let mut count = 0_u32;
    let mut offset = STOCK_PLMN_SEARCH_RECORDS_OFFSET;
    let mut records = response.records();
    while let Some(record) = records.next_record().map_err(HandleError::PlmnSearch)? {
        data[offset..offset + 3].copy_from_slice(&record.plmn_id);
        data[offset + 3..offset + 7].copy_from_slice(&record.priority.to_be_bytes());
        data[offset + 7..offset + 11].copy_from_slice(&record.status.to_be_bytes());
        offset += STOCK_PLMN_RECORD_LEN;
        count += 1;
    }
    data[27..31].copy_from_slice(&count.to_be_bytes());
    if let Some(priority) = response.plmn_priority {
        data[STOCK_PLMN_SEARCH_PRIORITY_OFFSET..STOCK_PLMN_SEARCH_PRIORITY_OFFSET + 4]
            .copy_from_slice(&priority.to_be_bytes());
    }
    if let Some(sib1) = response.sib1_plmn {
        data[STOCK_PLMN_SEARCH_SIB1_OFFSET] = sib1.count;
        let start = STOCK_PLMN_SEARCH_SIB1_OFFSET + 1;
        data[start..start + sib1.packed_plmn.len()].copy_from_slice(sib1.packed_plmn);
    }

    let callback_kind = SdkCallbackKind::PlmnSearch;
    let mut frame = [0_u8; STOCK_PLMN_SEARCH_CALLBACK_FRAME_LEN];
    let frame_len = SdkCallback {
        callback_id: callback_kind.callback_id(),
        device_id,
        data: &data,
    }
    .encode(&mut frame)
    .map_err(|_| {
        HandleError::Ipc(io::Error::new(
            io::ErrorKind::InvalidData,
            "fixed-size PLMN-search callback failed to encode",
        ))
    })?;

    let mut report = BroadcastReport::default();
    for client_id in server.client_ids() {
        let registered = server
            .client_context(client_id)?
            .read_u32_be(callback_kind.registration_offset())?
            != 0;
        if !registered {
            continue;
        }
        report.registered_clients += 1;
        server.send_to_client(client_id, &frame[..frame_len])?;
        report.sent_clients += 1;
    }
    Ok(report)
}

/// Materialize and broadcast stock callback 45 (`PLMN List`).
///
/// The live daemon sends exactly `5 + 11*N` callback-data bytes: one
/// `search_complete` byte, a big-endian `u32` record count, then `N` records
/// laid out as `plmn_id[3] | priority:u32be | status:u32be`.
///
/// # Errors
/// Returns [`HandleError::PlmnList`] for a malformed semantic record stream,
/// or [`HandleError::Ipc`] for callback encoding/shared-context/socket errors.
pub fn broadcast_plmn_list_callback(
    server: &mut Server,
    device_id: u32,
    response: PlmnListResponse<'_>,
) -> Result<BroadcastReport, HandleError> {
    let mut data = [0_u8; MAX_PLMN_CALLBACK_DATA_LEN];
    data[0] = response.search_complete;
    let mut count = 0_u32;
    let mut offset = STOCK_PLMN_PREFIX_LEN;
    let mut records = response.records();
    while let Some(record) = records.next_record().map_err(HandleError::PlmnList)? {
        data[offset..offset + 3].copy_from_slice(&record.plmn_id);
        data[offset + 3..offset + 7].copy_from_slice(&record.priority.to_be_bytes());
        data[offset + 7..offset + 11].copy_from_slice(&record.status.to_be_bytes());
        offset += STOCK_PLMN_RECORD_LEN;
        count += 1;
    }
    data[1..5].copy_from_slice(&count.to_be_bytes());

    let callback_kind = SdkCallbackKind::PlmnList;
    let mut frame = [0_u8; MAX_PLMN_CALLBACK_FRAME_LEN];
    let frame_len = SdkCallback {
        callback_id: callback_kind.callback_id(),
        device_id,
        data: &data[..offset],
    }
    .encode(&mut frame)
    .map_err(|_| {
        HandleError::Ipc(io::Error::new(
            io::ErrorKind::InvalidData,
            "bounded PLMN-list callback failed to encode",
        ))
    })?;

    let mut report = BroadcastReport::default();
    for client_id in server.client_ids() {
        let registered = server
            .client_context(client_id)?
            .read_u32_be(callback_kind.registration_offset())?
            != 0;
        if !registered {
            continue;
        }
        report.registered_clients += 1;
        server.send_to_client(client_id, &frame[..frame_len])?;
        report.sent_clients += 1;
    }
    Ok(report)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartupPhase {
    Idle,
    AwaitingPsInit,
    NeedOnline,
    AwaitingOnline,
    Complete,
}

/// Per-physical-modem compatibility state.
///
/// The stock SDK resolves every request through `device_find(handle, device_id)`
/// and response handlers pass `device->device_id` back as the first callback
/// argument. The replacement therefore binds one stable OEM device ID to one
/// modem runtime instead of inventing request-side callback tokens.
#[derive(Debug, Eq, PartialEq)]
pub struct DeviceBridge {
    device_id: u32,
    pending: PendingRequests,
    startup_phase: StartupPhase,
}

impl DeviceBridge {
    #[must_use]
    pub const fn new(device_id: u32) -> Self {
        Self {
            device_id,
            pending: PendingRequests::new(),
            startup_phase: StartupPhase::Idle,
        }
    }

    #[must_use]
    pub const fn device_id(&self) -> u32 {
        self.device_id
    }

    #[must_use]
    pub const fn pending_count(&self) -> usize {
        self.pending.len()
    }

    #[must_use]
    pub const fn init_complete(&self) -> bool {
        matches!(self.startup_phase, StartupPhase::Complete)
    }

    #[must_use]
    pub const fn startup_phase(&self) -> StartupPhase {
        self.startup_phase
    }

    /// Advance the proven daemon-owned `PSInit` -> `Online` startup sequence.
    ///
    /// Stock `lted` starts PS initialization for a newly inserted device and,
    /// after its first `PSInit` response, issues `Online` from a helper thread. The
    /// clean daemon preserves those modem-visible transitions without copying
    /// unrelated legacy side effects.
    ///
    /// # Errors
    /// Returns [`HandleError::Tracked`] or [`HandleError::Send`] if the next
    /// startup request cannot be encoded/tracked/written.
    pub fn drive_initialization<T: Write>(
        &mut self,
        modem: &mut Modem<T>,
    ) -> Result<Option<usize>, HandleError> {
        let (request, next) = match self.startup_phase {
            StartupPhase::Idle => (EmptyRequest::PsInit, StartupPhase::AwaitingPsInit),
            StartupPhase::NeedOnline => (EmptyRequest::Online, StartupPhase::AwaitingOnline),
            StartupPhase::AwaitingPsInit
            | StartupPhase::AwaitingOnline
            | StartupPhase::Complete => return Ok(None),
        };
        let bytes = modem.send_tracked_command(&mut self.pending, ModemCommand::Empty(request))?;
        self.startup_phase = next;
        Ok(Some(bytes))
    }

    /// Execute one stock SDK request and complete the OEM semaphore/shm
    /// synchronous return path.
    ///
    /// The recovered OEM sequence is preserved: acquire the daemon semaphore,
    /// clear `lte_api_ret`, attempt the LAPI send, store `0` on success or `1`
    /// on failure, then release the daemon semaphore. Result-family requests are
    /// tracked before touching GLIF so a second indistinguishable request cannot
    /// steal the eventual callback.
    ///
    /// # Errors
    /// Returns [`HandleError`] for an unused client slot, System V IPC failure,
    /// a request for another physical device, an unsupported/not-yet-translated
    /// command, unexpected legacy parameters, or a modem encode/write/pending
    /// failure.
    pub fn handle_sdk_api<T: Write>(
        &mut self,
        server: &mut Server,
        modem: &mut Modem<T>,
        client_id: u8,
        request: SdkApiRequest<'_>,
    ) -> Result<HandledCall, HandleError> {
        let context = server.client_context(client_id)?;
        context.daemon_acquire()?;
        if let Err(error) = context.write_i32_be(LTE_API_RET_OFFSET, 0) {
            let _ = context.daemon_release();
            return Err(error.into());
        }

        let dispatch = if request.device_id == self.device_id {
            match request.known_command() {
                Ok(SdkCommand::GetPsInitComplete) => {
                    if request.params.is_empty() {
                        context
                            .write(PS_INIT_COMPLETE_OFFSET, &[u8::from(self.init_complete())])?;
                        Ok(HandledCall {
                            command: SdkCommand::GetPsInitComplete,
                            device_id: request.device_id,
                            bytes_written: 0,
                        })
                    } else {
                        Err(HandleError::UnexpectedParameters {
                            command: request.command,
                            expected: 0,
                            actual: request.params.len(),
                        })
                    }
                }
                Ok(SdkCommand::Attach) => self.dispatch_attach(modem, request),
                Ok(SdkCommand::AttachExt) => self.dispatch_attach_ext(modem, request),
                Ok(SdkCommand::Detach) => self.dispatch_detach(modem, request),
                Ok(SdkCommand::PdnConnect) => self.dispatch_pdn_connect(modem, request),
                Ok(SdkCommand::PdnDisconnect) => self.dispatch_pdn_disconnect(modem, request),
                Ok(SdkCommand::PlmnSearch) => self.dispatch_plmn_search(modem, request),
                Ok(SdkCommand::PlmnSearchStop) => self.dispatch_plmn_search_stop(modem, request),
                Ok(_) => self.dispatch_zero_parameter(modem, request),
                Err(_) => Err(HandleError::UnsupportedCommand(request.command)),
            }
        } else {
            Err(HandleError::UnknownDevice {
                requested: request.device_id,
                expected: self.device_id,
            })
        };
        let status = i32::from(dispatch.is_err());
        let status_result = context.write_i32_be(LTE_API_RET_OFFSET, status);
        let release_result = context.daemon_release();

        status_result?;
        release_result?;
        dispatch
    }

    /// Route one decoded modem event through the asynchronous stock callback
    /// path implemented so far.
    ///
    /// Four-byte Online/Offline/PSInit result responses and multipart PLMN-list
    /// responses are handled here. An event without a matching tracked request
    /// is ignored, matching the replacement's conservative correlation policy.
    ///
    /// # Errors
    /// Returns [`HandleError::Ipc`] when broadcasting to a subscribed stock
    /// client fails.
    pub fn handle_modem_event(
        &mut self,
        server: &mut Server,
        event: &ModemEvent<'_>,
    ) -> Result<Option<BroadcastReport>, HandleError> {
        match event {
            ModemEvent::Attach(response) => {
                let key = ResponseKey::Attach(response.transaction_id);
                if !self.pending.remove(key) {
                    return Ok(None);
                }
                broadcast_attach_callback(server, self.device_id, *response).map(Some)
            }
            ModemEvent::AttachExt(response) => {
                if !self.pending.remove(ResponseKey::AttachExt) {
                    return Ok(None);
                }
                broadcast_attach_ext_callback(server, self.device_id, *response).map(Some)
            }
            ModemEvent::Detach(response) => {
                if !self.pending.remove(ResponseKey::Detach) {
                    return Ok(None);
                }
                broadcast_detach_callback(server, self.device_id, *response).map(Some)
            }
            ModemEvent::PdnConnect(response) => {
                let key = ResponseKey::PdnConnect(response.transaction_id);
                if !self.pending.remove(key) {
                    return Ok(None);
                }
                broadcast_pdn_connect_callback(server, self.device_id, *response).map(Some)
            }
            ModemEvent::PdnDisconnect(response) => {
                let key = ResponseKey::PdnDisconnect(response.transaction_id);
                if !self.pending.remove(key) {
                    return Ok(None);
                }
                broadcast_pdn_disconnect_callback(server, self.device_id, *response).map(Some)
            }
            ModemEvent::Result { kind, response } => {
                let key = ResponseKey::Result(*kind);
                if !self.pending.remove(key) {
                    return Ok(None);
                }
                match (*kind, self.startup_phase) {
                    (ResultResponseKind::PsInit, StartupPhase::AwaitingPsInit) => {
                        self.startup_phase = StartupPhase::NeedOnline;
                    }
                    (ResultResponseKind::Online, StartupPhase::AwaitingOnline) => {
                        self.startup_phase = StartupPhase::Complete;
                    }
                    _ => {}
                }
                broadcast_result_callback(server, *kind, self.device_id, *response).map(Some)
            }
            ModemEvent::PlmnSearchStop(response) => {
                let key = ResponseKey::PlmnSearchStop(response.search_type);
                if !self.pending.remove(key) {
                    return Ok(None);
                }
                broadcast_plmn_search_stop_callback(server, self.device_id, *response).map(Some)
            }
            ModemEvent::PlmnSearch(response) => {
                if !self.pending.remove(ResponseKey::PlmnSearch) {
                    return Ok(None);
                }
                broadcast_plmn_search_callback(server, self.device_id, *response).map(Some)
            }
            ModemEvent::PlmnList(response) => {
                let key = ResponseKey::PlmnList;
                if !self.pending.contains(key) {
                    return Ok(None);
                }
                let report = broadcast_plmn_list_callback(server, self.device_id, *response)?;
                if response.search_complete != 0 {
                    self.pending.remove(key);
                }
                Ok(Some(report))
            }
            _ => Ok(None),
        }
    }

    fn allocate_transaction_id(&self) -> Result<u8, HandleError> {
        for transaction_id in 1_u8..=253 {
            let used = self.pending.contains(ResponseKey::Attach(transaction_id))
                || self
                    .pending
                    .contains(ResponseKey::PdnConnect(transaction_id))
                || self
                    .pending
                    .contains(ResponseKey::PdnDisconnect(transaction_id));
            if !used {
                return Ok(transaction_id);
            }
        }
        Err(HandleError::TransactionIdsExhausted)
    }

    fn dispatch_plmn_search_stop<T: Write>(
        &mut self,
        modem: &mut Modem<T>,
        request: SdkApiRequest<'_>,
    ) -> Result<HandledCall, HandleError> {
        let [search_type]: [u8; 1] =
            request
                .params
                .try_into()
                .map_err(|_| HandleError::UnexpectedParameters {
                    command: request.command,
                    expected: 1,
                    actual: request.params.len(),
                })?;
        let bytes_written = modem.send_tracked_command(
            &mut self.pending,
            ModemCommand::PlmnSearchStop(PlmnSearchStopRequest { search_type }),
        )?;
        Ok(HandledCall {
            command: SdkCommand::PlmnSearchStop,
            device_id: request.device_id,
            bytes_written,
        })
    }

    fn dispatch_plmn_search<T: Write>(
        &mut self,
        modem: &mut Modem<T>,
        request: SdkApiRequest<'_>,
    ) -> Result<HandledCall, HandleError> {
        let params: [u8; 9] =
            request
                .params
                .try_into()
                .map_err(|_| HandleError::UnexpectedParameters {
                    command: request.command,
                    expected: 9,
                    actual: request.params.len(),
                })?;
        let search = PlmnSearchRequest {
            search_mode: params[0],
            mcc: [params[1], params[2], params[3]],
            mnc: [params[4], params[5], params[6]],
            emergency_mode: params[7],
            roaming_option: params[8],
        };
        let bytes_written =
            modem.send_tracked_command(&mut self.pending, ModemCommand::PlmnSearch(search))?;
        Ok(HandledCall {
            command: SdkCommand::PlmnSearch,
            device_id: request.device_id,
            bytes_written,
        })
    }

    fn dispatch_detach<T: Write>(
        &mut self,
        modem: &mut Modem<T>,
        request: SdkApiRequest<'_>,
    ) -> Result<HandledCall, HandleError> {
        let bytes: [u8; 4] =
            request
                .params
                .try_into()
                .map_err(|_| HandleError::UnexpectedParameters {
                    command: request.command,
                    expected: 4,
                    actual: request.params.len(),
                })?;
        let detach = DetachRequest::from_raw(u32::from_be_bytes(bytes));
        let bytes_written =
            modem.send_tracked_command(&mut self.pending, ModemCommand::Detach(detach))?;

        // Live LAPI_DetachRequest calls tid_list_clean() before sending. That
        // list is populated by normal PDN connect/disconnect TID allocation.
        // Retire those pending transaction keys once the detach write succeeds.
        for transaction_id in 1_u8..=253 {
            self.pending.remove(ResponseKey::PdnConnect(transaction_id));
            self.pending
                .remove(ResponseKey::PdnDisconnect(transaction_id));
        }

        Ok(HandledCall {
            command: SdkCommand::Detach,
            device_id: request.device_id,
            bytes_written,
        })
    }

    fn dispatch_pdn_connect<T: Write>(
        &mut self,
        modem: &mut Modem<T>,
        request: SdkApiRequest<'_>,
    ) -> Result<HandledCall, HandleError> {
        let transaction_id = self.allocate_transaction_id()?;
        let pdn = decode_legacy_pdn_connect(request.params, transaction_id)
            .map_err(HandleError::LegacyPdnConnect)?;
        let bytes_written =
            modem.send_tracked_command(&mut self.pending, ModemCommand::PdnConnect(pdn))?;
        Ok(HandledCall {
            command: SdkCommand::PdnConnect,
            device_id: request.device_id,
            bytes_written,
        })
    }

    fn dispatch_pdn_disconnect<T: Write>(
        &mut self,
        modem: &mut Modem<T>,
        request: SdkApiRequest<'_>,
    ) -> Result<HandledCall, HandleError> {
        let transaction_id = self.allocate_transaction_id()?;
        let pdn = decode_legacy_pdn_disconnect(request.params, transaction_id)
            .map_err(HandleError::LegacyPdnDisconnect)?;
        let bytes_written =
            modem.send_tracked_command(&mut self.pending, ModemCommand::PdnDisconnect(pdn))?;
        Ok(HandledCall {
            command: SdkCommand::PdnDisconnect,
            device_id: request.device_id,
            bytes_written,
        })
    }

    fn dispatch_attach_ext<T: Write>(
        &mut self,
        modem: &mut Modem<T>,
        request: SdkApiRequest<'_>,
    ) -> Result<HandledCall, HandleError> {
        let attach =
            decode_legacy_attach_ext(request.params).map_err(HandleError::LegacyAttachExt)?;
        let bytes_written =
            modem.send_tracked_command(&mut self.pending, ModemCommand::AttachExt(attach))?;
        Ok(HandledCall {
            command: SdkCommand::AttachExt,
            device_id: request.device_id,
            bytes_written,
        })
    }

    fn dispatch_attach<T: Write>(
        &mut self,
        modem: &mut Modem<T>,
        request: SdkApiRequest<'_>,
    ) -> Result<HandledCall, HandleError> {
        let attach = decode_legacy_attach(request.params).map_err(HandleError::LegacyAttach)?;
        let bytes_written =
            modem.send_tracked_command(&mut self.pending, ModemCommand::Attach(attach))?;
        Ok(HandledCall {
            command: SdkCommand::Attach,
            device_id: request.device_id,
            bytes_written,
        })
    }

    fn dispatch_zero_parameter<T: Write>(
        &mut self,
        modem: &mut Modem<T>,
        request: SdkApiRequest<'_>,
    ) -> Result<HandledCall, HandleError> {
        let command = request
            .known_command()
            .map_err(|_| HandleError::UnsupportedCommand(request.command))?;
        let empty = match command {
            SdkCommand::PsInit => EmptyRequest::PsInit,
            SdkCommand::Online => EmptyRequest::Online,
            SdkCommand::Offline => EmptyRequest::Offline,
            SdkCommand::PlmnList => EmptyRequest::PlmnList,
            SdkCommand::GetPsInitComplete => {
                return Err(HandleError::UnsupportedCommand(request.command));
            }
            _ => return Err(HandleError::UnsupportedCommand(request.command)),
        };
        if !request.params.is_empty() {
            return Err(HandleError::UnexpectedParameters {
                command: request.command,
                expected: 0,
                actual: request.params.len(),
            });
        }
        let modem_command = ModemCommand::Empty(empty);
        let bytes_written = modem.send_tracked_command(&mut self.pending, modem_command)?;
        if empty == EmptyRequest::PsInit && self.startup_phase == StartupPhase::Idle {
            self.startup_phase = StartupPhase::AwaitingPsInit;
        }
        Ok(HandledCall {
            command,
            device_id: request.device_id,
            bytes_written,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::{self, Cursor, Write},
        os::unix::net::UnixDatagram,
        path::PathBuf,
        process,
        sync::atomic::{AtomicU64, Ordering},
    };

    use gct_lapi::{ResultResponse, ResultResponseKind};
    use gct_runtime::{Modem, ModemEvent, ResponseKey};
    use gct_transport::HciIo;
    use lted_compat::Server;
    use lted_proto::{
        ApiOpenRequest, ApiOpenResponse, Packet, SdkApiRequest, SdkCallback, SdkCallbackKind,
        SdkCommand,
    };

    use super::{
        BroadcastReport, DeviceBridge, HandleError, LTE_API_RET_OFFSET, LegacyAttachDecodeError,
        LegacyAttachExtDecodeError, LegacyAttachExtStringField, LegacyAttachStringField,
        LegacyPdnConnectDecodeError, LegacyPdnConnectStringField, LegacyPdnDisconnectDecodeError,
        PS_INIT_COMPLETE_OFFSET, StartupPhase, broadcast_result_callback, decode_legacy_attach,
        decode_legacy_attach_ext, decode_legacy_pdn_disconnect,
    };

    static NEXT_TEST_DIR: AtomicU64 = AtomicU64::new(0);

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let suffix = NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("wf830-lted-bridge-{}-{suffix}", process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir(&path).unwrap_or_else(|_| std::process::abort());
            Self(path)
        }

        fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn open_client(server: &mut Server, dir: &TestDir, number: usize) -> (UnixDatagram, u8) {
        let peer_path = dir.join(&format!("peer-{number}"));
        let client = UnixDatagram::bind(&peer_path).unwrap_or_else(|_| std::process::abort());
        let mut open = [0_u8; 8];
        let len = (ApiOpenRequest {
            client_identity: Some(0x1234),
        })
        .encode(&mut open)
        .unwrap_or_else(|_| std::process::abort());
        client
            .send_to(&open[..len], server.common_path())
            .unwrap_or_else(|_| std::process::abort());
        let opened = server
            .accept_open_once()
            .unwrap_or_else(|_| std::process::abort())
            .unwrap_or_else(|| std::process::abort());
        let mut response = [0_u8; 5];
        let (len, source) = client
            .recv_from(&mut response)
            .unwrap_or_else(|_| std::process::abort());
        let packet = Packet::parse(&response[..len]).unwrap_or_else(|_| std::process::abort());
        let response = ApiOpenResponse::parse(packet).unwrap_or_else(|_| std::process::abort());
        assert_eq!(response.client_id, opened.id);
        let source = source
            .as_pathname()
            .unwrap_or_else(|| std::process::abort());
        client
            .connect(source)
            .unwrap_or_else(|_| std::process::abort());
        (client, opened.id)
    }

    fn read_api_ret(server: &mut Server, id: u8) -> i32 {
        let mut bytes = [0_u8; 4];
        server
            .client_context(id)
            .unwrap_or_else(|_| std::process::abort())
            .read(LTE_API_RET_OFFSET, &mut bytes)
            .unwrap_or_else(|_| std::process::abort());
        i32::from_be_bytes(bytes)
    }

    fn bind_server(dir: &TestDir) -> Server {
        Server::bind_paths(dir.join("daemon"), dir.join("client-"))
            .unwrap_or_else(|_| std::process::abort())
    }

    fn route_one_hci(
        bridge: &mut DeviceBridge,
        server: &mut Server,
        frame: Vec<u8>,
    ) -> Option<BroadcastReport> {
        let transport = HciIo::new(Cursor::new(frame));
        let mut modem = Modem::new(transport);
        let mut routed = None;
        modem
            .poll_events_once(|event| {
                let Ok(event) = event else {
                    std::process::abort();
                };
                routed = bridge
                    .handle_modem_event(server, &event)
                    .unwrap_or_else(|_| std::process::abort());
            })
            .unwrap_or_else(|_| std::process::abort());
        routed
    }

    #[test]
    fn daemon_startup_drives_ps_init_then_online_before_reporting_complete() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (_client, id) = open_client(&mut server, &dir, 0);
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(1);

        assert_eq!(bridge.startup_phase(), StartupPhase::Idle);
        assert!(matches!(
            bridge.drive_initialization(&mut modem),
            Ok(Some(4))
        ));
        assert_eq!(bridge.startup_phase(), StartupPhase::AwaitingPsInit);
        assert_eq!(bridge.pending_count(), 1);

        let ps_init = ModemEvent::Result {
            kind: ResultResponseKind::PsInit,
            response: ResultResponse { result: 0 },
        };
        bridge
            .handle_modem_event(&mut server, &ps_init)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(bridge.startup_phase(), StartupPhase::NeedOnline);
        assert_eq!(bridge.pending_count(), 0);

        assert!(matches!(
            bridge.drive_initialization(&mut modem),
            Ok(Some(4))
        ));
        assert_eq!(bridge.startup_phase(), StartupPhase::AwaitingOnline);
        assert_eq!(bridge.pending_count(), 1);

        let online = ModemEvent::Result {
            kind: ResultResponseKind::Online,
            response: ResultResponse { result: 0 },
        };
        bridge
            .handle_modem_event(&mut server, &online)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(bridge.startup_phase(), StartupPhase::Complete);
        assert!(bridge.init_complete());
        assert_eq!(bridge.pending_count(), 0);
        assert!(matches!(bridge.drive_initialization(&mut modem), Ok(None)));
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            vec![0x31, 0x2e, 0x00, 0x00, 0x31, 0x21, 0x00, 0x00]
        );

        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let request = SdkApiRequest {
            command: SdkCommand::GetPsInitComplete as u16,
            device_id: 1,
            params: &[],
        };
        bridge
            .handle_sdk_api(&mut server, &mut modem, id, request)
            .unwrap_or_else(|_| std::process::abort());
        let mut value = [0_u8; 1];
        server
            .client_context(id)
            .unwrap_or_else(|_| std::process::abort())
            .read(PS_INIT_COMPLETE_OFFSET, &mut value)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(value, [1]);
    }

    #[test]
    fn get_ps_init_complete_is_local_and_uses_recovered_shared_byte() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (_client, id) = open_client(&mut server, &dir, 0);
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(1);
        let request = SdkApiRequest {
            command: SdkCommand::GetPsInitComplete as u16,
            device_id: 1,
            params: &[],
        };

        let handled = bridge
            .handle_sdk_api(&mut server, &mut modem, id, request)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(handled.command, SdkCommand::GetPsInitComplete);
        assert_eq!(handled.bytes_written, 0);
        assert_eq!(read_api_ret(&mut server, id), 0);
        let mut value = [0xff_u8; 1];
        server
            .client_context(id)
            .unwrap_or_else(|_| std::process::abort())
            .read(PS_INIT_COMPLETE_OFFSET, &mut value)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(value, [0]);
        assert!(!bridge.init_complete());
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn stock_style_ps_init_reaches_modem_and_completes_shm_return() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (client, id) = open_client(&mut server, &dir, 0);
        let request = SdkApiRequest {
            command: SdkCommand::PsInit as u16,
            device_id: 0x1122_3344,
            params: &[],
        };
        let mut frame = [0_u8; 12];
        let len = request
            .encode(&mut frame)
            .unwrap_or_else(|_| std::process::abort());
        client
            .send(&frame[..len])
            .unwrap_or_else(|_| std::process::abort());

        let mut received = [0_u8; 32];
        let len = server
            .recv_from_client(id, &mut received)
            .unwrap_or_else(|_| std::process::abort());
        let packet = Packet::parse(&received[..len]).unwrap_or_else(|_| std::process::abort());
        let parsed = SdkApiRequest::parse(packet).unwrap_or_else(|_| std::process::abort());
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(0x1122_3344);
        let handled = bridge
            .handle_sdk_api(&mut server, &mut modem, id, parsed)
            .unwrap_or_else(|_| std::process::abort());

        assert_eq!(handled.command, SdkCommand::PsInit);
        assert_eq!(handled.device_id, 0x1122_3344);
        assert_eq!(handled.bytes_written, 4);
        assert_eq!(read_api_ret(&mut server, id), 0);
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            vec![0x31, 0x2e, 0x00, 0x00]
        );
    }

    #[test]
    fn all_recovered_zero_parameter_calls_map_to_exact_hci_frames() {
        let cases = [
            (SdkCommand::PlmnList, [0x31, 0x0b, 0x00, 0x00]),
            (SdkCommand::Online, [0x31, 0x21, 0x00, 0x00]),
            (SdkCommand::Offline, [0x31, 0x23, 0x00, 0x00]),
            (SdkCommand::PsInit, [0x31, 0x2e, 0x00, 0x00]),
        ];
        for (index, (command, expected)) in cases.into_iter().enumerate() {
            let dir = TestDir::new();
            let mut server = bind_server(&dir);
            let (_client, id) = open_client(&mut server, &dir, 0);
            let transport = HciIo::new(Cursor::new(Vec::new()));
            let mut modem = Modem::new(transport);
            let device_id = u32::try_from(index).unwrap_or_else(|_| std::process::abort());
            let mut bridge = DeviceBridge::new(device_id);
            let request = SdkApiRequest {
                command: command as u16,
                device_id,
                params: &[],
            };
            bridge
                .handle_sdk_api(&mut server, &mut modem, id, request)
                .unwrap_or_else(|_| std::process::abort());
            assert_eq!(read_api_ret(&mut server, id), 0);
            assert_eq!(modem.into_transport().into_inner().into_inner(), expected);
        }
    }

    #[test]
    fn plmn_list_callback_matches_stock_layout_and_releases_only_terminal_fragment() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (client, id) = open_client(&mut server, &dir, 0);
        server
            .client_context(id)
            .unwrap_or_else(|_| std::process::abort())
            .write_u32_be(SdkCallbackKind::PlmnList.registration_offset(), 1)
            .unwrap_or_else(|_| std::process::abort());

        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(0x1122_3344);
        let request = SdkApiRequest {
            command: SdkCommand::PlmnList as u16,
            device_id: 0x1122_3344,
            params: &[],
        };
        bridge
            .handle_sdk_api(&mut server, &mut modem, id, request)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(bridge.pending_count(), 1);
        assert!(matches!(
            bridge.handle_sdk_api(&mut server, &mut modem, id, request),
            Err(HandleError::Tracked(_))
        ));
        assert_eq!(read_api_ret(&mut server, id), 1);

        let partial = vec![
            0xb1, 0x0c, 0x00, 0x12, 0x00, 0x12, 0x03, 0x62, 0xf0, 0x10, 0x13, 0x04, 0x00, 0x00,
            0x00, 0x07, 0x14, 0x04, 0x00, 0x00, 0x00, 0x09,
        ];
        assert_eq!(
            route_one_hci(&mut bridge, &mut server, partial),
            Some(BroadcastReport {
                registered_clients: 1,
                sent_clients: 1,
            })
        );
        assert_eq!(bridge.pending_count(), 1);

        let mut frame = [0_u8; 64];
        let len = client
            .recv(&mut frame)
            .unwrap_or_else(|_| std::process::abort());
        let packet = Packet::parse(&frame[..len]).unwrap_or_else(|_| std::process::abort());
        let callback = SdkCallback::parse(packet).unwrap_or_else(|_| std::process::abort());
        assert_eq!(callback.callback_id, 45);
        assert_eq!(callback.device_id, 0x1122_3344);
        assert_eq!(
            callback.data,
            &[
                0x00, 0x00, 0x00, 0x00, 0x01, 0x62, 0xf0, 0x10, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00,
                0x00, 0x09,
            ]
        );

        let terminal = vec![
            0xb1, 0x0c, 0x00, 0x23, 0x01, 0x14, 0x04, 0x00, 0x00, 0x00, 0x03, 0x12, 0x03, 0x21,
            0x43, 0x65, 0x13, 0x04, 0x00, 0x00, 0x00, 0x02, 0x12, 0x03, 0x13, 0x37, 0x42, 0x13,
            0x04, 0x00, 0x00, 0x00, 0x05, 0x14, 0x04, 0x00, 0x00, 0x00, 0x06,
        ];
        assert_eq!(
            route_one_hci(&mut bridge, &mut server, terminal),
            Some(BroadcastReport {
                registered_clients: 1,
                sent_clients: 1,
            })
        );
        assert_eq!(bridge.pending_count(), 0);

        let len = client
            .recv(&mut frame)
            .unwrap_or_else(|_| std::process::abort());
        let packet = Packet::parse(&frame[..len]).unwrap_or_else(|_| std::process::abort());
        let callback = SdkCallback::parse(packet).unwrap_or_else(|_| std::process::abort());
        assert_eq!(callback.callback_id, 45);
        assert_eq!(callback.device_id, 0x1122_3344);
        assert_eq!(
            callback.data,
            &[
                0x01, 0x00, 0x00, 0x00, 0x02, 0x21, 0x43, 0x65, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
                0x00, 0x03, 0x13, 0x37, 0x42, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x06,
            ]
        );

        bridge
            .handle_sdk_api(&mut server, &mut modem, id, request)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(read_api_ret(&mut server, id), 0);
        assert_eq!(bridge.pending_count(), 1);
    }

    #[test]
    fn result_callback_reaches_only_registered_stock_clients() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (registered_client, registered_id) = open_client(&mut server, &dir, 0);
        let (unregistered_client, _unregistered_id) = open_client(&mut server, &dir, 1);
        server
            .client_context(registered_id)
            .unwrap_or_else(|_| std::process::abort())
            .write_u32_be(SdkCallbackKind::Online.registration_offset(), 0x1234_5678)
            .unwrap_or_else(|_| std::process::abort());

        let report = broadcast_result_callback(
            &mut server,
            ResultResponseKind::Online,
            0x1122_3344,
            ResultResponse {
                result: 0xaabb_ccdd,
            },
        )
        .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            report,
            BroadcastReport {
                registered_clients: 1,
                sent_clients: 1,
            }
        );

        let mut frame = [0_u8; 16];
        let len = registered_client
            .recv(&mut frame)
            .unwrap_or_else(|_| std::process::abort());
        let packet = Packet::parse(&frame[..len]).unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            SdkCallback::parse(packet),
            Ok(SdkCallback {
                callback_id: 59,
                device_id: 0x1122_3344,
                data: &[0xaa, 0xbb, 0xcc, 0xdd],
            })
        );

        unregistered_client
            .set_nonblocking(true)
            .unwrap_or_else(|_| std::process::abort());
        let mut nothing = [0_u8; 16];
        let Err(error) = unregistered_client.recv(&mut nothing) else {
            std::process::abort();
        };
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn each_result_kind_uses_its_recovered_callback_id_and_slot() {
        let cases = [
            (ResultResponseKind::Online, SdkCallbackKind::Online, 59),
            (ResultResponseKind::Offline, SdkCallbackKind::Offline, 62),
            (ResultResponseKind::PsInit, SdkCallbackKind::PsInit, 68),
        ];
        for (number, (kind, callback_kind, callback_id)) in cases.into_iter().enumerate() {
            let dir = TestDir::new();
            let mut server = bind_server(&dir);
            let (client, id) = open_client(&mut server, &dir, number);
            server
                .client_context(id)
                .unwrap_or_else(|_| std::process::abort())
                .write_u32_be(callback_kind.registration_offset(), 1)
                .unwrap_or_else(|_| std::process::abort());
            broadcast_result_callback(&mut server, kind, 7, ResultResponse { result: 9 })
                .unwrap_or_else(|_| std::process::abort());
            let mut frame = [0_u8; 16];
            let len = client
                .recv(&mut frame)
                .unwrap_or_else(|_| std::process::abort());
            let packet = Packet::parse(&frame[..len]).unwrap_or_else(|_| std::process::abort());
            let callback = SdkCallback::parse(packet).unwrap_or_else(|_| std::process::abort());
            assert_eq!(callback.callback_id, callback_id);
            assert_eq!(callback.device_id, 7);
            assert_eq!(callback.data, 9_u32.to_be_bytes());
        }
    }

    #[test]
    fn result_response_uses_stable_device_id_and_releases_pending_family() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (client, id) = open_client(&mut server, &dir, 0);
        server
            .client_context(id)
            .unwrap_or_else(|_| std::process::abort())
            .write_u32_be(SdkCallbackKind::Online.registration_offset(), 1)
            .unwrap_or_else(|_| std::process::abort());
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(0x1122_3344);
        let request = SdkApiRequest {
            command: SdkCommand::Online as u16,
            device_id: 0x1122_3344,
            params: &[],
        };
        bridge
            .handle_sdk_api(&mut server, &mut modem, id, request)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(bridge.pending_count(), 1);

        let duplicate = bridge.handle_sdk_api(&mut server, &mut modem, id, request);
        assert!(matches!(duplicate, Err(HandleError::Tracked(_))));
        assert_eq!(read_api_ret(&mut server, id), 1);
        assert_eq!(bridge.pending_count(), 1);

        let event = ModemEvent::Result {
            kind: ResultResponseKind::Online,
            response: ResultResponse { result: 7 },
        };
        let report = bridge
            .handle_modem_event(&mut server, &event)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            report,
            Some(BroadcastReport {
                registered_clients: 1,
                sent_clients: 1,
            })
        );
        assert_eq!(bridge.pending_count(), 0);

        let mut frame = [0_u8; 16];
        let len = client
            .recv(&mut frame)
            .unwrap_or_else(|_| std::process::abort());
        let packet = Packet::parse(&frame[..len]).unwrap_or_else(|_| std::process::abort());
        let callback = SdkCallback::parse(packet).unwrap_or_else(|_| std::process::abort());
        assert_eq!(callback.callback_id, 59);
        assert_eq!(callback.device_id, 0x1122_3344);
        assert_eq!(callback.data, 7_u32.to_be_bytes());

        bridge
            .handle_sdk_api(&mut server, &mut modem, id, request)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(read_api_ret(&mut server, id), 0);
    }

    #[test]
    fn request_for_another_physical_device_fails_before_glif_write() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (_client, id) = open_client(&mut server, &dir, 0);
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(7);
        let request = SdkApiRequest {
            command: SdkCommand::PsInit as u16,
            device_id: 8,
            params: &[],
        };
        assert!(matches!(
            bridge.handle_sdk_api(&mut server, &mut modem, id, request),
            Err(HandleError::UnknownDevice {
                requested: 8,
                expected: 7,
            })
        ));
        assert_eq!(read_api_ret(&mut server, id), 1);
        assert_eq!(bridge.pending_count(), 0);
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            Vec::<u8>::new()
        );
    }

    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "test failure"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn failed_modem_write_returns_one_to_stock_client() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (_client, id) = open_client(&mut server, &dir, 0);
        let mut modem = Modem::new(HciIo::new(FailingWriter));
        let mut bridge = DeviceBridge::new(1);
        let request = SdkApiRequest {
            command: SdkCommand::Online as u16,
            device_id: 1,
            params: &[],
        };
        assert!(matches!(
            bridge.handle_sdk_api(&mut server, &mut modem, id, request),
            Err(HandleError::Tracked(_))
        ));
        assert_eq!(read_api_ret(&mut server, id), 1);
    }

    #[test]
    fn minimal_stock_attach_ignores_dead_legacy_fields() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (_client, id) = open_client(&mut server, &dir, 0);
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(1);
        let mut params = [0xff_u8; 352];
        params[0] = 0;
        let request = SdkApiRequest {
            command: SdkCommand::Attach as u16,
            device_id: 1,
            params: &params,
        };

        let call = bridge
            .handle_sdk_api(&mut server, &mut modem, id, request)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(call.command, SdkCommand::Attach);
        assert_eq!(call.bytes_written, 5);
        assert_eq!(read_api_ret(&mut server, id), 0);
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            [0x31, 0x01, 0x00, 0x01, 0x00]
        );
    }

    fn stock_attach_ext_params() -> [u8; 484] {
        let mut params = [0_u8; 484];
        params[0] = 1;
        params[1] = 2;
        params[2] = 3;
        params[3..6].copy_from_slice(b"ims");
        params[103] = 4;
        params[104] = b'u';
        params[168] = b'p';
        params[232] = 5;
        params[233..242].copy_from_slice(&[1, 2, 3, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        params[242] = 6;
        params[243] = 7;
        params[244..247].copy_from_slice(b"net");
        params[344] = 8;
        params[345] = b'r';
        params[409] = b's';
        params[473] = 9;
        params[474..483].copy_from_slice(&[10, 11, 12, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc]);
        params[483] = 0xee;
        params
    }

    #[test]
    fn stock_attach_ext_layout_translates_to_exact_live_p4_hci() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (_client, id) = open_client(&mut server, &dir, 0);
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(1);
        let params = stock_attach_ext_params();
        let request = SdkApiRequest {
            command: SdkCommand::AttachExt as u16,
            device_id: 1,
            params: &params,
        };
        let call = bridge
            .handle_sdk_api(&mut server, &mut modem, id, request)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(call.command, SdkCommand::AttachExt);
        assert_eq!(call.bytes_written, 73);
        assert_eq!(read_api_ret(&mut server, id), 0);
        assert_eq!(bridge.pending_count(), 1);
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            [
                0x31, 0x65, 0x00, 0x45, 0x01, 0x01, 0x01, 0x02, 0x20, 0x01, 0x03, 0x04, 0x03, b'i',
                b'm', b's', 0x05, 0x01, 0x04, 0x02, 0x01, b'u', 0x03, 0x01, b'p', 0x1e, 0x01, 0x05,
                0x21, 0x09, 1, 2, 3, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x01, 0x01, 0x06, 0x20,
                0x01, 0x07, 0x04, 0x03, b'n', b'e', b't', 0x05, 0x01, 0x08, 0x02, 0x01, b'r', 0x03,
                0x01, b's', 0x1e, 0x01, 0x09, 0x21, 0x09, 10, 11, 12, 0x77, 0x88, 0x99, 0xaa, 0xbb,
                0xcc,
            ]
        );
    }

    #[test]
    fn malformed_stock_attach_ext_is_rejected_before_modem_write() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (_client, id) = open_client(&mut server, &dir, 0);
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(1);
        let mut params = stock_attach_ext_params();
        params[3..103].fill(b'a');
        let request = SdkApiRequest {
            command: SdkCommand::AttachExt as u16,
            device_id: 1,
            params: &params,
        };
        assert!(matches!(
            bridge.handle_sdk_api(&mut server, &mut modem, id, request),
            Err(HandleError::LegacyAttachExt(
                LegacyAttachExtDecodeError::MissingTerminator(
                    LegacyAttachExtStringField::PrimaryApn
                )
            ))
        ));
        assert_eq!(read_api_ret(&mut server, id), 1);
        assert_eq!(bridge.pending_count(), 0);
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            Vec::<u8>::new()
        );

        assert_eq!(
            decode_legacy_attach_ext(&[0_u8; 483]),
            Err(LegacyAttachExtDecodeError::UnexpectedLength {
                expected: 484,
                actual: 483
            })
        );
    }

    #[test]
    fn attach_ext_response_materializes_exact_stock_callback_and_subscription_gate() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (subscribed, subscribed_id) = open_client(&mut server, &dir, 0);
        let (unsubscribed, _unsubscribed_id) = open_client(&mut server, &dir, 1);
        server
            .client_context(subscribed_id)
            .unwrap_or_else(|_| std::process::abort())
            .write_u32_be(SdkCallbackKind::AttachExt.registration_offset(), 1)
            .unwrap_or_else(|_| std::process::abort());

        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(0x1122_3344);
        let mut params = [0_u8; 484];
        params[0] = 0;
        bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                subscribed_id,
                SdkApiRequest {
                    command: SdkCommand::AttachExt as u16,
                    device_id: 0x1122_3344,
                    params: &params,
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(bridge.pending_count(), 1);

        let payload = [
            0x00, 0x01, 0x00, 0x02, 0x12, 0x34, 0x56, 0x78, 0x09, 0x0a, 1, 2, 3, 4, 5, 0x20, 0x01,
            0x07, 0x57, 0x03, b'i', b'm', b's', 0x58, 0x03, b'n', b'e', b't', 0xf0, 0x14, 0x04,
            0x03, b'p', b'd', b'n', 0x05, 0x01, 0x02, 0x07, 0x04, 192, 168, 1, 2, 0x40, 0x04, 0, 0,
            0, 9, 0xaa, 0x00,
        ];
        let mut hci = Vec::with_capacity(payload.len() + 4);
        hci.extend_from_slice(&[0xb1, 0x66]);
        hci.extend_from_slice(
            &u16::try_from(payload.len())
                .unwrap_or_else(|_| std::process::abort())
                .to_be_bytes(),
        );
        hci.extend_from_slice(&payload);
        assert_eq!(
            route_one_hci(&mut bridge, &mut server, hci),
            Some(BroadcastReport {
                registered_clients: 1,
                sent_clients: 1
            })
        );
        assert_eq!(bridge.pending_count(), 0);

        let mut frame = [0_u8; 720];
        let len = subscribed
            .recv(&mut frame)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(len, 12 + 700);
        let packet = Packet::parse(&frame[..len]).unwrap_or_else(|_| std::process::abort());
        let callback = SdkCallback::parse(packet).unwrap_or_else(|_| std::process::abort());
        assert_eq!(callback.callback_id, 28);
        assert_eq!(callback.device_id, 0x1122_3344);
        assert_eq!(callback.data.len(), 700);
        let data = callback.data;
        assert_eq!(&data[0..4], &[0, 1, 0, 2]);
        assert_eq!(data[4], 3);
        assert_eq!(&data[5..8], b"ims");
        assert_eq!(data[69], 3);
        assert_eq!(&data[70..73], b"net");
        assert_eq!(&data[134..136], &0x1234_u16.to_be_bytes());
        assert_eq!(&data[136..138], &0x5678_u16.to_be_bytes());
        assert_eq!(&data[138..141], &[9, 10, 7]);
        assert_eq!(&data[141..144], b"pdn");
        assert_eq!(data[141 + 0x80], 2);
        assert_eq!(&data[141 + 0x85..141 + 0x89], &[192, 168, 1, 2]);
        assert_eq!(&data[141 + 0x216..141 + 0x21a], &9_u32.to_be_bytes());
        assert_eq!(&data[695..700], &[1, 2, 3, 4, 5]);

        unsubscribed
            .set_nonblocking(true)
            .unwrap_or_else(|_| std::process::abort());
        let mut no_frame = [0_u8; 1];
        let Err(error) = unsubscribed.recv(&mut no_frame) else {
            std::process::abort();
        };
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn stock_attach_layout_translates_to_exact_live_p4_hci() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (_client, id) = open_client(&mut server, &dir, 0);
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(1);
        let mut params = [0_u8; 352];
        params[0x000] = 1;
        params[0x001] = 7;
        params[0x002..0x00a].copy_from_slice(b"internet");
        params[0x066] = 3;
        params[0x067] = 1;
        params[0x068] = b'u';
        params[0x0a8] = b'p';
        params[0x0e8] = 2;
        params[0x0e9] = 1;
        params[0x0ea..0x0ec].copy_from_slice(&0x1234_u16.to_be_bytes());
        params[0x0ec] = 1;
        params[0x0ed] = 2;
        params[0x0ee..0x0f0].copy_from_slice(&[0xaa, 0xbb]);
        params[0x152] = 0;
        params[0x153] = 4;
        params[0x154] = 5;
        params[0x155] = 0;
        params[0x156] = 1;
        params[0x157] = 0;
        params[0x158] = 1;
        params[0x159..0x15b].copy_from_slice(&20_u16.to_be_bytes());
        params[0x15b..0x15d].copy_from_slice(&300_u16.to_be_bytes());
        params[0x15d..0x15f].copy_from_slice(&10_u16.to_be_bytes());
        params[0x15f] = 1;
        let request = SdkApiRequest {
            command: SdkCommand::Attach as u16,
            device_id: 1,
            params: &params,
        };

        let call = bridge
            .handle_sdk_api(&mut server, &mut modem, id, request)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(call.command, SdkCommand::Attach);
        assert_eq!(call.bytes_written, 71);
        assert_eq!(read_api_ret(&mut server, id), 0);
        assert_eq!(bridge.pending_count(), 1);
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            [
                0x31, 0x01, 0x00, 0x43, 0x01, 0x20, 0x01, 0x07, 0x02, 0x01, 0x75, 0x03, 0x01, 0x70,
                0x04, 0x08, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x1e, 0x01, 0x02, 0x05,
                0x01, 0x03, 0x01, 0x01, 0x01, 0x5c, 0x02, 0x12, 0x34, 0x5d, 0x02, 0xaa, 0xbb, 0x5f,
                0x01, 0x04, 0x60, 0x01, 0x05, 0x70, 0x01, 0x03, 0x62, 0x01, 0x00, 0xf5, 0x02, 0x01,
                0x00, 0xf6, 0x01, 0x01, 0x71, 0x06, 0x00, 0x14, 0x01, 0x2c, 0x00, 0x0a, 0xf7, 0x01,
                0x01,
            ]
        );
    }

    #[test]
    fn attach_response_materializes_exact_stock_callback_and_subscription_gate() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (subscribed, subscribed_id) = open_client(&mut server, &dir, 0);
        let (unsubscribed, _unsubscribed_id) = open_client(&mut server, &dir, 1);
        server
            .client_context(subscribed_id)
            .unwrap_or_else(|_| std::process::abort())
            .write_u32_be(SdkCallbackKind::Attach.registration_offset(), 1)
            .unwrap_or_else(|_| std::process::abort());

        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(0x1122_3344);
        let mut params = [0_u8; 352];
        params[0] = 1;
        params[1] = 7;
        bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                subscribed_id,
                SdkApiRequest {
                    command: SdkCommand::Attach as u16,
                    device_id: 0x1122_3344,
                    params: &params,
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(bridge.pending_count(), 1);

        let payload = [
            0x00, 0x01, 0x00, 0x02, 0x12, 0x34, 0x56, 0x78, 0x09, 0x0a, 1, 2, 3, 4, 5, 0x20, 0x01,
            0x07, 0x99, 0x03, b'i', b'm', b's', 0xf0, 0x1a, 0x04, 0x03, b'p', b'd', b'n', 0x05,
            0x01, 0x02, 0x06, 0x04, 0xde, 0xad, 0xbe, 0xef, 0x07, 0x04, 192, 168, 1, 2, 0x40, 0x04,
            0x00, 0x00, 0x00, 0x09, 0x58, 0x01, 0xaa, 0x59, 0x01, 0xbb, 0x5a, 0x01, 0xcc, 0x5b,
            0x02, 0x05, 0xdc, 0x5d, 0x03, 0x11, 0x22, 0x33, 0x5e, 0x04, 0x01, 0x02, 0x03, 0x04,
            0xf3, 0x08, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0xc8, 0xf4, 0x05, 0x04, 0x09,
            b'1', b'1', b'2', 0xf8, 0x05, b'1', b'2', b'3', b'4', b'5',
        ];
        let mut hci = Vec::with_capacity(payload.len() + 4);
        hci.extend_from_slice(&[0xb1, 0x02]);
        hci.extend_from_slice(
            &u16::try_from(payload.len())
                .unwrap_or_else(|_| std::process::abort())
                .to_be_bytes(),
        );
        hci.extend_from_slice(&payload);

        assert_eq!(
            route_one_hci(&mut bridge, &mut server, hci),
            Some(BroadcastReport {
                registered_clients: 1,
                sent_clients: 1,
            })
        );
        assert_eq!(bridge.pending_count(), 0);

        let mut frame = [0_u8; 2200];
        let len = subscribed
            .recv(&mut frame)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(len, 12 + 0x88b);
        let packet = Packet::parse(&frame[..len]).unwrap_or_else(|_| std::process::abort());
        let callback = SdkCallback::parse(packet).unwrap_or_else(|_| std::process::abort());
        assert_eq!(callback.callback_id, 26);
        assert_eq!(callback.device_id, 0x1122_3344);
        assert_eq!(callback.data.len(), 0x88b);
        let data = callback.data;
        assert_eq!(
            &data[0x000..0x00a],
            &[0, 1, 0, 2, 0x12, 0x34, 0x56, 0x78, 9, 10]
        );
        assert_eq!(data[0x00a], 3);
        assert_eq!(&data[0x00b..0x00e], b"ims");
        assert_eq!(&data[0x04b..0x04e], b"pdn");
        assert_eq!(data[0x0cb], 2);
        assert_eq!(&data[0x0cc..0x0d0], &0xdead_beef_u32.to_be_bytes());
        assert_eq!(&data[0x0d0..0x0d4], &[192, 168, 1, 2]);
        assert_eq!(&data[0x261..0x265], &9_u32.to_be_bytes());
        assert_eq!(&data[0x275..0x27a], &[1, 2, 3, 4, 5]);
        assert_eq!(data[0x27a], 7);
        assert_eq!(&data[0x27b..0x27e], &[0xaa, 0xbb, 0xcc]);
        assert_eq!(&data[0x27e..0x280], &1500_u16.to_be_bytes());
        assert_eq!(&data[0x280..0x285], &[1, 3, 0x11, 0x22, 0x33]);
        assert_eq!(&data[0x2e6..0x2ea], &0x0102_0304_u32.to_be_bytes());
        assert_eq!(&data[0x2ea..0x2ee], &100_u32.to_be_bytes());
        assert_eq!(&data[0x2ee..0x2f2], &200_u32.to_be_bytes());
        assert_eq!(data[0x2f2], 1);
        assert_eq!(&data[0x2f3..0x2f8], &[4, 9, b'1', b'1', b'2']);
        assert_eq!(data[0x875], 5);
        assert_eq!(&data[0x876..0x87b], b"12345");
        assert!(data[0x87b..].iter().all(|&byte| byte == 0));

        unsubscribed
            .set_nonblocking(true)
            .unwrap_or_else(|_| std::process::abort());
        let mut no_frame = [0_u8; 1];
        let Err(error) = unsubscribed.recv(&mut no_frame) else {
            std::process::abort();
        };
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn stock_pdn_connect_allocates_first_free_tid_and_matches_live_p4_hci() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (_client, id) = open_client(&mut server, &dir, 0);
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(1);

        let mut params = [0_u8; 0x1a4];
        params[0x000] = 0x11;
        params[0x001] = 1;
        params[0x002..0x005].copy_from_slice(b"ims");
        params[0x066] = 2;
        params[0x067] = 3;
        params[0x068] = b'u';
        params[0x0cc] = b'p';
        params[0x130] = 4;
        params[0x131] = 1;
        params[0x132..0x134].copy_from_slice(&0x1234_u16.to_be_bytes());
        params[0x134] = 1;
        params[0x135] = 2;
        params[0x136..0x138].copy_from_slice(&[0xaa, 0xbb]);
        params[0x19a] = 1;
        params[0x19b] = 5;
        params[0x19c..0x19e].copy_from_slice(&10_u16.to_be_bytes());
        params[0x19e..0x1a0].copy_from_slice(&20_u16.to_be_bytes());
        params[0x1a0..0x1a2].copy_from_slice(&30_u16.to_be_bytes());
        params[0x1a2] = 6;
        params[0x1a3] = 0xfe;

        let request = SdkApiRequest {
            command: SdkCommand::PdnConnect as u16,
            device_id: 1,
            params: &params,
        };
        let first = bridge
            .handle_sdk_api(&mut server, &mut modem, id, request)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(first.bytes_written, 54);
        assert_eq!(bridge.pending_count(), 1);

        let second = bridge
            .handle_sdk_api(&mut server, &mut modem, id, request)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(second.bytes_written, 54);
        assert_eq!(bridge.pending_count(), 2);

        let mut expected = vec![
            0x31, 0x05, 0x00, 0x32, 0x11, 0x01, 0x20, 0x01, 0x01, 0x04, 0x03, b'i', b'm', b's',
            0x02, 0x01, b'u', 0x03, 0x01, b'p', 0x05, 0x01, 0x02, 0x1e, 0x01, 0x04, 0x01, 0x01,
            0x03, 0x5c, 0x02, 0x12, 0x34, 0x5d, 0x02, 0xaa, 0xbb, 0xf6, 0x01, 0x05, 0x71, 0x06,
            0x00, 0x0a, 0x00, 0x14, 0x00, 0x1e, 0xf7, 0x01, 0x06, 0x70, 0x01, 0x01,
        ];
        let mut expected_second = expected.clone();
        expected_second[8] = 2;
        expected.extend_from_slice(&expected_second);
        assert_eq!(modem.into_transport().into_inner().into_inner(), expected);
    }

    #[test]
    fn malformed_stock_pdn_connect_is_rejected_before_modem_write() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (_client, id) = open_client(&mut server, &dir, 0);
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(1);
        let mut params = [0_u8; 0x1a4];
        params[0x002..0x066].fill(0xff);

        let request = SdkApiRequest {
            command: SdkCommand::PdnConnect as u16,
            device_id: 1,
            params: &params,
        };
        assert!(matches!(
            bridge.handle_sdk_api(&mut server, &mut modem, id, request),
            Err(HandleError::LegacyPdnConnect(
                LegacyPdnConnectDecodeError::MissingTerminator(LegacyPdnConnectStringField::Apn)
            ))
        ));
        assert_eq!(read_api_ret(&mut server, id), 1);
        assert_eq!(bridge.pending_count(), 0);
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn pdn_connect_response_materializes_exact_stock_callback_and_subscription_gate() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (subscribed, subscribed_id) = open_client(&mut server, &dir, 0);
        let (unsubscribed, _unsubscribed_id) = open_client(&mut server, &dir, 1);
        server
            .client_context(subscribed_id)
            .unwrap_or_else(|_| std::process::abort())
            .write_u32_be(SdkCallbackKind::PdnConnect.registration_offset(), 1)
            .unwrap_or_else(|_| std::process::abort());

        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(0x1122_3344);
        let mut params = [0_u8; 0x1a4];
        params[0] = 1;
        params[2..5].copy_from_slice(b"ims");
        params[0x19a] = 1;
        params[0x1a3] = 0xfe;
        bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                subscribed_id,
                SdkApiRequest {
                    command: SdkCommand::PdnConnect as u16,
                    device_id: 0x1122_3344,
                    params: &params,
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(bridge.pending_count(), 1);

        let payload = [
            0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x12, 0x34, 0x09, 0x0a, 0x20, 0x01, 0x01, 0x99,
            0x03, b'i', b'm', b's', 0xf0, 0x14, 0x04, 0x03, b'p', b'd', b'n', 0x05, 0x01, 0x02,
            0x07, 0x04, 192, 168, 1, 2, 0x40, 0x04, 0x00, 0x00, 0x00, 0x09, 0x5b, 0x02, 0x05, 0xdc,
            0x5d, 0x03, 0x11, 0x22, 0x33, 0xf0, 0x06, 0x08, 0x04, 1, 1, 1, 1, 0xf3, 0x08, 0x00,
            0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0xc8,
        ];
        let mut hci = Vec::with_capacity(payload.len() + 4);
        hci.extend_from_slice(&[0xb1, 0x06]);
        hci.extend_from_slice(
            &u16::try_from(payload.len())
                .unwrap_or_else(|_| std::process::abort())
                .to_be_bytes(),
        );
        hci.extend_from_slice(&payload);

        assert_eq!(
            route_one_hci(&mut bridge, &mut server, hci),
            Some(BroadcastReport {
                registered_clients: 1,
                sent_clients: 1,
            })
        );
        assert_eq!(bridge.pending_count(), 0);

        let mut frame = [0_u8; 800];
        let len = subscribed
            .recv(&mut frame)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(len, 12 + 0x2e6);
        let packet = Packet::parse(&frame[..len]).unwrap_or_else(|_| std::process::abort());
        let callback = SdkCallback::parse(packet).unwrap_or_else(|_| std::process::abort());
        assert_eq!(callback.callback_id, 33);
        assert_eq!(callback.device_id, 0x1122_3344);
        assert_eq!(callback.data.len(), 0x2e6);
        let data = callback.data;
        assert_eq!(&data[0x000..0x00a], &[0, 1, 0, 2, 0, 3, 0x12, 0x34, 9, 10]);
        assert_eq!(data[0x00a], 1);
        assert_eq!(data[0x00b], 3);
        assert_eq!(&data[0x00c..0x00f], b"ims");
        assert_eq!(&data[0x04c..0x04f], b"pdn");
        assert_eq!(data[0x0cc], 2);
        assert_eq!(&data[0x0d1..0x0d5], &[192, 168, 1, 2]);
        assert_eq!(&data[0x0d5..0x0d9], &[1, 1, 1, 1]);
        assert_eq!(&data[0x262..0x266], &9_u32.to_be_bytes());
        assert_eq!(&data[0x276..0x278], &1500_u16.to_be_bytes());
        assert_eq!(&data[0x278..0x27d], &[1, 3, 0x11, 0x22, 0x33]);
        assert_eq!(&data[0x2de..0x2e2], &100_u32.to_be_bytes());
        assert_eq!(&data[0x2e2..0x2e6], &200_u32.to_be_bytes());

        unsubscribed
            .set_nonblocking(true)
            .unwrap_or_else(|_| std::process::abort());
        let mut no_frame = [0_u8; 1];
        let Err(error) = unsubscribed.recv(&mut no_frame) else {
            std::process::abort();
        };
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn stock_plmn_search_stop_matches_live_p4_hci() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (_client, id) = open_client(&mut server, &dir, 0);
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(1);

        let call = bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                id,
                SdkApiRequest {
                    command: SdkCommand::PlmnSearchStop as u16,
                    device_id: 1,
                    params: &[3],
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(call.bytes_written, 5);
        assert_eq!(bridge.pending_count(), 1);
        assert!(bridge.pending.contains(ResponseKey::PlmnSearchStop(3)));
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            [0x31, 0x27, 0x00, 0x01, 0x03]
        );
    }

    #[test]
    fn malformed_stock_plmn_search_stop_is_rejected_before_modem_write() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (_client, id) = open_client(&mut server, &dir, 0);
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(1);

        assert!(matches!(
            bridge.handle_sdk_api(
                &mut server,
                &mut modem,
                id,
                SdkApiRequest {
                    command: SdkCommand::PlmnSearchStop as u16,
                    device_id: 1,
                    params: &[],
                },
            ),
            Err(HandleError::UnexpectedParameters {
                command: 63,
                expected: 1,
                actual: 0
            })
        ));
        assert_eq!(read_api_ret(&mut server, id), 1);
        assert_eq!(bridge.pending_count(), 0);
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn plmn_search_stop_response_materializes_exact_stock_callback_and_subscription_gate() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (subscribed, subscribed_id) = open_client(&mut server, &dir, 0);
        let (unsubscribed, _unsubscribed_id) = open_client(&mut server, &dir, 1);
        server
            .client_context(subscribed_id)
            .unwrap_or_else(|_| std::process::abort())
            .write_u32_be(SdkCallbackKind::PlmnSearchStop.registration_offset(), 1)
            .unwrap_or_else(|_| std::process::abort());

        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(0x1122_3344);
        bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                subscribed_id,
                SdkApiRequest {
                    command: SdkCommand::PlmnSearchStop as u16,
                    device_id: 0x1122_3344,
                    params: &[3],
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(bridge.pending_count(), 1);

        let hci = vec![0xb1, 0x28, 0x00, 0x05, 0x03, 0x11, 0x22, 0x33, 0x44];
        assert_eq!(
            route_one_hci(&mut bridge, &mut server, hci),
            Some(BroadcastReport {
                registered_clients: 1,
                sent_clients: 1,
            })
        );
        assert_eq!(bridge.pending_count(), 0);

        let mut frame = [0_u8; 32];
        let len = subscribed
            .recv(&mut frame)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(len, 17);
        let packet = Packet::parse(&frame[..len]).unwrap_or_else(|_| std::process::abort());
        let callback = SdkCallback::parse(packet).unwrap_or_else(|_| std::process::abort());
        assert_eq!(callback.callback_id, 64);
        assert_eq!(callback.device_id, 0x1122_3344);
        assert_eq!(callback.data, &[0x03, 0x11, 0x22, 0x33, 0x44]);

        unsubscribed
            .set_nonblocking(true)
            .unwrap_or_else(|_| std::process::abort());
        let mut no_frame = [0_u8; 1];
        let Err(error) = unsubscribed.recv(&mut no_frame) else {
            std::process::abort();
        };
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn stock_plmn_search_matches_live_p4_hci() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (_client, id) = open_client(&mut server, &dir, 0);
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(1);
        let params = [1, 2, 6, 0, 0, 1, 0x0f, 3, 4];

        let call = bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                id,
                SdkApiRequest {
                    command: SdkCommand::PlmnSearch as u16,
                    device_id: 1,
                    params: &params,
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(call.bytes_written, 14);
        assert_eq!(bridge.pending_count(), 1);
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            [
                0x31, 0x09, 0x00, 0x0a, 0x01, 0x62, 0xf0, 0x10, 0x62, 0x01, 0x03, 0x63, 0x01, 0x04,
            ]
        );
    }

    #[test]
    fn malformed_stock_plmn_search_is_rejected_before_modem_write() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (_client, id) = open_client(&mut server, &dir, 0);
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(1);
        let params = [0_u8; 8];

        assert!(matches!(
            bridge.handle_sdk_api(
                &mut server,
                &mut modem,
                id,
                SdkApiRequest {
                    command: SdkCommand::PlmnSearch as u16,
                    device_id: 1,
                    params: &params,
                },
            ),
            Err(HandleError::UnexpectedParameters {
                command: 40,
                expected: 9,
                actual: 8
            })
        ));
        assert_eq!(read_api_ret(&mut server, id), 1);
        assert_eq!(bridge.pending_count(), 0);
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn plmn_search_response_materializes_exact_stock_callback_and_subscription_gate() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (subscribed, subscribed_id) = open_client(&mut server, &dir, 0);
        let (unsubscribed, _unsubscribed_id) = open_client(&mut server, &dir, 1);
        server
            .client_context(subscribed_id)
            .unwrap_or_else(|_| std::process::abort())
            .write_u32_be(SdkCallbackKind::PlmnSearch.registration_offset(), 1)
            .unwrap_or_else(|_| std::process::abort());

        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(0x1122_3344);
        let params = [1, 2, 6, 0, 0, 1, 0x0f, 3, 4];
        bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                subscribed_id,
                SdkApiRequest {
                    command: SdkCommand::PlmnSearch as u16,
                    device_id: 0x1122_3344,
                    params: &params,
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(bridge.pending_count(), 1);

        let payload = [
            0x00, 0x00, 0x00, 0x00, 0x02, 0x62, 0xf0, 0x10, 0x00, 0x11, 0x00, 0x1e, 0xfe, 0x00,
            0x03, 0x12, 0x34, 0x00, 0x00, 0x18, 0x9c, 0xaa, 0xbb, 0x01, 0x23, 0x45, 0x67, 0x13,
            0x04, 0x00, 0x00, 0x00, 0x07, 0x26, 0x04, 0x01, 0x62, 0xf0, 0x10, 0x12, 0x03, 0x62,
            0xf0, 0x10, 0x13, 0x04, 0x00, 0x00, 0x00, 0x01, 0x14, 0x04, 0x00, 0x00, 0x00, 0x02,
        ];
        let mut hci = Vec::with_capacity(payload.len() + 4);
        hci.extend_from_slice(&[0xb1, 0x0a]);
        hci.extend_from_slice(
            &u16::try_from(payload.len())
                .unwrap_or_else(|_| std::process::abort())
                .to_be_bytes(),
        );
        hci.extend_from_slice(&payload);

        assert_eq!(
            route_one_hci(&mut bridge, &mut server, hci),
            Some(BroadcastReport {
                registered_clients: 1,
                sent_clients: 1,
            })
        );
        assert_eq!(bridge.pending_count(), 0);

        let mut frame = [0_u8; 512];
        let len = subscribed
            .recv(&mut frame)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(len, 12 + 436);
        let packet = Packet::parse(&frame[..len]).unwrap_or_else(|_| std::process::abort());
        let callback = SdkCallback::parse(packet).unwrap_or_else(|_| std::process::abort());
        assert_eq!(callback.callback_id, 41);
        assert_eq!(callback.device_id, 0x1122_3344);
        assert_eq!(callback.data.len(), 436);
        let data = callback.data;
        assert_eq!(&data[0..27], &payload[0..27]);
        assert_eq!(&data[27..31], &1_u32.to_be_bytes());
        assert_eq!(&data[31..34], &[0x62, 0xf0, 0x10]);
        assert_eq!(&data[34..38], &1_u32.to_be_bytes());
        assert_eq!(&data[38..42], &2_u32.to_be_bytes());
        assert!(data[42..383].iter().all(|&byte| byte == 0));
        assert_eq!(&data[383..387], &7_u32.to_be_bytes());
        assert_eq!(data[387], 1);
        assert_eq!(&data[388..391], &[0x62, 0xf0, 0x10]);
        assert!(data[391..].iter().all(|&byte| byte == 0));

        unsubscribed
            .set_nonblocking(true)
            .unwrap_or_else(|_| std::process::abort());
        let mut no_frame = [0_u8; 1];
        let Err(error) = unsubscribed.recv(&mut no_frame) else {
            std::process::abort();
        };
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn stock_pdn_disconnect_allocates_tid_and_matches_live_p4_hci() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (_client, id) = open_client(&mut server, &dir, 0);
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(1);

        let params = [0x12, 0x34, 0xfe, 3, b'i', b'm', b's'];
        let request = SdkApiRequest {
            command: SdkCommand::PdnDisconnect as u16,
            device_id: 1,
            params: &params,
        };

        let first = bridge
            .handle_sdk_api(&mut server, &mut modem, id, request)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(first.bytes_written, 14);
        let second = bridge
            .handle_sdk_api(&mut server, &mut modem, id, request)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(second.bytes_written, 14);
        assert_eq!(bridge.pending_count(), 2);

        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            [
                0x31, 0x07, 0x00, 0x0a, 0x12, 0x34, 0x20, 0x01, 0x01, 0x57, 0x03, b'i', b'm', b's',
                0x31, 0x07, 0x00, 0x0a, 0x12, 0x34, 0x20, 0x01, 0x02, 0x57, 0x03, b'i', b'm', b's',
            ]
        );
    }

    #[test]
    fn malformed_stock_pdn_disconnect_is_rejected_before_modem_write() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (_client, id) = open_client(&mut server, &dir, 0);
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(1);
        let params = [0, 0, 0xfe, 65];

        let request = SdkApiRequest {
            command: SdkCommand::PdnDisconnect as u16,
            device_id: 1,
            params: &params,
        };
        assert!(matches!(
            bridge.handle_sdk_api(&mut server, &mut modem, id, request),
            Err(HandleError::LegacyPdnDisconnect(
                LegacyPdnDisconnectDecodeError::ApnTooLong {
                    maximum: 64,
                    actual: 65
                }
            ))
        ));
        assert_eq!(read_api_ret(&mut server, id), 1);
        assert_eq!(bridge.pending_count(), 0);
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            Vec::<u8>::new()
        );

        assert_eq!(
            decode_legacy_pdn_disconnect(&[0, 1, 0xfe, 3, b'i'], 1),
            Err(LegacyPdnDisconnectDecodeError::LengthMismatch {
                expected: 7,
                actual: 5,
            })
        );
    }

    #[test]
    fn pdn_disconnect_response_materializes_exact_stock_callback_and_subscription_gate() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (subscribed, subscribed_id) = open_client(&mut server, &dir, 0);
        let (unsubscribed, _unsubscribed_id) = open_client(&mut server, &dir, 1);
        server
            .client_context(subscribed_id)
            .unwrap_or_else(|_| std::process::abort())
            .write_u32_be(SdkCallbackKind::PdnDisconnect.registration_offset(), 1)
            .unwrap_or_else(|_| std::process::abort());

        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(0x1122_3344);
        let params = [0x12, 0x34, 0xfe, 3, b'i', b'm', b's'];
        bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                subscribed_id,
                SdkApiRequest {
                    command: SdkCommand::PdnDisconnect as u16,
                    device_id: 0x1122_3344,
                    params: &params,
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(bridge.pending_count(), 1);

        let payload = [
            0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x12, 0x34, 0x20, 0x01, 0x01, 0x57, 0x03, b'i',
            b'm', b's', 0x5d, 0x03, 0x11, 0x22, 0x33,
        ];
        let mut hci = Vec::with_capacity(payload.len() + 4);
        hci.extend_from_slice(&[0xb1, 0x08]);
        hci.extend_from_slice(
            &u16::try_from(payload.len())
                .unwrap_or_else(|_| std::process::abort())
                .to_be_bytes(),
        );
        hci.extend_from_slice(&payload);

        assert_eq!(
            route_one_hci(&mut bridge, &mut server, hci),
            Some(BroadcastReport {
                registered_clients: 1,
                sent_clients: 1,
            })
        );
        assert_eq!(bridge.pending_count(), 0);

        let mut frame = [0_u8; 256];
        let len = subscribed
            .recv(&mut frame)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(len, 12 + 0xb0);
        let packet = Packet::parse(&frame[..len]).unwrap_or_else(|_| std::process::abort());
        let callback = SdkCallback::parse(packet).unwrap_or_else(|_| std::process::abort());
        assert_eq!(callback.callback_id, 37);
        assert_eq!(callback.device_id, 0x1122_3344);
        assert_eq!(callback.data.len(), 0xb0);
        let data = callback.data;
        assert_eq!(&data[0x000..0x008], &[0, 1, 0, 2, 0, 3, 0x12, 0x34]);
        assert_eq!(data[0x008], 1);
        assert_eq!(data[0x009], 3);
        assert_eq!(&data[0x00a..0x00d], b"ims");
        assert_eq!(&data[0x04a..0x04f], &[1, 3, 0x11, 0x22, 0x33]);
        assert!(data[0x04f..].iter().all(|&byte| byte == 0));

        unsubscribed
            .set_nonblocking(true)
            .unwrap_or_else(|_| std::process::abort());
        let mut no_frame = [0_u8; 1];
        let Err(error) = unsubscribed.recv(&mut no_frame) else {
            std::process::abort();
        };
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn stock_detach_matches_live_p4_hci_and_cleans_pdn_transaction_state() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (_client, id) = open_client(&mut server, &dir, 0);
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(1);
        bridge
            .pending
            .try_insert(ResponseKey::PdnConnect(7))
            .unwrap_or_else(|_| std::process::abort());
        bridge
            .pending
            .try_insert(ResponseKey::PdnDisconnect(9))
            .unwrap_or_else(|_| std::process::abort());

        let params = [0x11, 0x22, 0x33, 0x44];
        let call = bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                id,
                SdkApiRequest {
                    command: SdkCommand::Detach as u16,
                    device_id: 1,
                    params: &params,
                },
            )
            .unwrap_or_else(|_| std::process::abort());

        assert_eq!(call.bytes_written, 8);
        assert_eq!(bridge.pending_count(), 1);
        assert!(bridge.pending.contains(ResponseKey::Detach));
        assert!(!bridge.pending.contains(ResponseKey::PdnConnect(7)));
        assert!(!bridge.pending.contains(ResponseKey::PdnDisconnect(9)));
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            [0x31, 0x03, 0x00, 0x04, 0x11, 0x22, 0x33, 0x44]
        );
    }

    #[test]
    fn malformed_stock_detach_is_rejected_before_modem_write() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (_client, id) = open_client(&mut server, &dir, 0);
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(1);
        let params = [0x11, 0x22, 0x33];

        assert!(matches!(
            bridge.handle_sdk_api(
                &mut server,
                &mut modem,
                id,
                SdkApiRequest {
                    command: SdkCommand::Detach as u16,
                    device_id: 1,
                    params: &params,
                },
            ),
            Err(HandleError::UnexpectedParameters {
                command: 29,
                expected: 4,
                actual: 3
            })
        ));
        assert_eq!(read_api_ret(&mut server, id), 1);
        assert_eq!(bridge.pending_count(), 0);
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn detach_response_materializes_exact_stock_callback_and_subscription_gate() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (subscribed, subscribed_id) = open_client(&mut server, &dir, 0);
        let (unsubscribed, _unsubscribed_id) = open_client(&mut server, &dir, 1);
        server
            .client_context(subscribed_id)
            .unwrap_or_else(|_| std::process::abort())
            .write_u32_be(SdkCallbackKind::Detach.registration_offset(), 1)
            .unwrap_or_else(|_| std::process::abort());

        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(0x1122_3344);
        bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                subscribed_id,
                SdkApiRequest {
                    command: SdkCommand::Detach as u16,
                    device_id: 0x1122_3344,
                    params: &[0, 0, 0, 1],
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(bridge.pending_count(), 1);

        let hci = vec![
            0xb1, 0x04, 0x00, 0x08, 0x01, 0x02, 0x03, 0x04, 0x11, 0x22, 0x33, 0x44,
        ];
        assert_eq!(
            route_one_hci(&mut bridge, &mut server, hci),
            Some(BroadcastReport {
                registered_clients: 1,
                sent_clients: 1,
            })
        );
        assert_eq!(bridge.pending_count(), 0);

        let mut frame = [0_u8; 32];
        let len = subscribed
            .recv(&mut frame)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(len, 20);
        let packet = Packet::parse(&frame[..len]).unwrap_or_else(|_| std::process::abort());
        let callback = SdkCallback::parse(packet).unwrap_or_else(|_| std::process::abort());
        assert_eq!(callback.callback_id, 30);
        assert_eq!(callback.device_id, 0x1122_3344);
        assert_eq!(
            callback.data,
            &[0x01, 0x02, 0x03, 0x04, 0x11, 0x22, 0x33, 0x44]
        );

        unsubscribed
            .set_nonblocking(true)
            .unwrap_or_else(|_| std::process::abort());
        let mut no_frame = [0_u8; 1];
        let Err(error) = unsubscribed.recv(&mut no_frame) else {
            std::process::abort();
        };
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn malformed_stock_attach_is_rejected_before_modem_write() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (_client, id) = open_client(&mut server, &dir, 0);
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(1);
        let params = [0xff_u8; 352];
        let request = SdkApiRequest {
            command: SdkCommand::Attach as u16,
            device_id: 1,
            params: &params,
        };

        assert!(matches!(
            bridge.handle_sdk_api(&mut server, &mut modem, id, request),
            Err(HandleError::LegacyAttach(
                LegacyAttachDecodeError::MissingTerminator(LegacyAttachStringField::Apn)
            ))
        ));
        assert_eq!(read_api_ret(&mut server, id), 1);
        assert_eq!(bridge.pending_count(), 0);
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn oversized_operator_pco_is_rejected_by_legacy_decoder() {
        let mut params = [0_u8; 352];
        params[0] = 1;
        params[0x0ec] = 1;
        params[0x0ed] = 101;
        assert_eq!(
            decode_legacy_attach(&params),
            Err(LegacyAttachDecodeError::OperatorPcoTooLong {
                maximum: 100,
                actual: 101,
            })
        );
    }

    #[test]
    fn unexpected_legacy_payload_is_rejected_before_modem_write() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (_client, id) = open_client(&mut server, &dir, 0);
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(1);
        let request = SdkApiRequest {
            command: SdkCommand::PsInit as u16,
            device_id: 1,
            params: &[0xaa],
        };
        assert!(matches!(
            bridge.handle_sdk_api(&mut server, &mut modem, id, request),
            Err(HandleError::UnexpectedParameters {
                command,
                expected: 0,
                actual: 1,
            }) if command == SdkCommand::PsInit as u16
        ));
        assert_eq!(read_api_ret(&mut server, id), 1);
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            Vec::<u8>::new()
        );
    }
}
