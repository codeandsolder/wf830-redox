//! Stock callback frame assembly and routing.
//!
//! Pure historical-memory decoding/materialization lives in `legacy`; this
//! module owns callback-envelope construction and delegates client delivery to
//! `delivery`. It has no modem transport or daemon-loop responsibility.

use std::io;

use gct_lapi::{
    attach::{AttachExtResponse, AttachResponse, DetachRequiredIndication, DetachResponse},
    common::{ResultResponse, ResultResponseKind},
    emm::{ContentsResetAndDeleteResponse, EmmReattachControlReport, UeModeChangeResponse},
    misc::{IccidReadResponse, MobileIdReadResponse, MsisdnReadResponse, TemperatureReadResponse},
    pdn::{PdnConnectExtResponse, PdnConnectResponse, PdnDisconnectResponse},
    plmn::{
        PlmnListResponse, PlmnSearchResponse, PlmnSearchStopResponse, QuerySelectedPlmnResponse,
    },
    rf::{RfMeasureReportIndication, RfMeasureReportResponse, RfStatusReportControlResponse},
    rrc::{
        RrcCapabilityGetResponse, RrcCapabilitySetResponse, RrcFunctionResponse,
        SetProtocolInfoResponse,
    },
    uicc::{UiccResponse, uicc_control},
};
use lted_compat::Server;
use lted_proto::{SdkCallback, SdkCallbackKind};

use crate::{
    HandleError,
    delivery::{BroadcastReport, broadcast_registered},
    legacy::{
        STOCK_ATTACH_CALLBACK_DATA_LEN, STOCK_ATTACH_CALLBACK_FRAME_LEN,
        STOCK_ATTACH_EXT_CALLBACK_DATA_LEN, STOCK_ATTACH_EXT_CALLBACK_FRAME_LEN,
        STOCK_PDN_CONNECT_CALLBACK_DATA_LEN, STOCK_PDN_CONNECT_CALLBACK_FRAME_LEN,
        STOCK_PDN_CONNECT_EXT_CALLBACK_DATA_LEN, STOCK_PDN_CONNECT_EXT_CALLBACK_FRAME_LEN,
        STOCK_PDN_DISCONNECT_CALLBACK_DATA_LEN, STOCK_PDN_DISCONNECT_CALLBACK_FRAME_LEN,
        materialize_attach_callback, materialize_attach_ext_callback,
        materialize_pdn_connect_callback, materialize_pdn_connect_ext_callback,
        materialize_pdn_disconnect_callback,
    },
};

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
pub(crate) fn broadcast_attach_callback(
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

    broadcast_registered(server, callback_kind, &frame[..frame_len]).map_err(HandleError::from)
}

/// Materialize and broadcast live-P4 stock callback 28 (`Attach EXT`).
///
/// Live P4 sends the exact 700-byte `_ATTACH_RSP_EXT_INFO` image and resolves
/// callback 28 through `cb_rsp[3]` (registration offset `0x1c`).
///
/// # Errors
/// Returns [`HandleError::AttachExtCallback`] for malformed proven nested PDN
/// fields or [`HandleError::Ipc`] for callback/shared-context/socket failures.
pub(crate) fn broadcast_attach_ext_callback(
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

    broadcast_registered(server, callback_kind, &frame[..frame_len]).map_err(HandleError::from)
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
pub(crate) fn broadcast_detach_callback(
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

    broadcast_registered(server, callback_kind, &frame[..frame_len]).map_err(HandleError::from)
}

const STOCK_DETACH_REQUIRED_CALLBACK_DATA_LEN: usize = 4;
const STOCK_DETACH_REQUIRED_CALLBACK_FRAME_LEN: usize =
    12 + STOCK_DETACH_REQUIRED_CALLBACK_DATA_LEN;

/// Broadcast live-P4 stock callback 31 (`Detach Required`).
///
/// The modem indication `0xb16a` carries one big-endian `detach_type:u32`.
/// Live P4 `ind_detach_required_indication` passes selector 31 to the daemon
/// callback assembler; the unchanged stock client dispatches it through
/// `cb_rsp[5]` (registration offset `0x2c`). B014 DWARF independently fixes
/// `_DETACH_REQ_IND_INFO` at exactly four bytes.
///
/// # Errors
/// Returns [`HandleError::Ipc`] for callback/shared-context/socket failures.
pub(crate) fn broadcast_detach_required_callback(
    server: &mut Server,
    device_id: u32,
    indication: DetachRequiredIndication,
) -> Result<BroadcastReport, HandleError> {
    let data = indication.detach_type.to_be_bytes();
    let callback_kind = SdkCallbackKind::DetachRequired;
    let mut frame = [0_u8; STOCK_DETACH_REQUIRED_CALLBACK_FRAME_LEN];
    let frame_len = SdkCallback {
        callback_id: callback_kind.callback_id(),
        device_id,
        data: &data,
    }
    .encode(&mut frame)
    .map_err(|_| {
        HandleError::Ipc(io::Error::new(
            io::ErrorKind::InvalidData,
            "fixed-size Detach Required callback failed to encode",
        ))
    })?;

    broadcast_registered(server, callback_kind, &frame[..frame_len]).map_err(HandleError::from)
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
pub(crate) fn broadcast_pdn_connect_callback(
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

    broadcast_registered(server, callback_kind, &frame[..frame_len]).map_err(HandleError::from)
}

/// Materialize and broadcast live-P4 stock callback 35 (`PDNConn EXT`).
///
/// B014 DWARF fixes `_PDN_CONNECTIVITY_RSP_EXT_INFO` at 697 bytes. Live P4
/// emits callback 35, and the stock client maps that selector to `cb_rsp[7]`
/// (registration offset `0x3c`).
///
/// # Errors
/// Returns [`HandleError::PdnConnectExtCallback`] for malformed proven nested
/// PDN fields or [`HandleError::Ipc`] for callback/shared-context/socket
/// failures.
pub(crate) fn broadcast_pdn_connect_ext_callback(
    server: &mut Server,
    device_id: u32,
    response: PdnConnectExtResponse<'_>,
) -> Result<BroadcastReport, HandleError> {
    let mut data = [0_u8; STOCK_PDN_CONNECT_EXT_CALLBACK_DATA_LEN];
    materialize_pdn_connect_ext_callback(response, &mut data)
        .map_err(HandleError::PdnConnectExtCallback)?;
    let callback_kind = SdkCallbackKind::PdnConnectExt;
    let mut frame = [0_u8; STOCK_PDN_CONNECT_EXT_CALLBACK_FRAME_LEN];
    let frame_len = SdkCallback {
        callback_id: callback_kind.callback_id(),
        device_id,
        data: &data,
    }
    .encode(&mut frame)
    .map_err(|_| {
        HandleError::Ipc(io::Error::new(
            io::ErrorKind::InvalidData,
            "fixed-size extended PDN-connect callback failed to encode",
        ))
    })?;

    broadcast_registered(server, callback_kind, &frame[..frame_len]).map_err(HandleError::from)
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
pub(crate) fn broadcast_pdn_disconnect_callback(
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

    broadcast_registered(server, callback_kind, &frame[..frame_len]).map_err(HandleError::from)
}

const MAX_PLMN_RECORDS: usize = 32;
const STOCK_PLMN_RECORD_LEN: usize = 11;
const STOCK_PLMN_PREFIX_LEN: usize = 5;
const MAX_PLMN_CALLBACK_DATA_LEN: usize =
    STOCK_PLMN_PREFIX_LEN + MAX_PLMN_RECORDS * STOCK_PLMN_RECORD_LEN;
const MAX_PLMN_CALLBACK_FRAME_LEN: usize = 12 + MAX_PLMN_CALLBACK_DATA_LEN;

pub(crate) fn broadcast_variable_callback(
    server: &mut Server,
    device_id: u32,
    callback_kind: SdkCallbackKind,
    data: &[u8],
) -> Result<BroadcastReport, HandleError> {
    let total = 12_usize.checked_add(data.len()).ok_or_else(|| {
        HandleError::Ipc(io::Error::new(
            io::ErrorKind::InvalidData,
            "stock callback length overflow",
        ))
    })?;
    let mut frame = vec![0_u8; total];
    let frame_len = SdkCallback {
        callback_id: callback_kind.callback_id(),
        device_id,
        data,
    }
    .encode(&mut frame)
    .map_err(|_| {
        HandleError::Ipc(io::Error::new(
            io::ErrorKind::InvalidData,
            "stock callback exceeds recovered 16-bit local envelope",
        ))
    })?;

    broadcast_registered(server, callback_kind, &frame[..frame_len]).map_err(HandleError::from)
}

/// Broadcast stock callback 54 through `cb_rsp[16]` (`0x84`).
pub(crate) fn broadcast_query_selected_plmn_callback(
    server: &mut Server,
    device_id: u32,
    response: QuerySelectedPlmnResponse,
) -> Result<BroadcastReport, HandleError> {
    let data = [
        response.result,
        response.selected_plmn[0],
        response.selected_plmn[1],
        response.selected_plmn[2],
    ];
    broadcast_variable_callback(server, device_id, SdkCallbackKind::QuerySelectedPlmn, &data)
}

/// Broadcast stock callback 225 through `cb_rsp[117]` (`0x3ac`).
/// Stock `lted` deliberately discards any response data and exposes only
/// `result:u16 | len:u16 | type:u16`.
pub(crate) fn broadcast_rrc_function_set_callback(
    server: &mut Server,
    device_id: u32,
    response: RrcFunctionResponse<'_>,
) -> Result<BroadcastReport, HandleError> {
    let len = u16::try_from(response.data.len()).map_err(|_| {
        HandleError::Ipc(io::Error::new(
            io::ErrorKind::InvalidData,
            "RRC-function data too long",
        ))
    })?;
    let mut data = [0_u8; 6];
    data[0..2].copy_from_slice(&response.result.to_be_bytes());
    data[2..4].copy_from_slice(&len.to_be_bytes());
    data[4..6].copy_from_slice(&response.type_id.to_be_bytes());
    broadcast_variable_callback(
        server,
        device_id,
        SdkCallbackKind::RrcFunctionControl,
        &data,
    )
}

/// Broadcast stock callback 227 through `cb_rsp[118]` (`0x3b4`).
/// The live daemon consumes the normalized local image
/// `result:u16 | type:u16 | len:u16 | data[len]`.
pub(crate) fn broadcast_rrc_function_get_callback(
    server: &mut Server,
    device_id: u32,
    response: RrcFunctionResponse<'_>,
) -> Result<BroadcastReport, HandleError> {
    let len = u16::try_from(response.data.len()).map_err(|_| {
        HandleError::Ipc(io::Error::new(
            io::ErrorKind::InvalidData,
            "RRC-function data too long",
        ))
    })?;
    let mut data = Vec::with_capacity(6 + response.data.len());
    data.extend_from_slice(&response.result.to_be_bytes());
    data.extend_from_slice(&response.type_id.to_be_bytes());
    data.extend_from_slice(&len.to_be_bytes());
    data.extend_from_slice(response.data);
    broadcast_variable_callback(
        server,
        device_id,
        SdkCallbackKind::RrcFunctionControlGet,
        &data,
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RrcCapabilityCallbackError {
    DataTooLong(usize),
    Type4ListTruncated {
        count: u8,
        minimum_data_len: usize,
        actual_data_len: usize,
    },
}

fn validate_rrc_capability_get_callback(
    response: RrcCapabilityGetResponse<'_>,
) -> Result<(), RrcCapabilityCallbackError> {
    if response.result != 0 || response.type_id != 4 {
        return Ok(());
    }
    let Some(&count) = response.data.first() else {
        return Err(RrcCapabilityCallbackError::Type4ListTruncated {
            count: 0,
            minimum_data_len: 1,
            actual_data_len: 0,
        });
    };
    let minimum_data_len = 1_usize.saturating_add(usize::from(count).saturating_mul(2));
    if response.data.len() < minimum_data_len {
        return Err(RrcCapabilityCallbackError::Type4ListTruncated {
            count,
            minimum_data_len,
            actual_data_len: response.data.len(),
        });
    }
    Ok(())
}

/// Broadcast live-P4 callback 221 through `cb_rsp[115]` (`0x39c`).
///
/// The daemon exposes only the normalized six-byte `result,len,type` header;
/// the SDK's set-response data buffer never crosses the stock local callback
/// boundary.
///
/// # Errors
/// Returns [`HandleError::RrcCapabilityCallback`] if the data length cannot be
/// represented by the stock u16 field, or [`HandleError::Ipc`] for callback
/// encoding/shared-context/socket failures.
pub(crate) fn broadcast_rrc_capability_set_callback(
    server: &mut Server,
    device_id: u32,
    response: RrcCapabilitySetResponse<'_>,
) -> Result<BroadcastReport, HandleError> {
    let len = u16::try_from(response.data.len()).map_err(|_| {
        HandleError::RrcCapabilityCallback(RrcCapabilityCallbackError::DataTooLong(
            response.data.len(),
        ))
    })?;
    let mut data = [0_u8; 6];
    data[0..2].copy_from_slice(&response.result.to_be_bytes());
    data[2..4].copy_from_slice(&len.to_be_bytes());
    data[4..6].copy_from_slice(&response.type_id.to_be_bytes());
    broadcast_variable_callback(
        server,
        device_id,
        SdkCallbackKind::RrcCapabilityControl,
        &data,
    )
}

/// Broadcast live-P4 callback 223 through `cb_rsp[116]` (`0x3a4`).
///
/// The stock callback image is `result,type,len,data[len]`. Type 4 contains a
/// count followed by u16 entries; validate its minimum extent before exposing
/// bytes so the clean daemon cannot reproduce the OEM parser's possible
/// over-read.
///
/// # Errors
/// Returns [`HandleError::RrcCapabilityCallback`] for an unsafe type-4 list or
/// unrepresentable data length, or [`HandleError::Ipc`] for callback
/// encoding/shared-context/socket failures.
pub(crate) fn broadcast_rrc_capability_get_callback(
    server: &mut Server,
    device_id: u32,
    response: RrcCapabilityGetResponse<'_>,
) -> Result<BroadcastReport, HandleError> {
    validate_rrc_capability_get_callback(response).map_err(HandleError::RrcCapabilityCallback)?;
    let len = u16::try_from(response.data.len()).map_err(|_| {
        HandleError::RrcCapabilityCallback(RrcCapabilityCallbackError::DataTooLong(
            response.data.len(),
        ))
    })?;
    let mut data = Vec::with_capacity(6 + response.data.len());
    data.extend_from_slice(&response.result.to_be_bytes());
    data.extend_from_slice(&response.type_id.to_be_bytes());
    data.extend_from_slice(&len.to_be_bytes());
    data.extend_from_slice(response.data);
    broadcast_variable_callback(
        server,
        device_id,
        SdkCallbackKind::RrcCapabilityControlGet,
        &data,
    )
}

/// Broadcast live-P4 callback 178 through `cb_rsp[90]` (`0x2d4`).
///
/// Live daemon DWARF fixes `_SET_PROTOCOL_INFO_RSP` at five bytes:
/// `result:u16 | ps_info_type:u16 | value:u8`. The SDK response buffer is
/// zero-initialized, so a failure or zero-length success exposes value zero;
/// otherwise only the first converted data byte crosses this legacy boundary.
///
/// # Errors
/// Returns [`HandleError::Ipc`] for callback encoding/shared-context/socket
/// failures.
pub(crate) fn broadcast_set_protocol_info_callback(
    server: &mut Server,
    device_id: u32,
    response: SetProtocolInfoResponse<'_>,
) -> Result<BroadcastReport, HandleError> {
    let mut data = [0_u8; 5];
    data[0..2].copy_from_slice(&response.result.to_be_bytes());
    data[2..4].copy_from_slice(&response.type_id.to_be_bytes());
    if response.result == 0 {
        data[4] = response.data.first().copied().unwrap_or(0);
    }
    broadcast_variable_callback(server, device_id, SdkCallbackKind::SetProtocolInfo, &data)
}

/// Broadcast callback 126 (`AT_COMMAND_FROM_DEVICE`) as raw command bytes.
///
/// The live stock client reconstructs its historical `{cmd pointer, length}`
/// object locally from this variable callback payload, so no pointer-bearing C
/// layout crosses the daemon boundary.
///
/// # Errors
/// Returns [`HandleError::Ipc`] for an unrepresentable callback length or an
/// IPC/socket failure.
pub(crate) fn broadcast_at_callback(
    server: &mut Server,
    device_id: u32,
    command: &[u8],
) -> Result<BroadcastReport, HandleError> {
    broadcast_variable_callback(
        server,
        device_id,
        SdkCallbackKind::AtCommandFromDevice,
        command,
    )
}

/// Broadcast callback 128 (`AT_COMMAND_FROM_DEVICE_EXT`) as
/// `[channel, command...]`.
///
/// The stock client converts that local payload back into its historical
/// `{channel, cmd pointer, length}` view before invoking the registered callback.
///
/// # Errors
/// Returns [`HandleError::Ipc`] for an unrepresentable callback length or an
/// IPC/socket failure.
pub(crate) fn broadcast_at_ext_callback(
    server: &mut Server,
    device_id: u32,
    channel: u8,
    command: &[u8],
) -> Result<BroadcastReport, HandleError> {
    let mut data = Vec::with_capacity(1 + command.len());
    data.push(channel);
    data.extend_from_slice(command);
    broadcast_variable_callback(
        server,
        device_id,
        SdkCallbackKind::AtCommandFromDeviceExt,
        &data,
    )
}

const STOCK_UICC_PREFIX_LEN: usize = 6;
const STOCK_UICC_READ_BINARY_RSP_LEN: usize = 2038;
const STOCK_UICC_READ_RECORD_RSP_MAX_LEN: usize = 2038;

/// Broadcast stock callback 77 (`MOBILE_ID_READ_RSP`) through `cb_rsp[26]`.
///
/// Live P4 `lted` sends exactly `5 + len` bytes from the historical 21-byte
/// object: `read_result:u16 | id_type:u8 | result:u8 | len:u8 | id[len]`.
///
/// # Errors
/// Returns [`HandleError::Ipc`] for an unrepresentable local callback or IPC
/// failure.
pub(crate) fn broadcast_mobile_id_callback(
    server: &mut Server,
    device_id: u32,
    response: MobileIdReadResponse<'_>,
) -> Result<BroadcastReport, HandleError> {
    let id_len = u8::try_from(response.id.len()).map_err(|_| {
        HandleError::Ipc(io::Error::new(
            io::ErrorKind::InvalidData,
            "Mobile ID exceeds stock one-byte length",
        ))
    })?;
    let mut data = Vec::with_capacity(5 + response.id.len());
    data.extend_from_slice(&response.read_result.to_be_bytes());
    data.push(response.id_type);
    data.push(response.result);
    data.push(id_len);
    data.extend_from_slice(response.id);
    broadcast_variable_callback(server, device_id, SdkCallbackKind::MobileIdRead, &data)
}

/// Broadcast stock callback 83 (`TEMPERATURE_READ_RSP`) through `cb_rsp[29]`.
///
/// Live P4 forwards the exact four-byte historical object
/// `read_result:u16 | result:u8 | temperature:s8`.
///
/// # Errors
/// Returns [`HandleError::Ipc`] for local IPC failures.
pub(crate) fn broadcast_temperature_callback(
    server: &mut Server,
    device_id: u32,
    response: TemperatureReadResponse,
) -> Result<BroadcastReport, HandleError> {
    let read_result = response.read_result.to_be_bytes();
    let data = [
        read_result[0],
        read_result[1],
        response.result,
        response.temperature.cast_unsigned(),
    ];
    broadcast_variable_callback(server, device_id, SdkCallbackKind::TemperatureRead, &data)
}

/// Broadcast stock callback 79 (`ICCID_READ_RSP`) through `cb_rsp[27]`.
///
/// Live P4 forwards the exact 13-byte historical object
/// `read_result:u16 | result:u8 | iccid[10]`.
///
/// # Errors
/// Returns [`HandleError::Ipc`] for a malformed typed response or IPC failure.
pub(crate) fn broadcast_iccid_callback(
    server: &mut Server,
    device_id: u32,
    response: IccidReadResponse<'_>,
) -> Result<BroadcastReport, HandleError> {
    if response.iccid.len() != 10 {
        return Err(HandleError::Ipc(io::Error::new(
            io::ErrorKind::InvalidData,
            "ICCID callback requires the recovered fixed 10-byte ICCID",
        )));
    }
    let mut data = [0_u8; 13];
    data[..2].copy_from_slice(&response.read_result.to_be_bytes());
    data[2] = response.result;
    data[3..].copy_from_slice(response.iccid);
    broadcast_variable_callback(server, device_id, SdkCallbackKind::IccidRead, &data)
}

/// Broadcast stock callback 81 (`MSISDN_READ_RSP`) through `cb_rsp[28]`.
///
/// Live P4 `lted` sends `read_result:u16 | result:u8 | num_msisdn:u8`
/// followed by exactly `num_msisdn * 256` fixed record bytes.
///
/// # Errors
/// Returns [`HandleError::Ipc`] for an unrepresentable callback length or IPC
/// failure.
pub(crate) fn broadcast_msisdn_callback(
    server: &mut Server,
    device_id: u32,
    response: MsisdnReadResponse<'_>,
) -> Result<BroadcastReport, HandleError> {
    if !response
        .records
        .len()
        .is_multiple_of(gct_lapi::misc::MSISDN_RECORD_LEN)
        || response.records.len()
            > gct_lapi::misc::MAX_MSISDN_RECORDS * gct_lapi::misc::MSISDN_RECORD_LEN
    {
        return Err(HandleError::Ipc(io::Error::new(
            io::ErrorKind::InvalidData,
            "MSISDN callback record block violates the recovered 3 x 256-byte layout",
        )));
    }
    let num_msisdn = u8::try_from(response.num_msisdn()).map_err(|_| {
        HandleError::Ipc(io::Error::new(
            io::ErrorKind::InvalidData,
            "MSISDN record count exceeds stock one-byte field",
        ))
    })?;
    let mut data = Vec::with_capacity(4 + response.records.len());
    data.extend_from_slice(&response.read_result.to_be_bytes());
    data.push(response.result);
    data.push(num_msisdn);
    data.extend_from_slice(response.records);
    broadcast_variable_callback(server, device_id, SdkCallbackKind::MsisdnRead, &data)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UiccCallbackError {
    UnsupportedKind(u16),
    UnexpectedSubtypeLength {
        kind: u16,
        expected: usize,
        actual: usize,
    },
    EmbeddedLengthMismatch {
        kind: u16,
        declared: usize,
        actual: usize,
    },
    AuthenticationFieldTooLong {
        offset: usize,
        maximum: usize,
        actual: usize,
    },
    LegacyObjectTooLong {
        kind: u16,
        maximum: usize,
        actual: usize,
    },
}

fn require_uicc_callback_len(
    kind: u16,
    data: &[u8],
    expected: usize,
) -> Result<usize, UiccCallbackError> {
    if data.len() != expected {
        return Err(UiccCallbackError::UnexpectedSubtypeLength {
            kind,
            expected,
            actual: data.len(),
        });
    }
    Ok(STOCK_UICC_PREFIX_LEN + expected)
}

fn validate_uicc_read_binary(data: &[u8]) -> Result<usize, UiccCallbackError> {
    if data.len() < 10 {
        return Err(UiccCallbackError::UnexpectedSubtypeLength {
            kind: uicc_control::READ_BINARY,
            expected: 10,
            actual: data.len(),
        });
    }
    let declared = usize::from(u16::from_be_bytes([data[8], data[9]]));
    let actual = data.len() - 10;
    if declared != actual {
        return Err(UiccCallbackError::EmbeddedLengthMismatch {
            kind: uicc_control::READ_BINARY,
            declared,
            actual,
        });
    }
    if data.len() > STOCK_UICC_READ_BINARY_RSP_LEN {
        return Err(UiccCallbackError::LegacyObjectTooLong {
            kind: uicc_control::READ_BINARY,
            maximum: STOCK_UICC_READ_BINARY_RSP_LEN,
            actual: data.len(),
        });
    }
    Ok(STOCK_UICC_PREFIX_LEN + STOCK_UICC_READ_BINARY_RSP_LEN)
}

fn validate_uicc_read_record(data: &[u8]) -> Result<usize, UiccCallbackError> {
    if data.len() < 11 {
        return Err(UiccCallbackError::UnexpectedSubtypeLength {
            kind: uicc_control::READ_RECORD,
            expected: 11,
            actual: data.len(),
        });
    }
    let one_len = usize::from(data[9]);
    let record_count = usize::from(data[10]);
    let declared = if data[8] == 0 {
        one_len
            .checked_mul(record_count)
            .ok_or(UiccCallbackError::LegacyObjectTooLong {
                kind: uicc_control::READ_RECORD,
                maximum: STOCK_UICC_READ_RECORD_RSP_MAX_LEN - 11,
                actual: usize::MAX,
            })?
    } else {
        one_len
    };
    let actual = data.len() - 11;
    if declared != actual {
        return Err(UiccCallbackError::EmbeddedLengthMismatch {
            kind: uicc_control::READ_RECORD,
            declared,
            actual,
        });
    }
    if data.len() > STOCK_UICC_READ_RECORD_RSP_MAX_LEN {
        return Err(UiccCallbackError::LegacyObjectTooLong {
            kind: uicc_control::READ_RECORD,
            maximum: STOCK_UICC_READ_RECORD_RSP_MAX_LEN,
            actual: data.len(),
        });
    }
    Ok(STOCK_UICC_PREFIX_LEN + data.len())
}

fn validate_uicc_authenticate(data: &[u8]) -> Result<usize, UiccCallbackError> {
    require_uicc_callback_len(uicc_control::AUTHENTICATE, data, 86)?;
    for (offset, maximum) in [(3, 16), (20, 16), (37, 16), (54, 16), (71, 4), (76, 8)] {
        let actual = usize::from(data[offset]);
        if actual > maximum {
            return Err(UiccCallbackError::AuthenticationFieldTooLong {
                offset,
                maximum,
                actual,
            });
        }
    }
    Ok(STOCK_UICC_PREFIX_LEN + 86)
}

fn validate_uicc_callback_response(response: UiccResponse<'_>) -> Result<usize, UiccCallbackError> {
    if response.result != 0 {
        return Ok(STOCK_UICC_PREFIX_LEN);
    }
    match response.kind {
        uicc_control::STATUS => require_uicc_callback_len(response.kind, response.data, 2),
        uicc_control::READ_BINARY => validate_uicc_read_binary(response.data),
        uicc_control::READ_RECORD => validate_uicc_read_record(response.data),
        uicc_control::AUTHENTICATE => validate_uicc_authenticate(response.data),
        uicc_control::PIN_COMMAND => require_uicc_callback_len(response.kind, response.data, 5),
        uicc_control::PIN_STATUS => require_uicc_callback_len(response.kind, response.data, 11),
        _ => Err(UiccCallbackError::UnsupportedKind(response.kind)),
    }
}

/// Broadcast live-P4 stock callback 148 (`UICC_FROM_DEVICE`).
///
/// The modem wire order is `{result,type,len,data}` but stock callback memory is
/// `{result,len,type,data}`. Live P4 zeroes a 2048-byte scratch object before
/// parsing; READ BINARY then deliberately exposes its entire fixed 2038-byte
/// legacy subtype object, including deterministic zero padding.
///
/// # Errors
/// Returns [`HandleError::UiccCallback`] for a malformed proven subtype or
/// [`HandleError::Ipc`] for local callback transport failures.
pub(crate) fn broadcast_uicc_callback(
    server: &mut Server,
    device_id: u32,
    response: UiccResponse<'_>,
) -> Result<BroadcastReport, HandleError> {
    let callback_len =
        validate_uicc_callback_response(response).map_err(HandleError::UiccCallback)?;
    let mut data = vec![0_u8; callback_len];
    data[0..2].copy_from_slice(&response.result.to_be_bytes());
    let raw_len = u16::try_from(response.data.len()).map_err(|_| {
        HandleError::UiccCallback(UiccCallbackError::LegacyObjectTooLong {
            kind: response.kind,
            maximum: usize::from(u16::MAX),
            actual: response.data.len(),
        })
    })?;
    data[2..4].copy_from_slice(&raw_len.to_be_bytes());
    data[4..6].copy_from_slice(&response.kind.to_be_bytes());
    if response.result == 0 {
        data[6..6 + response.data.len()].copy_from_slice(response.data);
    }
    broadcast_variable_callback(server, device_id, SdkCallbackKind::UiccFromDevice, &data)
}

/// Broadcast one of the three proven four-byte result callbacks to every stock
/// client that has the corresponding `cb_rsp[]` function slot registered.
///
/// The callback payload is the original big-endian four-byte modem result, and
/// the local `0x8107` envelope carries the supplied OEM device ID.
///
/// # Errors
/// Returns [`HandleError::Ipc`] for shared-context or UNIX-datagram failures.
pub(crate) fn broadcast_result_callback(
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

    broadcast_registered(server, callback_kind, &frame[..frame_len]).map_err(HandleError::from)
}

/// Broadcast live-P4 callback 308 (`EMM_NI_REATTACH_CTRL_RSP`) through
/// `cb_rsp[159]` as the exact four-byte result object.
///
/// # Errors
/// Returns [`HandleError::Ipc`] for local IPC failures.
pub(crate) fn broadcast_emm_ni_reattach_callback(
    server: &mut Server,
    device_id: u32,
    result: u32,
) -> Result<BroadcastReport, HandleError> {
    broadcast_variable_callback(
        server,
        device_id,
        SdkCallbackKind::EmmNiReattachControl,
        &result.to_be_bytes(),
    )
}

/// Broadcast unsolicited live-P4 callback 309 (`EMM_REATTACH_CTRL_RPT`) through
/// `cb_rsp[160]`. The SDK callback object is exactly six bytes.
///
/// # Errors
/// Returns [`HandleError::Ipc`] for local IPC failures.
pub(crate) fn broadcast_emm_reattach_report_callback(
    server: &mut Server,
    device_id: u32,
    report: EmmReattachControlReport,
) -> Result<BroadcastReport, HandleError> {
    let mut data = [0_u8; 6];
    data[..2].copy_from_slice(&report.prefix.to_be_bytes());
    data[2..].copy_from_slice(&report.value.to_be_bytes());
    broadcast_variable_callback(
        server,
        device_id,
        SdkCallbackKind::EmmReattachControlReport,
        &data,
    )
}

/// Broadcast live-P4 callback 188 (`RF_STATUS_REPORT_CONTROL_RSP`) through
/// `cb_rsp[95]`. The exact stock object is 12 bytes.
///
/// # Errors
/// Returns [`HandleError::Ipc`] for local IPC failures.
pub(crate) fn broadcast_rf_status_report_control_callback(
    server: &mut Server,
    device_id: u32,
    response: RfStatusReportControlResponse,
) -> Result<BroadcastReport, HandleError> {
    let mut data = [0_u8; 12];
    data[0..2].copy_from_slice(&response.result.to_be_bytes());
    data[2..4].copy_from_slice(&response.status.to_be_bytes());
    data[4..6].copy_from_slice(&response.mode.to_be_bytes());
    data[6..8].copy_from_slice(&response.prev_rsrp.to_be_bytes());
    data[8..10].copy_from_slice(&response.cur_rsrp.to_be_bytes());
    data[10..12].copy_from_slice(&response.thresh.to_be_bytes());
    broadcast_variable_callback(
        server,
        device_id,
        SdkCallbackKind::RfStatusReportControl,
        &data,
    )
}

/// Broadcast live-P4 callback 203 (`RF_MEASURE_REPORT_RSP`) through
/// `cb_rsp[106]`. The exact stock object is `result:u16 | status:u16`.
///
/// # Errors
/// Returns [`HandleError::Ipc`] for local IPC failures.
pub(crate) fn broadcast_rf_measure_report_callback(
    server: &mut Server,
    device_id: u32,
    response: RfMeasureReportResponse,
) -> Result<BroadcastReport, HandleError> {
    let mut data = [0_u8; 4];
    data[0..2].copy_from_slice(&response.result.to_be_bytes());
    data[2..4].copy_from_slice(&response.status.to_be_bytes());
    broadcast_variable_callback(server, device_id, SdkCallbackKind::RfMeasureReport, &data)
}

/// Broadcast unsolicited live-P4 callback 204 (`RF_MEASURE_REPORT_IND`) through
/// `cb_rsp[107]`. The exact stock object is 12 bytes.
///
/// # Errors
/// Returns [`HandleError::Ipc`] for local IPC failures.
pub(crate) fn broadcast_rf_measure_report_indication_callback(
    server: &mut Server,
    device_id: u32,
    indication: RfMeasureReportIndication,
) -> Result<BroadcastReport, HandleError> {
    let mut data = [0_u8; 12];
    data[0..2].copy_from_slice(&indication.result.to_be_bytes());
    data[2] = indication.rrc_state;
    data[3] = indication.paging_cycle;
    data[4..6].copy_from_slice(&indication.rssi.to_be_bytes());
    data[6..8].copy_from_slice(&indication.rsrp.to_be_bytes());
    data[8..10].copy_from_slice(&indication.rsrq.to_be_bytes());
    data[10..12].copy_from_slice(&indication.snr.to_be_bytes());
    broadcast_variable_callback(
        server,
        device_id,
        SdkCallbackKind::RfMeasureReportIndication,
        &data,
    )
}

/// Broadcast the exact live-P4 one-byte UE-mode-change callback 162.
///
/// # Errors
/// Returns [`HandleError::Ipc`] for shared-context or UNIX-datagram failures.
pub(crate) fn broadcast_ue_mode_change_callback(
    server: &mut Server,
    device_id: u32,
    response: UeModeChangeResponse,
) -> Result<BroadcastReport, HandleError> {
    broadcast_variable_callback(
        server,
        device_id,
        SdkCallbackKind::UeModeChange,
        &[response.result],
    )
}

/// Broadcast live-P4 callback 66 for contents reset/delete.
///
/// The SDK response converter uses slot 21 and copies exactly one byte; the
/// daemon forwards that object unchanged as stock callback 66.
///
/// # Errors
/// Returns [`HandleError::Ipc`] for local IPC failures.
pub(crate) fn broadcast_contents_reset_and_delete_callback(
    server: &mut Server,
    device_id: u32,
    response: ContentsResetAndDeleteResponse,
) -> Result<BroadcastReport, HandleError> {
    broadcast_variable_callback(
        server,
        device_id,
        SdkCallbackKind::ContentsResetAndDelete,
        &[response.result],
    )
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
pub(crate) fn broadcast_plmn_search_stop_callback(
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
    broadcast_registered(server, callback_kind, &frame[..frame_len]).map_err(HandleError::from)
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
pub(crate) fn broadcast_plmn_search_callback(
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

    broadcast_registered(server, callback_kind, &frame[..frame_len]).map_err(HandleError::from)
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
pub(crate) fn broadcast_plmn_list_callback(
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

    broadcast_registered(server, callback_kind, &frame[..frame_len]).map_err(HandleError::from)
}
