//! Translation layer from the recovered stock `lted` client ABI to typed GCT
//! modem requests.
//!
//! Synchronous SDK-call completion and asynchronous modem callbacks are two
//! separate paths in the OEM design. This crate currently implements the
//! synchronous half for the zero-parameter P0 calls whose wire mapping is fully
//! proven.

use std::{io, io::Write};

mod callbacks;
mod delivery;
pub mod legacy;
mod state;

pub use callbacks::{RrcCapabilityCallbackError, UiccCallbackError};
use callbacks::{
    broadcast_at_callback, broadcast_at_ext_callback, broadcast_attach_callback,
    broadcast_attach_ext_callback, broadcast_contents_reset_and_delete_callback,
    broadcast_detach_callback, broadcast_detach_required_callback,
    broadcast_emm_ni_reattach_callback, broadcast_emm_reattach_report_callback,
    broadcast_iccid_callback, broadcast_mobile_id_callback, broadcast_msisdn_callback,
    broadcast_pdn_connect_callback, broadcast_pdn_connect_ext_callback,
    broadcast_pdn_disconnect_callback, broadcast_plmn_list_callback,
    broadcast_plmn_search_callback, broadcast_plmn_search_stop_callback,
    broadcast_query_selected_plmn_callback, broadcast_result_callback,
    broadcast_rf_measure_report_callback, broadcast_rf_measure_report_indication_callback,
    broadcast_rf_status_report_control_callback, broadcast_rrc_capability_get_callback,
    broadcast_rrc_capability_set_callback, broadcast_rrc_function_get_callback,
    broadcast_rrc_function_set_callback, broadcast_set_protocol_info_callback,
    broadcast_temperature_callback, broadcast_ue_mode_change_callback, broadcast_uicc_callback,
};
pub use delivery::BroadcastReport;
use legacy::{
    AttachCallbackError, AttachExtCallbackError, PdnConnectCallbackError,
    PdnConnectExtCallbackError, PdnDisconnectCallbackError,
};
use legacy::{
    LEGACY_PLMN_SEARCH_EXT_PARAMS_LEN, LEGACY_PLMN_SEARCH_PARAMS_LEN, LegacyAttachDecodeError,
    LegacyAttachExtDecodeError, LegacyPdnConnectDecodeError, LegacyPdnConnectExtDecodeError,
    LegacyPdnDisconnectDecodeError, LegacyRrcCapabilityDecodeError, LegacyRrcFunctionDecodeError,
    LegacySetProtocolInfoDecodeError, LegacyUiccDecodeError, LegacyUiccRequest,
    RRC_FUNCTION_CELL_LOCK_WIRE_LEN, decode_legacy_attach, decode_legacy_attach_ext,
    decode_legacy_pdn_connect, decode_legacy_pdn_connect_ext, decode_legacy_pdn_disconnect,
    decode_legacy_plmn_search, decode_legacy_plmn_search_ext, decode_legacy_rrc_capability_get,
    decode_legacy_rrc_capability_set, decode_legacy_rrc_function_get,
    decode_legacy_rrc_function_set, decode_legacy_set_protocol_info, decode_legacy_special_tid,
    decode_legacy_uicc, materialize_rrc_function_cell_lock_wire,
    rrc_capability_set_success_has_callback,
};
use state::{ApnState, NicState, SpecialTidRecord};
pub use state::{ApnStateError, ConnectionStateError};

use gct_lapi::{
    at::{AtCommand, AtCommandExt},
    attach::{AttachExtResponse, AttachResponse, DetachRequest},
    common::{EmptyRequest, ResultResponse, ResultResponseKind},
    emm::{
        ContentsResetAndDeleteRequest, EmmNiReattachControlRequest, EmmTimerControlRequest,
        EmmTimerStartRequest, LcsControlRequest, LppControlRequest, NasConfigGetRequest,
        NasConfigSetRequest, PsmControlRequest, UeModeChangeRequest, UeModeChangeResponse,
    },
    misc::{
        DeviceInformationRequest, DeviceInformationResponse, IccidReadRequest, MobileIdReadRequest,
        MsisdnReadRequest, TemperatureReadRequest,
    },
    pdn::{PdnConnectResponse, PdnDisconnectResponse},
    plmn::{
        PlmnInfoDecodeError, PlmnListResponse, PlmnSearchStopRequest, QuerySelectedPlmnRequest,
        QuerySelectedPlmnResponse,
    },
    rf::{RfMeasureReportRequest, RfStatusReportControlRequest},
    rrc::{
        RrcCapabilityGetResponse, RrcCapabilitySetResponse, RrcFunctionResponse,
        RrcFunctionSetRequest, SetProtocolInfoResponse,
    },
    uicc::UiccResponse,
};
use gct_runtime::{
    EventDecodeError, Modem, ModemCommand, ModemEvent, PendingRequests, ResponseKey,
    SendCommandError, SendTrackedCommandError,
};
use lted_compat::Server;
use lted_proto::{SdkApiRequest, SdkCommand};

/// Offset of `lte_api_ret` inside the recovered 38,784-byte
/// `lted_client_context`.
pub const LTE_API_RET_OFFSET: usize = 0x524;
/// One-byte `LTED_GetPSInitComplete` return slot in the stock shared context.
pub const PS_INIT_COMPLETE_OFFSET: usize = 0x528;
/// Exact 30-byte `_SYSTEM_VERSION` result slot read by stock command 3.
pub const DEVICE_INFORMATION_OFFSET: usize = 0x52a;
pub const DEVICE_INFORMATION_LEN: usize = 30;
/// Exact live-P4 command-7 `_NETWORK_CONNECT_INFO` result slot.
pub const CONNECTION_INFO_OFFSET: usize = 0x8d6c;
pub const CONNECTION_INFO_LEN: usize = state::CONNECTION_INFO_LEN;
/// `libltesdk.so` live-P4 compiled SDK version filled locally after `0xb003`.
pub const STOCK_SDK_VERSION: [u8; 4] = [3, 7, 18, 2];
/// Live-P4 `gdmlte.ko` `DRIVER_VERSION` (`1.0.2`) after stock `GET_DRV_VER` parsing.
pub const STOCK_DRIVER_VERSION: [u8; 4] = [1, 0, 2, 0];
/// One-byte stock APN-type query result near the end of the shared context.
pub const APN_TYPE_RESULT_OFFSET: usize = 0x977d;
/// One-byte result slot read by stock command 19 (`LTED_GetDHCPLeaseStateByCID`).
pub const DHCP_LEASE_STATE_RESULT_OFFSET: usize = 0x977e;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostAction {
    SetMtu {
        interface_name: [u8; 15],
        name_len: usize,
        mtu: u16,
    },
}

impl HostAction {
    #[must_use]
    pub fn interface_name_bytes(&self) -> &[u8] {
        match self {
            Self::SetMtu {
                interface_name,
                name_len,
                ..
            } => &interface_name[..*name_len],
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostRequestError {
    EmptyInterfaceName,
    ZeroMtu,
}

#[derive(Debug)]
pub enum HandleError {
    Ipc(io::Error),
    Host(io::Error),
    HostRequest(HostRequestError),
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
    LegacyPdnConnectExt(LegacyPdnConnectExtDecodeError),
    LegacyPdnDisconnect(LegacyPdnDisconnectDecodeError),
    LegacyUicc(LegacyUiccDecodeError),
    LegacyRrcCapability(LegacyRrcCapabilityDecodeError),
    LegacyRrcFunction(LegacyRrcFunctionDecodeError),
    LegacySetProtocolInfo(LegacySetProtocolInfoDecodeError),
    RrcCapabilityCallback(RrcCapabilityCallbackError),
    UiccCallback(UiccCallbackError),
    AttachCallback(AttachCallbackError),
    AttachExtCallback(AttachExtCallbackError),
    PdnConnectCallback(PdnConnectCallbackError),
    PdnConnectExtCallback(PdnConnectExtCallbackError),
    PdnDisconnectCallback(PdnDisconnectCallbackError),
    TransactionIdsExhausted,
    ApnState(ApnStateError),
    ConnectionState(ConnectionStateError),
    PlmnSearch(PlmnInfoDecodeError),
    PlmnList(PlmnInfoDecodeError),
    Send(SendCommandError),
    Tracked(SendTrackedCommandError),
}

impl std::fmt::Display for HandleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ipc(error) => write!(f, "lted IPC error: {error}"),
            Self::Host(error) => write!(f, "host networking action failed: {error}"),
            Self::HostRequest(error) => write!(f, "invalid stock host-network request: {error:?}"),
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
            Self::LegacyPdnConnectExt(error) => {
                write!(f, "invalid stock extended PDN-connect request: {error:?}")
            }
            Self::LegacyPdnDisconnect(error) => {
                write!(f, "invalid stock PDN-disconnect request: {error:?}")
            }
            Self::LegacyUicc(error) => write!(f, "invalid stock UICC request: {error:?}"),
            Self::LegacyRrcCapability(error) => {
                write!(f, "invalid stock RRC-capability request: {error:?}")
            }
            Self::LegacyRrcFunction(error) => {
                write!(f, "invalid stock RRC-function request: {error:?}")
            }
            Self::LegacySetProtocolInfo(error) => {
                write!(f, "invalid stock set-protocol-info request: {error:?}")
            }
            Self::RrcCapabilityCallback(error) => {
                write!(f, "invalid RRC-capability callback payload: {error:?}")
            }
            Self::UiccCallback(error) => write!(f, "invalid UICC callback payload: {error:?}"),
            Self::AttachCallback(error) => write!(f, "invalid attach callback payload: {error:?}"),
            Self::AttachExtCallback(error) => {
                write!(f, "invalid extended-attach callback payload: {error:?}")
            }
            Self::PdnConnectCallback(error) => {
                write!(f, "invalid PDN-connect callback payload: {error:?}")
            }
            Self::PdnConnectExtCallback(error) => {
                write!(
                    f,
                    "invalid extended PDN-connect callback payload: {error:?}"
                )
            }
            Self::PdnDisconnectCallback(error) => {
                write!(f, "invalid PDN-disconnect callback payload: {error:?}")
            }
            Self::TransactionIdsExhausted => write!(f, "no free OEM transaction ID in 1..=253"),
            Self::ApnState(error) => write!(f, "invalid stock APN/TID state request: {error:?}"),
            Self::ConnectionState(error) => write!(f, "invalid stock connection state: {error:?}"),
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
            Self::Ipc(error) | Self::Host(error) => Some(error),
            Self::HostRequest(_)
            | Self::UnsupportedCommand(_)
            | Self::UnexpectedParameters { .. }
            | Self::UnknownDevice { .. }
            | Self::LegacyAttach(_)
            | Self::LegacyAttachExt(_)
            | Self::LegacyPdnConnect(_)
            | Self::LegacyPdnConnectExt(_)
            | Self::LegacyPdnDisconnect(_)
            | Self::LegacyUicc(_)
            | Self::LegacyRrcCapability(_)
            | Self::LegacyRrcFunction(_)
            | Self::LegacySetProtocolInfo(_)
            | Self::RrcCapabilityCallback(_)
            | Self::UiccCallback(_)
            | Self::AttachCallback(_)
            | Self::AttachExtCallback(_)
            | Self::PdnConnectCallback(_)
            | Self::PdnConnectExtCallback(_)
            | Self::PdnDisconnectCallback(_)
            | Self::TransactionIdsExhausted
            | Self::ApnState(_)
            | Self::ConnectionState(_)
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandledCall {
    pub command: SdkCommand,
    pub device_id: u32,
    pub bytes_written: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompletionMode {
    Immediate,
    Deferred(ResponseKey),
}

impl HandledCall {
    const fn for_request(
        request: SdkApiRequest<'_>,
        command: SdkCommand,
        bytes_written: usize,
    ) -> Self {
        Self {
            command,
            device_id: request.device_id,
            bytes_written,
        }
    }

    #[must_use]
    pub const fn completion_mode(self) -> CompletionMode {
        match self.command {
            SdkCommand::GetDeviceInformation => {
                CompletionMode::Deferred(ResponseKey::DeviceInformation)
            }
            _ => CompletionMode::Immediate,
        }
    }
}

fn exact_params<'a, const N: usize>(
    request: &SdkApiRequest<'a>,
) -> Result<&'a [u8; N], HandleError> {
    request
        .params
        .try_into()
        .map_err(|_| HandleError::UnexpectedParameters {
            command: request.command,
            expected: N,
            actual: request.params.len(),
        })
}

fn require_no_params(request: &SdkApiRequest<'_>) -> Result<(), HandleError> {
    exact_params::<0>(request).map(|_| ())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DeferredSdkCall {
    client_id: u8,
    key: ResponseKey,
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
    deferred_calls: Vec<DeferredSdkCall>,
    apn_state: ApnState,
    nic_state: NicState,
}

impl DeviceBridge {
    #[must_use]
    pub const fn new(device_id: u32) -> Self {
        Self {
            device_id,
            pending: PendingRequests::new(),
            startup_phase: StartupPhase::Idle,
            deferred_calls: Vec::new(),
            apn_state: ApnState::new(),
            nic_state: NicState::new(),
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
    pub const fn deferred_count(&self) -> usize {
        self.deferred_calls.len()
    }

    #[must_use]
    pub const fn init_complete(&self) -> bool {
        matches!(self.startup_phase, StartupPhase::Complete)
    }

    /// Merge one stock IPv6 Router Advertisement prefix into the matching
    /// connection record. The interface ID and DNS values remain modem-owned;
    /// only the high 64-bit prefix and the post-configuration cache are updated.
    #[must_use]
    pub fn apply_ipv6_prefix(&mut self, interface_name: &str, prefix: [u8; 16]) -> bool {
        self.nic_state.apply_ipv6_prefix(interface_name, prefix)
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
    /// failure. Host-local requests such as Set MTU fail closed here; production
    /// callers that can perform those side effects must use
    /// [`Self::handle_sdk_api_with_host`].
    pub fn handle_sdk_api<T: Write>(
        &mut self,
        server: &mut Server,
        modem: &mut Modem<T>,
        client_id: u8,
        request: SdkApiRequest<'_>,
    ) -> Result<HandledCall, HandleError> {
        self.handle_sdk_api_with_host(server, modem, client_id, request, |_| {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "host action executor required",
            ))
        })
    }

    /// Execute one stock SDK request while delegating recovered host-network
    /// side effects to the caller. This keeps the bridge testable without
    /// privileges and lets the production daemon surface real host failures
    /// through the stock synchronous `lte_api_ret` path.
    ///
    /// # Errors
    /// Returns the same errors as [`Self::handle_sdk_api`] plus
    /// [`HandleError::Host`] when the injected host operation fails.
    pub fn handle_sdk_api_with_host<T: Write, F>(
        &mut self,
        server: &mut Server,
        modem: &mut Modem<T>,
        client_id: u8,
        request: SdkApiRequest<'_>,
        mut host_action: F,
    ) -> Result<HandledCall, HandleError>
    where
        F: FnMut(HostAction) -> io::Result<()>,
    {
        let context = server.client_context(client_id)?;
        context.daemon_acquire()?;
        if let Err(error) = context.write_i32_be(LTE_API_RET_OFFSET, 0) {
            let _ = context.daemon_release();
            return Err(error.into());
        }

        let dispatch = if request.device_id == self.device_id {
            match request.known_command() {
                Ok(SdkCommand::GetPsInitComplete) => self
                    .dispatch_ps_init_complete(request, |value| {
                        context.write(PS_INIT_COMPLETE_OFFSET, &[value])
                    }),
                Ok(SdkCommand::GetDeviceInformation) => {
                    self.dispatch_device_information(modem, request)
                }
                Ok(SdkCommand::GetConnectionInfo) => self
                    .dispatch_connection_info(request, |snapshot| {
                        context.write(CONNECTION_INFO_OFFSET, snapshot)
                    }),
                Ok(SdkCommand::CheckDhcpLeaseState) => self
                    .dispatch_check_dhcp_lease_state(request, |value| {
                        context.write(DHCP_LEASE_STATE_RESULT_OFFSET, &[value])
                    }),
                Ok(SdkCommand::SetMtuSize) => {
                    Self::dispatch_set_mtu_size(request, &mut host_action)
                }
                Ok(
                    SdkCommand::SetApnType
                    | SdkCommand::GetApnType
                    | SdkCommand::GetApnTypeByDefaultEpsId
                    | SdkCommand::DeleteApnTypeFromTidNode
                    | SdkCommand::AddSpecialTid,
                ) => self.dispatch_apn_state(request, |value| {
                    context.write(APN_TYPE_RESULT_OFFSET, &[value])
                }),
                Ok(SdkCommand::Attach) => self.dispatch_attach(modem, request),
                Ok(SdkCommand::AttachExt) => self.dispatch_attach_ext(modem, request),
                Ok(SdkCommand::Detach) => self.dispatch_detach(modem, request),
                Ok(SdkCommand::PdnConnect) => self.dispatch_pdn_connect(modem, request),
                Ok(SdkCommand::PdnConnectExt) => self.dispatch_pdn_connect_ext(modem, request),
                Ok(SdkCommand::PdnDisconnect) => self.dispatch_pdn_disconnect(modem, request),
                Ok(SdkCommand::PlmnSearch) => self.dispatch_plmn_search(modem, request),
                Ok(SdkCommand::PlmnSearchExt) => self.dispatch_plmn_search_ext(modem, request),
                Ok(SdkCommand::PlmnSearchStop) => self.dispatch_plmn_search_stop(modem, request),
                Ok(SdkCommand::QuerySelectedPlmn) => {
                    self.dispatch_query_selected_plmn(modem, request)
                }
                Ok(SdkCommand::ContentsResetAndDelete) => {
                    self.dispatch_contents_reset_and_delete(modem, request)
                }
                Ok(SdkCommand::MobileIdRead) => self.dispatch_mobile_id_read(modem, request),
                Ok(SdkCommand::IccidRead) => self.dispatch_iccid_read(modem, request),
                Ok(SdkCommand::MsisdnRead) => self.dispatch_msisdn_read(modem, request),
                Ok(SdkCommand::TemperatureRead) => self.dispatch_temperature_read(modem, request),
                Ok(SdkCommand::AtCommand) => Self::dispatch_at(modem, request),
                Ok(SdkCommand::AtCommandExt) => Self::dispatch_at_ext(modem, request),
                Ok(SdkCommand::UiccRequest) => self.dispatch_uicc(modem, request),
                Ok(SdkCommand::UeModeChange) => self.dispatch_ue_mode_change(modem, request),
                Ok(SdkCommand::SetProtocolInfo) => self.dispatch_set_protocol_info(modem, request),
                Ok(SdkCommand::RfStatusReportControl) => {
                    self.dispatch_rf_status_report_control(modem, request)
                }
                Ok(SdkCommand::RfMeasureReport) => self.dispatch_rf_measure_report(modem, request),
                Ok(SdkCommand::SetNasConfig) => Self::dispatch_nas_config_set(modem, request),
                Ok(SdkCommand::GetNasConfig) => Self::dispatch_nas_config_get(modem, request),
                Ok(SdkCommand::EmmTimerControl) => Self::dispatch_emm_timer_control(modem, request),
                Ok(SdkCommand::PsmControl) => Self::dispatch_psm_control(modem, request),
                Ok(SdkCommand::LcsControl) => Self::dispatch_lcs_control(modem, request),
                Ok(SdkCommand::LppControl) => Self::dispatch_lpp_control(modem, request),
                Ok(SdkCommand::EmmTimerStart) => Self::dispatch_emm_timer_start(modem, request),
                Ok(SdkCommand::EmmNiReattachControl) => {
                    self.dispatch_emm_ni_reattach_control(modem, request)
                }
                Ok(
                    command @ (SdkCommand::RrcCapabilityControl
                    | SdkCommand::RrcCapabilityControlGet
                    | SdkCommand::RrcFunctionControl
                    | SdkCommand::RrcFunctionControlGet),
                ) => self.dispatch_rrc_request(modem, request, command),
                Ok(_) => self.dispatch_zero_parameter(modem, request),
                Err(_) => Err(HandleError::UnsupportedCommand(request.command)),
            }
        } else {
            Err(HandleError::UnknownDevice {
                requested: request.device_id,
                expected: self.device_id,
            })
        };
        if let Ok(call) = dispatch
            && let CompletionMode::Deferred(key) = call.completion_mode()
        {
            self.deferred_calls.push(DeferredSdkCall { client_id, key });
            return Ok(call);
        }

        let status = i32::from(dispatch.is_err());
        let status_result = context.write_i32_be(LTE_API_RET_OFFSET, status);
        let release_result = context.daemon_release();

        status_result?;
        release_result?;
        dispatch
    }

    fn dispatch_check_dhcp_lease_state<F>(
        &self,
        request: SdkApiRequest<'_>,
        write_result: F,
    ) -> Result<HandledCall, HandleError>
    where
        F: FnOnce(u8) -> io::Result<()>,
    {
        let &[cid] = exact_params::<1>(&request)?;
        write_result(u8::from(self.nic_state.has_ipv4_lease_for_cid(cid)))?;
        Ok(HandledCall::for_request(
            request,
            SdkCommand::CheckDhcpLeaseState,
            0,
        ))
    }

    fn dispatch_set_mtu_size<F>(
        request: SdkApiRequest<'_>,
        host_action: &mut F,
    ) -> Result<HandledCall, HandleError>
    where
        F: FnMut(HostAction) -> io::Result<()>,
    {
        let params = exact_params::<258>(&request)?;
        let name_source = &params[..15];
        let name_len = name_source
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(name_source.len());
        if name_len == 0 {
            return Err(HandleError::HostRequest(
                HostRequestError::EmptyInterfaceName,
            ));
        }
        let mtu = u16::from_be_bytes([params[256], params[257]]);
        if mtu == 0 {
            return Err(HandleError::HostRequest(HostRequestError::ZeroMtu));
        }
        let mut interface_name = [0_u8; 15];
        interface_name[..name_len].copy_from_slice(&name_source[..name_len]);
        host_action(HostAction::SetMtu {
            interface_name,
            name_len,
            mtu,
        })
        .map_err(HandleError::Host)?;
        Ok(HandledCall::for_request(request, SdkCommand::SetMtuSize, 0))
    }

    fn dispatch_ps_init_complete<F>(
        &self,
        request: SdkApiRequest<'_>,
        write_result: F,
    ) -> Result<HandledCall, HandleError>
    where
        F: FnOnce(u8) -> io::Result<()>,
    {
        require_no_params(&request)?;
        write_result(u8::from(self.init_complete()))?;
        Ok(HandledCall::for_request(
            request,
            SdkCommand::GetPsInitComplete,
            0,
        ))
    }

    fn dispatch_connection_info<F>(
        &self,
        request: SdkApiRequest<'_>,
        write_result: F,
    ) -> Result<HandledCall, HandleError>
    where
        F: FnOnce(&[u8]) -> io::Result<()>,
    {
        exact_params::<CONNECTION_INFO_LEN>(&request)?;
        let snapshot = self.nic_state.snapshot();
        write_result(&snapshot)?;
        Ok(HandledCall::for_request(
            request,
            SdkCommand::GetConnectionInfo,
            0,
        ))
    }

    fn handle_attach_ext_event(
        &mut self,
        server: &mut Server,
        response: AttachExtResponse<'_>,
    ) -> Result<Option<BroadcastReport>, HandleError> {
        if !self.pending.remove(ResponseKey::AttachExt) {
            return Ok(None);
        }
        broadcast_attach_ext_callback(server, self.device_id, response).map(Some)
    }

    fn handle_plmn_list_event(
        &mut self,
        server: &mut Server,
        response: PlmnListResponse<'_>,
    ) -> Result<Option<BroadcastReport>, HandleError> {
        let key = ResponseKey::PlmnList;
        if !self.pending.contains(key) {
            return Ok(None);
        }
        let report = broadcast_plmn_list_callback(server, self.device_id, response)?;
        if response.search_complete != 0 {
            self.pending.remove(key);
        }
        Ok(Some(report))
    }

    fn handle_rrc_capability_set_event(
        &mut self,
        server: &mut Server,
        response: RrcCapabilitySetResponse<'_>,
    ) -> Result<Option<BroadcastReport>, HandleError> {
        let key = ResponseKey::RrcCapabilitySet(response.type_id);
        if !self.pending.contains(key) {
            return Ok(None);
        }
        if response.result == 0 && !rrc_capability_set_success_has_callback(response.type_id) {
            self.pending.remove(key);
            return Ok(None);
        }
        let report = broadcast_rrc_capability_set_callback(server, self.device_id, response)?;
        self.pending.remove(key);
        Ok(Some(report))
    }

    fn handle_rrc_capability_get_event(
        &mut self,
        server: &mut Server,
        response: RrcCapabilityGetResponse<'_>,
    ) -> Result<Option<BroadcastReport>, HandleError> {
        let key = ResponseKey::RrcCapabilityGet(response.type_id);
        if !self.pending.contains(key) {
            return Ok(None);
        }
        let report = broadcast_rrc_capability_get_callback(server, self.device_id, response)?;
        self.pending.remove(key);
        Ok(Some(report))
    }

    fn handle_query_selected_plmn_event(
        &mut self,
        server: &mut Server,
        response: QuerySelectedPlmnResponse,
    ) -> Result<Option<BroadcastReport>, HandleError> {
        let key = ResponseKey::QuerySelectedPlmn;
        if !self.pending.contains(key) {
            return Ok(None);
        }
        let report = broadcast_query_selected_plmn_callback(server, self.device_id, response)?;
        self.pending.remove(key);
        Ok(Some(report))
    }

    fn handle_rrc_function_set_event(
        &mut self,
        server: &mut Server,
        response: RrcFunctionResponse<'_>,
    ) -> Result<Option<BroadcastReport>, HandleError> {
        let key = ResponseKey::RrcFunctionSet(response.type_id);
        if !self.pending.contains(key) {
            return Ok(None);
        }
        let report = broadcast_rrc_function_set_callback(server, self.device_id, response)?;
        self.pending.remove(key);
        Ok(Some(report))
    }

    fn handle_rrc_function_get_event(
        &mut self,
        server: &mut Server,
        response: RrcFunctionResponse<'_>,
    ) -> Result<Option<BroadcastReport>, HandleError> {
        let key = ResponseKey::RrcFunctionGet(response.type_id);
        if !self.pending.contains(key) {
            return Ok(None);
        }
        let report = broadcast_rrc_function_get_callback(server, self.device_id, response)?;
        self.pending.remove(key);
        Ok(Some(report))
    }

    fn handle_device_information_event(
        &mut self,
        server: &mut Server,
        response: DeviceInformationResponse,
    ) -> Result<Option<BroadcastReport>, HandleError> {
        let key = ResponseKey::DeviceInformation;
        if !self.pending.contains(key) {
            return Ok(None);
        }
        let Some(index) = self.deferred_calls.iter().position(|call| call.key == key) else {
            return Ok(None);
        };
        let deferred = self.deferred_calls[index];
        let mut result = [0_u8; DEVICE_INFORMATION_LEN];
        result[0..4].copy_from_slice(&response.fw_revision);
        result[4..6].copy_from_slice(&response.chip_revision);
        result[10..14].copy_from_slice(&STOCK_SDK_VERSION);
        result[14..18].copy_from_slice(&STOCK_DRIVER_VERSION);

        let context = server.client_context(deferred.client_id)?;
        context.write(DEVICE_INFORMATION_OFFSET, &result)?;
        context.write_i32_be(LTE_API_RET_OFFSET, 0)?;
        context.daemon_release()?;

        self.deferred_calls.swap_remove(index);
        self.pending.remove(key);
        Ok(Some(BroadcastReport::default()))
    }

    fn handle_set_protocol_info_event(
        &mut self,
        server: &mut Server,
        response: SetProtocolInfoResponse<'_>,
    ) -> Result<Option<BroadcastReport>, HandleError> {
        let key = ResponseKey::SetProtocolInfo(response.type_id);
        if !self.pending.contains(key) {
            return Ok(None);
        }
        let report = broadcast_set_protocol_info_callback(server, self.device_id, response)?;
        self.pending.remove(key);
        Ok(Some(report))
    }

    fn handle_uicc_event(
        &mut self,
        server: &mut Server,
        response: UiccResponse<'_>,
    ) -> Result<Option<BroadcastReport>, HandleError> {
        let key = ResponseKey::Uicc(response.kind);
        if !self.pending.contains(key) {
            return Ok(None);
        }
        let report = broadcast_uicc_callback(server, self.device_id, response)?;
        self.pending.remove(key);
        Ok(Some(report))
    }

    fn handle_misc_read_event(
        &mut self,
        server: &mut Server,
        event: &ModemEvent<'_>,
    ) -> Result<Option<BroadcastReport>, HandleError> {
        match event {
            ModemEvent::IccidRead(response) => {
                if !self.pending.contains(ResponseKey::MiscRead) {
                    return Ok(None);
                }
                let report = broadcast_iccid_callback(server, self.device_id, *response)?;
                self.pending.remove(ResponseKey::MiscRead);
                Ok(Some(report))
            }
            ModemEvent::MobileIdRead(response) => {
                if !self.pending.remove(ResponseKey::MiscRead) {
                    return Ok(None);
                }
                broadcast_mobile_id_callback(server, self.device_id, *response).map(Some)
            }
            ModemEvent::TemperatureRead(response) => {
                if !self.pending.contains(ResponseKey::MiscRead) {
                    return Ok(None);
                }
                let report = broadcast_temperature_callback(server, self.device_id, *response)?;
                self.pending.remove(ResponseKey::MiscRead);
                Ok(Some(report))
            }
            ModemEvent::MsisdnRead(response) => {
                if !self.pending.contains(ResponseKey::MiscRead) {
                    return Ok(None);
                }
                let report = broadcast_msisdn_callback(server, self.device_id, *response)?;
                self.pending.remove(ResponseKey::MiscRead);
                Ok(Some(report))
            }
            ModemEvent::MiscReadFailure { .. } => {
                self.pending.remove(ResponseKey::MiscRead);
                Ok(None)
            }
            _ => Ok(None),
        }
    }

    fn handle_ue_mode_change_event(
        &mut self,
        server: &mut Server,
        response: UeModeChangeResponse,
    ) -> Result<Option<BroadcastReport>, HandleError> {
        if !self.pending.remove(ResponseKey::UeModeChange) {
            return Ok(None);
        }
        broadcast_ue_mode_change_callback(server, self.device_id, response).map(Some)
    }

    fn handle_rf_status_report_control_event(
        &mut self,
        server: &mut Server,
        response: gct_lapi::rf::RfStatusReportControlResponse,
    ) -> Result<Option<BroadcastReport>, HandleError> {
        if !self.pending.remove(ResponseKey::RfStatusReportControl) {
            return Ok(None);
        }
        broadcast_rf_status_report_control_callback(server, self.device_id, response).map(Some)
    }

    fn handle_contents_reset_and_delete_event(
        &mut self,
        server: &mut Server,
        response: gct_lapi::emm::ContentsResetAndDeleteResponse,
    ) -> Result<Option<BroadcastReport>, HandleError> {
        if !self.pending.remove(ResponseKey::ContentsResetAndDelete) {
            return Ok(None);
        }
        broadcast_contents_reset_and_delete_callback(server, self.device_id, response).map(Some)
    }

    fn handle_result_event(
        &mut self,
        server: &mut Server,
        kind: ResultResponseKind,
        response: ResultResponse,
    ) -> Result<Option<BroadcastReport>, HandleError> {
        let key = ResponseKey::Result(kind);
        if !self.pending.remove(key) {
            return Ok(None);
        }
        match (kind, self.startup_phase) {
            (ResultResponseKind::PsInit, StartupPhase::AwaitingPsInit) => {
                self.startup_phase = StartupPhase::NeedOnline;
            }
            (ResultResponseKind::Online, StartupPhase::AwaitingOnline) => {
                self.startup_phase = StartupPhase::Complete;
            }
            _ => {}
        }
        broadcast_result_callback(server, kind, self.device_id, response).map(Some)
    }

    /// Complete a deferred stock synchronous call with failure when its known
    /// modem response is structurally malformed.
    ///
    /// This prevents a malformed `0xb003` from leaving the stock caller blocked
    /// forever on its `SysV` semaphore. Decode failures for asynchronous families
    /// do not have a deferred local caller and are left to the normal log path.
    ///
    /// # Errors
    /// Returns [`HandleError::Ipc`] if the shared status or semaphore handoff
    /// cannot be completed.
    pub fn handle_modem_decode_error(
        &mut self,
        server: &mut Server,
        error: &EventDecodeError,
    ) -> Result<bool, HandleError> {
        let key = match error {
            EventDecodeError::DeviceInformation(_) => ResponseKey::DeviceInformation,
            _ => return Ok(false),
        };
        let Some(index) = self.deferred_calls.iter().position(|call| call.key == key) else {
            return Ok(false);
        };
        let deferred = self.deferred_calls[index];
        let context = server.client_context(deferred.client_id)?;
        context.write_i32_be(LTE_API_RET_OFFSET, 1)?;
        context.daemon_release()?;
        self.deferred_calls.swap_remove(index);
        self.pending.remove(key);
        Ok(true)
    }

    fn handle_attach_event(
        &mut self,
        server: &mut Server,
        response: AttachResponse<'_>,
    ) -> Result<Option<BroadcastReport>, HandleError> {
        let key = ResponseKey::Attach(response.transaction_id);
        if !self.pending.remove(key) {
            return Ok(None);
        }
        if response.register_result2 == 0 {
            self.apn_state
                .update_default_eps_id(response.transaction_id, response.default_eps_id);
            let apn_type = self
                .apn_state
                .resolved_apn_type_for_tid(response.transaction_id);
            self.nic_state
                .apply_attach(response, apn_type)
                .map_err(HandleError::ConnectionState)?;
        } else {
            self.apn_state.delete_by_tid(response.transaction_id);
        }
        broadcast_attach_callback(server, self.device_id, response).map(Some)
    }

    fn handle_pdn_connect_event(
        &mut self,
        server: &mut Server,
        response: PdnConnectResponse<'_>,
    ) -> Result<Option<BroadcastReport>, HandleError> {
        let key = ResponseKey::PdnConnect(response.transaction_id);
        if !self.pending.remove(key) {
            return Ok(None);
        }
        if response.result == 5 {
            self.apn_state.delete_by_tid(response.transaction_id);
        } else {
            self.apn_state
                .update_default_eps_id(response.transaction_id, response.default_eps_id);
        }
        if response.result == 1 {
            let apn_type = self
                .apn_state
                .resolved_apn_type_for_tid(response.transaction_id);
            self.nic_state
                .apply_pdn_connect(response, apn_type)
                .map_err(HandleError::ConnectionState)?;
        }
        broadcast_pdn_connect_callback(server, self.device_id, response).map(Some)
    }

    fn handle_pdn_disconnect_event(
        &mut self,
        server: &mut Server,
        response: PdnDisconnectResponse<'_>,
    ) -> Result<Option<BroadcastReport>, HandleError> {
        let key = ResponseKey::PdnDisconnect(response.transaction_id);
        if !self.pending.remove(key) {
            return Ok(None);
        }
        if matches!(response.result, 101 | 108) {
            self.nic_state
                .clear_by_default_eps_id(response.default_eps_id);
            self.apn_state.delete_by_tid(response.transaction_id);
        }
        broadcast_pdn_disconnect_callback(server, self.device_id, response).map(Some)
    }

    fn handle_rrc_event(
        &mut self,
        server: &mut Server,
        event: &ModemEvent<'_>,
    ) -> Result<Option<BroadcastReport>, HandleError> {
        match event {
            ModemEvent::RrcCapabilitySet(response) => {
                self.handle_rrc_capability_set_event(server, *response)
            }
            ModemEvent::RrcCapabilityGet(response) => {
                self.handle_rrc_capability_get_event(server, *response)
            }
            ModemEvent::RrcFunctionSet(response) => {
                self.handle_rrc_function_set_event(server, *response)
            }
            ModemEvent::RrcFunctionGet(response) => {
                self.handle_rrc_function_get_event(server, *response)
            }
            _ => Ok(None),
        }
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
            ModemEvent::Attach(response) => self.handle_attach_event(server, *response),
            ModemEvent::AttachExt(response) => self.handle_attach_ext_event(server, *response),
            ModemEvent::Detach(response) => {
                if !self.pending.remove(ResponseKey::Detach) {
                    return Ok(None);
                }
                broadcast_detach_callback(server, self.device_id, *response).map(Some)
            }
            ModemEvent::DetachRequired(indication) => {
                broadcast_detach_required_callback(server, self.device_id, *indication).map(Some)
            }
            ModemEvent::PdnConnect(response) => self.handle_pdn_connect_event(server, *response),
            ModemEvent::PdnConnectExt(response) => {
                if !self.pending.remove(ResponseKey::PdnConnectExt) {
                    return Ok(None);
                }
                broadcast_pdn_connect_ext_callback(server, self.device_id, *response).map(Some)
            }
            ModemEvent::PdnDisconnect(response) => {
                self.handle_pdn_disconnect_event(server, *response)
            }
            ModemEvent::At(response) => {
                broadcast_at_callback(server, self.device_id, response.command).map(Some)
            }
            ModemEvent::AtExt(response) => broadcast_at_ext_callback(
                server,
                self.device_id,
                response.channel,
                response.command,
            )
            .map(Some),
            event @ (ModemEvent::RrcCapabilitySet(_)
            | ModemEvent::RrcCapabilityGet(_)
            | ModemEvent::RrcFunctionSet(_)
            | ModemEvent::RrcFunctionGet(_)) => self.handle_rrc_event(server, event),
            ModemEvent::QuerySelectedPlmn(response) => {
                self.handle_query_selected_plmn_event(server, *response)
            }
            ModemEvent::SetProtocolInfo(response) => {
                self.handle_set_protocol_info_event(server, *response)
            }
            ModemEvent::DeviceInformation(response) => {
                self.handle_device_information_event(server, *response)
            }
            ModemEvent::Uicc(response) => self.handle_uicc_event(server, *response),
            ModemEvent::UeModeChange(response) => {
                self.handle_ue_mode_change_event(server, *response)
            }
            ModemEvent::EmmNiReattachControl { result } => {
                if !self.pending.remove(ResponseKey::EmmNiReattachControl) {
                    return Ok(None);
                }
                broadcast_emm_ni_reattach_callback(server, self.device_id, *result).map(Some)
            }
            ModemEvent::EmmReattachControlReport(report) => {
                broadcast_emm_reattach_report_callback(server, self.device_id, *report).map(Some)
            }
            ModemEvent::RfStatusReportControl(response) => {
                self.handle_rf_status_report_control_event(server, *response)
            }
            ModemEvent::RfMeasureReport(response) => {
                if !self.pending.remove(ResponseKey::RfMeasureReport) {
                    return Ok(None);
                }
                broadcast_rf_measure_report_callback(server, self.device_id, *response).map(Some)
            }
            ModemEvent::RfMeasureReportIndication(indication) => {
                broadcast_rf_measure_report_indication_callback(server, self.device_id, *indication)
                    .map(Some)
            }
            ModemEvent::Result { kind, response } => {
                self.handle_result_event(server, *kind, *response)
            }
            ModemEvent::ContentsResetAndDelete(response) => {
                self.handle_contents_reset_and_delete_event(server, *response)
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
            ModemEvent::MobileIdRead(_)
            | ModemEvent::IccidRead(_)
            | ModemEvent::MsisdnRead(_)
            | ModemEvent::TemperatureRead(_)
            | ModemEvent::MiscReadFailure { .. } => self.handle_misc_read_event(server, event),
            ModemEvent::PlmnList(response) => self.handle_plmn_list_event(server, *response),
            ModemEvent::Unknown(_) => Ok(None),
        }
    }

    fn allocate_transaction_id(&self) -> Result<u8, HandleError> {
        for transaction_id in 1_u8..=253 {
            let used = self.apn_state.contains_tid(transaction_id)
                || self.pending.contains_transaction_id(transaction_id);
            if !used {
                return Ok(transaction_id);
            }
        }
        Err(HandleError::TransactionIdsExhausted)
    }

    fn dispatch_apn_state<F>(
        &mut self,
        request: SdkApiRequest<'_>,
        mut write_result: F,
    ) -> Result<HandledCall, HandleError>
    where
        F: FnMut(u8) -> io::Result<()>,
    {
        let command = request
            .known_command()
            .map_err(|_| HandleError::UnsupportedCommand(request.command))?;
        match command {
            SdkCommand::SetApnType => {
                let bytes = exact_params::<4>(&request)?;
                self.apn_state
                    .set_configured_type(u32::from_be_bytes(*bytes))
                    .map_err(HandleError::ApnState)?;
            }
            SdkCommand::GetApnType => {
                require_no_params(&request)?;
                write_result(self.apn_state.configured_type())?;
            }
            SdkCommand::GetApnTypeByDefaultEpsId => {
                let bytes = exact_params::<2>(&request)?;
                write_result(
                    self.apn_state
                        .apn_type_by_default_eps_id(u16::from_be_bytes(*bytes)),
                )?;
            }
            SdkCommand::DeleteApnTypeFromTidNode => {
                let record = decode_legacy_special_tid(request.params).map_err(|actual| {
                    HandleError::UnexpectedParameters {
                        command: request.command,
                        expected: 7,
                        actual,
                    }
                })?;
                self.apn_state.delete_by_apn_type(record.requested_apn_type);
            }
            SdkCommand::AddSpecialTid => {
                let record = decode_legacy_special_tid(request.params).map_err(|actual| {
                    HandleError::UnexpectedParameters {
                        command: request.command,
                        expected: 7,
                        actual,
                    }
                })?;
                let tid = self.allocate_transaction_id()?;
                self.apn_state.add_special_tid(
                    tid,
                    SpecialTidRecord::new(
                        record.message_id,
                        record.default_eps_id,
                        record.tid_type,
                        record.requested_apn_type,
                        record.ip_allocation,
                    ),
                );
            }
            _ => return Err(HandleError::UnsupportedCommand(request.command)),
        }
        Ok(HandledCall::for_request(request, command, 0))
    }

    fn dispatch_device_information<T: Write>(
        &mut self,
        modem: &mut Modem<T>,
        request: SdkApiRequest<'_>,
    ) -> Result<HandledCall, HandleError> {
        require_no_params(&request)?;
        let bytes_written = modem.send_tracked_command(
            &mut self.pending,
            ModemCommand::DeviceInformation(DeviceInformationRequest),
        )?;
        Ok(HandledCall::for_request(
            request,
            SdkCommand::GetDeviceInformation,
            bytes_written,
        ))
    }

    fn dispatch_nas_config_set<T: Write>(
        modem: &mut Modem<T>,
        request: SdkApiRequest<'_>,
    ) -> Result<HandledCall, HandleError> {
        let params = exact_params::<33>(&request)?;
        let modem_request = NasConfigSetRequest {
            count: params[0],
            pairs: &params[1..],
        };
        let bytes_written = modem.send_command(ModemCommand::NasConfigSet(modem_request))?;
        Ok(HandledCall::for_request(
            request,
            SdkCommand::SetNasConfig,
            bytes_written,
        ))
    }

    fn dispatch_nas_config_get<T: Write>(
        modem: &mut Modem<T>,
        request: SdkApiRequest<'_>,
    ) -> Result<HandledCall, HandleError> {
        require_no_params(&request)?;
        let bytes_written = modem.send_command(ModemCommand::NasConfigGet(NasConfigGetRequest))?;
        Ok(HandledCall::for_request(
            request,
            SdkCommand::GetNasConfig,
            bytes_written,
        ))
    }

    fn dispatch_set_protocol_info<T: Write>(
        &mut self,
        modem: &mut Modem<T>,
        request: SdkApiRequest<'_>,
    ) -> Result<HandledCall, HandleError> {
        let modem_request = decode_legacy_set_protocol_info(request.params)
            .map_err(HandleError::LegacySetProtocolInfo)?;
        let bytes_written = modem.send_tracked_command(
            &mut self.pending,
            ModemCommand::SetProtocolInfo(modem_request),
        )?;
        Ok(HandledCall::for_request(
            request,
            SdkCommand::SetProtocolInfo,
            bytes_written,
        ))
    }

    fn dispatch_rrc_request<T: Write>(
        &mut self,
        modem: &mut Modem<T>,
        request: SdkApiRequest<'_>,
        command: SdkCommand,
    ) -> Result<HandledCall, HandleError> {
        match command {
            SdkCommand::RrcCapabilityControl => self.dispatch_rrc_capability_set(modem, request),
            SdkCommand::RrcCapabilityControlGet => self.dispatch_rrc_capability_get(modem, request),
            SdkCommand::RrcFunctionControl => self.dispatch_rrc_function_set(modem, request),
            SdkCommand::RrcFunctionControlGet => self.dispatch_rrc_function_get(modem, request),
            _ => Err(HandleError::UnsupportedCommand(request.command)),
        }
    }

    fn dispatch_rrc_capability_set<T: Write>(
        &mut self,
        modem: &mut Modem<T>,
        request: SdkApiRequest<'_>,
    ) -> Result<HandledCall, HandleError> {
        let modem_request = decode_legacy_rrc_capability_set(request.params)
            .map_err(HandleError::LegacyRrcCapability)?;
        let bytes_written = modem.send_tracked_command(
            &mut self.pending,
            ModemCommand::RrcCapabilitySet(modem_request),
        )?;
        Ok(HandledCall::for_request(
            request,
            SdkCommand::RrcCapabilityControl,
            bytes_written,
        ))
    }

    fn dispatch_rrc_capability_get<T: Write>(
        &mut self,
        modem: &mut Modem<T>,
        request: SdkApiRequest<'_>,
    ) -> Result<HandledCall, HandleError> {
        let modem_request = decode_legacy_rrc_capability_get(request.params)
            .map_err(HandleError::LegacyRrcCapability)?;
        let bytes_written = modem.send_tracked_command(
            &mut self.pending,
            ModemCommand::RrcCapabilityGet(modem_request),
        )?;
        Ok(HandledCall::for_request(
            request,
            SdkCommand::RrcCapabilityControlGet,
            bytes_written,
        ))
    }

    fn dispatch_query_selected_plmn<T: Write>(
        &mut self,
        modem: &mut Modem<T>,
        request: SdkApiRequest<'_>,
    ) -> Result<HandledCall, HandleError> {
        require_no_params(&request)?;
        let bytes_written = modem.send_tracked_command(
            &mut self.pending,
            ModemCommand::QuerySelectedPlmn(QuerySelectedPlmnRequest),
        )?;
        Ok(HandledCall::for_request(
            request,
            SdkCommand::QuerySelectedPlmn,
            bytes_written,
        ))
    }

    fn dispatch_rrc_function_set<T: Write>(
        &mut self,
        modem: &mut Modem<T>,
        request: SdkApiRequest<'_>,
    ) -> Result<HandledCall, HandleError> {
        let legacy = decode_legacy_rrc_function_set(request.params)
            .map_err(HandleError::LegacyRrcFunction)?;
        let mut converted = [0_u8; RRC_FUNCTION_CELL_LOCK_WIRE_LEN];
        let data = if legacy.type_id == 1 {
            materialize_rrc_function_cell_lock_wire(legacy.data, &mut converted)
                .map_err(HandleError::LegacyRrcFunction)?;
            converted.as_slice()
        } else {
            legacy.data
        };
        let bytes_written = modem.send_tracked_command(
            &mut self.pending,
            ModemCommand::RrcFunctionSet(RrcFunctionSetRequest {
                type_id: legacy.type_id,
                data,
            }),
        )?;
        Ok(HandledCall::for_request(
            request,
            SdkCommand::RrcFunctionControl,
            bytes_written,
        ))
    }

    fn dispatch_rrc_function_get<T: Write>(
        &mut self,
        modem: &mut Modem<T>,
        request: SdkApiRequest<'_>,
    ) -> Result<HandledCall, HandleError> {
        let modem_request = decode_legacy_rrc_function_get(request.params)
            .map_err(HandleError::LegacyRrcFunction)?;
        let bytes_written = modem.send_tracked_command(
            &mut self.pending,
            ModemCommand::RrcFunctionGet(modem_request),
        )?;
        Ok(HandledCall::for_request(
            request,
            SdkCommand::RrcFunctionControlGet,
            bytes_written,
        ))
    }

    fn dispatch_emm_timer_control<T: Write>(
        modem: &mut Modem<T>,
        request: SdkApiRequest<'_>,
    ) -> Result<HandledCall, HandleError> {
        let bytes = *exact_params::<4>(&request)?;
        let modem_request = EmmTimerControlRequest {
            timer_id: u16::from_be_bytes([bytes[0], bytes[1]]),
            timer_value_unit: bytes[2],
            timer_value: bytes[3],
        };
        let bytes_written = modem.send_command(ModemCommand::EmmTimerControl(modem_request))?;
        Ok(HandledCall::for_request(
            request,
            SdkCommand::EmmTimerControl,
            bytes_written,
        ))
    }

    fn dispatch_psm_control<T: Write>(
        modem: &mut Modem<T>,
        request: SdkApiRequest<'_>,
    ) -> Result<HandledCall, HandleError> {
        let bytes = *exact_params::<6>(&request)?;
        let modem_request = PsmControlRequest {
            ctrl_cmd: u16::from_be_bytes([bytes[0], bytes[1]]),
            t3324_timer_value_unit: bytes[2],
            t3324_timer_value: bytes[3],
            ext_t3412_timer_value_unit: bytes[4],
            ext_t3412_timer_value: bytes[5],
        };
        let bytes_written = modem.send_command(ModemCommand::PsmControl(modem_request))?;
        Ok(HandledCall::for_request(
            request,
            SdkCommand::PsmControl,
            bytes_written,
        ))
    }

    fn dispatch_lcs_control<T: Write>(
        modem: &mut Modem<T>,
        request: SdkApiRequest<'_>,
    ) -> Result<HandledCall, HandleError> {
        let bytes = *exact_params::<4>(&request)?;
        let bytes_written = modem.send_command(ModemCommand::LcsControl(LcsControlRequest {
            mode: u32::from_be_bytes(bytes),
        }))?;
        Ok(HandledCall::for_request(
            request,
            SdkCommand::LcsControl,
            bytes_written,
        ))
    }

    fn dispatch_lpp_control<T: Write>(
        modem: &mut Modem<T>,
        request: SdkApiRequest<'_>,
    ) -> Result<HandledCall, HandleError> {
        let bytes = *exact_params::<4>(&request)?;
        let bytes_written = modem.send_command(ModemCommand::LppControl(LppControlRequest {
            mode: u32::from_be_bytes(bytes),
        }))?;
        Ok(HandledCall::for_request(
            request,
            SdkCommand::LppControl,
            bytes_written,
        ))
    }

    fn dispatch_emm_timer_start<T: Write>(
        modem: &mut Modem<T>,
        request: SdkApiRequest<'_>,
    ) -> Result<HandledCall, HandleError> {
        let params = *exact_params::<3>(&request)?;
        let bytes_written =
            modem.send_command(ModemCommand::EmmTimerStart(EmmTimerStartRequest { params }))?;
        Ok(HandledCall::for_request(
            request,
            SdkCommand::EmmTimerStart,
            bytes_written,
        ))
    }

    fn dispatch_emm_ni_reattach_control<T: Write>(
        &mut self,
        modem: &mut Modem<T>,
        request: SdkApiRequest<'_>,
    ) -> Result<HandledCall, HandleError> {
        let bytes = *exact_params::<4>(&request)?;
        let modem_request = EmmNiReattachControlRequest {
            control: u32::from_be_bytes(bytes),
        };
        let bytes_written = modem.send_tracked_command(
            &mut self.pending,
            ModemCommand::EmmNiReattachControl(modem_request),
        )?;
        Ok(HandledCall::for_request(
            request,
            SdkCommand::EmmNiReattachControl,
            bytes_written,
        ))
    }

    fn dispatch_rf_status_report_control<T: Write>(
        &mut self,
        modem: &mut Modem<T>,
        request: SdkApiRequest<'_>,
    ) -> Result<HandledCall, HandleError> {
        let bytes = *exact_params::<10>(&request)?;
        let modem_request = RfStatusReportControlRequest {
            on_off: u16::from_be_bytes([bytes[0], bytes[1]]),
            intval_idle: u16::from_be_bytes([bytes[2], bytes[3]]),
            intval_connect: u16::from_be_bytes([bytes[4], bytes[5]]),
            thresh_idle: u16::from_be_bytes([bytes[6], bytes[7]]),
            thresh_connect: u16::from_be_bytes([bytes[8], bytes[9]]),
        };
        let bytes_written = modem.send_tracked_command(
            &mut self.pending,
            ModemCommand::RfStatusReportControl(modem_request),
        )?;
        Ok(HandledCall::for_request(
            request,
            SdkCommand::RfStatusReportControl,
            bytes_written,
        ))
    }

    fn dispatch_rf_measure_report<T: Write>(
        &mut self,
        modem: &mut Modem<T>,
        request: SdkApiRequest<'_>,
    ) -> Result<HandledCall, HandleError> {
        let &[control] = exact_params::<1>(&request)?;
        let bytes_written = modem.send_tracked_command(
            &mut self.pending,
            ModemCommand::RfMeasureReport(RfMeasureReportRequest { control }),
        )?;
        Ok(HandledCall::for_request(
            request,
            SdkCommand::RfMeasureReport,
            bytes_written,
        ))
    }

    fn dispatch_ue_mode_change<T: Write>(
        &mut self,
        modem: &mut Modem<T>,
        request: SdkApiRequest<'_>,
    ) -> Result<HandledCall, HandleError> {
        let &[mode] = exact_params::<1>(&request)?;
        let bytes_written = modem.send_tracked_command(
            &mut self.pending,
            ModemCommand::UeModeChange(UeModeChangeRequest { mode }),
        )?;
        Ok(HandledCall::for_request(
            request,
            SdkCommand::UeModeChange,
            bytes_written,
        ))
    }

    fn dispatch_contents_reset_and_delete<T: Write>(
        &mut self,
        modem: &mut Modem<T>,
        request: SdkApiRequest<'_>,
    ) -> Result<HandledCall, HandleError> {
        let bytes = *exact_params::<4>(&request)?;
        let bytes_written = modem.send_tracked_command(
            &mut self.pending,
            ModemCommand::ContentsResetAndDelete(ContentsResetAndDeleteRequest {
                mask_id: u32::from_be_bytes(bytes),
            }),
        )?;
        Ok(HandledCall::for_request(
            request,
            SdkCommand::ContentsResetAndDelete,
            bytes_written,
        ))
    }

    fn dispatch_plmn_search_stop<T: Write>(
        &mut self,
        modem: &mut Modem<T>,
        request: SdkApiRequest<'_>,
    ) -> Result<HandledCall, HandleError> {
        let &[search_type] = exact_params::<1>(&request)?;
        let bytes_written = modem.send_tracked_command(
            &mut self.pending,
            ModemCommand::PlmnSearchStop(PlmnSearchStopRequest { search_type }),
        )?;
        Ok(HandledCall::for_request(
            request,
            SdkCommand::PlmnSearchStop,
            bytes_written,
        ))
    }

    fn dispatch_plmn_search_ext<T: Write>(
        &mut self,
        modem: &mut Modem<T>,
        request: SdkApiRequest<'_>,
    ) -> Result<HandledCall, HandleError> {
        let params = exact_params::<LEGACY_PLMN_SEARCH_EXT_PARAMS_LEN>(&request)?;
        let search = decode_legacy_plmn_search_ext(params);
        let bytes_written =
            modem.send_tracked_command(&mut self.pending, ModemCommand::PlmnSearchExt(search))?;
        Ok(HandledCall::for_request(
            request,
            SdkCommand::PlmnSearchExt,
            bytes_written,
        ))
    }

    fn dispatch_plmn_search<T: Write>(
        &mut self,
        modem: &mut Modem<T>,
        request: SdkApiRequest<'_>,
    ) -> Result<HandledCall, HandleError> {
        let params = exact_params::<LEGACY_PLMN_SEARCH_PARAMS_LEN>(&request)?;
        let search = decode_legacy_plmn_search(params);
        let bytes_written =
            modem.send_tracked_command(&mut self.pending, ModemCommand::PlmnSearch(search))?;
        Ok(HandledCall::for_request(
            request,
            SdkCommand::PlmnSearch,
            bytes_written,
        ))
    }

    fn dispatch_detach<T: Write>(
        &mut self,
        modem: &mut Modem<T>,
        request: SdkApiRequest<'_>,
    ) -> Result<HandledCall, HandleError> {
        let bytes = *exact_params::<4>(&request)?;
        let detach = DetachRequest::from_raw(u32::from_be_bytes(bytes));
        let bytes_written =
            modem.send_tracked_command(&mut self.pending, ModemCommand::Detach(detach))?;

        // Live LAPI_DetachRequest calls tid_list_clean() before sending. Keep
        // the same logical reset, but commit it only after a successful GLIF
        // write so an I/O failure cannot strand replacement-side state.
        self.apn_state.clear_tids();
        self.pending.clear_transaction_ids();

        Ok(HandledCall::for_request(
            request,
            SdkCommand::Detach,
            bytes_written,
        ))
    }

    fn dispatch_pdn_connect<T: Write>(
        &mut self,
        modem: &mut Modem<T>,
        request: SdkApiRequest<'_>,
    ) -> Result<HandledCall, HandleError> {
        let transaction_id = self.allocate_transaction_id()?;
        let decoded = decode_legacy_pdn_connect(request.params, transaction_id)
            .map_err(HandleError::LegacyPdnConnect)?;
        let bytes_written = modem
            .send_tracked_command(&mut self.pending, ModemCommand::PdnConnect(decoded.modem))?;
        self.apn_state.add_normal_tid(
            transaction_id,
            0x3105,
            decoded.tid_state.requested_apn_type,
            0,
            decoded.tid_state.ip_allocation,
        );
        Ok(HandledCall::for_request(
            request,
            SdkCommand::PdnConnect,
            bytes_written,
        ))
    }

    fn dispatch_pdn_connect_ext<T: Write>(
        &mut self,
        modem: &mut Modem<T>,
        request: SdkApiRequest<'_>,
    ) -> Result<HandledCall, HandleError> {
        let pdn = decode_legacy_pdn_connect_ext(request.params)
            .map_err(HandleError::LegacyPdnConnectExt)?;
        let bytes_written =
            modem.send_tracked_command(&mut self.pending, ModemCommand::PdnConnectExt(pdn))?;
        Ok(HandledCall::for_request(
            request,
            SdkCommand::PdnConnectExt,
            bytes_written,
        ))
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
        self.apn_state
            .add_normal_tid(transaction_id, 0x3107, 0xff, pdn.default_eps_id, 0);
        Ok(HandledCall::for_request(
            request,
            SdkCommand::PdnDisconnect,
            bytes_written,
        ))
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
        Ok(HandledCall::for_request(
            request,
            SdkCommand::AttachExt,
            bytes_written,
        ))
    }

    fn dispatch_attach<T: Write>(
        &mut self,
        modem: &mut Modem<T>,
        request: SdkApiRequest<'_>,
    ) -> Result<HandledCall, HandleError> {
        let decoded = decode_legacy_attach(request.params).map_err(HandleError::LegacyAttach)?;
        let mut attach = decoded.modem;
        let transaction_id = if attach.optional_info == 0 {
            None
        } else {
            let transaction_id = self.allocate_transaction_id()?;
            attach.transaction_id = transaction_id;
            Some(transaction_id)
        };
        let bytes_written =
            modem.send_tracked_command(&mut self.pending, ModemCommand::Attach(attach))?;
        if let Some(transaction_id) = transaction_id {
            self.apn_state.add_normal_tid(
                transaction_id,
                0x3101,
                decoded.tid_state.requested_apn_type,
                0,
                decoded.tid_state.ip_allocation,
            );
        }
        Ok(HandledCall::for_request(
            request,
            SdkCommand::Attach,
            bytes_written,
        ))
    }

    fn dispatch_uicc<T: Write>(
        &mut self,
        modem: &mut Modem<T>,
        request: SdkApiRequest<'_>,
    ) -> Result<HandledCall, HandleError> {
        let decoded = decode_legacy_uicc(request.params).map_err(HandleError::LegacyUicc)?;
        let modem_command = match decoded {
            LegacyUiccRequest::Status(request) => ModemCommand::UiccStatus(request),
            LegacyUiccRequest::ReadBinary(request) => ModemCommand::UiccReadBinary(request),
            LegacyUiccRequest::ReadRecord(request) => ModemCommand::UiccReadRecord(request),
            LegacyUiccRequest::Fixed(request) => ModemCommand::UiccFixed(request),
            LegacyUiccRequest::PinStatus(request) => ModemCommand::UiccPinStatus(request),
        };
        let bytes_written = modem.send_tracked_command(&mut self.pending, modem_command)?;
        Ok(HandledCall::for_request(
            request,
            SdkCommand::UiccRequest,
            bytes_written,
        ))
    }

    fn dispatch_at<T: Write>(
        modem: &mut Modem<T>,
        request: SdkApiRequest<'_>,
    ) -> Result<HandledCall, HandleError> {
        let bytes_written = modem.send_command(ModemCommand::At(AtCommand::new(request.params)))?;
        Ok(HandledCall::for_request(
            request,
            SdkCommand::AtCommand,
            bytes_written,
        ))
    }

    fn dispatch_at_ext<T: Write>(
        modem: &mut Modem<T>,
        request: SdkApiRequest<'_>,
    ) -> Result<HandledCall, HandleError> {
        let Some((&channel, command)) = request.params.split_first() else {
            return Err(HandleError::UnexpectedParameters {
                command: request.command,
                expected: 1,
                actual: 0,
            });
        };
        let bytes_written =
            modem.send_command(ModemCommand::AtExt(AtCommandExt::new(channel, command)))?;
        Ok(HandledCall::for_request(
            request,
            SdkCommand::AtCommandExt,
            bytes_written,
        ))
    }

    fn dispatch_temperature_read<T: Write>(
        &mut self,
        modem: &mut Modem<T>,
        request: SdkApiRequest<'_>,
    ) -> Result<HandledCall, HandleError> {
        require_no_params(&request)?;
        let bytes_written = modem.send_tracked_command(
            &mut self.pending,
            ModemCommand::TemperatureRead(TemperatureReadRequest),
        )?;
        Ok(HandledCall::for_request(
            request,
            SdkCommand::TemperatureRead,
            bytes_written,
        ))
    }

    fn dispatch_iccid_read<T: Write>(
        &mut self,
        modem: &mut Modem<T>,
        request: SdkApiRequest<'_>,
    ) -> Result<HandledCall, HandleError> {
        require_no_params(&request)?;
        let bytes_written = modem
            .send_tracked_command(&mut self.pending, ModemCommand::IccidRead(IccidReadRequest))?;
        Ok(HandledCall::for_request(
            request,
            SdkCommand::IccidRead,
            bytes_written,
        ))
    }

    fn dispatch_msisdn_read<T: Write>(
        &mut self,
        modem: &mut Modem<T>,
        request: SdkApiRequest<'_>,
    ) -> Result<HandledCall, HandleError> {
        require_no_params(&request)?;
        let bytes_written = modem.send_tracked_command(
            &mut self.pending,
            ModemCommand::MsisdnRead(MsisdnReadRequest),
        )?;
        Ok(HandledCall::for_request(
            request,
            SdkCommand::MsisdnRead,
            bytes_written,
        ))
    }

    fn dispatch_mobile_id_read<T: Write>(
        &mut self,
        modem: &mut Modem<T>,
        request: SdkApiRequest<'_>,
    ) -> Result<HandledCall, HandleError> {
        let &[mobile_id_type] = exact_params::<1>(&request)?;
        let bytes_written = modem.send_tracked_command(
            &mut self.pending,
            ModemCommand::MobileIdRead(MobileIdReadRequest { mobile_id_type }),
        )?;
        Ok(HandledCall::for_request(
            request,
            SdkCommand::MobileIdRead,
            bytes_written,
        ))
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
        require_no_params(&request)?;
        let modem_command = ModemCommand::Empty(empty);
        let bytes_written = modem.send_tracked_command(&mut self.pending, modem_command)?;
        if empty == EmptyRequest::PsInit && self.startup_phase == StartupPhase::Idle {
            self.startup_phase = StartupPhase::AwaitingPsInit;
        }
        Ok(HandledCall::for_request(request, command, bytes_written))
    }
}

#[cfg(test)]
mod tests;
