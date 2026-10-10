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
    LegacyAttachDecodeError, LegacyAttachExtDecodeError, LegacyPdnConnectDecodeError,
    LegacyPdnConnectExtDecodeError, LegacyPdnDisconnectDecodeError, LegacyRrcCapabilityDecodeError,
    LegacyRrcFunctionDecodeError, LegacySetProtocolInfoDecodeError, LegacyUiccDecodeError,
    LegacyUiccRequest, RRC_FUNCTION_CELL_LOCK_WIRE_LEN, decode_legacy_attach,
    decode_legacy_attach_ext, decode_legacy_pdn_connect, decode_legacy_pdn_connect_ext,
    decode_legacy_pdn_disconnect, decode_legacy_rrc_capability_get,
    decode_legacy_rrc_capability_set, decode_legacy_rrc_function_get,
    decode_legacy_rrc_function_set, decode_legacy_set_protocol_info, decode_legacy_uicc,
    materialize_rrc_function_cell_lock_wire, rrc_capability_set_success_has_callback,
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
        PlmnInfoDecodeError, PlmnListResponse, PlmnSearchExtRequest, PlmnSearchRequest,
        PlmnSearchStopRequest, QuerySelectedPlmnRequest, QuerySelectedPlmnResponse,
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
        name_len: u8,
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
            } => &interface_name[..usize::from(*name_len)],
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
        let [cid] = request.params else {
            return Err(HandleError::UnexpectedParameters {
                command: request.command,
                expected: 1,
                actual: request.params.len(),
            });
        };
        write_result(u8::from(self.nic_state.has_ipv4_lease_for_cid(*cid)))?;
        Ok(HandledCall {
            command: SdkCommand::CheckDhcpLeaseState,
            device_id: request.device_id,
            bytes_written: 0,
        })
    }

    fn dispatch_set_mtu_size<F>(
        request: SdkApiRequest<'_>,
        host_action: &mut F,
    ) -> Result<HandledCall, HandleError>
    where
        F: FnMut(HostAction) -> io::Result<()>,
    {
        if request.params.len() != 258 {
            return Err(HandleError::UnexpectedParameters {
                command: request.command,
                expected: 258,
                actual: request.params.len(),
            });
        }
        let name_source = &request.params[..15];
        let name_len = name_source
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(name_source.len());
        if name_len == 0 {
            return Err(HandleError::HostRequest(
                HostRequestError::EmptyInterfaceName,
            ));
        }
        let mtu = u16::from_be_bytes([request.params[256], request.params[257]]);
        if mtu == 0 {
            return Err(HandleError::HostRequest(HostRequestError::ZeroMtu));
        }
        let mut interface_name = [0_u8; 15];
        interface_name[..name_len].copy_from_slice(&name_source[..name_len]);
        host_action(HostAction::SetMtu {
            interface_name,
            name_len: u8::try_from(name_len).unwrap_or(15),
            mtu,
        })
        .map_err(HandleError::Host)?;
        Ok(HandledCall {
            command: SdkCommand::SetMtuSize,
            device_id: request.device_id,
            bytes_written: 0,
        })
    }

    fn dispatch_ps_init_complete<F>(
        &self,
        request: SdkApiRequest<'_>,
        write_result: F,
    ) -> Result<HandledCall, HandleError>
    where
        F: FnOnce(u8) -> io::Result<()>,
    {
        if !request.params.is_empty() {
            return Err(HandleError::UnexpectedParameters {
                command: request.command,
                expected: 0,
                actual: request.params.len(),
            });
        }
        write_result(u8::from(self.init_complete()))?;
        Ok(HandledCall {
            command: SdkCommand::GetPsInitComplete,
            device_id: request.device_id,
            bytes_written: 0,
        })
    }

    fn dispatch_connection_info<F>(
        &self,
        request: SdkApiRequest<'_>,
        write_result: F,
    ) -> Result<HandledCall, HandleError>
    where
        F: FnOnce(&[u8]) -> io::Result<()>,
    {
        if request.params.len() != CONNECTION_INFO_LEN {
            return Err(HandleError::UnexpectedParameters {
                command: request.command,
                expected: CONNECTION_INFO_LEN,
                actual: request.params.len(),
            });
        }
        let snapshot = self.nic_state.snapshot();
        write_result(&snapshot)?;
        Ok(HandledCall {
            command: SdkCommand::GetConnectionInfo,
            device_id: request.device_id,
            bytes_written: 0,
        })
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
                || self.pending.contains(ResponseKey::Attach(transaction_id))
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
                let bytes: [u8; 4] =
                    request
                        .params
                        .try_into()
                        .map_err(|_| HandleError::UnexpectedParameters {
                            command: request.command,
                            expected: 4,
                            actual: request.params.len(),
                        })?;
                self.apn_state
                    .set_configured_type(u32::from_be_bytes(bytes))
                    .map_err(HandleError::ApnState)?;
            }
            SdkCommand::GetApnType => {
                if !request.params.is_empty() {
                    return Err(HandleError::UnexpectedParameters {
                        command: request.command,
                        expected: 0,
                        actual: request.params.len(),
                    });
                }
                write_result(self.apn_state.configured_type())?;
            }
            SdkCommand::GetApnTypeByDefaultEpsId => {
                let bytes: [u8; 2] =
                    request
                        .params
                        .try_into()
                        .map_err(|_| HandleError::UnexpectedParameters {
                            command: request.command,
                            expected: 2,
                            actual: request.params.len(),
                        })?;
                write_result(
                    self.apn_state
                        .apn_type_by_default_eps_id(u16::from_be_bytes(bytes)),
                )?;
            }
            SdkCommand::DeleteApnTypeFromTidNode => {
                let record = SpecialTidRecord::decode(request.params).map_err(|actual| {
                    HandleError::UnexpectedParameters {
                        command: request.command,
                        expected: 7,
                        actual,
                    }
                })?;
                self.apn_state
                    .delete_by_apn_type(record.requested_apn_type());
            }
            SdkCommand::AddSpecialTid => {
                let record = SpecialTidRecord::decode(request.params).map_err(|actual| {
                    HandleError::UnexpectedParameters {
                        command: request.command,
                        expected: 7,
                        actual,
                    }
                })?;
                let tid = self.allocate_transaction_id()?;
                self.apn_state.add_special_tid(tid, record);
            }
            _ => return Err(HandleError::UnsupportedCommand(request.command)),
        }
        Ok(HandledCall {
            command,
            device_id: request.device_id,
            bytes_written: 0,
        })
    }

    fn dispatch_device_information<T: Write>(
        &mut self,
        modem: &mut Modem<T>,
        request: SdkApiRequest<'_>,
    ) -> Result<HandledCall, HandleError> {
        if !request.params.is_empty() {
            return Err(HandleError::UnexpectedParameters {
                command: request.command,
                expected: 0,
                actual: request.params.len(),
            });
        }
        let bytes_written = modem.send_tracked_command(
            &mut self.pending,
            ModemCommand::DeviceInformation(DeviceInformationRequest),
        )?;
        Ok(HandledCall {
            command: SdkCommand::GetDeviceInformation,
            device_id: request.device_id,
            bytes_written,
        })
    }

    fn dispatch_nas_config_set<T: Write>(
        modem: &mut Modem<T>,
        request: SdkApiRequest<'_>,
    ) -> Result<HandledCall, HandleError> {
        if request.params.len() != 33 {
            return Err(HandleError::UnexpectedParameters {
                command: request.command,
                expected: 33,
                actual: request.params.len(),
            });
        }
        let modem_request = NasConfigSetRequest {
            count: request.params[0],
            pairs: &request.params[1..],
        };
        let bytes_written = modem.send_command(ModemCommand::NasConfigSet(modem_request))?;
        Ok(HandledCall {
            command: SdkCommand::SetNasConfig,
            device_id: request.device_id,
            bytes_written,
        })
    }

    fn dispatch_nas_config_get<T: Write>(
        modem: &mut Modem<T>,
        request: SdkApiRequest<'_>,
    ) -> Result<HandledCall, HandleError> {
        if !request.params.is_empty() {
            return Err(HandleError::UnexpectedParameters {
                command: request.command,
                expected: 0,
                actual: request.params.len(),
            });
        }
        let bytes_written = modem.send_command(ModemCommand::NasConfigGet(NasConfigGetRequest))?;
        Ok(HandledCall {
            command: SdkCommand::GetNasConfig,
            device_id: request.device_id,
            bytes_written,
        })
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
        Ok(HandledCall {
            command: SdkCommand::SetProtocolInfo,
            device_id: request.device_id,
            bytes_written,
        })
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
        Ok(HandledCall {
            command: SdkCommand::RrcCapabilityControl,
            device_id: request.device_id,
            bytes_written,
        })
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
        Ok(HandledCall {
            command: SdkCommand::RrcCapabilityControlGet,
            device_id: request.device_id,
            bytes_written,
        })
    }

    fn dispatch_query_selected_plmn<T: Write>(
        &mut self,
        modem: &mut Modem<T>,
        request: SdkApiRequest<'_>,
    ) -> Result<HandledCall, HandleError> {
        if !request.params.is_empty() {
            return Err(HandleError::UnexpectedParameters {
                command: request.command,
                expected: 0,
                actual: request.params.len(),
            });
        }
        let bytes_written = modem.send_tracked_command(
            &mut self.pending,
            ModemCommand::QuerySelectedPlmn(QuerySelectedPlmnRequest),
        )?;
        Ok(HandledCall {
            command: SdkCommand::QuerySelectedPlmn,
            device_id: request.device_id,
            bytes_written,
        })
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
        Ok(HandledCall {
            command: SdkCommand::RrcFunctionControl,
            device_id: request.device_id,
            bytes_written,
        })
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
        Ok(HandledCall {
            command: SdkCommand::RrcFunctionControlGet,
            device_id: request.device_id,
            bytes_written,
        })
    }

    fn dispatch_emm_timer_control<T: Write>(
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
        let modem_request = EmmTimerControlRequest {
            timer_id: u16::from_be_bytes([bytes[0], bytes[1]]),
            timer_value_unit: bytes[2],
            timer_value: bytes[3],
        };
        let bytes_written = modem.send_command(ModemCommand::EmmTimerControl(modem_request))?;
        Ok(HandledCall {
            command: SdkCommand::EmmTimerControl,
            device_id: request.device_id,
            bytes_written,
        })
    }

    fn dispatch_psm_control<T: Write>(
        modem: &mut Modem<T>,
        request: SdkApiRequest<'_>,
    ) -> Result<HandledCall, HandleError> {
        let bytes: [u8; 6] =
            request
                .params
                .try_into()
                .map_err(|_| HandleError::UnexpectedParameters {
                    command: request.command,
                    expected: 6,
                    actual: request.params.len(),
                })?;
        let modem_request = PsmControlRequest {
            ctrl_cmd: u16::from_be_bytes([bytes[0], bytes[1]]),
            t3324_timer_value_unit: bytes[2],
            t3324_timer_value: bytes[3],
            ext_t3412_timer_value_unit: bytes[4],
            ext_t3412_timer_value: bytes[5],
        };
        let bytes_written = modem.send_command(ModemCommand::PsmControl(modem_request))?;
        Ok(HandledCall {
            command: SdkCommand::PsmControl,
            device_id: request.device_id,
            bytes_written,
        })
    }

    fn dispatch_lcs_control<T: Write>(
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
        let bytes_written = modem.send_command(ModemCommand::LcsControl(LcsControlRequest {
            mode: u32::from_be_bytes(bytes),
        }))?;
        Ok(HandledCall {
            command: SdkCommand::LcsControl,
            device_id: request.device_id,
            bytes_written,
        })
    }

    fn dispatch_lpp_control<T: Write>(
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
        let bytes_written = modem.send_command(ModemCommand::LppControl(LppControlRequest {
            mode: u32::from_be_bytes(bytes),
        }))?;
        Ok(HandledCall {
            command: SdkCommand::LppControl,
            device_id: request.device_id,
            bytes_written,
        })
    }

    fn dispatch_emm_timer_start<T: Write>(
        modem: &mut Modem<T>,
        request: SdkApiRequest<'_>,
    ) -> Result<HandledCall, HandleError> {
        let params: [u8; 3] =
            request
                .params
                .try_into()
                .map_err(|_| HandleError::UnexpectedParameters {
                    command: request.command,
                    expected: 3,
                    actual: request.params.len(),
                })?;
        let bytes_written =
            modem.send_command(ModemCommand::EmmTimerStart(EmmTimerStartRequest { params }))?;
        Ok(HandledCall {
            command: SdkCommand::EmmTimerStart,
            device_id: request.device_id,
            bytes_written,
        })
    }

    fn dispatch_emm_ni_reattach_control<T: Write>(
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
        let modem_request = EmmNiReattachControlRequest {
            control: u32::from_be_bytes(bytes),
        };
        let bytes_written = modem.send_tracked_command(
            &mut self.pending,
            ModemCommand::EmmNiReattachControl(modem_request),
        )?;
        Ok(HandledCall {
            command: SdkCommand::EmmNiReattachControl,
            device_id: request.device_id,
            bytes_written,
        })
    }

    fn dispatch_rf_status_report_control<T: Write>(
        &mut self,
        modem: &mut Modem<T>,
        request: SdkApiRequest<'_>,
    ) -> Result<HandledCall, HandleError> {
        let bytes: [u8; 10] =
            request
                .params
                .try_into()
                .map_err(|_| HandleError::UnexpectedParameters {
                    command: request.command,
                    expected: 10,
                    actual: request.params.len(),
                })?;
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
        Ok(HandledCall {
            command: SdkCommand::RfStatusReportControl,
            device_id: request.device_id,
            bytes_written,
        })
    }

    fn dispatch_rf_measure_report<T: Write>(
        &mut self,
        modem: &mut Modem<T>,
        request: SdkApiRequest<'_>,
    ) -> Result<HandledCall, HandleError> {
        let [control]: [u8; 1] =
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
            ModemCommand::RfMeasureReport(RfMeasureReportRequest { control }),
        )?;
        Ok(HandledCall {
            command: SdkCommand::RfMeasureReport,
            device_id: request.device_id,
            bytes_written,
        })
    }

    fn dispatch_ue_mode_change<T: Write>(
        &mut self,
        modem: &mut Modem<T>,
        request: SdkApiRequest<'_>,
    ) -> Result<HandledCall, HandleError> {
        let [mode]: [u8; 1] =
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
            ModemCommand::UeModeChange(UeModeChangeRequest { mode }),
        )?;
        Ok(HandledCall {
            command: SdkCommand::UeModeChange,
            device_id: request.device_id,
            bytes_written,
        })
    }

    fn dispatch_contents_reset_and_delete<T: Write>(
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
        let bytes_written = modem.send_tracked_command(
            &mut self.pending,
            ModemCommand::ContentsResetAndDelete(ContentsResetAndDeleteRequest {
                mask_id: u32::from_be_bytes(bytes),
            }),
        )?;
        Ok(HandledCall {
            command: SdkCommand::ContentsResetAndDelete,
            device_id: request.device_id,
            bytes_written,
        })
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

    fn dispatch_plmn_search_ext<T: Write>(
        &mut self,
        modem: &mut Modem<T>,
        request: SdkApiRequest<'_>,
    ) -> Result<HandledCall, HandleError> {
        const STOCK_LEN: usize = 1_292;
        let params: &[u8; STOCK_LEN] =
            request
                .params
                .try_into()
                .map_err(|_| HandleError::UnexpectedParameters {
                    command: request.command,
                    expected: STOCK_LEN,
                    actual: request.params.len(),
                })?;

        let list_count = params[9];
        let list_len = usize::from(params[10]);
        let list_data = if list_count == 0 {
            &[][..]
        } else {
            &params[11..11 + list_len]
        };
        let search = PlmnSearchExtRequest {
            selection_mode: params[0],
            operation_mode: params[1],
            mcc: [params[2], params[3], params[4]],
            mnc: [params[5], params[6], params[7]],
            roaming_option: params[8],
            list_count,
            list_data,
            power_scan: params[1_291] == 1,
        };
        let bytes_written =
            modem.send_tracked_command(&mut self.pending, ModemCommand::PlmnSearchExt(search))?;
        Ok(HandledCall {
            command: SdkCommand::PlmnSearchExt,
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

        // Live LAPI_DetachRequest calls tid_list_clean() before sending. Keep
        // the same logical reset, but commit it only after a successful GLIF
        // write so an I/O failure cannot strand replacement-side state.
        self.apn_state.clear_tids();
        for transaction_id in 1_u8..=253 {
            self.pending.remove(ResponseKey::Attach(transaction_id));
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
        self.apn_state.add_normal_tid(
            transaction_id,
            0x3105,
            request.params[0x19a],
            0,
            request.params[0x067],
        );
        Ok(HandledCall {
            command: SdkCommand::PdnConnect,
            device_id: request.device_id,
            bytes_written,
        })
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
        Ok(HandledCall {
            command: SdkCommand::PdnConnectExt,
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
        self.apn_state
            .add_normal_tid(transaction_id, 0x3107, 0xff, pdn.default_eps_id, 0);
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
        let mut attach = decode_legacy_attach(request.params).map_err(HandleError::LegacyAttach)?;
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
                request.params[0x152],
                0,
                request.params[0x067],
            );
        }
        Ok(HandledCall {
            command: SdkCommand::Attach,
            device_id: request.device_id,
            bytes_written,
        })
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
        Ok(HandledCall {
            command: SdkCommand::UiccRequest,
            device_id: request.device_id,
            bytes_written,
        })
    }

    fn dispatch_at<T: Write>(
        modem: &mut Modem<T>,
        request: SdkApiRequest<'_>,
    ) -> Result<HandledCall, HandleError> {
        let bytes_written = modem.send_command(ModemCommand::At(AtCommand::new(request.params)))?;
        Ok(HandledCall {
            command: SdkCommand::AtCommand,
            device_id: request.device_id,
            bytes_written,
        })
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
        Ok(HandledCall {
            command: SdkCommand::AtCommandExt,
            device_id: request.device_id,
            bytes_written,
        })
    }

    fn dispatch_temperature_read<T: Write>(
        &mut self,
        modem: &mut Modem<T>,
        request: SdkApiRequest<'_>,
    ) -> Result<HandledCall, HandleError> {
        if !request.params.is_empty() {
            return Err(HandleError::UnexpectedParameters {
                command: request.command,
                expected: 0,
                actual: request.params.len(),
            });
        }
        let bytes_written = modem.send_tracked_command(
            &mut self.pending,
            ModemCommand::TemperatureRead(TemperatureReadRequest),
        )?;
        Ok(HandledCall {
            command: SdkCommand::TemperatureRead,
            device_id: request.device_id,
            bytes_written,
        })
    }

    fn dispatch_iccid_read<T: Write>(
        &mut self,
        modem: &mut Modem<T>,
        request: SdkApiRequest<'_>,
    ) -> Result<HandledCall, HandleError> {
        if !request.params.is_empty() {
            return Err(HandleError::UnexpectedParameters {
                command: request.command,
                expected: 0,
                actual: request.params.len(),
            });
        }
        let bytes_written = modem
            .send_tracked_command(&mut self.pending, ModemCommand::IccidRead(IccidReadRequest))?;
        Ok(HandledCall {
            command: SdkCommand::IccidRead,
            device_id: request.device_id,
            bytes_written,
        })
    }

    fn dispatch_msisdn_read<T: Write>(
        &mut self,
        modem: &mut Modem<T>,
        request: SdkApiRequest<'_>,
    ) -> Result<HandledCall, HandleError> {
        if !request.params.is_empty() {
            return Err(HandleError::UnexpectedParameters {
                command: request.command,
                expected: 0,
                actual: request.params.len(),
            });
        }
        let bytes_written = modem.send_tracked_command(
            &mut self.pending,
            ModemCommand::MsisdnRead(MsisdnReadRequest),
        )?;
        Ok(HandledCall {
            command: SdkCommand::MsisdnRead,
            device_id: request.device_id,
            bytes_written,
        })
    }

    fn dispatch_mobile_id_read<T: Write>(
        &mut self,
        modem: &mut Modem<T>,
        request: SdkApiRequest<'_>,
    ) -> Result<HandledCall, HandleError> {
        let [mobile_id_type] = request.params else {
            return Err(HandleError::UnexpectedParameters {
                command: request.command,
                expected: 1,
                actual: request.params.len(),
            });
        };
        let bytes_written = modem.send_tracked_command(
            &mut self.pending,
            ModemCommand::MobileIdRead(MobileIdReadRequest {
                mobile_id_type: *mobile_id_type,
            }),
        )?;
        Ok(HandledCall {
            command: SdkCommand::MobileIdRead,
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

    use gct_lapi::{
        attach::DetachRequiredIndication,
        common::{ResultResponse, ResultResponseKind},
        misc::DeviceInformationDecodeError,
        uicc::UiccResponse,
    };
    use gct_runtime::{EventDecodeError, Modem, ModemEvent, ResponseKey};
    use gct_transport::HciIo;
    use lted_compat::Server;
    use lted_proto::{
        ApiOpenRequest, ApiOpenResponse, Packet, SdkApiRequest, SdkCallback, SdkCallbackKind,
        SdkCommand,
    };

    use super::legacy::{
        LegacyAttachExtStringField, LegacyAttachStringField, LegacyPdnConnectExtStringField,
        LegacyPdnConnectStringField,
    };
    use super::{
        APN_TYPE_RESULT_OFFSET, ApnStateError, BroadcastReport, CONNECTION_INFO_LEN,
        CONNECTION_INFO_OFFSET, DEVICE_INFORMATION_LEN, DEVICE_INFORMATION_OFFSET,
        DHCP_LEASE_STATE_RESULT_OFFSET, DeviceBridge, HandleError, HostAction, HostRequestError,
        LTE_API_RET_OFFSET, LegacyAttachDecodeError, LegacyAttachExtDecodeError,
        LegacyPdnConnectDecodeError, LegacyPdnConnectExtDecodeError,
        LegacyPdnDisconnectDecodeError, LegacyRrcCapabilityDecodeError,
        LegacyRrcFunctionDecodeError, LegacySetProtocolInfoDecodeError, LegacyUiccDecodeError,
        PS_INIT_COMPLETE_OFFSET, StartupPhase, UiccCallbackError, broadcast_result_callback,
        decode_legacy_attach, decode_legacy_attach_ext, decode_legacy_pdn_connect_ext,
        decode_legacy_pdn_disconnect, decode_legacy_rrc_capability_get,
        decode_legacy_rrc_capability_set, decode_legacy_set_protocol_info,
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

    fn read_shared_byte(server: &mut Server, id: u8, offset: usize) -> u8 {
        let mut byte = [0_u8; 1];
        server
            .client_context(id)
            .unwrap_or_else(|_| std::process::abort())
            .read(offset, &mut byte)
            .unwrap_or_else(|_| std::process::abort());
        byte[0]
    }

    fn bind_server(dir: &TestDir) -> Server {
        Server::bind_paths(dir.join("daemon"), dir.join("client-"))
            .unwrap_or_else(|_| std::process::abort())
    }

    fn hci_frame(command: u16, payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(4 + payload.len());
        frame.extend_from_slice(&command.to_be_bytes());
        frame.extend_from_slice(
            &u16::try_from(payload.len())
                .unwrap_or_else(|_| std::process::abort())
                .to_be_bytes(),
        );
        frame.extend_from_slice(payload);
        frame
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
    fn get_connection_info_materializes_typed_attach_network_state() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (_client, id) = open_client(&mut server, &dir, 0);
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(1);

        let mut attach = [0_u8; 352];
        attach[0] = 1;
        attach[0x067] = 4;
        attach[0x152] = 3;
        bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                id,
                SdkApiRequest {
                    command: SdkCommand::Attach as u16,
                    device_id: 1,
                    params: &attach,
                },
            )
            .unwrap_or_else(|_| std::process::abort());

        let mut attach_rsp = vec![
            0, 0, // register_result1
            0, 0, // register_result2
            0x12, 0x34, // default EPS ID
            0, 9, // EPS ID
            1, 4, // data path / IP allocation
            0, 0, 0, 0, 0, // network features
            0x20, 1, 1, // allocated transaction ID
            0x04, 8, b'i', b'n', b't', b'e', b'r', b'n', b'e', b't', // APN
        ];
        let pdn_fields = [
            0x05, 1, 3, // PDN type
            0x07, 4, 10, 20, 30, 40, // IPv4
            0x08, 4, 1, 1, 1, 1, // IPv4 DNS 1
            0x09, 4, 8, 8, 8, 8, // IPv4 DNS 2
            0x0a, 16, 0x20, 1, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x0b, 16, 0x20, 1,
            0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0x0c, 8, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x66, 0x77, 0x88,
        ];
        attach_rsp.push(0xf0);
        attach_rsp.push(u8::try_from(pdn_fields.len()).unwrap_or_else(|_| std::process::abort()));
        attach_rsp.extend_from_slice(&pdn_fields);
        attach_rsp.extend_from_slice(&[0x5b, 2, 0x05, 0xdc]); // IPv4 MTU 1500

        assert_eq!(
            route_one_hci(&mut bridge, &mut server, hci_frame(0xb102, &attach_rsp)),
            Some(BroadcastReport::default())
        );

        let params = vec![0_u8; CONNECTION_INFO_LEN];
        let handled = bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                id,
                SdkApiRequest {
                    command: SdkCommand::GetConnectionInfo as u16,
                    device_id: 1,
                    params: &params,
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(handled.command, SdkCommand::GetConnectionInfo);
        assert_eq!(handled.bytes_written, 0);
        assert_eq!(read_api_ret(&mut server, id), 0);

        let mut snapshot = vec![0_u8; CONNECTION_INFO_LEN];
        server
            .client_context(id)
            .unwrap_or_else(|_| std::process::abort())
            .read(CONNECTION_INFO_OFFSET, &mut snapshot)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(&snapshot[..4], &1_u32.to_be_bytes());
        let record = &snapshot[4..4 + 0x202];
        assert_eq!(&record[..8], b"lte0pdn3");
        assert_eq!(&record[0x100..0x104], &8_u32.to_be_bytes());
        assert_eq!(&record[0x104..0x108], &3_u32.to_be_bytes());
        assert_eq!(record[0x10d], 1);
        assert_eq!(record[0x10e], 3);
        assert_eq!(record[0x10f], 4);
        assert_eq!(&record[0x111..0x113], &0x1234_u16.to_be_bytes());
        assert_eq!(&record[0x113..0x11b], b"internet");
        assert_eq!(&record[0x154..0x158], &[10, 20, 30, 40]);
        assert_eq!(&record[0x158..0x15c], &[0xff, 0, 0, 0]);
        assert_eq!(&record[0x15c..0x160], &[10, 0, 0, 0xd7]);
        assert_eq!(&record[0x160..0x164], &[1, 1, 1, 1]);
        assert_eq!(&record[0x164..0x168], &[8, 8, 8, 8]);
        assert_eq!(&record[0x168..0x16a], &1500_u16.to_be_bytes());
        assert_eq!(
            &record[0x172..0x17a],
            &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]
        );
        assert_eq!(
            &record[0x18a..0x19a],
            &[0x20, 1, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        );
        assert_eq!(
            &record[0x19a..0x1aa],
            &[0x20, 1, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]
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
                0x31, 0x01, 0x00, 0x43, 0x01, 0x20, 0x01, 0x01, 0x02, 0x01, 0x75, 0x03, 0x01, 0x70,
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
            0x01, 0x99, 0x03, b'i', b'm', b's', 0xf0, 0x1a, 0x04, 0x03, b'p', b'd', b'n', 0x05,
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
        assert_eq!(data[0x27a], 1);
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
    fn stock_uicc_supported_requests_match_exact_live_p4_hci() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (_client, id) = open_client(&mut server, &dir, 0);
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(1);

        let cases: Vec<(Vec<u8>, Vec<u8>)> = vec![
            (
                vec![0x00, 0x00, 0x00, 0x01, 0x02],
                vec![0x35, 0x04, 0x00, 0x05, 0x00, 0x00, 0x00, 0x01, 0x02],
            ),
            (
                vec![
                    0x00, 0x01, 0x00, 0x09, 0x02, 0x00, 0x00, 0x6f, 0x07, 0x01, 0x23, 0x00, 0x40,
                ],
                vec![
                    0x35, 0x04, 0x00, 0x0d, 0x00, 0x01, 0x00, 0x09, 0x02, 0x00, 0x00, 0x6f, 0x07,
                    0x01, 0x23, 0x00, 0x40,
                ],
            ),
            (
                vec![0x00, 0x02, 0x00, 0x06, 0x01, 0x00, 0x00, 0x6f, 0x3a, 0x00],
                vec![
                    0x35, 0x04, 0x00, 0x0a, 0x00, 0x02, 0x00, 0x06, 0x01, 0x00, 0x00, 0x6f, 0x3a,
                    0x00,
                ],
            ),
        ];
        let mut expected = Vec::new();
        for (params, hci) in cases {
            bridge
                .handle_sdk_api(
                    &mut server,
                    &mut modem,
                    id,
                    SdkApiRequest {
                        command: SdkCommand::UiccRequest as u16,
                        device_id: 1,
                        params: &params,
                    },
                )
                .unwrap_or_else(|_| std::process::abort());
            expected.extend_from_slice(&hci);
        }

        let mut auth = vec![0xa5_u8; 40];
        auth[0..4].copy_from_slice(&[0x00, 0x05, 0x00, 0x24]);
        auth[4] = 2;
        auth[5] = 1;
        auth[6] = 0x11;
        auth[22] = 1;
        auth[23] = 0x22;
        auth[39] = 1;
        bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                id,
                SdkApiRequest {
                    command: SdkCommand::UiccRequest as u16,
                    device_id: 1,
                    params: &auth,
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        expected.extend_from_slice(&[0x35, 0x04, 0x00, 0x28, 0x00, 0x05, 0x00, 0x24]);
        expected.extend_from_slice(&auth[4..]);

        let mut pin = vec![0x5a_u8; 24];
        pin[0..4].copy_from_slice(&[0x00, 0x06, 0x00, 0x14]);
        bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                id,
                SdkApiRequest {
                    command: SdkCommand::UiccRequest as u16,
                    device_id: 1,
                    params: &pin,
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        expected.extend_from_slice(&[0x35, 0x04, 0x00, 0x18, 0x00, 0x06, 0x00, 0x14]);
        expected.extend_from_slice(&pin[4..]);

        // Live type-7 handling ignores the local data and emits len=0.
        let pin_status = [0x00, 0x07, 0x00, 0x03, 0xaa, 0xbb, 0xcc];
        bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                id,
                SdkApiRequest {
                    command: SdkCommand::UiccRequest as u16,
                    device_id: 1,
                    params: &pin_status,
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        expected.extend_from_slice(&[0x35, 0x04, 0x00, 0x04, 0x00, 0x07, 0x00, 0x00]);

        assert_eq!(bridge.pending_count(), 6);
        assert_eq!(read_api_ret(&mut server, id), 0);
        assert_eq!(modem.into_transport().into_inner().into_inner(), expected);
    }

    #[test]
    fn malformed_stock_uicc_is_rejected_before_modem_write() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (_client, id) = open_client(&mut server, &dir, 0);
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(1);

        let malformed = [0x00, 0x01, 0x00, 0x09, 1, 2, 3];
        assert!(matches!(
            bridge.handle_sdk_api(
                &mut server,
                &mut modem,
                id,
                SdkApiRequest {
                    command: SdkCommand::UiccRequest as u16,
                    device_id: 1,
                    params: &malformed,
                },
            ),
            Err(HandleError::LegacyUicc(
                LegacyUiccDecodeError::LengthMismatch {
                    declared: 9,
                    actual: 3,
                }
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
    fn uicc_callback_matches_stock_prefix_padding_and_subscription_gate() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (subscribed, subscribed_id) = open_client(&mut server, &dir, 0);
        let (unsubscribed, _unsubscribed_id) = open_client(&mut server, &dir, 1);
        server
            .client_context(subscribed_id)
            .unwrap_or_else(|_| std::process::abort())
            .write_u32_be(SdkCallbackKind::UiccFromDevice.registration_offset(), 1)
            .unwrap_or_else(|_| std::process::abort());

        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(0x1122_3344);
        let status_request = [0x00, 0x00, 0x00, 0x01, 0x02];
        bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                subscribed_id,
                SdkApiRequest {
                    command: SdkCommand::UiccRequest as u16,
                    device_id: 0x1122_3344,
                    params: &status_request,
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(bridge.pending_count(), 1);
        assert_eq!(
            route_one_hci(
                &mut bridge,
                &mut server,
                vec![
                    0xb5, 0x05, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 3, 2
                ],
            ),
            Some(BroadcastReport {
                registered_clients: 1,
                sent_clients: 1,
            })
        );
        assert_eq!(bridge.pending_count(), 0);
        let mut frame = vec![0_u8; 4096];
        let len = subscribed
            .recv(&mut frame)
            .unwrap_or_else(|_| std::process::abort());
        let callback = SdkCallback::parse(
            Packet::parse(&frame[..len]).unwrap_or_else(|_| std::process::abort()),
        )
        .unwrap_or_else(|_| std::process::abort());
        assert_eq!(callback.callback_id, 148);
        assert_eq!(callback.device_id, 0x1122_3344);
        assert_eq!(callback.data, &[0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 3, 2]);

        // READ BINARY uses the full fixed 2038-byte legacy subtype object.
        let binary_request = [
            0x00, 0x01, 0x00, 0x09, 0x02, 0x00, 0x00, 0x6f, 0x07, 0x00, 0x00, 0x00, 0x04,
        ];
        bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                subscribed_id,
                SdkApiRequest {
                    command: SdkCommand::UiccRequest as u16,
                    device_id: 0x1122_3344,
                    params: &binary_request,
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        let binary_hci = vec![
            0xb5, 0x05, 0x00, 0x14, 0x00, 0x00, 0x00, 0x01, 0x00, 0x0e, 0x00, 0x02, 0x00, 0x00,
            0x6f, 0x07, 0x90, 0x00, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef,
        ];
        assert!(route_one_hci(&mut bridge, &mut server, binary_hci).is_some());
        let len = subscribed
            .recv(&mut frame)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(len, 12 + 6 + 2038);
        let callback = SdkCallback::parse(
            Packet::parse(&frame[..len]).unwrap_or_else(|_| std::process::abort()),
        )
        .unwrap_or_else(|_| std::process::abort());
        assert_eq!(callback.data.len(), 2044);
        assert_eq!(&callback.data[..6], &[0, 0, 0, 14, 0, 1]);
        assert_eq!(
            &callback.data[6..20],
            &[
                0, 2, 0, 0, 0x6f, 0x07, 0x90, 0, 0, 4, 0xde, 0xad, 0xbe, 0xef
            ]
        );
        assert!(callback.data[20..].iter().all(|&byte| byte == 0));

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
    fn malformed_uicc_callback_keeps_pending_request_reserved() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (_client, id) = open_client(&mut server, &dir, 0);
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(1);
        let request = [0x00, 0x02, 0x00, 0x06, 1, 0, 0, 0x6f, 0x3a, 0];
        bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                id,
                SdkApiRequest {
                    command: SdkCommand::UiccRequest as u16,
                    device_id: 1,
                    params: &request,
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(bridge.pending_count(), 1);

        let malformed = UiccResponse {
            result: 0,
            kind: 2,
            data: &[0, 1, 0, 0, 0x6f, 0x3a, 0x90, 0, 0, 3, 2, 1, 2, 3, 4, 5],
        };
        assert!(matches!(
            bridge.handle_modem_event(&mut server, &ModemEvent::Uicc(malformed)),
            Err(HandleError::UiccCallback(
                UiccCallbackError::EmbeddedLengthMismatch {
                    kind: 2,
                    declared: 6,
                    actual: 5,
                }
            ))
        ));
        assert_eq!(bridge.pending_count(), 1);
    }

    #[test]
    fn stock_at_requests_match_exact_live_p4_local_and_hci_shapes() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (_client, id) = open_client(&mut server, &dir, 0);
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(1);

        let normal = bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                id,
                SdkApiRequest {
                    command: SdkCommand::AtCommand as u16,
                    device_id: 1,
                    params: b"ATI",
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(normal.command, SdkCommand::AtCommand);
        assert_eq!(normal.bytes_written, 8);
        assert_eq!(bridge.pending_count(), 0);

        let extended = bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                id,
                SdkApiRequest {
                    command: SdkCommand::AtCommandExt as u16,
                    device_id: 1,
                    params: &[7, b'A', b'T', b'I'],
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(extended.command, SdkCommand::AtCommandExt);
        assert_eq!(extended.bytes_written, 9);
        assert_eq!(bridge.pending_count(), 0);
        assert_eq!(read_api_ret(&mut server, id), 0);
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            [
                0x33, 0x07, 0x00, 0x04, b'A', b'T', b'I', b'\n', 0x33, 0x23, 0x00, 0x05, 7, b'A',
                b'T', b'I', b'\n',
            ]
        );
    }

    #[test]
    fn stock_extended_at_requires_only_the_channel_prefix() {
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
                    command: SdkCommand::AtCommandExt as u16,
                    device_id: 1,
                    params: &[],
                },
            ),
            Err(HandleError::UnexpectedParameters {
                command,
                expected: 1,
                actual: 0,
            }) if command == SdkCommand::AtCommandExt as u16
        ));
        assert_eq!(read_api_ret(&mut server, id), 1);
        assert_eq!(bridge.pending_count(), 0);
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn at_indications_broadcast_exact_variable_payloads_without_pending_state() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (subscribed, subscribed_id) = open_client(&mut server, &dir, 0);
        let (unsubscribed, _unsubscribed_id) = open_client(&mut server, &dir, 1);
        let context = server
            .client_context(subscribed_id)
            .unwrap_or_else(|_| std::process::abort());
        context
            .write_u32_be(
                SdkCallbackKind::AtCommandFromDevice.registration_offset(),
                1,
            )
            .unwrap_or_else(|_| std::process::abort());
        context
            .write_u32_be(
                SdkCallbackKind::AtCommandFromDeviceExt.registration_offset(),
                1,
            )
            .unwrap_or_else(|_| std::process::abort());

        let mut bridge = DeviceBridge::new(0x1122_3344);
        assert_eq!(bridge.pending_count(), 0);

        assert_eq!(
            route_one_hci(
                &mut bridge,
                &mut server,
                [
                    0xb3, 0x08, 0x00, 0x06, b'\r', b'\n', b'O', b'K', b'\r', b'\n'
                ]
                .to_vec(),
            ),
            Some(BroadcastReport {
                registered_clients: 1,
                sent_clients: 1,
            })
        );
        assert_eq!(bridge.pending_count(), 0);

        assert_eq!(
            route_one_hci(
                &mut bridge,
                &mut server,
                [0xb3, 0x24, 0x00, 0x03, 7, b'O', b'K'].to_vec(),
            ),
            Some(BroadcastReport {
                registered_clients: 1,
                sent_clients: 1,
            })
        );
        assert_eq!(bridge.pending_count(), 0);

        let mut frame = [0_u8; 64];
        let len = subscribed
            .recv(&mut frame)
            .unwrap_or_else(|_| std::process::abort());
        let packet = Packet::parse(&frame[..len]).unwrap_or_else(|_| std::process::abort());
        let callback = SdkCallback::parse(packet).unwrap_or_else(|_| std::process::abort());
        assert_eq!(callback.callback_id, 126);
        assert_eq!(callback.device_id, 0x1122_3344);
        assert_eq!(callback.data, b"\r\nOK\r\n");

        let len = subscribed
            .recv(&mut frame)
            .unwrap_or_else(|_| std::process::abort());
        let packet = Packet::parse(&frame[..len]).unwrap_or_else(|_| std::process::abort());
        let callback = SdkCallback::parse(packet).unwrap_or_else(|_| std::process::abort());
        assert_eq!(callback.callback_id, 128);
        assert_eq!(callback.device_id, 0x1122_3344);
        assert_eq!(callback.data, &[7, b'O', b'K']);

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
    fn stock_pdn_connect_ext_matches_exact_live_p4_hci() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (_client, id) = open_client(&mut server, &dir, 0);
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(1);

        let mut params = [0_u8; 0x0f4];
        params[0x000] = 0x11;
        params[0x001] = 1;
        params[0x002..0x005].copy_from_slice(b"ims");
        params[0x066] = 2;
        params[0x067] = 3;
        params[0x068] = 4;
        params[0x069] = b'u';
        params[0x0a9] = b'p';
        params[0x0e9] = 5;
        params[0x0ea..0x0f3].copy_from_slice(&[1, 2, 3, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        params[0x0f3] = 0xfe;

        let request = SdkApiRequest {
            command: SdkCommand::PdnConnectExt as u16,
            device_id: 1,
            params: &params,
        };
        let call = bridge
            .handle_sdk_api(&mut server, &mut modem, id, request)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(call.command, SdkCommand::PdnConnectExt);
        assert_eq!(call.bytes_written, 40);
        assert_eq!(bridge.pending_count(), 1);
        assert_eq!(read_api_ret(&mut server, id), 0);
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            [
                0x31, 0x67, 0x00, 0x24, 0x11, 0x01, 0x04, 0x03, b'i', b'm', b's', 0x20, 0x01, 0x03,
                0x02, 0x01, b'u', 0x03, 0x01, b'p', 0x05, 0x01, 0x04, 0x1e, 0x01, 0x05, 0x01, 0x01,
                0x02, 0x21, 0x09, 1, 2, 3, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            ]
        );
    }

    #[test]
    fn malformed_stock_pdn_connect_ext_is_rejected_before_modem_write() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (_client, id) = open_client(&mut server, &dir, 0);
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(1);
        let mut params = [0_u8; 0x0f4];
        params[0x002..0x066].fill(0xff);

        let request = SdkApiRequest {
            command: SdkCommand::PdnConnectExt as u16,
            device_id: 1,
            params: &params,
        };
        assert!(matches!(
            bridge.handle_sdk_api(&mut server, &mut modem, id, request),
            Err(HandleError::LegacyPdnConnectExt(
                LegacyPdnConnectExtDecodeError::MissingTerminator(
                    LegacyPdnConnectExtStringField::Apn
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
            decode_legacy_pdn_connect_ext(&[0_u8; 0x0f3]),
            Err(LegacyPdnConnectExtDecodeError::UnexpectedLength {
                expected: 0x0f4,
                actual: 0x0f3,
            })
        );
    }

    #[test]
    fn stock_pdn_connect_ext_optional_zero_still_requires_apn_only() {
        let mut params = [0xff_u8; 0x0f4];
        params[0] = 2;
        params[1] = 0;
        params[2..6].copy_from_slice(b"ims\0");
        let request =
            decode_legacy_pdn_connect_ext(&params).unwrap_or_else(|_| std::process::abort());
        assert_eq!(request.request_type, 2);
        assert_eq!(request.optional_info, 0);
        assert_eq!(request.apn, b"ims");
        assert_eq!(request.username, b"");
        assert_eq!(request.password, b"");
    }

    #[test]
    fn pdn_connect_ext_response_materializes_exact_stock_callback_and_subscription_gate() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (subscribed, subscribed_id) = open_client(&mut server, &dir, 0);
        let (unsubscribed, _unsubscribed_id) = open_client(&mut server, &dir, 1);
        server
            .client_context(subscribed_id)
            .unwrap_or_else(|_| std::process::abort())
            .write_u32_be(SdkCallbackKind::PdnConnectExt.registration_offset(), 1)
            .unwrap_or_else(|_| std::process::abort());

        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(0x1122_3344);
        let mut params = [0_u8; 0x0f4];
        params[0] = 1;
        params[2..5].copy_from_slice(b"ims");
        bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                subscribed_id,
                SdkApiRequest {
                    command: SdkCommand::PdnConnectExt as u16,
                    device_id: 0x1122_3344,
                    params: &params,
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(bridge.pending_count(), 1);

        let payload = [
            0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x12, 0x34, 0x09, 0x0a, 0x05, 0x55, 0x20, 0x01,
            0x07, 0x57, 0x03, b'i', b'm', b's', 0x58, 0x03, b'n', b'e', b't', 0xf0, 0x14, 0x04,
            0x03, b'p', b'd', b'n', 0x05, 0x01, 0x02, 0x07, 0x04, 192, 168, 1, 2, 0x40, 0x04, 0, 0,
            0, 9, 0xaa, 0x00,
        ];
        let mut hci = Vec::with_capacity(payload.len() + 4);
        hci.extend_from_slice(&[0xb1, 0x68]);
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

        let mut frame = [0_u8; 720];
        let len = subscribed
            .recv(&mut frame)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(len, 12 + 697);
        let packet = Packet::parse(&frame[..len]).unwrap_or_else(|_| std::process::abort());
        let callback = SdkCallback::parse(packet).unwrap_or_else(|_| std::process::abort());
        assert_eq!(callback.callback_id, 35);
        assert_eq!(callback.device_id, 0x1122_3344);
        assert_eq!(callback.data.len(), 697);
        let data = callback.data;
        assert_eq!(
            &data[0x000..0x00c],
            &[0, 1, 0, 2, 0, 3, 0x12, 0x34, 9, 10, 0x05, 0x55]
        );
        assert_eq!(data[0x00c], 7);
        assert_eq!(data[0x00d], 3);
        assert_eq!(&data[0x00e..0x011], b"ims");
        assert_eq!(data[0x04e], 3);
        assert_eq!(&data[0x04f..0x052], b"net");
        assert_eq!(&data[0x08f..0x092], b"pdn");
        assert_eq!(data[0x10f], 2);
        assert_eq!(&data[0x114..0x118], &[192, 168, 1, 2]);
        assert_eq!(&data[0x2a5..0x2a9], &9_u32.to_be_bytes());
        assert!(data[0x2a9..].iter().all(|&byte| byte == 0));

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
    fn stock_temperature_read_matches_live_p4_hci_and_callback_83() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (subscribed, subscribed_id) = open_client(&mut server, &dir, 0);
        let (unsubscribed, _unsubscribed_id) = open_client(&mut server, &dir, 1);
        server
            .client_context(subscribed_id)
            .unwrap_or_else(|_| std::process::abort())
            .write_u32_be(SdkCallbackKind::TemperatureRead.registration_offset(), 1)
            .unwrap_or_else(|_| std::process::abort());
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(1);
        let call = bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                subscribed_id,
                SdkApiRequest {
                    command: SdkCommand::TemperatureRead as u16,
                    device_id: 1,
                    params: &[],
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(call.bytes_written, 8);
        assert_eq!(bridge.pending_count(), 1);
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            [0x31, 0x45, 0, 4, 0, 4, 0, 0]
        );
        assert_eq!(
            route_one_hci(
                &mut bridge,
                &mut server,
                vec![0xb1, 0x46, 0, 8, 0, 0, 0, 4, 0, 2, 0, 0xef],
            ),
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
        assert_eq!(len, 16);
        let callback = SdkCallback::parse(
            Packet::parse(&frame[..len]).unwrap_or_else(|_| std::process::abort()),
        )
        .unwrap_or_else(|_| std::process::abort());
        assert_eq!(callback.callback_id, 83);
        assert_eq!(callback.data, &[0, 0, 0, 0xef]);

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
    fn malformed_stock_temperature_read_is_rejected_before_modem_write() {
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
                    command: SdkCommand::TemperatureRead as u16,
                    device_id: 1,
                    params: &[0],
                },
            ),
            Err(HandleError::UnexpectedParameters {
                command: 82,
                expected: 0,
                actual: 1,
            })
        ));
        assert_eq!(bridge.pending_count(), 0);
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn stock_iccid_read_matches_live_p4_hci_and_callback_79() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (subscribed, subscribed_id) = open_client(&mut server, &dir, 0);
        let (unsubscribed, _unsubscribed_id) = open_client(&mut server, &dir, 1);
        server
            .client_context(subscribed_id)
            .unwrap_or_else(|_| std::process::abort())
            .write_u32_be(SdkCallbackKind::IccidRead.registration_offset(), 1)
            .unwrap_or_else(|_| std::process::abort());
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(1);
        let call = bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                subscribed_id,
                SdkApiRequest {
                    command: SdkCommand::IccidRead as u16,
                    device_id: 1,
                    params: &[],
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(call.bytes_written, 8);
        assert_eq!(bridge.pending_count(), 1);
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            [0x31, 0x45, 0, 4, 0, 2, 0, 0]
        );
        let iccid = [0x89, 0x10, 0x32, 0x54, 0x76, 0x98, 0x10, 0x32, 0x54, 0xf6];
        let mut response = vec![0xb1, 0x46, 0, 17, 0, 0, 0, 2, 0, 11, 0];
        response.extend_from_slice(&iccid);
        assert_eq!(
            route_one_hci(&mut bridge, &mut server, response),
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
        assert_eq!(len, 25);
        let callback = SdkCallback::parse(
            Packet::parse(&frame[..len]).unwrap_or_else(|_| std::process::abort()),
        )
        .unwrap_or_else(|_| std::process::abort());
        assert_eq!(callback.callback_id, 79);
        assert_eq!(
            callback.data,
            &[
                0, 0, 0, 0x89, 0x10, 0x32, 0x54, 0x76, 0x98, 0x10, 0x32, 0x54, 0xf6
            ]
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
    fn malformed_stock_iccid_read_is_rejected_before_modem_write() {
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
                    command: SdkCommand::IccidRead as u16,
                    device_id: 1,
                    params: &[0],
                },
            ),
            Err(HandleError::UnexpectedParameters {
                command: 78,
                expected: 0,
                actual: 1,
            })
        ));
        assert_eq!(bridge.pending_count(), 0);
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn stock_msisdn_read_matches_live_p4_hci_and_variable_callback_81() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (subscribed, subscribed_id) = open_client(&mut server, &dir, 0);
        let (unsubscribed, _unsubscribed_id) = open_client(&mut server, &dir, 1);
        server
            .client_context(subscribed_id)
            .unwrap_or_else(|_| std::process::abort())
            .write_u32_be(SdkCallbackKind::MsisdnRead.registration_offset(), 1)
            .unwrap_or_else(|_| std::process::abort());

        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(0x1122_3344);
        let call = bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                subscribed_id,
                SdkApiRequest {
                    command: SdkCommand::MsisdnRead as u16,
                    device_id: 0x1122_3344,
                    params: &[],
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(call.bytes_written, 8);
        assert_eq!(bridge.pending_count(), 1);
        assert!(bridge.pending.contains(ResponseKey::MiscRead));
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            [0x31, 0x45, 0, 4, 0, 3, 0, 0]
        );

        let mut record = [0_u8; 256];
        record[0] = 3;
        record[1..4].copy_from_slice(b"Jan");
        record[0xf2] = 4;
        record[0xf3] = 0x91;
        record[0xf4..0xf8].copy_from_slice(&[0x21, 0x43, 0x65, 0xf7]);
        record[0xfe] = 8;
        record[0xff] = 9;
        let mut response = vec![0xb1, 0x46, 0x01, 0x08, 0, 0, 0, 3, 0x01, 0x02, 0, 1];
        response.extend_from_slice(&record);
        assert_eq!(
            route_one_hci(&mut bridge, &mut server, response),
            Some(BroadcastReport {
                registered_clients: 1,
                sent_clients: 1,
            })
        );
        assert_eq!(bridge.pending_count(), 0);

        let mut frame = [0_u8; 300];
        let len = subscribed
            .recv(&mut frame)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(len, 272);
        let packet = Packet::parse(&frame[..len]).unwrap_or_else(|_| std::process::abort());
        let callback = SdkCallback::parse(packet).unwrap_or_else(|_| std::process::abort());
        assert_eq!(callback.callback_id, 81);
        assert_eq!(callback.device_id, 0x1122_3344);
        assert_eq!(callback.data.len(), 260);
        assert_eq!(&callback.data[..4], &[0, 0, 0, 1]);
        assert_eq!(&callback.data[4..], &record);

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
    fn stock_msisdn_subtype_failure_emits_four_byte_callback_81() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (client, id) = open_client(&mut server, &dir, 0);
        server
            .client_context(id)
            .unwrap_or_else(|_| std::process::abort())
            .write_u32_be(SdkCallbackKind::MsisdnRead.registration_offset(), 1)
            .unwrap_or_else(|_| std::process::abort());
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(1);
        bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                id,
                SdkApiRequest {
                    command: SdkCommand::MsisdnRead as u16,
                    device_id: 1,
                    params: &[],
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            route_one_hci(
                &mut bridge,
                &mut server,
                vec![0xb1, 0x46, 0, 7, 0, 0, 0, 3, 0, 1, 7],
            ),
            Some(BroadcastReport {
                registered_clients: 1,
                sent_clients: 1,
            })
        );
        assert_eq!(bridge.pending_count(), 0);
        let mut frame = [0_u8; 32];
        let len = client
            .recv(&mut frame)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(len, 16);
        let callback = SdkCallback::parse(
            Packet::parse(&frame[..len]).unwrap_or_else(|_| std::process::abort()),
        )
        .unwrap_or_else(|_| std::process::abort());
        assert_eq!(callback.callback_id, 81);
        assert_eq!(callback.data, &[0, 0, 7, 0]);
    }

    #[test]
    fn malformed_stock_msisdn_read_is_rejected_before_modem_write() {
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
                    command: SdkCommand::MsisdnRead as u16,
                    device_id: 1,
                    params: &[0],
                },
            ),
            Err(HandleError::UnexpectedParameters {
                command: 80,
                expected: 0,
                actual: 1,
            })
        ));
        assert_eq!(bridge.pending_count(), 0);
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn stock_mobile_id_read_matches_live_p4_hci_and_callback_77() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (subscribed, subscribed_id) = open_client(&mut server, &dir, 0);
        let (unsubscribed, _unsubscribed_id) = open_client(&mut server, &dir, 1);
        server
            .client_context(subscribed_id)
            .unwrap_or_else(|_| std::process::abort())
            .write_u32_be(SdkCallbackKind::MobileIdRead.registration_offset(), 1)
            .unwrap_or_else(|_| std::process::abort());

        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(1);
        let call = bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                subscribed_id,
                SdkApiRequest {
                    command: SdkCommand::MobileIdRead as u16,
                    device_id: 1,
                    params: &[3],
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(call.bytes_written, 9);
        assert_eq!(bridge.pending_count(), 1);
        assert!(bridge.pending.contains(ResponseKey::MiscRead));
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            [0x31, 0x45, 0x00, 0x05, 0x00, 0x01, 0x00, 0x01, 0x03]
        );

        let response = vec![
            0xb1, 0x46, 0x00, 0x0e, // shared response header
            0x00, 0x00, // read_result success
            0x00, 0x01, 0x00, 0x08, // Mobile-ID chunk + length
            0x03, 0x00, 0x05, b'1', b'2', b'3', b'4', b'5',
        ];
        assert_eq!(
            route_one_hci(&mut bridge, &mut server, response),
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
        assert_eq!(len, 22);
        let packet = Packet::parse(&frame[..len]).unwrap_or_else(|_| std::process::abort());
        let callback = SdkCallback::parse(packet).unwrap_or_else(|_| std::process::abort());
        assert_eq!(callback.callback_id, 77);
        assert_eq!(callback.device_id, 1);
        assert_eq!(
            callback.data,
            &[0, 0, 3, 0, 5, b'1', b'2', b'3', b'4', b'5']
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
    fn mobile_id_shared_failure_releases_family_without_stock_callback() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (client, id) = open_client(&mut server, &dir, 0);
        server
            .client_context(id)
            .unwrap_or_else(|_| std::process::abort())
            .write_u32_be(SdkCallbackKind::MobileIdRead.registration_offset(), 1)
            .unwrap_or_else(|_| std::process::abort());
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(1);
        bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                id,
                SdkApiRequest {
                    command: SdkCommand::MobileIdRead as u16,
                    device_id: 1,
                    params: &[1],
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(bridge.pending_count(), 1);

        assert_eq!(
            route_one_hci(
                &mut bridge,
                &mut server,
                vec![0xb1, 0x46, 0x00, 0x02, 0x00, 0x07],
            ),
            None
        );
        assert_eq!(bridge.pending_count(), 0);
        client
            .set_nonblocking(true)
            .unwrap_or_else(|_| std::process::abort());
        let mut no_frame = [0_u8; 1];
        let Err(error) = client.recv(&mut no_frame) else {
            std::process::abort();
        };
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn malformed_stock_mobile_id_read_is_rejected_before_modem_write() {
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
                    command: SdkCommand::MobileIdRead as u16,
                    device_id: 1,
                    params: &[],
                },
            ),
            Err(HandleError::UnexpectedParameters {
                command: 76,
                expected: 1,
                actual: 0,
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
    fn stock_plmn_search_ext_matches_live_p4_hci_and_ignores_dead_fields() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (_client, id) = open_client(&mut server, &dir, 0);
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(1);
        let mut params = [0_u8; 1_292];
        params[0] = 1;
        params[1] = 1;
        params[2..5].copy_from_slice(&[2, 6, 0]);
        params[5..8].copy_from_slice(&[0, 1, 0x0f]);
        params[8] = 9;
        let list = [
            2, 2, 0x00, 0x00, 0x0a, 0x28, 0x00, 0x00, 0x09, 0xc4, 3, 2, 3, 5, 4, 1, 0x00, 0x00,
            0x09, 0xc4, 0x00, 0x00, 0x0a, 0x28,
        ];
        params[9] = 3;
        params[10] = 24;
        params[11..35].copy_from_slice(&list);
        params[1_286] = 0xfe;
        params[1_287..1_291].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        params[1_291] = 1;

        let call = bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                id,
                SdkApiRequest {
                    command: SdkCommand::PlmnSearchExt as u16,
                    device_id: 1,
                    params: &params,
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(call.bytes_written, 38);
        assert_eq!(bridge.pending_count(), 1);
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            [
                0x31, 0x5a, 0x00, 0x22, 0x01, 0x01, 0x64, 0x62, 0xf0, 0x10, 0x65, 24, 2, 2, 0x00,
                0x00, 0x0a, 0x28, 0x00, 0x00, 0x09, 0xc4, 3, 2, 3, 5, 4, 1, 0x00, 0x00, 0x09, 0xc4,
                0x00, 0x00, 0x0a, 0x28, 0x66, 1,
            ]
        );
    }

    #[test]
    fn malformed_stock_plmn_search_ext_is_rejected_before_modem_write() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (_client, id) = open_client(&mut server, &dir, 0);
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(1);
        let mut params = [0_u8; 1_292];
        params[9] = 1;
        params[10] = 5;
        params[11..16].copy_from_slice(&[2, 1, 0, 0, 0]);

        assert!(
            bridge
                .handle_sdk_api(
                    &mut server,
                    &mut modem,
                    id,
                    SdkApiRequest {
                        command: SdkCommand::PlmnSearchExt as u16,
                        device_id: 1,
                        params: &params,
                    },
                )
                .is_err()
        );
        assert_eq!(read_api_ret(&mut server, id), 1);
        assert_eq!(bridge.pending_count(), 0);
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn ext_plmn_search_completes_through_live_product_callback_41_path() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (subscribed, id) = open_client(&mut server, &dir, 0);
        server
            .client_context(id)
            .unwrap_or_else(|_| std::process::abort())
            .write_u32_be(SdkCallbackKind::PlmnSearch.registration_offset(), 1)
            .unwrap_or_else(|_| std::process::abort());

        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(1);
        let params = [0_u8; 1_292];
        bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                id,
                SdkApiRequest {
                    command: SdkCommand::PlmnSearchExt as u16,
                    device_id: 1,
                    params: &params,
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(bridge.pending_count(), 1);

        let mut payload = [0_u8; 27];
        payload[..4].copy_from_slice(&1_u32.to_be_bytes());
        let mut hci = Vec::with_capacity(31);
        hci.extend_from_slice(&[0xb1, 0x0a, 0x00, 0x1b]);
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
        assert_eq!(&callback.data[..4], &1_u32.to_be_bytes());
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
    fn detach_required_indication_broadcasts_exact_callback_31_without_pending_state() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (subscribed, subscribed_id) = open_client(&mut server, &dir, 0);
        let (unsubscribed, _unsubscribed_id) = open_client(&mut server, &dir, 1);
        server
            .client_context(subscribed_id)
            .unwrap_or_else(|_| std::process::abort())
            .write_u32_be(SdkCallbackKind::DetachRequired.registration_offset(), 1)
            .unwrap_or_else(|_| std::process::abort());

        let mut bridge = DeviceBridge::new(1);
        assert_eq!(bridge.pending_count(), 0);
        let report = bridge
            .handle_modem_event(
                &mut server,
                &ModemEvent::DetachRequired(DetachRequiredIndication {
                    detach_type: 0x1122_3344,
                }),
            )
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            report,
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
        assert_eq!(len, 16);
        let packet = Packet::parse(&frame[..len]).unwrap_or_else(|_| std::process::abort());
        let callback = SdkCallback::parse(packet).unwrap_or_else(|_| std::process::abort());
        assert_eq!(callback.callback_id, 31);
        assert_eq!(callback.device_id, 1);
        assert_eq!(callback.data, &[0x11, 0x22, 0x33, 0x44]);

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
    fn stock_psm_lcs_lpp_controls_match_live_p4_request_only_contracts() {
        let cases: &[(SdkCommand, &[u8], &[u8])] = &[
            (
                SdkCommand::PsmControl,
                &[0x12, 0x34, 5, 6, 7, 8],
                &[0x31, 0x55, 0, 10, 0, 8, 0, 6, 0x12, 0x34, 5, 6, 7, 8],
            ),
            (
                SdkCommand::LcsControl,
                &[0x11, 0x22, 0x33, 0x44],
                &[0x31, 0x55, 0, 8, 0, 9, 0, 4, 0x11, 0x22, 0x33, 0x44],
            ),
            (
                SdkCommand::LppControl,
                &[0x55, 0x66, 0x77, 0x88],
                &[0x31, 0x55, 0, 8, 0, 10, 0, 4, 0x55, 0x66, 0x77, 0x88],
            ),
        ];
        for (command, params, expected) in cases {
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
                        command: *command as u16,
                        device_id: 1,
                        params,
                    },
                )
                .unwrap_or_else(|_| std::process::abort());
            assert_eq!(call.command, *command);
            assert_eq!(call.bytes_written, expected.len());
            assert_eq!(bridge.pending_count(), 0);
            assert_eq!(modem.into_transport().into_inner().into_inner(), *expected);
        }
    }

    #[test]
    fn malformed_stock_psm_lcs_lpp_controls_are_rejected_before_modem_write() {
        let cases: &[(SdkCommand, &[u8], usize)] = &[
            (SdkCommand::PsmControl, &[0_u8; 5], 6),
            (SdkCommand::LcsControl, &[0_u8; 3], 4),
            (SdkCommand::LppControl, &[0_u8; 5], 4),
        ];
        for (command, params, expected_len) in cases {
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
                        command: *command as u16,
                        device_id: 1,
                        params,
                    },
                ),
                Err(HandleError::UnexpectedParameters { expected, actual, .. })
                    if expected == *expected_len && actual == params.len()
            ));
            assert_eq!(bridge.pending_count(), 0);
            assert_eq!(
                modem.into_transport().into_inner().into_inner(),
                Vec::<u8>::new()
            );
        }
    }

    #[test]
    fn stock_emm_timer_start_is_exact_and_deliberately_untracked() {
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
                    command: SdkCommand::EmmTimerStart as u16,
                    device_id: 1,
                    params: &[0x12, 0x34, 0x56],
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(call.bytes_written, 11);
        assert_eq!(bridge.pending_count(), 0);
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            vec![0x31, 0x55, 0, 7, 0, 13, 0, 3, 0x12, 0x34, 0x56]
        );
    }

    #[test]
    fn malformed_stock_emm_timer_start_is_rejected_before_modem_write() {
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
                    command: SdkCommand::EmmTimerStart as u16,
                    device_id: 1,
                    params: &[0; 2],
                },
            ),
            Err(HandleError::UnexpectedParameters {
                command: 213,
                expected: 3,
                actual: 2,
            })
        ));
        assert_eq!(bridge.pending_count(), 0);
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn stock_emm_timer_control_is_exact_and_deliberately_untracked() {
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
                    command: SdkCommand::EmmTimerControl as u16,
                    device_id: 1,
                    params: &[0x12, 0x34, 5, 6],
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(call.bytes_written, 12);
        assert_eq!(bridge.pending_count(), 0);
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            vec![
                0x31, 0x55, 0x00, 0x08, 0x00, 0x07, 0x00, 0x04, 0x12, 0x34, 5, 6
            ]
        );
    }

    #[test]
    fn malformed_stock_emm_timer_control_is_rejected_before_modem_write() {
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
                    command: SdkCommand::EmmTimerControl as u16,
                    device_id: 1,
                    params: &[0; 3],
                },
            ),
            Err(HandleError::UnexpectedParameters {
                command: 207,
                expected: 4,
                actual: 3,
            })
        ));
        assert_eq!(bridge.pending_count(), 0);
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn malformed_stock_emm_ni_reattach_is_rejected_before_modem_write() {
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
                    command: SdkCommand::EmmNiReattachControl as u16,
                    device_id: 1,
                    params: &[0; 3],
                },
            ),
            Err(HandleError::UnexpectedParameters {
                command: 211,
                expected: 4,
                actual: 3,
            })
        ));
        assert_eq!(bridge.pending_count(), 0);
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn unsubscribed_emm_ni_reattach_retires_pending_without_callback() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (client, id) = open_client(&mut server, &dir, 0);
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(1);
        bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                id,
                SdkApiRequest {
                    command: SdkCommand::EmmNiReattachControl as u16,
                    device_id: 1,
                    params: &[0, 0, 0, 1],
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(bridge.pending_count(), 1);
        assert_eq!(
            route_one_hci(
                &mut bridge,
                &mut server,
                vec![
                    0xb1, 0x56, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x04, 0, 0, 0, 0,
                ],
            ),
            Some(BroadcastReport {
                registered_clients: 0,
                sent_clients: 0,
            })
        );
        assert_eq!(bridge.pending_count(), 0);
        client
            .set_nonblocking(true)
            .unwrap_or_else(|_| std::process::abort());
        let mut frame = [0_u8; 32];
        let Err(error) = client.recv(&mut frame) else {
            std::process::abort();
        };
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn stock_emm_ni_reattach_round_trips_callback_308() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (subscribed, id) = open_client(&mut server, &dir, 0);
        server
            .client_context(id)
            .unwrap_or_else(|_| std::process::abort())
            .write_u32_be(
                SdkCallbackKind::EmmNiReattachControl.registration_offset(),
                1,
            )
            .unwrap_or_else(|_| std::process::abort());
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(0x1122_3344);
        let call = bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                id,
                SdkApiRequest {
                    command: SdkCommand::EmmNiReattachControl as u16,
                    device_id: 0x1122_3344,
                    params: &[0x11, 0x22, 0x33, 0x44],
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(call.bytes_written, 12);
        assert_eq!(bridge.pending_count(), 1);
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            vec![
                0x31, 0x55, 0x00, 0x08, 0x00, 0x0b, 0x00, 0x04, 0x11, 0x22, 0x33, 0x44
            ]
        );

        assert_eq!(
            route_one_hci(
                &mut bridge,
                &mut server,
                vec![
                    0xb1, 0x56, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x04, 0xaa, 0xbb, 0xcc,
                    0xdd,
                ],
            ),
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
        assert_eq!(len, 16);
        let packet = Packet::parse(&frame[..len]).unwrap_or_else(|_| std::process::abort());
        let callback = SdkCallback::parse(packet).unwrap_or_else(|_| std::process::abort());
        assert_eq!(callback.callback_id, 308);
        assert_eq!(callback.device_id, 0x1122_3344);
        assert_eq!(callback.data, &[0xaa, 0xbb, 0xcc, 0xdd]);
    }

    #[test]
    fn emm_reattach_report_is_unsolicited_callback_309() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (subscribed, id) = open_client(&mut server, &dir, 0);
        server
            .client_context(id)
            .unwrap_or_else(|_| std::process::abort())
            .write_u32_be(
                SdkCallbackKind::EmmReattachControlReport.registration_offset(),
                1,
            )
            .unwrap_or_else(|_| std::process::abort());
        let mut bridge = DeviceBridge::new(0x1122_3344);
        assert_eq!(bridge.pending_count(), 0);
        assert_eq!(
            route_one_hci(
                &mut bridge,
                &mut server,
                vec![
                    0xb1, 0x64, 0x00, 0x0a, 0x12, 0x34, 0x00, 0x0b, 0x00, 0x04, 0xaa, 0xbb, 0xcc,
                    0xdd,
                ],
            ),
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
        assert_eq!(len, 18);
        let packet = Packet::parse(&frame[..len]).unwrap_or_else(|_| std::process::abort());
        let callback = SdkCallback::parse(packet).unwrap_or_else(|_| std::process::abort());
        assert_eq!(callback.callback_id, 309);
        assert_eq!(callback.device_id, 0x1122_3344);
        assert_eq!(callback.data, &[0x12, 0x34, 0xaa, 0xbb, 0xcc, 0xdd]);
    }

    #[test]
    fn stock_rf_status_report_control_round_trips_exact_live_p4_contract() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (subscribed, id) = open_client(&mut server, &dir, 0);
        server
            .client_context(id)
            .unwrap_or_else(|_| std::process::abort())
            .write_u32_be(
                SdkCallbackKind::RfStatusReportControl.registration_offset(),
                1,
            )
            .unwrap_or_else(|_| std::process::abort());

        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(0x1122_3344);
        let params = [0x00, 0x01, 0x00, 0x3c, 0x00, 0x0a, 0xff, 0x9c, 0xff, 0x88];
        let call = bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                id,
                SdkApiRequest {
                    command: SdkCommand::RfStatusReportControl as u16,
                    device_id: 0x1122_3344,
                    params: &params,
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(call.bytes_written, 18);
        assert_eq!(bridge.pending_count(), 1);
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            vec![
                0x31, 0x55, 0x00, 0x0e, 0x00, 0x01, 0x00, 0x0a, 0x00, 0x01, 0x00, 0x3c, 0x00, 0x0a,
                0xff, 0x9c, 0xff, 0x88,
            ]
        );

        assert_eq!(
            route_one_hci(
                &mut bridge,
                &mut server,
                hci_frame(
                    0xb156,
                    &[
                        0x00, 0x00, 0x00, 0x01, 0x00, 0x0a, 0x00, 0x01, 0x00, 0x02, 0xff, 0x9c,
                        0xff, 0xa6, 0xff, 0x92,
                    ],
                ),
            ),
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
        let packet = Packet::parse(&frame[..len]).unwrap_or_else(|_| std::process::abort());
        let callback = SdkCallback::parse(packet).unwrap_or_else(|_| std::process::abort());
        assert_eq!(callback.callback_id, 188);
        assert_eq!(callback.device_id, 0x1122_3344);
        assert_eq!(
            callback.data,
            &[
                0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0xff, 0x9c, 0xff, 0xa6, 0xff, 0x92,
            ]
        );
    }

    #[test]
    fn stock_rf_measure_report_round_trips_response_and_unsolicited_indication() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (subscribed, id) = open_client(&mut server, &dir, 0);
        let context = server
            .client_context(id)
            .unwrap_or_else(|_| std::process::abort());
        context
            .write_u32_be(SdkCallbackKind::RfMeasureReport.registration_offset(), 1)
            .unwrap_or_else(|_| std::process::abort());
        context
            .write_u32_be(
                SdkCallbackKind::RfMeasureReportIndication.registration_offset(),
                1,
            )
            .unwrap_or_else(|_| std::process::abort());

        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(0x1122_3344);
        let call = bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                id,
                SdkApiRequest {
                    command: SdkCommand::RfMeasureReport as u16,
                    device_id: 0x1122_3344,
                    params: &[1],
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(call.bytes_written, 9);
        assert_eq!(bridge.pending_count(), 1);
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            vec![0x31, 0x55, 0x00, 0x05, 0x00, 0x05, 0x00, 0x01, 0x01]
        );

        assert_eq!(
            route_one_hci(
                &mut bridge,
                &mut server,
                hci_frame(0xb156, &[0x00, 0x00, 0x00, 0x05, 0x00, 0x02, 0x00, 0x01],),
            ),
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
        let packet = Packet::parse(&frame[..len]).unwrap_or_else(|_| std::process::abort());
        let callback = SdkCallback::parse(packet).unwrap_or_else(|_| std::process::abort());
        assert_eq!(callback.callback_id, 203);
        assert_eq!(callback.device_id, 0x1122_3344);
        assert_eq!(callback.data, &[0x00, 0x00, 0x00, 0x01]);

        assert_eq!(
            route_one_hci(
                &mut bridge,
                &mut server,
                hci_frame(
                    0xb164,
                    &[
                        0x00, 0x00, 0x00, 0x05, 0x00, 0x0a, 0x02, 0x03, 0xff, 0xba, 0xff, 0xa1,
                        0xff, 0xf4, 0x00, 0x19,
                    ],
                ),
            ),
            Some(BroadcastReport {
                registered_clients: 1,
                sent_clients: 1,
            })
        );
        assert_eq!(bridge.pending_count(), 0);

        let len = subscribed
            .recv(&mut frame)
            .unwrap_or_else(|_| std::process::abort());
        let packet = Packet::parse(&frame[..len]).unwrap_or_else(|_| std::process::abort());
        let callback = SdkCallback::parse(packet).unwrap_or_else(|_| std::process::abort());
        assert_eq!(callback.callback_id, 204);
        assert_eq!(callback.device_id, 0x1122_3344);
        assert_eq!(
            callback.data,
            &[
                0x00, 0x00, 0x02, 0x03, 0xff, 0xba, 0xff, 0xa1, 0xff, 0xf4, 0x00, 0x19,
            ]
        );
    }

    #[test]
    fn stock_contents_reset_and_delete_round_trips_exact_live_p4_contract() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (subscribed, id) = open_client(&mut server, &dir, 0);
        server
            .client_context(id)
            .unwrap_or_else(|_| std::process::abort())
            .write_u32_be(
                SdkCallbackKind::ContentsResetAndDelete.registration_offset(),
                1,
            )
            .unwrap_or_else(|_| std::process::abort());

        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(0x1122_3344);
        let call = bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                id,
                SdkApiRequest {
                    command: SdkCommand::ContentsResetAndDelete as u16,
                    device_id: 0x1122_3344,
                    params: &[0x00, 0x00, 0x00, 0x03],
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(call.bytes_written, 8);
        assert_eq!(bridge.pending_count(), 1);
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            vec![0xb1, 0x73, 0x00, 0x04, 0x00, 0x00, 0x00, 0x03]
        );

        assert_eq!(
            route_one_hci(&mut bridge, &mut server, hci_frame(0xb174, &[0x00]),),
            Some(BroadcastReport {
                registered_clients: 1,
                sent_clients: 1,
            })
        );
        assert_eq!(bridge.pending_count(), 0);

        let mut frame = [0_u8; 24];
        let len = subscribed
            .recv(&mut frame)
            .unwrap_or_else(|_| std::process::abort());
        let packet = Packet::parse(&frame[..len]).unwrap_or_else(|_| std::process::abort());
        let callback = SdkCallback::parse(packet).unwrap_or_else(|_| std::process::abort());
        assert_eq!(callback.callback_id, 66);
        assert_eq!(callback.device_id, 0x1122_3344);
        assert_eq!(callback.data, &[0x00]);
    }

    #[test]
    fn malformed_stock_contents_reset_is_rejected_before_modem_write() {
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
                    command: SdkCommand::ContentsResetAndDelete as u16,
                    device_id: 1,
                    params: &[0, 0, 3],
                },
            ),
            Err(HandleError::UnexpectedParameters {
                command: 65,
                expected: 4,
                actual: 3,
            })
        ));
        assert_eq!(bridge.pending_count(), 0);
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn malformed_stock_rf_requests_are_rejected_before_modem_write() {
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
                    command: SdkCommand::RfStatusReportControl as u16,
                    device_id: 1,
                    params: &[0; 9],
                },
            ),
            Err(HandleError::UnexpectedParameters {
                command: 187,
                expected: 10,
                actual: 9,
            })
        ));
        assert!(matches!(
            bridge.handle_sdk_api(
                &mut server,
                &mut modem,
                id,
                SdkApiRequest {
                    command: SdkCommand::RfMeasureReport as u16,
                    device_id: 1,
                    params: &[],
                },
            ),
            Err(HandleError::UnexpectedParameters {
                command: 202,
                expected: 1,
                actual: 0,
            })
        ));
        assert_eq!(bridge.pending_count(), 0);
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn stock_ue_mode_change_round_trips_exact_live_p4_contract() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (subscribed, id) = open_client(&mut server, &dir, 0);
        server
            .client_context(id)
            .unwrap_or_else(|_| std::process::abort())
            .write_u32_be(SdkCallbackKind::UeModeChange.registration_offset(), 1)
            .unwrap_or_else(|_| std::process::abort());

        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(0x1122_3344);
        let call = bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                id,
                SdkApiRequest {
                    command: SdkCommand::UeModeChange as u16,
                    device_id: 0x1122_3344,
                    params: &[7],
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(call.bytes_written, 5);
        assert_eq!(bridge.pending_count(), 1);
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            vec![0x31, 0x18, 0x00, 0x01, 7]
        );

        assert_eq!(
            route_one_hci(&mut bridge, &mut server, vec![0xb1, 0x4f, 0x00, 0x01, 9]),
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
        assert_eq!(len, 13);
        let packet = Packet::parse(&frame[..len]).unwrap_or_else(|_| std::process::abort());
        let callback = SdkCallback::parse(packet).unwrap_or_else(|_| std::process::abort());
        assert_eq!(callback.callback_id, 162);
        assert_eq!(callback.device_id, 0x1122_3344);
        assert_eq!(callback.data, &[9]);
    }

    #[test]
    fn malformed_stock_ue_mode_change_is_rejected_before_modem_write() {
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
                    command: SdkCommand::UeModeChange as u16,
                    device_id: 1,
                    params: &[],
                },
            ),
            Err(HandleError::UnexpectedParameters {
                command: 161,
                expected: 1,
                actual: 0,
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
    fn stock_local_apn_type_set_get_and_validation_never_touch_glif() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (_set_client, set_id) = open_client(&mut server, &dir, 0);
        let (_get_client, get_id) = open_client(&mut server, &dir, 1);
        let (_bad_client, bad_id) = open_client(&mut server, &dir, 2);
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(1);

        let set = bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                set_id,
                SdkApiRequest {
                    command: SdkCommand::SetApnType as u16,
                    device_id: 1,
                    params: &[0, 0, 0, 3],
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(set.bytes_written, 0);
        assert_eq!(read_api_ret(&mut server, set_id), 0);

        bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                get_id,
                SdkApiRequest {
                    command: SdkCommand::GetApnType as u16,
                    device_id: 1,
                    params: &[],
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(read_api_ret(&mut server, get_id), 0);
        assert_eq!(
            read_shared_byte(&mut server, get_id, APN_TYPE_RESULT_OFFSET),
            3
        );

        assert!(matches!(
            bridge.handle_sdk_api(
                &mut server,
                &mut modem,
                bad_id,
                SdkApiRequest {
                    command: SdkCommand::SetApnType as u16,
                    device_id: 1,
                    params: &[0, 0, 0, 8],
                },
            ),
            Err(HandleError::ApnState(ApnStateError::InvalidConfiguredType(
                8
            )))
        ));
        assert_eq!(read_api_ret(&mut server, bad_id), 1);
        assert_eq!(bridge.pending_count(), 0);
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn normal_tid_lifecycle_shares_oem_allocator_and_updates_default_eps_state() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (_client, id) = open_client(&mut server, &dir, 0);
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(1);

        // Special TIDs and normal modem requests share one live-SDK allocator.
        bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                id,
                SdkApiRequest {
                    command: SdkCommand::AddSpecialTid as u16,
                    device_id: 1,
                    params: &[0x31, 0x05, 0, 0, 2, 6, 7],
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(bridge.apn_state.tids[0].tid, 1);

        let mut attach = [0_u8; 352];
        attach[0] = 1;
        attach[1] = 0x77; // historical caller TID: live SDK overwrites it
        attach[0x067] = 4;
        attach[0x152] = 3;
        bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                id,
                SdkApiRequest {
                    command: SdkCommand::Attach as u16,
                    device_id: 1,
                    params: &attach,
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        let attach_node = bridge
            .apn_state
            .tids
            .iter()
            .find(|entry| entry.tid == 2)
            .unwrap_or_else(|| std::process::abort());
        assert_eq!(attach_node.record.message_id, 0x3101);
        assert_eq!(attach_node.record.requested_apn_type, 3);
        assert_eq!(attach_node.record.default_eps_id, 0);
        assert_eq!(attach_node.record.ip_allocation, 4);

        let attach_rsp = [
            0, 0, // register_result1
            0, 0, // register_result2
            0x12, 0x34, // default EPS ID
            0, 9, // EPS ID
            1, 2, // data path / IP allocation
            0, 0, 0, 0, 0, // network features
            0x20, 1, 2, // allocated transaction ID
            0x99, 0, // positional APN TLV
        ];
        assert_eq!(
            route_one_hci(&mut bridge, &mut server, hci_frame(0xb102, &attach_rsp)),
            Some(BroadcastReport::default())
        );
        assert_eq!(
            bridge
                .apn_state
                .tids
                .iter()
                .find(|entry| entry.tid == 2)
                .map(|entry| entry.record.default_eps_id),
            Some(0x1234)
        );

        bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                id,
                SdkApiRequest {
                    command: SdkCommand::GetApnTypeByDefaultEpsId as u16,
                    device_id: 1,
                    params: &0x1234_u16.to_be_bytes(),
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(read_shared_byte(&mut server, id, APN_TYPE_RESULT_OFFSET), 3);
    }

    #[test]
    fn normal_pdn_tid_lifecycle_updates_disconnects_and_detaches() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (_client, id) = open_client(&mut server, &dir, 0);
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(1);

        let mut pdn = [0_u8; 420];
        pdn[0x067] = 7;
        pdn[0x19a] = 4;
        bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                id,
                SdkApiRequest {
                    command: SdkCommand::PdnConnect as u16,
                    device_id: 1,
                    params: &pdn,
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        let pdn_node = bridge
            .apn_state
            .tids
            .iter()
            .find(|entry| entry.tid == 1)
            .unwrap_or_else(|| std::process::abort());
        assert_eq!(pdn_node.record.message_id, 0x3105);
        assert_eq!(pdn_node.record.requested_apn_type, 4);
        assert_eq!(pdn_node.record.ip_allocation, 7);

        let pdn_rsp = [0, 0, 0, 0, 0, 0, 0x56, 0x78, 1, 7, 0x20, 1, 1, 0x99, 0];
        assert_eq!(
            route_one_hci(&mut bridge, &mut server, hci_frame(0xb106, &pdn_rsp)),
            Some(BroadcastReport::default())
        );
        assert_eq!(
            bridge
                .apn_state
                .tids
                .iter()
                .find(|entry| entry.tid == 1)
                .map(|entry| entry.record.default_eps_id),
            Some(0x5678)
        );

        let disconnect = [0x56, 0x78, 0xee, 0];
        bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                id,
                SdkApiRequest {
                    command: SdkCommand::PdnDisconnect as u16,
                    device_id: 1,
                    params: &disconnect,
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        assert!(bridge.apn_state.tids.iter().any(|entry| entry.tid == 2));

        let disconnect_rsp = [0, 101, 0, 0, 0, 0, 0x56, 0x78, 0x20, 1, 2];
        assert_eq!(
            route_one_hci(&mut bridge, &mut server, hci_frame(0xb108, &disconnect_rsp)),
            Some(BroadcastReport::default())
        );
        assert!(!bridge.apn_state.tids.iter().any(|entry| entry.tid == 2));
        assert!(bridge.apn_state.tids.iter().any(|entry| entry.tid == 1));

        bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                id,
                SdkApiRequest {
                    command: SdkCommand::Detach as u16,
                    device_id: 1,
                    params: &0_u32.to_be_bytes(),
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(bridge.apn_state.tids.len(), 0);
    }

    #[test]
    fn normal_tid_failure_responses_retire_only_the_stock_failure_cases() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (_client, id) = open_client(&mut server, &dir, 0);
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(1);

        let mut attach = [0_u8; 352];
        attach[0] = 1;
        bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                id,
                SdkApiRequest {
                    command: SdkCommand::Attach as u16,
                    device_id: 1,
                    params: &attach,
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        assert!(bridge.apn_state.contains_tid(1));
        let attach_failure = [
            0, 0, 0, 1, // register_result2 != 0 is the live deletion condition
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20, 1, 1, 0x99, 0,
        ];
        route_one_hci(&mut bridge, &mut server, hci_frame(0xb102, &attach_failure));
        assert!(!bridge.apn_state.contains_tid(1));

        let pdn = [0_u8; 420];
        bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                id,
                SdkApiRequest {
                    command: SdkCommand::PdnConnect as u16,
                    device_id: 1,
                    params: &pdn,
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        assert!(bridge.apn_state.contains_tid(1));
        let pdn_result_five = [
            0, 5, // this exact result is the live deletion condition
            0, 0, 0, 0, 0, 7, 0, 0, 0x20, 1, 1, 0x99, 0,
        ];
        route_one_hci(
            &mut bridge,
            &mut server,
            hci_frame(0xb106, &pdn_result_five),
        );
        assert!(!bridge.apn_state.contains_tid(1));

        // Live 0xb108 only feeds event 256 into the PDN manager for result
        // 101 or 108. Other disconnect responses still callback, but leave the
        // SDK TID node untouched.
        let disconnect = [0, 7, 0, 0];
        bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                id,
                SdkApiRequest {
                    command: SdkCommand::PdnDisconnect as u16,
                    device_id: 1,
                    params: &disconnect,
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        assert!(bridge.apn_state.contains_tid(1));
        let rejected_disconnect = [
            0, 1, // not one of the two live PDN-manager completion results
            0, 0, 0, 0, 0, 7, 0x20, 1, 1,
        ];
        route_one_hci(
            &mut bridge,
            &mut server,
            hci_frame(0xb108, &rejected_disconnect),
        );
        assert!(bridge.apn_state.contains_tid(1));

        bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                id,
                SdkApiRequest {
                    command: SdkCommand::PdnDisconnect as u16,
                    device_id: 1,
                    params: &disconnect,
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        assert!(bridge.apn_state.contains_tid(2));
        let completed_disconnect = [
            0, 108, // second live PDN-manager completion result
            0, 0, 0, 0, 0, 7, 0x20, 1, 2,
        ];
        route_one_hci(
            &mut bridge,
            &mut server,
            hci_frame(0xb108, &completed_disconnect),
        );
        assert!(bridge.apn_state.contains_tid(1));
        assert!(!bridge.apn_state.contains_tid(2));
    }

    #[test]
    fn failed_normal_tid_write_does_not_leave_replacement_side_stale_state() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (_client, id) = open_client(&mut server, &dir, 0);
        let mut modem = Modem::new(HciIo::new(FailingWriter));
        let mut bridge = DeviceBridge::new(1);
        let mut pdn = [0_u8; 420];
        pdn[0x19a] = 2;

        assert!(matches!(
            bridge.handle_sdk_api(
                &mut server,
                &mut modem,
                id,
                SdkApiRequest {
                    command: SdkCommand::PdnConnect as u16,
                    device_id: 1,
                    params: &pdn,
                },
            ),
            Err(HandleError::Tracked(_))
        ));
        assert_eq!(bridge.apn_state.tids.len(), 0);
        assert_eq!(bridge.pending_count(), 0);
    }

    #[test]
    fn stock_special_tid_add_query_delete_matches_live_local_state_contract() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (_add_client, add_id) = open_client(&mut server, &dir, 0);
        let (_query_client, query_id) = open_client(&mut server, &dir, 1);
        let (_delete_client, delete_id) = open_client(&mut server, &dir, 2);
        let (_missing_client, missing_id) = open_client(&mut server, &dir, 3);
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(1);

        bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                add_id,
                SdkApiRequest {
                    command: SdkCommand::AddSpecialTid as u16,
                    device_id: 1,
                    params: &[0x31, 0x01, 0, 0x2a, 1, 4, 2],
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(read_api_ret(&mut server, add_id), 0);

        bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                query_id,
                SdkApiRequest {
                    command: SdkCommand::GetApnTypeByDefaultEpsId as u16,
                    device_id: 1,
                    params: &[0, 0x2a],
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            read_shared_byte(&mut server, query_id, APN_TYPE_RESULT_OFFSET),
            4
        );

        bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                delete_id,
                SdkApiRequest {
                    command: SdkCommand::DeleteApnTypeFromTidNode as u16,
                    device_id: 1,
                    params: &[0, 0, 0, 0, 0, 4, 0],
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(read_api_ret(&mut server, delete_id), 0);

        bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                missing_id,
                SdkApiRequest {
                    command: SdkCommand::GetApnTypeByDefaultEpsId as u16,
                    device_id: 1,
                    params: &[0, 0x2a],
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            read_shared_byte(&mut server, missing_id, APN_TYPE_RESULT_OFFSET),
            0xff
        );
        assert_eq!(bridge.pending_count(), 0);
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn malformed_special_tid_record_is_rejected_before_glif() {
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
                    command: SdkCommand::AddSpecialTid as u16,
                    device_id: 1,
                    params: &[0x31, 0x01, 0, 0, 1, 4],
                },
            ),
            Err(HandleError::UnexpectedParameters {
                expected: 7,
                actual: 6,
                ..
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
    fn stock_device_information_defers_then_materializes_exact_system_version() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (_client, id) = open_client(&mut server, &dir, 0);
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(0x1122_3344);

        let call = bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                id,
                SdkApiRequest {
                    command: SdkCommand::GetDeviceInformation as u16,
                    device_id: 0x1122_3344,
                    params: &[],
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(call.command, SdkCommand::GetDeviceInformation);
        assert_eq!(call.bytes_written, 4);
        assert_eq!(bridge.pending_count(), 1);
        assert_eq!(bridge.deferred_count(), 1);
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            vec![0x30, 0x02, 0, 0]
        );

        assert_eq!(
            route_one_hci(
                &mut bridge,
                &mut server,
                vec![0xb0, 0x03, 0, 10, 0xa0, 4, 1, 2, 3, 4, 0xa1, 2, 5, 6],
            ),
            Some(BroadcastReport::default())
        );
        assert_eq!(bridge.pending_count(), 0);
        assert_eq!(bridge.deferred_count(), 0);
        assert_eq!(read_api_ret(&mut server, id), 0);

        let mut result = [0_u8; DEVICE_INFORMATION_LEN];
        server
            .client_context(id)
            .unwrap_or_else(|_| std::process::abort())
            .read(DEVICE_INFORMATION_OFFSET, &mut result)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(&result[0..4], &[1, 2, 3, 4]);
        assert_eq!(&result[4..6], &[5, 6]);
        assert_eq!(&result[6..10], &[0; 4]);
        assert_eq!(&result[10..14], &[3, 7, 18, 2]);
        assert_eq!(&result[14..18], &[1, 0, 2, 0]);
        assert_eq!(&result[18..], &[0; 12]);
    }

    #[test]
    fn malformed_device_information_fails_deferred_stock_call() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (_client, id) = open_client(&mut server, &dir, 0);
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(1);

        bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                id,
                SdkApiRequest {
                    command: SdkCommand::GetDeviceInformation as u16,
                    device_id: 1,
                    params: &[],
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(bridge.pending_count(), 1);
        assert_eq!(bridge.deferred_count(), 1);

        let error = EventDecodeError::DeviceInformation(
            DeviceInformationDecodeError::TruncatedRecordHeader {
                offset: 0,
                remaining: 1,
            },
        );
        assert!(matches!(
            bridge.handle_modem_decode_error(&mut server, &error),
            Ok(true)
        ));
        assert_eq!(read_api_ret(&mut server, id), 1);
        assert_eq!(bridge.pending_count(), 0);
        assert_eq!(bridge.deferred_count(), 0);
    }

    #[test]
    fn stock_device_information_rejects_local_parameters_before_glif() {
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
                    command: SdkCommand::GetDeviceInformation as u16,
                    device_id: 1,
                    params: &[0],
                },
            ),
            Err(HandleError::UnexpectedParameters {
                expected: 0,
                actual: 1,
                ..
            })
        ));
        assert_eq!(read_api_ret(&mut server, id), 1);
        assert_eq!(bridge.pending_count(), 0);
        assert_eq!(bridge.deferred_count(), 0);
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn stock_nas_config_set_get_match_live_request_wire_without_synthetic_completion() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (_client, id) = open_client(&mut server, &dir, 0);
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(0x1122_3344);

        let mut params = [0_u8; 33];
        params[0] = 3;
        params[1..7].copy_from_slice(&[0x80, 1, 0x85, 2, 0x8a, 3]);
        let set = bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                id,
                SdkApiRequest {
                    command: SdkCommand::SetNasConfig as u16,
                    device_id: 0x1122_3344,
                    params: &params,
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(set.command, SdkCommand::SetNasConfig);
        assert_eq!(set.bytes_written, 13);
        assert_eq!(bridge.pending_count(), 0);
        assert_eq!(bridge.deferred_count(), 0);
        assert_eq!(read_api_ret(&mut server, id), 0);

        let get = bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                id,
                SdkApiRequest {
                    command: SdkCommand::GetNasConfig as u16,
                    device_id: 0x1122_3344,
                    params: &[],
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(get.command, SdkCommand::GetNasConfig);
        assert_eq!(get.bytes_written, 4);
        assert_eq!(bridge.pending_count(), 0);
        assert_eq!(bridge.deferred_count(), 0);
        assert_eq!(read_api_ret(&mut server, id), 0);

        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            vec![
                0x33, 0x70, 0, 9, 0x80, 1, 1, 0x85, 1, 2, 0x8a, 1, 3, 0x33, 0x72, 0, 0,
            ]
        );
    }

    #[test]
    fn malformed_nas_config_is_rejected_before_glif() {
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
                    command: SdkCommand::SetNasConfig as u16,
                    device_id: 1,
                    params: &[0; 32],
                },
            ),
            Err(HandleError::UnexpectedParameters {
                expected: 33,
                actual: 32,
                ..
            })
        ));
        assert_eq!(read_api_ret(&mut server, id), 1);

        let mut too_many = [0_u8; 33];
        too_many[0] = 17;
        assert!(matches!(
            bridge.handle_sdk_api(
                &mut server,
                &mut modem,
                id,
                SdkApiRequest {
                    command: SdkCommand::SetNasConfig as u16,
                    device_id: 1,
                    params: &too_many,
                },
            ),
            Err(HandleError::Send(_))
        ));
        assert_eq!(read_api_ret(&mut server, id), 1);

        let mut bad_tag = [0_u8; 33];
        bad_tag[0] = 1;
        bad_tag[1] = 0x7f;
        assert!(matches!(
            bridge.handle_sdk_api(
                &mut server,
                &mut modem,
                id,
                SdkApiRequest {
                    command: SdkCommand::SetNasConfig as u16,
                    device_id: 1,
                    params: &bad_tag,
                },
            ),
            Err(HandleError::Send(_))
        ));
        assert_eq!(read_api_ret(&mut server, id), 1);

        assert!(matches!(
            bridge.handle_sdk_api(
                &mut server,
                &mut modem,
                id,
                SdkApiRequest {
                    command: SdkCommand::GetNasConfig as u16,
                    device_id: 1,
                    params: &[0],
                },
            ),
            Err(HandleError::UnexpectedParameters {
                expected: 0,
                actual: 1,
                ..
            })
        ));
        assert_eq!(read_api_ret(&mut server, id), 1);
        assert_eq!(bridge.pending_count(), 0);
        assert_eq!(bridge.deferred_count(), 0);
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn stock_set_protocol_info_type8_round_trips_exact_live_p4_contract() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (subscribed, id) = open_client(&mut server, &dir, 0);
        let (_unsubscribed, _) = open_client(&mut server, &dir, 1);
        server
            .client_context(id)
            .unwrap_or_else(|_| std::process::abort())
            .write_u32_be(SdkCallbackKind::SetProtocolInfo.registration_offset(), 1)
            .unwrap_or_else(|_| std::process::abort());

        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(0x1122_3344);
        let call = bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                id,
                SdkApiRequest {
                    command: SdkCommand::SetProtocolInfo as u16,
                    device_id: 0x1122_3344,
                    params: &[0, 8, 0x55],
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(call.bytes_written, 9);
        assert_eq!(bridge.pending_count(), 1);
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            vec![0x31, 0x51, 0, 5, 0, 8, 0, 1, 0x55]
        );

        assert_eq!(
            route_one_hci(
                &mut bridge,
                &mut server,
                vec![0xb1, 0x52, 0, 7, 0, 0, 0, 8, 0, 1, 0x55],
            ),
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
        let callback = SdkCallback::parse(
            Packet::parse(&frame[..len]).unwrap_or_else(|_| std::process::abort()),
        )
        .unwrap_or_else(|_| std::process::abort());
        assert_eq!(callback.callback_id, 178);
        assert_eq!(callback.device_id, 0x1122_3344);
        assert_eq!(callback.data, &[0, 0, 0, 8, 0x55]);
    }

    #[test]
    fn stock_set_protocol_info_type1_uses_exact_four_byte_data_shape() {
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
                    command: SdkCommand::SetProtocolInfo as u16,
                    device_id: 1,
                    params: &[0, 1, 0x11, 0x22, 0x33, 0x44],
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(call.bytes_written, 12);
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            vec![0x31, 0x51, 0, 8, 0, 1, 0, 4, 0x11, 0x22, 0x33, 0x44]
        );
    }

    #[test]
    fn set_protocol_info_rejects_type9_and_bad_lengths_before_glif() {
        assert_eq!(
            decode_legacy_set_protocol_info(&[0, 9, 0]),
            Err(LegacySetProtocolInfoDecodeError::UnsupportedType(9))
        );
        assert_eq!(
            decode_legacy_set_protocol_info(&[0, 8]),
            Err(LegacySetProtocolInfoDecodeError::UnexpectedLength {
                expected: 3,
                actual: 2,
            })
        );

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
                    command: SdkCommand::SetProtocolInfo as u16,
                    device_id: 1,
                    params: &[0, 9, 0],
                },
            ),
            Err(HandleError::LegacySetProtocolInfo(
                LegacySetProtocolInfoDecodeError::UnsupportedType(9)
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
    fn stock_rrc_capability_set_get_round_trip_and_subscription_slots() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (subscribed, id) = open_client(&mut server, &dir, 0);
        server
            .client_context(id)
            .unwrap_or_else(|_| std::process::abort())
            .write_u32_be(
                SdkCallbackKind::RrcCapabilityControl.registration_offset(),
                1,
            )
            .unwrap_or_else(|_| std::process::abort());
        server
            .client_context(id)
            .unwrap_or_else(|_| std::process::abort())
            .write_u32_be(
                SdkCallbackKind::RrcCapabilityControlGet.registration_offset(),
                1,
            )
            .unwrap_or_else(|_| std::process::abort());

        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(0x1122_3344);

        let set = bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                id,
                SdkApiRequest {
                    command: SdkCommand::RrcCapabilityControl as u16,
                    device_id: 0x1122_3344,
                    params: &[0, 18, 0, 2, 0xaa, 0xbb],
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(set.bytes_written, 10);
        let get = bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                id,
                SdkApiRequest {
                    command: SdkCommand::RrcCapabilityControlGet as u16,
                    device_id: 0x1122_3344,
                    params: &[0, 4, 0xff, 0xee, 0xdd],
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(get.bytes_written, 6);
        assert_eq!(bridge.pending_count(), 2);
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            vec![
                0x39, 0x06, 0, 6, 0, 18, 0, 2, 0xaa, 0xbb, 0x39, 0x0d, 0, 2, 0, 4,
            ]
        );

        assert_eq!(
            route_one_hci(
                &mut bridge,
                &mut server,
                vec![0xb9, 0x07, 0, 6, 0, 0, 0, 0, 0, 18],
            ),
            Some(BroadcastReport {
                registered_clients: 1,
                sent_clients: 1,
            })
        );
        assert_eq!(
            route_one_hci(
                &mut bridge,
                &mut server,
                vec![0xb9, 0x0e, 0, 11, 0, 0, 0, 4, 0, 5, 2, 0, 1, 0, 2,],
            ),
            Some(BroadcastReport {
                registered_clients: 1,
                sent_clients: 1,
            })
        );
        assert_eq!(bridge.pending_count(), 0);

        let mut frame = [0_u8; 64];
        let len = subscribed
            .recv(&mut frame)
            .unwrap_or_else(|_| std::process::abort());
        let callback = SdkCallback::parse(
            Packet::parse(&frame[..len]).unwrap_or_else(|_| std::process::abort()),
        )
        .unwrap_or_else(|_| std::process::abort());
        assert_eq!(callback.callback_id, 221);
        assert_eq!(callback.data, &[0, 0, 0, 0, 0, 18]);

        let len = subscribed
            .recv(&mut frame)
            .unwrap_or_else(|_| std::process::abort());
        let callback = SdkCallback::parse(
            Packet::parse(&frame[..len]).unwrap_or_else(|_| std::process::abort()),
        )
        .unwrap_or_else(|_| std::process::abort());
        assert_eq!(callback.callback_id, 223);
        assert_eq!(callback.data, &[0, 0, 0, 4, 0, 5, 2, 0, 1, 0, 2]);
    }

    #[test]
    fn rrc_capability_legacy_decoder_rejects_unsafe_or_unshipped_shapes() {
        assert_eq!(
            decode_legacy_rrc_capability_set(&[0, 4, 0, 3, 2, 0, 1]),
            Err(LegacyRrcCapabilityDecodeError::Type4ListTruncated {
                count: 2,
                minimum_data_len: 5,
                actual_data_len: 3,
            })
        );
        assert_eq!(
            decode_legacy_rrc_capability_set(&[0, 5, 0, 0]),
            Err(LegacyRrcCapabilityDecodeError::UnsupportedType(5))
        );
        assert_eq!(
            decode_legacy_rrc_capability_get(&[0, 4, 0, 0]),
            Err(LegacyRrcCapabilityDecodeError::UnexpectedLength {
                expected: 5,
                actual: 4,
            })
        );
    }

    #[test]
    fn rrc_capability_type11_success_is_silent_but_failure_emits_callback() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (client, id) = open_client(&mut server, &dir, 0);
        server
            .client_context(id)
            .unwrap_or_else(|_| std::process::abort())
            .write_u32_be(
                SdkCallbackKind::RrcCapabilityControl.registration_offset(),
                1,
            )
            .unwrap_or_else(|_| std::process::abort());
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(1);
        bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                id,
                SdkApiRequest {
                    command: SdkCommand::RrcCapabilityControl as u16,
                    device_id: 1,
                    params: &[0, 11, 0, 1, 0x7f],
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(bridge.pending_count(), 1);
        assert_eq!(
            route_one_hci(
                &mut bridge,
                &mut server,
                vec![0xb9, 0x07, 0, 6, 0, 0, 0, 0, 0, 11],
            ),
            None
        );
        assert_eq!(bridge.pending_count(), 0);
        client
            .set_nonblocking(true)
            .unwrap_or_else(|_| std::process::abort());
        let mut no_frame = [0_u8; 1];
        let Err(error) = client.recv(&mut no_frame) else {
            std::process::abort();
        };
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        client
            .set_nonblocking(false)
            .unwrap_or_else(|_| std::process::abort());

        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                id,
                SdkApiRequest {
                    command: SdkCommand::RrcCapabilityControl as u16,
                    device_id: 1,
                    params: &[0, 11, 0, 1, 0x7f],
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            route_one_hci(
                &mut bridge,
                &mut server,
                vec![0xb9, 0x07, 0, 6, 0, 1, 0, 0, 0, 11],
            ),
            Some(BroadcastReport {
                registered_clients: 1,
                sent_clients: 1,
            })
        );
        let mut frame = [0_u8; 32];
        let len = client
            .recv(&mut frame)
            .unwrap_or_else(|_| std::process::abort());
        let callback = SdkCallback::parse(
            Packet::parse(&frame[..len]).unwrap_or_else(|_| std::process::abort()),
        )
        .unwrap_or_else(|_| std::process::abort());
        assert_eq!(callback.callback_id, 221);
        assert_eq!(callback.data, &[0, 1, 0, 0, 0, 11]);
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

    #[test]
    fn stock_query_selected_plmn_round_trips_exact_live_p4_contract() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (client, id) = open_client(&mut server, &dir, 0);
        server
            .client_context(id)
            .unwrap_or_else(|_| std::process::abort())
            .write_u32_be(SdkCallbackKind::QuerySelectedPlmn.registration_offset(), 1)
            .unwrap_or_else(|_| std::process::abort());

        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(0x1122_3344);
        let call = bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                id,
                SdkApiRequest {
                    command: SdkCommand::QuerySelectedPlmn as u16,
                    device_id: 0x1122_3344,
                    params: &[],
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(call.bytes_written, 4);
        assert_eq!(bridge.pending_count(), 1);
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            vec![0x31, 0x0f, 0, 0]
        );

        assert_eq!(
            route_one_hci(
                &mut bridge,
                &mut server,
                vec![0xb1, 0x10, 0, 4, 0, 0x21, 0xf3, 0x54],
            ),
            Some(BroadcastReport {
                registered_clients: 1,
                sent_clients: 1,
            })
        );
        assert_eq!(bridge.pending_count(), 0);
        let mut frame = [0_u8; 32];
        let len = client
            .recv(&mut frame)
            .unwrap_or_else(|_| std::process::abort());
        let callback = SdkCallback::parse(
            Packet::parse(&frame[..len]).unwrap_or_else(|_| std::process::abort()),
        )
        .unwrap_or_else(|_| std::process::abort());
        assert_eq!(callback.callback_id, 54);
        assert_eq!(callback.data, &[0, 0x21, 0xf3, 0x54]);
    }

    #[test]
    fn stock_rrc_function_set_get_round_trip_exact_shipped_selector7() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (client, id) = open_client(&mut server, &dir, 0);
        for kind in [
            SdkCallbackKind::RrcFunctionControl,
            SdkCallbackKind::RrcFunctionControlGet,
        ] {
            server
                .client_context(id)
                .unwrap_or_else(|_| std::process::abort())
                .write_u32_be(kind.registration_offset(), 1)
                .unwrap_or_else(|_| std::process::abort());
        }

        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(1);
        bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                id,
                SdkApiRequest {
                    command: SdkCommand::RrcFunctionControl as u16,
                    device_id: 1,
                    params: &[0, 7, 0, 1, 1],
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                id,
                SdkApiRequest {
                    command: SdkCommand::RrcFunctionControlGet as u16,
                    device_id: 1,
                    params: &[0, 7, 0, 0],
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(bridge.pending_count(), 2);
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            vec![
                0x39, 0x08, 0, 5, 0, 7, 0, 1, 1, 0x39, 0x0f, 0, 4, 0, 7, 0, 0,
            ]
        );

        assert_eq!(
            route_one_hci(
                &mut bridge,
                &mut server,
                vec![0xb9, 0x09, 0, 7, 0, 0, 0, 1, 0, 7, 0xaa],
            ),
            Some(BroadcastReport {
                registered_clients: 1,
                sent_clients: 1,
            })
        );
        assert_eq!(
            route_one_hci(
                &mut bridge,
                &mut server,
                vec![0xb9, 0x10, 0, 7, 0, 0, 0, 1, 0, 7, 0xbb],
            ),
            Some(BroadcastReport {
                registered_clients: 1,
                sent_clients: 1,
            })
        );
        assert_eq!(bridge.pending_count(), 0);

        let mut frame = [0_u8; 32];
        let len = client
            .recv(&mut frame)
            .unwrap_or_else(|_| std::process::abort());
        let callback = SdkCallback::parse(
            Packet::parse(&frame[..len]).unwrap_or_else(|_| std::process::abort()),
        )
        .unwrap_or_else(|_| std::process::abort());
        assert_eq!(callback.callback_id, 225);
        assert_eq!(callback.data, &[0, 0, 0, 1, 0, 7]);

        let len = client
            .recv(&mut frame)
            .unwrap_or_else(|_| std::process::abort());
        let callback = SdkCallback::parse(
            Packet::parse(&frame[..len]).unwrap_or_else(|_| std::process::abort()),
        )
        .unwrap_or_else(|_| std::process::abort());
        assert_eq!(callback.callback_id, 227);
        assert_eq!(callback.data, &[0, 0, 0, 7, 0, 1, 0xbb]);
    }

    #[test]
    fn stock_rrc_function_selector1_compresses_legacy_earfcns_deterministically() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (_client, id) = open_client(&mut server, &dir, 0);
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(1);

        let mut params = vec![0_u8; 4 + 182];
        params[..4].copy_from_slice(&[0, 1, 0, 182]);
        params[4..6].copy_from_slice(&2_u16.to_be_bytes());
        params[6..10].copy_from_slice(&0x1234_u32.to_be_bytes());
        params[10..14].copy_from_slice(&0x1_2345_u32.to_be_bytes());
        for (index, byte) in params[4 + 122..4 + 182].iter_mut().enumerate() {
            *byte = u8::try_from(index).unwrap_or(0).wrapping_add(0xa0);
        }
        bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                id,
                SdkApiRequest {
                    command: SdkCommand::RrcFunctionControl as u16,
                    device_id: 1,
                    params: &params,
                },
            )
            .unwrap_or_else(|_| std::process::abort());

        let wire = modem.into_transport().into_inner().into_inner();
        assert_eq!(&wire[..8], &[0x39, 0x08, 0, 126, 0, 1, 0, 122]);
        assert_eq!(&wire[8..14], &[0, 2, 0x12, 0x34, 0x23, 0x45]);
        assert!(wire[14..70].iter().all(|byte| *byte == 0));
        assert_eq!(&wire[70..130], &params[126..186]);
    }

    #[test]
    fn unshipped_rrc_function_selector_is_rejected_before_modem_write() {
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
                    command: SdkCommand::RrcFunctionControl as u16,
                    device_id: 1,
                    params: &[0, 8, 0, 0],
                },
            ),
            Err(HandleError::LegacyRrcFunction(
                LegacyRrcFunctionDecodeError::UnsupportedType(8)
            ))
        ));
        assert_eq!(read_api_ret(&mut server, id), 1);
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn stock_set_mtu_requires_explicit_host_executor() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (_client, id) = open_client(&mut server, &dir, 0);
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(1);
        let mut params = [0_u8; 258];
        params[..9].copy_from_slice(b"lte0pdn3\0");
        params[256..].copy_from_slice(&1500_u16.to_be_bytes());

        assert!(matches!(
            bridge.handle_sdk_api(
                &mut server,
                &mut modem,
                id,
                SdkApiRequest {
                    command: SdkCommand::SetMtuSize as u16,
                    device_id: 1,
                    params: &params,
                },
            ),
            Err(HandleError::Host(_))
        ));
        assert_eq!(read_api_ret(&mut server, id), 1);
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn stock_set_mtu_is_host_local_and_propagates_host_failure() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (_client, id) = open_client(&mut server, &dir, 0);
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(1);
        let mut params = [0_u8; 258];
        params[..9].copy_from_slice(b"lte0pdn3\0");
        params[256..].copy_from_slice(&1500_u16.to_be_bytes());

        let mut captured = None;
        let call = bridge
            .handle_sdk_api_with_host(
                &mut server,
                &mut modem,
                id,
                SdkApiRequest {
                    command: SdkCommand::SetMtuSize as u16,
                    device_id: 1,
                    params: &params,
                },
                |action| {
                    captured = Some(action);
                    Ok(())
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(call.bytes_written, 0);
        assert_eq!(read_api_ret(&mut server, id), 0);
        assert_eq!(
            captured,
            Some(HostAction::SetMtu {
                interface_name: [
                    b'l', b't', b'e', b'0', b'p', b'd', b'n', b'3', 0, 0, 0, 0, 0, 0, 0,
                ],
                name_len: 8,
                mtu: 1500,
            })
        );

        let error = bridge.handle_sdk_api_with_host(
            &mut server,
            &mut modem,
            id,
            SdkApiRequest {
                command: SdkCommand::SetMtuSize as u16,
                device_id: 1,
                params: &params,
            },
            |_| Err(io::Error::from_raw_os_error(1)),
        );
        assert!(matches!(error, Err(HandleError::Host(_))));
        assert_eq!(read_api_ret(&mut server, id), 1);
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn stock_set_mtu_rejects_zero_mtu_before_host_action() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (_client, id) = open_client(&mut server, &dir, 0);
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(1);
        let mut params = [0_u8; 258];
        params[..9].copy_from_slice(b"lte0pdn3\0");
        let mut called = false;
        assert!(matches!(
            bridge.handle_sdk_api_with_host(
                &mut server,
                &mut modem,
                id,
                SdkApiRequest {
                    command: SdkCommand::SetMtuSize as u16,
                    device_id: 1,
                    params: &params,
                },
                |_| {
                    called = true;
                    Ok(())
                },
            ),
            Err(HandleError::HostRequest(HostRequestError::ZeroMtu))
        ));
        assert!(!called);
        assert_eq!(read_api_ret(&mut server, id), 1);
    }

    #[test]
    fn stock_dhcp_lease_state_tracks_typed_ipv4_connection_state() {
        let dir = TestDir::new();
        let mut server = bind_server(&dir);
        let (_client, id) = open_client(&mut server, &dir, 0);
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        let mut bridge = DeviceBridge::new(1);

        bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                id,
                SdkApiRequest {
                    command: SdkCommand::CheckDhcpLeaseState as u16,
                    device_id: 1,
                    params: &[3],
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            read_shared_byte(&mut server, id, DHCP_LEASE_STATE_RESULT_OFFSET),
            0
        );

        let mut attach = [0_u8; 352];
        attach[0] = 1;
        attach[0x067] = 4;
        attach[0x152] = 3;
        bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                id,
                SdkApiRequest {
                    command: SdkCommand::Attach as u16,
                    device_id: 1,
                    params: &attach,
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        let mut attach_rsp = vec![
            0, 0, 0, 0, 0x12, 0x34, 0, 9, 1, 4, 0, 0, 0, 0, 0, 0x20, 1, 1, 0x04, 8, b'i', b'n',
            b't', b'e', b'r', b'n', b'e', b't',
        ];
        let pdn_fields = [
            0x05, 1, 3, 0x07, 4, 10, 20, 30, 40, 0x08, 4, 1, 1, 1, 1, 0x09, 4, 8, 8, 8, 8,
        ];
        attach_rsp.push(0xf0);
        attach_rsp.push(u8::try_from(pdn_fields.len()).unwrap_or(0));
        attach_rsp.extend_from_slice(&pdn_fields);
        assert_eq!(
            route_one_hci(&mut bridge, &mut server, hci_frame(0xb102, &attach_rsp)),
            Some(BroadcastReport::default())
        );

        bridge
            .handle_sdk_api(
                &mut server,
                &mut modem,
                id,
                SdkApiRequest {
                    command: SdkCommand::CheckDhcpLeaseState as u16,
                    device_id: 1,
                    params: &[3],
                },
            )
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            read_shared_byte(&mut server, id, DHCP_LEASE_STATE_RESULT_OFFSET),
            1
        );
    }
}
