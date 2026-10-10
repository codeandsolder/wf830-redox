use std::io;

use lted_compat::Server;
use lted_proto::SdkCallbackKind;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BroadcastReport {
    pub registered_clients: usize,
    pub sent_clients: usize,
}

/// Deliver one already-encoded stock callback frame to every client with the
/// corresponding recovered `cb_rsp[]` registration slot enabled.
///
/// Encoding and compatibility semantics deliberately stay outside this module:
/// this layer owns only subscription lookup and UNIX-datagram delivery.
pub(crate) fn broadcast_registered(
    server: &mut Server,
    callback_kind: SdkCallbackKind,
    frame: &[u8],
) -> io::Result<BroadcastReport> {
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
        server.send_to_client(client_id, frame)?;
        report.sent_clients += 1;
    }
    Ok(report)
}
