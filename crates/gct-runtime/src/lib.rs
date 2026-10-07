//! Minimal modem runtime over the proven GCT GLIF transport.
//!
//! This crate intentionally stops below the OEM `lted` compatibility layer.
//! It owns byte-stream buffering, the live SDK startup handshake and dispatch
//! of complete borrowed HCI packets. Higher layers can build request/response
//! correlation and client APIs without duplicating transport state.

use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

use gct_hci::{Header, Packet, recovered_opcode};
use gct_transport::{GlifTransport, HciIo, HciStreamDecoder, OEM_READ_BUFFER_LEN};

/// Result of one blocking read/dispatch iteration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PollOutcome {
    /// Raw bytes returned by the underlying GLIF read.
    pub bytes_read: usize,
    /// Complete HCI packets dispatched from this read plus any buffered suffix.
    pub packets_dispatched: usize,
}

/// Core modem runtime over an arbitrary bidirectional transport.
pub struct Modem<T> {
    transport: HciIo<T>,
    decoder: HciStreamDecoder,
    read_buffer: Vec<u8>,
}

impl<T> Modem<T> {
    /// Construct a runtime using the live SDK's observed 32 KiB read size.
    #[must_use]
    pub fn new(transport: HciIo<T>) -> Self {
        Self {
            transport,
            decoder: HciStreamDecoder::new(),
            read_buffer: vec![0_u8; OEM_READ_BUFFER_LEN],
        }
    }

    /// Recover the underlying transport.
    #[must_use]
    pub fn into_transport(self) -> HciIo<T> {
        self.transport
    }

    /// Borrow the underlying transport.
    #[must_use]
    pub const fn transport(&self) -> &HciIo<T> {
        &self.transport
    }

    /// Mutably borrow the underlying transport.
    pub const fn transport_mut(&mut self) -> &mut HciIo<T> {
        &mut self.transport
    }

    /// Number of bytes retained because the final HCI frame is incomplete.
    #[must_use]
    pub const fn pending_rx_bytes(&self) -> usize {
        self.decoder.pending_len()
    }
}

impl Modem<File> {
    /// Open `/dev/glif0` and create the runtime.
    ///
    /// # Errors
    /// Returns the underlying [`io::Error`] when the character device cannot
    /// be opened read/write.
    pub fn open_default() -> io::Result<Self> {
        GlifTransport::open_default().map(Self::new)
    }

    /// Open a GLIF-compatible character device and create the runtime.
    ///
    /// # Errors
    /// Returns the underlying [`io::Error`] when `path` cannot be opened
    /// read/write.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        GlifTransport::open(path).map(Self::new)
    }
}

impl<T: Write> Modem<T> {
    /// Send the zero-payload `0x3337` command emitted by the live P4 SDK after
    /// its GLIF readiness probe.
    ///
    /// No matching response handler exists in the SDK dispatch table, so this
    /// is intentionally modeled as a fire-and-forget startup handshake.
    ///
    /// # Errors
    /// Returns the underlying transport [`io::Error`] if all four bytes cannot
    /// be written.
    pub fn send_startup_handshake(&mut self) -> io::Result<()> {
        let frame = Header {
            command: recovered_opcode::SDK_STARTUP_HANDSHAKE,
            payload_len: 0,
        }
        .encode();
        self.transport.write_bytes(&frame)
    }

    /// Write one caller-encoded HCI frame or batch unchanged.
    ///
    /// Typed LAPI encoders remain responsible for producing the wire bytes;
    /// this runtime does not silently normalize or rewrite requests.
    ///
    /// # Errors
    /// Returns the underlying transport [`io::Error`] if all bytes cannot be
    /// written.
    pub fn send_bytes(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.transport.write_bytes(bytes)
    }
}

impl<T: Read> Modem<T> {
    /// Perform one blocking transport read and dispatch every complete HCI
    /// packet made available by it.
    ///
    /// A partial trailing packet stays in the decoder until a later call.
    /// A zero-byte read is reported as such and dispatches no new packet.
    ///
    /// # Errors
    /// Returns the underlying [`io::Error`] from the GLIF read.
    pub fn poll_once<F>(&mut self, dispatch: F) -> io::Result<PollOutcome>
    where
        F: FnMut(Packet<'_>),
    {
        let bytes_read = self.transport.read_chunk(&mut self.read_buffer)?;
        let packets_dispatched = self.decoder.feed(&self.read_buffer[..bytes_read], dispatch);
        Ok(PollOutcome {
            bytes_read,
            packets_dispatched,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use gct_hci::public_opcode;
    use gct_transport::HciIo;

    use super::{Modem, PollOutcome};

    #[test]
    fn startup_handshake_matches_live_p4_bytes() {
        let transport = HciIo::new(Cursor::new(Vec::new()));
        let mut modem = Modem::new(transport);
        assert!(matches!(modem.send_startup_handshake(), Ok(())));
        assert_eq!(
            modem.into_transport().into_inner().into_inner(),
            vec![0x33, 0x37, 0x00, 0x00]
        );
    }

    #[test]
    fn one_poll_dispatches_a_concatenated_hci_batch() {
        let bytes = vec![
            0xb3, 0x08, 0x00, 0x02, b'O', b'K', 0xb3, 0x24, 0x00, 0x02, 0x03, b'X',
        ];
        let transport = HciIo::new(Cursor::new(bytes));
        let mut modem = Modem::new(transport);
        let mut seen = Vec::new();
        let outcome = modem.poll_once(|packet| {
            seen.push((packet.header.command, packet.payload.to_vec()));
        });

        assert!(matches!(
            outcome,
            Ok(PollOutcome {
                bytes_read: 12,
                packets_dispatched: 2,
            })
        ));
        assert_eq!(
            seen,
            vec![
                (public_opcode::LTE_AT_CMD_FROM_DEVICE, b"OK".to_vec()),
                (public_opcode::LTE_AT_CMD_FROM_DEVICE_EXT, vec![0x03, b'X'],),
            ]
        );
        assert_eq!(modem.pending_rx_bytes(), 0);
    }
}
