//! Safe userspace transport for the WF830 GCT host-control interface.
//!
//! Live P4 reverse engineering shows that control traffic is read from and
//! written to `/dev/glif0` with ordinary POSIX `read`/`write`. The kernel GLIF
//! read path can split one queued buffer across userspace reads, while the SDK
//! decoder accepts multiple concatenated HCI packets in one returned buffer.
//! [`HciStreamDecoder`] therefore carries an incomplete trailing frame across
//! reads and dispatches every complete frame without per-frame allocation.

use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    path::Path,
};

use gct_hci::{HEADER_LEN, Header, Packet};

/// Character device used by the live P4 SDK for HCI control traffic.
pub const DEFAULT_GLIF_PATH: &str = "/dev/glif0";

/// Buffer size used by the live P4 `io_recv_thread` for one GLIF read.
///
/// This is an observed SDK choice, not a protocol-level maximum.
pub const OEM_READ_BUFFER_LEN: usize = 32_768;

/// Maximum representable HCI frame size: four-byte header plus a `u16` payload.
pub const MAX_HCI_FRAME_LEN: usize = HEADER_LEN + 65_535;

/// Thin safe wrapper around a bidirectional byte stream carrying HCI traffic.
///
/// Keeping this generic makes the framing and I/O behavior testable without a
/// modem; production code uses [`GlifTransport`].
pub struct HciIo<T> {
    inner: T,
}

impl<T> HciIo<T> {
    /// Wrap an already-open bidirectional transport.
    pub const fn new(inner: T) -> Self {
        Self { inner }
    }

    /// Recover the wrapped transport.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.inner
    }

    /// Borrow the wrapped transport.
    #[must_use]
    pub const fn inner(&self) -> &T {
        &self.inner
    }

    /// Mutably borrow the wrapped transport.
    pub const fn inner_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

impl HciIo<File> {
    /// Open the live firmware's default GLIF character device read/write.
    ///
    /// # Errors
    /// Returns the underlying [`io::Error`] when `/dev/glif0` cannot be opened.
    pub fn open_default() -> io::Result<Self> {
        Self::open(DEFAULT_GLIF_PATH)
    }

    /// Open a GLIF-compatible character device read/write.
    ///
    /// # Errors
    /// Returns the underlying [`io::Error`] when `path` cannot be opened.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map(Self::new)
    }
}

impl<T: Read> HciIo<T> {
    /// Read one raw chunk from the underlying transport.
    ///
    /// A returned chunk is not guaranteed to contain exactly one HCI frame;
    /// feed it to [`HciStreamDecoder`].
    ///
    /// # Errors
    /// Returns the underlying [`io::Error`] from [`Read::read`].
    pub fn read_chunk(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buffer)
    }
}

impl<T: Write> HciIo<T> {
    /// Write all supplied bytes to the underlying transport.
    ///
    /// # Errors
    /// Returns the underlying [`io::Error`] from [`Write::write_all`].
    pub fn write_bytes(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.inner.write_all(bytes)
    }
}

/// Production GLIF transport backed by a Linux character-device file.
pub type GlifTransport = HciIo<File>;

/// Incremental decoder for the byte stream returned by `/dev/glif0`.
///
/// Complete packets are borrowed only for the duration of the callback. The
/// decoder retains at most the incomplete suffix needed by the next call.
#[derive(Debug, Default)]
pub struct HciStreamDecoder {
    pending: Vec<u8>,
}

impl HciStreamDecoder {
    /// Create an empty stream decoder.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            pending: Vec::new(),
        }
    }

    /// Number of bytes currently retained for an incomplete next frame.
    #[must_use]
    pub const fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Whether no incomplete frame bytes are retained.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Discard an incomplete buffered suffix.
    pub fn clear(&mut self) {
        self.pending.clear();
    }

    /// Append one raw GLIF read and dispatch every newly complete HCI packet.
    ///
    /// Returns the number of packets dispatched. An incomplete header or
    /// payload remains buffered for the next call. Every four-byte HCI header
    /// has a bounded `u16` payload length, so no framing error is required: a
    /// suffix is either complete now or can become complete after more bytes.
    pub fn feed<F>(&mut self, bytes: &[u8], mut dispatch: F) -> usize
    where
        F: FnMut(Packet<'_>),
    {
        self.pending.extend_from_slice(bytes);
        let mut consumed = 0_usize;
        let mut packet_count = 0_usize;

        loop {
            let remaining = &self.pending[consumed..];
            let Some(header_bytes) = remaining.get(..HEADER_LEN) else {
                break;
            };
            let header = Header::decode([
                header_bytes[0],
                header_bytes[1],
                header_bytes[2],
                header_bytes[3],
            ]);
            let frame_len = HEADER_LEN + usize::from(header.payload_len);
            let Some(frame) = remaining.get(..frame_len) else {
                break;
            };

            dispatch(Packet {
                header,
                payload: &frame[HEADER_LEN..],
            });
            consumed += frame_len;
            packet_count += 1;
        }

        if consumed != 0 {
            self.pending.drain(..consumed);
        }
        packet_count
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use gct_hci::{Header, public_opcode};

    use super::{HciIo, HciStreamDecoder, MAX_HCI_FRAME_LEN};

    #[test]
    fn stream_decoder_handles_multiple_frames_in_one_read() {
        let bytes = [
            0xb3, 0x08, 0x00, 0x02, b'O', b'K', 0xb3, 0x24, 0x00, 0x03, 0x07, b'O', b'K',
        ];
        let mut decoder = HciStreamDecoder::new();
        let mut seen = Vec::new();
        let count = decoder.feed(&bytes, |packet| {
            seen.push((packet.header.command, packet.payload.to_vec()));
        });

        assert_eq!(count, 2);
        assert_eq!(
            seen,
            vec![
                (public_opcode::LTE_AT_CMD_FROM_DEVICE, b"OK".to_vec()),
                (
                    public_opcode::LTE_AT_CMD_FROM_DEVICE_EXT,
                    vec![0x07, b'O', b'K'],
                ),
            ]
        );
        assert!(decoder.is_empty());
    }

    #[test]
    fn stream_decoder_carries_a_frame_across_reads() {
        let bytes = [0xb3, 0x08, 0x00, 0x04, b'T', b'E', b'S', b'T'];
        let mut decoder = HciStreamDecoder::new();
        let mut seen = Vec::new();

        assert_eq!(decoder.feed(&bytes[..3], |_| {}), 0);
        assert_eq!(decoder.pending_len(), 3);
        assert_eq!(decoder.feed(&bytes[3..6], |_| {}), 0);
        assert_eq!(decoder.pending_len(), 6);
        assert_eq!(
            decoder.feed(&bytes[6..], |packet| {
                seen.push((packet.header, packet.payload.to_vec()));
            }),
            1
        );
        assert_eq!(
            seen,
            vec![(
                Header {
                    command: public_opcode::LTE_AT_CMD_FROM_DEVICE,
                    payload_len: 4,
                },
                b"TEST".to_vec(),
            )]
        );
        assert!(decoder.is_empty());
    }

    #[test]
    fn stream_decoder_preserves_partial_trailing_frame_after_complete_one() {
        let first = [0xb3, 0x08, 0x00, 0x01, b'A'];
        let second = [0xb3, 0x08, 0x00, 0x03, b'X', b'Y', b'Z'];
        let mut combined = Vec::from(first);
        combined.extend_from_slice(&second[..5]);

        let mut decoder = HciStreamDecoder::new();
        let mut payloads = Vec::new();
        assert_eq!(
            decoder.feed(&combined, |packet| payloads.push(packet.payload.to_vec())),
            1
        );
        assert_eq!(payloads, vec![b"A".to_vec()]);
        assert_eq!(decoder.pending_len(), 5);

        assert_eq!(
            decoder.feed(&second[5..], |packet| payloads
                .push(packet.payload.to_vec())),
            1
        );
        assert_eq!(payloads, vec![b"A".to_vec(), b"XYZ".to_vec()]);
        assert!(decoder.is_empty());
    }

    #[test]
    fn generic_transport_forwards_reads_and_writes_exactly() {
        let mut reader = HciIo::new(Cursor::new(vec![1_u8, 2, 3, 4]));
        let mut read_buffer = [0_u8; 8];
        assert!(matches!(reader.read_chunk(&mut read_buffer), Ok(4)));
        assert_eq!(&read_buffer[..4], &[1, 2, 3, 4]);

        let mut writer = HciIo::new(Cursor::new(Vec::new()));
        assert!(matches!(writer.write_bytes(&[5, 6, 7]), Ok(())));
        assert_eq!(writer.into_inner().into_inner(), vec![5, 6, 7]);
    }

    #[test]
    fn maximum_frame_size_matches_u16_wire_length() {
        assert_eq!(MAX_HCI_FRAME_LEN, 65_539);
    }
}
