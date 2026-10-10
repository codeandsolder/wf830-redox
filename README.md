# WF830 Rust rewrite

Clean-room Rust components for the WF830/GCT GDM7243QT replacement userland.

The repository intentionally excludes firmware dumps, OEM binaries, credentials,
and extracted proprietary files. Reverse-engineering inputs remain in the parent
`wf830` research tree.

Current crates:

- `gct-hci`: exact GCT HCI framing, TLV primitives and verified public/recovered opcodes.
- `gct-lapi`: typed clean codecs for proven modem request/response families; no stock `liblted.so` ABI.
- `gct-transport`: safe `/dev/glif0` byte transport plus incremental HCI stream framing across split/coalesced reads.
- `gct-runtime`: modem request correlation, startup sequencing and typed modem-event decoding above transport.
- `lted-proto`: exact local `lted` datagram envelopes, SDK command IDs and callback metadata.
- `lted-sysv`: bounded System V shared-memory/semaphore compatibility for stock clients.
- `lted-compat`: stock local client/socket lifecycle and shared-context access.
- `lted-bridge`: translation between the stock client ABI and clean modem/runtime semantics, including compatibility-only state.
- `gctd`: process integration and polling/event-loop wiring for the layers above, including the recovered rtnetlink IPv6-prefix feed.

The dependency direction is deliberate: modem wire data is decoded into typed
semantics before compatibility translation. Historical stock ABI byte layouts are
output formats, not an internal state model. In particular, connection state is
maintained from typed Attach/PDN responses rather than reconstructed from serialized
stock callback images.

The rule is evidence first: guessed layouts do not enter executable protocol
code. Every recovered constant should be traceable to either upstream GCT/Linux
source or a specific OEM function/disassembly. Host-derived compatibility state
is wired from the proven kernel event source rather than synthesized from
plausible defaults.
