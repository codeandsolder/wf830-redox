# WF830 Rust rewrite

Clean-room Rust components for the WF830/GCT GDM7243QT replacement userland.

The repository intentionally excludes firmware dumps, OEM binaries, credentials,
and extracted proprietary files. Reverse-engineering inputs remain in the parent
`wf830` research tree.

Current crates:

- `gct-hci`: exact GCT HCI framing plus only verified public/recovered opcodes.
- `gct-lapi`: typed clean codecs for proven attach/detach, PDN, PLMN, UICC, online/offline and AT paths.
- `gct-transport`: safe `/dev/glif0` byte transport plus incremental HCI stream framing across split/coalesced reads.
- `gct-runtime`: modem core owning GLIF buffering, typed proven TX/P0 event dispatch and the observed startup handshake; includes the `gctd` executable harness.
- `lted-proto`: exact local `lted` framing and the minimum critical SDK command set.

The rule is evidence first: guessed layouts do not enter executable protocol
code. Every recovered constant should be traceable to either upstream GCT/Linux
source or a specific OEM function/disassembly.
