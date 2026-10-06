# WF830 Rust rewrite

Clean-room Rust components for the WF830/GCT GDM7243QT replacement userland.

The repository intentionally excludes firmware dumps, OEM binaries, credentials,
and extracted proprietary files. Reverse-engineering inputs remain in the parent
`wf830` research tree.

Current crates:

- `gct-hci`: exact GCT HCI framing plus only verified public/recovered opcodes.
- `gct-lapi`: typed clean encoders for proven attach/detach, PDN, PLMN, online/offline and AT request paths.
- `lted-proto`: exact local `lted` framing and the minimum critical SDK command set.

The rule is evidence first: guessed layouts do not enter executable protocol
code. Every recovered constant should be traceable to either upstream GCT/Linux
source or a specific OEM function/disassembly.
