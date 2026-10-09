# RE provenance

This file records why values promoted into the clean Rust implementation are trusted. It is intentionally narrower than the historical WF830 research notes.

## Binary evidence

### B014 reference SDK

- Path: `previous-dumps/bolt-pl100-b014/ubifs-root/lib/libltesdk.so`
- SHA-256: `154fe31d7895a4889a37fd266fdf49cd959b6bc1d0cc06ad5048c280e1a82438`
- Role: symbol-rich reference binary used to recover structure and intent.

### Live Polish P4 SDK

- Path: `our-device/ubifs/files-img-1934699295_vol-rootfs/lib/libltesdk.so`
- SHA-256: `066f592d45338c98e832a1487b669c5ad7147666aa21369d18763284d29676e0`
- Role: compatibility authority for values used by the actual target firmware.

The currently promoted request opcodes are identical in both binaries.

## HCI framing

The public Linux `drivers/staging/gdm724x/hci_packet.h` defines the common packet as two device-endian `u16` fields followed by payload. On GDM7243 the device byte order is big-endian. Rust therefore encodes:

```text
u16 command, big-endian
u16 payload length, big-endian
payload bytes
```

`gct-hci` implements exact-length parsing and allocation-free encoding of this frame.

## Recovered request opcodes

The values below are the constants passed through `H2D()` in the corresponding `LAPI_*` function. Each listed value was independently observed in both the B014 and live P4 `libltesdk.so` binaries.

| Function | Request opcode |
|---|---:|
| `LAPI_AttachRequest` | `0x3101` |
| `LAPI_AttachRequestEXT` | `0x3165` |
| `LAPI_DetachRequest` | `0x3103` |
| `LAPI_PDNConnRequest` | `0x3105` |
| `LAPI_PDNConnRequestEXT` | `0x3167` |
| `LAPI_PDNDisconnRequest` | `0x3107` |
| `LAPI_PLMNSearchRequest` | `0x3109` |
| `LAPI_PLMNListRequest` | `0x310b` |
| `LAPI_OnlineRequest` | `0x3121` |
| `LAPI_OfflineRequest` | `0x3123` |
| `LAPI_PSInitRequest` | `0x312e` |
| `LAPI_ATCommandToDevice` | `0x3307` |
| `LAPI_UICCRequest` | `0x3504` |

## Receive dispatch table

`decode_hci_packet` does a linear lookup through eight-byte entries with layout:

```text
u16 opcode
u16 padding
u32 handler pointer
```

B014 table:

- virtual address: `0x89f6c`
- entries: 96

Live P4 table:

- virtual address: `0x8e704`
- entries: 98

The live table preserves all 96 B014 opcodes in the same order and adds only `0xb15e` and `0xb321`.

The following response identities are proven by request identity plus their presence in both dispatch tables:

| Request | Response |
|---:|---:|
| `0x3101` attach | `0xb102` |
| `0x3165` attach extended | `0xb166` |
| `0x3103` detach | `0xb104` |
| `0x3105` PDN connect | `0xb106` |
| `0x3167` PDN connect extended | `0xb168` |
| `0x3107` PDN disconnect | `0xb108` |
| `0x3109` PLMN search | `0xb10a` |
| `0x310b` PLMN list | `0xb10c` |
| `0x3121` online | `0xb122` |
| `0x3123` offline | `0xb124` |
| `0x312e` PS init | `0xb12f` |
| `0x3504` UICC | `0xb505` |

Do not assign semantic names to other table entries until the handler identity is independently recovered.

## Recovered TLV encoder

The shared B014 helper at virtual address `0x3f2f4` is used by multiple LAPI request builders. Its behavior is:

```text
output[0] = type
output[1] = payload_length
output[2..] = payload
return payload_length + 2
```

It has three conversion paths:

- selector `0`: raw copy
- selector `1`: 16-bit value converted with `H2D()`
- selector `2`: 32-bit value converted with `H4D()`

`gct-hci::TlvWriter` implements those proven semantics without reproducing the OEM helper ABI.

## First clean LAPI codecs

The following request payloads are simple enough to implement exactly from disassembly:

- `Online`, `Offline`, `PSInit`, `PLMNList`: header only, zero-length payload.
- `Detach`: four-byte caller word converted to device order; represented as an opaque `u32` until its internal semantics are proven.
- `ATCommandToDevice`: the OEM ABI supplies `{pointer, length}`; the SDK copies exactly `length` bytes and appends one `0x0a` byte. Rust exposes `&[u8]` and performs the append directly.

No compatibility layer for the historical C ABI is intended.

## Live-only delta discovered during cross-check

The live P4 SDK adds exported functions including `LAPI_DmCtrlRequest`, `LAPI_EMMTimerStartRequest`, `LAPI_ExtDRXParamctrlRequest`, `LAPI_ReadForbiddenTAListRequest`, and `LAPI_SetMTUSize`. `LAPI_DmCtrlRequest` emits request opcode `0x3320`, consistent with live-only dispatch entry `0xb321`. The other live-only dispatch entry `0xb15e` remains intentionally unnamed pending direct handler identification.

## Validation status

As of 2026-10-06 the clean Rust workspace contains:

- `gct-hci`
- `gct-lapi`
- `lted-proto`

All unit tests and strict workspace Clippy checks pass on Rust 1.99.0. Test vectors are small golden frames derived from the public driver or direct OEM disassembly, not captured proprietary payloads.

## Typed normal attach — live P4 authority

DWARF in the B014 `lted` binary reconstructs `_ATTACH_REQ_PARAM` exactly as a 352-byte structure with named members and offsets: `optional_info`, `transaction_id`, APN, PDN/IP allocation modes, username/password/authentication, general/operator PCO, requested APN type, attach/request/emergency modes, `POS_LOC_INFO`, NAS low-priority indication, `PDN_CONNECTION_CTRL_PARAM`, and secure PCO.

A normalized instruction diff against the live P4 `LAPI_AttachRequest` showed the wire layout and TLV sequence are unchanged, but one policy mapping differs. The live P4 requested-APN mapping is therefore authoritative:

- Internet (0) -> 3
- IMS (1) -> 1
- Admin (2) -> 2
- App (3) -> 4
- Emergency (4) -> 0
- Reserved1 (5) -> 6
- Reserved2 (6) -> 0
- Reserved3 (7) -> 0
- NotSet/other -> 0

B014 historically mapped 4/6/7 to 5/7/8; those mappings are deliberately not reproduced.

The normal attach payload begins with the one-byte `optional_info`. If it is zero, the complete payload is that single byte. Otherwise the live SDK emits TLVs in this order: transaction `0x20`, username `0x02`, password `0x03`, APN `0x04`, auth `0x1e`, PDN type `0x05`, IP allocation `0x01`, optional general PCO `0x5c`, optional operator PCO `0x5d`, attach type `0x5f`, request type `0x60`, requested APN mapping `0x70`, emergency mode `0x62`, positioning `0xf5`, low-priority NAS `0xf6`, PDN connection control `0x71`, secure PCO `0xf7`.

`gct-lapi::AttachRequest` now implements this live-P4 behavior directly. It uses borrowed byte slices rather than the historical fixed C arrays, but intentionally caps inputs to the proven safe OEM storage limits. The OEM SDK silently rewrites out-of-range PDN control values; the clean Rust API rejects them instead.

`lted-bridge` now also translates stock SDK command 25 from the exact 352-byte `_ATTACH_REQ_PARAM` IPC payload into that clean request. The bridge uses the DWARF-proven offsets but does not recreate the C struct: APN/username/password are borrowed as bounded NUL-terminated slices, operator PCO length is checked against its 100-byte slot, packed `u16` fields are decoded big-endian, and `optional_info == 0` deliberately ignores all dead trailing legacy bytes. Unterminated fixed strings and impossible lengths fail before GLIF is touched.

This request path has an independent stock-library gate. A tiny BE8 ARMv7 harness, dynamically linked to the unchanged P4 `liblted.so` and OEM uClibc under `qemu-armeb`, called `lted_client_init_ex` followed by `LTED_AttachRequest` against Rust `gctd`. After the normal automatic PSInit→Online startup, the pseudo-GLIF peer received exactly 71 bytes beginning `31 01 00 43` and matching the clean golden frame byte-for-byte; the stock wrapper returned success. This proves request-side command 25 interop through the real library. Callback 26 is now implemented independently: live P4 reverse engineering plus B014 DWARF recover the 2,187-byte `_ATTACH_RSP_INFO` materialization and `cb_rsp[2]` registration slot (function at +0x14, user at +0x18). The Rust bridge parses `0xb102` semantically, reconstructs the legacy byte image, correlates it by transaction ID, and emits stock `0x8107` callback ID 26 only to registered clients. An end-to-end test drives a pending legacy Attach through representative nested and trailing response fields and verifies the 2,199-byte callback frame, representative legacy offsets, pending-request release, and subscription gate.

## Typed PDN requests — live P4 authority

B014 `lted` DWARF reconstructs the request-side C layouts used by the SDK:

- `_PDN_CONNECTIVITY_REQ_PARAM`: 0x1a4 bytes.
- `_PDN_CONNECTIVITY_REQ_EXT_PARAM`: 0xf4 bytes.
- `_PDN_DISCONNECT_REQ_PARAM`: 0x44 bytes.
- `_APN_NI`: one-byte length plus 64 bytes of network identifier storage.
- `_PCO_INFO`: nine bytes: three u8 selectors followed by three u16 protocol IDs.

A normalized instruction diff of `LAPI_PDNConnRequest` shows the same live-P4
policy delta as normal attach: B014's requested-APN mappings for historical
classes 4/6/7 are absent in P4. `ApnType::p4_wire_value()` is therefore shared
by attach and normal PDN connect.

Normal PDN connect (`0x3105`) sends two fixed payload bytes first:
`request_type, optional_info`. It always sends transaction `0x20`, APN `0x04`,
and requested APN type `0x70`. When `optional_info != 0`, the live SDK inserts,
in order: username `0x02`, password `0x03`, PDN type `0x05`, auth `0x1e`, IP
allocation `0x01`, optional general PCO `0x5c`, optional operator PCO `0x5d`,
low-priority NAS `0xf6`, PDN connection control `0x71`, and secure PCO `0xf7`.
The private SDK generated the transaction byte through `tid_list_add()`; the
clean codec accepts an explicit transaction ID from its caller instead.

Extended PDN connect (`0x3167`) is instruction-shape equivalent between B014
and live P4. Its payload begins with `request_type, optional_info`, always sends
APN `0x04`, then when optional data is enabled sends APN class `0x20`, username
`0x02`, password `0x03`, PDN type `0x05`, auth `0x1e`, IP allocation `0x01`,
and the complete nine-byte PCO block as `0x21`. The OEM structure also contains
`req_apn_type`, but the live encoder never serializes it; it is deliberately not
part of the clean wire type.

PDN disconnect (`0x3107`) sends `default_eps_id` as a big-endian u16, transaction
TLV `0x20`, then a message-specific `0x57, len, apn_ni...` field. That final APN
field does not go through the shared SDK TLV helper. The clean codec caps it at
the recovered 64-byte `APN_NI` capacity.

`gct-lapi` now has typed encoders for normal connect, extended connect and
disconnect, with golden tests for minimal/optional paths, PCO endianness, live
APN mapping and recovered size limits.

## Core response-side prefixes

The B014 `decode_hci_packet` dispatch targets and the symbol-rich `lted` DWARF
provide both modem-wire parser behavior and callback-structure field names.
The clean implementation models only bytes proven to arrive from the modem;
it does not mirror the much larger callback structures populated by SDK state.

- Online (`0xb122`), Offline (`0xb124`) and PS Init (`0xb12f`) each carry one
  four-byte device-endian `u32 result` and no additional wire fields.
- Detach (`0xb104`) is exactly eight bytes: `u32 result`, then two device-endian
  `u16` deregistration causes. This matches `_DETACH_RSP_INFO` exactly.
- Normal attach (`0xb102`) and extended attach (`0xb166`) share the same first
  15 wire bytes despite different callback-structure layouts: two registration
  result u16s, default EPS ID u16, EPS ID u16, `data_path`, `ip_alloc`, then the
  five one-byte `NET_FEATURE_INFO` fields (`ims_voice_over_ps`, `emc_bc`,
  `epc_lcs`, `sc_lcs`, `ext_sr`). Parser-managed fields follow byte 15.
- Normal PDN connect (`0xb106`) has a ten-byte fixed prefix: result/reject1/
  reject2/default-EPS-ID as four u16 values, then `data_path` and `ip_alloc`.
- Extended PDN connect (`0xb168`) adds a device-endian u16 throttle-time value
  after that common ten-byte prefix, for twelve fixed bytes total.
- PDN disconnect (`0xb108`) starts with four device-endian u16 values: result,
  reject cause 1, reject cause 2 and default EPS ID. Optional fields follow.

`gct-hci::TlvCursor` now decodes the shared borrowed `[type,len,payload...]`
format with strict truncation checks. `gct-lapi` exposes bounded response parsers
for every fixed prefix above and leaves the parser-managed suffix borrowed until
its nested grammar is independently proven.

## Nested ATTACH/PDN response information

The PIC table used by the inner nested parser resolves to B014 VA `0x89c54`.
It contains 23 first-match entries. Correlating each handler's destination offset
with B014 `PDN`/`LTE_QOS` DWARF gives the effective wire mapping:

- `0x04`: APN (`PDN.ap_name`, max recovered destination 128 bytes)
- `0x05`: PDN type (u8)
- `0x06`: PDN type cause (device-endian u32)
- `0x07`: IPv4 address
- `0x08`, `0x09`: primary/secondary IPv4 DNS
- `0x0a`, `0x0b`: primary/secondary IPv6 DNS
- `0x0c`: IPv6 interface ID (8 bytes)
- `0x0d..0x11`: P-CSCF IPv6 addresses 1..5
- `0x1f`, `0x21`, `0x22`: P-CSCF IPv4 addresses 1..3
- `0x40..0x44`: QCI, max UL, max DL, guaranteed UL, guaranteed DL as
  five device-endian u32 values in `LTE_QOS`.

The table then contains a second `0x22` entry whose handler writes `PDN.opspec_len`
and `PDN.opspec`. The dispatcher returns after the first matching type, so this
second `0x22` handler is unreachable in the OEM implementation. The clean parser
records the effective first-match behavior (`0x22` = P-CSCF IPv4 #3) rather than
inventing a corrected opcode for the dead handler.

The enclosing nested parser accepts at most two contiguous outer containers,
each tagged `0xf0` or `0xf2`, and runs the same inner dispatch table over their
payloads. It stops before the first non-container field. `gct-lapi` now exposes
this as borrowed `PdnInfoContainers` plus semantic `PdnInfoField` values, with
strict fixed-length validation and unknown inner TLVs preserved as raw data.

## Full PDN response grammar — live P4 confirmed

The current P4 handlers preserve the same response-parser shape as B014. The
live binary uses normal-PDN handler `0xbf10`, extended-PDN handler `0xc700`, and
PDN-disconnect handler `0xcb9c`; their B014 counterparts are `0xbd60`, `0xc550`,
and `0xc9ec`. Helper addresses shift, but the call sequence, fixed prefixes and
descriptor tags used below are unchanged. P4 therefore remains the authority,
while B014 DWARF supplies names for the historical callback destinations.

Normal PDN connect (`0xb106`) is:

1. ten-byte fixed prefix (`result`, two reject causes, default EPS ID,
   `data_path`, `ip_alloc`);
2. mandatory transaction TLV `0x20`, whose payload is one byte;
3. one fixed-order APN-NI TLV copied into the 65-byte `APN_NI` destination
   (one length byte + at most 64 APN bytes). The OEM helper does not validate
   this TLV's tag, so the clean parser preserves the observed tag rather than
   inventing a stronger contract;
4. up to two contiguous `0xf0`/`0xf2` nested PDN-info containers;
5. a descriptor-driven TLV suffix with `0x5b` = IPv4 link MTU (device-endian
   u16), `0x5d` = operator PCO (at most 100 payload bytes), `0xf0` = an
   additional inner-PDN-info chunk, and `0xf3` = APN-AMBR (UL and DL as two
   device-endian u32 values). Unknown suffix TLVs are skipped by the OEM and
   preserved by the Rust cursor.

An earlier ad-hoc reading suggested an unexplained eight-byte gap between the
APN and nested parser. That was false: the local variable at `r11-8` is a count
of bytes consumed *after* the ten-byte fixed prefix. The subsequent `+8` and
`+2` address arithmetic reconstructs that same `+10` base. There are no opaque
eight wire bytes in this path.

Extended PDN connect (`0xb168`) is twelve fixed bytes, followed by three
fixed-order TLVs copied into `apn_class`, requested APN-NI and received APN-NI,
then the same at-most-two nested `0xf0`/`0xf2` parser. The fixed-order helpers do
not validate the three TLV tags. `apn_class` is a one-byte destination; each APN
has the same 64-byte payload bound. The OEM ignores the nested parser's return
value and therefore ignores any bytes after those initial containers. The clean
Rust representation deliberately exposes that remainder as `unparsed_suffix`
instead of silently dropping it.

PDN disconnect (`0xb108`) is an eight-byte fixed prefix, mandatory transaction
TLV `0x20`, then a descriptor-driven suffix: `0x57` = APN-NI (max 64 bytes),
`0x5d` = operator PCO (max 100 bytes), and unknown TLVs are skipped/preserved.

`gct-lapi` now implements these complete layouts with allocation-free borrowed
views. It is intentionally stricter than the old C on malformed input: exact
one-byte transaction/apn-class fields, exact MTU/AMBR widths, APN/PCO destination
bounds, truncation errors, and preservation of unknown or OEM-ignored bytes.

### Stock normal-PDN bridge ABI

`lted-bridge` now carries the normal PDN-connect path through the unchanged stock
SDK ABI as well as the clean modem wire codec. Stock SDK command 32 supplies the
exact 420-byte `_PDN_CONNECTIVITY_REQ_PARAM` image recovered from B014 DWARF.
The bridge decodes only fields the live P4 `LAPI_PDNConnRequest` actually
consumes, rejects malformed fixed strings and PCO lengths before touching GLIF,
and deliberately ignores the historical `transaction_id@0x1a3`: live P4 calls
`tid_list_add()` and allocates the first free transaction ID in `1..=253`, so
the Rust bridge does the same against its pending-request ledger.

The reverse path is callback 33 (`PDNConn`). B014 DWARF gives the exact
742-byte `_PDN_CONNECTIVITY_RSP_INFO` image: transaction ID at `0x00a`,
65-byte APN-NI at `0x00b`, `PDN` at `0x04c`, IPv4 link MTU at `0x276`,
operator PCO at `0x278`, and APN-AMBR at `0x2de`. Live P4 callback dispatch
uses `cb_rsp[6]`; in the recovered shared client context that is registration
offset `0x34`. The bridge parses modem response `0xb106` semantically,
re-materializes this packed legacy image, correlates by transaction ID, and
emits callback 33 only to clients registered in that slot.

The end-to-end bridge tests cover first-free TID allocation, exact `0x3105`
wire bytes, malformed legacy input rejected before modem I/O, complete callback
materialization across initial and trailing PDN fields, subscription gating,
and pending-request release. The workspace gate is Rust 1.99
`cargo test --workspace` plus strict all-target Clippy with warnings denied.

### Stock extended-PDN bridge ABI

Extended PDN connect now crosses the stock ABI independently of the normal
transaction-ID path. Live P4 `liblted.so::LTED_PDNConnRequestEXT` at `0xaf90`
constructs SDK command **34** and copies **exactly 244 bytes** from the caller.
B014 DWARF fixes that `_PDN_CONNECTIVITY_REQ_EXT_PARAM` layout: `request_type@0`,
`optional_info@1`, 100-byte APN at `2`, `ip_alloc@102`, `apn_class@103`,
`pdn_type@104`, 64-byte username/password at `105/169`, `auth_flag@233`,
nine-byte `PCO_INFO@234`, and `req_apn_type@243`. The last byte is SDK-local
bookkeeping and never reaches HCI `0x3167`. The clean decoder preserves the live
encoder's asymmetric rule that APN is always serialized, while username,
password and the remaining optional fields are dead when `optional_info == 0`.
Unterminated fixed strings that would actually be consumed are rejected before
GLIF I/O.

The reverse path is live-P4 callback **35**. `ind_pdn_conectivity_response_extension`
at `0x21a9c` passes selector 35 directly to the stock callback assembler, and
`lted_sdk_recv_cb_handler` maps that selector to `cb_rsp[7]`, registration
offset `0x3c`. B014 DWARF fixes `_PDN_CONNECTIVITY_RSP_EXT_INFO` at exactly
**697 bytes**: result/reject/default-EPS fields at `0..8`, data path/IP allocation
at `8/9`, throttle time at `10`, APN class at `12`, requested/received 65-byte
APN-NI objects at `13/78`, and the shared 554-byte `ATTACH_PDN_RSP_INFO` at
`143`. The bridge reuses the proven PDN/QoS materializer at that exact base and
intentionally ignores the modem suffix that live P4 also leaves unparsed.

End-to-end bridge tests cover exact 40-byte `0x3167` output from the 244-byte
stock object, malformed input rejection before GLIF, the `optional_info == 0`
APN-only rule, exact 697-byte callback materialization, callback-35 subscription
gating, family-level pending correlation/release, and the recovered `cb_rsp[7]`
slot.

Normal PDN disconnect now crosses the stock ABI as well. B014 DWARF gives a
68-byte in-process `_PDN_DISCONNECT_REQ_PARAM`
(`default_eps_id:u16@0`, `transaction_id:u8@2`, APN-NI object at `0x03`), but
live P4 `LTED_PDNDisconnRequest` does **not** copy all 68 bytes into SDK command
36. Its wrapper reads the APN-NI length byte, sizes the local SDK envelope from
that value, and copies exactly `4 + apn_len` request bytes. The bridge therefore
accepts that exact variable local payload (maximum 68 bytes), rejects truncated
or inconsistent lengths, ignores the historical transaction byte, and mirrors
live `LAPI_PDNDisconnRequest` by allocating a fresh TID before encoding
`0x3107`.

The reverse path on the target P4 firmware is callback 37 (`PDNDisconn`).
B014 DWARF fixes `_PDN_DISCONNECT_RSP_INFO` at 176 bytes: result/reject causes/default EPS ID at
`0x000..0x008`, transaction ID at `0x008`, 65-byte APN-NI at `0x009`, and
102-byte operator PCO at `0x04a`. Live P4 `ind_pdn_disconnect_response` directly passes callback ID 37 to
`lted_srv_send_sdk_cb_assemble_hci`, and its callback jump table maps ID 37 to
`cb_rsp[8]`, registration offset `0x44`. The older B014 daemon passes 36 here;
this is a firmware-generation selector delta, so the live P4 value is the
compatibility contract. Rust parses `0xb108`, correlates by the fresh transaction ID,
re-materializes the 176-byte legacy response, and broadcasts only to clients
registered in that slot. End-to-end tests cover exact `0x3107` bytes,
variable-length local request validation, callback materialization,
subscription gating, and pending release.

### Stock normal-Detach bridge ABI

Normal Detach is exact on both sides of the stock boundary. B014 DWARF fixes
`_DETACH_REQ_PARAM` at four bytes with the single `detach_type:u32` field, and
live P4 `LTED_DetachRequest` copies exactly those four caller bytes into local
SDK command 29. Live `LAPI_DetachRequest` converts that word with `H4D()` and
sends it unchanged as the complete four-byte payload of HCI `0x3103`. The Rust
bridge therefore requires exactly four local request bytes and preserves the
word without inventing semantic subfields.

Live `LAPI_DetachRequest` also calls `tid_list_clean()` before the modem write.
That list is populated by normal PDN-connect/disconnect TID allocation. The
bridge mirrors the successful-call effect by retiring pending PDN transaction
keys after the Detach write succeeds, while retaining the new family-level
`ResponseKey::Detach` until its response arrives. This intentionally avoids
losing tracked state on a failed write while preserving the observable
post-success state.

B014 DWARF fixes `_DETACH_RSP_INFO` at exactly eight bytes:
`result:u32@0`, `deregister_cause1:u16@4`, and `deregister_cause2:u16@6`.
Live P4 `ind_detach_response` passes callback ID 30 to the stock callback
assembler; the live callback jump table maps ID 30 to `cb_rsp[4]`, registration
offset `0x24`. Rust parses exact modem response `0xb104`, releases the pending
Detach family, materializes those eight bytes, and emits stock `0x8107`
callback 30 only to clients registered in that slot. Tests cover exact request
bytes, malformed local length rejection before modem I/O, PDN-TID cleanup,
callback materialization, subscription gating, and pending release.

### Stock PLMN-search bridge ABI

Stock PLMN Search now crosses the local compatibility boundary without copying
unrelated legacy state. Live P4 `LTED_PLMNSearchRequest` allocates a local SDK
command-40 frame and copies exactly nine caller parameter bytes. Those bytes are
the B014-DWARF `_PLMN_SEARCH_REQ_PARAM`: `search_mode@0`, MCC digits at `1..4`,
MNC digits at `4..7`, `emergency_mode@7`, and `roaming_option@8`. The bridge
requires exactly that nine-byte payload and feeds the existing typed
`PlmnSearchRequest`, which produces the independently proven `0x3109` wire
shape.

The target P4 `ind_plmn_search_response` sends a fixed 436-byte legacy response
through callback ID 41. The live callback jump table maps 41 to `cb_rsp[9]`,
registration offset `0x4c`. B014 DWARF fixes `_PLMN_SEARCH_RSP_INFO` at 436
bytes: the 27-byte fixed metadata prefix is followed by `num_plmn_info:u32` at
`0x01b`, up to 32 packed 11-byte PLMN records at `0x01f`, `plmn_priority:u32` at
`0x17f`, and the 49-byte SIB1 PLMN list at `0x183` (`count` plus 48 bytes).
Rust parses modem `0xb10a` semantically, reconstructs this fixed legacy image,
releases the tracked PLMN-search family, and emits stock callback 41 only to
clients registered in that slot. Tests cover the exact command-40-to-`0x3109`
translation, malformed local length before modem I/O, all recovered callback
regions, subscription gating, and pending release.

### Stock PLMN-search-stop bridge ABI

PLMN Search Stop is another exact small compatibility family. Live P4
`LTED_PLMNSearchStopRequest` sends SDK command 63 with exactly one parameter
byte. `LAPI_PLMNSearchStopRequest` copies that byte unchanged as `search_type`
into the one-byte payload of HCI `0x3127`; the existing typed codec already
tracks the response by that search type.

B014 DWARF fixes `_PLMN_SEARCH_STOP_RSP_INFO` at five bytes:
`search_type:u8@0 | result:u32@1`. Live P4 `ind_plmn_search_stop_response`
sends those exact five bytes through callback ID 64. The live callback lookup
maps ID 64 to `cb_rsp[20]`, registration offset `0xa4`. Rust now requires the
exact one-byte local request, tracks `ResponseKey::PlmnSearchStop(search_type)`,
parses modem `0xb128`, reconstructs the fixed response image, and broadcasts
callback 64 only to clients registered in that slot. Tests cover exact local and
modem wire bytes, malformed request length before I/O, callback materialization,
subscription gating, search-type correlation, and pending release.

## Shared EMM control — timer control, NI reattach, and live widened callbacks

This family is heavily used by the shipping P4 userspace: recovered LTE clients
import both `LTED_EMMtimerCtrlRequest` and `LTED_EMMNIREATTACHctrlRequest` seven
times each. Live `liblted.so` fixes the local stock request IDs and lengths:

- **207** (`LTED_EMMtimerCtrlRequest`): exactly four caller bytes.
- **211** (`LTED_EMMNIREATTACHctrlRequest`): exactly four caller bytes.

B014 DWARF independently fixes the four-byte timer object as
`timerID:u16 @0 | timerValUnit:u8 @2 | timerVal:u8 @3`; the NI-reattach request is
a single four-byte control value. The live SDK serializes both through shared
HCI command **`0x3155`** with an eight-byte payload:

- timer control: `00 07 00 04 <timer_id:u16> <unit:u8> <value:u8>`;
- NI reattach: `00 0b 00 04 <control:u32>`.

The live SDK receive dispatch table at `0x8e704` maps **`0xb156`** to handler
`0x3319c` and **`0xb164`** to handler `0x33898`. The handler calling convention is
independently calibrated against the known `0xb14f` UE-mode path: `r1` points at
the HCI payload. Both EMM handlers therefore expose the same recovered envelope
`prefix:u16 @0 | kind:u16 @2 | value_len:u16 @4 | value @6`.

For solicited **`0xb156`**, the live switch handles kind **11** by calling
`0x32fc8`, which looks up SDK callback **159**, reads/converts four bytes from
payload offset 6, and materializes a four-byte callback object. Kind **7**
(timer control) falls through the SDK's unsupported/default branch. Rust therefore
sends timer control **untracked** and deliberately treats a kind-7 acknowledgement
as unknown instead of inventing a stock callback.

For unsolicited **`0xb164`**, kind **11** calls `0x33678`, which looks up SDK
callback **160** and materializes a six-byte object: the converted first envelope
word plus the converted four-byte value. The friendly semantics of those widened
live fields are not proven, so Rust preserves them as raw `prefix:u16` and
`value:u32` instead of reusing B014's obsolete one-byte field names.

This is another large firmware-generation ABI delta. Older B014 DWARF describes
the NI response and reattach report as one byte each, but live P4 widens them and
uses very different stock callback selectors. Live `lted::ind_regist` proves the
bindings directly:

- SDK callback **159** -> `ind_emm_nireattach_response` at `0x38114`;
- SDK callback **160** -> `ind_emm_reattach_ctrl_rpt_indication` at `0x3343c`.

Those live daemon handlers emit stock callback selectors **308 (`0x134`)** and
**309 (`0x135`)**, carrying four and six bytes respectively. Live `liblted.so`
then resolves selector 308 to **`cb_rsp[159]` at registration offset `0x4fc`**
(user pointer `0x500`) and selector 309 to **`cb_rsp[160]` at `0x504`** (user
pointer `0x508`). Earlier one-byte / 212-ish interpretations are explicitly
superseded by this direct live-P4 evidence.

Rust mirrors the live behavior conservatively: timer-control is request-only;
NI reattach is a single family-level tracked request; the NI response retires its
pending key even when no client is subscribed; and the six-byte reattach report
is unsolicited. Tests lock exact local->HCI bytes, strict shared-envelope length
validation, duplicate NI request rejection, malformed local requests before GLIF,
callback-308 subscription gating, and exact unsolicited callback-309 bytes.

## UE mode change — live P4 command/response and callback-generation delta

This is a high-value live-client path: eight recovered P4 LTE binaries import
`LTED_UeModeChangeRequest`. Live `liblted.so` proves stock SDK command **161**
and copies exactly one caller byte. B014 DWARF independently describes
`_UE_MODE_CHANGE_REQ_PARAM` as exactly one byte, `mode:u8`.

Live `LAPI_UeModeChangeRequest` emits HCI request **`0x3118`** with that byte
unchanged. The live SDK receive table maps **`0xb14f`** to handler `0x2628c`.
That handler requires registered SDK callback **82**, converts exactly one payload
byte, and forwards it to the registered callback. B014 DWARF independently fixes
`_UE_MODE_CHANGE_RSP_INFO` at one byte with sole field `result:u8`.

The stock callback number is another firmware-generation trap. B014
`ind_ue_mode_change_response` emits callback **167**, but the live P4 function at
`0x2fd70` emits callback **162**. Live `lted::ind_regist` registers SDK callback
82 directly to that function. In live `liblted.so`, selector 162 lands at the
callback-dispatch case using `cb_rsp[82]`, whose function/user fields begin at
**`0x294` / `0x298`**. Rust therefore uses live callback **162** and registration
offset **`0x294`**, not the older B014 selector.

Rust models this as a family-level tracked exchange because neither request nor
response carries a transaction identity. Tests lock the exact five-byte request
frame, exact one-byte `0xb14f` response, duplicate-in-flight rejection, stock
command-161 parameter validation before GLIF, and callback-162 materialization
and subscription gating.

## PLMN Search EXT — live P4 request path and response-wiring anomaly

Live P4 `LTED_PLMNSearchExtRequest` uses stock SDK command **42** and copies the
full **1,292-byte** `_PLMN_SEARCH_EXT_REQ_PARAM` into the daemon request. B014
DWARF fixes the object layout as `selection_mode@0`, `operation_mode@1`,
`MCC[3]@2`, `MNC[3]@5`, `roaming_option@8`, `list_num@9`, `list_len@10`,
`list_data[255]@11`, `reserved[1020]@266`, `fastScanOption@1286`, `eci[4]@1287`,
and `pwrScanOption@1291`.

Live `LAPI_PLMNSearchExtRequest` emits HCI **`0x315a`**. The 1,292-byte legacy
container is not copied wholesale: the modem payload begins with selection and
operation mode, then uses compact tags. Selection modes 0/2 emit `0x63 |
roaming_option`; other modes emit `0x64 | packed_plmn[3]`. A non-empty scan list
is `0x65 | list_len | list_data`; list elements are `type:u8 | count:u8 | data`
with proven types 2 = EARFCN list, 3 = band-byte list, 4 = EARFCN start/end
pairs. Every shipped P4 operator profile sets `<earfcn_ext>1</earfcn_ext>`, so
types 2/4 use the 32-bit EARFCN representation unchanged. `fastScanOption`, ECI
and the 1,020 reserved bytes are not read by the live serializer.
`pwrScanOption == 1` appends `0x66 | 1`. Rust validates that the declared element
count exactly consumes the bounded `list_len` region before touching GLIF.

The response side has a vendor-generation anomaly that must not be normalized by
guesswork. `libltesdk.so` contains a distinct **`0xb15b`** EXT-response decoder
and an internal response slot 10 / historical callback 43 path, but live P4
`lted::ind_regist` never registers SDK slot 10, and every recovered connection
manager subscribes to normal PLMN-search response slot 9 instead.
`LAPI_RegisterCallbackResponse` stores callback IDs verbatim, so there is no
hidden alias. With no recovered packet capture proving `0xb15b` is used by the
shipping product, Rust keeps `0xb15b` explicitly **dormant/unhandled** and gives
command 42 the same conservative `ResponseKey::PlmnSearch` as command 40. The
live product's executable completion path is therefore the already-proven
`0xb10a` -> stock callback **41 / `cb_rsp[9]`** path. Tests lock both decisions:
exact `0x315a` request bytes and dead-field behavior, malformed-list rejection
before GLIF, normal/EXT family collision, callback-41 completion, and continued
`Unknown` treatment of dormant `0xb15b`.

## PLMN search/list wire grammar — live P4 confirmed

B014 DWARF names `_PLMN_SEARCH_REQ_PARAM` as a nine-byte host structure
(`search_mode`, three MCC digits, three MNC digits, `emergency_mode`,
`roaming_option`), but `LAPI_PLMNSearchRequest` does not transmit that structure
raw. B014 `0x436a8` and live P4 `0x46a1c` have the same encoder:

- payload byte 0 is `search_mode`;
- mode 0 emits wildcard PLMN bytes `ff ff ff`;
- other modes pack the digit nibbles as `(mcc[1]<<4)|mcc[0]`,
  `(mnc[2]<<4)|mcc[2]`, `(mnc[1]<<4)|mnc[0]`;
- TLV `0x62` carries the one-byte emergency mode;
- TLV `0x63` carries the one-byte roaming option.

The resulting payload is ten bytes. `PLMNListRequest` (`0x310b`) remains an
empty/header-only request.

The response dispatch table maps `0xb10a` to B014 `0xf664` / P4 `0xfa88`, and
`0xb10c` to B014 `0x1055c` / P4 `0x10980`. P4 preserves the same parser shape:
search subtracts/adds a fixed 27-byte prefix, while list skips exactly one
leading byte before calling the common record parser.

PLMN-search response `0xb10a` has this fixed wire prefix:

- `result: u32` at 0;
- `selection_mode: u8` at 4;
- selected PLMN ID `[u8;3]` at 5;
- `next_index: u16` at 8;
- `network_interval: u16` at 10;
- signed `remaining_count: i8` at 12;
- `band: u16` at 13;
- `cell_id: u16` at 15;
- `frequency: u32` at 17;
- TAC `[u8;2]` at 21;
- 28-bit-style cell ID stored as `u32` at 23.

On successful search (`result == 0`) the OEM optionally consumes, in order,
TLV `0x13` into the callback's standalone PLMN-priority word and TLV `0x26`
into its 49-byte SIB1 PLMN-list destination. The `0x26` helper clamps lengths
above 49 by modifying the incoming TLV length byte; the clean parser rejects
such input instead. Remaining bytes are the shared PLMN-record stream.

A wire PLMN record is *not* the eleven-byte `PLMN_INFO` callback structure.
Helper table `0x89d2c` (B014) proves that one semantic record is assembled from
three TLVs:

- `0x12`: three-byte PLMN ID;
- `0x13`: BE `u32` priority;
- `0x14`: BE `u32` status.

The old parser accepts those three tags in arbitrary order, increments the
record destination only after three recognized fields, and allocates room for
32 records. `PlmnInfoCursor` preserves order-independence for valid records but
requires exactly one of each field, rejects unknown/duplicate/mis-sized TLVs,
and enforces the recovered 32-record bound.

PLMN-list response `0xb10c` is simply one `search_complete` byte followed by
that same record stream. The SDK-computed `num_plmn_info` words present in the
DWARF callback structs are not wire fields and are intentionally absent from
the Rust representation.

## UICC common framing and SIM/PIN bring-up — live P4 confirmed

`LAPI_UICCRequest` is a fifteen-way subtype switch (`0..14`) in both B014 and
live P4. The common request wire envelope is HCI `0x3504` followed by BE
`type: u16`, BE `len: u16`, then subtype data. This is not exposed as an
unrestricted raw public request encoder because several file-operation subtypes
perform additional field-specific endian conversion after the common copy.

The recovered control subtype values are: 0 status, 1 read binary, 2 read
record, 3 update binary, 4 update record, 5 authenticate, 6 PIN command, 7 PIN
status, 8 remote command, 9 PIN required, 10 refresh (the B014 headers also
contain the typo `REPRESH`), 11 USAT terminal profile, 12 USAT envelope, 13
USAT terminal response, and 14 poll-interval timer.

Status (`type 0`) has a one-byte request payload `apptype`. This is independently
confirmed by `lted`'s `make_uicc_control_req_param`: its type-0 branch requires
one input byte and writes outer `len = 1`. PIN status (`type 7`) always writes
outer `len = 0`.

PIN command (`type 6`) carries exactly twenty raw bytes after the common UICC
envelope. B014 DWARF names them as `pin_type`, `pin_cmd`, then two `PIN_DATA`
objects. Each `PIN_DATA` is one length byte plus an eight-byte fixed-capacity
code buffer. The SDK copies these twenty bytes without endian fixups. The Rust
encoder zero-pads the fixed buffers and rejects codes longer than eight bytes.
The available DWARF does not give a trustworthy value-domain enum for
`pin_type` or `pin_cmd`, so those remain explicit recovered wire values rather
than receiving guessed public names.

UICC response HCI opcode is `0xb505`. The outer wire order is BE `result: u16`,
BE `type: u16`, BE `len: u16`, then `data[len]`. This differs from the historical
`_UICC_INFO_RSP` callback-memory order in DWARF (`result`, `len`, `type`,
`data`). Both B014 parser `0x20178` and live P4 parser `0x20f44` explicitly read
wire bytes 4..5 into callback offset 2 and wire bytes 2..3 into callback offset
4, proving the reshuffle. The clean `UiccResponse` keeps wire semantics and
requires the embedded UICC length to equal the actual remaining HCI payload.

For successful (`result == 0`) subtypes used during normal bring-up, both SDK
versions copy the subtype data raw:

- status response (`type 0`) is two bytes: `uicc_status`, `apptype`;
- PIN-command response (`type 6`) is five bytes: `uicc_ret`, `umm_pin_type`,
  `umm_pin_cmd`, PIN retry count, PUK retry count;
- PIN-status response (`type 7`) is eleven bytes: `uicc_ret`, `global_pin`, then
  three `PIN_STATUS` triplets (application, universal, local), each
  `{status, pin_retries, puk_retries}`.

Typed Rust response parsers reject outer nonzero results before interpreting
subtype data, reject the wrong subtype, and require the exact recovered DWARF
payload width.

## UICC READ BINARY / READ RECORD — live P4 confirmed

B014 DWARF describes `_UICC_READ_BINARY_REQ` as exactly nine bytes:
`app_type:u8`, `fid:u32`, `offset:u16`, `len:u16`. `_UICC_READ_RECORD_REQ` is
exactly six bytes: `app_type:u8`, `fid:u32`, `record_idx:u8`. Both B014
`LAPI_UICCRequest` and live P4 perform host-to-device conversion on the multi-
byte fields before transmitting them inside the common UICC request envelope.
The clean encoders therefore emit BE `fid`, BE binary offset and BE binary
length directly, without materializing the historical packed structs.

Successful READ BINARY response (`type 1`) is a ten-byte fixed subtype prefix
followed by file data. B014 DWARF names the prefix fields as `uicc_ret`,
`app_type`, `fid:u32`, `sw1`, `sw2`, `len:u16`; the response helper converts
`fid` and `len` from device order. The Rust view borrows `data` and requires the
BE embedded `len` at offset 8 to equal the actual remaining subtype bytes.
This replaces the OEM callback's fixed 2028-byte data array.

Successful READ RECORD response (`type 2`) is an eleven-byte fixed subtype
prefix followed by record bytes: `uicc_ret`, `app_type`, `fid:u32`, `sw1`,
`sw2`, `record_idx`, `len:u8`, `record_num:u8`, then `data`. Only `fid` needs
endian conversion. Live P4 `ind_uicc_from_device` proves the length semantics:
when `record_idx == 0` it sizes the legacy response as `11 + len * record_num`;
for a specific record it uses `11 + len`. The live SDK zeroes a full 2048-byte
callback scratch buffer before copying the modem's declared UICC payload, so
legacy callback padding is deterministic zero rather than uninitialized data.
The old debug printer only dumps one `len` chunk and is therefore not a valid
description of the all-records payload grammar.

Both response types remain allocation-free borrowed views and reject truncated
fixed prefixes or disagreement between their embedded length and the common
UICC envelope payload.

## UICC AUTHENTICATE — live P4 confirmed

B014 DWARF names `_UICC_AUTHENTICATE_REQ` as a fixed 36-byte subtype object:
`app_type`, `rand_len`, a 16-byte RAND slot, `auth_len`, a 16-byte AUTH slot,
and `gsm_auth_sel`. `lted`'s request builder bounds each hex input to 16 bytes.
Both B014 and live P4 `LAPI_UICCRequest` type-5 branches copy those 36 bytes
raw after writing the common UICC envelope; there are no subtype endian fixups.
The Rust encoder accepts borrowed RAND/AUTH slices up to 16 bytes, writes their
one-byte lengths, and zero-fills unused fixed-slot bytes.

The type-5 response branch is likewise a raw copy in B014 and live P4. B014
DWARF gives the fixed 86-byte subtype layout: `uicc_ret`, `app_type`,
`auth_ret`, then length + fixed-capacity slots for RES(16), CK(16), IK(16),
AUTS(16), SRES(4), Kc(8), followed by `result_gsm_auth`. The clean parser
requires the recovered 86-byte outer subtype size but exposes each result as a
borrowed slice trimmed to its embedded length. Embedded lengths larger than the
corresponding historical slot are rejected rather than allowing the OEM-style
consumer to observe out-of-bounds logical data.

### Stock command 147 / callback 148 UICC bridge

The stock daemon boundary is independently recovered and is intentionally not
modeled as the historical pointer-bearing subtype structs. Live P4
`liblted.so::LTED_UICCRequest` reads the 16-bit length at caller bytes 2..3 and
copies exactly `4 + len` bytes into SDK command **147**. The local parameter
image is therefore the variable envelope `type:u16 | len:u16 | data[len]`.
The bridge accepts only the six already-proven modem subtypes used by the clean
runtime: status (0), read binary (1), read record (2), authenticate (5), PIN
command (6), and PIN status (7). Unsafe fixed C shapes are required at their
recovered widths before GLIF is touched. Type 7 deliberately ignores any local
data because live `LAPI_UICCRequest` forcibly emits a zero-length modem subtype.

AUTHENTICATE and PIN COMMAND deserve a special compatibility path: live P4
copies their complete fixed 36-byte and 20-byte subtype objects raw, including
otherwise-dead fixed-slot padding. `gct-lapi::UiccFixedRequest` therefore has
only two constrained constructors for those exact widths and preserves every
input byte. This avoids silently changing stock-observable padding while still
refusing an unrestricted raw-UICC API. Status/read-binary/read-record continue
through semantic typed encoders because their multi-byte fields have proven
host/device conversion rules.

Live P4 `ind_uicc_from_device` emits stock callback **148**. The unchanged stock
client dispatches selector 148 directly through `cb_rsp[71]`, function offset
`0x23c` (user at `0x240`). The local callback object is not in modem wire order:
the live SDK explicitly reshuffles `0xb505` from wire
`result:u16 | type:u16 | len:u16 | data` into historical
`result:u16 | len:u16 | type:u16 | data` before invoking `lted`.

The SDK response path allocates and zeroes a full 2048-byte scratch object before
parsing. The daemon then exposes subtype-specific legacy sizes: failed responses
carry only the six-byte historical prefix; STATUS adds 2 bytes; READ BINARY
always adds the complete 2038-byte `_UICC_READ_BINARY_RSP` (therefore unused
array tail is deterministic zero); READ RECORD adds `11 + len * record_num`
bytes for `record_idx == 0` and `11 + len` otherwise; AUTHENTICATE adds 86;
PIN COMMAND 5; PIN STATUS 11. The Rust bridge reproduces those exact callback
sizes and prefix order, validates bounded subtype fields before broadcast, and
releases the subtype-specific pending key only after successful materialization.
Malformed callback data leaves the request reserved instead of losing
correlation state.

## Mobile ID read — shared read-info HCI family, live P4 confirmed

This path is stock-client relevant rather than a debug-only curiosity: the live
P4 connection managers (`sprint_cm`, `smartfren`, `lteautocm`, and `cmcc_cm`)
all import `LTED_MobileIDReadRequest`.

The unchanged live P4 `liblted.so::LTED_MobileIDReadRequest` at `0xcf08`
constructs SDK command **76** and copies exactly one caller byte,
`mobile_id_type`, into its local request envelope. B014 DWARF independently
names `_MOBILE_ID_READ_REQ_PARAM` as a one-byte object containing only that
field.

Live P4 `libltesdk.so::LAPI_MobileIDReadRequest` at `0x4ab04` proves that this
stock call uses the shared HCI read-info request opcode **`0x3145`**. It
allocates a nine-byte frame, converts payload length 5 with `H2D`, writes two
SDK-generated `u16` values both equal to 1, then appends the caller's
`mobile_id_type`. The exact request is therefore:

`31 45 00 05 00 01 00 01 <mobile_id_type>`.

Adjacent stock APIs such as ICCID and MSISDN use the same opcode with different
subtype words, so Rust names the wire family `MISC_READ` rather than pretending
`0x3145` is Mobile-ID-specific.

The live SDK `decode_hci_packet` dispatch table maps response opcode **`0xb146`**
to the shared read-info parser at `0x16ee0`. A successful response begins with
`read_result:u16 == 0` and then contains chunks
`subtype:u16 | len:u16 | body[len]`. Subtype **1** dispatches to the Mobile-ID
handler at `0x16124`. That handler uses SDK callback slot **26**, zeroes the
exact 21-byte historical object, converts the top-level `read_result`, then
materializes `id_type:u8 | result:u8 | len:u8 | id[16]`. It refuses a chunk
whose payload beyond the three-byte prefix exceeds the historical 16-byte ID
slot. A nonzero top-level `read_result` exits the shared parser before any
subtype callback is invoked, so there is deliberately no stock Mobile-ID
callback on that failure path.

Live P4 `lted::ind_mobile_id_read_response` at `0x284f4` receives that 21-byte
SDK object. On success it sends stock callback selector **77** with exactly
`5 + len` bytes: `read_result:u16 | id_type:u8 | result:u8 | len:u8 | id[len]`.
The unchanged live `liblted.so` selector switch maps callback 77 to case
`0x6400`, which loads function pointer offset `0xd4` and user pointer offset
`0xd8`: **`cb_rsp[26]`**. Thus the stock registration offset is exactly `0xd4`.

The clean runtime models `0xb146` as a shared response family. Mobile-ID success
is typed and bounded; other successful subtypes remain unsupported rather than
being misparsed. Because a top-level failure carries no subtype identity, all
currently implemented shared-read commands use one conservative family-level
`ResponseKey::MiscRead`. The bridge releases that key on either Mobile-ID
success or shared failure. Only success becomes callback 77, matching the OEM
SDK behavior. Tests cover exact command-76/HCI bytes, safe shared-chunk parsing,
callback 77 materialization and subscription gating, malformed local input
before GLIF, and failure cleanup without a fabricated callback.

## Detach-required and AT-from-device P0 indications — live P4 confirmed

The detach-required indication is dispatch opcode `0xb16a`, not a guessed
adjacent `0xb105`. In B014 the dispatch entry points to `0xbaec`; live P4 points
the same opcode to `0xbc9c`. Both handlers allocate exactly four bytes, zero
them, convert the incoming word with `D4H`, and invoke callback slot 5. B014
DWARF names the callback object `_DETACH_REQ_IND_INFO` and its only member is
`detach_type:u32`. As an independent identity check, the B014 handler's PIC
log-string reference resolves to rodata string `hci_ind_detach_required` at
`0x7b288`. The Rust parser therefore accepts exactly four payload bytes and
returns one BE `u32` detach type.

The stock compatibility selector is now independently pinned on both sides of
the daemon boundary. Live P4 `lted::ind_detach_required_indication` calls
`lted_srv_send_sdk_cb_assemble_hci` with selector **31** and an exact four-byte
payload. The unchanged live P4 `liblted.so` callback dispatcher maps selector 31
to `cb_rsp[5]`: function pointer offset `0x2c`, user pointer offset `0x30`.
`libltesdk.so` converts the modem word with `D4H` before invoking callback slot
5, so the daemon receives the historical four-byte host object and forwards
that same big-endian byte image. The Rust bridge mirrors this as an unsolicited
callback: no pending request is required or consumed. Tests verify callback 31,
stock slot `cb_rsp[5]`, exact four-byte data, per-device ID, subscription gating,
and unchanged zero pending state.

AT responses use the Linux-published opcodes `0xb308` (normal) and `0xb324`
(extended), both present in the B014 and P4 SDK dispatch tables. The normal SDK
handler does no decoding: it constructs the historical `_AT_COMMAND_DATA`
callback object from the incoming payload pointer and HCI payload length. Thus
the entire `0xb308` payload is raw AT bytes, including any CR/LF bytes supplied
by the modem.

The extended handler similarly performs no character decoding. Its first
payload byte becomes `_AT_COMMAND_EXT_DATA.channel`; `cmd` points at byte 1 and
`length` is the HCI payload length minus one. B014 and P4 have the same code
shape. The OEM subtracts one without checking for a zero-length packet; the
Rust parser requires the one-byte channel prefix and returns a truncation error
for an empty `0xb324` payload instead of representing an underflowed length.

## Live P4 GLIF transport and kernel read semantics

The runtime transport is simpler than several earlier research notes implied.
Live P4 `LAPI_LTEAPIOpen` at `0x40b98` allocates the SDK API handle and mutex
state; it does not itself open `/dev/glif0`. The actual transport setup occurs
inside P4 `io_recv_thread` at `0x718f0`:

- `net_open` (`0x6b35c`) creates an `AF_PACKET`/`SOCK_DGRAM` socket used for
  netdev/private-ioctl bookkeeping;
- a separate character-device helper opens `/dev/glif0` with `O_RDWR`;
- only the `/dev/glif0` fd is inserted into the receive thread's `select()`
  read set;
- when readable, the SDK calls `read(glif_fd, buffer, 32768)` and eventually
  hands the returned byte count to `decode_hci_packet` (`0x37c3c`);
- transmit paths, including `io_send_data` (`0x710dc`), ultimately call ordinary
  `write(glif_fd, frame, len)` after OEM-local filtering/side effects.

The live P4 kernel gives the exact stream behavior. In the symbolized kernel,
`glif_open` is `0xd001bb88` and delegates to generic `gif_open`; the shared
file operations are `gif_write` at `0xd001c02c` and `gif_read` at
`0xd001c244`. The kernel is ARM BE8, so these functions must be decoded as
little-endian ARM instruction words despite the big-endian ELF data encoding.

`gif_read` dequeues one kernel buffer entry and computes its remaining byte
count. If the caller buffer can hold the whole remainder, it copies all bytes
to userspace, frees that entry and returns its full remaining length. If the
caller buffer is smaller, it copies exactly the caller capacity, advances the
entry's internal offset and leaves the rest queued for the next read. Therefore
a userspace read can end in the middle of an HCI frame or batch. When no entry
is ready the path uses `prepare_to_wait`, `schedule` and `finish_wait`, proving
normal blocking character-device semantics rather than a message-only syscall.

Conversely, P4 `decode_hci_packet` explicitly loops over the returned read
buffer: it reads one BE HCI header, dispatches that packet, advances by
`4 + payload_len`, and continues while consumed bytes are less than the read
length. Thus one GLIF read can also contain multiple concatenated HCI packets.
A correct clean runtime must support both directions of mismatch: many frames
in one read and one frame split over multiple reads.

`gif_write` forwards the supplied userspace byte pointer and length through the
registered lower-driver callback chain and returns that callback result. The
clean transport therefore uses normal safe Rust `Read`/`Write` semantics and
`write_all` rather than reproducing SDK mutex/filter machinery in the byte
transport itself.

The SDK's nearby startup private ioctl is a separate netdev operation, not a
character-device prerequisite. P4 `io_ioctl` (`0x70350`) sends outer
`SIOCDEVPRIVATE` (`0x89f0`) through the packet socket with a zero-initialized
32-byte block. Bytes 0..15 are the interface name, 16..17 are the private
command as a device-order `u16`, 18..19 are the subcommand, 20..23 are the
32-bit length and 24..27 are a raw 32-bit userspace data pointer. Startup uses
private command `0x8d10`, subcommand 7, length 2. Live
`gdmlte.ko:gdm_lte_ioctl` (`0x2658`, decoded with ARM little-endian instruction
words) routes that exact subcommand to a path that copies two zero bytes back to
userspace and returns; it does not configure GLIF/HCI receive state.

The startup interface name is now independently recovered rather than inferred
from nearby strings. Live `dev_init` (`0x77e74`) allocates the 632-byte I/O
state and copies its second argument into the first 255 bytes. `net_open`
(`0x6b35c`) later treats the beginning of that same object as the interface
name, opens `AF_PACKET/SOCK_DGRAM`, performs `SIOCGIFHWADDR` (`0x8927`) on it,
and stores the packet-socket fd at state offset `0x268`. The detector routine at
`0x78240` opens `/proc/net/dev`, searches each line for `"lte"`, parses the
matched substring with `sscanf("lte%dpdn%d", ...)`, requires the parsed PDN
index to be zero, and passes that exact `lteNpdn0` substring to `dev_init`.
Thus the first modem's normal startup interface is `lte0pdn0`; additional modem
indices use the same grammar.

The clean runtime deliberately does not reproduce the pointer-bearing private
ioctl. The workspace forbids Rust `unsafe`, and reproducing an ABI whose live
driver effect is only `00 00` would add architecture-specific FFI risk without
restoring modem state. Instead `discover_startup_interface` safely scans
`/proc/net/dev` for the recovered `lteNpdn0` grammar (or verifies an explicit
caller-selected interface) before sending the separately proven `0x3337`
handshake. This preserves the meaningful readiness condition while eliding a
proven no-op compatibility mechanism.

The SDK also sends a separate zero-payload HCI command `0x3337` during startup
from helper `0x71800`. Its semantic name is not yet proven by an authoritative
header, so it remains a documented recovered initialization handshake rather
than receiving a guessed typed API.

`gct-transport` implements the proven core without `unsafe`: `GlifTransport`
opens `/dev/glif0` read/write, while `HciStreamDecoder` retains an incomplete
suffix across reads and dispatches all complete borrowed HCI packets. The
observed 32768-byte SDK read buffer is exposed only as an informational
constant, not as a protocol maximum; the actual HCI framing limit remains a
four-byte header plus the `u16` payload length.

## Minimal runtime bootstrap

Live P4 helper `0x71800` constructs one exact four-byte HCI frame: command
`0x3337`, payload length zero, then passes it to `io_send_data`. Its only live
caller is `io_recv_thread`: the helper runs immediately after the netdev
`0x8d10`/subcommand-7 readiness probe returns success, before the thread enters
its normal GLIF receive loop. The P4 response dispatch table contains no
`0xb338` entry and no other direct response handler corresponding to `0x3337`.
The clean runtime therefore names the value neutrally as
`SDK_STARTUP_HANDSHAKE` and models it as the observed fire-and-forget startup
command, not as a request with an invented response contract.

`gct-runtime::Modem` now owns the three pieces that are genuinely shared by any
higher-level daemon: `HciIo`, `HciStreamDecoder`, and a 32768-byte read buffer
matching the live SDK choice. `send_startup_handshake` emits exactly
`33 37 00 00`; `poll_once` performs one blocking read and dispatches all
complete packets produced from that read plus any suffix retained from the
previous iteration. This core deliberately contains no OEM UNIX-socket/shared-
memory compatibility state. That compatibility layer can sit above the modem
core instead of contaminating the proven HCI transport with historical IPC ABI.

## Typed P0 event dispatch and executable modem core

The receive side now narrows the proven Stage-2/P0 opcodes before any daemon or
client compatibility policy is applied. `gct-runtime::decode_event` maps the
recovered attach/detach, PDN, PLMN, online/offline/PS-init, AT and UICC response
opcodes to their existing `gct-lapi` borrowed parsers. Unknown opcodes remain
available as `ModemEvent::Unknown(Packet)`; a malformed packet carrying a known
opcode is instead returned as `EventDecodeError`. This distinction is
intentional: protocol drift or corruption must not silently become an
"unsupported event".

`Modem::poll_events_once` composes that typed decoder with the proven GLIF
stream framer. Decode errors are delivered to the callback per complete frame,
so one malformed known frame does not discard later complete HCI frames from
the same character-device read.

The `gctd` binary is the first executable modem-core harness. Before opening
`/dev/glif0` (or a caller-supplied path) for normal startup, it discovers the
first `lteNpdn0` primary interface in `/proc/net/dev`; `--interface IFACE`
selects and verifies one explicitly. It then emits the observed P4 `0x3337`
zero-payload startup handshake and continuously logs typed inbound P0 events.
`--no-startup-handshake` remains an explicit low-level mode that skips both the
netdev readiness gate and the handshake. The executable intentionally does not
yet implement the OEM `lted` UNIX-datagram + SysV shared-memory/semaphore ABI.

## Typed outbound command routing

The modem core now has a symmetric typed TX surface. `ModemCommand` contains
only request families whose executable wire encoders have already been proven
in `gct-lapi`: normal and extended attach, detach, normal and extended PDN
connect, PDN disconnect, PLMN search/search-stop, the recovered zero-payload
online/offline/PS-init and PLMN-list requests, normal and extended AT, plus
status/read-binary/read-record/authenticate/PIN-status/PIN-command UICC
requests.

Known SDK operations without a recovered encoder are intentionally absent.
Callers that truly need an untyped experimental frame still have the explicit
low-level `send_bytes` escape hatch, but it is not part of the typed request
API.

`Modem::send_command` encodes into one reusable `MAX_HCI_FRAME_LEN` scratch
buffer (4 + 65535 bytes) and only touches the GLIF writer after validation and
encoding succeed. This preserves the `u16` HCI maximum without per-request heap
allocation and guarantees that local validation failures cannot produce a
partial modem command.

## Normal attach transaction identity and conservative correlation

Live P4 gives a stronger normal-attach response grammar than the earlier
15-byte-prefix-only model. Dispatch opcode `0xb102` targets handler `0xac9c`.
After decoding the common fixed 15-byte prefix, the handler passes the suffix to
helper `0xa9a0` and points the destination at `_ATTACH_RSP_INFO.transaction_id`.
That helper checks the first suffix tag for `0x20`, copies byte 2 to the
destination, and reports three bytes consumed. B014 `lted` DWARF independently
places `transaction_id` at callback offset 634 (`0x27a`).

The OEM helper does not validate the TLV length byte before reading byte 2. The
clean `AttachResponse` parser therefore strengthens the recovered grammar to a
mandatory first TLV `20 01 <tid>` and rejects missing, wrong-tag, truncated or
non-one-byte transaction fields. Descriptor-managed fields after that TLV
remain borrowed rather than guessed.

The live normal-attach handler also reveals why transaction identity must not be
invented for every response family: if its callback transaction field remains
`0xff`, it falls back to `getTidByTid_type(1)` from SDK bookkeeping. In other
words, the OEM SDK sometimes supplements modem wire data with local pending
state. The extended-attach handler at `0xb4d8` has no equivalent TID-list path,
and the clean runtime does not transfer normal-attach semantics to it by
analogy.

`gct-runtime::ResponseKey` consequently uses exact transaction IDs only for
normal attach, normal PDN connect and PDN disconnect, where the response grammar
actually exposes one. Extended attach, detach, extended PDN, PLMN search/list
and the individual online/offline/PS-init families use family-level identities;
UICC uses its response subtype. AT is deliberately untracked because its
inbound byte stream has no recovered one-request identity.

`PendingRequests` prevents a second indistinguishable request from being sent
through `Modem::send_tracked_command`, while allowing concurrent exact-ID
requests with different TIDs. It intentionally does not auto-remove a key when
an event arrives: some families (notably PLMN search/list) can be multipart, so
terminal-response policy belongs in the command-specific state machine once
that behavior is proven.

## Extended attach — live P4 authority

B014 DWARF describes `_ATTACH_REQ_EXT_PARAM` as a 484-byte historical C object.
Its apparent size is mostly two fixed-capacity copies of the same logical PDN
profile rather than 484 bytes of distinct protocol state:

- `optional_info` at offset 0.
- Primary profile: `ip_alloc` 1, `apn_class` 2, APN 3..102, `pdn_type` 103,
  username 104..167, password 168..231, `auth_flag` 232 and nine-byte
  `_PCO_INFO` at 233..241.
- Retry profile: `ip_alloc` 242, `apn_class` 243, APN 244..343, `pdn_type` 344,
  username 345..408, password 409..472, `auth_flag` 473 and `_PCO_INFO`
  474..482.
- `req_apn_type` at offset 483.

The authoritative live P4 `LAPI_AttachRequestEXT` is at `0x44b70`; B014 has the
same exported function at `0x417dc`. Both allocate a 2048-byte temporary frame,
write request opcode `0x3165`, copy `optional_info` as payload byte 0 and, when
that byte is zero, send a one-byte payload (five-byte HCI frame total).

When optional data is enabled, live P4 calls its shared TLV encoder at
`0x42564` in this exact order for the primary profile:

`01 ip_alloc`, `20 apn_class`, `04 apn`, `05 pdn_type`, `02 username`,
`03 password`, `1e auth_flag`, `21 PCO[9]`.

It then emits the retry profile with the exact same tag sequence. B014 does the
same through its shared helper at `0x3f2f4`. The three `u16` protocol IDs inside
`_PCO_INFO` are converted through `H2D()` before the nine-byte block is emitted,
so `AttachExtProfile` reuses the already-proven `PcoInfo` wire conversion.
Context matters here: tag `0x20` is APN class in extended attach, whereas the
normal-attach grammar uses `0x20` for its transaction ID.

The old 100-byte APN arrays and 64-byte username/password arrays imply maximum
serialized lengths of 99/63/63 bytes when preserving the OEM C-string safety
boundary. The clean encoder validates those limits only when `optional_info`
causes the fields to be serialized; the live SDK does not inspect those strings
on the zero-optional path either.

`req_apn_type` is intentionally not present in `AttachExtRequest`. Live P4 reads
byte 483 before constructing the frame and stores it at offset `0x108` in its
private per-device bookkeeping object, but no call to the TLV helper references
that member and it never appears on the modem wire. Reproducing that SDK-local
side effect would incorrectly turn implementation state into protocol syntax.

The extended-attach response (`0xb166`) has no recovered transaction identity.
`gct-runtime` therefore uses the conservative family key `ResponseKey::AttachExt`
and rejects a second in-flight extended attach rather than inventing correlation
metadata absent from the response.

The unchanged stock-client ABI is now bridged in both directions as well. Live P4
`liblted.so::LTED_AttachRequestEXT` at `0xaa80` sends SDK command 27 and copies
**exactly 484 caller bytes** into the local request. `lted-bridge` therefore
decodes the proven B014 object only at the offsets above; it does not expose the
historical struct, and when `optional_info == 0` it deliberately leaves dead
fixed-string storage uninterpreted just as the live encoder does. A golden test
turns a representative 484-byte stock object into the exact 73-byte `0x3165`
frame, while unterminated fixed strings fail before GLIF I/O.

On the reverse path, live P4 `ind_attach_response_extension` at `0x210bc` passes
callback ID **28** to `lted_srv_send_sdk_cb_assemble_hci`. The live callback
lookup maps ID 28 to `cb_rsp[3]`, function-registration offset `0x1c`. B014 DWARF
fixes `_ATTACH_RSP_EXT_INFO` at exactly **700 bytes**: registration results at
0/2, requested APN-NI at 4, received APN-NI at 69, default/active EPS IDs at
134/136, data path/IP allocation/APN class at 138/139/140, the 554-byte
`ATTACH_PDN_RSP_INFO` at 141, and five-byte `NET_FEATURE_INFO` at 695.

The live P4 modem parser independently confirms the response construction. After
the shared 15-byte fixed prefix it consumes one fixed-order APN-class TLV, then
requested and received APN-NI TLVs, then runs the same at-most-two contiguous
`0xf0`/`0xf2` PDN/QoS parser already used by the normal bridge. `gct-lapi` now
exposes this as `AttachExtResponse`; bytes after those initial containers remain
visible as `unparsed_suffix` because the OEM ignores them. The callback
materializer reuses the shared PDN/QoS writer at base `0x08d`, producing the
exact 700-byte stock image. End-to-end tests verify callback 28 routing, the
legacy offsets above, subscription gating, and release of the family-level
pending key.

## AT command families and PLMN-search-stop

Two request families previously omitted from the typed runtime now have direct
live-P4 evidence rather than opcode inference.

`LAPI_ATCommandToDeviceEXT` is exported at live P4 `0x4d0d0` (B014
`0x4a0f4`). B014 DWARF defines its nine-byte historical input object as
`channel:u8` at offset 0, `cmd:*const u8` at offset 1 and `length:u32` at offset
5. The P4 function loads that 32-bit length from offsets 5..8, allocates
`length + 6`, writes HCI opcode `0x3323`, sets the HCI payload length to
`length + 2`, copies channel to payload byte 0, copies exactly `length` command
bytes after it and appends `0x0a`. `AtCommandExt` models precisely
`[channel, command..., LF]` without preserving the unaligned pointer-bearing C
object.

The stock `liblted.so` IPC wrappers deliberately flatten those pointer-bearing
objects before crossing the daemon boundary. Live P4 `LTED_ATCommandToDevice`
at `0xe198` reads the `AT_COMMAND_DATA.length` word at offset 4, emits SDK
command **125**, and copies exactly `length` bytes from the caller's command
pointer as the complete local request parameters. `LTED_ATCommandToDeviceEXT`
at `0xe3d0` reads the extended length at offset 5, emits SDK command **127**,
copies the channel byte first, then exactly `length` pointed-to command bytes.
The Rust bridge therefore accepts command 125 as raw AT bytes and command 127
as `[channel, raw AT bytes...]`; no process-local pointer value or redundant
length field is reproduced. Both paths remain deliberately untracked because
the modem's AT receive stream has no request identity.

The reverse path is equally pointer-free on the daemon wire. Live P4
`ind_at_command_from_device` at `0x274bc` emits callback **126** with the raw
`0xb308` payload. The stock client's callback-126 case at `0x6d20` derives the
length from the local envelope, rebuilds `{cmd pointer, length}` on its own
stack, and invokes `cb_rsp[60]` (function registration offset `0x1e4`, user at
`0x1e8`). `ind_at_command_from_device_ext` at `0x275b0` emits callback **128**
as one channel byte followed by the raw `0xb324` command bytes; the stock
callback-128 case at `0x6d8c` reconstructs `{channel, cmd pointer, length}` and
invokes `cb_rsp[61]` (registration offset `0x1ec`, user at `0x1f0`).

Bridge tests verify exact command-125/127 local shapes, exact `0x3307`/`0x3323`
HCI bytes including the SDK-added LF, callback 126/128 payloads and subscription
slots, and that unsolicited AT receive events do not create or consume pending
request state.

`LAPI_PLMNSearchStopRequest` is exported at live P4 `0x495d4` (B014
`0x46344`). It allocates five bytes, writes HCI `0x3127` with payload length
one and copies exactly one request byte. B014 DWARF names the one-byte request
`_PLMN_SEARCH_STOP_REQ_PARAM { search_type:u8 }`.

The live P4 HCI dispatch table maps response `0xb128` to handler `0x12228`.
That handler leaves payload byte 0 untouched, converts bytes 1..4 through
`D4H`, then invokes callback slot 20. B014 DWARF independently describes the
five-byte `_PLMN_SEARCH_STOP_RSP_INFO` as `search_type:u8` at offset 0 followed
by `result:u32` at offset 1. The clean response parser therefore requires
exactly five payload bytes and decodes the result as one big-endian word.

Because both request and response carry `search_type`, runtime correlation uses
`ResponseKey::PlmnSearchStop(search_type)`. Extended AT remains deliberately
untracked: like normal AT, its inbound channel/raw-byte stream has no recovered
one-request completion identity.

## Live P4 PSM / LCS / LPP shared controls

A fresh live-rootfs import inventory was used to choose these families rather
than extending old headers speculatively. `LTED_PSMctrlRequest`,
`LTED_LCSctrlRequest`, and `LTED_LPPctrlRequest` are each imported by five
shipped connection-manager binaries/instances (`lteautocm`, `smartfren`, and
`sprint_cm`), making them the highest-use remaining compact request families.

Live P4 `liblted.so` proves the stock local ABI directly:

- `LTED_PSMctrlRequest` at `0x14108` emits SDK command **208** and copies exactly
  **6 caller bytes**.
- `LTED_LCSctrlRequest` at `0x142b8` emits command **209** and copies exactly
  **4 caller bytes**.
- `LTED_LPPctrlRequest` at `0x14468` emits command **210** and copies exactly
  **4 caller bytes**.

Older B014 DWARF independently names the same object layouts. `_PSM_CTRL_REQ`
is six bytes: `ctrlCmd:u16@0`, `T3324TimerValUnit:u8@2`,
`T3324TimerVal:u8@3`, `extT3412TimerValUnit:u8@4`, and
`extT3412TimerVal:u8@5`. `_LCS_CTRL_REQ` and `_LPP_CTRL_REQ` are each exactly
four bytes containing only `mode:u32@0`. The Rust compatibility layer decodes
those semantics rather than carrying opaque historical C structs.

The live modem SDK then proves all three wire grammars. `LAPI_PSMctrlRequest`
at `0x5f388`, `LAPI_LCSctrlRequest` at `0x5f69c`, and
`LAPI_LPPctrlRequest` at `0x5f9a4` all serialize through shared HCI opcode
**`0x3155`**:

- PSM: `00 08 00 06 <ctrlCmd:u16> <T3324 unit,value> <ext-T3412 unit,value>`.
- LCS: `00 09 00 04 <mode:u32>`.
- LPP: `00 0a 00 04 <mode:u32>`.

The response side is intentionally *not* modeled as three request/response
families. Live P4's shared `0xb156` handler at `0x3319c` switches on the
payload discriminator and sends **7, 8, 9, and 10** to the same default/drop
path; only discriminator 11 reaches the NI-reattach response handler. Thus EMM
timer control, PSM, LCS, and LPP acknowledgements are all request-only from the
observable stock-client ABI. Rust sends them with `send_command`, assigns no
`ResponseKey`, and continues to decode any `0xb156` discriminator 7..10 as an
unsupported/unknown event instead of inventing callbacks or pending-state
completion.

Golden tests cover each exact stock-local-to-HCI translation, malformed local
length rejection before GLIF I/O, zero pending-state creation, and the live
shared-response drop behavior for discriminators 7 through 10.

## Live-only EMM Timer Start

The live rootfs has one shipped importer of `LTED_EMMTimerStartRequest`
(`lteautocm`). Live P4 `liblted.so::LTED_EMMTimerStartRequest` at `0x14978`
emits SDK command **213** and copies exactly **3 caller bytes** into the local
request. This family is absent from the older B014 type information available
here, so those three bytes intentionally remain an opaque fixed-size parameter
object rather than receiving guessed field names.

Live `libltesdk.so::LAPI_EMMTimerStartRequest` at `0x604a8` independently proves
the modem serialization: shared HCI opcode **`0x3155`**, discriminator **13**,
declared body length **3**, followed by the same three caller bytes. The
implementation combines the first two bytes into a word only to emit the same
high/low bytes again; the third byte is copied directly. Thus the exact clean
wire grammar is `00 0d 00 03 <three stock bytes>`.

The live shared `0xb156` response switch at `0x3319c` routes discriminator 13 to
the same default/drop path as 7..10. No stock response callback is therefore
invented and Timer Start is request-only/untracked. This also exposed an overly
strict assumption in the earlier shared-response decoder: stock chooses the
handler from the discriminator *before* parsing a family-specific body, while
Rust previously required every unsupported response to look like the ten-byte
NI-reattach envelope. `EmmControlResponse::parse` now requires only enough bytes
to read the discriminator for unsupported families; only discriminator 11 must
satisfy the exact NI-reattach body grammar. Tests prove command 213, the exact
11-byte HCI frame, malformed local-length rejection before GLIF I/O, zero
pending state, and discriminator-13 drop behavior with a non-NI body shape.

## Live P4 MSISDN Read

A fresh live-rootfs import inventory found one shipped importer of
`LTED_MSISDNReadRequest` (`bin/gdmmon`). Although small in client count, this is
a direct stock-client compatibility hole with a fully recoverable shared-read
wire grammar.

Live P4 `liblted.so::LTED_MSISDNReadRequest` at `0xd238` emits SDK command
**80** with **zero local parameter bytes**. Live
`libltesdk.so::LAPI_MSISDNReadRequest` at `0x4b014` then emits shared read-info
HCI opcode **`0x3145`** with exact four-byte payload `00 03 00 00`: subtype 3,
empty subtype request body. The response remains on the already-proven shared
read-info opcode **`0xb146`**.

The live shared response dispatcher selects subtype 3 handler `0x16568`. That
handler obtains SDK response slot **28**, zeroes an exact **772-byte** historical
response object, stores converted `read_result:u16@0`, copies subtype-local
`result:u8@2`, and on `result == 0` copies `num_msisdn:u8@3` plus exactly
`num_msisdn << 8` bytes from the modem body into the record area at offset 4.
A subtype-local nonzero result leaves the zero-filled count at zero and copies
no records. Top-level nonzero shared `read_result` still exits before subtype
dispatch, matching the existing `MiscReadFailure` behavior with no subtype
callback.

B014 DWARF independently proves the historical object bounds and record layout:
`_MSISDN_READ_RSP_INFO` is **0x304 / 772 bytes** with `read_result:u16@0`,
`result:u8@2`, `num_msisdn:u8@3`, and three `MSISDN_STR` records from offset 4.
Each `MSISDN_STR` is exactly **0x100 / 256 bytes**:
`alpha_id_len:u8@0`, `alpha_id[241]@1`, `bcdssc_len:u8@0xf2`,
`ton_npi:u8@0xf3`, `dial_num_ssc[10]@0xf4`, `cap_cfg2:u8@0xfe`, and
`ext5:u8@0xff`. Rust therefore caps the modem-provided count at three, rejects
truncated fixed records, and otherwise preserves each 256-byte record exactly
rather than normalizing its internal fields.

Live daemon `ind_msisdn_read_response@0x288d4` sends stock callback **81** with
an assembled variable payload. Its final iovec length is exactly
`4 + (num_msisdn << 8)`, so the daemon callback data is
`read_result:u16 | result:u8 | num_msisdn:u8 | MSISDN_STR[num_msisdn]` rather
than the full 772-byte backing object. `ind_regist` registers SDK slot 28 to
this exact handler: the literal at `0x39b44` is `0xfffef2e4`, which resolves
from the ARM PC at the registration site to `0x288d4`. Live stock
`liblted.so::lted_sdk_recv_cb_handler` case at `0x6490` reads the registered
callback pointer at **offset `0xe4`**, i.e. `cb_rsp[28]`.

The Rust implementation uses the shared family-level `ResponseKey::MiscRead`
for both Mobile ID and MSISDN, deliberately preventing concurrent requests
whose top-level shared failure cannot identify a subtype. Tests cover exact
command-80 local/HCI bytes, collision with Mobile ID, callback 81 and slot
`0xe4`, one exact 256-byte record, subtype-local failure producing only the
four-byte callback prefix, subscription gating, local input rejection before
GLIF, count > 3 rejection, and truncated-record rejection. The callback
builder also independently rejects raw record blocks that are not an exact
multiple of 256 bytes or exceed the three proven slots.

## Live P4 MSISDN Read

A fresh live-rootfs import inventory found one shipped importer of
`LTED_MSISDNReadRequest` (`bin/gdmmon`). Although small in client count, this is
a direct stock-client compatibility hole with a fully recoverable shared-read
wire grammar.

Live P4 `liblted.so::LTED_MSISDNReadRequest` at `0xd238` emits SDK command
**80** with **zero local parameter bytes**. Live
`libltesdk.so::LAPI_MSISDNReadRequest` at `0x4b014` then emits shared read-info
HCI opcode **`0x3145`** with exact four-byte payload `00 03 00 00`: subtype 3,
empty subtype request body. The response remains on the already-proven shared
read-info opcode **`0xb146`**.

The live shared response dispatcher selects subtype 3 handler `0x16568`. That
handler obtains SDK response slot **28**, zeroes an exact **772-byte** historical
response object, stores converted `read_result:u16@0`, copies subtype-local
`result:u8@2`, and on `result == 0` copies `num_msisdn:u8@3` plus exactly
`num_msisdn << 8` bytes from the modem body into the record area at offset 4.
A subtype-local nonzero result leaves the zero-filled count at zero and copies
no records. Top-level nonzero shared `read_result` still exits before subtype
dispatch, matching the existing `MiscReadFailure` behavior with no subtype
callback.

B014 DWARF independently proves the historical object bounds and record layout:
`_MSISDN_READ_RSP_INFO` is **0x304 / 772 bytes** with `read_result:u16@0`,
`result:u8@2`, `num_msisdn:u8@3`, and three `MSISDN_STR` records from offset 4.
Each `MSISDN_STR` is exactly **0x100 / 256 bytes**:
`alpha_id_len:u8@0`, `alpha_id[241]@1`, `bcdssc_len:u8@0xf2`,
`ton_npi:u8@0xf3`, `dial_num_ssc[10]@0xf4`, `cap_cfg2:u8@0xfe`, and
`ext5:u8@0xff`. Rust therefore caps the modem-provided count at three, rejects
truncated fixed records, and otherwise preserves each 256-byte record exactly
rather than normalizing its internal fields.

Live daemon `ind_msisdn_read_response@0x288d4` sends stock callback **81** with
an assembled variable payload. Its final iovec length is exactly
`4 + (num_msisdn << 8)`, so the daemon callback data is
`read_result:u16 | result:u8 | num_msisdn:u8 | MSISDN_STR[num_msisdn]` rather
than the full 772-byte backing object. `ind_regist` registers SDK slot 28 to
this exact handler: the literal at `0x39b44` is `0xfffef2e4`, which resolves
from the ARM PC at the registration site to `0x288d4`. Live stock
`liblted.so::lted_sdk_recv_cb_handler` case at `0x6490` reads the registered
callback pointer at **offset `0xe4`**, i.e. `cb_rsp[28]`.

The Rust implementation uses the shared family-level `ResponseKey::MiscRead`
for both Mobile ID and MSISDN, deliberately preventing concurrent requests
whose top-level shared failure cannot identify a subtype. Tests cover exact
command-80 local/HCI bytes, collision with Mobile ID, callback 81 and slot
`0xe4`, one exact 256-byte record, subtype-local failure producing only the
four-byte callback prefix, subscription gating, local input rejection before
GLIF, count > 3 rejection, and truncated-record rejection. The callback
builder also independently rejects raw record blocks that are not an exact
multiple of 256 bytes or exceed the three proven slots.

## Live P4 ICCID Read

The live import audit found two shipped users of `LTED_ICCIDReadRequest`.
Live `liblted.so::LTED_ICCIDReadRequest@0xd0b8` emits SDK command **78** with
**zero local parameter bytes**. Live `libltesdk.so::LAPI_ICCIDReadRequest`
at `0x4adb8` serializes the exact shared-read request
`0x3145 | len 4 | 00 02 00 00`, i.e. subtype **2** with an empty subtype body.

The live shared `0xb146` response dispatcher routes subtype 2 to handler
`0x16384`. That handler obtains SDK response slot **27**, zeroes an exact
13-byte object, converts/stores `read_result:u16@0`, stores subtype-local
`result:u8@2`, and copies exactly ten bytes from the subtype body into offset 3.
B014 DWARF independently proves `_ICCID_READ_RSP_INFO` is **0x0d / 13 bytes**
with exactly `read_result:u16@0 | result:u8@2 | iccid:u8[10]@3`.

Live daemon `ind_iccid_read_response@0x286d8` emits stock callback **79** and
always assembles exactly 13 response bytes after the generic callback envelope.
The live registration is exact rather than inferred by adjacency: SDK slot 27
loads literal `0xfffef124` from `0x39b3c`; resolving that PC-relative value at
the registration site yields `0x286d8`. Live stock `liblted.so` callback
routing for the same slot reads the callback pointer from **offset `0xdc`**,
i.e. `cb_rsp[27]`.

Rust models ICCID as another member of family-level `ResponseKey::MiscRead`, so
ICCID, Mobile ID, and MSISDN cannot overlap when the shared top-level failure
path carries no subtype identity. The shared-read parser was refactored into
subtype-specific helpers while adding ICCID rather than weakening the strict
100-line Clippy limit. Tests cover exact command-78/HCI request bytes, exact
13-byte subtype-2 parsing, truncated ICCID rejection, shared-family collision,
callback 79 / slot `0xdc`, subscription gating, and local nonzero-parameter
rejection before GLIF I/O.

## Live P4 Temperature Read

The live import inventory has one shipped importer of
`LTED_TemperatureReadRequest`. Live `liblted.so::LTED_TemperatureReadRequest`
at `0xd3b8` emits SDK command **82** with **zero local parameter bytes**. Live
`libltesdk.so::LAPI_TemperatureReadRequest@0x4b270` serializes the shared
read-info request as HCI **`0x3145`** with exact payload `00 04 00 00`:
subtype **4**, empty subtype body.

The live shared `0xb146` dispatcher routes subtype 4 to handler `0x16798`.
That handler obtains SDK response slot **29**, zeroes exactly four bytes,
converts/stores `read_result:u16@0`, copies `result:u8@2`, and copies the next
byte as the temperature value at offset 3. B014 DWARF independently proves
`_TEMPERATURE_READ_RSP_INFO` is exactly **4 bytes**:
`read_result:u16@0 | result:u8@2 | temperature:s8@3`. Rust therefore models
temperature as signed `i8` and uses explicit signed/unsigned byte casts at the
wire boundary rather than implicit wrapping casts.

Live daemon `ind_temperature_read_response@0x28c74` emits stock callback
**83** and always assembles the exact four-byte historical response object.
The live registration is independently pinned: SDK slot 29 loads literal
`0xfffef648` from `0x39b4c`, which resolves at the registration site to
`0x28c74`. Live stock `liblted.so` callback dispatch reads the callback pointer
at **offset `0xec`**, i.e. `cb_rsp[29]`.

Temperature Read is another member of the shared family-level
`ResponseKey::MiscRead`, preventing overlap with Mobile ID, ICCID, and MSISDN
when the shared top-level failure path carries no subtype identity. Tests cover
exact command-82/HCI request bytes, signed negative-temperature decoding,
truncated subtype-body rejection, shared-family collision, exact callback 83 /
slot `0xec`, subscription gating, and local nonzero-parameter rejection before
GLIF I/O.


## Live P4 RRC Capability Control

The remaining RRC-capability API looked broad at the SDK boundary, but shipped
callsite analysis makes the product surface finite. Live P4 `lteautocm` uses
set/get type IDs **1, 2, 3, 11, 18, and 20**, plus a type-**4** variable-list
setter. The replacement therefore supports exactly `{1,2,3,4,11,18,20}` and
rejects the rest before GLIF rather than cloning a twenty-way legacy switch
only exposed by generic AT/debug plumbing.

Live P4 `liblted.so::LTED_RRCCapabilityControlRequest@0x108b0` emits SDK
command **220**. B014 DWARF describes the historical flexible object as
`type:u16@0 | len:u16@2 | data:u8[1]@4` (nominal C size 5), while the live
wrapper is the authoritative local transport rule: it copies exactly
**`4 + len` bytes** into the SDK datagram. Thus a declared zero-length set
object is four bytes on the socket boundary. Live
`libltesdk.so::LAPI_RRCCapabilityControlRequest@0x5215c` sends HCI
**`0x3906`** with the common payload `type:u16 | len:u16 | data[len]` for the
shipped types. Type 4 is the one shipped list shape: `data[0]` is a count
followed by big-endian u16 entries. Rust validates the minimum
`1 + 2*count` extent before GLIF instead of reproducing possible OEM over-read.

Live P4 `liblted.so::LTED_RRCCapabilityControlGetRequest@0x10a80` emits SDK
command **222** and copies the exact five-byte historical object. Live
`LAPI_RRCCapabilityControlGetRequest@0x53450` consumes only its leading
`type:u16` and emits HCI **`0x390d`** with exactly those two payload bytes; the
legacy `len + data[1]` tail is local ABI noise and is intentionally ignored at
the clean modem boundary.

The live SDK dispatch table independently pins both response paths:
**`0xb907 -> 0x218a4 -> SDK callback 115`** for set and
**`0xb90e -> 0x21a50 -> SDK callback 116`** for get. Set responses use the
common modem envelope `result:u16 | len:u16 | type:u16 | data[len]`; get uses
`result:u16 | type:u16 | len:u16 | data[len]`. The get converter only performs
additional type-specific normalization for types 4, 15, 16, and 19. For the
shipped types 1/2/3/11/18/20 it preserves data bytes after normalizing the
common words; type 4 converts its counted u16 list. Because both modem and
stock callback representations are big-endian on the target, the clean bridge
can preserve the bytes while still independently checking the type-4 bounds.

Live daemon registration is exact rather than inferred. In `ind_regist`, SDK
slot 115 loads literal `0xffff1674` at `0x39d64`; resolving it against the ARM
PC at `0x3aa28` yields
`ind_rrc_capability_control_req_indication@0x2c09c`. SDK slot 116 loads
`0xffff1854` at `0x39d6c`; resolving it against PC `0x3aa64` yields
`ind_rrc_capability_control_get_req_indication@0x2c2b8`. Those handlers emit
stock callbacks **221** and **223** respectively.

The live stock client jump table independently maps callback **221** to the
registered function/context at offsets `0x39c/0x3a0`, i.e. **`cb_rsp[115]`**,
and callback **223** to `0x3a4/0x3a8`, i.e. **`cb_rsp[116]`**. B014 DWARF fixes
the historical response field order: set is
`result:u16 | len:u16 | type:u16 | data...`; get is
`result:u16 | type:u16 | len:u16 | data...`. The live daemon exposes only the
six-byte set header to callback 221, while callback 223 carries exactly
`6 + len` bytes.

One live-SDK quirk is deliberately preserved: on successful set responses the
converter accepts callback-bearing types **1/2/3/4/18**, but rejects types
**11/20** after parsing, suppressing the daemon callback. A nonzero `result`
skips that success-type switch, so failures for 11/20 still reach callback 221.
Rust tracks all set requests by `type_id` so the direct HCI response always
retires pending state; successful 11/20 responses are consumed silently, while
failures are materialized as the stock six-byte callback. Get requests are
also tracked by exact `type_id`.

Golden tests cover the exact command-220 variable local envelope to `0x3906`,
the exact five-byte command-222 local object to `0x390d`, both response opcode
and field orders, callback 221/223 registration slots, subscription gating,
per-type correlation, type-4 bounds rejection before unsafe exposure, silent
successful type-11 completion, and the asymmetric type-11 failure callback.

## Live P4 DMLogExt — transport proven, semantic bridge intentionally deferred

Live P4 proves the DMLogExt transport contract completely: stock SDK command
**173** maps to modem request **`0x3318`**; the live HCI dispatch table maps
response **`0xb319`** to the DMLogExt response path; that path uses SDK callback
**88**. The daemon registers slot 88 to `ind_dm_log_ext_response@0x30584` and
emits stock callback **174**. Live stock callback routing maps selector 174 to
**`cb_rsp[88]`**, registration offset **`0x2c4`**.

This family is deliberately not implemented as opaque compatibility bytes.
`0xb319` is a streaming/multi-record diagnostic format: the SDK walks records
and performs category/item-specific conversion before producing separate
callback-88 objects. Shipping a one-record or raw-forwarding bridge would be a
false compatibility claim and would recreate a large legacy conversion switch
without product-demand evidence. The proven transport facts are retained here
for later work; implementation stays deferred until the used record grammar is
narrowed by real callsites or captures.
