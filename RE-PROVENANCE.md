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
endian conversion. The B014 `lted` consumer `print_uicc_read_record` iterates
from zero up to byte 9 (`len`) and uses `record_num` only as separately reported
metadata. Consequently `len` is validated as the total number of returned data
bytes; it is not multiplied by `record_num`.

Both response types remain allocation-free borrowed views and reject truncated
fixed prefixes or disagreement between their embedded length and the common
UICC envelope payload.
