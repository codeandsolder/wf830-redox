# P4 stock-client compatibility oracle (optional integration test)

This checks the Rust `gctd` daemon against **the original Polish P4 BE8
`liblted.so` and unchanged shipped clients**, without a live modem.

It is not part of ordinary `cargo test` or shared CI: a separately obtained
Polish P4 firmware extraction is required. **No OEM binaries, calibration
data, device credentials, or captured customer traffic belong in this repo.**

The host uses the real `gctd` executable and a PTY-backed simulated GLIF
stream. A small ARM BE8 C test program is cross-compiled with Clang and
dynamically linked *at runtime* against the original `liblted.so`. The
original stock client owns API-open, SysV shared memory, callback
registration, SDK calls and callback invocation. The Rust daemon owns
local protocol translation, HCI request serialization, response parsing and
callback materialization.

## Prerequisites

- Linux host with `bash`, `bubblewrap`, `qemu-armeb`, `clang`, `ld.lld`,
  `readelf`, `uv` and the normal Rust toolchain
- The extracted **Polish P4** rootfs containing `lib/liblted.so` and the
  original uClibc libraries; don't substitute the older Indosat build
- A native `gctd` built from the matching research branch
- A writable dedicated scratch directory **outside the Git repository**

For example, on Acer:

```bash
export WF830_OEM_ROOTFS="$HOME/projects/wf830/our-device/ubifs/files-img-1934699295_vol-rootfs"
export WF830_NATIVE_GCTD="$HOME/projects/wf830-redox/target/debug/gctd"
export WF830_ORACLE_WORK_DIR="$HOME/research/wf830-differential-20261118"

cd "$HOME/projects/wf830-redox"
RUSTC_WRAPPER=/usr/local/bin/sccache \
  CARGO_TARGET_DIR="$HOME/projects/wf830-redox/target" \
  cargo +stable build --locked -p gctd

tools/stock-oem-oracle/run.sh ltesms normal
tools/stock-oem-oracle/run.sh ltesms early
tools/stock-oem-oracle/run.sh attach_probe normal
tools/stock-oem-oracle/run.sh pdn_probe split
tools/stock-oem-oracle/run.sh plmn_probe coalesced
tools/stock-oem-oracle/run.sh rrc_probe normal
```

The `normal`, `split` and `coalesced` modes exercise identical response
semantics with different GLIF read boundaries. `split` sends one- and
two-byte pieces across the header and later payload. `coalesced` surrounds
the response with two complete unrelated HCI notifications in the same write.
`early` is a separate `ltesms`-only startup race test: its first SDK
command 0 must precede PSInit completion.

### What is actually verified

| Guest | OEM request | HCI request | OEM callback | Callback bytes |
| --- | ---: | ---: | ---: | ---: |
| `attach_probe` | 25 | `0x3101` | 26 | 2,187 |
| `pdn_probe` | 32 | `0x3105` | 33 | 742 |
| `plmn_probe` | 40 | `0x3109` | 41 | 436 |
| `rrc_probe` Set | 224 | `0x3908` | 225 | 6 |
| `rrc_probe` Get | 226 | `0x390f` | 227 | 7 |

The guest calls genuine P4 `liblted.so` exports. The oracle compares the
complete serialized HCI request with the independently established Rust golden
request, verifies that the unmodified OEM callback handler runs exactly once,
and validates each resulting callback image against recovered byte offsets.
The image checker includes the full RRC Set/Get images and checks 40 selected
Attach/PDN/PLMN byte spans plus expected zero padding. JSON logs include
image SHA-256 hashes.

**Provenance:** the *injected HCI responses* are synthetic fixtures extracted
at runtime from `crates/lted-bridge/src/tests.rs` by
`generate_fixtures.py`; they are **not live modem captures**. The output
callback bytes are independently observed through the OEM library. A pass
proves stock-client ABI interop with the fixtures, not real-radio behavior
or correctness of unverified HCI fields.

The exact original `ltesms` binary also tests stock API-open and
GetPSInitComplete semantics. The original `lted_cli` can run to document its
distinct unsupported `0x010a` diagnostic command surface; it reports
`observed-unsupported-cli` rather than masquerading as a compatibility pass.
Other OEM clients only pass if the targeted IPC operation was actually used.

### Isolation and outputs

`run.sh` reconstructs missing SONAME links in a scratch-only sysroot, builds
the native test guest under `$WF830_ORACLE_WORK_DIR/bin`, and generates the
test-derived modem responses under `fixtures`. It runs the emulator,
the Rust daemon and the GLIF mock inside disposable **user, PID, IPC, network
and mount namespaces**, with private `/tmp` and `/var/tmp`.

No test interacts with `/dev/glif0`, the physical modem, the host's lted
socket, or host SysV IPC objects. The original firmware tree is read-only.
Build products, callback images, optional `WF830_STRACE=1` socket traces and
structured `*.json` results go under the dedicated scratch directory.

The detailed historical record and live-device dependencies are documented in
the WF830 project Notion page *Stock-client BE8 QEMU oracle — 2026-11-18*.
