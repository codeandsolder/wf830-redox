# WF830 Rust-only ARM0 platform scope

This is the literal-pride target: keep the proprietary LTE modem image on ARM1 as firmware, but replace the entire mutable ARM0 application-side runtime with one Rust system image. Stock U-Boot may remain as a recovery/DDR-loading stage initially; it can be replaced later if desired.

This is distinct from [`FULL_SYSTEM_PORT.md`](FULL_SYSTEM_PORT.md), which targets modern Linux/OpenWrt. The Rust-only route can actually be *simpler* because it does not need to forward-port an old proprietary BSP into Linux abstractions before doing useful work.

## Executive result

The WF830 is much less "blobby" than its stock filesystem suggests.

At the practical Rust-only end state, executable proprietary code consists of:

1. immutable mask ROM inside the SoC;
2. the **single monolithic ARM1 TK modem image** (6,215,317 bytes decompressed);
3. optionally the tiny embedded RTL8192E Wi-Fi MCU firmware if we ever choose to use that radio.

LTE/RF NV, board configuration and calibration are data, not executable blobs.

The stock ARM0 kernel, BSP modules and hundreds of userspace ELFs are all replaceable. The custom GCT hardware support in the symbolized kernel is measured in tens of kilobytes per subsystem and exposes rich function names. The genuinely novel work is therefore a small SoC HAL plus GIPC/modem boot, not a mystery megabyte-scale platform rewrite.

## Native BE8 Rust is proven

Stock ARM0 runs ARMv7-A BE8: data is big-endian while instructions are stored little-endian.

A current nightly Rust/LLVM toolchain on Acer was experimentally used to build the checked-in [`targets/armebv7a-none-eabi.json`](../targets/armebv7a-none-eabi.json) target with `core` and `compiler_builtins`. Linking with `ld.lld --be8` produced:

```text
ELF 32-bit MSB executable, ARM, EABI5 BE8 version 1
Flags: ... BE8
```

The linked test image preserved big-endian data (`0x11223344` appears as `11 22 33 44`) while ARM instructions were emitted in BE8 byte order (`e92d4800` stored as `00 48 2d e9`).

Therefore **switching ARM0 to little-endian is not a prerequisite for a Rust-only system**. LE remains useful only for the separate modern-Linux/OpenWrt route because that ecosystem is overwhelmingly little-endian and Rust-for-Linux support is better there.

The target JSON describes big-endian ARMv7-A; the final BE8 transformation is a linker property, so builds must pass `-C link-arg=--be8` (or equivalent `rust-lld --be8`). The proof build used nightly Cargo with `-Zjson-target-spec -Zbuild-std=core,compiler_builtins`.

## What can be reused from `wf830-redox`

The current host stack is already about 24 kLOC of Rust.

Immediately reusable in bare metal:

- `gct-hci`: already `#![no_std]`;
- `gct-lapi`: already `#![no_std]`;
- protocol definitions, endian handling and typed request/response codecs;
- much of request correlation/state-machine logic after separating it from Linux I/O/time primitives.

Linux-specific layers become unnecessary rather than needing ports:

- `/dev/glif0` transport becomes a direct GIPC transport;
- SysV/shared-memory/socket compatibility can disappear;
- `lted` compatibility can disappear unless useful for testing;
- Linux netdevice plumbing from `gdmlte.ko` is replaced by a direct LTE packet endpoint feeding the Rust router/network stack.

## Mandatory hardware for the first useful Rust appliance

The first target is deliberately **not** "implement every peripheral." It is "boot Rust, bring up TK, attach LTE, route packets over Ethernet."

### 1. ARMv7-A startup / exceptions

Need reset/entry handoff from U-Boot, stack/linker layout, exception/vector table, cache/MMU policy, IRQ entry/dispatch, and basic barriers/MMIO helpers. U-Boot can keep doing DDR initialization initially, which removes one of the nastiest early-boot jobs.

### 2. Clock / timer / IRQ core

The live kernel provides named oracles such as `gdm7243_init_clock`, `gdm_init_irq`, `gdm_init_time`, `gdm_timer_interrupt`, `gdm_set_next_event` and `gdm_set_mode`.

Live IRQs on the P4 unit:

| IRQ | Device |
|---:|---|
| 2 | serial0 RX |
| 3 | serial0 TX |
| 10 | GPIO0 |
| 11 | **USIM** |
| 15 | Ethernet |
| 16 | SDHCI slot0 |
| 18 | timer |
| 21 | serial1 RX |
| 22 | serial1 TX |
| 28 | RTC timer |
| 29 | GPIO1 |
| 31 | IPCIF |

Only timer, Ethernet, IPCIF, USIM and one UART are mandatory early.

### 3. UART

The symbolized kernel exposes 46 `gdm_uart*` functions, about 6.9 KiB of named implementation. Console output is the first hardware milestone and an unusually friendly RE target.

### 4. Ethernet + RTL8211 MDIO

The external PHY is ordinary RTL8211. The custom GCT MAC side is roughly 29 named functions / 11.4 KiB of implementation in the current symbol-size accounting.

For bare metal we do not need to reproduce Linux `net_device`, ethtool, tasklets, etc. We need only MAC/descriptor-ring initialization, RX/TX DMA, MDIO link setup, packet send/receive and interrupt handling.

### 5. GIPC / IPCIF / ARM1 shared memory

This is the unique critical block.

The stock kernel exposes about 53 named GIF/GIPC/IPCIF/list-buffer functions, ~15 KiB in the current symbol-size accounting. Useful names include `gipc_init`, `gipc_irb_init`, `gipc_send`, `gipc_get_tx_irb`, `gipc_get_rx_irb`, `gipc_rel_rx_irb`, `gipc_abort`, `ipcif_send_buf`, `ipcif_reg_rx_action`, notifier/IRQ/reset helpers, and the `gif_*`/`glif_*` high-level transport functions.

Existing RE already places the shared IPC register region around `0xF4007000`, reset/status controls near `0xF4007FF8/FFC`, and modem-ready state near `0xF4007444` bit `0x2000`.

Bare metal can expose a small Rust transport trait directly instead of cloning `/dev/glif0`.

### 6. ARM1/TK loader and reset

`modem.ko` is only ~26.7 KiB and is richly symbolized. Its bounded job is to obtain TK/NV, validate/decompress as needed, construct modem boot parameters, copy firmware into modem-visible memory, initialize/reset IPC, release ARM1, wait for modem-ready, and handle reset/crash recovery.

For a first TFTP-loaded Rust image, TK itself can also be supplied externally, so NAND and compression support are not prerequisites.

### 7. LTE/RF NV and calibration

`lte1nv`, `lte2nv`, `cmnnv`, board config and RF calibration are state/data. Preserve unknown records verbatim and parse only the record headers/checksums/fields required to feed TK.

We already have substantial typed decoding for LTE board config in the VNAOLTE tooling. Nothing here requires executing vendor host code.

### 8. **USIM controller**

This is a newly important mandatory dependency.

The live P4 kernel exposes `/dev/usim`, IRQ 11, and substantial physical-card controller code including `usim_open/read/write/ioctl`, `usim_isr`, `init_usim_reg`, `set_gpg2usim`, `restore_usim_state` and `gdm_usim_init`.

TK itself contains the higher UICC/USIM state machine, ATR parsing and APDU logic (`UMM_Send_APDU_Req`, APDU/ATR handling, etc.). The host-side LTE SDK independently proves the split: `libltesdk.so` opens `/dev/usim`, performs power/reset/read/write/ioctl operations, handles ATR/protocol state, and exchanges `LTE_EMBEDED_HOST_UICC_INIT_REQUEST`, `...ACTIVATION_DONE`, `...CMD_REQUEST`, `...READY_ACTIVATION` and related messages with ARM1.

Therefore **ARM0 owns the physical UICC controller and ARM1/TK owns the modem-side UICC protocol/application state**. USIM support is mandatory for a useful LTE-capable Rust image.

### 9. Router/network stack

This is generic Rust engineering, not SoC reverse engineering. A minimal appliance needs Ethernet ARP/IPv4/IPv6, DHCP as desired, routing, NAT44 where needed, ICMP/MTU handling, DNS forwarding/resolution, and TCP/UDP for management.

`smoltcp` or another no-std-capable stack can provide much of the protocol layer. For throughput, LTE↔Ethernet forwarding/NAT should use a deliberately simple zero/minimal-copy fast path rather than reproducing Linux networking architecture.

## Things we can defer entirely

- NAND/ECC/UBI/UBIFS — boot image and TK by TFTP during bring-up;
- SDHCI/SDIO/microSD — later daughterboard work;
- USB 3 / DWC3 — later;
- Wi-Fi — not even loaded on the live P4 system;
- audio/SLIC;
- I2C/SPI unless needed for a specific board device;
- LEDs/buttons/GPIO niceties;
- RTC;
- suspend/deep PM;
- old WiMAX stack and module;
- OEM debug/kmon infrastructure.

The symbolized kernel contains ~56 KiB of named GCT debug/monitor code alone; none of it needs to be reimplemented.

## Custom GCT implementation scale

Current symbol-size accounting from the live symbolized kernel:

| Subsystem | Named functions | Approx. named code/data |
|---|---:|---:|
| GIPC / GLIF / IPCIF | 53 | 15.0 KiB |
| Ethernet/MDIO | 29 | 11.1 KiB |
| UART | 46 | 6.8 KiB |
| IRQ/timer/clock core | 10 | 2.0 KiB |
| GPIO | 9 | 1.1 KiB |
| I2C | 9 | 1.9 KiB |
| NAND/flash | 13 | 5.5 KiB |
| SDHCI | 12 | 10.8 KiB |
| DMAC | 9 | 1.5 KiB |
| debug/monitor (delete) | 129 | 54.5 KiB |

These are not estimates of eventual Rust LOC. They are an order-of-magnitude oracle: the unique host silicon support is compact and symbol-rich.

## Blob inventory

### Required / accepted

| Item | Executable? | Status |
|---|---|---|
| SoC mask ROM | yes | immutable hardware; unavoidable |
| ARM1 TK firmware | **yes** | one ~6.2 MiB monolithic proprietary modem image; keep |
| LTE/RF calibration/NV | no | data; preserve |

### Optional

| Item | Executable? | Status |
|---|---|---|
| stock U-Boot | yes, GPL vendor build | keep initially for DDR/TFTP/recovery; replace later for completeness |
| RTL8192E MCU firmware | yes, ~24 KiB variants embedded in stock driver | only if onboard Wi-Fi is retained; live P4 does not currently load it |

### Delete / replace

- Linux 3.10 kernel and all GCT modules;
- OEM rootfs/userspace (270 BE8 ELFs in the extracted rootfs);
- `libltesdk`, `liblted`, NVM/config helpers;
- WiMAX/EAP stack;
- netfilter/Linux networking stack if using bare metal;
- all OEM monitoring/web/router daemons.

## TK is one blob, not a matryoshka doll

The decompressed TK payload was scanned for nested container/image signatures: no ELF, gzip/XZ/bzip2/ZIP, uImage/FIT/FDT, UBI/UBIFS/squashfs, LZ4 or Zstd. 717 byte positions looked like possible RFC1950/zlib headers, but **zero** terminated as valid zlib streams when actually decompressed.

64 KiB entropy windows look like linked code/data rather than large compressed/encrypted payloads. LTE L1/L2/L3, RF, NAS, RRC, UICC and diagnostic strings all live directly in the image.

There may still be opaque tables or accelerator microcode with no container magic, but for system architecture TK is best treated as **one linked modem firmware artifact**, not a loader for a hidden collection of independent firmware blobs.

## Public prior art

Useful public work exists above and beside this boundary:

- historical Linux `drivers/staging/gdm724x`: GCT GPL HCI/endian/network semantics for USB-attached GDM724x;
- `nedyarrd/lted_mf258`: small host-control reference;
- `patryk4815/openwrt-gdm7243-lte`: mature Zig/OpenWrt daemon using a GDM7243 as an Ethernet-attached modem (AT TCP/7788, UDP keepalive, VLAN data);
- Huawei B5328 / URoad / BOLT work: bootloader, partition and recovery oracles.

No indexed public copy of the integrated ARM0 GDM7243Q files such as `arch/arm/plat-gdm/gipc/gipc.c`, `gdm_ether.c`, `gdm_sdhost.c`, `serial_gdm.c` or `pm7243q.c` has been found yet.

So the genuinely novel work is the small on-chip GCT ARM0 HAL/GIPC layer.

## Staged bring-up

### Phase 0 — prove Rust owns ARM0

Stock U-Boot exposes `tftpboot`, `go`, raw memory access, DRAM tests and `bootm`. The `go` command is explicitly present as "start application at address 'addr'", so the first Rust payload does **not** need a Linux/uImage wrapper: TFTP a flat linked image into safe DDR and jump straight to its entry point. This is ideal for repeated bring-up with no NAND writes.

- U-Boot TFTP/load a flat BE8 Rust image and `go` to its entry;
- print over UART;
- verify RAM, timer and exception handling;
- verify MMIO reads against known stock values.

### Phase 1 — networked Rust monitor

- IRQ controller + timer;
- Ethernet/MDIO;
- simple DHCP/static management IP;
- remote register/debug console.

### Phase 2 — boot ARM1

- GIPC/IPCIF rings;
- modem reset/startup-vector sequence;
- feed TK + NV;
- receive first HCI/DM messages;
- reuse `gct-hci` / `gct-lapi` directly.

### Phase 3 — SIM and LTE attach

- implement USIM physical controller/proxy;
- port/refactor `gct-runtime` core into `no_std + alloc`;
- attach/register/activate bearer;
- obtain bearer IP state.

### Phase 4 — actual router

- direct LTE packet channel;
- Ethernet LAN;
- routing/NAT/DHCP/DNS;
- watchdog and crash recovery.

At this point stock Linux and every stock userspace executable are unnecessary.

### Phase 5 — local persistent boot

- Rust NAND/ECC support;
- simple own A/B image/data format rather than recreating UBI/UBIFS unless compatibility is useful;
- boot Rust and TK from flash.

### Phase 6 — toys

- SDIO/microSD;
- USB3;
- daughterboard/debug buses;
- optional replacement Wi-Fi;
- power management;
- eventually replace U-Boot if the pride budget demands it. The stock `mtd00` begins with executable ARM code rather than a uImage header and includes DDR/PLL/NAND bring-up; replacing it therefore means reproducing the mask-ROM handoff plus early DDR/clock/NAND initialization, not merely swapping a second-stage file loader.

## What remains non-Rust at each milestone

| Milestone | Non-Rust executable code after reset |
|---|---|
| first Rust image | mask ROM + stock U-Boot + TK |
| Rust local-boot appliance | mask ROM + stock U-Boot + TK |
| Rust bootloader too | **mask ROM + TK only** |
| replace TK | effectively an LTE baseband/PHY project; not a rational compatibility target |

## Bottom line

The practical "all Rust" WF830 is not blocked by hundreds of blobs. It is blocked by a **small, symbol-rich ARM0 hardware layer** and one genuine modem firmware blob that we intentionally keep.

The most attractive target is:

> **mask ROM → stock U-Boot (temporarily) → one BE8 Rust image on ARM0 → one TK firmware image on ARM1**

with LTE/RF calibration carried as data.

That is a far smaller and more coherent project than a Linux/OpenWrt forward port if the goal is the gloriously unnecessary claim that the appliance runtime is Rust because we can.
