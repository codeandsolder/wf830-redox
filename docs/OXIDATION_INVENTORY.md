# WF830 oxidation inventory

This inventories everything between the current WF830 and a useful "fully oxidized" host system: modern Linux/OpenWrt on ARM0, Rust for project-owned host logic, and the vendor LTE modem image treated as coprocessor firmware on ARM1.

The distinction matters:

- **Useful total oxidation:** every host-side component we maintain is open and preferably Rust; mature upstream Linux subsystems remain Linux; ARM1 TK stays firmware.
- **Zero proprietary executable payloads:** additionally replace TK (and any Wi-Fi firmware). That means reimplementing the LTE modem/PHY and is intentionally outside the practical project.
- **Literally only Rust ever executes after reset:** impossible in a strict sense because the SoC starts in immutable mask ROM, and pointless if it also means replacing Linux itself. The useful pride target is "all custom ARM0 software is ours and Rust-first."

## Executive result

The stock system looks blob-heavy because the rootfs contains hundreds of BE8 ELFs, but almost all of that complexity is removable rather than hardware-enabling.

At a modern OpenWrt end state:

1. stock OEM userspace disappears completely;
2. stock Linux 3.10 and its GCT BSP/modules disappear completely;
3. U-Boot can be kept temporarily for TFTP/recovery and replaced later if desired;
4. RF/LTE calibration NVRAM remains as **data**, not code;
5. the ARM1 `tk` image remains as the one substantial modem firmware blob;
6. onboard RTL8192ES adds one small embedded Wi-Fi firmware blob only if we choose to keep that radio.

| Target | Proprietary executable code remaining | Practicality |
|---|---|---|
| Rust userland on stock 3.10 | stock U-Boot + stock kernel/BSP/modules + TK (+ RTL8192E firmware if Wi-Fi used) | Already close; useful compatibility milestone. |
| Modern OpenWrt + Rust host stack | TK (+ optional RTL8192E firmware); stock U-Boot can initially remain | Practical and bounded. |
| No proprietary firmware anywhere | none, but requires replacing ARM1 LTE/PHY and likely Wi-Fi microcode | Modem-reimplementation project; not justified. |

## Flash inventory

Live P4 command line:

```text
mtdparts=gdm7243:
  512k(u-boot),512k(env),
  1m(lte1nv),1m(lte2nv),1m(wmnv),1m(cmnnv),1m(cmnnv2),
  4m(rev1),4m(linux),4m(linux2),
  30m(rootfs),30m(rootfs2),
  5m(tk),5m(tk2),
  35m(update),4m(cfg),1m(factory),32m(syslog),1m(zone)
```

The complete dumps in `../wf830/our-device/mtd` classify as follows:

| MTD | Name | Size | Live contents | Oxidation disposition |
|---:|---|---:|---|---|
| 0 | u-boot | 512 KiB | GCT U-Boot 2010.09; ~39% non-erased | Keep for recovery/TFTP initially; replace only for completeness. |
| 1 | env | 512 KiB | U-Boot environment | Data. Keep/migrate. |
| 2 | lte1nv | 1 MiB | populated LTE/RF NV, redundant records | Calibration/config **data**. Preserve. |
| 3 | lte2nv | 1 MiB | populated LTE/RF NV, redundant records | Calibration/config **data**. Preserve. |
| 4 | wmnv | 1 MiB | erased | Nothing to port. |
| 5 | cmnnv | 1 MiB | partly populated common NV | Data; parse/migrate as needed. |
| 6 | cmnnv2 | 1 MiB | erased | Nothing to port. |
| 7 | rev1 | 4 MiB | erased | Nothing to port on this unit. |
| 8 | linux | 4 MiB | Linux 3.10 uImage | Replace. |
| 9 | linux2 | 4 MiB | byte-identical duplicate of `linux` | Replace / recovery slot. |
| 10 | rootfs | 30 MiB | UBI/UBIFS OEM rootfs | Replace with OpenWrt. |
| 11 | rootfs2 | 30 MiB | UBI/UBIFS; only 32 KiB differs from rootfs dump | Replace / recovery slot. |
| 12 | tk | 5 MiB | gzip-compressed modem image | Keep as ARM1 firmware. |
| 13 | tk2 | 5 MiB | same decompressed image as `tk` | Keep as redundant firmware slot. |
| 14 | update | 35 MiB | erased | Reuse if desired. |
| 15 | cfg | 4 MiB | erased | Reuse if desired. |
| 16 | factory | 1 MiB | erased | Preserve layout until semantics are understood. |
| 17 | syslog | 32 MiB | erased | Reuse/remove as desired. |
| 18 | zone | 1 MiB | ~128 KiB programmed; non-executable state format | Data; preserve until decoded. |

`linux/linux2` are byte-identical. `tk/tk2` differ by only two bytes in their compressed partitions; both streams decompress to the exact same 6,215,317-byte payload (SHA-256 `4e965e3b336f9b8117e285576642487df1ee66694d374933674c038e21e307af`).

The decompressed TK image contains no nested ELF, gzip, XZ, bzip2, ZIP or uImage payload by simple magic scanning. Strings expose LTE NAS/RRC/PDCP/RLC/MAC/PHY/RF/DSP functionality directly. For host-system purposes it is best modeled as **one monolithic ARM1 firmware image**, not a loader for a pile of other opaque binaries.

## Boot chain

### Immutable SoC boot ROM

The first code after reset is mask ROM. It cannot be oxidized without changing silicon. Treat it as hardware.

### U-Boot

`mtd00` identifies itself as:

```text
U-Boot 2010.09 (Nov 02 2017 - 10:28:18)GCT GDM7243
```

It is old but unusually useful for bring-up: serial at 921600, NAND read/write/erase, TFTP, direct kernel/rootfs/TK slot commands, and legacy uImage boot. The live environment already contains `tftplinux`, `tftpuboot`, `tftptk`, serial download and dual-slot helpers.

Stock U-Boot is therefore an asset during the modern-kernel port, not a blocker. Replacing it later is optional completeness work.

## ARM0 userspace: large blob count, almost zero hard dependency

The extracted OEM rootfs contains approximately:

- 270 ELF files;
- 144 executables;
- 49 shared objects;
- 77 relocatable kernel modules.

That count dramatically overstates the real problem. uClibc, BusyBox, netfilter, DHCP, lighttpd, ALSA, MTD tools, etc. are ordinary replaceable software. The custom host stack is policy/protocol code, not device firmware.

Notable OEM libraries:

| Library | Size | Role | End state |
|---|---:|---|---|
| `libltesdk.so` | 552,820 | GCT LTE HCI/LAPI SDK | Already being replaced by `gct-lapi`/runtime. |
| `liblted.so` | 133,700 | local client wrapper/API | Compatibility only; replace/remove. |
| `libnvm.so` | 88,172 | host NVM API | Replace with Rust parsers/storage. |
| `libucfg.so` | 31,332 | OEM configuration API | Replace with OpenWrt/UCI or Rust config. |
| `libgpio.so` | 8,696 | host GPIO helper | Replace with kernel GPIO interface. |
| `libcfg_nvram.so` | 4,744 | small NV compatibility shim | Replace. |
| `libgcthttp.so` | 7,216 | OEM HTTP helper | Delete. |
| `libsdk.so` | 99,340 | WiMAX SDK | Delete. |
| `libeap.so` | 1,886,824 | WiMAX/EAP stack | Delete. |

The live system starts `lted`, `lteatcm`, `ltesms`, `ipatc`, `lteautocm`, `lted_cli`, monitoring/diagnostic helpers, router daemons, web UI and even WiMAX services. None is a required binary compatibility dependency in a clean OpenWrt system.

Current `wf830-redox` is already about **24.3 kLOC of Rust** with roughly **246 test markers**. It owns HCI framing, `/dev/glif0` transport, typed LAPI, request correlation/runtime, shipped `lted` compatibility, broad `lteatcm`/connection-manager compatibility and the recovered host-network state feeds. No `TODO`/`FIXME`/`todo!`/`unimplemented!` markers are present in the Rust crates at this inventory point.

Therefore **there is no OEM userspace binary that must survive**.

## ARM0 kernel/BSP: the real host oxidation frontier

The stock kernel is Linux 3.10.0-uc0, ARM BE8. We have the raw image, recovered/symbolized ELF, ~26k live symbols, unstripped GCT modules, original compiler/source-path strings, working hardware, and close-family documentation.

This is a forward-port/RE project, not an opaque-kernel problem.

### Original source decomposition leaked by the kernel

The image contains literal paths including:

```text
arch/arm/mach-gdm7243q/pm7243q.c
arch/arm/plat-gdm/cpu.c
arch/arm/plat-gdm/gdm_dma.c
arch/arm/plat-gdm/gdm_hl_if.c
arch/arm/plat-gdm/gdm_mux_if.c
arch/arm/plat-gdm/gipc/gipc.c
arch/arm/plat-gdm/hci_sys.c
arch/arm/plat-gdm/ipcif.c
arch/arm/plat-gdm/kmon/kmon.c
arch/arm/plat-gdm/kmon/kmon_net.c
arch/arm/plat-gdm/listb.c
arch/arm/plat-gdm/pm.c
arch/arm/plat-gdm/time.c
drivers/mmc/host/gdm_sdhost.c
drivers/net/ethernet/gdm/gdm_ether.c
drivers/tty/serial/serial_gdm.c
```

The separate LTE modules are GPL-tagged. `gdmlte.ko` leaks its original source path as `component/standalone/lte/drv/gdm_lte.c`; `host_cat.ko` and `ipc_dump.ko` expose their source filenames too.

No matching integrated GDM7243Q BSP source tree has yet been found locally or in indexed public-source searches. Public Linux `drivers/staging/gdm724x` is genuine GCT GPL source and useful for HCI/endian/network semantics, but targets an externally attached GDM724x USB modem rather than the integrated ARM0/GIPC platform.

### Rough custom-code footprint

Approximate stock text spans from the symbolized kernel (not a formal size audit; small neighboring helpers can be included):

| Block | Approx. stock text | What must be done |
|---|---:|---|
| GIF/GIPC/IPCIF | ~20.5 KiB | Critical: ARM0↔ARM1 transport/shared rings/IRQ/reset. |
| DMAC | ~2.6 KiB | Small custom DMA controller helper/driver. |
| Ethernet | ~24.7 KiB | GCT MAC/DMA; use upstream phylib for RTL8211. |
| SD/MMC | ~19.7 KiB | Port `gdm_sdhci_*` quirks/host glue. |
| NAND/ECC | ~14.8 KiB | GCT NAND/ECC; defer behind TFTP/initramfs. |
| serial | ~7 KiB | UART driver; needed early unless generic-compatible. |
| I2C | ~3.6 KiB | Conventional and optional early. |
| GPIO | ~2.8 KiB | Small board-control driver. |
| clocks/timer/RTC | ~1.3 KiB named core | Plus surrounding platform/IRQ/reset setup. |

The important scale result is that custom silicon support is measured in **tens of kilobytes per subsystem, not megabytes**.

### Early platform core

A modern kernel needs CPU/memory/reserved-memory description, interrupt controller, timer/clocksource, clocks/PLL/reset, UART, pinmux/GPIO and ARM1 shared memory.

Symbols such as `gdm7243_init`, `gdm7243_map_io`, `gdm_init_irq`, `gdm_init_clock`, `gdm_setup_clocks`, `gdm_init_time` and `gdm_init_sys_pad` make this bounded.

### GIPC / IPCIF / GIF

This is the most important unique block and unusually exposed.

The stock symbol map includes:

- `gif_add_hdriver`, `gif_add_ldriver`, `glif_open`, `gif_read`, `gif_write`, `gif_poll`, `gif_ioctl`;
- `ipcif_reg_rx_action`, `ipcif_register_notifier`, `ipc_irq_handler`, `ipcif_send_buf`, `ipcif_rel_rx_irb`;
- `gipc_send`, `gipc_get_tx_irb`, `gipc_get_rx_irb`, `gipc_rel_rx_irb`, `gipc_abort`, `gipc_init`, `gipc_irb_init`.

The image also leaks the original files `gdm_hl_if.c`, `gipc/gipc.c`, `ipcif.c` and `listb.c`.

This is the main thing between modern Linux and the already-working Rust modem stack. The first port should deliberately preserve `/dev/glif0` so `gctd` runs unchanged.

### `board.ko`

Only 2,948 bytes, GPL-tagged. It mostly registers GCT platform devices and platform data. It should disappear into DT/platform setup.

### `modem.ko`

26,692 bytes, GPL-tagged and GCT-authored.

Its job is conceptually small but critical:

- choose/read active TK and NV data;
- validate/decompress firmware;
- allocate/map modem memory;
- set boot parameters/startup vector;
- boot/reset ARM1;
- initialize/reset IPC;
- crash/PM handling.

Defined functions include `read_tk_image`, `load_modem_fw_main`, `set_modem_param`, `req_load_modem_fw`, `gdm_modem_probe` and reset/PM paths. Dependencies (`gipc`, `ipcif_send_buf`, `load_nv`, `gdm_flash_read`, reset helpers) expose the architecture well.

This is a good Rust-for-Linux candidate once ARM0 is little-endian, or a tiny C forward port if that accelerates bring-up.

### `gdmlte.ko`

46,148 bytes, GPL-tagged and GCT-authored.

It converts GIPC LTE data channels into Linux netdevices and QoS/rate-control behavior. Major functions include `gdm_lte_ipc_rx_handler`, `gdm_lte_start_xmit`, `gdm_lte_ioctl`, probe/remove, and proc/debug/rate-control paths.

Possible replacements:

1. forward-port only its useful data path as a modern netdev;
2. implement a Rust kernel netdev once APIs/architecture allow it;
3. expose the data GIPC channel to userspace and feed TUN from Rust (maximum kino, potentially worse for a 300 Mb/s-class datapath).

It is not an irreplaceable blob.

### Optional old modules

- `gdmnet.ko` (12,280 B): LTE/DM socket/UART mux; unnecessary if Rust owns modem control.
- `host_cat.ko` (4,724 B): diagnostic path; optional.
- `ipc_dump.ko` (6,848 B): debug/netlink dump; delete.
- `wimax.ko` (8,344 B): delete with WiMAX.

## Standard-ish peripherals: do not RIIR mature subsystems

### USB 3

Stock configuration identifies Synopsys DWC3 plus GCT PHY/platform glue (`CONFIG_USB_DWC3`, `CONFIG_USB_DWC3_GADGET`, `CONFIG_GDM_USBPHY`). The kernel exports `gdm_dwc3_device`, `gdm_dwc3_phy2_device`, and `gdm_dwc3_phy3_device`.

Use upstream DWC3. Reconstruct only GCT clocks/resets/PHY/platform glue.

### SDIO/MMC

The older close-family config used `CONFIG_MMC_GDM`; P4 symbols include `gdm_sdhci_probe`, `request`, `irq`, `set_ios`, `execute_tuning`, `start_signal_voltage_switch`, `enable_sdio_irq`. The leaked filename is `drivers/mmc/host/gdm_sdhost.c`.

This is custom host glue, but Linux-facing behavior is already MMC/SDHCI-shaped.

### Ethernet

The external PHY is RTL8211 and should use normal phylib. Only the GCT MAC/DMA side is custom. The stock driver is roughly 25 KiB and richly symbolized.

### NAND/ECC

GCT-specific NAND/ECC is needed for normal flash operation but **not** for the first modern kernel. Stock U-Boot can TFTP kernel/initramfs while it is ported.

### UART / GPIO / I2C / SPI / RTC / DMA

All are small conventional platform drivers. None requires a separate firmware blob. Port only what the board uses.

## Wi-Fi is the extra firmware-blob wrinkle

The stock `rtl8192es.ko` is ~1.0 MiB and is an out-of-tree-style Realtek driver, not a GCT platform secret. It embeds two RTL8192E firmware arrays:

```text
data_rtl8192Efw    0x5df4 bytes (~23.5 KiB)
data_rtl8192EfwMP  0x6038 bytes (~24.1 KiB)
```

So retaining onboard RTL8192ES means retaining Realtek MCU firmware even if the host driver is open/replaced.

Choices: accept the small peripheral firmware; omit onboard Wi-Fi; or add a better USB3/SDIO radio on the planned daughterboard and choose its firmware/openness tradeoff deliberately.

## ARM1 TK: the actual irreducible modem blob

The one major proprietary executable payload worth keeping is TK: **6,215,317 bytes decompressed**.

It contains, in one linked image, uT-Kernel/runtime services, LTE NAS/RRC, PDCP/RLC/MAC, PHY/DSP, RF calibration/RFFE, SIM/USIM, NVM, DM diagnostics, data scheduling and IPC endpoints.

Our Ghidra work makes it unusually inspectable and patchable. That makes it an excellent **firmware coprocessor**, not a good rewrite target.

Replacing TK means implementing and validating an LTE Release-10/11 modem stack plus PHY/RF calibration. That is where oxidation stops being a router port and becomes a baseband project.

## NV/calibration is not a blob problem

`lte1nv/lte2nv`, common NV and other programmed state contain identity, RF calibration, board routing, PA/RFFE data and similar state. Preserve unknown calibration records verbatim, expose proven fields through typed Rust models, and only write checksumed/versioned structures behind explicit safety gates.

## Endianness and Rust

Stock ARM0 is BE8. Current nightly Rust on Acer exposes `armeb-unknown-linux-gnueabi` as 32-bit big-endian ARM/Linux, so Rust userspace on the stock kernel is possible in principle with an appropriate libc/link/runtime strategy.

Mainline Rust-for-Linux currently supports 32-bit ARM as ARMv7 little-endian. Kernel-side Rust therefore strongly favors changing ARM0 to LE before booting a modern kernel.

Highest-value spike:

1. TFTP a tiny payload from stock U-Boot;
2. switch Cortex-A7 data endianness to LE;
3. prove UART/RAM/MMIO;
4. boot a minimal LE zImage/DT/initramfs;
5. only then commit to Rust platform drivers.

If LE works, this becomes a mostly ordinary ARMv7 OpenWrt target with a small set of GCT-specific drivers.

## Existing public work

### GCT `gdm724x` staging driver

Older upstream/Android kernels contain GCT-authored GPL `drivers/staging/gdm724x` source for GDM7240/7243 USB devices. Our local RROS corpus contains it under `sources/eos/EOS/src/RROS/drivers/staging/gdm724x/`.

It does **not** contain the integrated ARM0 BSP, but gives exact HCI framing, endian conversion, LTE command/event IDs, mux/network conventions and historical GCT driver structure.

### OpenWrt / other devices

Projects such as `patryk4815/openwrt-gdm7243-lte`, plus public B5328, URoad/Home2 and BOLT/PL100 work, provide compatibility, boot, partition and recovery oracles. No indexed public copy of the integrated source files (`arch/arm/plat-gdm/gipc/gipc.c`, `gdm_ether.c`, `gdm_sdhost.c`, etc.) has been located yet. A GPL source bundle from any GDM7243Q CPE could collapse much of the BSP RE immediately.

## What actually stands between us and the end state

1. **LE boot proof** — architectural fork.
2. **Minimal SoC support** — DT + IRQ/timer/clock/reset/UART/pinctrl.
3. **Ethernet** — enough GCT MAC support for a comfortable networked OpenWrt shell.
4. **GIPC/IPCIF + ARM1 boot** — ~20 KiB IPC core plus useful `modem.ko` semantics, preserving `/dev/glif0`.
5. **LTE data plane** — replace useful `gdmlte.ko` semantics.
6. **NAND/ECC + UBI** — normal flash/sysupgrade; defer until TFTP kernel is healthy.
7. **USB3/SDIO toys** — daughterboard, microSD, better Wi-Fi, extra buses.
8. **Polish** — PM/watchdog/crash recovery/A-B/upstream-quality drivers/optional bootloader modernization.

## Blob scorecard at the useful end state

| Component | Executable proprietary blob? | Must remain? |
|---|---|---|
| SoC mask ROM | yes, immutable silicon ROM | physically unavoidable |
| U-Boot | vendor build, GPL and replaceable | no; keep initially because useful |
| Linux kernel | no; upstream/open build | no OEM binary |
| GCT BSP/kernel modules | no after port; our source | no OEM binary |
| OEM rootfs/userspace | no | delete |
| LTE TK / ARM1 modem firmware | **yes** | **yes for practical LTE** |
| LTE/RF NV + calibration | data, not executable | yes |
| RTL8192E Wi-Fi firmware | yes if onboard Wi-Fi retained | optional |
| Ethernet PHY | no external firmware blob observed | no host blob |
| USB3/SDIO/NAND/etc. | no firmware blob required | open drivers |

Thus:

> **One big executable firmware blob (TK), optionally one tiny Wi-Fi firmware blob, and calibration data. Everything else can be ours.**

## Recommended next work

1. **Do the LE trampoline now.**
2. Generate a SoC/register inventory from the symbolized kernel/Ghidra, grouped by leaked original source file.
3. Create a minimal modern-kernel/OpenWrt patch stack with UART/IRQ/timer/clock/reset.
4. TFTP it from stock U-Boot; do not touch NAND until healthy.
5. Port Ethernet.
6. Reconstruct GIPC/IPCIF and a minimal ARM1 loader, preserving `/dev/glif0`.
7. Run current `gctd` against TK unchanged.
8. Replace `gdmlte` data-path semantics; declare OEM ARM0 dead.
9. Add USB3/SDIO daughterboard toys.
