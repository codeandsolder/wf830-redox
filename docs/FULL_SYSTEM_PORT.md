# WF830 full-system oxidation / modern OpenWrt scope

See [`OXIDATION_INVENTORY.md`](OXIDATION_INVENTORY.md) for the flash-by-flash, userspace, kernel/BSP and firmware inventory behind this scope.

For the literal all-Rust ARM0 alternative, see [`RUST_ONLY_PLATFORM.md`](RUST_ONLY_PLATFORM.md). Native BE8 Rust output has been proven, so that route does not depend on the LE-kernel experiment below.

This scopes the layer below wf830-redox: replace the GDM7243QT application-side vendor Linux/BSP with modern Linux/OpenWrt while keeping the cellular modem RTOS/PHY firmware on ARM1.

## Boundary

- ARM0/application CPU: Cortex-A7 ARMv7-A, stock Linux 3.10.0-uc0, BE8.
- ARM1/modem CPU: separate uT-Kernel firmware containing LTE NAS/RRC/PDCP/RLC/MAC/PHY and RF calibration/control.

Current wf830-redox is already about 24 kLOC of Rust and owns HCI framing, typed LAPI, direct /dev/glif0 transport, request/runtime correlation, startup, shipped lted compatibility, substantial lteatcm compatibility, and normal LTE control semantics. The hard remaining boundary is kernel-side GCT platform support and ARM0<->ARM1 IPC.

Do not rewrite the LTE modem stack. Extending DM/RF/DMA interfaces is sensible; replacing NAS/RRC/PHY is a modem/certification project measured in person-years.

## Public prior art

Historical Linux drivers/staging/gdm724x is host-side USB modem code, not the integrated SoC BSP. It is still useful independent documentation for GCT HCI/endian/network behavior. It was removed for Linux 6.13 in October 2024 because there were no known users, hardware/docs were unavailable, and GCT did not engage:

- https://github.com/torvalds/linux/commit/1c2d364e7f7fd0e6d2f7317ad6d2cd02b05de02a
- https://github.com/patryk4815/openwrt-gdm7243-lte
- https://github.com/nedyarrd/lted_mf258
- https://github.com/openwrt/openwrt/pull/22783

The OpenWrt-side projects validate AT/TCP 7788, UDP keepalive, VLAN data, CA/cell-lock behavior, but they operate the GDM7243 as an Ethernet-attached modem and do not replace its ARM0 BSP.

## The BSP is less proprietary than it looked

### USB 3: Synopsys DWC3

Stock config has CONFIG_USB_DWC3=y, CONFIG_USB_DWC3_GADGET=y and CONFIG_GDM_USBPHY=y. Live symbols include gdm_dwc3_device, gdm_dwc3_phy2_device, gdm_dwc3_phy3_device, gdm_ehci_device and gdm_ohci_device. Reuse upstream DWC3; reconstruct only GCT PHY/clock/reset/platform glue.

### SDIO/MMC: SDHCI-shaped

Live symbols include gdm_sdhci_probe/request/irq/set_ios/execute_tuning/start_signal_voltage_switch/enable_sdio_irq. This strongly suggests a standard SDHCI-like block with GCT quirks, so SDIO/microSD/Wi-Fi on a daughterboard is a realistic target rather than a full controller RE project.

### Other identified blocks

The symbolized BSP exposes clocks/PLL, IRQ/reset, GPIO/pinmux/PWM, gdm_dmac DMA, timers/RTC, SERIAL_GDM, I2C_GDM, SPI_GDM, GDM NAND+ECC, gdm_eth plus RTL8211, PM/suspend, and GIPC/IPCIF. We have ~26k recovered live-kernel symbols and a Ghidra-ready symbolized kernel ELF.

## Hard pieces

1. Early SoC bring-up: DT/memory/reserved regions, IRQ controller, timer, UART, clocks/resets, pinctrl/GPIO.
2. Ethernet: external RTL8211 is standard; GCT MAC/DMA is proprietary but symbol-rich.
3. NAND/ECC: needed for normal flash boot, but defer with TFTP+initramfs.
4. GIPC/IPCIF: most important proprietary block. Existing RE already maps the MMIO region around 0xF4007000, reset/status near 0xF4007FF8/FFC, modem-ready state near 0xF4007444, firmware loader, boot parameters and tk flow.

The first modern modem bridge should expose a /dev/glif0-compatible ABI so current wf830-redox runs unchanged. We do not need to recreate all legacy LTE kernel modules; boot ARM1, move HCI frames, implement reset/PM enough for normal service, and let Rust own protocol/policy.

## BE8 vs little-endian ARM0

This is the first spike because it changes the cost of everything else. Stock ARM0 is BE8. rustc has an armeb Linux target, but current Rust-for-Linux supports 32-bit ARM only as ARMv7 little-endian:

- https://docs.kernel.org/rust/arch-support.html

Cortex-A7/AArch32 supports configurable data endianness, while BE8 instruction bytes are already little-endian. It is plausible that a tiny U-Boot-loaded handoff can switch ARM0 to ordinary LE before entering a modern kernel. This is not proven on GDM7243Q; MMIO and boot assumptions need testing.

LE spike:
1. TFTP a tiny payload from stock U-Boot.
2. Switch architectural data endianness to LE.
3. Print on the known UART.
4. Verify RAM, timer and IRQ MMIO.
5. Boot minimal LE Linux zImage + DT + initramfs.

If it works, prefer LE: normal ARMv7 OpenWrt/toolchains and Rust-for-Linux become available. If it fails for a hard SoC reason, stay BE8; userspace Rust remains fine, but kernel Rust and distro tooling stay bespoke.

## Practical Rust boundary

Rust should own LTE policy/runtime, diagnostics/RF tooling, management and OpenWrt-facing control. New GCT kernel glue can be Rust where LE + Rust-for-Linux APIs make that sensible. Do not rewrite DWC3, SDHCI, MTD, phylib or other mature upstream subsystems for language purity. A small C platform driver is better than blocking the port on ideology. ARM1 stays vendor firmware.

## Bring-up order

Phase 0: decide LE vs BE8 — UART trampoline, RAM, timer/GIC, minimal Linux/initramfs.
Phase 1: minimum modern Linux — DT, reserved memory, UART, IRQ/timer, clocks/reset, GPIO/pinctrl.
Phase 2: useful OpenWrt box — Ethernet/RTL8211, watchdog, NAND/ECC+UBI, procd/netifd.
Phase 3: restore LTE — GIPC/IPCIF, ARM1 reset/boot, tk loader, /dev/glif0 compatibility, run wf830-redox.
Phase 4: omitted hardware — DWC3, SDHCI/SDIO, I2C/SPI/UART1, USB3/SDIO/microSD/debug daughterboard, LEDs.
Phase 5: PM/recovery/sysupgrade/A-B/upstream-quality cleanup; modernize U-Boot only if useful later.

## Updated scope

| Milestone | Remaining work |
|---|---|
| UART + modern kernel/initramfs | a few days to ~2 weeks |
| Ethernet + NAND + stable OpenWrt shell | +~1-3 weeks |
| GIPC + modem boot + GLIF compatibility | +~1-3 weeks; existing RE may make it shorter |
| USB3 + SDIO + ordinary peripheral glue | +~1-3 weeks; DWC3/SDHCI make this much less scary |
| PM/polish/upstream-quality cleanup | several further weeks |

A practical modern OpenWrt + Rust control plane + LTE + all interesting exposed peripherals now looks like roughly a 1-3 month hobby-scale project, not the old six-month-before-anything-useful estimate. First modern-kernel boot should be much sooner. Full ARM1 LTE replacement is intentionally not a goal.

## Highest-value next actions

1. Do the LE trampoline/kernel spike before writing large drivers.
2. Generate a compact SoC register/driver map from the symbolized stock kernel for clock/reset/UART/IRQ/timer/Ethernet/NAND/GIPC/DWC3-PHY/SDHCI.
3. Start a modern-kernel patch stack with only DT + minimum boot drivers.
4. Preserve /dev/glif0 at the first modem milestone so wf830-redox does not need another transport rewrite.
5. Map the SoM escape routes on the actual carrier PCB before laying out the USB3/SDIO daughterboard.

## Bottom line

- Linux-side LTE userspace: largely solved in Rust.
- Modern ARM0 BSP: substantial but bounded; USB3=DWC3 and SDIO~=SDHCI are major wins.
- GIPC/modem boot: proprietary but already heavily REd and symbol-rich.
- ARM1 LTE stack: keep it.
- Extra hardware: worth pursuing once the kernel is modern.

The LE-vs-BE8 spike is the single decision most likely to turn this from a bespoke legacy port into a mostly normal ARMv7 OpenWrt target with a handful of GCT drivers.
