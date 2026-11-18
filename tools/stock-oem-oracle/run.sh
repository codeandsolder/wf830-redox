#!/usr/bin/env bash
set -euo pipefail

tool_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_dir=$(cd "$tool_dir/../.." && pwd)
: "${WF830_OEM_ROOTFS:?Set to the extracted Polish P4 rootfs directory (never copied to the repo)}"
: "${WF830_NATIVE_GCTD:?Set to the compiled native Rust gctd binary}"
: "${WF830_ORACLE_WORK_DIR:?Set to a dedicated scratch directory outside the repo}"
stock=$(realpath -- "$WF830_OEM_ROOTFS")
gctd=$(realpath -- "$WF830_NATIVE_GCTD")
base=$(realpath -m -- "$WF830_ORACLE_WORK_DIR")
[[ "$base" == /* && "$base" != "/" ]] || { echo "Invalid scratch directory" >&2; exit 2; }
[[ -x "$gctd" && -r "$stock/lib/liblted.so" ]] || { echo "Missing native gctd or extracted OEM liblted.so" >&2; exit 2; }
case "$base/" in "$repo_dir/"*) echo "Build/capture output must be outside the git worktree" >&2; exit 2;; esac

client=${1:-ltesms}
case "$client" in
    ltesms|lted_cli|ltebip|lteautocm|ipatc|attach_probe|pdn_probe|plmn_probe|rrc_probe) ;;
    *) echo "Unknown OEM client: $client" >&2; exit 2 ;;
esac
mode=${2:-normal}
case "$mode" in
    normal) early=0; layout=normal ;;
    early) early=1; layout=normal ;;
    split) early=0; layout=split ;;
    coalesced) early=0; layout=coalesced ;;
    *) echo "usage: $0 [stock-client|attach_probe|pdn_probe|plmn_probe|rrc_probe] [normal|early|split|coalesced]" >&2; exit 2 ;;
esac
[[ "$early" == 0 || "$client" == ltesms ]] || { echo "Early-PSInit test is only defined for ltesms" >&2; exit 2; }

mkdir -p "$base"/{bin,fixtures,logs,uvcache,sysroot/lib,sysroot/usr/lib}

# Extract only the deterministic synthetic HCI response fixtures from Rust tests.
UV_CACHE_DIR="$base/uvcache" uv run --no-project python "$tool_dir/generate_fixtures.py" \
    "$repo_dir/crates/lted-bridge/src/tests.rs" "$base/fixtures" >/dev/null

# Recover SONAME symlinks absent from the extracted UBIFS. These links are
# created in the scratch sysroot only, never in the immutable stock dump.
for folder in lib usr/lib; do
    for file in "$stock/$folder/"*; do
        [[ -f "$file" ]] || continue
        ln -sfn -- "$file" "$base/sysroot/$folder/${file##*/}"
        soname=$(readelf -d "$file" 2>/dev/null |
            sed -n 's/.*(SONAME).*\[\([^]]*\)\].*/\1/p' | head -1 || true)
        if [[ -n "$soname" && ! -e "$base/sysroot/$folder/$soname" ]]; then
            ln -s -- "${file##*/}" "$base/sysroot/$folder/$soname"
        fi
    done
done
ln -sfn -- "$stock/lib/ld-uClibc-0.9.33.2.so" "$base/sysroot/lib/ld-uClibc.so.0"

# Compile our own small ARM BE8 harness; only OEM .so files are used at runtime.
case "$client" in
    attach_probe|pdn_probe|plmn_probe|rrc_probe)
        family=${client%_probe}
        define=()
        if [[ "$family" != attach ]]; then define=(-D"WF830_${family^^}"); fi
        clang -target armeb-unknown-linux-gnueabi -march=armv7-a -marm \
            -nostdlib -fno-builtin -fuse-ld=lld "${define[@]}" \
            -Wl,-e,_start -Wl,-dynamic-linker,/lib/ld-uClibc.so.0 \
            -Wl,--allow-shlib-undefined -L"$base/sysroot/lib" \
            -o "$base/bin/$client" "$tool_dir/guest/stock_request_probe.c" \
            -l:liblted.so -l:libpthread.so.0 -l:libc.so.0
        ;;
esac

# If a guest was compiled for the first time, the symlink recovery above was
# intentionally done before invocation. Earlier runs may already provide links.
# The live daemon socket and SysV IPC IDs exist exclusively inside the test's
# disposable IPC/mount namespaces.
bwrap --unshare-user --unshare-pid --unshare-ipc --unshare-net \
    --ro-bind / / --dev-bind /dev /dev --proc /proc \
    --tmpfs /tmp --tmpfs /var/tmp --bind "$base" "$base" \
    --chdir "$base/logs" \
    --setenv UV_CACHE_DIR "$base/uvcache" \
    --setenv PYTHONDONTWRITEBYTECODE 1 \
    --setenv WF830_ORACLE_WORK_DIR "$base" \
    --setenv WF830_OEM_ROOTFS "$stock" \
    --setenv WF830_NATIVE_GCTD "$gctd" \
    --setenv WF830_STOCK_CLIENT "$client" \
    --setenv WF830_EARLY_CLIENT "$early" \
    --setenv WF830_RESPONSE_LAYOUT "$layout" \
    --setenv WF830_STRACE "${WF830_STRACE:-0}" \
    -- uv run --no-project python "$tool_dir/oracle.py"
