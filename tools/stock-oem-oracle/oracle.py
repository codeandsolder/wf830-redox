"""Isolated stock BE8 client / Rust gctd compatibility oracle.

Run with run.sh: the launcher creates a read-only vendor library sysroot
and a disposable user/PID/IPC/network/mount namespace, including /var/tmp.
The HCI peer is a PTY; only explicit PSInit/Online successes are injected.
"""
from __future__ import annotations

import json
import os
import pty
import select
import signal
import struct
import subprocess
import time
import tty
from pathlib import Path

from verify_images import check_family

ROOT = Path(os.environ["WF830_ORACLE_WORK_DIR"])
STOCK_ROOT = Path(os.environ["WF830_OEM_ROOTFS"])
GCTD = Path(os.environ["WF830_NATIVE_GCTD"])
LOG = ROOT / "logs"
CLIENT = os.environ.get("WF830_STOCK_CLIENT", "ltesms")
EARLY = os.environ.get("WF830_EARLY_CLIENT") == "1"
TRACE = os.environ.get("WF830_STRACE") == "1"
RESPONSE_LAYOUT = os.environ.get("WF830_RESPONSE_LAYOUT", "normal")
if RESPONSE_LAYOUT not in ("normal", "split", "coalesced"):
    raise ValueError("unrecognized response layout")
SCENARIO = CLIENT + ("-early" if EARLY else "-"+RESPONSE_LAYOUT)
CLIENTS = {"ltesms", "lted_cli", "ltebip", "lteautocm", "ipatc", "attach_probe", "pdn_probe", "plmn_probe", "rrc_probe"}
PS_INIT, ONLINE = 0x312E, 0x3121
PS_INIT_RESPONSE, ONLINE_RESPONSE = 0xB12F, 0xB122
ATTACH_RESPONSE = ROOT / "fixtures" / "attach-response-test-fixture.bin"
PDN_RESPONSE = ROOT / "fixtures" / "pdn-response-test-fixture.bin"
PLMN_RESPONSE = ROOT / "fixtures" / "plmn-response-test-fixture.bin"
ATTACH_REQUEST_GOLDEN = bytes.fromhex(
    "31010043012001010201750301700408696e7465726e65741e01020501030101015c021234"
    "5d02aabb5f0104600105700103620100f5020100f6010171060014012c000af70101"
)
PLMN_REQUEST_GOLDEN = bytes.fromhex("3109000a0162f010620103630104")
PDN_REQUEST_GOLDEN = bytes.fromhex("3105003211012001010403696d730201750301700501021e01040101035c0212345d02aabbf601057106000a0014001ef70106700101")


def terminate(proc: subprocess.Popen[bytes]) -> None:
    if proc.poll() is None:
        os.killpg(proc.pid, signal.SIGTERM)
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait(timeout=2)


def client_command() -> list[str]:
    cmd = [
        "qemu-armeb", "-L", str(ROOT / "sysroot"),
        "-E", "LD_LIBRARY_PATH=/lib:/usr/lib",
        str(ROOT / "bin" / CLIENT) if CLIENT.endswith("_probe") else str(STOCK_ROOT / "usr/lte" / CLIENT),
    ]
    if TRACE:
        cmd = [
            "strace", "-ff", "-s", "1024", "-xx",
            "-e", "sendto,sendmsg,recvfrom,recvmsg",
            "-o", str(LOG / f"{SCENARIO}.trace"), *cmd,
        ]
    return cmd


def inject_response(master: int, frame: bytes) -> None:
    if RESPONSE_LAYOUT == "split":
        offset = 0
        for n in (1, 2, 1, 3, 5, 8, 13, 21, len(frame)):
            part = frame[offset:offset+n]
            if not part:
                return
            os.write(master, part)
            offset += len(part)
            # Force the GLIF reader to observe incomplete headers and TLVs.
            time.sleep(0.016)
    elif RESPONSE_LAYOUT == "coalesced":
        # Unknown but complete HCI notifications on both sides of the real
        # synthetic response; decoder must still route the matching response.
        noise = bytes.fromhex("beef0002aabb")
        os.write(master, noise + frame + noise)
    else:
        os.write(master, frame)


def main() -> int:
    if CLIENT not in CLIENTS:
        raise ValueError(f"Unsupported client: {CLIENT}")
    LOG.mkdir(exist_ok=True)
    master, slave = pty.openpty()
    tty.setraw(slave)
    daemon_log_path = LOG / f"gctd-{SCENARIO}.log"
    client_log_path = LOG / f"{SCENARIO}.log"
    requests: list[tuple[int, bytes]] = []
    client = None
    saw_ps_init = saw_online = False
    held_ps_init_at = None
    with daemon_log_path.open("wb") as daemon_log, client_log_path.open("wb") as client_log:
        daemon = subprocess.Popen(
            [str(GCTD), "--no-startup-handshake", "--device-id", "1", os.ttyname(slave)],
            stdout=daemon_log, stderr=subprocess.STDOUT, start_new_session=True,
        )
        client_start = None
        buffer = bytearray()
        try:
            deadline = time.monotonic() + 12
            while time.monotonic() < deadline:
                if daemon.poll() is not None:
                    break
                if EARLY and held_ps_init_at is not None and time.monotonic() - held_ps_init_at > 1:
                    os.write(master, struct.pack(">HHI", PS_INIT_RESPONSE, 4, 0))
                    held_ps_init_at = None
                if client is None and (
                    (saw_ps_init and saw_online)
                    or (EARLY and saw_ps_init and Path("/var/tmp/lted-daemon").exists())
                ):
                    client = subprocess.Popen(
                        client_command(), stdin=subprocess.PIPE,
                        stdout=client_log, stderr=subprocess.STDOUT, start_new_session=True,
                    )
                    if CLIENT == "lted_cli" and client.stdin is not None:
                        client.stdin.write(b"help\nquit\n")
                        client.stdin.flush()
                    client_start = time.monotonic()
                if client_start is not None and time.monotonic() - client_start > 5:
                    break
                ready, _, _ = select.select([master], [], [], 0.10)
                if not ready:
                    continue
                chunk = os.read(master, 65536)
                buffer.extend(chunk)
                while len(buffer) >= 4:
                    opcode, length = struct.unpack_from(">HH", buffer)
                    if len(buffer) < 4 + length:
                        break
                    payload = bytes(buffer[4:4 + length])
                    del buffer[:4 + length]
                    requests.append((opcode, payload))
                    print(f"HCI TX opcode=0x{opcode:04x} payload={payload.hex()}")
                    if opcode == PS_INIT:
                        saw_ps_init = True
                        if EARLY:
                            held_ps_init_at = time.monotonic()
                        else:
                            os.write(master, struct.pack(">HHI", PS_INIT_RESPONSE, 4, 0))
                    elif opcode == ONLINE:
                        saw_online = True
                        os.write(master, struct.pack(">HHI", ONLINE_RESPONSE, 4, 0))
                    elif opcode == 0x3101 and CLIENT == "attach_probe":
                        # Existing Rust fixture, not a live modem capture.
                        inject_response(master, ATTACH_RESPONSE.read_bytes())
                    elif opcode == 0x3105 and CLIENT == "pdn_probe":
                        # Existing Rust fixture, not a live modem capture.
                        inject_response(master, PDN_RESPONSE.read_bytes())
                    elif opcode == 0x3109 and CLIENT == "plmn_probe":
                        inject_response(master, PLMN_RESPONSE.read_bytes())
                    elif opcode == 0x3908 and CLIENT == "rrc_probe":
                        inject_response(master, bytes.fromhex("b9090007000000010007aa"))
                    elif opcode == 0x390f and CLIENT == "rrc_probe":
                        inject_response(master, bytes.fromhex("b9100007000000010007bb"))
                    else:
                        print(f"unexpected request opcode 0x{opcode:04x}")
        finally:
            if client is not None:
                terminate(client)
            terminate(daemon)
            os.close(master)
            os.close(slave)

    daemon_text = daemon_log_path.read_text(errors="replace")
    client_text = client_log_path.read_text(errors="replace")
    sequence = [opcode for opcode, _ in requests]
    client_opens = daemon_text.count("stock lted client 0 opened (Some(0))")
    init_queries = daemon_text.count("client 0 SDK command 0 -> 0 HCI bytes")
    expected_queries = 2 if EARLY else 1
    status = "no-compatible-client-exercised"
    if (
        CLIENT == "ltesms"
        and client_opens >= 1
        and init_queries >= expected_queries
        and sequence == [PS_INIT, ONLINE]
        and "SDK request rejected:" not in daemon_text
    ):
        status = "pass"
        if EARLY:
            first = daemon_text.find("client 0 SDK command 0")
            ps_result = daemon_text.find("Result { kind: PsInit")
            online_result = daemon_text.find("Result { kind: Online")
            last = daemon_text.rfind("client 0 SDK command 0")
            if not (0 <= first < ps_result < online_result < last):
                status = "incorrect-startup-query-order"
    elif CLIENT == "rrc_probe" and client_opens >= 1:
        set_bytes = struct.pack(">HH", requests[2][0],len(requests[2][1])) + requests[2][1] if len(requests)>2 else b""
        get_bytes = struct.pack(">HH", requests[3][0],len(requests[3][1])) + requests[3][1] if len(requests)>3 else b""
        status = "pass" if (
            sequence == [PS_INIT, ONLINE, 0x3908, 0x390f]
            and set_bytes == bytes.fromhex("390800050007000101")
            and get_bytes == bytes.fromhex("390f000400070000")
            and "OEM_INIT ret=0" in client_text
            and "OEM_REGISTER_RRC ret=0" in client_text
            and "OEM_REGISTER_RRC_GET ret=0" in client_text
            and "OEM_RRC_SET_REQUEST ret=0" in client_text
            and "OEM_RRC_GET_REQUEST ret=0" in client_text
            and "OEM_RRC_CALLBACK_COUNT=2" in client_text
            and (LOG/"rrc-set-image.bin").is_file()
            and (LOG/"rrc-set-image.bin").stat().st_size==6
            and (LOG/"rrc-get-image.bin").is_file()
            and (LOG/"rrc-get-image.bin").stat().st_size==7
        ) else "rrc-request-or-callback-mismatch"
    elif CLIENT in ("attach_probe", "pdn_probe", "plmn_probe") and client_opens >= 1:
        label = {"attach_probe": "ATTACH", "pdn_probe": "PDN", "plmn_probe": "PLMN"}[CLIENT]
        request_opcode = {"ATTACH": 0x3101, "PDN": 0x3105, "PLMN": 0x3109}[label]
        expected_request = {"ATTACH": ATTACH_REQUEST_GOLDEN, "PDN": PDN_REQUEST_GOLDEN, "PLMN": PLMN_REQUEST_GOLDEN}[label]
        image_size = {"ATTACH": 0x88b, "PDN": 0x2e6, "PLMN": 436}[label]
        image_file = LOG / (label.lower() + "-image.bin")
        actual_frame = struct.pack(">HH", request_opcode, len(requests[2][1])) + requests[2][1] if len(requests) > 2 else b""
        status = "pass" if (
            sequence == [PS_INIT, ONLINE, request_opcode]
            and actual_frame == expected_request
            and "OEM_INIT ret=0" in client_text
            and f"OEM_REGISTER_{label} ret=0" in client_text
            and f"OEM_{label}_REQUEST ret=0" in client_text
            and f"OEM_{label}_CALLBACK_COUNT=1" in client_text
            and image_file.is_file() and image_file.stat().st_size == image_size
        ) else "request-or-callback-abi-mismatch"
    elif CLIENT == "lted_cli" and client_opens >= 1 and sequence == [PS_INIT, ONLINE]:
        status = (
            "observed-unsupported-cli"
            if daemon_text.count("event CliCommand not implemented") >= 2
            else "unexpected-cli-behavior"
        )

    callback_checks = []
    if status == "pass" and CLIENT.endswith("_probe"):
        families = ["rrc-set", "rrc-get"] if CLIENT == "rrc_probe" else [
            CLIENT.removesuffix("_probe")
        ]
        try:
            callback_checks = [check_family(family) for family in families]
        except (AssertionError, OSError) as error:
            status = f"callback-image-validation-failed: {error}"

    result = {
        "client": CLIENT,
        "scenario": SCENARIO,
        "status": status,
        "callback_checks": callback_checks,
        "hci_tx": [f"{opcode:04x}:{payload.hex()}" for opcode, payload in requests],
        "api_open_count": client_opens,
        "sdk_init_queries": init_queries,
        "early_client": EARLY,
        "response_layout": RESPONSE_LAYOUT,
        "response_fixture_origin": (
            "crates/lted-bridge/src/tests.rs (synthetic golden vector)"
            if CLIENT in ("attach_probe", "pdn_probe", "plmn_probe", "rrc_probe") else None
        ),
        "stock_binary": str(ROOT / "bin" / CLIENT) if CLIENT.endswith("_probe") else str(STOCK_ROOT / "usr/lte" / CLIENT),
        "rust_binary": str(GCTD),
    }
    (LOG / f"{SCENARIO}.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    if status not in ("pass", "observed-unsupported-cli"):
        print("daemon log tail:", daemon_text[-2000:])
        print("client log tail:", client_text[-2000:])
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
