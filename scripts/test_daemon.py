#!/usr/bin/env python3
"""
Integration test suite for Privacy Sentinel native daemon (sentineld) & CLI (sentinelctl).
Verifies:
  1. 127.0.0.1 token enforcement (401 without token, 200 with 256-bit webui.token)
  2. Zero-port UNIX socket RPC via sentinelctl
  3. Binary SOCK_DGRAM telemetry ingestion & 15,000-capacity ring buffer config
  4. Read-only policy.mmap header magic (0x50534E54) & per-UID bitmask sync
  5. Zero-Touch protection on Google Play Services (UID 10212)
  6. Deep Sleep 3-mode rule compilation (Linux 5.10 iptables + AOSP IntentFirewall XML)
  7. Interactive Android 17 Permission Prompt lifecycle (trigger -> resolve)
"""

import json
import os
import shutil
import socket
import struct
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SENTINELD = ROOT / "build" / "host" / "sentineld"
SENTINELCTL = ROOT / "build" / "host" / "sentinelctl"
WEBROOT = ROOT / "module" / "webroot"


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def http_post(port: int, path: str, payload: dict, token: str = "") -> tuple[int, dict]:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=data,
        method="POST",
        headers={"Content-Type": "application/json", **({"X-Sentinel-Token": token} if token else {})},
    )
    try:
        with urllib.request.urlopen(req, timeout=3) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8"))


def main() -> None:
    assert SENTINELD.exists(), f"Missing {SENTINELD}"
    assert SENTINELCTL.exists(), f"Missing {SENTINELCTL}"

    tmp_base = Path(tempfile.mkdtemp(prefix="sentinel_test_"))
    port = find_free_port()

    proc = subprocess.Popen(
        [
            str(SENTINELD),
            "--base-dir", str(tmp_base),
            "--webroot", str(WEBROOT),
            "--bind", "127.0.0.1",
            "--port", str(port),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    try:
        # Wait for socket & token creation
        token_file = tmp_base / "run" / "webui.token"
        for _ in range(40):
            if token_file.exists() and (tmp_base / "run" / "sentinel.sock").exists():
                break
            time.sleep(0.05)

        assert token_file.exists(), "webui.token was not created"
        token = token_file.read_text().strip()
        assert len(token) == 64, f"Expected 64-char hex token, got {len(token)}"

        # 1. Verify strict 401 Unauthorized without token
        code_no_tok, _ = http_post(port, "/api/v1/status", {})
        assert code_no_tok == 401, f"Expected 401 without token, got {code_no_tok}"

        # 2. Verify authenticated status & 15,000 ring buffer capacity
        code_ok, st = http_post(port, "/api/v1/status", {}, token=token)
        assert code_ok == 200 and st["ok"] is True
        assert st["ring_capacity"] == 15000, f"Expected ring_capacity=15000, got {st['ring_capacity']}"
        assert st["device"]["codename"] == "garnet"

        # 3. Verify zero-port sentinelctl CLI over UNIX socket
        ctl_out = subprocess.check_output(
            [str(SENTINELCTL), "--base-dir", str(tmp_base), "status"],
            timeout=3,
        ).decode("utf-8")
        ctl_json = json.loads(ctl_out)
        assert ctl_json["ok"] is True

        # 4. Emit datagram telemetry via sentinelctl and confirm ingestion
        subprocess.check_call(
            [
                str(SENTINELCTL), "--base-dir", str(tmp_base),
                "emit", "10261", "com.zhiliaoapp.musically", "1",
                "DNS_PRE_DOH", "mon.musical.ly", "Unit test DNS event",
            ],
            stdout=subprocess.DEVNULL,
        )
        time.sleep(0.05)
        _, dash = http_post(port, "/api/v1/dashboard", {"limit": 10}, token=token)
        assert any(ev["target"] == "mon.musical.ly" for ev in dash["events"]), "DGRAM telemetry not recorded"

        # 5. Verify policy.mmap binary header & per-UID update
        mmap_file = tmp_base / "run" / "policy.mmap"
        raw = mmap_file.read_bytes()
        magic, version, gen, seed = struct.unpack_from("<IIQI", raw, 0)
        assert magic == 0x50534E54, f"Unexpected policy.mmap magic: {hex(magic)}"
        assert version == 1

        # Update UID 10292 flags and confirm mmap bitmask reflects it at offset 24 + 10292*4
        new_flags = (1 << 1) | (1 << 8)  # POL_BLOCK_NETWORK | POL_ASK_INTERACTIVE
        _, upd = http_post(port, "/api/v1/update_app", {"uid": 10292, "flags": new_flags}, token=token)
        assert upd["ok"] is True
        raw2 = mmap_file.read_bytes()
        uid_mask = struct.unpack_from("<I", raw2, 24 + (10292 * 4))[0]
        assert uid_mask == new_flags, f"Expected mmap uid_mask={new_flags}, got {uid_mask}"

        # 6. Verify Zero-Touch lock cannot be stripped from Google Play Services (UID 10212)
        http_post(port, "/api/v1/update_app", {"uid": 10212, "flags": (1 << 1)}, token=token)
        gms_mask = struct.unpack_from("<I", mmap_file.read_bytes(), 24 + (10212 * 4))[0]
        assert gms_mask == 1, f"Zero-Touch exemption must remain 1, got {gms_mask}"

        # 7. Test all 3 Deep Sleep modes & inspect compiled Linux 5.10 iptables + IFW XML
        for mode in (1, 2, 3):
            _, sg = http_post(
                port, "/api/v1/set_global",
                {"sleep_mode": mode, "screen_sleeping": True},
                token=token,
            )
            assert sg["ok"] is True

        _, rules = http_post(port, "/api/v1/inspect_rules", {}, token=token)
        assert "SENTINEL_OUT" in rules["firewall_script"]
        assert "SENTINEL_SLEEP" in rules["firewall_script"]
        assert "SENTINEL_PROXY" in rules["firewall_script"]
        assert "<rules>" in rules["ifw_xml"]

        # 8. Test Interactive Android 17 Permission Prompt lifecycle
        _, trig = http_post(
            port, "/api/v1/trigger_prompt",
            {
                "uid": 10292,
                "package_name": "ru.ozon.app.android",
                "category": 1,
                "resource_title": "TCP Connect -> api.ozon.ru:443",
                "detail": "Integration test prompt",
            },
            token=token,
        )
        assert trig["ok"] is True and trig["prompt_id"] > 0
        _, res_p = http_post(
            port, "/api/v1/resolve_prompt",
            {"prompt_id": trig["prompt_id"], "decision": "allow_once"},
            token=token,
        )
        assert res_p["ok"] is True

        # 9. Verify static WebUI index.html serves cleanly
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=3) as web_resp:
            html = web_resp.read().decode("utf-8")
            assert "Privacy Sentinel" in html

        print("[PASS] All 9 integration checks passed for sentineld & sentinelctl!")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
        shutil.rmtree(tmp_base, ignore_errors=True)


if __name__ == "__main__":
    main()
