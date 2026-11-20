#!/usr/bin/env python3
"""
clover_configs.py — pull Xray configs out of Clover VPN (net.clovervpn.fast).

How this works (see REPORT.md for the full write-up)
----------------------------------------------------
The app does not use share-links or subscriptions. Its Go core
(`libgojni.so`, package `x_sdk`) fetches a node list from a private API
(`POST /api/v1.0/getNodesV2` on an "xrouter" host) and the server returns,
per node, a `coreType` ("xray" or "singbox") plus a complete, ready-to-run
`coreConfig` JSON document. The client is just a runner for those documents.

After a node is selected, the SDK persists the whole resolved set
(4 channel configs for the chosen country) into

    /data/data/net.clovervpn.fast/shared_prefs/clovervpn_core.xml
        -> key "connectorStartOptions" -> JSON -> nodes[*].coreConfig

which is what this script reads. Reading it needs root (`adb root`), because
the app is not debuggable and the file is 0600 under /data/data.

Live API replay
---------------
Replaying `getNodesV2` directly is possible (endpoints are plain HTTP and
listed in the report), but the request body must be wrapped by the SDK's
`HttpApiRequestEncrypt` (Brotli + a proprietary AES envelope keyed by the
`X-Nl-Crypto-Key` header). Without that envelope the server answers
`43004 "Your app version is too low"`, which is its generic reject for
unencrypted clients. That is why this script harvests the already-resolved
configs rather than re-fetching them.

Usage
-----
    ./clover_configs.py                      # list Xray configs found
    ./clover_configs.py --xrayjson           # write ./configs.json
    ./clover_configs.py --xrayjson --pretty  # pretty-printed
    ./clover_configs.py --xml prefs.xml      # parse a local copy
    ./clover_configs.py --refresh            # reconnect first, then read
    ./clover_configs.py --raw                # full nodes incl. metadata

Requires: adb in PATH, device with root (`adb root`), app installed.
"""

from __future__ import annotations

import argparse
import html
import json
import os
import re
import shutil
import subprocess
import sys

PKG = "net.clovervpn.fast"
PREF_PATH = f"/data/data/{PKG}/shared_prefs/clovervpn_core.xml"
PREF_KEY = "connectorStartOptions"


# --------------------------------------------------------------------------
# adb helpers
# --------------------------------------------------------------------------
def adb(serial: str | None, *args: str, input_bytes: bytes | None = None) -> bytes:
    exe = shutil.which("adb")
    if not exe:
        sys.exit("error: adb not found in PATH")
    cmd = [exe] + (["-s", serial] if serial else []) + list(args)
    p = subprocess.run(cmd, input=input_bytes, capture_output=True)
    if p.returncode != 0:
        msg = p.stderr.decode("utf-8", "replace").strip() or p.stdout.decode("utf-8", "replace").strip()
        raise RuntimeError(f"adb {' '.join(args)} failed: {msg}")
    return p.stdout


def ensure_root(serial: str | None) -> None:
    adb(serial, "root")
    uid = adb(serial, "shell", "id").decode("utf-8", "replace")
    if "uid=0" not in uid:
        sys.exit("error: adb root unavailable; this device does not allow root shell")


def read_prefs(serial: str | None) -> str:
    raw = adb(serial, "exec-out", f"cat {PREF_PATH}")
    if not raw:
        sys.exit(f"error: {PREF_PATH} is empty or missing (is the app installed/running?)")
    return raw.decode("utf-8", "replace")


def refresh_app(serial: str | None) -> None:
    """Best effort: restart the app and press Connect so the SDK resolves nodes."""
    print("[*] restarting app to refresh node cache ...", file=sys.stderr)
    adb(serial, "shell", "am force-stop", PKG)
    adb(serial, "shell", "am start -W -n", f"{PKG}/.ui.MainActivity")
    import time

    time.sleep(6)
    # power button sits near the bottom centre on the main screen
    try:
        adb(serial, "shell", "input", "tap", "540", "2160")
        time.sleep(12)
    except RuntimeError as exc:
        print(f"[!] could not auto-connect: {exc}", file=sys.stderr)


# --------------------------------------------------------------------------
# parsing
# --------------------------------------------------------------------------
def parse_prefs(xml: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for m in re.finditer(r'<string name="([^"]+)">(.*?)</string>', xml, re.S):
        out[m.group(1)] = html.unescape(m.group(2))
    return out


def load_nodes(xml: str) -> list[dict]:
    prefs = parse_prefs(xml)
    blob = prefs.get(PREF_KEY)
    if not blob:
        sys.exit(f"error: pref '{PREF_KEY}' not found (open the app and connect once)")
    try:
        data = json.loads(blob)
    except json.JSONDecodeError as exc:
        sys.exit(f"error: cannot parse {PREF_KEY}: {exc}")
    nodes = data.get("nodes") or []
    if not nodes:
        sys.exit("error: node list is empty; connect once to populate it")
    return nodes


def split_nodes(nodes: list[dict]) -> tuple[list[dict], list[dict]]:
    xray, other = [], []
    for n in nodes:
        cfg_raw = n.get("coreConfig")
        if not cfg_raw:
            continue
        try:
            cfg = json.loads(cfg_raw)
        except json.JSONDecodeError:
            continue
        entry = {
            "nodeId": n.get("nodeId"),
            "coreType": n.get("coreType"),
            "config": cfg,
        }
        (xray if n.get("coreType") == "xray" else other).append(entry)
    return xray, other


def describe(entry: dict) -> str:
    cfg = entry["config"]
    outs = []
    for ob in cfg.get("outbounds", []):
        proto = ob.get("protocol")
        tag = ob.get("tag", "")
        if proto in ("freedom", "blackhole", "dns"):
            continue
        addr = ""
        st = ob.get("settings", {})
        if st.get("servers"):
            s = st["servers"][0]
            addr = f"{s.get('address')}:{s.get('port')}"
        elif st.get("vnext"):
            v = st["vnext"][0]
            addr = f"{v.get('address')}:{v.get('port')}"
        net = ob.get("streamSettings", {}).get("network", "tcp")
        outs.append(f"{proto} {addr} ({net})")
    return f"node {entry['nodeId']}: " + ("; ".join(outs) or "no proxy outbound")


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(
        description="Extract Clover VPN node configs (Xray JSON) from the device.",
    )
    ap.add_argument("-s", "--serial", help="adb serial (default: only attached device)")
    ap.add_argument("--xml", help="parse a local clovervpn_core.xml instead of the device")
    ap.add_argument("--refresh", action="store_true", help="restart+connect the app before reading")
    ap.add_argument("--xrayjson", action="store_true",
                    help="write a list of Xray configs to configs.json next to this script")
    ap.add_argument("--out", help="output path (default: ./configs.json)")
    ap.add_argument("--pretty", action="store_true", help="pretty-print the JSON output")
    ap.add_argument("--raw", action="store_true",
                    help="emit full node records (coreType + coreConfig) instead of bare configs")
    ap.add_argument("--save-prefs", metavar="PATH",
                    help="cache the pulled prefs XML so later runs work offline via --xml")
    args = ap.parse_args()

    if args.xml:
        with open(args.xml, "r", encoding="utf-8") as fh:
            xml = fh.read()
    else:
        ensure_root(args.serial)
        if args.refresh:
            refresh_app(args.serial)
        xml = read_prefs(args.serial)
        if args.save_prefs:
            with open(args.save_prefs, "w", encoding="utf-8") as fh:
                fh.write(xml)
            print(f"[+] saved prefs snapshot -> {args.save_prefs}")

    nodes = load_nodes(xml)
    xray, other = split_nodes(nodes)

    print(f"[+] {len(nodes)} node(s) cached, {len(xray)} xray, {len(other)} other")
    for e in xray:
        print("    " + describe(e))
    for e in other:
        print(f"    node {e['nodeId']}: coreType={e['coreType']} (not Xray)")

    if not args.xrayjson:
        print("\n(use --xrayjson to write configs.json)")
        return 0

    if args.raw:
        payload = nodes
    else:
        payload = [e["config"] for e in xray]

    out_path = args.out or os.path.join(os.path.dirname(os.path.abspath(__file__)), "configs.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2 if args.pretty else None, ensure_ascii=False)
        fh.write("\n")
    print(f"[+] wrote {len(payload)} config(s) -> {out_path}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as exc:
        sys.exit(f"error: {exc}")
    except KeyboardInterrupt:
        sys.exit(130)
