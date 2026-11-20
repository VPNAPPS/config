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
import random
import os
import re
import shutil
import subprocess
import sys

PKG = "net.clovervpn.fast"
PREF_PATH = f"/data/data/{PKG}/shared_prefs/clovervpn_core.xml"
PREF_KEY = "connectorStartOptions"

# ISO 3166-1 alpha-2 -> English short name (fallback: the code itself)
COUNTRY_NAMES = {
    "ad": "Andorra", "ae": "United Arab Emirates", "af": "Afghanistan", "ag": "Antigua and Barbuda",
    "ai": "Anguilla", "al": "Albania", "am": "Armenia", "ao": "Angola", "ar": "Argentina",
    "at": "Austria", "au": "Australia", "aw": "Aruba", "az": "Azerbaijan", "ba": "Bosnia and Herzegovina",
    "bb": "Barbados", "bd": "Bangladesh", "be": "Belgium", "bf": "Burkina Faso", "bg": "Bulgaria",
    "bh": "Bahrain", "bi": "Burundi", "bj": "Benin", "bm": "Bermuda", "bn": "Brunei",
    "bo": "Bolivia", "br": "Brazil", "bs": "Bahamas", "bt": "Bhutan", "bw": "Botswana",
    "by": "Belarus", "bz": "Belize", "ca": "Canada", "cd": "DR Congo", "cf": "Central African Republic",
    "cg": "Congo", "ch": "Switzerland", "ci": "Côte d'Ivoire", "cl": "Chile", "cm": "Cameroon",
    "cn": "China", "co": "Colombia", "cr": "Costa Rica", "cu": "Cuba", "cv": "Cape Verde",
    "cw": "Curaçao", "cy": "Cyprus", "cz": "Czechia", "de": "Germany", "dj": "Djibouti",
    "dk": "Denmark", "dm": "Dominica", "do": "Dominican Republic", "dz": "Algeria", "ec": "Ecuador",
    "ee": "Estonia", "eg": "Egypt", "er": "Eritrea", "es": "Spain", "et": "Ethiopia",
    "fi": "Finland", "fj": "Fiji", "fm": "Micronesia", "fo": "Faroe Islands", "fr": "France",
    "ga": "Gabon", "gb": "United Kingdom", "gd": "Grenada", "ge": "Georgia", "gh": "Ghana",
    "gi": "Gibraltar", "gl": "Greenland", "gm": "Gambia", "gn": "Guinea", "gp": "Guadeloupe",
    "gq": "Equatorial Guinea", "gr": "Greece", "gt": "Guatemala", "gu": "Guam", "gw": "Guinea-Bissau",
    "gy": "Guyana", "hk": "Hong Kong", "hn": "Honduras", "hr": "Croatia", "ht": "Haiti",
    "hu": "Hungary", "id": "Indonesia", "ie": "Ireland", "il": "Israel", "im": "Isle of Man",
    "in": "India", "iq": "Iraq", "ir": "Iran", "is": "Iceland", "it": "Italy",
    "jm": "Jamaica", "jo": "Jordan", "jp": "Japan", "ke": "Kenya", "kg": "Kyrgyzstan",
    "kh": "Cambodia", "ki": "Kiribati", "km": "Comoros", "kn": "Saint Kitts and Nevis", "kp": "North Korea",
    "kr": "South Korea", "kw": "Kuwait", "ky": "Cayman Islands", "kz": "Kazakhstan", "la": "Laos",
    "lb": "Lebanon", "lc": "Saint Lucia", "li": "Liechtenstein", "lk": "Sri Lanka", "lr": "Liberia",
    "ls": "Lesotho", "lt": "Lithuania", "lu": "Luxembourg", "lv": "Latvia", "ly": "Libya",
    "ma": "Morocco", "mc": "Monaco", "md": "Moldova", "me": "Montenegro", "mg": "Madagascar",
    "mh": "Marshall Islands", "mk": "North Macedonia", "ml": "Mali", "mm": "Myanmar", "mn": "Mongolia",
    "mo": "Macao", "mq": "Martinique", "mr": "Mauritania", "ms": "Montserrat", "mt": "Malta",
    "mu": "Mauritius", "mv": "Maldives", "mw": "Malawi", "mx": "Mexico", "my": "Malaysia",
    "mz": "Mozambique", "na": "Namibia", "ne": "Niger", "ng": "Nigeria", "ni": "Nicaragua",
    "nl": "Netherlands", "no": "Norway", "np": "Nepal", "nr": "Nauru", "nz": "New Zealand",
    "om": "Oman", "pa": "Panama", "pe": "Peru", "pf": "French Polynesia", "pg": "Papua New Guinea",
    "ph": "Philippines", "pk": "Pakistan", "pl": "Poland", "pm": "Saint Pierre and Miquelon", "pr": "Puerto Rico",
    "ps": "Palestine", "pt": "Portugal", "pw": "Palau", "py": "Paraguay", "qa": "Qatar",
    "re": "Réunion", "ro": "Romania", "rs": "Serbia", "ru": "Russia", "rw": "Rwanda",
    "sa": "Saudi Arabia", "sb": "Solomon Islands", "sc": "Seychelles", "sd": "Sudan", "se": "Sweden",
    "sg": "Singapore", "si": "Slovenia", "sk": "Slovakia", "sl": "Sierra Leone", "sm": "San Marino",
    "sn": "Senegal", "so": "Somalia", "sr": "Suriname", "ss": "South Sudan", "st": "São Tomé and Príncipe",
    "sv": "El Salvador", "sx": "Sint Maarten", "sy": "Syria", "sz": "Eswatini", "tc": "Turks and Caicos Islands",
    "td": "Chad", "tg": "Togo", "th": "Thailand", "tj": "Tajikistan", "tl": "Timor-Leste",
    "tm": "Turkmenistan", "tn": "Tunisia", "to": "Tonga", "tr": "Türkiye", "tt": "Trinidad and Tobago",
    "tv": "Tuvalu", "tw": "Taiwan", "tz": "Tanzania", "ua": "Ukraine", "ug": "Uganda",
    "us": "United States", "uy": "Uruguay", "uz": "Uzbekistan", "va": "Vatican City", "vc": "Saint Vincent and the Grenadines",
    "ve": "Venezuela", "vg": "British Virgin Islands", "vi": "U.S. Virgin Islands", "vn": "Vietnam", "vu": "Vanuatu",
    "ws": "Samoa", "ye": "Yemen", "yt": "Mayotte", "za": "South Africa", "zm": "Zambia", "zw": "Zimbabwe",
}
DEFAULT_SUFFIX = "CV Fast ⚡️"


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


def node_country(node: dict) -> tuple[str | None, str | None]:
    """Country/region of the node's primary channel (XVPN_PROXY_NODE_CHANNELS)."""
    env = node.get("coreRuntimeEnvVars") or {}
    raw = env.get("XVPN_PROXY_NODE_CHANNELS")
    if not raw:
        return None, None
    try:
        channels = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None, None
    primary = None
    for ch in channels:
        attrs = ch.get("nodeAttrs") or {}
        if attrs.get("linePurpose") != "ad":
            primary = ch
            break
    primary = primary or (channels[0] if channels else None)
    if not primary:
        return None, None
    last = (primary.get("nodeAttrs") or {}).get("lastNode") or {}
    cc = last.get("idcCountry")
    region = last.get("idcRegion")
    return (cc.lower() if isinstance(cc, str) else None), region


def flag_emoji(code: str) -> str:
    return "".join(chr(0x1F1E6 + ord(c) - 65) for c in code.upper())


def country_label(code: str | None, region: str | None, suffix: str,
                  tag: int | None = None) -> str:
    if not code:
        return f"#{tag} {suffix}" if tag is not None else suffix
    name = COUNTRY_NAMES.get(code, code.upper())
    head = f"{flag_emoji(code)} {name}"
    if tag is not None:
        head += f" #{tag}"
    return f"{head} {suffix}"


def split_nodes(nodes: list[dict], suffix: str, remarks: bool = True,
                tags: list[int | None] | None = None) -> tuple[list[dict], list[dict]]:
    xray, other = [], []
    for idx, n in enumerate(nodes):
        tag = tags[idx] if tags else None
        cfg_raw = n.get("coreConfig")
        if not cfg_raw:
            continue
        try:
            cfg = json.loads(cfg_raw)
        except json.JSONDecodeError:
            continue
        cc, region = node_country(n)
        label = country_label(cc, region, suffix, tag)
        if remarks:
            cfg["remarks"] = label
        entry = {
            "nodeId": n.get("nodeId"),
            "coreType": n.get("coreType"),
            "country": cc,
            "region": region,
            "remarks": label,
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
    ap.add_argument("--remarks-suffix", default=DEFAULT_SUFFIX,
                    help=f'text appended to each config remarks (default: "{DEFAULT_SUFFIX}")')
    ap.add_argument("--no-hashtag", action="store_true",
                    help="omit the random #N suffix from the remarks")
    ap.add_argument("--hashtag-max", type=int, default=999,
                    help="upper bound of the random #N number (default: 999)")
    ap.add_argument("--no-remarks", action="store_true",
                    help="do not add the country remarks field to configs")
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
    suffix = args.remarks_suffix
    tags = None
    if not args.no_hashtag and not args.no_remarks:
        tags = [None] * len(nodes)
        pool = list(range(1, max(2, args.hashtag_max) + 1))
        picks = random.sample(pool, min(len(nodes), len(pool)))
        for i in range(len(nodes)):
            tags[i] = picks[i] if i < len(picks) else random.randint(1, max(2, args.hashtag_max))
    xray, other = split_nodes(nodes, suffix, remarks=not args.no_remarks, tags=tags)

    print(f"[+] {len(nodes)} node(s) cached, {len(xray)} xray, {len(other)} other")
    for e in xray:
        print("    " + describe(e) + "   [" + e["remarks"] + "]")
    for e in other:
        print(f"    node {e['nodeId']}: coreType={e['coreType']} (not Xray)")

    if not args.xrayjson:
        print("\n(use --xrayjson to write configs.json)")
        return 0

    if args.raw:
        payload = nodes
        if not args.no_remarks:
            for n in payload:
                cc, _ = node_country(n)
                n["remarks"] = country_label(cc, None, suffix)
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
