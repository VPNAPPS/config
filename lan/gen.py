#!/usr/bin/env python3
"""
lantern_fetch.py — fetch Lantern server config the way Lantern 10.x (radiance) does.

The --xrayjson output is byte-for-byte the shape of the original script:
a JSON array of complete configs, each {remarks, log, inbounds, outbounds:[proxy]}
with the outbound tagged "proxy".

Fetch-side fixes over the original (these do not change the output format):

  1. HOST.  df.iantem.io answers 403 for these paths. The working host is
     df.getiantem.org (verified 200); api.getiantem.org is 404.
  2. PLATFORM.  The pool is platform-dependent. platform="linux" returns
     Shadowsocks only; platform="android" also yields VLESS.
  3. PROTOCOLS.  `protocols` is required (omitting it => 400) and filters the
     pool. Asking only for vless+shadowsocks hides hysteria2x and samizdat.

Requests only READ server config. It registers a free anonymous account on first
run and stores it next to this script with mode 0600.
"""

import argparse
import base64
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

API_HOSTS = [
    "https://df.getiantem.org",   # verified 200
    "https://df.iantem.io",       # 403 from many networks
    "https://api.getiantem.org",  # 404 for /api/v1/config-new
]
CONFIG_PATH = "/api/v1/config-new"
REGISTER_PATH = "/user-create"

ALL_PROTOCOLS = ["vless", "hysteria2x", "samizdat", "shadowsocks"]
VALID_PROTOCOLS = {"vless", "hysteria2x", "samizdat", "shadowsocks", "outline"}
CAPABILITIES = ["non_selectable_outbounds"]

GROUP_TYPES = {"mutableautoselect", "mutableselector", "selector", "urltest"}
PROXY_TYPES = {"vless", "shadowsocks", "hysteria2x", "samizdat", "outline",
               "trojan", "vmess", "wireguard", "anytls"}
EXPORTABLE = ("vless", "shadowsocks")


# ------------------------------------------------------------------ transport

def post_json(url, headers, payload=None, timeout=40):
    data = b"" if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.load(resp)


def call_api(path, headers, payload=None):
    """Try each known API host, return (config, host) from the first 2xx."""
    errors = []
    for host in API_HOSTS:
        try:
            return post_json(host + path, headers, payload), host
        except urllib.error.HTTPError as exc:
            errors.append(f"{host}{path}: HTTP {exc.code}")
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            errors.append(f"{host}{path}: {type(exc).__name__}")
    raise RuntimeError(
        "all API hosts failed -> "
        + "; ".join(errors)
        + "\n  (HTTP 500 here usually means a malformed request body, "
          "not an outage - check --protocols/--platform)"
    )


def save_account(path, account):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(account, stream)
    os.chmod(path, 0o600)


def parse_protocols(raw):
    """Normalise --protocols.

    Accepts `--protocols vless shadowsocks`, and also tolerates the bracketed
    and/or comma-joined forms a shell may hand over literally, e.g.
    `--protocols [shadowsocks, vless]` -> ['shadowsocks', 'vless'].

    The server does NOT validate these; an unknown name makes it return HTTP
    500, so we reject bad input here instead.
    """
    tokens = []
    for item in raw:
        for part in str(item).replace("[", " ").replace("]", " ").split(","):
            for name in part.split():
                if name:
                    tokens.append(name.strip().strip("'\"").lower())

    bad = [t for t in tokens if t not in VALID_PROTOCOLS]
    if bad:
        raise RuntimeError(
            "unknown protocol(s): "
            + ", ".join(bad)
            + "\n  accepted: "
            + ", ".join(sorted(VALID_PROTOCOLS))
            + "\n  usage: --protocols vless shadowsocks   (space separated, no brackets/commas)"
        )
    if not tokens:
        raise RuntimeError(
            "no protocols given; accepted: " + ", ".join(sorted(VALID_PROTOCOLS))
        )
    # de-duplicate, keep order
    return list(dict.fromkeys(tokens))


# ------------------------------------------------------------ config plumbing

def find_proxies(cfg):
    """Yield proxy outbound dicts, skipping selector/urltest group nodes."""
    def walk(node):
        if isinstance(node, dict):
            t = node.get("type")
            if t in PROXY_TYPES:
                yield node
            elif t in GROUP_TYPES or "outbounds" in node:
                for k in ("outbounds", "endpoints"):
                    if isinstance(node.get(k), list):
                        for child in node[k]:
                            yield from walk(child)
            else:
                for child in node.values():
                    yield from walk(child)
        elif isinstance(node, list):
            for child in node:
                yield from walk(child)

    seen = set()
    for ob in walk(cfg):
        key = json.dumps(ob, sort_keys=True)
        if key not in seen:
            seen.add(key)
            yield ob


def config_name(location):
    code = str(location.get("country_code", "")).upper()
    country = location.get("country") or "Unknown"
    if country == "U.S.A.":
        country = "United States"
    flag = (
        "".join(chr(127397 + ord(c)) for c in code)
        if len(code) == 2 and all("A" <= c <= "Z" for c in code)
        else "\U0001F310"
    )
    return f"{flag} {country}"


# ---------------------------------------------------------------- share links

def to_link(o, location):
    if (
        o.get("transport")
        or o.get("detour")
        or o.get("multiplex", {}).get("enabled")
    ):
        raise ValueError("additional transport/chain/multiplex settings")

    host = o["server"]
    if ":" in host:
        host = f"[{host}]"
    address = f'{host}:{int(o["server_port"])}'
    label = urllib.parse.quote(config_name(location), safe="")

    if o["type"] == "shadowsocks":
        if o.get("plugin") or o.get("tls", {}).get("enabled"):
            raise ValueError("additional Shadowsocks plugin/TLS settings")
        auth = f'{o["method"]}:{o["password"]}'
        encoded = (
            base64.urlsafe_b64encode(auth.encode())
            .decode()
            .rstrip("=")
        )
        return f"ss://{encoded}@{address}#{label}"

    query = {"encryption": "none", "type": "tcp"}
    if o.get("flow"):
        query["flow"] = o["flow"]

    tls = o.get("tls") or {}
    if tls.get("enabled"):
        reality = tls.get("reality") or {}
        query["security"] = (
            "reality" if reality.get("enabled") else "tls"
        )
        if tls.get("server_name"):
            query["sni"] = tls["server_name"]
        if tls.get("insecure"):
            query["allowInsecure"] = "1"
        if tls.get("alpn"):
            query["alpn"] = ",".join(tls["alpn"])

        utls = tls.get("utls") or {}
        if utls.get("enabled"):
            query["fp"] = utls.get("fingerprint", "chrome")
        if reality.get("enabled"):
            query["pbk"] = reality["public_key"]
            query["sid"] = reality.get("short_id", "")
    else:
        query["security"] = "none"

    return (
        f'vless://{o["uuid"]}@{address}?'
        f"{urllib.parse.urlencode(query)}#{label}"
    )


# --------------------------------------------------------- xray config (yours)

def to_xray(o, location):
    if o["type"] == "shadowsocks":
        proxy = {
            "tag": "proxy",
            "protocol": "shadowsocks",
            "settings": {
                "servers": [{
                    "address": o["server"],
                    "port": int(o["server_port"]),
                    "method": o["method"],
                    "password": o["password"],
                }],
            },
        }
    else:
        user = {"id": o["uuid"], "encryption": "none"}
        if o.get("flow"):
            user["flow"] = o["flow"]

        stream = {"network": "tcp", "security": "none"}
        tls = o.get("tls") or {}

        if tls.get("enabled"):
            reality = tls.get("reality") or {}
            opts = {"serverName": tls.get("server_name", "")}
            utls = tls.get("utls") or {}

            if utls.get("enabled"):
                opts["fingerprint"] = utls.get("fingerprint", "chrome")

            if reality.get("enabled"):
                stream["security"] = "reality"
                opts.update({
                    "fingerprint": opts.get("fingerprint", "chrome"),
                    "publicKey": reality["public_key"],
                    "shortId": reality.get("short_id", ""),
                })
                stream["realitySettings"] = opts
            else:
                stream["security"] = "tls"
                opts["allowInsecure"] = bool(tls.get("insecure", False))
                if tls.get("alpn"):
                    opts["alpn"] = tls["alpn"]
                stream["tlsSettings"] = opts

        proxy = {
            "tag": "proxy",
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": o["server"],
                    "port": int(o["server_port"]),
                    "users": [user],
                }],
            },
            "streamSettings": stream,
        }

    return {
        "remarks": config_name(location),
        "log": {"loglevel": "warning"},
        "dns": {"servers": ["8.8.8.8", "1.1.1.1"]},
        "inbounds": [{
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "port": 10808,
            "protocol": "socks",
            "settings": {
                "auth": "noauth",
                "udp": True,
            },
        }],
        "outbounds": [proxy],
    }


# ----------------------------------------------------------------------- main

def main():
    parser = argparse.ArgumentParser(
        description="Fetch Lantern VLESS/SS links and optional Xray configs"
    )
    parser.add_argument(
        "--xrayjson",
        action="store_true",
        help="Also write a JSON array of complete Xray configs",
    )
    parser.add_argument(
        "-o", "--output", type=Path, default=Path("configs.txt")
    )
    parser.add_argument(
        "--account", type=Path, default=Path(".lantern-account.json")
    )
    # defaults now match the shipping Android build (was 9.0.29 / linux)
    parser.add_argument("--app-version", default="10.0.5")
    parser.add_argument("--singbox-version", default="v1.13.20")
    parser.add_argument("--platform", default="android")
    parser.add_argument("--country", default="IR")
    parser.add_argument("--timezone", default="Asia/Tehran")
    parser.add_argument("--locale", default="en")
    parser.add_argument("--protocols", nargs="+", default=ALL_PROTOCOLS)
    parser.add_argument(
        "--singbox", action="store_true",
        help="Also write a sing-box config (what Lantern itself runs)",
    )
    args = parser.parse_args()
    args.protocols = parse_protocols(args.protocols)

    account = (
        json.loads(args.account.read_text(encoding="utf-8"))
        if args.account.exists()
        else {"device_id": str(uuid.uuid4())}
    )
    headers = {
        "X-Lantern-Device-Id": account["device_id"],
        "X-Lantern-App": "lantern",
        "X-Lantern-App-Version": args.app_version,
        "X-Lantern-Version": args.app_version,
        "X-Lantern-Platform": args.platform,
        "X-Lantern-Origin": "lantern",
        "X-Lantern-Time-Zone": args.timezone,
    }
    # Sent only when set; omitting it makes the server fall back to the
    # country already stored on the account (set at registration).
    if args.country:
        headers["X-Lantern-Client-Country"] = args.country

    if not account.get("user_id") or not account.get("token"):
        user, host = call_api(REGISTER_PATH, headers)
        if not user.get("userId") or not user.get("token"):
            raise RuntimeError("Registration returned no user ID/token")
        account.update(
            user_id=str(user["userId"]),
            token=user["token"],
        )
        save_account(args.account, account)
        print(f"registered account {account['user_id']} via {host}")

    headers.update({
        "Content-Type": "application/json",
        "Cache-Control": "no-cache",
        "X-Lantern-User-Id": str(account["user_id"]),
    })
    payload = {
        "device_id": account["device_id"],
        "user_id": str(account["user_id"]),
        "pro_token": account["token"],
        "app_name": "lantern",
        "platform": args.platform,
        "singbox_version": args.singbox_version,
        "backend": "sing-box",
        "locale": args.locale,
        "protocols": args.protocols,
        "capabilities": CAPABILITIES,
    }
    config, host = call_api(CONFIG_PATH, headers, payload)
    print(f"config fetched from {host}")

    locations = config.get("outbound_locations") or {}
    links = []
    xray_configs = []
    singbox_out = []
    skipped = []

    for outbound in find_proxies(config):
        location = locations.get(outbound.get("tag")) or {}

        if outbound["type"] not in EXPORTABLE:
            # Lantern runs these natively; Xray has no equivalent.
            singbox_out.append(outbound)
            skipped.append((outbound["type"], outbound.get("tag", "")))
            continue

        try:
            link = to_link(outbound, location)
            xray = to_xray(outbound, location)
        except (KeyError, ValueError, TypeError) as exc:
            skipped.append((outbound["type"], f'{outbound.get("tag","")} ({exc})'))
            continue

        if link not in links:
            links.append(link)
            xray_configs.append(xray)
            singbox_out.append(outbound)
            print(f"Added: {config_name(location)}")

    if not links:
        raise RuntimeError(
            "No exportable VLESS/SS configs returned; output left unchanged"
        )

    args.output.write_text("\n".join(links) + "\n", encoding="utf-8")
    print(f"Saved {len(links)} links to {args.output}")

    if args.xrayjson:
        json_path = args.output.with_suffix(".json")
        json_path.write_text(
            json.dumps(xray_configs, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        print(f"Saved {len(xray_configs)} Xray configs to {json_path}")

    if args.singbox:
        sp = args.output.with_suffix(".singbox.json")
        doc = {"log": {"level": "info"}, "outbounds": singbox_out}
        opts = config.get("options") or {}
        if opts.get("dns"):
            doc["dns"] = opts["dns"]
        if opts.get("route"):
            doc["route"] = opts["route"]
        sp.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n")
        print(f"Saved sing-box config ({len(singbox_out)} outbounds) to {sp}")

    if skipped:
        print("\nnot exportable as Xray configs:", file=sys.stderr)
        for kind, tag in skipped:
            print(f"  - {kind}: {tag}", file=sys.stderr)


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError, KeyError) as exc:
        sys.exit(f"Error: {exc}")
