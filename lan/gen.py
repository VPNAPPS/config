#!/usr/bin/env python3
import argparse
import base64
import json
import os
from pathlib import Path
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid


def post(url, headers, payload=None):
    data = b"" if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data, headers=headers, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=40) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"{url}: HTTP {exc.code}") from None


def save_account(path, account):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(account, stream)
    os.chmod(path, 0o600)


def find_outbounds(value):
    if isinstance(value, dict):
        if value.get("type") in ("vless", "shadowsocks"):
            yield value
        else:
            for child in value.values():
                yield from find_outbounds(child)
    elif isinstance(value, list):
        for child in value:
            yield from find_outbounds(child)


def config_name(location):
    code = str(location.get("country_code", "")).upper()
    country = location.get("country") or "Unknown"
    if country == "U.S.A.":
        country = "United States"
    flag = (
        "".join(chr(127397 + ord(c)) for c in code)
        if len(code) == 2 and all("A" <= c <= "Z" for c in code)
        else "🌐"
    )
    return f"{flag} {country}"


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
    parser.add_argument("--app-version", default="9.0.29")
    parser.add_argument("--singbox-version", default="v1.13.19")
    parser.add_argument("--platform", default="linux")
    args = parser.parse_args()

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
    }

    if not account.get("user_id") or not account.get("token"):
        user = post("https://api.getiantem.org/user-create", headers)
        if not user.get("userId") or not user.get("token"):
            raise RuntimeError("Registration returned no user ID/token")
        account.update(
            user_id=str(user["userId"]),
            token=user["token"],
        )
        save_account(args.account, account)

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
        "locale": "en",
        "protocols": ["vless", "shadowsocks"],
        "capabilities": ["non_selectable_outbounds"],
    }
    config = post(
        "https://df.iantem.io/api/v1/config-new",
        headers,
        payload,
    )

    locations = config.get("outbound_locations") or {}
    links = []
    xray_configs = []

    for outbound in find_outbounds(config):
        location = locations.get(outbound.get("tag")) or {}
        try:
            link = to_link(outbound, location)
            xray = to_xray(outbound, location) if args.xrayjson else None
        except (KeyError, ValueError, TypeError) as exc:
            print(
                f"Skipped {outbound.get('type')}: {exc}",
                file=sys.stderr,
            )
            continue

        if link not in links:
            links.append(link)
            if xray is not None:
                xray_configs.append(xray)
            print(f"Added: {config_name(location)}")

    if not links:
        raise RuntimeError(
            "No exportable VLESS/SS configs returned; "
            "output left unchanged"
        )

    args.output.write_text(
        "\n".join(links) + "\n", encoding="utf-8"
    )
    print(f"Saved {len(links)} links to {args.output}")

    if args.xrayjson:
        json_path = args.output.with_suffix(".json")
        json_path.write_text(
            json.dumps(xray_configs, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        print(f"Saved {len(xray_configs)} Xray configs to {json_path}")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError, KeyError) as exc:
        sys.exit(f"Error: {exc}")