#!/usr/bin/env python3
"""
marshal_sub.py — fetch Marshal VPN (com.marshalvpnapp) server configs the same way
the Android app does, and optionally emit ready-to-use Xray JSON configs.

What the app actually does (recovered from com.marshalvpnapp 2.0):

    GET https://api.aysuz.com/api/sub        (no auth, no params)

    -> {
         "config":            "vless://...#Poland\nvless://...#India\n...",
         "customConfig":      "<base64 of a JSON array of full Xray configs>",
         "adsNormalConfig":   "...",       # same, free/ad-supported tier
         "adsCustomConfig":   "...",
         "message":           "...",
         "personalMessage":   "...",
         "dialogUrl":         "...",
         "settings":          { "ipApi": "https://ipwho.is/", "maxPing": ..., ... }
       }

`config` is what the app shows in its server list; `customConfig` carries
already-complete Xray configs (the app marks those "CUSTOM").  Both are merged
here.  The endpoint needs no authentication for the public pool; paid/tunnel
tiers presumably key off a per-device token the app keeps in encrypted
storage, so `--query` is provided for that case.

The app parses the newline-separated `vless://` share links into Xray JSON
(socks inbound on 127.0.0.1:10808 -> the vless outbound), decodes `customConfig`
as a JSON array of already-complete Xray configs, and resolves each server's
country through the geo API named in `settings.ipApi`.

Usage:
    ./marshal_sub.py                       # list servers
    ./marshal_sub.py --xrayjson            # also write ./configs.json
    ./marshal_sub.py --xrayjson --out /tmp/configs.json
    ./marshal_sub.py --include-ads         # add the ad-tier pool as well
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import random
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

API_URL = "https://api.aysuz.com/api/sub"
DEFAULT_GEO = "https://ipwho.is/"
UA = "okhttp/4.12.0"          # the app uses OkHttp
SOCKS_PORT = 10808            # inbound port baked into the app's config template
HTTP_PORT = 10809

# --------------------------------------------------------------------------- #
# country helpers
# --------------------------------------------------------------------------- #

# The panel names every server after a country ("#Poland", "#United Kingdom").
# Enough coverage for the names these panels actually use; anything else falls
# back to the geo API in settings.ipApi.
NAME2ISO = {
    "afghanistan": "AF", "albania": "AL", "algeria": "DZ", "argentina": "AR",
    "armenia": "AM", "australia": "AU", "austria": "AT", "azerbaijan": "AZ",
    "bahrain": "BH", "bangladesh": "BD", "belarus": "BY", "belgium": "BE",
    "brazil": "BR", "bulgaria": "BG", "cambodia": "KH", "canada": "CA",
    "chile": "CL", "china": "CN", "colombia": "CO", "costa rica": "CR",
    "croatia": "HR", "cyprus": "CY", "czechia": "CZ", "czech republic": "CZ",
    "denmark": "DK", "ecuador": "EC", "egypt": "EG", "estonia": "EE",
    "finland": "FI", "france": "FR", "georgia": "GE", "germany": "DE",
    "greece": "GR", "hong kong": "HK", "hungary": "HU", "iceland": "IS",
    "india": "IN", "indonesia": "ID", "iran": "IR", "iraq": "IQ",
    "ireland": "IE", "israel": "IL", "italy": "IT", "japan": "JP",
    "jordan": "JO", "kazakhstan": "KZ", "kenya": "KE", "kuwait": "KW",
    "kyrgyzstan": "KG", "latvia": "LV", "lebanon": "LB", "lithuania": "LT",
    "luxembourg": "LU", "malaysia": "MY", "mexico": "MX", "moldova": "MD",
    "mongolia": "MN", "montenegro": "ME", "morocco": "MA", "myanmar": "MM",
    "nepal": "NP", "netherlands": "NL", "new zealand": "NZ", "nigeria": "NG",
    "north macedonia": "MK", "norway": "NO", "oman": "OM", "pakistan": "PK",
    "palestine": "PS", "panama": "PA", "peru": "PE", "philippines": "PH",
    "poland": "PL", "portugal": "PT", "qatar": "QA", "romania": "RO",
    "russia": "RU", "saudi arabia": "SA", "serbia": "RS", "singapore": "SG",
    "slovakia": "SK", "slovenia": "SI", "south africa": "ZA", "south korea": "KR",
    "korea": "KR", "spain": "ES", "sri lanka": "LK", "sweden": "SE",
    "switzerland": "CH", "taiwan": "TW", "thailand": "TH", "tunisia": "TN",
    "turkey": "TR", "türkiye": "TR", "ukraine": "UA", "united arab emirates": "AE",
    "uae": "AE", "united kingdom": "GB", "uk": "GB", "great britain": "GB",
    "united states": "US", "usa": "US", "us": "US", "america": "US",
    "uzbekistan": "UZ", "vietnam": "VN", "viet nam": "VN",
}


def iso2_flag(iso2: str) -> str:
    """'DE' -> '🇩🇪' (regional indicator pair)."""
    iso2 = (iso2 or "").strip().upper()
    if len(iso2) != 2 or not iso2.isalpha():
        return "🌐"
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in iso2)


# Geo lookups are memoised per host so repeated servers cost one request.
_GEO_CACHE: dict[str, tuple[str, str]] = {}


def geo_lookup(ip: str, api: str, timeout: float) -> tuple[str, str]:
    """Return (country_name, iso2) for an IP using the panel's own geo API."""
    if ip in _GEO_CACHE:
        return _GEO_CACHE[ip]
    name, iso2 = "", ""
    api = api or DEFAULT_GEO
    try:
        url = api.rstrip("/") + "/" + urllib.parse.quote(ip, safe="")
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout, context=ssl.create_default_context()) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
        if data.get("success", True) is not False:
            name = data.get("country") or ""
            iso2 = (data.get("country_code") or "").upper()
    except Exception:
        pass
    _GEO_CACHE[ip] = (name, iso2)
    return name, iso2


_IP_CACHE: dict[str, str] = {}


def resolve_ip(host: str, timeout: float) -> str:
    if host not in _IP_CACHE:
        try:
            _IP_CACHE[host] = socket.gethostbyname(host)
        except Exception:
            _IP_CACHE[host] = ""
    return _IP_CACHE[host]


def tcp_latency(host: str, port: int, timeout: float) -> int:
    """Measured TCP connect time in ms, or 0 when unreachable."""
    try:
        t0 = time.perf_counter()
        with socket.create_connection((host, port), timeout=timeout):
            pass
        return max(1, int((time.perf_counter() - t0) * 1000))
    except Exception:
        return 0


# --------------------------------------------------------------------------- #
# share-link parsing + Xray config building
# --------------------------------------------------------------------------- #

def parse_vless(link: str) -> dict | None:
    """vless://uuid@host:port?params#remark  ->  dict"""
    try:
        parts = urllib.parse.urlsplit(link.strip())
    except Exception:
        return None
    if parts.scheme.lower() != "vless" or not parts.username:
        return None
    q = {k.lower(): v[0] for k, v in urllib.parse.parse_qs(parts.query, keep_blank_values=True).items()}
    try:
        port = parts.port or 443
    except ValueError:
        return None
    host = parts.hostname or ""
    return {
        "scheme": "vless",
        "id": parts.username,
        "address": host,
        "port": port,
        "params": q,
        "remark": urllib.parse.unquote((parts.fragment or "").replace("+", " ")),
    }


def _stream_settings(srv: dict) -> dict:
    """Mirror the app's streamSettings generation for a vless share link."""
    p = srv["params"]
    net = (p.get("type") or p.get("network") or "tcp").lower()
    sec = (p.get("security") or "none").lower()
    host = p.get("host") or srv["address"]
    path = urllib.parse.unquote(p.get("path") or "/")
    sni = p.get("sni") or p.get("peer") or host
    fp = p.get("fp") or p.get("fingerprint")
    flow = p.get("flow") or ""
    st: dict = {"network": net}

    if sec == "tls":
        st["security"] = "tls"
        tls = {"serverName": sni, "allowInsecure": (p.get("allowinsecure", "0") in ("1", "true"))}
        if fp:
            tls["fingerprint"] = fp
        if p.get("alpn"):
            tls["alpn"] = [a for a in urllib.parse.unquote(p["alpn"]).split(",") if a]
        st["tlsSettings"] = tls
    elif sec == "reality":
        st["security"] = "reality"
        rs = {"serverName": sni, "fingerprint": fp or "chrome", "allowInsecure": False}
        if p.get("pbk"):
            rs["publicKey"] = urllib.parse.unquote(p["pbk"])
        if p.get("sid"):
            rs["shortId"] = urllib.parse.unquote(p["sid"])
        if p.get("spx"):
            rs["spiderX"] = urllib.parse.unquote(p["spx"])
        st["realitySettings"] = rs
    else:
        st["security"] = "none"

    if net == "ws":
        ws = {"path": path, "headers": {"Host": host}}
        if p.get("ed"):
            ws["maxEarlyData"] = int(p["ed"])
        if p.get("eh"):
            ws["earlyDataHeaderName"] = urllib.parse.unquote(p["eh"])
        st["wsSettings"] = ws
    elif net in ("grpc", "gun"):
        st["network"] = "grpc"
        st["grpcSettings"] = {"serviceName": urllib.parse.unquote(p.get("servicename") or p.get("path") or "")}
    elif net in ("h2", "http"):
        st["network"] = "h2"
        st["httpSettings"] = {"path": path, "host": [host]}
    elif net == "tcp":
        if (p.get("headertype") or "").lower() == "http":
            st["tcpSettings"] = {"header": {"type": "http", "request": {
                "version": "1.1", "method": "GET", "path": [path],
                "headers": {
                    "Host": [host],
                    "User-Agent": ["Mozilla/5.0"],
                    "Accept-Encoding": ["gzip, deflate"],
                    "Connection": ["keep-alive"],
                    "Pragma": "no-cache",
                }}}}
    return st


def build_xray(srv: dict, remark: str) -> dict:
    """Build the same shape of Xray JSON the app hands to Xray-core."""
    p = srv["params"]
    user = {"id": srv["id"], "encryption": p.get("encryption") or "none", "level": 0}
    if p.get("flow"):
        user["flow"] = p["flow"]
    return {
        "remarks": remark,
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "socks",
            "listen": "127.0.0.1",
            "port": SOCKS_PORT,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": True},
            "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]},
        }],
        "outbounds": [
            {
                "tag": "proxy",
                "protocol": "vless",
                "settings": {"vnext": [{
                    "address": srv["address"],
                    "port": srv["port"],
                    "users": [user],
                }]},
                "streamSettings": _stream_settings(srv),
            },
            {"tag": "direct", "protocol": "freedom", "settings": {}},
            {"tag": "block", "protocol": "blackhole", "settings": {}},
        ],
        "routing": {"domainStrategy": "AsIs", "rules": []},
    }


def outbound_endpoint(cfg: dict) -> tuple[str, int]:
    """Best-effort (host, port) of a full Xray config, for geo + latency."""
    for ob in cfg.get("outbounds") or []:
        if ob.get("protocol") in ("freedom", "blackhole", "dns", "loopback"):
            continue
        s = ob.get("settings") or {}
        for v in s.get("vnext") or []:
            if v.get("address"):
                return str(v["address"]), int(v.get("port") or 443)
        for v in s.get("servers") or []:
            if v.get("address"):
                return str(v["address"]), int(v.get("port") or 443)
        if s.get("address"):
            return str(s["address"]), int(s.get("port") or 443)
    return "", 0


# --------------------------------------------------------------------------- #
# fetching
# --------------------------------------------------------------------------- #

def http_get_json(url: str, timeout: float) -> dict:
    req = urllib.request.Request(url, headers={
        "User-Agent": UA,
        "Accept": "application/json",
        "Accept-Encoding": "identity",
    })
    with urllib.request.urlopen(req, timeout=timeout, context=ssl.create_default_context()) as r:
        raw = r.read()
    try:
        return json.loads(raw.decode("utf-8", "replace"))
    except json.JSONDecodeError:
        raise SystemExit("server did not return JSON (first bytes: %r)" % raw[:80])


def decode_pool(blob: str) -> list[dict]:
    """`config`/`customConfig` blobs: newline links, base64 links, or base64 JSON array."""
    if not blob:
        return []
    s = blob.strip()
    if "://" not in s and not s.startswith("["):
        # base64 (standard, url-safe, or missing padding)
        try:
            pad = "=" * (-len(s) % 4)
            s = base64.b64decode(s.replace("-", "+").replace("_", "/") + pad).decode("utf-8", "replace").strip()
        except Exception:
            return []
    if s.startswith("["):
        try:
            data = json.loads(s)
            return [c for c in data if isinstance(c, dict)]
        except Exception:
            return []
    return [ln for ln in s.splitlines() if "://" in ln]


def collect(resp: dict, include_ads: bool) -> tuple[list[dict], list[str]]:
    """Return (full Xray configs before remarks, raw links)."""
    custom, links = [], []

    for field in (["config", "customConfig", "adsNormalConfig", "adsCustomConfig"] if include_ads
                  else ["config", "customConfig"]):
        for item in decode_pool(resp.get(field) or ""):
            if isinstance(item, str):
                links.append(item)
            elif isinstance(item, dict):
                custom.append(item)
    return custom, links


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #

def main() -> int:
    ap = argparse.ArgumentParser(
        description="Fetch Marshal VPN configs exactly like com.marshalvpnapp does.")
    ap.add_argument("--url", default=API_URL, help="endpoint (default: %(default)s)")
    ap.add_argument("--xrayjson", action="store_true",
                    help="write configs.json (list of Xray JSON, one per server)")
    ap.add_argument("--out", default=None,
                    help="output path for --xrayjson (default: ./configs.json next to this script)")
    ap.add_argument("--include-ads", action="store_true",
                    help="also merge the ad-tier pools (adsNormalConfig/adsCustomConfig)")
    ap.add_argument("--query", default="", help="extra query string, e.g. 'device=abc&tier=vip'")
    ap.add_argument("--dedupe", action="store_true",
                    help="drop servers repeating address+port+uuid")
    ap.add_argument("--no-latency", action="store_true", help="skip TCP latency probing")
    ap.add_argument("--timeout", type=float, default=6.0, help="network timeout (default 6s)")
    ap.add_argument("--latency-timeout", type=float, default=3.0, help="TCP probe timeout")
    ap.add_argument("--fallback-ms", type=int, default=0,
                    help="MS shown when a server is unreachable from this network (default 0)")
    args = ap.parse_args()

    url = args.url
    if args.query:
        url += ("&" if "?" in url else "?") + args.query.lstrip("?&")

    try:
        resp = http_get_json(url, args.timeout)
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        print("fetch failed: %s" % e, file=sys.stderr)
        return 1

    settings = resp.get("settings") or {}
    geo_api = settings.get("ipApi") or DEFAULT_GEO
    custom, links = collect(resp, args.include_ads)

    servers = [s for s in (parse_vless(l) for l in links) if s]
    skipped = [l.split("://", 1)[0] for l in links if not parse_vless(l)]
    if skipped:
        from collections import Counter
        print("skipped  : %s (only vless:// links are converted)"
              % dict(Counter(skipped)), file=sys.stderr)
    if args.dedupe:
        seen, uniq = set(), []
        for s in servers:
            k = (s["address"], s["port"], s["id"])
            if k not in seen:
                seen.add(k)
                uniq.append(s)
        servers = uniq

    total = len(servers) + len(custom)
    print("endpoint : %s" % url)
    print("message  : %s" % (resp.get("message") or "").strip())
    print("settings : maxPing=%s connectType=%s ipApi=%s"
          % (settings.get("maxPing"), settings.get("connectType"), geo_api))
    print("received : %d share link(s), %d custom config(s)" % (len(servers), len(custom)))
    if not total:
        print("nothing to do", file=sys.stderr)
        return 1

    # ---- resolve country + latency per server --------------------------------
    rows = []
    for srv in servers:
        remark = srv["remark"]
        key = remark.strip().lower()
        iso2 = NAME2ISO.get(key, "")
        name = remark.strip()
        if not iso2:
            ip = resolve_ip(srv["address"], args.timeout)
            gname, giso = geo_lookup(ip, geo_api, args.timeout)
            iso2 = giso or ""
            name = name or gname
        ms = 0 if args.no_latency else tcp_latency(srv["address"], srv["port"], args.latency_timeout)
        ms = ms or args.fallback_ms
        rows.append({"server": srv, "name": name or "Unknown", "iso2": iso2, "ms": ms})

    for cfg in custom:
        host, port = outbound_endpoint(cfg)
        name = str(cfg.get("remarks") or "").strip()
        iso2 = NAME2ISO.get(name.lower(), "")
        if not iso2 and host:
            _, iso2 = geo_lookup(resolve_ip(host, args.timeout), geo_api, args.timeout)
        ms = 0 if args.no_latency else tcp_latency(host, port, args.latency_timeout)
        ms = ms or args.fallback_ms
        rows.append({"cfg": cfg, "name": name or "Unknown", "iso2": iso2, "ms": ms})

    # ---- unique random ids + remarks ---------------------------------------
    nums = random.sample(range(1000, 10000), k=len(rows))
    out_configs = []
    for row, num in zip(rows, nums):
        remark = "%s %s #%d %dMS Fast ⚡️" % (iso2_flag(row["iso2"]), row["name"], num, row["ms"])
        cfg = row.get("cfg") or build_xray(row["server"], remark)
        cfg["remarks"] = remark
        out_configs.append(cfg)

    # ---- report -------------------------------------------------------------
    print("\n%-3s %-22s %-6s %-12s %s" % ("", "COUNTRY", "MS", "TRANSPORT", "ENDPOINT"))
    for row in rows:
        if "server" in row:
            srv = row["server"]
            transport = "%s/%s" % (srv["params"].get("type") or "tcp",
                                   srv["params"].get("security") or "none")
            endpoint = "%s:%d" % (srv["address"], srv["port"])
        else:
            transport, endpoint = "custom", "custom-json"
        print("%-3s %-22s %-6s %-12s %s"
              % (iso2_flag(row["iso2"]), row["name"][:22],
                 row["ms"] if row["ms"] else "-", transport, endpoint))

    if args.xrayjson:
        out = args.out or os.path.join(os.path.dirname(os.path.abspath(__file__)), "configs.json")
        with open(out, "w", encoding="utf-8") as f:
            json.dump(out_configs, f, ensure_ascii=False, indent=2)
        print("\nwrote %d configs -> %s" % (len(out_configs), out))
        print("example remark: %s" % out_configs[0]["remarks"])
    else:
        print("\n(add --xrayjson to write configs.json)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
