#!/usr/bin/env python3
"""
kidi_config.py - standalone reimplementation of how the Kidi VPN client
(com.kidi.vkk.anp, a JimboVPN-family white-label build) loads its remote
"app configs".

Pipeline reproduced from the shipped APK (v700.71). The native crypto and the
panel protocol are unchanged as of the 2026-11 service update; what changed is
the payload content (share links instead of JSON configs, new CDN domains,
GO-only smart profiles), handled below.

  1. Sources (Java: defpackage.pw0.c(), AppDataFetchChannel)
       CDN mirrors  -> "native:github-raw" / "native:gitlab-raw"   (disabled in this build:
                       com.jimbovpn.jimbo2023.kq.xb.hwj.ww()/sc() return null)
       GITHUB_API   -> "native:github-api"                          (dead code in this build)
       DOMAIN       -> baseUrl / domains remembered from the previous payload
       BASE_URL     -> remembered baseUrl, then the hard-coded https://api.gem-panel.com
     Each source is fetched at  <base>/api/v1/apps/app-data with the header
       authorization: ApiKey <key>
     where <key> is the 36-byte constant embedded in libjimbosec (FUN_0010f924)
     and the header is added by NativePanelAuthBridge.applyAuthorization
     (FUN_001072f8). Without it the panel answers 400 "Missing authorization header".

  2. Response wrapper:  {"data": "<base64>", "timestamp": <unix ms>}
     The timestamp is compared with the cached one before any decryption
     (Java: defpackage.vc / lk1, "timestamp gate").

  3. Decryption (native: libjimbosec.so, hwj.sq -> FUN_00106ba4)
       key      = SHA-256( hex(pinned X.509 cert) + package name )
       payload  = base64 -> [16-byte IV][AES-256-CTR ciphertext]
       plain    = gzip.decompress(AES-256-CTR(key, IV, ciphertext))
     The pinned certificate is the DER blob embedded in .rodata of libjimbosec
     (hex string, 2842 chars) and the package name comes from
     ActivityThread.currentApplication().getPackageName().

  4. Validation (Java: defpackage.lk1.g)
       top level must be a JSON object with:
         settings            : object
         configs.normal[]    : objects with string "config"
         configs.smart[]     : string or object with string "config"

  5. v2rayNG export (--xrayjson / --uris)
       Each profile's "config" is either a full JSON document ("protocol":
       "json") or a share link ("protocol": "vless", e.g. vless://uuid@ip:port?
       type=tcp&security=reality&...#fragment). Share links are converted into
       complete Xray/v2ray JSON configs (see below), so:
         --xrayjson  one minified JSON array of *JSON configs only*
         --uris      the raw share links, one per line (clipboard import)
       Remarks become "<flag emoji> <country name>", plus the panel profile name
       when a country has several servers (e.g. "🇺🇸 United States · Zenith-14F5A1");
       for share links the same text goes into the URI #fragment.
       --keep-remarks preserves the panel's own remarks/fragments.
       Profiles whose country is GO (the panel's smart/global bundles) are
       dropped by default because they do not connect; --include-go keeps them.

     The link->config conversion follows the client's own parser: ro0.c()
     splits the query and ro0.a() maps type/headerType/host/path/seed/
     quicSecurity/key/mode/serviceName/authority/security/insecure/sni/fp/alpn/
     pbk/sid/spx/flow onto a ProfileItem, which is rendered as
     outbounds[0] = {protocol, settings.vnext[{address,port,users[{id,
     encryption,flow}]}], streamSettings{network,security,tlsSettings|
     realitySettings,wsSettings|grpcSettings|httpSettings|tcpSettings|
     kcpSettings|quicSettings|httpupgradeSettings|xhttpSettings}} plus
     freedom/blackhole outbounds and private-network routing rules.

  6. Model mapping (Java: RepoCdnAppDataMapper)
       normal profiles are grouped per country into locations/servers,
       smart profiles become a flat list.

Only the Python standard library is used (AES-256 is implemented below).

Usage:
    python3 kidi_config.py                              # fetch + decrypt + summarize
    python3 kidi_config.py --proxy 192.168.0.208:1080   # same, through a SOCKS5 proxy
    python3 kidi_config.py --json                # full decrypted config as JSON
    python3 kidi_config.py --raw response.json   # parse a saved HTTP body
    python3 kidi_config.py --payload-file b64.txt  # decrypt a saved "data" string
    python3 kidi_config.py --source https://...  # override the base URL
    python3 kidi_config.py --uris                # one vless:// per line (clipboard)
    python3 kidi_config.py --uris --out links.txt
    python3 kidi_config.py --include-go          # keep the GO smart bundles
"""

from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import http.client
import json
import os
import re
import secrets
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib

PACKAGE_NAME = "com.kidi.vkk.anp"
DEFAULT_BASE_URL = "https://api.gem-panel.com"
# Mirrors observed in the panel's own payload ("domains"), newest first. The
# panel rotates these; the older ones are kept as extra fallbacks. CDNs like
# CloudFront are usually reachable from CI networks that Cloudflare blocks.
FALLBACK_SOURCES = (
    "https://d1tqd8ppvb4ro.cloudfront.net",
    "https://dehewunz4k3zc.cloudfront.net",
    "https://d1x2lvttinxnrj.cloudfront.net",
    "https://dp2l1bztx8f43.cloudfront.net",
)
APP_DATA_PATH = "/api/v1/apps/app-data"
USER_AGENT = "okhttp/4.12.0"

# Panel API key sent as "authorization: ApiKey <key>" by
# NativePanelAuthBridge.applyAuthorization(...). It is the 36-byte constant at
# libjimbosec .rodata 0x3e4c XOR 0x97c3d9e98ddd73a3 (FUN_0010f924) prefixed by
# "ApiKey " in FUN_001072f8.
API_KEY = "1eb4afa5-060a-43a4-ba57-af1e16194083"

# Hex-encoded DER of the certificate pinned inside libjimbosec.so
# (rodata @ 0x3332..0x3e6a, 1421-byte X.509, subject CN=Android, O=Google Inc.).
PINNED_CERT_HEX = (
    "3082058930820371a00302010202150096643cf074b408fabfdb03ad4b2771a5d994565c"
    "300d06092a864886f70d01010b05003074310b3009060355040613025553311330110603"
    "550408130a43616c69666f726e6961311630140603550407130d4d6f756e7461696e2056"
    "69657731143012060355040a130b476f6f676c6520496e632e3110300e060355040b1307"
    "416e64726f69643110300e06035504031307416e64726f69643020170d32333035333130"
    "37333835355a180f32303533303533313037333835355a3074310b300906035504061302"
    "5553311330110603550408130a43616c69666f726e6961311630140603550407130d4d6f"
    "756e7461696e205669657731143012060355040a130b476f6f676c6520496e632e311030"
    "0e060355040b1307416e64726f69643110300e06035504031307416e64726f6964308202"
    "22300d06092a864886f70d01010105000382020f003082020a0282020100a1070e353c12"
    "2c9c4ce83f4a396931bc494c706a09f65b061a35dbea2df5445ef092e6b1f34182a74bf4"
    "f9ea96e02aa4e502b12d1ea03550acaaf92657d956d8ca595fa66c74868d9a2986de7327"
    "6d97f7721822f567400a3441f3b1ff53796f8659f489eb60dc3ce21dacc67b7b16715da0"
    "5f09ea5138768590d900868bd97b794ce909f16ae6f0df186c4ae693b71ecf4ba119e831"
    "2467605e2d759f49ce57b68dca390b57f2ad74966b00373ff5d1cc99dff9cdbe015e9be2"
    "c67460f5d1b91f6dc0cb0a43ec60296ded610caa25cbfadf8cfc5e0b29726c2aa2c797ae"
    "66b9654c26b951583bf6b9fac871d687067e23cfb002f00a4ce1ab95c3c0aba6627ecb53"
    "1765dfe201bb608853c3e47527050ce0dba42d37de83d0d7af3b0bc9f7688cd413962b2c"
    "7d5ce222749c6bd2754df12b20a134702e1f972f2bab85ffde570c7b18dd407b603d2414"
    "838b4af627f55ade7630965ea8b0cbe361c5dbf307d14edc11fbaed17866d4f2f1e62988"
    "962d086c3a646fc7931abcf6539adc9899302cc9ff6c84c643bbb719907c93fba71990f6"
    "e57a2ac4ed5f497b4fb18f20046fd1089f2b800565ff0d8bd00d89e616ea999cacca9d77"
    "fee4c847278f5e0324588b3293a5135a0ba7287fd789d32782fad7d7bb1be6dc2197360e"
    "8cf7386fbb25f7560bd0cf625d3d42aca108e53d6fb7b8e7542ce2a08d37f9418351686b"
    "dcab0203010001a310300e300c0603551d13040530030101ff300d06092a864886f70d01"
    "010b050003820201000323b5200b8b71f2115dc3619d7235e145d069b6ef5400ee41eab5"
    "510fec53b458ff656511cb84fd67ec0862a5c4f25decaaa9d4e9ff0c99e769e87f2897bc"
    "b07ebbd3fd331df0f2daf1154a1070e7e2c793f9298dac26b2558fa961277dbf33e32f28"
    "e2d2a389b44574e23afc485731a9a6dcf353a5a322d7b22cba25d438176a2c50ea93cf55"
    "610b180e6596c2c7b376a391b73d22cf648b0ece469f979af295079e99b1453b26a0dd35"
    "22efeb807b64a24ea19d75de1702379efefe03fd3f681b053892e34bbbf449ad1f99604a"
    "67e1914685220d715803badc9897e9ca4016cbd632561907b17efd61b268e8b6dd7bdec1"
    "37aa87350c88c5790d58f29df1bc704b55805525592a1ef76b3615ec26058ca8c3af302f"
    "81ad8dd82444a8980b992a8d29d52a113e4f0410f02c46707fddf3d707d43de5e22b85d5"
    "78caaa62b4a73c34b4c261d9a6c879f6733b52a9a66808795681fa882e300342757cca24"
    "9cae36c9fcc552f5acb4028c62f333f311ad74552a122ad66d1cfb0c48a2a70dd3799ccb"
    "9a1378fa4a9c37e04a3e1ef07f1855cc581f18200217e5df2daf1f41c79e12142213e169"
    "e22289f728f717018e78a500871a27fbbe6a897d79f569db96f699802029bd49e705fed4"
    "1c90a9e1bf15c6abb0543766d96668508f9efa381e803e7985091cdd6e2f49e1b0b389c7"
    "fdfd93334e361539488ca266be1a874436"
)

# An external copy (one line of hex) may be supplied with --cert-hex; otherwise
# the constant embedded above is used.
_CERT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pinned_cert.hex")



# ISO 3166-1 alpha-2 -> English country name (from iso-codes 3166-1), used to
# build readable v2rayNG remarks: "<flag emoji> <country name>".
_COUNTRY_BLOB = (
    "AD:Andorra|AE:United Arab Emirates|AF:Afghanistan|AG:Antigua and Barbuda|AI:Anguilla|AL:Albania|"
    "AM:Armenia|AO:Angola|AQ:Antarctica|AR:Argentina|AS:American Samoa|AT:Austria|AU:Australia|AW:Aru"
    "ba|AX:Åland Islands|AZ:Azerbaijan|BA:Bosnia and Herzegovina|BB:Barbados|BD:Bangladesh|BE:Belgium"
    "|BF:Burkina Faso|BG:Bulgaria|BH:Bahrain|BI:Burundi|BJ:Benin|BL:Saint Barthélemy|BM:Bermuda|BN:Br"
    "unei Darussalam|BO:Bolivia, Plurinational State of|BQ:Bonaire, Sint Eustatius and Saba|BR:Brazil"
    "|BS:Bahamas|BT:Bhutan|BV:Bouvet Island|BW:Botswana|BY:Belarus|BZ:Belize|CA:Canada|CC:Cocos (Keel"
    "ing) Islands|CD:Congo, The Democratic Republic of the|CF:Central African Republic|CG:Congo|CH:Sw"
    "itzerland|CI:Côte d'Ivoire|CK:Cook Islands|CL:Chile|CM:Cameroon|CN:China|CO:Colombia|CR:Costa Ri"
    "ca|CU:Cuba|CV:Cabo Verde|CW:Curaçao|CX:Christmas Island|CY:Cyprus|CZ:Czechia|DE:Germany|DJ:Djibo"
    "uti|DK:Denmark|DM:Dominica|DO:Dominican Republic|DZ:Algeria|EC:Ecuador|EE:Estonia|EG:Egypt|EH:We"
    "stern Sahara|ER:Eritrea|ES:Spain|ET:Ethiopia|FI:Finland|FJ:Fiji|FK:Falkland Islands (Malvinas)|F"
    "M:Micronesia, Federated States of|FO:Faroe Islands|FR:France|GA:Gabon|GB:United Kingdom|GD:Grena"
    "da|GE:Georgia|GF:French Guiana|GG:Guernsey|GH:Ghana|GI:Gibraltar|GL:Greenland|GM:Gambia|GN:Guine"
    "a|GP:Guadeloupe|GQ:Equatorial Guinea|GR:Greece|GS:South Georgia and the South Sandwich Islands|G"
    "T:Guatemala|GU:Guam|GW:Guinea-Bissau|GY:Guyana|HK:Hong Kong|HM:Heard Island and McDonald Islands"
    "|HN:Honduras|HR:Croatia|HT:Haiti|HU:Hungary|ID:Indonesia|IE:Ireland|IL:Israel|IM:Isle of Man|IN:"
    "India|IO:British Indian Ocean Territory|IQ:Iraq|IR:Iran, Islamic Republic of|IS:Iceland|IT:Italy"
    "|JE:Jersey|JM:Jamaica|JO:Jordan|JP:Japan|KE:Kenya|KG:Kyrgyzstan|KH:Cambodia|KI:Kiribati|KM:Comor"
    "os|KN:Saint Kitts and Nevis|KP:Korea, Democratic People's Republic of|KR:Korea, Republic of|KW:K"
    "uwait|KY:Cayman Islands|KZ:Kazakhstan|LA:Lao People's Democratic Republic|LB:Lebanon|LC:Saint Lu"
    "cia|LI:Liechtenstein|LK:Sri Lanka|LR:Liberia|LS:Lesotho|LT:Lithuania|LU:Luxembourg|LV:Latvia|LY:"
    "Libya|MA:Morocco|MC:Monaco|MD:Moldova, Republic of|ME:Montenegro|MF:Saint Martin (French part)|M"
    "G:Madagascar|MH:Marshall Islands|MK:North Macedonia|ML:Mali|MM:Myanmar|MN:Mongolia|MO:Macao|MP:N"
    "orthern Mariana Islands|MQ:Martinique|MR:Mauritania|MS:Montserrat|MT:Malta|MU:Mauritius|MV:Maldi"
    "ves|MW:Malawi|MX:Mexico|MY:Malaysia|MZ:Mozambique|NA:Namibia|NC:New Caledonia|NE:Niger|NF:Norfol"
    "k Island|NG:Nigeria|NI:Nicaragua|NL:Netherlands|NO:Norway|NP:Nepal|NR:Nauru|NU:Niue|NZ:New Zeala"
    "nd|OM:Oman|PA:Panama|PE:Peru|PF:French Polynesia|PG:Papua New Guinea|PH:Philippines|PK:Pakistan|"
    "PL:Poland|PM:Saint Pierre and Miquelon|PN:Pitcairn|PR:Puerto Rico|PS:Palestine, State of|PT:Port"
    "ugal|PW:Palau|PY:Paraguay|QA:Qatar|RE:Réunion|RO:Romania|RS:Serbia|RU:Russian Federation|RW:Rwan"
    "da|SA:Saudi Arabia|SB:Solomon Islands|SC:Seychelles|SD:Sudan|SE:Sweden|SG:Singapore|SH:Saint Hel"
    "ena, Ascension and Tristan da Cunha|SI:Slovenia|SJ:Svalbard and Jan Mayen|SK:Slovakia|SL:Sierra "
    "Leone|SM:San Marino|SN:Senegal|SO:Somalia|SR:Suriname|SS:South Sudan|ST:Sao Tome and Principe|SV"
    ":El Salvador|SX:Sint Maarten (Dutch part)|SY:Syrian Arab Republic|SZ:Eswatini|TC:Turks and Caico"
    "s Islands|TD:Chad|TF:French Southern Territories|TG:Togo|TH:Thailand|TJ:Tajikistan|TK:Tokelau|TL"
    ":Timor-Leste|TM:Turkmenistan|TN:Tunisia|TO:Tonga|TR:Türkiye|TT:Trinidad and Tobago|TV:Tuvalu|TW:"
    "Taiwan, Province of China|TZ:Tanzania, United Republic of|UA:Ukraine|UG:Uganda|UM:United States "
    "Minor Outlying Islands|US:United States|UY:Uruguay|UZ:Uzbekistan|VA:Holy See (Vatican City State"
    ")|VC:Saint Vincent and the Grenadines|VE:Venezuela, Bolivarian Republic of|VG:Virgin Islands, Br"
    "itish|VI:Virgin Islands, U.S.|VN:Viet Nam|VU:Vanuatu|WF:Wallis and Futuna|WS:Samoa|YE:Yemen|YT:M"
    "ayotte|ZA:South Africa|ZM:Zambia|ZW:Zimbabwe"
)

_country_names_cache: dict[str, str] | None = None


def country_names() -> dict[str, str]:
    global _country_names_cache
    if _country_names_cache is None:
        _country_names_cache = dict(
            entry.split(":", 1) for entry in _COUNTRY_BLOB.split("|") if ":" in entry
        )
    return _country_names_cache


def flag_emoji(code: str) -> str:
    """Regional-indicator flag for a two-letter code, else a globe."""
    code = (code or "").strip().upper()
    if len(code) != 2 or not code.isalpha():
        return "\U0001F310"  # 🌐
    return chr(0x1F1E6 + ord(code[0]) - 65) + chr(0x1F1E6 + ord(code[1]) - 65)


def country_label(code: str | None) -> str:
    """'GB' -> '🇬🇧 United Kingdom'; unknown codes keep the code with a globe."""
    code = (code or "").strip().upper()
    if not code:
        return "\U0001F310 Smart"
    name = country_names().get(code)
    if name:
        return f"{flag_emoji(code)} {name}"
    return f"\U0001F310 {code}"

# ---------------------------------------------------------------------------
# AES-256 (encrypt only) + CTR mode - standard library only
# ---------------------------------------------------------------------------

_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16"
)

_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


class AES256:
    """Minimal AES-256 block cipher (FIPS-197), used for CTR mode."""

    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("AES-256 needs a 32-byte key")
        self.round_keys = self._expand(key)

    @staticmethod
    def _expand(key: bytes):
        nk, nr = 8, 14
        w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
        for i in range(nk, 4 * (nr + 1)):
            temp = list(w[i - 1])
            if i % nk == 0:
                temp = temp[1:] + temp[:1]
                temp = [_SBOX[b] for b in temp]
                temp[0] ^= _RCON[i // nk - 1]
            elif i % nk == 4:
                temp = [_SBOX[b] for b in temp]
            w.append([w[i - nk][j] ^ temp[j] for j in range(4)])
        return w

    @staticmethod
    def _xtime(a):
        a <<= 1
        return (a ^ 0x11B) & 0xFF if a & 0x100 else a

    def encrypt_block(self, block: bytes) -> bytes:
        w = self.round_keys
        s = [block[i] ^ w[i // 4][i % 4] for i in range(16)]
        for rnd in range(1, 15):
            s = [_SBOX[b] for b in s]
            # ShiftRows (state is column-major)
            s = [s[0], s[5], s[10], s[15],
                 s[4], s[9], s[14], s[3],
                 s[8], s[13], s[2], s[7],
                 s[12], s[1], s[6], s[11]]
            if rnd != 14:
                mixed = []
                for c in range(4):
                    a = s[4 * c:4 * c + 4]
                    t = a[0] ^ a[1] ^ a[2] ^ a[3]
                    mixed += [
                        a[0] ^ t ^ self._xtime(a[0] ^ a[1]),
                        a[1] ^ t ^ self._xtime(a[1] ^ a[2]),
                        a[2] ^ t ^ self._xtime(a[2] ^ a[3]),
                        a[3] ^ t ^ self._xtime(a[3] ^ a[0]),
                    ]
                s = mixed
            s = [s[i] ^ w[4 * rnd + i // 4][i % 4] for i in range(16)]
        return bytes(s)


def aes256_ctr(key: bytes, iv: bytes, data: bytes) -> bytes:
    """CTR mode with a 128-bit big-endian counter starting at the IV."""
    cipher = AES256(key)
    counter = int.from_bytes(iv, "big")
    out = bytearray(len(data))
    for off in range(0, len(data), 16):
        ks = cipher.encrypt_block(counter.to_bytes(16, "big"))
        chunk = data[off:off + 16]
        for i, b in enumerate(chunk):
            out[off + i] = b ^ ks[i]
        counter = (counter + 1) & ((1 << 128) - 1)
    return bytes(out)


# ---------------------------------------------------------------------------
# Config loading pipeline
# ---------------------------------------------------------------------------

def load_pinned_cert_hex(path: str | None = None) -> str:
    """Pinned certificate as hex (as embedded in libjimbosec .rodata)."""
    p = path or _CERT_FILE
    if os.path.exists(p):
        return open(p, "r", encoding="ascii").read().strip()
    if len(PINNED_CERT_HEX) > 200:
        return PINNED_CERT_HEX
    raise SystemExit(f"pinned certificate hex not found (expected {p})")


def derive_key(cert_hex: str, package: str = PACKAGE_NAME) -> bytes:
    """SHA-256(hex(cert) || package) - libjimbosec FUN_00108174 + FUN_0010843c."""
    return hashlib.sha256((cert_hex + package).encode("utf-8")).digest()


def decrypt_payload(data_b64: str, key: bytes) -> dict:
    """base64 -> [16-byte IV][AES-256-CTR] -> gzip -> JSON."""
    raw = base64.b64decode(data_b64)
    if len(raw) < 32:
        raise ValueError("payload too short")
    iv, ciphertext = raw[:16], raw[16:]
    plain = aes256_ctr(key, iv, ciphertext)
    return json.loads(gzip.decompress(plain).decode("utf-8"))


def validate_payload(cfg: dict) -> None:
    """Mirror the checks in defpackage.lk1.g (message-compatible)."""
    if not isinstance(cfg, dict):
        raise ValueError("Repo CDN decrypted payload is not a JSON object")
    if "settings" not in cfg or not isinstance(cfg["settings"], dict):
        raise ValueError("Repo CDN payload.settings is missing")
    if "configs" not in cfg or not isinstance(cfg["configs"], dict):
        raise ValueError("Repo CDN payload.configs is missing")
    normal = cfg["configs"].get("normal")
    smart = cfg["configs"].get("smart")
    if not isinstance(normal, list):
        raise ValueError("Repo CDN payload.configs.normal is missing")
    if not isinstance(smart, list):
        raise ValueError("Repo CDN payload.configs.smart is missing")
    for i, item in enumerate(normal):
        if not isinstance(item, dict) or not isinstance(item.get("config"), str):
            raise ValueError(f"Repo CDN payload.configs.normal[{i}].config is missing or invalid")
    for i, item in enumerate(smart):
        ok = (isinstance(item, str)
              or (isinstance(item, dict) and isinstance(item.get("config"), str)))
        if not ok:
            raise ValueError(f"Repo CDN payload.configs.smart[{i}] is neither string nor object with config")


def _normalize_base(value: str) -> str:
    """Accept both full URLs and bare host names ("host" -> "https://host")."""
    v = (value or "").strip().rstrip("/")
    if not v:
        return ""
    if "://" not in v:
        v = "https://" + v
    return v


def build_sources(state: dict, override: list[str] | str | None = None) -> list[str]:
    """Base URLs to try, in the order the app prefers them (pw0.c)."""
    if override:
        items = [override] if isinstance(override, str) else list(override)
        return [u for u in (_normalize_base(x) for x in items) if u]
    candidates: list[str] = []
    remembered = state.get("baseUrl")
    # The panel now ships bare host names in "domains" (older payloads had
    # full https:// URLs), so both forms are normalised here.
    for d in (state.get("domains") or []):
        if isinstance(d, str) and d.strip():
            candidates.append(_normalize_base(d))
    if isinstance(remembered, str) and remembered.strip():
        candidates.append(_normalize_base(remembered))
    candidates.append(_normalize_base(DEFAULT_BASE_URL))
    candidates.extend(_normalize_base(u) for u in FALLBACK_SOURCES)
    # de-duplicate, keep order
    seen, out = set(), []
    for c in candidates:
        if c and c not in seen:
            seen.add(c)
            out.append(c)
    return out


def _socks5_connect(proxy: tuple[str, int], host: str, port: int, timeout: float) -> socket.socket:
    """Minimal SOCKS5 CONNECT (no auth, remote DNS)."""
    sock = socket.create_connection(proxy, timeout=timeout)
    sock.settimeout(timeout)
    sock.sendall(b"\x05\x01\x00")
    if sock.recv(2) != b"\x05\x00":
        sock.close()
        raise OSError("SOCKS5 method negotiation rejected")
    name = host.encode("idna")
    sock.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + port.to_bytes(2, "big"))
    reply = sock.recv(4)
    if len(reply) < 4 or reply[0] != 5 or reply[1] != 0:
        sock.close()
        raise OSError(f"SOCKS5 connect failed (reply={reply!r})")
    atyp = reply[3]
    if atyp == 1:
        sock.recv(4)
    elif atyp == 4:
        sock.recv(16)
    elif atyp == 3:
        n = sock.recv(1)[0]
        sock.recv(n)
    sock.recv(2)  # bound port
    return sock


class _SocksHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, port, proxy, timeout, context):
        super().__init__(host, port, timeout=timeout, context=context)
        self._proxy = proxy

    def connect(self):
        raw = _socks5_connect(self._proxy, self.host, self.port, self.timeout)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


def parse_proxy(value: str | None) -> tuple[str, int] | None:
    if not value:
        return None
    value = value.strip()
    for prefix in ("socks5h://", "socks5://", "socks://"):
        if value.startswith(prefix):
            value = value[len(prefix):]
    host, _, port = value.rpartition(":")
    if not host or not port.isdigit():
        raise ValueError(f"invalid proxy {value!r}; expected HOST:PORT (e.g. 192.168.0.208:1080)")
    return host, int(port)


def _decode_body(body: bytes, content_encoding: str | None) -> bytes:
    """Undo gzip/deflate so error pages are readable instead of mojibake."""
    enc = (content_encoding or "").lower()
    if not body:
        return body
    try:
        if "gzip" in enc or body[:2] == b"\x1f\x8b":
            return gzip.decompress(body)
        if "deflate" in enc:
            return zlib.decompress(body)
    except (OSError, zlib.error):
        pass
    return body


def _error_detail(body: bytes, content_encoding: str | None,
                  headers=None) -> str:
    """One readable line from an error response (HTML block pages included)."""
    text = _decode_body(body, content_encoding).decode("utf-8", "replace")
    title = re.search(r"<title[^>]*>(.*?)</title>", text, re.S | re.I)
    if title:
        text = title.group(1)
    text = re.sub(r"[^\x20-\x7e\u00a0-\uffff]+", " ", text)
    text = " ".join(text.split())[:300]
    return text or "(empty body)"


def _http_error(url: str, status: int, reason: str, headers, body: bytes):
    """Build an HTTPError whose message is safe to print in a CI log."""
    enc = None
    if headers is not None:
        try:
            enc = headers.get("Content-Encoding")
        except AttributeError:
            enc = None
    detail = _error_detail(body, enc, headers)
    ray = None
    if headers is not None:
        try:
            ray = headers.get("cf-ray")
        except AttributeError:
            ray = None
    msg = f"HTTP {status}: {detail}"
    if ray:
        msg += f" [cf-ray {ray}]"
    if status == 403:
        msg += (" - the panel sits behind Cloudflare and blocks many datacenter/CI "
                "addresses; retry with --proxy <host:port> from a residential/other egress")
    return urllib.error.HTTPError(url, status, msg, headers, None)


def http_get(url: str, timeout: float = 15.0,
             proxy: tuple[str, int] | None = None,
             api_key: str | None = API_KEY,
             debug: bool = False) -> bytes:
    """GET url, optionally through SOCKS5, with the panel API key header."""
    parts = urllib.parse.urlsplit(url)
    headers = {
        "User-Agent": USER_AGENT,
        "Accept-Encoding": "gzip",
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "keep-alive",
    }
    if api_key:
        headers["authorization"] = f"ApiKey {api_key}"
    path = parts.path + (f"?{parts.query}" if parts.query else "")

    if proxy:
        ctx = ssl.create_default_context()
        conn = _SocksHTTPSConnection(parts.hostname, parts.port or 443, proxy, timeout, ctx)
        try:
            conn.request("GET", path, headers=headers)
            resp = conn.getresponse()
            body = resp.read()
            if debug:
                print(f"debug: GET {url} -> {resp.status} {resp.reason}", file=sys.stderr)
                for h in ("content-type", "content-encoding", "server", "cf-ray", "cache-control"):
                    if resp.getheader(h):
                        print(f"debug:   {h}: {resp.getheader(h)}", file=sys.stderr)
            if resp.status != 200:
                raise _http_error(url, resp.status, resp.reason, resp.headers, body)
            return _decode_body(body, resp.getheader("Content-Encoding"))
        finally:
            conn.close()

    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read()
            if debug:
                print(f"debug: GET {url} -> {resp.status} {resp.reason}", file=sys.stderr)
                for h in ("content-type", "content-encoding", "server", "cf-ray", "cache-control"):
                    if resp.headers.get(h):
                        print(f"debug:   {h}: {resp.headers.get(h)}", file=sys.stderr)
            return _decode_body(body, resp.headers.get("Content-Encoding"))
    except urllib.error.HTTPError as exc:
        body = exc.read() if exc.fp else b""
        raise _http_error(url, exc.code, exc.reason, exc.headers, body)


def fetch_wrapper(base_url: str, timeout: float = 15.0,
                  proxy=None, api_key: str | None = API_KEY,
                  debug: bool = False) -> tuple[str, int]:
    """GET <base>/api/v1/apps/app-data -> (base64 data, timestamp)."""
    body = http_get(base_url + APP_DATA_PATH, timeout=timeout, proxy=proxy,
                    api_key=api_key, debug=debug)
    wrapper = json.loads(body.decode("utf-8"))
    if not isinstance(wrapper, dict) or "data" not in wrapper:
        raise ValueError("unsupported response wrapper")
    return wrapper["data"], int(wrapper.get("timestamp") or 0)


_RETRYABLE_STATUS = {429, 500, 502, 503, 504}


def _fetch_with_retries(base: str, timeout: float, proxy, api_key, debug: bool,
                        attempts: int = 2):
    """Fetch one source, retrying transient failures with a short backoff."""
    last = None
    for attempt in range(attempts + 1):
        try:
            return fetch_wrapper(base, timeout=timeout, proxy=proxy,
                                 api_key=api_key, debug=debug)
        except urllib.error.HTTPError as exc:
            last = exc
            if exc.code in _RETRYABLE_STATUS and attempt < attempts:
                if debug:
                    print(f"debug: {base} -> {exc.reason}; retrying", file=sys.stderr)
                time.sleep(1.5 * (attempt + 1))
                continue
            raise
        except (urllib.error.URLError, TimeoutError, OSError, ssl.SSLError) as exc:
            last = exc
            # Only retry transient failures; DNS errors, refused connections and
            # "network unreachable" are deterministic and just waste time.
            then = time.monotonic()
            transient = isinstance(exc, TimeoutError) or isinstance(
                getattr(exc, "reason", None), (TimeoutError, socket.timeout))
            if transient and attempt < attempts:
                if debug:
                    print(f"debug: {base} -> {type(exc).__name__}; retrying", file=sys.stderr)
                time.sleep(1.5 * (attempt + 1))
                continue
            raise
    raise last  # pragma: no cover


def load_config(sources, cert_hex, state=None, timeout=15.0, force=False,
                proxy: tuple[str, int] | None = None,
                api_key: str | None = API_KEY,
                debug: bool = False):
    """
    Reproduce the app's source race/gate (simplified to a sequential attempt):
    timestamp must be newer than the cached one, otherwise the cached config
    stays in force. Returns (config, meta).
    """
    state = state or {}
    key = derive_key(cert_hex)
    cached_ts = int(state.get("timestamp") or 0)
    errors = []

    for base in sources:
        if debug:
            print(f"debug: trying {base}", file=sys.stderr)
        try:
            data_b64, ts = _fetch_with_retries(base, timeout=timeout, proxy=proxy,
                                               api_key=api_key, debug=debug)
            current = ts if ts > 0 else cached_ts
            payload = decrypt_payload(data_b64, key)
            validate_payload(payload)
            accepted = force or ts > cached_ts or cached_ts == 0
            meta = {
                "source": base,
                "url": base + APP_DATA_PATH,
                "proxy": f"{proxy[0]}:{proxy[1]}" if proxy else None,
                "server_timestamp": ts,
                "cached_timestamp": cached_ts,
                "accepted": accepted,
            }
            if accepted:
                return payload, meta
            errors.append(f"{base}: timestamp gate rejected (server={ts} cached={cached_ts})")
        except urllib.error.HTTPError as exc:
            errors.append(f"{base}: {exc.reason}")
            if debug:
                print(f"debug: {base} -> {exc.reason}", file=sys.stderr)
        except Exception as exc:  # network, decode, validation
            errors.append(f"{base}: {type(exc).__name__}: {exc}")
            if debug:
                print(f"debug: {base} -> {type(exc).__name__}: {exc}", file=sys.stderr)

    if state.get("config"):
        for err in errors:
            print(f"warning: {err}", file=sys.stderr)
        return state["config"], {
            "source": "cache",
            "accepted": False,
            "proxy": f"{proxy[0]}:{proxy[1]}" if proxy else None,
            "errors": errors,
            "note": (errors[0] if errors else
                     "server timestamp not newer than the cached one (pass --force to accept anyway)"),
        }
    raise RuntimeError("no usable source: " + " | ".join(errors))


# ---------------------------------------------------------------------------
# App model mapping (RepoCdnAppDataMapper)
# ---------------------------------------------------------------------------

_URI_SCHEMES = (
    "vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "hy2://",
    "tuic://", "socks://", "wireguard://", "ssh://",
)

# Panel entries whose country is this one are smart/global bundles that do not
# work in practice; they are dropped unless --include-go is given.
EXCLUDED_COUNTRIES = ("GO",)


def _is_uri_config(value: str) -> bool:
    v = value.lstrip().lower()
    return any(v.startswith(s) for s in _URI_SCHEMES)


def _uri_protocol(uri: str) -> str:
    return uri.split("://", 1)[0].strip().lower()


def _with_fragment(uri: str, label: str) -> str:
    """Set the #fragment of a share URI (v2rayNG uses it as the profile name)."""
    base = uri.split("#", 1)[0]
    return base + "#" + urllib.parse.quote(label, safe="")


def _doc_protocol(doc: dict):
    p = doc.get("protocol")
    if isinstance(p, str) and p.strip():
        return p.strip().lower()
    for ob in doc.get("outbounds") or []:
        if isinstance(ob, dict) and isinstance(ob.get("protocol"), str):
            return ob["protocol"].strip().lower()
    return None



# ---------------------------------------------------------------------------
# Share link -> Xray/v2ray config
#
# Mirrors the client's own pipeline: ro0.c()/ro0.a() parse the URI query into a
# ProfileItem (network, headerType, host, path, seed, quicSecurity, key, mode,
# serviceName, authority, security, insecure, sni, fp, alpn, pbk, sid, spx,
# flow), and V2rayConfig builds the outbound as
#   {"protocol":"vless","settings":{"vnext":[{"address","port","users":[
#     {"id","encryption","flow"}]}]},"streamSettings":{...}}
# which is what v2rayNG imports.
# ---------------------------------------------------------------------------

_UNSUPPORTED_URI_WARNED: set[str] = set()


def _truthy(value) -> bool:
    return str(value or "").strip().lower() in ("1", "true", "yes", "on")


def _uri_query(uri: str) -> tuple:
    parts = urllib.parse.urlsplit(uri.strip())
    query = {}
    for key, values in urllib.parse.parse_qs(parts.query, keep_blank_values=True).items():
        query[key.lower()] = values[0]
    return parts, query


def _stream_settings(host: str, q: dict) -> dict:
    network = (q.get("type") or q.get("network") or "tcp").strip().lower()
    if network == "http":
        network = "http"
    security = (q.get("security") or "none").strip().lower()
    sni = q.get("sni") or q.get("peer") or host
    fp = (q.get("fp") or "").strip() or None
    alpn = [a for a in (q.get("alpn") or "").split(",") if a.strip()]
    insecure = _truthy(q.get("allowinsecure") or q.get("insecure"))

    stream: dict = {"network": network}
    if security in ("tls", "reality"):
        stream["security"] = security
        if security == "reality":
            reality = {
                "show": False,
                "serverName": sni,
                "fingerprint": fp or "chrome",
                "publicKey": q.get("pbk", ""),
                "shortId": q.get("sid", ""),
                "spiderX": q.get("spx", "/") or "/",
            }
            if insecure:
                reality["allowInsecure"] = True
            stream["realitySettings"] = reality
        else:
            tls = {"serverName": sni, "allowInsecure": insecure}
            if fp:
                tls["fingerprint"] = fp
            if alpn:
                tls["alpn"] = alpn
            stream["tlsSettings"] = tls

    if network == "ws":
        ws = {"path": q.get("path") or "/"}
        ws_host = q.get("host") or "" 
        if ws_host:
            ws["headers"] = {"Host": ws_host}
        stream["wsSettings"] = ws
    elif network in ("grpc", "gun"):
        grpc = {"serviceName": q.get("servicename", "")}
        if q.get("authority"):
            grpc["authority"] = q["authority"]
        if q.get("mode"):
            grpc["multiMode"] = q["mode"].lower() == "multi"
        stream["grpcSettings"] = grpc
    elif network in ("http", "h2"):
        http = {"path": q.get("path") or "/"}
        hosts = [h for h in (q.get("host") or "").split(",") if h]
        if hosts:
            http["host"] = hosts
        stream["httpSettings"] = http
    elif network == "tcp":
        header_type = (q.get("headertype") or "none").lower()
        if header_type == "http":
            stream["tcpSettings"] = {"header": {"type": "http", "request": {
                "path": [q.get("path") or "/"],
                "headers": {"Host": [q.get("host") or sni]},
            }}}
        else:
            stream["tcpSettings"] = {"header": {"type": "none"}}
    elif network == "kcp":
        stream["kcpSettings"] = {
            "header": {"type": (q.get("headertype") or "none").lower()},
            "seed": q.get("seed", ""),
        }
    elif network == "quic":
        stream["quicSettings"] = {
            "security": q.get("quicsecurity", "none"),
            "key": q.get("key", ""),
            "header": {"type": (q.get("headertype") or "none").lower()},
        }
    elif network == "httpupgrade":
        stream["httpupgradeSettings"] = {"path": q.get("path") or "/", "host": q.get("host") or sni}
    elif network in ("xhttp", "splithttp"):
        xhttp = {"path": q.get("path") or "/", "host": q.get("host") or sni}
        if q.get("mode"):
            xhttp["mode"] = q["mode"]
        stream["xhttpSettings"] = xhttp
    return stream


def _base_config(host: str, outbound: dict, remark: str | None) -> dict:
    return {
        "remarks": remark or host,
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "socks",
            "listen": "127.0.0.1",
            "port": 10808,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": True, "userLevel": 8},
            "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": False},
        }],
        "outbounds": [
            outbound,
            {"tag": "direct", "protocol": "freedom", "settings": {"domainStrategy": "UseIP"}},
            {"tag": "block", "protocol": "blackhole", "settings": {"response": {"type": "http"}}},
        ],
        "routing": {"domainStrategy": "IPIfNonMatch", "rules": [
            {"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"},
            {"type": "field", "domain": ["geosite:private"], "outboundTag": "direct"},
        ]},
    }


def vless_to_config(uri: str, remark: str | None = None) -> dict:
    """vless://uuid@host:port?type=…&security=reality&pbk=… -> Xray config."""
    parts, q = _uri_query(uri)
    host = parts.hostname or ""
    port = parts.port or 443
    uuid = urllib.parse.unquote(parts.username or "")
    if not host or not uuid:
        raise ValueError("vless link is missing host or id")
    user = {
        "id": uuid,
        "encryption": q.get("encryption", "none") or "none",
        "level": 8,
    }
    flow = (q.get("flow") or "").strip()
    if flow:
        user["flow"] = flow
    outbound = {
        "tag": "proxy",
        "protocol": "vless",
        "settings": {"vnext": [{"address": host, "port": int(port), "users": [user]}]},
        "streamSettings": _stream_settings(host, q),
    }
    body = (q.get("security") or "").lower()
    if body:
        outbound["streamSettings"]["security"] = body if body in ("tls", "reality") else "none"
    return _base_config(host, outbound, remark)


def trojan_to_config(uri: str, remark: str | None = None) -> dict:
    """trojan://password@host:port?…#remark -> Xray config."""
    parts, q = _uri_query(uri)
    host = parts.hostname or ""
    port = parts.port or 443
    password = urllib.parse.unquote(parts.username or "")
    if not host or not password:
        raise ValueError("trojan link is missing host or password")
    outbound = {
        "tag": "proxy",
        "protocol": "trojan",
        "settings": {"servers": [{"address": host, "port": int(port), "password": password}]},
        "streamSettings": _stream_settings(host, {**q, "security": q.get("security", "tls")}),
    }
    return _base_config(host, outbound, remark)


def uri_to_config(uri: str, remark: str | None = None) -> dict:
    scheme = uri.split("://", 1)[0].strip().lower()
    if scheme == "vless":
        return vless_to_config(uri, remark)
    if scheme == "trojan":
        return trojan_to_config(uri, remark)
    raise ValueError(f"unsupported share-link scheme {scheme!r}")


# ---------------------------------------------------------------------------
# Export-time HTTPS URL checks
# ---------------------------------------------------------------------------

def _https_url(value: str, location: str) -> str:
    """Normalize an HTTPS-only endpoint without changing unrelated proxy hosts.

    HTTPS-only URL fields are URLs, not ordinary server addresses. A bare host,
    or an obsolete http:// prefix, must not be sent unchanged to clients that
    explicitly require an HTTPS scheme. This is a syntactic repair only: the
    destination still needs to support TLS and serve the requested endpoint.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{location}: HTTPS URL is missing")
    value = value.strip()
    if "://" not in value:
        value = "https://" + value.lstrip("/")
    else:
        parts = urllib.parse.urlsplit(value)
        if parts.scheme.lower() == "http":
            value = urllib.parse.urlunsplit(parts._replace(scheme="https"))
        elif parts.scheme.lower() != "https":
            raise ValueError(f"{location}: unsupported HTTPS URL scheme {parts.scheme!r}")
    try:
        parsed = urllib.parse.urlsplit(value)
        _ = parsed.port  # Detect malformed ports.
    except ValueError as exc:
        raise ValueError(f"{location}: malformed HTTPS URL: {exc}") from exc
    if parsed.scheme.lower() != "https" or not parsed.hostname or parsed.username is not None:
        raise ValueError(f"{location}: invalid HTTPS server URL")
    return value


def fix_https_endpoints(doc: dict) -> dict:
    """Fix explicit HTTPS-only URL fields in panel-provided Xray JSON.

    Do not prepend https:// to VLESS/Trojan *proxy addresses*, WebSocket hosts,
    REALITY serverNames, or any generic URL. Only explicitly HTTPS-only URL
    fields and DoH URLs need this repair.
    """
    def walk(value, loc="config"):
        if isinstance(value, list):
            return [walk(item, f"{loc}[{i}]") for i, item in enumerate(value)]
        if not isinstance(value, dict):
            return value
        fixed = {}
        for key, child in value.items():
            at = f"{loc}.{key}"
            canonical = key.lower().replace("_", "").replace("-", "")
            if canonical in {"serverurl", "dohurl", "dnsurl"} and isinstance(child, str):
                updated = _https_url(child, at)
                if updated != child:
                    print(f"warning: fixed HTTPS scheme in {at}", file=sys.stderr)
                fixed[key] = updated
            else:
                fixed[key] = walk(child, at)
        return fixed

    out = walk(doc)
    dns = out.get("dns")
    if isinstance(dns, dict) and isinstance(dns.get("servers"), list):
        # An http:// URL inside Xray's DNS resolver list is an invalid DoH URL.
        # Other DNS types (IP, tcp://, quic+local://, https+local://) are not changed.
        servers = []
        for i, entry in enumerate(dns["servers"]):
            if isinstance(entry, str) and entry.lower().startswith("http://"):
                new = _https_url(entry, f"dns.servers[{i}]")
                print(f"warning: fixed DoH HTTPS scheme in dns.servers[{i}]", file=sys.stderr)
                servers.append(new)
            elif isinstance(entry, dict) and isinstance(entry.get("address"), str) and entry["address"].lower().startswith("http://"):
                new = dict(entry)
                new["address"] = _https_url(entry["address"], f"dns.servers[{i}].address")
                print(f"warning: fixed DoH HTTPS scheme in dns.servers[{i}].address", file=sys.stderr)
                servers.append(new)
            else:
                servers.append(entry)
        dns["servers"] = servers

    # Happ 6.2.0 compatibility: some iOS clients reject DNS-over-TCP URLs
    # with an HTTPS-scheme validation error, even though Xray-core accepts them.
    # Convert ONLY well-known resolver endpoints to their real DoH services.
    # This is not a blind tcp:// -> https:// rewrite (which would be invalid).
    doh_for_dns_tcp = {
        "1.1.1.1": "https://cloudflare-dns.com/dns-query",
        "1.0.0.1": "https://cloudflare-dns.com/dns-query",
        "8.8.8.8": "https://dns.google/dns-query",
        "8.8.4.4": "https://dns.google/dns-query",
        "9.9.9.9": "https://dns.quad9.net/dns-query",
        "149.112.112.112": "https://dns.quad9.net/dns-query",
    }
    if isinstance(dns, dict) and isinstance(dns.get("servers"), list):
        fixed_servers = []
        for i, entry in enumerate(dns["servers"]):
            address = entry if isinstance(entry, str) else (
                entry.get("address") if isinstance(entry, dict) else None
            )
            if isinstance(address, str) and address.lower().startswith("tcp://"):
                parsed = urllib.parse.urlsplit(address)
                ip = parsed.hostname
                if ip not in doh_for_dns_tcp:
                    raise ValueError(
                        f"dns.servers[{i}]: no verified DoH equivalent for DNS-over-TCP server {address!r}; "
                        "replace it with a verified HTTPS DoH endpoint"
                    )
                doh = doh_for_dns_tcp[ip]
                if isinstance(entry, dict):
                    updated = dict(entry)
                    updated["address"] = doh
                    # Port 53 is the original DNS-over-TCP port, not valid for DoH.
                    updated.pop("port", None)
                    entry = updated
                else:
                    entry = doh
                print(f"warning: converted dns.servers[{i}] TCP DNS to {doh} for Happ", file=sys.stderr)
            fixed_servers.append(entry)
        dns["servers"] = fixed_servers

    # MASQUE requires TLS by the Xray transport specification. Rather than
    # inventing a TLS configuration for a non-TLS server, reject broken entries.
    for i, ob in enumerate(out.get("outbounds") or []):
        if not isinstance(ob, dict):
            continue
        stream = ob.get("streamSettings") or {}
        if ob.get("protocol") == "masque" and stream.get("security") != "tls":
            raise ValueError(f"outbounds[{i}]: MASQUE requires streamSettings.security='tls'")
    return out


def xray_configs(cfg: dict, drop_invalid: bool = True,
                 country_remarks: bool = True,
                 exclude: set[str] | None = None,
                 exclude_countries=EXCLUDED_COUNTRIES,
                 convert_uris: bool = True) -> list:
    """
    Return the exported profiles in payload order (normal, then smart).

    JSON profiles become objects (v2rayNG "Add profile from JSON"); share-link
    profiles (vless://, trojan://, ...) stay strings, which v2rayNG imports
    directly. Remarks / #fragments become
    "<flag> <country> #<unique 5-digit random number> KD Fast ⚡️".

    Countries listed in exclude_countries (default: GO) are dropped.
    """
    exclude_set = {p.strip().lower() for p in (exclude or set()) if p.strip()}
    drop_countries = {c.strip().upper() for c in (exclude_countries or ()) if c and c.strip()}

    items = list(cfg["configs"].get("normal") or []) + list(cfg["configs"].get("smart") or [])
    staged = []  # (kind, payload, country, name)
    for item in items:
        raw = item if isinstance(item, str) else (item or {}).get("config")
        if not isinstance(raw, str) or not raw.strip():
            continue
        country = ((item.get("country") if isinstance(item, dict) else "") or "").strip()
        name = ((item.get("name") if isinstance(item, dict) else "") or "").strip()
        if drop_countries and country.upper() in drop_countries:
            continue

        if _is_uri_config(raw):
            proto = _uri_protocol(raw)
            if exclude_set and proto in exclude_set:
                continue
            staged.append(("uri", raw.strip(), country, name))
            continue

        try:
            doc = json.loads(raw)
        except json.JSONDecodeError as exc:
            if not drop_invalid:
                raise
            print(f"warning: skipping unparsable config ({exc.msg})", file=sys.stderr)
            continue
        if not isinstance(doc, dict):
            continue
        proto = _doc_protocol(doc)
        if exclude_set and proto and proto in exclude_set:
            continue
        staged.append(("json", doc, country, name))

    # Draw without replacement so every exported profile gets a unique random
    # five-digit suffix, including profiles from the same country.
    if country_remarks and len(staged) > 90_000:
        raise ValueError("more profiles than available unique five-digit numbers")
    numbers = iter(secrets.SystemRandom().sample(range(10_000, 100_000), len(staged))) \
        if country_remarks else iter(())

    out: list = []
    for kind, payload, country, name in staged:
        label = None
        if country_remarks:
            label = f"{country_label(country)} #{next(numbers)} KD Fast ⚡️"
        if kind == "json":
            try:
                doc = fix_https_endpoints(payload)
                if label:
                    doc["remarks"] = label
                out.append(doc)
            except ValueError as exc:
                if not drop_invalid:
                    raise
                print(f"warning: skipping invalid JSON profile: {exc}", file=sys.stderr)
        elif convert_uris:
            try:
                out.append(fix_https_endpoints(uri_to_config(payload, label)))
            except Exception as exc:
                if not drop_invalid:
                    raise
                print(f"warning: skipping share link ({exc}): {payload[:60]}", file=sys.stderr)
        elif label:
            out.append(_with_fragment(payload, label))
        else:
            out.append(payload)
    return out


def to_app_model(cfg: dict) -> dict:
    """Group normal profiles per country and flatten smart profiles."""
    normal = [c for c in cfg["configs"]["normal"]
              if isinstance(c, dict) and (c.get("config") or "").strip()]
    groups: dict[str, list] = {}
    for item in normal:
        country = (item.get("country") or "Unknown").strip() or "Unknown"
        groups.setdefault(country.upper(), []).append(item)

    locations = []
    for country, items in groups.items():
        servers = []
        for idx, item in enumerate(items):
            raw_id = str(item.get("id") or "")
            server_id = int(raw_id) if raw_id.isdigit() else (idx + 1)
            servers.append({
                "id": server_id,
                "name": f"{country}_{raw_id or server_id}",
                "config": item.get("config"),
                "regions": item.get("regions", ""),
            })
        locations.append({
            "country": country,
            "name": country,
            "flag": f"https://flagcdn.com/w80/{country.lower()}.png",
            "servers": servers,
        })

    smart = []
    for idx, item in enumerate(cfg["configs"]["smart"]):
        if isinstance(item, str):
            config, country, sid = item, "SMART", idx + 1
        else:
            config = item.get("config", "")
            country = (item.get("country") or "SMART").upper()
            sid = int(str(item.get("id"))) if str(item.get("id") or "").isdigit() else idx + 1
        smart.append({"id": sid, "country": country, "config": config})

    operators = [{"name": "App Configs", "locations": locations}]
    return {
        "baseUrl": cfg.get("baseUrl"),
        "domains": cfg.get("domains", []),
        "operators": operators,
        "smartProfiles": smart,
        "settings": cfg["settings"],
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def emit(text: str, out_path: str | None = None, summary: str | None = None) -> int:
    """Write text to stdout or to --out, keeping stdout clean when a file is used."""
    if not text.endswith("\n"):
        text += "\n"
    if not out_path:
        sys.stdout.write(text)
        return 0
    try:
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(text)
    except OSError as exc:
        print(f"error: cannot write {out_path}: {exc}", file=sys.stderr)
        return 1
    detail = f"{len(text.encode('utf-8'))} bytes"
    if summary:
        detail = f"{summary}, {detail}"
    print(f"wrote {out_path} ({detail})", file=sys.stderr)
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Load Kidi VPN remote app configs")
    ap.add_argument("--source", action="append", metavar="URL",
                    help="base URL override; repeat for several (default: from state, "
                         "then api.gem-panel.com and its CDN mirror)")
    ap.add_argument("--state", default="kidi_state.json", help="cache/state file")
    ap.add_argument("--cert-hex", help="file with the pinned certificate hex")
    ap.add_argument("--raw", help="parse a saved HTTP response body instead of fetching")
    ap.add_argument("--fix-export", metavar="PATH",
                    help="repair an already-exported Xray JSON array without panel access")
    ap.add_argument("--payload-file", help="decrypt a saved base64 'data' string")
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--proxy", default=os.environ.get("KIDI_PROXY"), metavar="HOST:PORT",
                    help="route HTTP(S) through this SOCKS5 proxy, e.g. "
                         "--proxy 192.168.0.208:1080 (default: $KIDI_PROXY, else direct)")
    ap.add_argument("--no-auth", action="store_true", help="omit the ApiKey authorization header")
    ap.add_argument("--force", action="store_true", help="ignore the timestamp gate")
    ap.add_argument("--json", action="store_true", help="print the full decrypted config")
    ap.add_argument("--model", action="store_true", help="print the mapped app model")
    ap.add_argument("--xrayjson", action="store_true",
                    help="print every profile as a full Xray/v2ray JSON config in one minified "
                         "array (vless:// links are converted); importable in v2rayNG")
    ap.add_argument("--keep-remarks", action="store_true",
                    help="keep the panel's own remarks instead of generated country / number / KD Fast labels")
    ap.add_argument("--uris", action="store_true",
                    help="print share-link profiles (vless://, trojan://, ...) one per line, "
                         "ready for v2rayNG's import-from-clipboard")
    ap.add_argument("--include-go", action="store_true",
                    help="also export GO (smart/global) profiles; they usually do not connect")
    ap.add_argument("--exclude", action="append", metavar="PROTO",
                    help="exclude configs by protocol (e.g. hysteria2). Repeatable/comma-separated")
    ap.add_argument("--xray-one", type=int, metavar="N",
                    help="print only the N-th config (1-based) as minified JSON, for a single paste")
    ap.add_argument("--debug", action="store_true",
                    help="print response status/headers and the full error text to stderr")
    ap.add_argument("--out", metavar="PATH",
                    help="write the selected output (e.g. --xrayjson) to PATH instead of stdout")
    ap.add_argument("--no-save", action="store_true", help="do not update the state file")
    args = ap.parse_args(argv)

    exclude = set()
    for e in (args.exclude or []):
        if not e:
            continue
        for part in e.replace(" ", ",").split(","):
            p = part.strip().lower()
            if p:
                exclude.add(p)

    try:
        proxy = parse_proxy(args.proxy)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.fix_export:
        try:
            with open(args.fix_export, "r", encoding="utf-8") as stream:
                exported = json.load(stream)
            if not isinstance(exported, list):
                raise ValueError("Expected a JSON array of Xray profiles")
            repaired = []
            for idx, entry in enumerate(exported, start=1):
                if not isinstance(entry, dict):
                    raise ValueError(f"Profile {idx} is not an Xray JSON object")
                repaired.append(fix_https_endpoints(entry))
            return emit(json.dumps(repaired, ensure_ascii=False, separators=(",", ":")),
                        args.out, f"{len(repaired)} Happ-compatible profiles")
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: cannot repair export: {exc}", file=sys.stderr)
            return 1

    cert_hex = load_pinned_cert_hex(args.cert_hex)
    key = derive_key(cert_hex)
    state = {}
    if os.path.exists(args.state):
        try:
            state = json.load(open(args.state, "r", encoding="utf-8"))
        except Exception:
            state = {}

    # offline paths -------------------------------------------------------
    if args.payload_file:
        cfg = decrypt_payload(open(args.payload_file, "r", encoding="utf-8").read().strip(), key)
        validate_payload(cfg)
        meta = {"source": "payload-file", "accepted": True}
    elif args.raw:
        wrapper = json.loads(open(args.raw, "rb").read())
        if isinstance(wrapper, dict) and "data" in wrapper:
            cfg = decrypt_payload(wrapper["data"], key)
            meta = {"source": "raw", "server_timestamp": wrapper.get("timestamp"), "accepted": True}
        else:
            raise SystemExit("raw file is not a wrapper with a 'data' field")
        validate_payload(cfg)
    else:
        sources = build_sources(state, args.source)
        try:
            cfg, meta = load_config(sources, cert_hex, state=state,
                                    timeout=args.timeout, force=args.force,
                                    proxy=proxy,
                                    api_key=None if args.no_auth else API_KEY,
                                    debug=args.debug)
        except RuntimeError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        if not args.no_save and meta.get("accepted"):
            state.update({
                "timestamp": meta.get("server_timestamp", state.get("timestamp")),
                "baseUrl": cfg.get("baseUrl") or meta.get("source"),
                "domains": cfg.get("domains", []),
                "config": cfg,
            })
            with open(args.state, "w", encoding="utf-8") as fh:
                json.dump(state, fh)

    # output --------------------------------------------------------------
    if args.json:
        return emit(json.dumps(cfg, indent=2, ensure_ascii=False), args.out)
    exclude_countries = () if args.include_go else EXCLUDED_COUNTRIES

    if args.uris:
        docs = xray_configs(cfg, country_remarks=not args.keep_remarks, exclude=exclude,
                            exclude_countries=exclude_countries, convert_uris=False)
        uris = [d for d in docs if isinstance(d, str)]
        skipped = len(docs) - len(uris)
        if skipped:
            print(f"warning: {skipped} JSON profile(s) are not share links; "
                  f"use --xrayjson for those", file=sys.stderr)
        if not uris:
            print("error: no share-link profiles in this payload", file=sys.stderr)
            return 1
        return emit("\n".join(uris), args.out, f"{len(uris)} URI(s)")

    if args.xrayjson or args.xray_one:
        docs = xray_configs(cfg, country_remarks=not args.keep_remarks, exclude=exclude,
                            exclude_countries=exclude_countries)
        if args.xray_one is not None:
            if not 1 <= args.xray_one <= len(docs):
                print(f"error: --xray-one expects 1..{len(docs)}", file=sys.stderr)
                return 2
            entry = docs[args.xray_one - 1]
            text = (entry if isinstance(entry, str)
                    else json.dumps(entry, separators=(",", ":"), ensure_ascii=False))
            return emit(text, args.out, f"config {args.xray_one} of {len(docs)}")
        return emit(json.dumps(docs, separators=(",", ":"), ensure_ascii=False), args.out,
                    f"{len(docs)} config(s)")
    if args.model:
        return emit(json.dumps(to_app_model(cfg), indent=2, ensure_ascii=False), args.out)

    model = to_app_model(cfg)
    s = cfg["settings"]
    lines = [
        f"source            : {meta.get('source')}",
        f"proxy             : {meta.get('proxy') or 'direct'}",
    ]
    if meta.get("note"):
        lines.append(f"note              : {meta['note']}")
    lines += [
        f"baseUrl           : {cfg.get('baseUrl')}",
        f"domains           : {', '.join(cfg.get('domains') or []) or '-'}",
        f"settings groups   : {', '.join(s.keys())}",
    ]
    upd = s.get("appUpdate", {})
    lines.append(f"app update        : v{upd.get('appVersion', '-')} force={upd.get('forceUpdate', '-')}")
    lines.append(f"normal profiles   : {len(cfg['configs']['normal'])}")
    for loc in model["operators"][0]["locations"]:
        lines.append(f"  {loc['country']:<8} {len(loc['servers'])} server(s)")
    lines.append(f"smart profiles    : {len(model['smartProfiles'])}")
    lines.append(f"openvpn profiles  : {len(cfg['configs'].get('openvpn') or [])}")
    exported = xray_configs(cfg, country_remarks=False, exclude=exclude,
                            exclude_countries=exclude_countries)
    n_uri = sum(1 for d in exported if isinstance(d, str))
    n_json = len(exported) - n_uri
    tag = "" if args.include_go else ", GO excluded"
    lines.append(f"exported profiles : {len(exported)} ({n_uri} uri, {n_json} json{tag})")
    return emit("\n".join(lines), args.out)


if __name__ == "__main__":
    sys.exit(main())
