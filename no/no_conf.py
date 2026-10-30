#!/usr/bin/env python3
"""
noraconf.py — fetch Nora VPN (`com.nora.vpn`) server profiles the way the app does.

Faithful reimplementation of the app's config-fetch path, recovered by reversing
v117.0.10 (versionCode 131):

  1. Client identity   : random UUID persisted as "uuid" (nora_client_identity) and
                         a per-process session UUID.
  2. Auth              : per-request AES-256-GCM "grant" over
                         {uuid, sessionId, nonce, issuedAtUnixSeconds} sent in
                         X-Nora-Uuid / X-Nora-Session-Id / X-Nora-Signature / X-Nora-Key-Id: 2.
                         key = HKDF-SHA256(master, salt="nora-hkdf-salt-v2", info="nora-sign-v2")
                         master = SHA256( lp(SHA256(apk cert)) || lp("com.nora.vpn")
                                          || lp(nativeMaterial) || lp("Play Store") )
                         nativeMaterial = 64 constant bytes from libnora_secrets.so
  3. Clock             : server time from the X-Nora-Server-Unix-Seconds response header;
                         the app retries once on HTTP 400 after syncing.
  4. Endpoints         : GET /v1/config, /v1/servers/normal, /v1/servers/selective,
                         /v1/servers/selective/{id}
  5. Payload           : server "Config" and "Credential" are AES-256-GCM with
                         key = HKDF(..., info="nora-config-v2"), AAD="nora-config-v2",
                         encoded "v1.<b64url iv>.<b64url ct>.<b64url tag>".

No third-party dependencies (AES-GCM is included and self-tested).

Usage
  python3 noraconf.py                     # summary of the normal server
  python3 noraconf.py --all                # normal + every selective server
  python3 noraconf.py --all --xrayjson     # JSON array of the Xray configs
  python3 noraconf.py --all --xrayjson --inject-credential > configs.json
  python3 noraconf.py --all --prepared --out prepared.json
  python3 noraconf.py --mint-identity      # new local identity (standalone, bootstrap pool)
  python3 noraconf.py --mint-attested      # new attested identity via the app (real pool)
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import http.client
import itertools
import json
import os
import random
import ssl
import struct
import sys
import time
import urllib.error
import urllib.request
import uuid as uuidlib

# --------------------------------------------------------------------------- #
# Recovered constants
# --------------------------------------------------------------------------- #

BOOTSTRAP_HOST = '91.107.144.29'

DEFAULT_BASE_URL = "https://api.clyracore.com"
PACKAGE = "com.nora.vpn"
INSTALLER = "Play Store"           # xh1.a() mixes this literal into the master key
KEY_ID = "2"                       # X-Nora-Key-Id

# SHA-256 of the APK signing certificate of v117.0.10 (base.apk, versionCode 131).
DEFAULT_CERT_SHA256 = "1e7713fbc4c681284ece01608aa8a908c6048f7ad4e33cee175f9c5f9bf3ae56"

# nativeMaterial() output: libnora_secrets.so XORs three 64-byte constant tables at
# 0x10e4d0/0x10e510/0x10e550 (table3 permutes the result). Device independent.
NATIVE_MATERIAL = bytes.fromhex(
    "733e5368052660ec61023aff2d33d60867757a2da757410b8be01324592e81a5"
    "92e29dd2693e3018ababbaf67ede9a53d778dd3e31d59a2469b7d911adbf9518"
)

DEFAULT_UA = "Nora,131,Android(35),POCO,M2012K11AG,en"   # observed app UA on the test device

# Realistic Android devices for per-run fingerprint randomisation. The API only
# consumes the User-Agent string, so (brand, model, sdk) triples are enough.
DEVICE_POOL = [
    ('samsung', 'SM-S928B', 34), ('samsung', 'SM-S921B', 34), ('samsung', 'SM-A556E', 34),
    ('samsung', 'SM-A346E', 33), ('samsung', 'SM-F946B', 34),
    ('Google', 'Pixel 8 Pro', 34), ('Google', 'Pixel 8', 34), ('Google', 'Pixel 7a', 33),
    ('Google', 'Pixel 6', 33),
    ('Xiaomi', '23113RKC6G', 34), ('Xiaomi', '2211133G', 33), ('Xiaomi', 'M2101K6G', 33),
    ('Redmi', '2312DRA50G', 34), ('POCO', '23122PCD1G', 34),
    ('OnePlus', 'CPH2449', 34), ('OnePlus', 'LE2101', 33),
    ('OPPO', 'CPH2525', 34), ('OPPO', 'PJF110', 33),
    ('vivo', 'V2227', 33), ('vivo', 'V2230', 33),
    ('realme', 'RMX3706', 33), ('realme', 'RMX3630', 33),
    ('motorola', 'moto g84 5G', 33), ('motorola', 'moto g54 5G', 33),
    ('HONOR', 'ANY-LX1', 33), ('HONOR', 'RKY-LX1', 33),
    ('HUAWEI', 'ELS-NX9', 31), ('HUAWEI', 'NOH-NX9', 31),
    ('Nokia', 'TA-1043', 30), ('Sony', 'XQ-DQ72', 33), ('Nothing', 'A065', 33),
]
LOCALE_POOL = ['en', 'fa', 'ar', 'tr', 'ru', 'id', 'hi', 'fr', 'de', 'es', 'pt', 'it']


def random_user_agent(version=131, seed=None, lang='en'):
    """Build a User-Agent modeled on cs3.m0(): Nora,<vc>,Android(<sdk>),<brand>,<model>,<lang>.

    The API localises server Location names by this language token, so it is kept
    at English unless the caller asks otherwise ('random' picks one per run).
    """
    rng = random.Random(seed) if seed is not None else random.SystemRandom()
    brand, model, sdk = rng.choice(DEVICE_POOL)
    if lang in (None, '', 'random'):
        lang = rng.choice(LOCALE_POOL)
    return f'Nora,{version},Android({sdk}),{brand},{model},{lang}'


# --------------------------------------------------------------------------- #
# AES-256-GCM (encrypt + decrypt), verified against NIST vectors
# --------------------------------------------------------------------------- #

_SBOX = bytes.fromhex(
    '637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0'
    'b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275'
    '09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf'
    'd0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2'
    'cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb'
    'e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08'
    'ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e'
    'e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16'
)
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D]


def _xtime(a):
    a <<= 1
    return (a ^ 0x11B) & 0xFF if a & 0x100 else a


def _mul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = _xtime(a)
        b >>= 1
    return r


def _expand_key(key):
    nk = len(key) // 4
    nr = nk + 6
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        t = list(w[i - 1])
        if i % nk == 0:
            t = t[1:] + t[:1]
            t = [_SBOX[b] for b in t]
            t[0] ^= _RCON[i // nk - 1]
        elif nk > 6 and i % nk == 4:
            t = [_SBOX[b] for b in t]
        w.append([w[i - nk][j] ^ t[j] for j in range(4)])
    return [sum(w[4 * r:4 * r + 4], []) for r in range(nr + 1)], nr


def _encrypt_block(rk, nr, block):
    s = [block[i] ^ rk[0][i] for i in range(16)]
    for rnd in range(1, nr + 1):
        s = [_SBOX[b] for b in s]
        s = [s[0], s[5], s[10], s[15], s[4], s[9], s[14], s[3],
             s[8], s[13], s[2], s[7], s[12], s[1], s[6], s[11]]
        if rnd != nr:
            mixed = []
            for c in range(4):
                a0, a1, a2, a3 = s[4 * c:4 * c + 4]
                mixed += [
                    _mul(a0, 2) ^ _mul(a1, 3) ^ a2 ^ a3,
                    a0 ^ _mul(a1, 2) ^ _mul(a2, 3) ^ a3,
                    a0 ^ a1 ^ _mul(a2, 2) ^ _mul(a3, 3),
                    _mul(a0, 3) ^ a1 ^ a2 ^ _mul(a3, 2),
                ]
            s = mixed
        s = [s[i] ^ rk[rnd][i] for i in range(16)]
    return bytes(s)


def _gf_mul(x, y):
    r = 0
    for i in range(127, -1, -1):
        if (y >> i) & 1:
            r ^= x
        x = (x >> 1) ^ (0xE1 << 120) if x & 1 else x >> 1
    return r


def _ghash(h, aad, ct):
    def blocks(data):
        return [int.from_bytes(data[i:i + 16].ljust(16, b'\x00'), 'big')
                for i in range(0, len(data), 16)]

    y = 0
    for x in blocks(aad) + blocks(ct):
        y = _gf_mul(y ^ x, h)
    y = _gf_mul(y ^ int.from_bytes(struct.pack('>QQ', len(aad) * 8, len(ct) * 8), 'big'), h)
    return y.to_bytes(16, 'big')


def _keystream(rk, nr, iv, length):
    out = bytearray()
    counter = 2
    for _ in range(0, length, 16):
        out += _encrypt_block(rk, nr, iv + struct.pack('>I', counter))
        counter += 1
    return bytes(out[:length])


def aes_gcm_encrypt(key, iv, plaintext, aad=b''):
    rk, nr = _expand_key(key)
    h = int.from_bytes(_encrypt_block(rk, nr, b'\x00' * 16), 'big')
    ct = bytes(a ^ b for a, b in zip(plaintext, _keystream(rk, nr, iv, len(plaintext))))
    tag = bytes(a ^ b for a, b in zip(
        _encrypt_block(rk, nr, iv + b'\x00\x00\x00\x01'), _ghash(h, aad, ct)))
    return ct + tag


def aes_gcm_decrypt(key, iv, blob, aad=b''):
    ct, tag = blob[:-16], blob[-16:]
    rk, nr = _expand_key(key)
    h = int.from_bytes(_encrypt_block(rk, nr, b'\x00' * 16), 'big')
    expect = bytes(a ^ b for a, b in zip(
        _encrypt_block(rk, nr, iv + b'\x00\x00\x00\x01'), _ghash(h, aad, ct)))
    if not hmac.compare_digest(expect, tag):
        return None
    return bytes(a ^ b for a, b in zip(ct, _keystream(rk, nr, iv, len(ct))))


def _selftest():
    k, iv = b'\x00' * 32, b'\x00' * 12
    assert aes_gcm_encrypt(k, iv, b'').hex() == '530f8afbc74536b9a963b4f1c4cb738b'
    assert aes_gcm_encrypt(k, iv, b'\x00' * 16).hex() == \
        'cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919'
    assert aes_gcm_decrypt(k, iv, aes_gcm_encrypt(k, iv, b'hello', b'aad'), b'aad') == b'hello'


# --------------------------------------------------------------------------- #
# Key derivation
# --------------------------------------------------------------------------- #

def _lp4(data: bytes) -> bytes:
    return struct.pack('>I', len(data)) + data


def _hkdf(ikm: bytes, salt: bytes, info: bytes, n: int = 32) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, t, i = b'', b'', 1
    while len(okm) < n:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:n]


def derive_keys(cert_sha256: bytes):
    """Return (sign_key, config_key) exactly as xh1.a() computes them."""
    master = hashlib.sha256(
        _lp4(cert_sha256) + _lp4(PACKAGE.encode()) + _lp4(NATIVE_MATERIAL) + _lp4(INSTALLER.encode())
    ).digest()
    salt = b'nora-hkdf-salt-v2'
    return (_hkdf(master, salt, b'nora-sign-v2'),
            _hkdf(master, salt, b'nora-config-v2'))


def apk_cert_sha256(apk_path: str) -> bytes:
    """SHA-256 of the first APK Signature Scheme v2 signer certificate."""
    data = open(apk_path, 'rb').read()
    eocd = data.rfind(b'PK\x05\x06')
    if eocd < 0:
        raise ValueError('not a ZIP/APK')
    cd_off = struct.unpack_from('<I', data, eocd + 16)[0]
    if data[cd_off - 16: cd_off] != b'APK Sig Block 42':
        raise ValueError('no APK signing block (v2+ required)')
    size = struct.unpack_from('<Q', data, cd_off - 24)[0]
    off = cd_off - size - 8 + 8
    while off < cd_off - 24:
        ln = struct.unpack_from('<Q', data, off)[0]
        pid = struct.unpack_from('<I', data, off + 8)[0]
        val = data[off + 12: off + 8 + ln]
        off += 8 + ln
        if pid != 0x7109871a:
            continue
        n = struct.unpack_from('<I', val, 0)[0]
        signer, _ = val[4:4 + n], None
        n = struct.unpack_from('<I', signer, 0)[0]
        signed = signer[4:4 + n]
        n = struct.unpack_from('<I', signed, 0)[0]           # digests
        o = 4 + n
        n = struct.unpack_from('<I', signed, o)[0]           # certificates
        certs = signed[o + 4: o + 4 + n]
        n = struct.unpack_from('<I', certs, 0)[0]
        return hashlib.sha256(certs[4:4 + n]).digest()
    raise ValueError('no v2 signer found')


# --------------------------------------------------------------------------- #
# Client
# --------------------------------------------------------------------------- #

def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def b64u_dec(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))


class NoraError(RuntimeError):
    pass


class NoraClient:
    def __init__(self, base_url=DEFAULT_BASE_URL, uuid=None, cert_sha256=None, apk=None,
                 user_agent=DEFAULT_UA, timeout=25, retries=3, verify_tls=True, verbose=False):
        self.base_url = base_url.rstrip('/')
        self.uuid = uuid or str(uuidlib.uuid4())
        self.session_id = str(uuidlib.uuid4())
        self.user_agent = user_agent
        self.timeout = timeout
        self.retries = retries
        self.verbose = verbose
        self.clock_offset = 0

        cert = hashlib.sha256(apk_cert_sha256(apk)).digest() if apk else \
            bytes.fromhex(DEFAULT_CERT_SHA256 if cert_sha256 is None else cert_sha256)
        self.sign_key, self.config_key = derive_keys(cert)

        self.ctx = ssl.create_default_context()
        if not verify_tls:
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE
        _selftest()

    # -- helpers ---------------------------------------------------------- #

    def _log(self, *args):
        if self.verbose:
            print(*args, file=sys.stderr)

    def _auth_headers(self):
        ts = int(time.time()) + self.clock_offset
        payload = json.dumps({
            'uuid': self.uuid,
            'sessionId': self.session_id,
            'nonce': str(uuidlib.uuid4()),
            'issuedAtUnixSeconds': ts,
        }, separators=(',', ':')).encode()
        iv = os.urandom(12)
        blob = aes_gcm_encrypt(self.sign_key, iv, payload, b'nora-signature-v2')
        return {
            'X-Nora-Uuid': self.uuid,
            'X-Nora-Session-Id': self.session_id,
            'X-Nora-Signature': f'v1.{b64u(iv)}.{b64u(blob[:-16])}.{b64u(blob[-16:])}',
            'X-Nora-Key-Id': KEY_ID,
        }

    def _decode(self, blob: str):
        parts = blob.split('.')
        if len(parts) != 4 or parts[0] != 'v1':
            raise NoraError(f'unexpected payload envelope: {blob[:24]}...')
        plain = aes_gcm_decrypt(self.config_key, b64u_dec(parts[1]),
                                b64u_dec(parts[2]) + b64u_dec(parts[3]), b'nora-config-v2')
        if plain is None:
            raise NoraError('config payload failed to decrypt (key/APK mismatch?)')
        return plain.decode()

    # -- transport -------------------------------------------------------- #

    def request(self, path, method='GET', body=None):
        url = path if path.startswith('http') else self.base_url + path
        data = json.dumps(body, separators=(',', ':')).encode() if body is not None else None
        attempt = 0
        synced = False
        while True:
            attempt += 1
            req = urllib.request.Request(url, data=data, method=method)
            for k, v in self._auth_headers().items():
                req.add_header(k, v)
            req.add_header('Accept', 'application/json')
            req.add_header('User-Agent', self.user_agent)
            if data is not None:
                req.add_header('Content-Type', 'application/json; charset=utf-8')
            try:
                with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as resp:
                    raw = resp.read()
                    self._sync_clock(resp.headers)
                    return json.loads(raw) if raw else None
            except urllib.error.HTTPError as exc:
                self._sync_clock(exc.headers)
                code = exc.code
                self._log(f'[http] {method} {path} -> {code}')
                # The app retries once on 400 after syncing the server clock.
                if code == 400 and not synced:
                    synced = True
                    self._log('[http] 400 -> resyncing clock and retrying once')
                    continue
                if code in (429, 500, 502, 503, 504) and attempt <= self.retries:
                    delay = float(exc.headers.get('Retry-After') or 0) or (0.5 * 2 ** (attempt - 1))
                    time.sleep(min(delay, 10))
                    continue
                raise NoraError(f'HTTP {code} for {path}') from None
            except (urllib.error.URLError, OSError, http.client.HTTPException) as exc:
                # OSError covers socket.timeout (not a TimeoutError before Python 3.10),
                # ConnectionReset/Aborted, ssl.SSLError; HTTPException covers
                # RemoteDisconnected and BadStatusLine.
                if attempt <= self.retries:
                    time.sleep(0.5 * attempt)
                    continue
                raise NoraError(f'network error for {path}: {exc}') from None

    def _sync_clock(self, headers):
        value = headers.get('x-nora-server-unix-seconds') or headers.get('X-Nora-Server-Unix-Seconds')
        if not value:
            return
        try:
            offset = int(value) - int(time.time())
        except ValueError:
            return
        if abs(offset) >= 1:
            self._log(f'[clock] server offset {offset:+d}s')
        self.clock_offset = offset

    # -- endpoints -------------------------------------------------------- #

    def startup_config(self):
        return self.request('/v1/config')

    def normal_server(self):
        return self._server(self.request('/v1/servers/normal'), 'normal')

    def home_config(self):
        """The 'HomeCf' server from /v1/config: what the app's home button connects with."""
        startup = self.startup_config() or {}
        raw = startup.get('HomeCf')
        if not isinstance(raw, dict):
            raise NoraError('startup config has no HomeCf')
        return self._server(raw, 'home')

    def selective_servers(self):
        return self.request('/v1/servers/selective') or []

    def selective_server(self, server_id):
        return self._server(self.request(f'/v1/servers/selective/{int(server_id)}'), 'selective')

    def _server(self, raw, source='normal'):
        if not raw:
            raise NoraError('empty server response')
        try:
            return self._server_entry(raw, source)
        except NoraError:
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise NoraError(f'malformed server response: {exc!r}') from None

    def _server_entry(self, raw, source='normal'):
        entry = {
            'source': source,
            'id': raw.get('Id'),
            'location': raw.get('Location'),
            'flag': raw.get('Flag'),
            'circle_flag': raw.get('CircleFlag'),
            'credential': self._decode(raw['Credential']),
            'credential_kind': raw.get('CredentialKind'),
            'lease_id': raw.get('LeaseId'),
            'expires_at': raw.get('ExpiresAtUnix'),
            'lease_expires_at': raw.get('LeaseExpiresAt'),
            'lease_renew_after': raw.get('LeaseRenewAfter'),
        }
        entry['xray'] = json.loads(self._decode(raw['Config']))
        return entry


# --------------------------------------------------------------------------- #
# App-side post-processing (optional, mirrors the app)
# --------------------------------------------------------------------------- #

DNS_BLOCK = {
    'hosts': {},
    'queryStrategy': 'UseIPv4',
    'servers': ['https://1.1.1.1/dns-query', 'tcp://8.8.8.8:53', '1.1.1.1'],
    'tag': 'nora-dns',
}
ROUTING_RULES = [
    {'type': 'field', 'inboundTag': ['socks'], 'outboundTag': 'nora-dns-out',
     'port': '53', 'network': 'tcp,udp'},
    {'type': 'field', 'inboundTag': ['socks'], 'outboundTag': 'nora-dns-block',
     'port': '853', 'network': 'tcp', 'ip': ['10.10.14.2']},
    {'type': 'field', 'inboundTag': ['nora-dns'], 'outboundTag': 'proxy'},
    {'type': 'field', 'inboundTag': ['socks'], 'outboundTag': 'proxy',
     'port': '853', 'network': 'tcp'},
]


def inject_credential(cfg: dict, entry: dict) -> dict:
    """What Libv2ray.injectCredential() does: fill the lease secret into the outbound."""
    kind, secret = entry.get('credential_kind'), entry.get('credential')
    for out in cfg.get('outbounds', []):
        settings = out.get('settings') or {}
        if kind == 'user_id':
            for vnext in settings.get('vnext', []):
                for user in vnext.get('users', []):
                    user['id'] = secret
        elif kind == 'password':
            for server in settings.get('servers', []):
                server['password'] = secret
            for user in settings.get('users', []):
                user.setdefault('password', secret)
    return cfg


def prepare(cfg: dict, entry: dict) -> dict:
    """Mirror the app's prepared config: pinned DNS, DoH through the tunnel, DoT blocked."""
    cfg = inject_credential(cfg, entry)
    cfg['dns'] = json.loads(json.dumps(DNS_BLOCK))
    # The app keeps the profile's own host pins (dns.hosts) and adds its DoH resolver.
    cfg['dns']['hosts'].update((cfg.get('dns') or {}).get('hosts') or {})
    tags = {o.get('tag') for o in cfg.get('outbounds', [])}
    if 'nora-dns-out' not in tags:
        cfg['outbounds'].append({'tag': 'nora-dns-out', 'protocol': 'dns', 'settings': {}})
    if 'nora-dns-block' not in tags:
        cfg['outbounds'].append({'tag': 'nora-dns-block', 'protocol': 'blackhole', 'settings': {}})
    cfg['routing'] = {'domainStrategy': 'AsIs', 'rules': json.loads(json.dumps(ROUTING_RULES))}
    cfg.setdefault('stats', {})
    cfg.setdefault('policy', {'system': {'statsOutboundUplink': True, 'statsOutboundDownlink': True}})
    return cfg


def load_state(path):
    """Read a persisted identity (uuid + phone UA) from --state, if it exists."""
    if not path:
        return {}
    try:
        with open(path, 'r', encoding='utf-8') as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}
    out = {}
    if isinstance(data.get('uuid'), str) and data['uuid'].strip():
        out['uuid'] = data['uuid'].strip()
    if isinstance(data.get('user_agent'), str) and data['user_agent'].strip():
        out['user_agent'] = data['user_agent'].strip()
    return out


def load_uuid_pool(path):
    """Load a list of identities ({'uuid','user_agent'}) from JSON for rotation."""
    if not path:
        return []
    try:
        with open(path, 'r', encoding='utf-8') as fh:
            data = json.load(fh)
    except (OSError, ValueError) as exc:
        raise NoraError(f'cannot read --uuid-pool: {exc}') from None
    if isinstance(data, dict):
        data = data.get('identities') or []
    out = []
    for item in data:
        if isinstance(item, str):
            out.append({'uuid': item})
        elif isinstance(item, dict) and item.get('uuid'):
            out.append({'uuid': item['uuid'], 'user_agent': item.get('user_agent')})
    return out


def save_state(path, uuid, user_agent=None):
    """Persist an identity so later runs keep the same UUID (and phone fingerprint)."""
    if not path:
        return
    try:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        payload = {'uuid': uuid, 'created_at': int(time.time())}
        if user_agent:
            payload['user_agent'] = user_agent
        with open(path, 'w', encoding='utf-8') as fh:
            json.dump(payload, fh, indent=2)
        print(f'noraconf: saved identity to {path}', file=sys.stderr)
    except OSError as exc:
        print(f'noraconf: cannot persist identity to {path}: {exc}', file=sys.stderr)


def mint_identity(seed=None, lang='en'):
    """Create a brand-new client identity locally: random UUID + random phone UA.

    Fully standalone (no adb, no device). The API only knows this UUID as an
    unattested client, so it is served the shared bootstrap node; use
    --mint-attested (or --from-device) if you need the real server pool.
    """
    return {'uuid': str(uuidlib.uuid4()), 'user_agent': random_user_agent(seed=seed, lang=lang)}


def mint_attested_identity(serial=None, wait=40.0, settle=10.0, verbose=False):
    """Wipe the app data and let a fresh install attest a NEW identity.

    Device-assisted and destructive: only this path yields an *entitled* identity.

    The API only serves the real server pool (unique leases, REALITY or ECH nodes)
    to UUIDs the genuine app has attested with an Android Keystore hardware key; a synthetic UUID
    gets one shared bootstrap node. Clearing the data and launching the app once
    makes it create and attest a brand-new UUID — i.e. a fresh "random phone" that is
    also entitled. Destructive: erases the app's data on that device.
    """
    import re
    import subprocess

    def sh(*args, timeout=40):
        cmd = ['adb'] + (['-s', serial] if serial else []) + ['shell', *args]
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout.strip()

    if 'uid=0' not in sh('id'):
        raise NoraError('--mint-identity needs adb root (run `adb root` first)')

    if verbose:
        print('noraconf: force-stopping and clearing app data', file=sys.stderr)
    sh('am', 'force-stop', PACKAGE)
    sh('pm', 'clear', PACKAGE)
    sh('am', 'start', '-n', f'{PACKAGE}/.ui.SplashActivity')

    deadline = time.time() + wait
    uuid = None
    while time.time() < deadline:
        time.sleep(1.5)
        xml = sh('cat', f'/data/data/{PACKAGE}/shared_prefs/nora_client_identity.xml')
        match = re.search(r'name="uuid"[^>]*>([0-9a-fA-F-]{36})<', xml or '')
        if match:
            uuid = match.group(1)
            if verbose:
                print(f'noraconf: app created uuid {uuid}; waiting for first-run attestation',
                      file=sys.stderr)
            break
    if not uuid:
        raise NoraError('the app did not create a new identity in time')

    # Give the first run time to attest and fetch its configs.
    time.sleep(settle)
    return device_identity(serial)


def append_uuid_pool(path, uuid):
    """Append a UUID to a --uuid-pool file (created if missing, duplicates skipped).

    Only the UUID is stored: the pool is meant to stay fingerprint-free so every run can
    present a fresh random User-Agent.
    """
    if not path:
        return
    items = []
    try:
        with open(path, 'r', encoding='utf-8') as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            data = data.get('identities') or []
        items = [i if isinstance(i, dict) else {'uuid': i} for i in data if i]
    except (OSError, ValueError):
        items = []
    if any(str(i.get('uuid', '')).strip() == uuid for i in items):
        print(f'noraconf: {uuid} already in {path}', file=sys.stderr)
        return
    items.append({'uuid': uuid})
    try:
        parent = os.path.dirname(os.path.abspath(path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, 'w', encoding='utf-8') as fh:
            json.dump(items, fh, indent=2)
        print(f'noraconf: added {uuid} to {path} ({len(items)} identities)', file=sys.stderr)
    except OSError as exc:
        print(f'noraconf: cannot write {path}: {exc}', file=sys.stderr)


def device_identity(serial=None):
    """Read the installed app's UUID and the phone's properties via adb.

    The app is not debuggable, so the UUID needs adb root (userdebug/eng builds or
    `adb root`). Returns {'uuid', 'brand', 'model', 'sdk', 'lang', 'version'}.
    """
    import re
    import subprocess

    def sh(*args):
        cmd = ['adb'] + (['-s', serial] if serial else []) + ['shell', *args]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        return proc.stdout.strip()

    def prop(name, default=''):
        return sh('getprop', name).strip() or default

    xml = sh('cat', f'/data/data/{PACKAGE}/shared_prefs/nora_client_identity.xml')
    if not xml:
        xml = sh('su', '-c', f'cat /data/data/{PACKAGE}/shared_prefs/nora_client_identity.xml')
    match = re.search(r'name="uuid"[^>]*>([0-9a-fA-F-]{36})<', xml or '')
    if not match:
        raise NoraError(
            'cannot read the app UUID from the device; run `adb root` first '
            '(LineageOS userdebug) or pass --uuid/--state')

    version = '131'
    dump = sh('dumpsys', 'package', PACKAGE)
    vm = re.search(r'versionCode=(\d+)', dump or '')
    if vm:
        version = vm.group(1)

    brand = prop('ro.product.brand', 'Android').replace(',', ' ')
    model = prop('ro.product.model', 'device').replace(',', ' ')
    sdk = prop('ro.build.version.sdk', '35')
    locale = prop('persist.sys.locale') or prop('ro.product.locale', 'en')
    lang = locale.split('-')[0] or 'en'
    return {
        'uuid': match.group(1),
        'brand': brand, 'model': model, 'sdk': sdk, 'lang': lang,
        'version': version,
        'ua': f'Nora,{version},Android({sdk}),{brand},{model},{lang}',
    }


def remarks_label(entry: dict, mode: str = 'country'):
    """Build the '<flag> <country>' label for the Xray `remarks` field.

    mode 'country'  -> "<flag> <country>"        e.g. "🇩🇪 Germany"        (default)
    mode 'location' -> "<flag> <Location>"       e.g. "🇨🇦 Canada - Montreal"
    mode 'keep'     -> None (leave the server's own remarks untouched)
    """
    if mode == 'keep':
        return None
    flag = (entry.get('flag') or '').strip()
    location = (entry.get('location') or '').strip()
    if mode == 'country' and ' - ' in location:
        location = location.split(' - ', 1)[0].strip()
    parts = [part for part in (flag, location) if part]
    return ' '.join(parts) or None


def is_ech(entry: dict) -> bool:
    """True when the profile's TLS stream settings carry an ECHConfigList."""
    try:
        tls = entry['xray']['outbounds'][0]['streamSettings'].get('tlsSettings') or {}
    except (KeyError, IndexError, TypeError):
        return False
    return bool(tls.get('echConfigList'))


def server_key(entry: dict) -> str:
    try:
        v = entry['xray']['outbounds'][0]['settings']['vnext'][0]
        return f"{v.get('address')}:{v.get('port')}"
    except (KeyError, IndexError, TypeError):
        return str(entry.get('id'))


def describe_profile(entry: dict) -> str:
    """Short human label for a fetched profile: ECH / REALITY (bootstrap|real pool) / other."""
    try:
        out = entry['xray']['outbounds'][0]
        ss = out.get('streamSettings') or {}
        security = ss.get('security', '?')
        if is_ech(entry):
            return 'ECH'
        if security == 'reality':
            addr = (out.get('settings', {}).get('vnext', [{}])[0] or {}).get('address', '?')
            kind = 'bootstrap' if addr == BOOTSTRAP_HOST else 'real pool'
            return f'REALITY {addr} ({kind})'
        return str(security)
    except (KeyError, IndexError, TypeError):
        return 'unknown'


def collect_ech(clients, want_normal, want_selective, args, log=print):
    """Fetch repeatedly, rotating identities, until ECH-bearing profiles are found.

    The pool mixes ECH / REALITY / bootstrap, and per-UUID throttling kicks in after a
    couple of calls, so every single request rotates to the next identity.
    """
    if not isinstance(clients, (list, tuple)):
        clients = [clients]
    clients = list(clients)
    rotor = itertools.cycle(clients)
    collected, seen = {}, set()
    attempts = max(1, args.ech_attempts)
    limit = args.limit
    selective_ids = None

    for round_no in range(1, attempts + 1):
        targets = []
        if want_normal or not want_selective:
            targets.append(('normal', None))
        if want_selective:
            if selective_ids is None:
                listing = clients[0].selective_servers()
                if limit:
                    listing = listing[:limit]
                selective_ids = [item['Id'] for item in listing]
            targets += [('selective', sid) for sid in selective_ids if sid not in seen]
        if not targets:
            break

        for kind, sid in targets:
            client = next(rotor)
            if args.verbose:
                label = f'{kind}/{sid}' if sid is not None else kind
                log(f'noraconf: {label} via {client.uuid} ({client.user_agent})', file=sys.stderr)
            try:
                entry = client.normal_server() if kind == 'normal' else client.selective_server(sid)
            except Exception as exc:  # noqa: BLE001 - one bad request must not end the run
                log(f'noraconf: {kind}{"/" + str(sid) if sid else ""} failed: {exc}', file=sys.stderr)
                continue
            if args.verbose:
                log(f'noraconf: {kind}{"/" + str(sid) if sid else ""} -> '
                    f'{describe_profile(entry)}', file=sys.stderr)
            key = server_key(entry)
            if is_ech(entry) and key not in collected:
                collected[key] = entry
                log(f'noraconf: ECH {entry.get("location")} -> {key}', file=sys.stderr)
            elif sid is not None:
                seen.add(sid)
            if len(collected) >= args.ech_count:
                return list(collected.values())
            time.sleep(args.ech_delay)

        log(f'noraconf: round {round_no}/{attempts}: {len(collected)} ECH config(s)', file=sys.stderr)
        if round_no < attempts:
            time.sleep(args.ech_delay)

    return list(collected.values())


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main(argv=None):
    ap = argparse.ArgumentParser(
        description='Fetch Nora VPN server profiles (Xray configs) via the app API.')
    ap.add_argument('--xrayjson', action='store_true',
                    help='emit a JSON array of the Xray configs instead of a summary')
    ap.add_argument('--remarks', choices=('country', 'location', 'keep'), default='country',
                    help='Xray "remarks" label with --xrayjson: country = "<flag> <country>" '
                         '(default), location = "<flag> <Country - City>", keep = server value')
    ap.add_argument('--all', action='store_true',
                    help='fetch the normal server and every selective server')
    ap.add_argument('--selective', action='store_true',
                    help='fetch the selective server list (and their configs)')
    ap.add_argument('--normal', action='store_true', help='fetch the normal server (default)')
    ap.add_argument('--uuid-pool', metavar='FILE',
                    help='JSON list of enrolled identities to rotate for --ech '
                         '([{"uuid": "...", "user_agent": "..."}]); avoids per-UUID throttling')
    ap.add_argument('--allow-empty', action='store_true',
                    help='exit 0 even when nothing was retrieved (writes [] with --out); '
                         'use in CI so a throttled run does not fail the job')
    ap.add_argument('--ech', action='store_true',
                    help='collect ECH profiles only: retry (the pool mixes REALITY/ECH/bootstrap) '
                         'until ECH configs are found')
    ap.add_argument('--ech-count', type=int, default=1,
                    help='stop after this many distinct ECH servers (default 1)')
    ap.add_argument('--ech-attempts', type=int, default=10,
                    help='maximum fetch rounds in --ech mode (default 10)')
    ap.add_argument('--ech-delay', type=float, default=4.0,
                    help='seconds between --ech requests (default 4)')
    ap.add_argument('--home', action='store_true',
                    help='also include the HomeCf server from /v1/config (what the app '
                         'uses for its main connect button)')
    ap.add_argument('--inject-credential', action='store_true',
                    help='write the lease credential into each config (as the app does)')
    ap.add_argument('--prepared', action='store_true',
                    help='also apply the app\'s DNS/route hardening (implies --inject-credential)')
    ap.add_argument('--pretty', action='store_true', help='pretty-print JSON output')
    ap.add_argument('--out', metavar='FILE', help='write output to FILE instead of stdout')
    ap.add_argument('--uuid',
                    help='client UUID to use (default: a fresh random one per run, i.e. a new '
                         '"install"; the app instead keeps one UUID forever)')
    ap.add_argument('--state', metavar='FILE',
                    help='persist the client UUID in FILE and reuse it on later runs '
                         '(mimics the app\'s nora_client_identity); ignored when --uuid is set')
    ap.add_argument('--base-url', default=DEFAULT_BASE_URL)
    ap.add_argument('--apk', help='APK path; derive keys from its signing certificate')
    ap.add_argument('--cert-sha256', help='override the APK certificate SHA-256 (hex)')
    ap.add_argument('--random-ua', action='store_true',
                    help='always send a random fake phone in the User-Agent, ignoring any '
                         'device fingerprint stored in --state (hides your real model)')
    ap.add_argument('--user-agent', default=None,
                    help='pin the User-Agent; default is a random realistic Android device '
                         'per run (brand/model/sdk/language)')
    ap.add_argument('--seed', type=int,
                    help='seed for the random device fingerprint (reproducible runs)')
    ap.add_argument('--lang', default='en',
                    help='language token in the random User-Agent; the API localises server '
                         'Location names by it (default: en; use "random" to vary)')
    ap.add_argument('--from-device', nargs='?', const='', metavar='SERIAL',
                    help='read the UUID and device properties from a connected phone via adb '
                         '(needs `adb root` for the UUID); gives exact app parity')
    ap.add_argument('--mint-identity', action='store_true',
                    help='create a brand-new identity locally (random UUID + random phone UA); '
                         'standalone, no device needed. Unattested, so the API serves the '
                         'bootstrap node')
    ap.add_argument('--mint-attested', action='store_true',
                    help='enroll a NEW uuid through the app on a connected phone: wipes the app '
                         'data, launches it once so Android hardware key attestation registers '
                         'the uuid, then uses it (destructive, needs adb root). Combine with '
                         '--state to keep using it locally afterwards')
    ap.add_argument('--enroll', action='store_true',
                    help='alias for --mint-attested (one-time device enrollment; pair it with '
                         '--state so later runs need no device)')
    ap.add_argument('--jobs', type=int, default=1,
                    help='parallel fetches for --all/--selective (default 1; each call '
                         'provisions a lease and takes several seconds)')
    ap.add_argument('--limit', type=int, help='only fetch the first N selective servers')
    ap.add_argument('--delay', type=float, default=0.3,
                    help='seconds between sequential requests (default 0.3)')
    ap.add_argument('--mint-settle', type=float, default=10.0,
                    help='seconds to wait after a minted install before using it (default 10)')
    ap.add_argument('--timeout', type=float, default=25)
    ap.add_argument('--retries', type=int, default=3)
    ap.add_argument('--insecure', action='store_true', help='skip TLS verification')
    ap.add_argument('--verbose', '-v', action='store_true')
    args = ap.parse_args(argv)

    if args.prepared:
        args.inject_credential = True

    if args.ech and not (args.uuid or args.state or args.uuid_pool
                         or args.from_device is not None
                         or args.mint_attested or args.enroll):
        print("noraconf: --ech needs an enrolled identity (--uuid, --state, --uuid-pool\n"
              "          or --enroll). A brand-new local identity is not attested, so the\n"
              "          API only serves the shared bootstrap node and never an ECH profile.\n"
              "          Note: every enrollment made by the same phone shares that phone's\n"
              "          hardware attestation key, so the service can correlate them.", file=sys.stderr)
        return 2


    device = None
    local = None
    if args.mint_attested or args.enroll:
        if args.uuid:
            print('noraconf: --mint-attested cannot be combined with --uuid', file=sys.stderr)
            return 1
        try:
            device = mint_attested_identity(args.from_device or None,
                                            settle=args.mint_settle, verbose=args.verbose)
        except (NoraError, OSError) as exc:
            print(f'noraconf: --mint-attested failed: {exc}', file=sys.stderr)
            return 1
        print(f"noraconf: enrolled identity {device['uuid']} "
              f"({device['brand']} {device['model']})", file=sys.stderr)
        save_state(args.state, device['uuid'], device['ua'])
        append_uuid_pool(args.uuid_pool, device['uuid'])
        if not args.state:
            print('noraconf: tip: add --state FILE next time to reuse this identity locally '
                  'without the device', file=sys.stderr)
    elif args.mint_identity:
        if args.uuid:
            print('noraconf: --mint-identity cannot be combined with --uuid', file=sys.stderr)
            return 1
        local = mint_identity(seed=args.seed, lang=args.lang)
        print(f"noraconf: minted identity {local['uuid']} ({local['user_agent']})",
              file=sys.stderr)
        save_state(args.state, local['uuid'], local['user_agent'])
        append_uuid_pool(args.uuid_pool, local['uuid'])
    elif args.from_device is not None:
        try:
            device = device_identity(args.from_device or None)
        except (NoraError, OSError) as exc:
            print(f'noraconf: --from-device failed: {exc}', file=sys.stderr)
            return 1

    state = load_state(args.state)
    client_uuid = (args.uuid
                   or (device or {}).get('uuid')
                   or (local or {}).get('uuid')
                   or state.get('uuid'))
    if not client_uuid and args.state:
        created = mint_identity(seed=args.seed, lang=args.lang)
        save_state(args.state, created['uuid'], created['user_agent'])
        print(f'noraconf: {args.state} did not exist; created identity {created["uuid"]}',
              file=sys.stderr)
        local = created
        client_uuid = created['uuid']
    if args.user_agent:
        user_agent = args.user_agent
    elif args.random_ua:
        user_agent = random_user_agent(seed=args.seed, lang=args.lang)
    elif device:
        user_agent = device['ua']
    elif local:
        user_agent = local['user_agent']
    elif state.get('user_agent'):
        user_agent = state['user_agent']
    else:
        user_agent = random_user_agent(seed=args.seed, lang=args.lang)

    client = NoraClient(base_url=args.base_url, uuid=client_uuid, apk=args.apk,
                        cert_sha256=args.cert_sha256, user_agent=user_agent,
                        timeout=args.timeout, retries=args.retries,
                        verify_tls=not args.insecure, verbose=args.verbose)
    explicit_id = bool(args.uuid or args.state or args.from_device is not None
                       or args.mint_attested or args.enroll or args.mint_identity)
    if args.verbose:
        if args.uuid_pool and not explicit_id:
            print(f'noraconf: rotating {len(load_uuid_pool(args.uuid_pool))} pooled identit'
                  f'(ies); ua={client.user_agent}', file=sys.stderr)
        else:
            print(f'noraconf: uuid={client.uuid} session={client.session_id}', file=sys.stderr)
            print(f'noraconf: ua={client.user_agent}', file=sys.stderr)

    want_selective = args.all or args.selective
    want_normal = args.all or args.normal or not want_selective

    entries, errors = [], []
    if args.ech:
        pool = load_uuid_pool(args.uuid_pool)
        clients = [client] if (explicit_id or not pool) else []
        for ident in pool:
            if ident['uuid'] == client.uuid:
                continue
            clients.append(NoraClient(base_url=args.base_url, uuid=ident['uuid'],
                                      apk=args.apk, cert_sha256=args.cert_sha256,
                                      user_agent=ident.get('user_agent') or client.user_agent,
                                      timeout=args.timeout, retries=args.retries,
                                      verify_tls=not args.insecure, verbose=args.verbose))
        entries = collect_ech(clients, want_normal, want_selective, args)
        if not entries:
            print('noraconf: no ECH profile found (pool may be throttling); '
                  'retry later or raise --ech-attempts', file=sys.stderr)
            if not args.allow_empty:
                return 1
            print('noraconf: --allow-empty set, continuing with 0 configs', file=sys.stderr)
    elif want_normal:
        try:
            entries.append(client.normal_server())
        except Exception as exc:  # noqa: BLE001
            errors.append(f'normal: {exc}')
    if args.home and not args.ech:
        try:
            entries.append(client.home_config())
        except Exception as exc:  # noqa: BLE001
            errors.append(f'home: {exc}')

    if want_selective and not args.ech:
        try:
            listing = client.selective_servers()
        except Exception as exc:  # noqa: BLE001
            print(f'noraconf: {exc}', file=sys.stderr)
            return 1
        if args.limit:
            listing = listing[:args.limit]
        total = len(listing)

        def fetch(item, index):
            try:
                return client.selective_server(item['Id'])
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{item.get('Location') or item.get('Id')}: {exc}")
                return None

        if args.jobs > 1:
            from concurrent.futures import ThreadPoolExecutor
            with ThreadPoolExecutor(max_workers=args.jobs) as pool:
                futures = [pool.submit(fetch, item, i) for i, item in enumerate(listing)]
                for i, fut in enumerate(futures, 1):
                    entry = fut.result()
                    if entry:
                        entries.append(entry)
                    print(f'noraconf: {i}/{total} fetched', file=sys.stderr)
        else:
            for i, item in enumerate(listing, 1):
                entry = fetch(item, i)
                if entry:
                    entries.append(entry)
                print(f'noraconf: {i}/{total} fetched', file=sys.stderr)
                if i < total:
                    time.sleep(args.delay)

    if not entries:
        print('noraconf: no configs retrieved', file=sys.stderr)
        if not args.allow_empty:
            return 1
        print('noraconf: --allow-empty set, continuing with 0 configs', file=sys.stderr)
    for message in errors:
        print(f'noraconf: skipped {message}', file=sys.stderr)

    for entry in entries:
        if args.inject_credential:
            entry['xray'] = inject_credential(entry['xray'], entry)
        if args.prepared:
            entry['xray'] = prepare(entry['xray'], entry)
        if args.xrayjson:
            label = remarks_label(entry, args.remarks)
            if label:
                entry['xray']['remarks'] = label

    if args.xrayjson:
        payload = [entry['xray'] for entry in entries]
    else:
        payload = [{k: v for k, v in entry.items() if k != 'xray'} for entry in entries]

    text = json.dumps(payload, indent=2 if args.pretty else None,
                      ensure_ascii=False, separators=None if args.pretty else (',', ':'))
    if args.out:
        with open(args.out, 'w', encoding='utf-8') as fh:
            fh.write(text + '\n')
        print(f'noraconf: wrote {len(payload)} config(s) to {args.out}', file=sys.stderr)
    else:
        print(text)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print('noraconf: interrupted', file=sys.stderr)
        raise SystemExit(130) from None
    except NoraError as exc:
        print(f'noraconf: {exc}', file=sys.stderr)
        raise SystemExit(1) from None