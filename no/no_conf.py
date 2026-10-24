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
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
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

DEFAULT_UA = "Nora,131,Android(35),Xiaomi,M2012K11AG,en"


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
            except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
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
        return self._server(self.request('/v1/servers/normal'))

    def selective_servers(self):
        return self.request('/v1/servers/selective') or []

    def selective_server(self, server_id):
        return self._server(self.request(f'/v1/servers/selective/{int(server_id)}'))

    def _server(self, raw):
        if not raw:
            raise NoraError('empty server response')
        entry = {
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
    ap.add_argument('--inject-credential', action='store_true',
                    help='write the lease credential into each config (as the app does)')
    ap.add_argument('--prepared', action='store_true',
                    help='also apply the app\'s DNS/route hardening (implies --inject-credential)')
    ap.add_argument('--pretty', action='store_true', help='pretty-print JSON output')
    ap.add_argument('--out', metavar='FILE', help='write output to FILE instead of stdout')
    ap.add_argument('--uuid', help='client UUID to use (default: random, like a fresh install)')
    ap.add_argument('--base-url', default=DEFAULT_BASE_URL)
    ap.add_argument('--apk', help='APK path; derive keys from its signing certificate')
    ap.add_argument('--cert-sha256', help='override the APK certificate SHA-256 (hex)')
    ap.add_argument('--user-agent', default=DEFAULT_UA,
                    help=f'User-Agent (default: {DEFAULT_UA!r})')
    ap.add_argument('--jobs', type=int, default=1,
                    help='parallel fetches for --all/--selective (default 1; each call '
                         'provisions a lease and takes several seconds)')
    ap.add_argument('--limit', type=int, help='only fetch the first N selective servers')
    ap.add_argument('--delay', type=float, default=0.3,
                    help='seconds between sequential requests (default 0.3)')
    ap.add_argument('--timeout', type=float, default=25)
    ap.add_argument('--retries', type=int, default=3)
    ap.add_argument('--insecure', action='store_true', help='skip TLS verification')
    ap.add_argument('--verbose', '-v', action='store_true')
    args = ap.parse_args(argv)

    if args.prepared:
        args.inject_credential = True

    client = NoraClient(base_url=args.base_url, uuid=args.uuid, apk=args.apk,
                        cert_sha256=args.cert_sha256, user_agent=args.user_agent,
                        timeout=args.timeout, retries=args.retries,
                        verify_tls=not args.insecure, verbose=args.verbose)

    want_selective = args.all or args.selective
    want_normal = args.all or args.normal or not want_selective

    entries, errors = [], []
    if want_normal:
        try:
            entries.append(client.normal_server())
        except NoraError as exc:
            errors.append(f'normal: {exc}')
    if want_selective:
        try:
            listing = client.selective_servers()
        except NoraError as exc:
            print(f'noraconf: {exc}', file=sys.stderr)
            return 1
        if args.limit:
            listing = listing[:args.limit]
        total = len(listing)

        def fetch(item, index):
            try:
                return client.selective_server(item['Id'])
            except NoraError as exc:
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
        return 1
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
    raise SystemExit(main())