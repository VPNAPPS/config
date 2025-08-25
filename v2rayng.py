import json
import re
import time
import base64
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Any, Dict
from urllib.parse import urlparse, parse_qs, unquote, unquote_plus

# --- EConfigType ---
class EConfigType(Enum):
    VMESS = (1, "vmess")
    CUSTOM = (2, "custom")
    SHADOWSOCKS = (3, "shadowsocks")
    SOCKS = (4, "socks")
    VLESS = (5, "vless")
    TROJAN = (6, "trojan")
    WIREGUARD = (7, "wireguard")
    HYSTERIA2 = (9, "hysteria2")
    HTTP = (10, "http")

    def __init__(self, value, protocol_scheme):
        self._value_ = value
        self.protocol_scheme = protocol_scheme

# --- ProfileItem (Central Data Structure) ---
@dataclass
class ProfileItem:
    configType: EConfigType
    configVersion: int = 4
    subscriptionId: str = ""
    addedTime: int = field(default_factory=lambda: int(time.time() * 1000))
    remarks: str = ""
    server: Optional[str] = None
    serverPort: Optional[str] = None
    password: Optional[str] = None
    method: Optional[str] = None
    flow: Optional[str] = None
    username: Optional[str] = None
    network: Optional[str] = None
    headerType: Optional[str] = None
    host: Optional[str] = None
    path: Optional[str] = None
    seed: Optional[str] = None
    quicSecurity: Optional[str] = None
    quicKey: Optional[str] = None
    mode: Optional[str] = None
    serviceName: Optional[str] = None
    authority: Optional[str] = None
    xhttpMode: Optional[str] = None
    xhttpExtra: Optional[str] = None
    security: Optional[str] = None
    sni: Optional[str] = None
    alpn: Optional[str] = None
    fingerPrint: Optional[str] = None
    insecure: Optional[bool] = None
    publicKey: Optional[str] = None
    shortId: Optional[str] = None
    spiderX: Optional[str] = None
    mldsa65Verify: Optional[str] = None
    secretKey: Optional[str] = None
    preSharedKey: Optional[str] = None
    localAddress: Optional[str] = None
    reserved: Optional[str] = None
    mtu: Optional[int] = None
    obfsPassword: Optional[str] = None
    portHopping: Optional[str] = None
    portHoppingInterval: Optional[str] = None
    pinSHA256: Optional[str] = None
    bandwidthDown: Optional[str] = None
    bandwidthUp: Optional[str] = None

# --- V2rayConfig Data Classes ---
@dataclass
class UsersBean:
    id: str = ""
    alterId: Optional[int] = None
    security: Optional[str] = None
    level: int = 0
    encryption: Optional[str] = None
    flow: Optional[str] = None

@dataclass
class VnextBean:
    address: str = ""
    port: int = 443
    users: List[UsersBean] = field(default_factory=lambda: [UsersBean()])

@dataclass
class SocksUsersBean:
    user: str = ""
    pas: str = "" # Note: 'pass' is a reserved keyword in Python
    level: int = 0

@dataclass
class ServersBean:
    address: str = ""
    method: Optional[str] = None
    ota: bool = False
    password: Optional[str] = None
    port: int = 443
    level: int = 0
    email: Optional[str] = None
    flow: Optional[str] = None
    ivCheck: Optional[bool] = None
    users: Optional[List[SocksUsersBean]] = None

@dataclass
class WireGuardPeerBean:
    publicKey: str = ""
    preSharedKey: Optional[str] = None
    endpoint: str = ""

@dataclass
class OutSettingsBean:
    vnext: Optional[List[VnextBean]] = None
    servers: Optional[List[ServersBean]] = None
    secretKey: Optional[str] = None
    address: Optional[List[str]] = None
    peers: Optional[List[WireGuardPeerBean]] = None
    mtu: Optional[int] = None
    reserved: Optional[List[int]] = None

@dataclass
class WsHeadersBean:
    Host: str = ""

@dataclass
class WsSettingsBean:
    path: Optional[str] = None
    headers: WsHeadersBean = field(default_factory=WsHeadersBean)

@dataclass
class TlsSettingsBean:
    allowInsecure: bool = False
    serverName: Optional[str] = None
    alpn: Optional[List[str]] = None
    fingerprint: Optional[str] = None
    publicKey: Optional[str] = None
    shortId: Optional[str] = None
    spiderX: Optional[str] = None
    mldsa65Verify: Optional[str] = None

@dataclass
class StreamSettingsBean:
    network: str = "tcp"
    security: Optional[str] = None
    wsSettings: Optional[WsSettingsBean] = None
    tlsSettings: Optional[TlsSettingsBean] = None
    realitySettings: Optional[TlsSettingsBean] = None
    # Add other settings (tcp, kcp, etc.) as needed

@dataclass
class MuxBean:
    enabled: bool = False
    concurrency: Optional[int] = None

@dataclass
class OutboundBean:
    tag: str = "proxy"
    protocol: str = ""
    settings: Optional[OutSettingsBean] = None
    streamSettings: Optional[StreamSettingsBean] = None
    mux: Optional[MuxBean] = field(default_factory=MuxBean)

@dataclass
class VmessQRCode:
    v: str = "2"
    ps: str = ""
    add: str = ""
    port: str = "443"
    id: str = ""
    aid: str = "0"
    scy: str = "auto"
    net: str = "tcp"
    type: str = "none"
    host: str = ""
    path: str = ""
    tls: str = ""
    sni: str = ""
    alpn: str = ""
    fp: str = ""

# --- Utility Functions ---
def get_query_param(uri: urlparse) -> Dict[str, str]:
    if not uri.query:
        return {}
    # Use unquote_plus to handle spaces encoded as '+'
    return {k: unquote_plus(v[0]) for k, v in parse_qs(uri.query).items()}

def get_server_address(profile_item: ProfileItem) -> str:
    addr = profile_item.server or ""
    # Basic check for IPv6 literal
    if ':' in addr and not addr.startswith('[') and not addr.endswith(']'):
         return f"[{addr}]"
    return addr

def decode_base64(text: str) -> Optional[str]:
    """Tries to decode a base64 string, testing standard and URL-safe variants."""
    if not text:
        return None
    try:
        # Add padding if it's missing
        padded_text = text + '=' * (-len(text) % 4)
        return base64.b64decode(padded_text).decode('utf-8')
    except (ValueError, TypeError):
        try:
            return base64.urlsafe_b64decode(padded_text).decode('utf-8')
        except (ValueError, TypeError):
            return None

# --- Configuration Manager ---
class V2rayConfigManager:
    @staticmethod
    def create_init_outbound(config_type: EConfigType) -> Optional[OutboundBean]:
        protocol_name = config_type.name.lower()
        if config_type in [EConfigType.VMESS, EConfigType.VLESS]:
            return OutboundBean(protocol=protocol_name, settings=OutSettingsBean(vnext=[VnextBean()]), streamSettings=StreamSettingsBean())
        if config_type in [EConfigType.SHADOWSOCKS, EConfigType.SOCKS, EConfigType.HTTP, EConfigType.TROJAN]:
            return OutboundBean(protocol=protocol_name, settings=OutSettingsBean(servers=[ServersBean()]), streamSettings=StreamSettingsBean())
        if config_type == EConfigType.WIREGUARD:
             return OutboundBean(protocol=protocol_name, settings=OutSettingsBean(peers=[WireGuardPeerBean()]))
        return None

    @staticmethod
    def populate_transport_settings(stream_settings: StreamSettingsBean, profile: ProfileItem) -> Optional[str]:
        transport = profile.network or "tcp"
        stream_settings.network = transport
        sni = None
        if transport == "ws":
            ws_setting = WsSettingsBean()
            ws_setting.headers = WsHeadersBean(Host=profile.host or "")
            sni = profile.host
            ws_setting.path = profile.path or "/"
            stream_settings.wsSettings = ws_setting
        return sni

    @staticmethod
    def populate_tls_settings(stream_settings: StreamSettingsBean, profile: ProfileItem, sni_ext: Optional[str]):
        if not profile.security:
            return
        stream_settings.security = profile.security
        sni = profile.sni or sni_ext or profile.server
        tls_setting = TlsSettingsBean(
            allowInsecure=profile.insecure or False,
            serverName=sni,
            fingerprint=profile.fingerPrint,
            alpn=[x.strip() for x in profile.alpn.split(',')] if profile.alpn else None
        )
        if stream_settings.security == "tls":
            stream_settings.tlsSettings = tls_setting
        elif stream_settings.security == "reality":
            stream_settings.realitySettings = tls_setting

# --- Format Parsers ---
class FmtBase:
    @staticmethod
    def get_item_from_query(config: ProfileItem, query_param: Dict[str, str]):
        config.network = query_param.get("type", "tcp")
        config.security = query_param.get("security")
        config.path = query_param.get("path")
        config.host = query_param.get("host")
        config.sni = query_param.get("sni")
        config.flow = query_param.get("flow")
        config.fingerPrint = query_param.get("fp")
        config.alpn = query_param.get("alpn")
        # Add other params as needed

class VlessFmt(FmtBase):
    @staticmethod
    def parse(uri_str: str) -> Optional[ProfileItem]:
        uri = urlparse(uri_str)
        config = ProfileItem(configType=EConfigType.VLESS,
                             remarks=unquote(uri.fragment or "none"),
                             server=uri.hostname,
                             serverPort=str(uri.port),
                             password=uri.username)
        query_param = get_query_param(uri)
        config.method = query_param.get("encryption", "none")
        FmtBase.get_item_from_query(config, query_param)
        return config

    @staticmethod
    def to_outbound(profile: ProfileItem) -> Optional[OutboundBean]:
        outbound = V2rayConfigManager.create_init_outbound(EConfigType.VLESS)
        if not outbound or not outbound.settings or not outbound.settings.vnext: return None
        vnext = outbound.settings.vnext[0]
        vnext.address = get_server_address(profile)
        vnext.port = int(profile.serverPort) if profile.serverPort else 443
        user = vnext.users[0]
        user.id = profile.password or ""
        user.encryption = profile.method
        user.flow = profile.flow
        if outbound.streamSettings:
            sni = V2rayConfigManager.populate_transport_settings(outbound.streamSettings, profile)
            V2rayConfigManager.populate_tls_settings(outbound.streamSettings, profile, sni)
        return outbound

class TrojanFmt(FmtBase):
    @staticmethod
    def parse(uri_str: str) -> Optional[ProfileItem]:
        uri = urlparse(uri_str)
        config = ProfileItem(configType=EConfigType.TROJAN,
                             remarks=unquote(uri.fragment or "none"),
                             server=uri.hostname,
                             serverPort=str(uri.port),
                             password=uri.username)
        query_param = get_query_param(uri)
        if not query_param:
            config.network = "tcp"
            config.security = "tls"
        else:
            FmtBase.get_item_from_query(config, query_param)
            config.security = query_param.get("security", "tls")
        return config

    @staticmethod
    def to_outbound(profile: ProfileItem) -> Optional[OutboundBean]:
        outbound = V2rayConfigManager.create_init_outbound(EConfigType.TROJAN)
        if not outbound or not outbound.settings or not outbound.settings.servers: return None
        server = outbound.settings.servers[0]
        server.address = get_server_address(profile)
        server.port = int(profile.serverPort) if profile.serverPort else 443
        server.password = profile.password
        server.flow = profile.flow
        if outbound.streamSettings:
            sni = V2rayConfigManager.populate_transport_settings(outbound.streamSettings, profile)
            V2rayConfigManager.populate_tls_settings(outbound.streamSettings, profile, sni)
        return outbound

class VmessFmt(FmtBase):
    @staticmethod
    def parse(uri_str: str) -> Optional[ProfileItem]:
        content = uri_str.replace("vmess://", "")
        decoded_str = decode_base64(content)
        if not decoded_str: return None
        try:
            data = json.loads(decoded_str)
            vmess_qr = VmessQRCode(**data)
            config = ProfileItem(configType=EConfigType.VMESS,
                                 remarks=vmess_qr.ps,
                                 server=vmess_qr.add,
                                 serverPort=vmess_qr.port,
                                 password=vmess_qr.id,
                                 method=vmess_qr.scy if vmess_qr.scy else "auto",
                                 network=vmess_qr.net,
                                 headerType=vmess_qr.type,
                                 host=vmess_qr.host,
                                 path=vmess_qr.path,
                                 security=vmess_qr.tls,
                                 sni=vmess_qr.sni,
                                 alpn=vmess_qr.alpn,
                                 fingerPrint=vmess_qr.fp)
            return config
        except (json.JSONDecodeError, TypeError) as e:
            print(f"Error parsing VMess JSON: {e}")
            return None

    @staticmethod
    def to_outbound(profile: ProfileItem) -> Optional[OutboundBean]:
        outbound = V2rayConfigManager.create_init_outbound(EConfigType.VMESS)
        if not outbound or not outbound.settings or not outbound.settings.vnext: return None
        vnext = outbound.settings.vnext[0]
        vnext.address = get_server_address(profile)
        vnext.port = int(profile.serverPort) if profile.serverPort else 443
        user = vnext.users[0]
        user.id = profile.password or ""
        user.security = profile.method
        if outbound.streamSettings:
            sni = V2rayConfigManager.populate_transport_settings(outbound.streamSettings, profile)
            V2rayConfigManager.populate_tls_settings(outbound.streamSettings, profile, sni)
        return outbound

class ShadowsocksFmt(FmtBase):
    @staticmethod
    def parse(uri_str: str) -> Optional[ProfileItem]:
        uri = urlparse(uri_str)
        config = ProfileItem(configType=EConfigType.SHADOWSOCKS,
                             remarks=unquote(uri.fragment or "none"),
                             server=uri.hostname,
                             serverPort=str(uri.port))
        
        user_info = unquote(uri.username or "")
        if ':' not in user_info:
            user_info = decode_base64(user_info) or ""
        
        parts = user_info.split(':', 1)
        if len(parts) == 2:
            config.method, config.password = parts
        else:
            return None # Invalid user info
            
        return config

    @staticmethod
    def to_outbound(profile: ProfileItem) -> Optional[OutboundBean]:
        outbound = V2rayConfigManager.create_init_outbound(EConfigType.SHADOWSOCKS)
        if not outbound or not outbound.settings or not outbound.settings.servers: return None
        server = outbound.settings.servers[0]
        server.address = get_server_address(profile)
        server.port = int(profile.serverPort) if profile.serverPort else 443
        server.password = profile.password
        server.method = profile.method
        return outbound

class SocksFmt(FmtBase):
    @staticmethod
    def parse(uri_str: str) -> Optional[ProfileItem]:
        uri = urlparse(uri_str)
        config = ProfileItem(configType=EConfigType.SOCKS,
                             remarks=unquote(uri.fragment or "none"),
                             server=uri.hostname,
                             serverPort=str(uri.port))
        if uri.username:
            user_info = decode_base64(uri.username) or ""
            parts = user_info.split(':', 1)
            if len(parts) == 2:
                config.username, config.password = parts
        return config

    @staticmethod
    def to_outbound(profile: ProfileItem) -> Optional[OutboundBean]:
        outbound = V2rayConfigManager.create_init_outbound(EConfigType.SOCKS)
        if not outbound or not outbound.settings or not outbound.settings.servers: return None
        server = outbound.settings.servers[0]
        server.address = get_server_address(profile)
        server.port = int(profile.serverPort) if profile.serverPort else 1080
        if profile.username:
            server.users = [SocksUsersBean(user=profile.username, pas=profile.password or "")]
        return outbound

# --- Main Conversion Logic ---
FORMATTERS = {
    "vless": VlessFmt,
    "trojan": TrojanFmt,
    "vmess": VmessFmt,
    "ss": ShadowsocksFmt,
    "socks": SocksFmt,
}

def uri_to_json(uri_string: str) -> Optional[str]:
    """
    Converts a V2Ray URI to a pretty-printed JSON outbound configuration.
    """
    try:
        scheme = urlparse(uri_string).scheme
        formatter = FORMATTERS.get(scheme)
        if not formatter:
            print(f"Unsupported scheme: {scheme}")
            return None

        profile = formatter.parse(uri_string)
        if not profile:
            print("Failed to parse URI.")
            return None
        
        outbound_config = formatter.to_outbound(profile)
        if not outbound_config:
            print("Failed to convert profile to outbound config.")
            return None
            
        # Recursive function to convert dataclasses to dicts, filtering out None values
        def dataclass_to_dict(obj):
            if hasattr(obj, '__dict__'):
                result = {}
                for k, v in obj.__dict__.items():
                    if v is not None:
                        # Handle dataclass fields with default factories
                        if isinstance(v, list) and not v:
                            continue
                        if hasattr(v, '__dict__') and not any(v.__dict__.values()):
                            continue
                        result[k] = dataclass_to_dict(v)
                return result
            elif isinstance(obj, list):
                return [dataclass_to_dict(i) for i in obj]
            else:
                return obj

        config_dict = dataclass_to_dict(outbound_config)
        return json.dumps(config_dict, indent=2)

    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None

if __name__ == '__main__':
    test_uris = {
        "VLESS": "vless://a1b2c3d4-e5f6-g7h8-i9j0-k1l2m3n4o5p6@example.com:443?encryption=none&security=tls&sni=example.com&type=ws&host=example.com&path=%2Fpath#My-VLESS-Config",
        "Trojan": "trojan://password@trojan.example.com:443?sni=trojan.example.com#My-Trojan-Config",
        "VMess": "vmess://ewogICJ2IjogIjIiLAogICJwcyI6ICJNeS1WTWVzcy1Db25maWciLAogICJhZGQiOiAiZXhhbXBsZS5jb20iLAogICJwb3J0IjogIjQ0MyIsCiAgImlkIjogImExYjJjM2Q0LWU1ZjYtZzdoOC1pOWowLWsxbDJtM240bzVwNiIsCiAgImFpZCI6ICIwIiwKICAic2N5IjogImF1dG8iLAogICJuZXQiOiAid3MiLAogICJ0eXBlIjogIm5vbmUiLAogICJob3N0IjogImV4YW1wbGUuY29tIiwKICAicGF0aCI6ICIvcGF0aCIsCiAgInRscyI6ICJ0bHMiLAogICJzbmkiOiAiZXhhbXBsZS5jb20iLAogICJhbHBuIjogIiIsCiAgImZwIjogIiIKfQ==",
        "Shadowsocks": "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@ss.example.com:8443#My-SS-Config",
        "SOCKS5": "socks://dXNlcjpwYXNz@socks.example.com:1080#My-SOCKS-Config"
    }

    for name, uri in test_uris.items():
        print(f"--- {name} URI ---")
        print(uri)
        json_output = uri_to_json(uri)
        if json_output:
            print(f"\n--- Generated {name} JSON Config ---")
            print(json_output)
        else:
            print(f"\n--- Failed to convert {name} URI ---")
        print("-" * 40 + "\n")

