from typing import List
from v2ray2json import generateConfig
import json
import copy
import os

TEMPLATE_PATH = os.path.join(os.path.dirname(__file__), "template.json")
with open(TEMPLATE_PATH, "r") as f:
    TEMPLATE = json.load(f)

def build_proxies_from_content(content: str) -> List[dict]:
    """
    Parses content line-by-line, sends each line to `generateConfig`, and
    returns a list of proxy configurations.

    Parameters:
        name (str): A name tag (not currently used in logic, but available for extension).
        content (str): Multiline string where each line is a VLESS/Vmess/etc. link.

    Returns:
        List[dict]: List of proxy config dictionaries returned by `generateConfig`.
    """
    proxies = []
    i = 0
    for line in content.strip().splitlines():
        i += 1
        line = line.strip()
        if not line:
            continue  # skip empty lines
        try:
            config = json.loads(generateConfig(line))
            if config:
                proxy = config["outbounds"][0]
                proxy["tag"] = f"proxy{i}"
                proxies.append(proxy)
        except Exception as e:
            print(f"Error processing line: {line}\nException: {e}")
            continue
    return proxies

def build_config_json_from_proxies(name: str, proxies: list) -> dict:
    template =  copy.deepcopy(TEMPLATE)
    template["remarks"] = name
    template["outbounds"][:0] = proxies
    return template

def build_config(name: str, content: str) -> dict:
    proxies = build_proxies_from_content(content)
    return(build_config_json_from_proxies(name, proxies))
    