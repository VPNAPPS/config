from typing import List
from v2ray2json import generateConfig
import json
import copy
import os
import subprocess
import urllib.parse
import re
# Imports added for concurrency, connectivity testing, and dynamic port allocation
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import urllib.request
import socket

TEMPLATE_PATH = os.path.join(os.path.dirname(__file__), "template.json")
with open(TEMPLATE_PATH, "r") as f:
    TEMPLATE = json.load(f)

def find_free_port() -> int:
    """Finds and returns an available TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))  # Bind to a free port provided by the OS
        return s.getsockname()[1]

def is_valid_uuid(uuid: str) -> bool:
    return re.fullmatch(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        uuid
    ) is not None

def fix_uuid(raw_uuid: str) -> str:
    decoded = urllib.parse.unquote(raw_uuid)
    if is_valid_uuid(decoded):
        return decoded
    hex_chars = re.sub(r'[^a-fA-F0-9]', '', decoded)
    if len(hex_chars) >= 32:
        return f"{hex_chars[:8]}-{hex_chars[8:12]}-{hex_chars[12:16]}-{hex_chars[16:20]}-{hex_chars[20:32]}"
    return decoded

def remove_duplicate_type_param(url: str) -> str:
    # Remove all type= except the first one
    type_pattern = re.compile(r"(type=[^&]*)", re.IGNORECASE)
    matches = type_pattern.findall(url)
    if len(matches) <= 1:
        return url
    first = matches[0]
    start = url.find(first)
    rest = url[start + len(first):]
    rest_cleaned = type_pattern.sub('', rest)
    rest_cleaned = re.sub(r'&&+', '&', rest_cleaned)
    rest_cleaned = re.sub(r'[?&]+$', '', rest_cleaned)
    rest_cleaned = re.sub(r'[?&]+&', '?', rest_cleaned)
    return url[:start + len(first)] + rest_cleaned

def fix_encryption_param(url: str) -> str:
    # Fix malformed encryption=none%3D...
    def replacer(match):
        return "encryption=none"
    return re.sub(r"encryption=none[^&#]*", replacer, url)

def fix_vless_url(url: str) -> str:
    if not url.startswith("vless://"):
        return url

    body = url[len("vless://"):]
    if '@' not in body:
        return url

    userinfo, rest = body.split('@', 1)
    fixed_uuid = fix_uuid(userinfo)
    rebuilt = f"vless://{fixed_uuid}@{rest}"
    rebuilt = remove_duplicate_type_param(rebuilt)
    rebuilt = fix_encryption_param(rebuilt)
    return rebuilt

def is_xray_config_valid(config_dict: dict, port: int, xray_path: str = os.path.join(os.path.dirname(__file__), "xray")) -> bool:
    """
    Validates an Xray config by running it on a unique port and testing its connectivity.
    """
    if not config_dict:
        return False

    template = copy.deepcopy(TEMPLATE)
    
    # **Dynamically update the listening port in the template**
    http_inbound_found = False
    for inbound in template.get("inbounds", []):
        if inbound.get("protocol") == "http":
            inbound["port"] = port
            http_inbound_found = True
            break
    
    if not http_inbound_found:
        print("Error: Could not find HTTP inbound in template to assign dynamic port.")
        return False

    # Ensure the provided outbound is the primary one for the test.
    template["outbounds"] = [config_dict["outbounds"][0]] + template["outbounds"]
    config_str = json.dumps(template)
    command = [xray_path, "run", "-c", "stdin:"]
    
    process = None
    try:
        # Start the Xray process in the background.
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL, # Suppress stdout
            stderr=subprocess.PIPE,
            text=True
        )

        try:
            process.stdin.write(config_str)
            process.stdin.close()
        except (IOError, BrokenPipeError):
            stderr_output, _ = process.communicate()
            print(f"Xray process terminated unexpectedly. Error: {stderr_output.strip()}")
            return False

        time.sleep(1.5)

        if process.poll() is not None:
            stderr_output = process.stderr.read()
            print(f"Xray validation failed on startup: {stderr_output.strip()}")
            return False

        # **Test connectivity through the dynamically assigned proxy port**
        proxy_url = f'http://127.0.0.1:{port}'
        proxy_handler = urllib.request.ProxyHandler({
            'http': proxy_url,
            'https': proxy_url
        })
        opener = urllib.request.build_opener(proxy_handler)
        
        try:
            test_url = "http://www.gstatic.com/generate_204"
            response = opener.open(test_url, timeout=4)
            return 200 <= response.status < 300
        except Exception:
            return False

    except FileNotFoundError:
        print(f"Warning: '{xray_path}' executable not found. Skipping validation.")
        return True
        
    except Exception as e:
        print(f"An unexpected error occurred during validation: {e}")
        return False
        
    finally:
        # Ensure the background Xray process is terminated.
        if process and process.poll() is None:
            process.terminate()
            process.wait()

def build_proxies_from_content(content: str) -> List[dict]:
    """
    Parses content, validates each generated config CONCURRENTLY, and returns valid proxies.
    """
    tasks_to_process = []
    for i, line in enumerate(content.strip().splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            if "vless" in line:
                line = fix_vless_url(line)
            config = json.loads(generateConfig(line))
            tasks_to_process.append({'config': config, 'line': line, 'index': i + 1})
        except Exception as e:
            print(f"Error processing line: {line}\nException: {e}")
            continue
    
    proxies = []
    max_workers = min(32, (os.cpu_count() or 1) * 5)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Map each future to its task, now submitting with a unique port.
        future_to_task = {
            # **Find a free port and pass it to the validation function**
            executor.submit(is_xray_config_valid, task['config'], find_free_port()): task
            for task in tasks_to_process
        }
        
        for future in as_completed(future_to_task):
            task = future_to_task[future]
            try:
                is_valid = future.result()
                if is_valid:
                    proxy = task['config']["outbounds"][0]
                    proxy["tag"] = f"proxy{task['index']}"
                    proxies.append(proxy)
                else:
                    print(f"Skipping invalid config from line: {task['line']}")
            except Exception as e:
                print(f"An exception occurred for config from line {task['line']}: {e}")

    proxies.sort(key=lambda p: int(p['tag'].replace('proxy', '')))
    
    return proxies

def build_config_json_from_proxies(name: str, proxies: list) -> dict:
    template = copy.deepcopy(TEMPLATE)
    template["remarks"] = name
    template["outbounds"][:0] = proxies
    return template

def build_config(name: str, content: str) -> dict:
    proxies = build_proxies_from_content(content)
    return build_config_json_from_proxies(name, proxies)