from typing import List
from v2ray2json import generateConfig
import json
import copy
import os
import subprocess
import urllib.parse
import re
# Imports added for concurrency and connectivity testing
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import urllib.request

TEMPLATE_PATH = os.path.join(os.path.dirname(__file__), "template.json")
with open(TEMPLATE_PATH, "r") as f:
    TEMPLATE = json.load(f)

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

def is_xray_config_valid(config_dict: dict, xray_path: str = os.path.join(os.path.dirname(__file__), "xray")) -> bool:
    """
    Validates an Xray config by running it and testing its connectivity.
    It starts the config, which exposes an HTTP proxy on port 10809,
    and then attempts to make a request through that proxy.
    """
    if not config_dict:
        return False

    template = copy.deepcopy(TEMPLATE)
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

        # Send the configuration to the process's stdin.
        try:
            process.stdin.write(config_str)
            process.stdin.close()
        except (IOError, BrokenPipeError):
            # This can happen if the process terminates immediately on a bad config.
            stderr_output, _ = process.communicate()
            print(f"Xray process terminated unexpectedly. Error: {stderr_output.strip()}")
            return False

        # Give Xray a moment to start up.
        time.sleep(1.5)

        # Check if the process has already exited (i.e., failed to start).
        if process.poll() is not None:
            stderr_output = process.stderr.read()
            print(f"Xray validation failed on startup: {stderr_output.strip()}")
            return False

        # If the process is running, test connectivity through the proxy.
        proxy_handler = urllib.request.ProxyHandler({
            'http': 'http://127.0.0.1:10809',
            'https': 'http://127.0.0.1:10809'
        })
        opener = urllib.request.build_opener(proxy_handler)
        
        try:
            # Use a lightweight URL for the connectivity test.
            test_url = "http://www.gstatic.com/generate_204"
            # Set a reasonable timeout for the connection attempt.
            response = opener.open(test_url, timeout=4)
            # A successful response (e.g., 204 No Content) means the proxy works.
            if 200 <= response.status < 300:
                # print("Connectivity test successful.")
                return True
            else:
                # print(f"Connectivity test failed with status: {response.status}")
                return False
        except Exception as e:
            # Any exception during the request (e.g., timeout, connection refused) means failure.
            # print(f"Connectivity test failed: {e}")
            return False

    except FileNotFoundError:
        print(f"Warning: '{xray_path}' executable not found. Skipping validation.")
        return True # Maintain original behavior of skipping if not found
        
    except Exception as e:
        print(f"An unexpected error occurred during validation: {e}")
        return False
        
    finally:
        # Ensure the background Xray process is terminated.
        if process and process.poll() is None:
            process.terminate()
            process.wait() # Wait for the process to be fully terminated

def build_proxies_from_content(content: str) -> List[dict]:
    """
    Parses content, validates each generated config CONCURRENTLY, and returns valid proxies.
    """
    tasks_to_process = []
    # 1. First, parse all lines and generate configs without validating yet.
    for i, line in enumerate(content.strip().splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            if "vless" in line:
                line = fix_vless_url(line)
            config = json.loads(generateConfig(line))
            # Store the config and its original metadata (line, index) for later.
            tasks_to_process.append({'config': config, 'line': line, 'index': i + 1})
        except Exception as e:
            print(f"Error processing line: {line}\nException: {e}")
            continue
    
    proxies = []
    # Use a reasonable number of worker threads. Capped at 32.
    max_workers = min(32, (os.cpu_count() or 1) * 5)

    # 2. Concurrently validate all the generated configs.
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Map each future object back to its original task data.
        future_to_task = {
            executor.submit(is_xray_config_valid, task['config']): task
            for task in tasks_to_process
        }
        
        # Process results as they are completed.
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

    # 3. Sort proxies by their original index to maintain order.
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