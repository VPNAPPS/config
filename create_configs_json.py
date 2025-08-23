from typing import List
from v2ray2json import generateConfig
from xray_checker import get_working_proxies
import json
import copy
import os
import subprocess
import urllib.parse
import re
import base64

# Import added for concurrency
from concurrent.futures import ThreadPoolExecutor, as_completed

TEMPLATE_PATH = os.path.join(os.path.dirname(__file__), "template.json")
with open(TEMPLATE_PATH, "r") as f:
    TEMPLATE = json.load(f)


def is_valid_uuid(uuid: str) -> bool:
    return (
        re.fullmatch(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
            uuid,
        )
        is not None
    )


def fix_uuid(raw_uuid: str) -> str:
    decoded = urllib.parse.unquote(raw_uuid)
    if is_valid_uuid(decoded):
        return decoded
    hex_chars = re.sub(r"[^a-fA-F0-9]", "", decoded)
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
    rest = url[start + len(first) :]
    rest_cleaned = type_pattern.sub("", rest)
    rest_cleaned = re.sub(r"&&+", "&", rest_cleaned)
    rest_cleaned = re.sub(r"[?&]+$", "", rest_cleaned)
    rest_cleaned = re.sub(r"[?&]+&", "?", rest_cleaned)
    return url[: start + len(first)] + rest_cleaned


def fix_encryption_param(url: str) -> str:
    # Fix malformed encryption=none%3D...
    def replacer(match):
        return "encryption=none"

    return re.sub(r"encryption=none[^&#]*", replacer, url)


def fix_vless_url(url: str) -> str:
    if not url.startswith("vless://"):
        return url

    body = url[len("vless://") :]
    if "@" not in body:
        return url

    userinfo, rest = body.split("@", 1)
    fixed_uuid = fix_uuid(userinfo)
    rebuilt = f"vless://{fixed_uuid}@{rest}"
    rebuilt = remove_duplicate_type_param(rebuilt)
    rebuilt = fix_encryption_param(rebuilt)
    return rebuilt


def is_xray_config_valid(
    config_dict: dict, xray_path: str = os.path.join(os.path.dirname(__file__), "xray")
) -> bool:
    """
    Validates an Xray configuration by attempting to run it with a timeout.
    This is a workaround for older Xray versions that lack the 'test' command.
    """
    if not config_dict:
        return False

    config_str = json.dumps(config_dict)
    command = [xray_path, "run", "-c", "stdin:"]

    try:
        # Attempt to run the config with a 2-second timeout.
        result = subprocess.run(
            command,
            input=config_str,
            text=True,
            capture_output=True,
            timeout=2,  # Add a timeout
        )

        # If the process exited before the timeout, check its return code.
        # A non-zero code means the config was invalid.
        if result.returncode != 0:
            print(f"Xray validation failed: {result.stderr.strip()}")
            return False

        # This case is unlikely for 'run' but we'll treat a clean exit as valid.
        return True

    except subprocess.TimeoutExpired:
        # If it times out, it means Xray started successfully and is running.
        # This is our success condition for a valid config.
        return True

    except FileNotFoundError:
        print(f"Warning: '{xray_path}' executable not found. Skipping validation.")
        return True

    except Exception as e:
        print(f"An unexpected error occurred during validation: {e}")
        return False


def build_proxies_from_content(content: str, check: bool = True) -> List[dict]:
    """
    Parses content, validates each generated config CONCURRENTLY, and returns valid proxies.
    """
    tasks_to_process = []
    # print("",base64.b64encode(content.encode('utf-8')).decode('utf-8'),"")
    if check:
        content = get_working_proxies(
            base64.b64encode(content.encode("utf-8")).decode("utf-8")
        )
    if not content:
        return None
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
            tasks_to_process.append({"config": config, "line": line, "index": i + 1})
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
            executor.submit(is_xray_config_valid, task["config"]): task
            for task in tasks_to_process
        }

        # Process results as they are completed.
        for future in as_completed(future_to_task):
            task = future_to_task[future]
            try:
                is_valid = future.result()
                if is_valid:
                    proxy = task["config"]["outbounds"][0]
                    proxy["tag"] = f"proxy{task['index']}"
                    proxies.append(proxy)
                else:
                    print(
                        f"Skipping invalid config from line: {task['line']} \n {json.dumps(task['config'])}"
                    )
            except Exception as e:
                print(f"An exception occurred for config from line {task['line']}: {e}")

    # 3. Sort proxies by their original index to maintain order.
    proxies.sort(key=lambda p: int(p["tag"].replace("proxy", "")))

    return proxies


def build_config_json_from_proxies(name: str, proxies: list) -> dict:
    template = copy.deepcopy(TEMPLATE)
    template["remarks"] = name
    template["outbounds"][:0] = proxies
    return template


def build_config(name: str, content: str, check: bool = True) -> dict:
    proxies = build_proxies_from_content(content, check=check)
    if proxies:
        return build_config_json_from_proxies(name, proxies)
    else:
        return None
