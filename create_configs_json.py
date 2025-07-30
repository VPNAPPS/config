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

import logging
import json
import copy
import subprocess
import time
import urllib.request
import urllib.error
import socket
from typing import Optional, Tuple

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def is_xray_config_valid(
    config_dict: dict, 
    port: int, 
    xray_path: str = os.path.join(os.path.dirname(__file__), "xray"),
    timeout: int = 8,
    startup_wait: float = 3.0,
    test_urls: list = None
) -> bool:
    """
    Validates an Xray config by running it on a unique port and testing its connectivity.
    
    Args:
        config_dict: The Xray configuration dictionary
        port: The port to use for the HTTP proxy
        xray_path: Path to the Xray executable
        timeout: Timeout for connectivity tests in seconds
        startup_wait: Time to wait for Xray to start up
        test_urls: List of URLs to test connectivity with
    
    Returns:
        bool: True if the configuration is valid and connectivity works
    """
    if test_urls is None:
        test_urls = [
            "http://www.gstatic.com/generate_204",
            "http://connectivitycheck.gstatic.com/generate_204",
            "http://clients3.google.com/generate_204"
        ]
    
    logger.info(f"Validating Xray config on port {port}")
    
    # Validate input
    if not config_dict:
        logger.error("Empty config dictionary provided")
        return False
    
    if not config_dict.get("outbounds"):
        logger.error("No outbounds found in config")
        return False
    
    # Check if port is available
    if not _is_port_available(port):
        logger.warning(f"Port {port} is not available, finding alternative")
        port = find_free_port()
        logger.info(f"Using alternative port {port}")
    
    # Prepare config
    template = copy.deepcopy(TEMPLATE)
    
    # Update the listening port in the template
    http_inbound_found = False
    for inbound in template.get("inbounds", []):
        if inbound.get("protocol") == "http":
            inbound["port"] = port
            http_inbound_found = True
            logger.debug(f"Updated HTTP inbound port to {port}")
            break
    
    if not http_inbound_found:
        logger.error("Could not find HTTP inbound in template to assign dynamic port")
        return False

    # Set up outbounds - put the test config first
    template["outbounds"] = [config_dict["outbounds"][0]] + template["outbounds"]
    
    # Validate JSON serialization
    try:
        config_str = json.dumps(template, indent=2)
        logger.debug("Successfully serialized config to JSON")
    except (TypeError, ValueError) as e:
        logger.error(f"Failed to serialize config to JSON: {e}")
        return False
    
    # Prepare Xray command
    command = [xray_path, "run", "-c", "stdin:"]
    logger.debug(f"Running command: {' '.join(command)}")
    
    process = None
    try:
        # Check if Xray executable exists
        if not os.path.isfile(xray_path):
            logger.warning(f"Xray executable not found at '{xray_path}'. Skipping validation.")
            return True
        
        # Start the Xray process
        logger.info("Starting Xray process...")
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        # Send config to process
        try:
            stdout, stderr = process.communicate(input=config_str, timeout=5)
            
            # If process terminated during communication, check why
            if process.returncode is not None and process.returncode != 0:
                logger.error(f"Xray process failed to start properly (exit code: {process.returncode})")
                if stderr:
                    logger.error(f"Xray stderr: {stderr.strip()}")
                if stdout:
                    logger.debug(f"Xray stdout: {stdout.strip()}")
                return False
                
        except subprocess.TimeoutExpired:
            logger.error("Timeout while communicating with Xray process")
            process.kill()
            return False
        except (IOError, BrokenPipeError) as e:
            logger.error(f"Failed to send config to Xray process: {e}")
            return False

        # Wait for Xray to start up
        logger.info(f"Waiting {startup_wait}s for Xray to start up...")
        time.sleep(startup_wait)

        # Check if process is still running
        if process.poll() is not None:
            logger.error(f"Xray process terminated unexpectedly (exit code: {process.returncode})")
            if stderr:
                logger.error(f"Final stderr: {stderr.strip()}")
            return False

        logger.info("Xray process started successfully, testing connectivity...")
        
        # Test connectivity
        return _test_connectivity(port, test_urls, timeout)

    except FileNotFoundError:
        logger.warning(f"Xray executable '{xray_path}' not found. Skipping validation.")
        return True
        
    except Exception as e:
        logger.error(f"Unexpected error during validation: {type(e).__name__}: {e}")
        return False
        
    finally:
        # Ensure the Xray process is terminated
        if process and process.poll() is None:
            logger.info("Terminating Xray process...")
            process.terminate()
            try:
                process.wait(timeout=5)
                logger.debug("Xray process terminated gracefully")
            except subprocess.TimeoutExpired:
                logger.warning("Xray process didn't terminate gracefully, killing...")
                process.kill()
                process.wait()

def _is_port_available(port: int) -> bool:
    """Check if a port is available for use."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('127.0.0.1', port))
            return True
    except OSError:
        return False

def _test_connectivity(port: int, test_urls: list, timeout: int) -> Tuple[bool, str]:
    """
    Test connectivity through the proxy.
    
    Returns:
        bool: True if any test URL succeeds
    """
    proxy_url = f'http://127.0.0.1:{port}'
    proxy_handler = urllib.request.ProxyHandler({
        'http': proxy_url,
        'https': proxy_url
    })
    opener = urllib.request.build_opener(proxy_handler)
    opener.addheaders = [('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')]
    
    successful_tests = 0
    total_tests = len(test_urls)
    
    for i, test_url in enumerate(test_urls, 1):
        logger.debug(f"Testing connectivity ({i}/{total_tests}): {test_url}")
        
        try:
            start_time = time.time()
            response = opener.open(test_url, timeout=timeout)
            response_time = time.time() - start_time
            
            status_code = response.getcode()
            logger.info(f"✓ Connectivity test passed: {test_url} -> HTTP {status_code} ({response_time:.2f}s)")
            
            if 200 <= status_code < 300:
                successful_tests += 1
            else:
                logger.warning(f"Unexpected status code {status_code} for {test_url}")
                
        except urllib.error.HTTPError as e:
            logger.warning(f"HTTP error for {test_url}: {e.code} {e.reason}")
            if 200 <= e.code < 300:  # Some connectivity check endpoints return specific codes
                successful_tests += 1
                
        except urllib.error.URLError as e:
            logger.warning(f"URL error for {test_url}: {e.reason}")
            
        except socket.timeout:
            logger.warning(f"Timeout connecting to {test_url}")
            
        except Exception as e:
            logger.warning(f"Unexpected error testing {test_url}: {type(e).__name__}: {e}")
    
    success_rate = successful_tests / total_tests
    logger.info(f"Connectivity test results: {successful_tests}/{total_tests} successful ({success_rate:.1%})")
    
    # Consider it successful if at least one test passed
    is_valid = successful_tests > 0
    
    if is_valid:
        logger.info("🎉 Configuration validation PASSED!")
    else:
        logger.error("❌ Configuration validation FAILED - no successful connections")
    
    return is_valid

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
                    print("FUCK YEAH!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
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