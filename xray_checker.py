import subprocess
import requests
import time
import json
import re
import os
import signal
import socket
import base64
from typing import List, Dict, Optional
import logging
from urllib.parse import unquote, urlparse
import ipaddress
import re

def _find_free_port(start_port: int = 2112, max_attempts: int = 1000) -> int:
    """
    Find a free port starting from the given port number.

    Args:
        start_port (int): Starting port number to check
        max_attempts (int): Maximum number of ports to try

    Returns:
        int: Free port number

    Raises:
        Exception: If no free port is found
    """
    for port in range(start_port, start_port + max_attempts):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("localhost", port))
                return port
        except OSError:
            continue

    raise Exception(
        f"No free port found in range {start_port}-{start_port + max_attempts}"
    )


def parse_base64_subscription(base64_data: str) -> List[str]:
    """
    Parse base64-encoded subscription data and extract proxy URLs.
    Supports VLESS, VMess, Shadowsocks, and Trojan protocols.

    Args:
        base64_data (str): Base64-encoded subscription data

    Returns:
        List[str]: List of proxy URLs
    """
    try:
        # Decode base64 data
        decoded_data = base64.b64decode(base64_data).decode("utf-8")

        # Split by newlines and filter out empty lines
        # Support all major proxy protocols
        proxy_urls = []
        for line in decoded_data.split("\n"):
            line = line.strip()
            if line and any(
                line.startswith(protocol)
                for protocol in ["vless://", "ss://", "trojan://", "shadowsocks://"]
            ):
                proxy_urls.append(line)

        return proxy_urls
    except Exception as e:
        raise Exception(f"Failed to parse base64 subscription data: {e}")


def extract_proxy_info(proxy_url: str) -> Dict[str, str]:
    """
    Extract basic information from a proxy URL for matching with metrics.
    Enhanced to support VLESS, VMess, Shadowsocks, and Trojan protocols.

    Args:
        proxy_url (str): Proxy URL (vless://, vmess://, ss://, trojan://, etc.)

    Returns:
        Dict: Proxy information (protocol, address, name, port)
    """
    try:
        # Extract protocol
        protocol = proxy_url.split("://")[0].lower()

        # Handle different protocol formats
        if protocol in ["vless", "trojan"]:
            return _extract_vless_trojan_info(proxy_url, protocol)
        elif protocol == "vmess":
            return _extract_vmess_info(proxy_url)
        elif protocol in ["ss", "shadowsocks"]:
            return _extract_shadowsocks_info(proxy_url)
        else:
            # Fallback for unknown protocols
            return _extract_generic_info(proxy_url, protocol)

    except Exception as e:
        logging.warning(f"Failed to parse proxy URL {proxy_url[:50]}...: {e}")
        return {
            "protocol": "unknown",
            "address": "unknown",
            "name": "unknown",
            "port": "unknown",
            "url": proxy_url,
        }


def _extract_vless_trojan_info(proxy_url: str, protocol: str) -> Dict[str, str]:
    url_parts = proxy_url.split("://")[1]
    name = ""
    if "#" in proxy_url:
        name = unquote(proxy_url.split("#")[1])
    if "@" in url_parts:
        address_part = url_parts.split("@")[1]
    else:
        address_part = url_parts
    address = address_part.split("?")[0].split("#")[0]
    if ":" in address:
        host, port = address.rsplit(":", 1)
    else:
        host, port = address, "443"
    return {
        "protocol": protocol,
        "address": address,
        "host": host,
        "port": port,
        "name": name,
        "url": proxy_url,
    }



def _extract_vmess_info(proxy_url: str) -> Dict[str, str]:
    try:
        vmess_data = proxy_url.replace("vmess://", "")
        decoded_json = base64.b64decode(vmess_data).decode("utf-8")
        vmess_config = json.loads(decoded_json)
        host = vmess_config.get("add", "")
        port = str(vmess_config.get("port", ""))
        name = vmess_config.get("ps", "")

        address = f"{host}:{port}" if host and port else "unknown"
        return {
            "protocol": "vmess",
            "address": address,
            "host": host,
            "port": port,
            "name": name,
            "url": proxy_url,
        }
    except Exception as e:
        return _extract_generic_info(proxy_url, "vmess")



def _extract_shadowsocks_info(proxy_url: str) -> Dict[str, str]:
    try:
        url_parts = proxy_url.split("://")[1]
        name = ""
        if "#" in proxy_url:
            name = unquote(proxy_url.split("#")[1])
            url_parts = url_parts.split("#")[0]
        if "@" in url_parts:
            _, address_part = url_parts.rsplit("@", 1)
        else:
            address_part = url_parts
        if ":" in address_part:
            host, port = address_part.rsplit(":", 1)
        else:
            host, port = address_part, "8388"

        address = f"{host}:{port}"
        return {
            "protocol": "shadowsocks",
            "address": address,
            "host": host,
            "port": port,
            "name": name,
            "url": proxy_url,
        }
    except Exception as e:
        return _extract_generic_info(proxy_url, "shadowsocks")



def _extract_generic_info(proxy_url: str, protocol: str) -> Dict[str, str]:
    try:
        parsed = urlparse(proxy_url)
        host = parsed.hostname or "unknown"
        port = str(parsed.port) if parsed.port else "unknown"

        address = f"{host}:{port}" if host != "unknown" and port != "unknown" else "unknown"
        name = ""
        if "#" in proxy_url:
            name = unquote(proxy_url.split("#")[1])
        return {
            "protocol": protocol,
            "address": address,
            "host": host,
            "port": port,
            "name": name,
            "url": proxy_url,
        }
    except Exception:
        return {
            "protocol": protocol,
            "address": "unknown",
            "host": "unknown",
            "port": "unknown",
            "name": "unknown",
            "url": proxy_url,
        }



def _check_xray_subscription(
    subscription_base64: str,
    proxy_no: int,
    binary_path: str = None,
    timeout: int = 30,
    check_interval: int = 10,
    preferred_port: int = 2112,
) -> List[str]:
    """
    Run xray-checker binary with base64-encoded subscription data and return working proxy URLs.
    Enhanced to support VLESS, VMess, Shadowsocks, and Trojan protocols.

    Args:
        subscription_base64 (str): Base64-encoded subscription data containing proxy URLs
        proxy_no (int): Expected number of proxies
        binary_path (str, optional): Path to the xray-checker binary (default: looks in script directory)
        timeout (int): Maximum time to wait for checks to complete (seconds)
        check_interval (int): Interval between status checks (seconds)
        preferred_port (int): Preferred port for metrics (will find free port starting from this)

    Returns:
        List[str]: List of working proxy URLs

    Example:
        base64_data = "dmxlc3M6Ly8zOTU2ZGQzNS00Zjg2LTRiNDgtYTFjYS00NWEzZGJlNDcxYTBANTEuMjIyLjg2Ljc6NTE5NTI..."
        working_proxies = check_xray_subscription(base64_data, len(proxy_urls))
        for proxy_url in working_proxies:
            print(f"Working proxy: {proxy_url}")
    """

    # Set up logging
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
    )
    logger = logging.getLogger(__name__)

    # Set default binary path if not provided
    if binary_path is None:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        binary_path = os.path.join(script_dir, "xray-checker")
        # On Windows, add .exe extension if it doesn't exist
        if os.name == "nt" and not binary_path.endswith(".exe"):
            if os.path.exists(binary_path + ".exe"):
                binary_path += ".exe"

    process = None

    try:
        # Parse the base64 subscription data
        logger.info("Parsing base64 subscription data...")
        proxy_urls = parse_base64_subscription(subscription_base64)
        logger.info(f"Found {len(proxy_urls)} proxies in subscription")

        # Extract proxy information for matching
        proxy_info_list = []
        protocol_counts = {}

        for i, proxy_url in enumerate(proxy_urls):
            proxy_info = extract_proxy_info(proxy_url)
            proxy_info["index"] = i
            proxy_info_list.append(proxy_info)

            # Count protocols
            protocol = proxy_info["protocol"]
            protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1

        logger.info(f"Protocol distribution: {protocol_counts}")

        # Find a free port for metrics
        metrics_port = _find_free_port(preferred_port)
        logger.info(f"Using port {metrics_port} for metrics")

        # Set up environment variables for the binary
        env = os.environ.copy()
        env["SUBSCRIPTION_URL"] = subscription_base64  # Pass the base64 data directly

        # Prepare command with metrics port argument
        cmd = [binary_path, f"--metrics-port={metrics_port}"]

        # Start xray-checker binary
        logger.info(f"Starting xray-checker binary: {' '.join(cmd)}")

        process = subprocess.Popen(
            cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )

        # Wait for the service to start
        logger.info("Waiting for xray-checker service to start...")
        time.sleep(15)

        # Check if process is still running
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            logger.error(f"Binary exited early. Stdout: {stdout}, Stderr: {stderr}")
            raise Exception(f"xray-checker binary failed to start: {stderr}")

        # Wait for checks to complete and get working proxies
        start_time = time.time()
        working_proxy_urls = []

        while time.time() - start_time < timeout:
            try:
                # Check if service is healthy
                health_response = requests.get(
                    f"http://localhost:{metrics_port}/health", timeout=5
                )
                if health_response.status_code != 200:
                    logger.info("Service not ready yet, waiting...")
                    time.sleep(check_interval)
                    continue

                # Get metrics
                metrics_response = requests.get(
                    f"http://localhost:{metrics_port}/metrics", timeout=10
                )
                if metrics_response.status_code == 200:
                    if len(metrics_response.text.split("\n")) < proxy_no * 2 + 4:
                        continue
                    working_proxy_urls = _parse_metrics_and_match_urls(
                        metrics_response.text, proxy_info_list
                    )
                    if working_proxy_urls:
                        logger.info(f"Found {len(working_proxy_urls)} working proxies")
                        break
                    else:
                        logger.info(
                            "No working proxies found yet, continuing to wait..."
                        )
                else:
                    logger.warning(
                        f"Metrics endpoint returned status: {metrics_response.status_code}"
                    )

            except requests.exceptions.RequestException as e:
                logger.debug(f"Request failed: {e}, retrying...")

            # Check if process is still alive
            if process.poll() is not None:
                stdout, stderr = process.communicate()
                logger.error(
                    f"Process died unexpectedly. Stdout: {stdout}, Stderr: {stderr}"
                )
                break

            time.sleep(check_interval)

        if not working_proxy_urls:
            logger.warning("No working proxies found within timeout period")

        return working_proxy_urls

    except FileNotFoundError:
        logger.error(f"Binary not found at path: {binary_path}")
        raise Exception(f"xray-checker binary not found at: {binary_path}")

    except Exception as e:
        logger.error(f"Error running xray-checker: {e}")
        raise

    finally:
        # Clean up process
        if process and process.poll() is None:
            logger.info("Terminating xray-checker process...")
            try:
                # Try graceful termination first
                process.terminate()
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                # Force kill if graceful termination fails
                logger.warning("Graceful termination failed, force killing process...")
                process.kill()
                process.wait()
            except Exception as e:
                logger.warning(f"Error during process cleanup: {e}")


def _parse_metrics_and_match_urls(
    metrics_text: str, proxy_info_list: List[Dict]
) -> List[str]:
    """
    Parse Prometheus metrics text and match working proxies to original URLs.
    Enhanced to support multiple proxy protocols.

    Args:
        metrics_text (str): Raw Prometheus metrics text
        proxy_info_list (List[Dict]): List of proxy information with URLs

    Returns:
        List[str]: List of working proxy URLs
    """
    working_proxy_urls = []

    # Parse proxy status metrics - updated pattern to handle more protocols
    status_pattern = r'xray_proxy_status\{address="([^"]+)",name="([^"]*)",protocol="([^"]+)"\}\s+([01])'
    latency_pattern = r'xray_proxy_latency_ms\{address="([^"]+)",name="([^"]*)",protocol="([^"]+)"\}\s+(\d+(?:\.\d+)?)'

    status_matches = re.findall(status_pattern, metrics_text)
    latency_matches = re.findall(latency_pattern, metrics_text)

    # Create a dictionary for quick latency lookup
    latency_dict = {}
    for address, name, protocol, latency in latency_matches:
        key = (address, name, protocol)
        latency_dict[key] = float(latency)

    # Process status matches and find corresponding URLs
    for address, name, protocol, status in status_matches:
        if status == "1":  # Working proxy
            # Find matching proxy URL from original list
            matching_proxy = None

            # Try multiple matching strategies
            for proxy_info in proxy_info_list:
                # Strategy 1: Exact match on protocol and address
                if (
                    proxy_info["protocol"] == protocol
                    and proxy_info["address"] == address
                ):
                    matching_proxy = proxy_info
                    break

                # Strategy 2: Match by protocol and host:port separately
                if (
                    proxy_info["protocol"] == protocol
                    and proxy_info.get("host")
                    and proxy_info.get("port")
                    and f"{proxy_info['host']}:{proxy_info['port']}" == address
                ):
                    matching_proxy = proxy_info
                    break

                # Strategy 3: Match by name and protocol (fallback)
                if (
                    proxy_info["name"] == name
                    and proxy_info["protocol"] == protocol
                    and name
                    and name != "unknown"
                ):
                    matching_proxy = proxy_info
                    break

                # Strategy 4: Protocol normalization (ss vs shadowsocks)
                normalized_protocol = _normalize_protocol(proxy_info["protocol"])
                if (
                    normalized_protocol == _normalize_protocol(protocol)
                    and proxy_info["address"] == address
                ):
                    matching_proxy = proxy_info
                    break

            if matching_proxy:
                working_proxy_urls.append(matching_proxy["url"])
                logging.info(f"✅ Found working proxy: {protocol}://{address} ({name})")
            else:
                # If no exact match found, log for debugging
                logging.warning(
                    f"Could not find matching URL for working proxy: {protocol}://{address} ({name})"
                )

    return working_proxy_urls


def _normalize_protocol(protocol: str) -> str:
    """Normalize protocol names for better matching"""
    protocol = protocol.lower()
    if protocol in ["ss", "shadowsocks"]:
        return "shadowsocks"
    return protocol


def _parse_metrics(metrics_text: str) -> List[Dict[str, any]]:
    """
    Parse Prometheus metrics text and extract working proxy information (legacy function).
    Enhanced to support multiple protocols.

    Args:
        metrics_text (str): Raw Prometheus metrics text

    Returns:
        List[Dict]: List of working proxy configurations
    """
    working_proxies = []

    # Parse proxy status metrics
    status_pattern = r'xray_proxy_status\{address="([^"]+)",name="([^"]*)",protocol="([^"]+)"\}\s+([01])'
    latency_pattern = r'xray_proxy_latency_ms\{address="([^"]+)",name="([^"]*)",protocol="([^"]+)"\}\s+(\d+(?:\.\d+)?)'

    status_matches = re.findall(status_pattern, metrics_text)
    latency_matches = re.findall(latency_pattern, metrics_text)

    # Create a dictionary for quick latency lookup
    latency_dict = {}
    for address, name, protocol, latency in latency_matches:
        key = (address, name, protocol)
        latency_dict[key] = float(latency)

    # Process status matches and keep only working proxies
    for address, name, protocol, status in status_matches:
        if status == "1":  # Working proxy
            key = (address, name, protocol)
            latency = latency_dict.get(key, 0)

            proxy_info = {
                "name": name,
                "protocol": protocol,
                "address": address,
                "status": "working",
                "latency_ms": latency,
            }
            working_proxies.append(proxy_info)

    return working_proxies


def _get_individual_proxy_status(
    proxy_index: int, protocol: str, server: str, port: int, metrics_port: int = 2112
) -> bool:
    """
    Check individual proxy status using the specific proxy endpoint.
    Enhanced to support multiple protocols.

    Args:
        proxy_index (int): Proxy index number
        protocol (str): Protocol type (vless/vmess/trojan/shadowsocks)
        server (str): Server address
        port (int): Server port
        metrics_port (int): Port for the metrics endpoint

    Returns:
        bool: True if proxy is working, False otherwise
    """
    try:
        # Normalize protocol name
        normalized_protocol = _normalize_protocol(protocol)
        endpoint = f"http://localhost:{metrics_port}/config/{proxy_index}-{normalized_protocol}-{server}-{port}"
        response = requests.get(endpoint, timeout=10)
        return response.status_code == 200 and response.text.strip() == "OK"
    except requests.exceptions.RequestException:
        return False


def _check_xray_subscription_with_config_file(
    subscription_base64: str,
    binary_path: str = "xray-checker",
    config_file: Optional[str] = None,
    timeout: int = 300,
    preferred_port: int = 2112,
) -> List[str]:
    """
    Alternative function that uses a configuration file for xray-checker.
    Enhanced to support multiple protocols.

    Args:
        subscription_base64 (str): Base64-encoded subscription data
        binary_path (str): Path to the xray-checker binary
        config_file (str, optional): Path to configuration file
        timeout (int): Maximum time to wait for checks
        preferred_port (int): Preferred port for metrics

    Returns:
        List[str]: List of working proxy URLs
    """

    import tempfile

    logger = logging.getLogger(__name__)
    temp_config = None

    try:
        # Parse to get proxy count
        proxy_urls = parse_base64_subscription(subscription_base64)
        proxy_count = len(proxy_urls)

        # Find free port
        metrics_port = _find_free_port(preferred_port)

        # Create temporary config file if not provided
        if not config_file:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".env", delete=False
            ) as f:
                f.write(f"SUBSCRIPTION_URL={subscription_base64}\n")
                f.write(f"METRICS_PORT={metrics_port}\n")
                f.write("METRICS_ENABLED=true\n")
                f.write("CHECK_INTERVAL=30s\n")
                f.write("SUPPORT_PROTOCOLS=vless,vmess,trojan,shadowsocks\n")
                temp_config = f.name
                config_file = temp_config

        # Run with config file but still use command line for port
        return _check_xray_subscription(
            subscription_base64=subscription_base64,
            proxy_no=proxy_count,
            binary_path=binary_path,
            timeout=timeout,
            preferred_port=metrics_port,
        )

    finally:
        # Clean up temporary config file
        if temp_config and os.path.exists(temp_config):
            os.unlink(temp_config)

def get_working_proxies(base64_subscription: str):
    try:
        # Test parsing base64 data first
        print("Parsing base64 subscription data...")
        proxy_urls = parse_base64_subscription(base64_subscription)
        print(f"Found {len(proxy_urls)} proxies:")

        # Group by protocol for better display
        protocol_groups = {}
        for i, url in enumerate(proxy_urls):
            proxy_info = extract_proxy_info(url)
            protocol = proxy_info["protocol"]
            if protocol not in protocol_groups:
                protocol_groups[protocol] = []
            protocol_groups[protocol].append((i, proxy_info))

        # Display grouped results
        for protocol, proxies in protocol_groups.items():
            print(f"\n  {protocol.upper()} proxies ({len(proxies)}):")
            for i, proxy_info in proxies:
                print(f"    {i}: {proxy_info['address']} - {proxy_info['name']}")

        print(f"\nRunning xray-checker to test {len(proxy_urls)} proxies...")

        # Run the checker
        working_proxy_urls = _check_xray_subscription(
            base64_subscription, proxy_no=len(proxy_urls)
        )

        print(f"\nFound {len(working_proxy_urls)} working proxies:")

        # Group working proxies by protocol
        working_by_protocol = {}
        for proxy_url in working_proxy_urls:
            proxy_info = extract_proxy_info(proxy_url)
            protocol = proxy_info["protocol"]
            if protocol not in working_by_protocol:
                working_by_protocol[protocol] = []
            working_by_protocol[protocol].append(proxy_info)
        pxies = ""
        # Display working proxies grouped by protocol
        for protocol, proxies in working_by_protocol.items():
            print(f"\n  ✅ Working {protocol.upper()} proxies ({len(proxies)}):")
            for i, proxy_info in enumerate(proxies):
                print(f"    {i+1}: {proxy_info['name']} - {proxy_info['address']}")
                print(f"        URL: {proxy_info['url']}")
                pxies+=proxy_info['url']+"\n"

        if not working_proxy_urls:
            print("❌ No working proxies found")
            return None
        
        return pxies
    
    except Exception as e:
        print(f"❌ Error: {e}")
        return None

# Example usage
if __name__ == "__main__":
    # Example base64 subscription data with mixed protocols
    base64_subscription = ""


