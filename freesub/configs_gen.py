import json
import requests
import re
import random
import copy
import pycountry
import os
from dotenv import load_dotenv

# 1. Load Environment Variables
load_dotenv()

TARGET_URL = os.getenv("TARGET_URL")
TEMPLATE_FILE = "../template.json"
OUTPUT_FILE = "configs.json"
IPS = [
    "192.200.160.20",
    "63.141.128.231",
    "63.141.128.100",
    "192.200.160.24",
    
    "206.238.237.1",
    "206.238.239.65",
    "206.238.236.69",
    "206.238.236.105"
]


def starts_with_flag(text):
    """
    Checks if the text starts with a flag emoji.
    """
    if not text:
        return False
    # Regex for two regional indicator symbols
    flag_regex = r"^[\U0001F1E6-\U0001F1FF]{2}"
    return bool(re.match(flag_regex, text))


def flag_to_country_name(flag_char):
    """
    Converts a unicode flag emoji to a country name using pycountry.
    """
    try:
        # Convert Flag Emoji to ASCII ISO Code (e.g., 🇩🇪 -> DE)
        # Regional Indicator Symbol A is 127462. 'A' is 65. Difference is 127397.
        code = "".join([chr(ord(c) - 127397) for c in flag_char])

        country = pycountry.countries.get(alpha_2=code)
        if country:
            return country.name
        return None
    except Exception:
        return None


def replace_flag_with_country(text):
    """
    Finds flags in text and appends the country name from pycountry.
    """
    if not text:
        return text

    # Find all flags in the string
    flags = re.findall(r"[\U0001F1E6-\U0001F1FF]{2}", text)

    # Use set to avoid duplicates
    for flag in set(flags):
        country_name = flag_to_country_name(flag)
        if country_name:
            text = (
                f"{flag} {country_name}"  # text.replace(flag, f"{flag} {country_name}")
            )

    return text


def main():
    # Validation
    if not TARGET_URL:
        print("Error: TARGET_URL not found in .env file.")
        return

    # Load Template
    try:
        with open(TEMPLATE_FILE, "r", encoding="utf-8") as f:
            template = json.load(f)
    except FileNotFoundError:
        print(f"Error: {TEMPLATE_FILE} not found.")
        return

    # Fetch Data
    headers = {
        "User-Agent": "v2rayNG/1.10.32",
        "Accept": "application/json",
    }

    try:
        print(f"Fetching data from target URL...")
        response = requests.get(TARGET_URL, headers=headers)
        response.raise_for_status()
        data = response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching JSON: {e}")
        return

    final_data = []

    # Process Data
    for i, config in enumerate(data):
        remarks = config.get("remarks", "")

        # Skip if remarks doesn't start with a flag emoji
        if not starts_with_flag(remarks):
            continue

        # Check for "v6" or "REAL" conditions
        if "v6" in remarks:
            config["remarks"] = replace_flag_with_country(remarks)
            final_data.append(config)
            continue
        if "REAL" in remarks:
            continue

        print(f"Processing index {i}: {remarks}")

        proxy = config["outbounds"][0]
        # Check TLS serverName filter (starts with 'nl')
        try:
            tls_settings = config["outbounds"][0]["streamSettings"]["tlsSettings"]
            server_name = tls_settings.get("serverName", "")
            if server_name.lower().startswith("nl"):
                proxy = {
                    "mux": {"concurrency": -1, "enabled": False},
                    "protocol": "vless",
                    "settings": {
                        "vnext": [
                            {
                                "address": "ipw.ygdfw.com",
                                "port": 443,
                                "users": [
                                    {
                                        "encryption": "none",
                                        "id": "7e58699f-1d5d-4f6b-b181-cb74f0ad9509",
                                        "level": 8,
                                    }
                                ],
                            }
                        ]
                    },
                    "streamSettings": {
                        "network": "xhttp",
                        "security": "tls",
                        "tlsSettings": {
                            "allowInsecure": False,
                            "serverName": "Tp020KlHfZ.tRuStFoRtEaM.cOm",
                            "show": False,
                        },
                        "xhttpSettings": {
                            "host": "Tp020KlHfZ.tRuStFoRtEaM.cOm",
                            "mode": "stream-one",
                            "path": "/",
                        },
                    },
                    "tag": "proxy",
                }
        except (KeyError, IndexError, TypeError):
            pass
        # Deep clone template
        tmp = copy.deepcopy(template)

        # Update remarks
        tmp["remarks"] = replace_flag_with_country(remarks)

        # Add original proxy
        tmp["outbounds"].insert(0, proxy)

        # Generate variations for IPs
        for j, ip in enumerate(IPS):
            px = copy.deepcopy(proxy)

            try:
                original_string = px["streamSettings"]["tlsSettings"]["serverName"]
                new_string = original_string
                if original_string.startswith("DE"):
                    random_num = random.randint(10, 20)
                    new_string = re.sub(r"DE-\d+", f"DE-{random_num}", original_string)
                    print(new_string)

                elif original_string.startswith("FI"):
                    random_num = random.randint(1, 15)
                    new_string = re.sub(r"FI-\d+", f"FI-{random_num}", original_string)

                px["streamSettings"]["tlsSettings"]["serverName"] = new_string
            except (KeyError, TypeError):
                pass

            try:
                px["settings"]["vnext"][0]["address"] = ip
            except (KeyError, IndexError):
                pass

            px["tag"] = f"proxy{j}"
            tmp["outbounds"].insert(0, px)

        final_data.append(tmp)

    # ---------------------------------------------------------
    # Merge Logic: Combine configs with same remarks & reorder tags
    # ---------------------------------------------------------
    merged_configs = {}

    for config in final_data:
        rem = config.get("remarks", "")

        if rem not in merged_configs:
            merged_configs[rem] = config
        else:
            # Found a duplicate remark; merge proxies into the existing entry
            target_config = merged_configs[rem]

            # Extract proxies from the current config to merge
            # Filtering for tags starting with 'proxy' ensures we don't duplicate static outbounds (like direct/block)
            source_proxies = [
                out
                for out in config["outbounds"]
                if out.get("tag", "").startswith("proxy")
            ]

            # Insert new proxies at the beginning of the target's outbound list
            for px in reversed(source_proxies):
                target_config["outbounds"].insert(0, px)

    # Reconstruct final_data with reordered tags
    final_data_merged = []

    for rem, config in merged_configs.items():
        proxies = []
        others = []

        # Separate proxies from static outbounds
        for out in config["outbounds"]:
            if out.get("tag", "").startswith("proxy"):
                proxies.append(out)
            else:
                others.append(out)

        # Reorder/Renumber proxy tags sequentially (proxy, proxy1, proxy2...)
        for i, px in enumerate(proxies):
            if i == 0:
                px["tag"] = "proxy"
            else:
                px["tag"] = f"proxy{i}"

        # Combine back: proxies first, then others
        config["outbounds"] = proxies + others
        final_data_merged.append(config)

    # Update final_data reference
    final_data = final_data_merged
    # ---------------------------------------------------------

    # Save to config.json
    try:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            json.dump(final_data, f, indent=2, ensure_ascii=False)
        print(f"Successfully saved {len(final_data)} configurations to {OUTPUT_FILE}")
    except IOError as e:
        print(f"Error saving file: {e}")


if __name__ == "__main__":
    main()
