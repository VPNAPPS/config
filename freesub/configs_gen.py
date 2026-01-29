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
    "206.238.237.98",
    "192.200.160.15",
    "63.141.128.132",
    "185.225.195.61",
    "185.225.195.38",
    "ipw.ygdfw.com",
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
            text = text.replace(flag, f"{flag} {country_name}")

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
        # Check TLS serverName filter (starts with 'nl')
        try:
            tls_settings = config["outbounds"][0]["streamSettings"]["tlsSettings"]
            server_name = tls_settings.get("serverName", "")
            if server_name.startswith("nl"):
                continue
        except (KeyError, IndexError, TypeError):
            pass

        print(f"Processing index {i}: {remarks}")

        proxy = config["outbounds"][0]

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

                if original_string.startswith("de"):
                    random_num = random.randint(10, 20)
                    new_string = re.sub(r"de-\d+", f"de-{random_num}", original_string)

                elif original_string.startswith("fi"):
                    random_num = random.randint(1, 15)
                    new_string = re.sub(r"fi-\d+", f"fi-{random_num}", original_string)

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

    # Save to config.json
    try:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            json.dump(final_data, f, indent=2, ensure_ascii=False)
        print(f"Successfully saved {len(final_data)} configurations to {OUTPUT_FILE}")
    except IOError as e:
        print(f"Error saving file: {e}")


if __name__ == "__main__":
    main()
