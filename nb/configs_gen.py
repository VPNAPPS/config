import requests
import json
from collections import defaultdict
import copy
import os
from dotenv import load_dotenv
import pycountry

# Load environment variables from .env file
load_dotenv()

def emoji_to_country_name(emoji):
    """
    Convert flag emoji to country name using pycountry.
    Flag emojis are made of regional indicator symbols that correspond to ISO alpha-2 codes.
    """
    if not is_flag_emoji(emoji):
        # Handle special cases that aren't flag emojis
        special_cases = {
            "(nm_zorp)": "Zorp",
            "🛜": "WiFi",
            "✅": "Checked",
            "❌": "Blocked",
            "🏴󠁧󠁢󠁥󠁮󠁧󠁿": "England"  # England flag is a special case
        }
        return special_cases.get(emoji, emoji)
    
    # Convert flag emoji to country code
    # Flag emojis use regional indicator symbols (U+1F1E6 to U+1F1FF)
    # Each corresponds to A-Z, so we convert back to get the country code
    if len(emoji) == 2:
        try:
            # Convert each character back to its corresponding letter
            code = ''.join(chr(ord(char) - 0x1F1E6 + ord('A')) for char in emoji)
            
            # Look up the country using pycountry
            country = pycountry.countries.get(alpha_2=code)
            if country:
                return country.name
            else:
                return emoji  # Return emoji if country not found
        except (ValueError, AttributeError):
            return emoji
    
    return emoji

with open("../template.json", "r") as f:
  TEMPLATE = json.loads(f.read())

def is_flag_emoji(char):
    """Check if a character is a flag emoji (regional indicator symbols)"""
    # Flag emojis are composed of regional indicator symbols (U+1F1E6 to U+1F1FF)
    if len(char) == 2:  # Flag emojis are typically 2 characters
        return all(0x1F1E6 <= ord(c) <= 0x1F1FF for c in char)
    return False


def fetch_and_group_data():
    """
    Fetches data from the URL specified in .env file, groups it by the flag emoji in the 'remarks' field,
    and prints the grouped data.
    """
    # Get URL from environment variable
    url = os.getenv('URL')
    if not url:
        print("Error: URL not found in .env file. Please add URL=your_api_url to your .env file")
        return None
    
    headers = {"User-Agent": "v2rayNG/1.10.7"}

    try:
        # Send a GET request to the URL with the specified headers
        response = requests.get(url, headers=headers)
        # Raise an exception for bad status codes (4xx or 5xx)
        response.raise_for_status()

        # Parse the JSON response
        data = response.json()

        # A dictionary to hold the grouped results. defaultdict makes it easier
        # as we don't need to check if the key exists before appending.
        grouped_data = defaultdict(list)

        # Iterate over each object in the data list
        for item in data:
            # Get the 'remarks' string, default to an empty string if not found
            remarks = item.get("remarks", "")

            # The flag emoji is usually the first part of the remarks string.
            # We split the string by space and take the first element as the key.
            if remarks:
                key = remarks.split()[0]
                # Check if the key is a flag emoji
                if is_flag_emoji(key):
                    grouped_data[key].append(item)
                else:
                    # If not a flag emoji, group under 'no_remarks'
                    grouped_data["no_remarks"].append(item)
            else:
                # If there are no remarks, group them under a 'no_remarks' key
                grouped_data["no_remarks"].append(item)

        # Pretty-print the grouped JSON data.
        # ensure_ascii=False is used to correctly print the emoji characters.
        #print(json.dumps(grouped_data, indent=4, ensure_ascii=False))
        return grouped_data

    except requests.exceptions.RequestException as e:
        print(f"An error occurred during the request: {e}")
        return None
    except json.JSONDecodeError as e:
        print(f"Failed to parse JSON response: {e}")
        return None
    except IndexError:
        # This handles cases where remarks might be an empty string after splitting
        print("An error occurred while parsing remarks.")
        return None

def add_to_template(grouped_data):
    """
    Creates configurations for each country group using the template.
    """
    if not grouped_data:
        return []
    
    configs = []
    
    # Iterate over the grouped data properly
    for emoji, config_list in grouped_data.items():
        # Parse the template JSON for each country
        template = copy.deepcopy(TEMPLATE)
        
        # Keep the original proxy outbound at the first position
        # Find all non-proxy outbounds (after the first proxy)
        base_outbounds = [ob for ob in template["outbounds"] if ob["tag"] != "proxy"]
        
        # Start with just the base outbounds, we'll insert proxies at the beginning
        new_outbounds = []
        
        # Add the original proxy first (keep it as "proxy")
        original_proxy = next((ob for ob in template["outbounds"] if ob["tag"] == "proxy"), None)
        if original_proxy:
            new_outbounds.append(original_proxy)
        
        # Add each config from this country group
        for i, config in enumerate(config_list, 1):
            # Create a deep copy of the config's outbound to avoid modifying the original
            if "outbounds" in config and len(config["outbounds"]) > 0:
                proxy_config = copy.deepcopy(config["outbounds"][0])
                proxy_config["tag"] = f"proxy{i}"
                new_outbounds.append(proxy_config)
        
        # Add the base outbounds after all proxies
        new_outbounds.extend(base_outbounds)
        
        # Update the template outbounds
        template["outbounds"] = new_outbounds
        
        # Keep the original balancer selector unchanged (it stays as ["proxy"])
        
        # Set the remarks with country name using pycountry
        country_name = emoji_to_country_name(emoji)
        template["remarks"] = f"{emoji} {country_name}"
        
        configs.append(template)
    
    return configs

if __name__ == "__main__":
    grouped_data = fetch_and_group_data()
    if grouped_data:
        configs = add_to_template(grouped_data)
        configs = configs[1:]
        # Export to configs.json file
        try:
            with open("configs.json", "w", encoding="utf-8") as f:
                json.dump(configs, f, indent=4, ensure_ascii=False)
            print(f"Successfully exported {len(configs)} configurations to configs.json")
        except IOError as e:
            print(f"Failed to write configs.json: {e}")
            # Fallback to printing to console
            print(json.dumps(configs, indent=4, ensure_ascii=False))
    else:
        print("Failed to fetch or process data.")