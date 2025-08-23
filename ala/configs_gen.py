import requests
import re
import json
import pycountry
from collections import defaultdict
import sys, os
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from create_configs_json import build_config

def country_code_to_flag(country_code):
    """Convert country code to flag emoji"""
    # Convert country code to regional indicator symbols
    if len(country_code) == 2:
        return ''.join(chr(ord(c) + 0x1F1E6 - ord('A')) for c in country_code.upper())
    return '🏳️'  # Default flag for unknown codes

def get_country_info(country_code):
    """Get country name and flag emoji from country code using pycountry"""
    try:
        # Handle special cases that might not be in pycountry
        special_cases = {
            'HK': 'Hong Kong',
            'TW': 'Taiwan',
            'MO': 'Macau'
        }
        
        if country_code in special_cases:
            country_name = special_cases[country_code]
        else:
            # Use pycountry to get the country name
            country = pycountry.countries.get(alpha_2=country_code)
            if country:
                country_name = country.name
            else:
                # Fallback to country code if not found
                country_name = country_code
        
        flag_emoji = country_code_to_flag(country_code)
        return country_name, flag_emoji
        
    except Exception:
        # Fallback case for any errors
        return country_code, '🏳️'

def parse_config_line(line):
    """Parse a single configuration line and extract country, speed, and config"""
    # Pattern to match: Country: XX, Speed: XXXX.XX Mbps, Config: vless://...
    pattern = r'Country:\s*([A-Z]{2}),\s*Speed:\s*([\d.]+)\s*Mbps,\s*Config:\s*(.+)'
    match = re.match(pattern, line.strip())
    
    if match:
        country_code = match.group(1)
        speed = float(match.group(2))
        config = match.group(3)
        return country_code, speed, config
    return None, None, None

def fetch_and_process_configs():
    """Main function to fetch, parse, and process VPN configurations"""
    url = "https://raw.githubusercontent.com/VPNAPPS/checker/refs/heads/main/configs.txt"
    
    try:
        # Fetch the data
        print("Fetching data from URL...")
        response = requests.get(url)
        response.raise_for_status()
        
        # Parse the content
        lines = response.text.strip().split('\n')
        
        # Group configs by country
        country_configs = defaultdict(list)
        
        print("Parsing configurations...")
        for line in lines:
            if line.strip():  # Skip empty lines
                country_code, speed, config = parse_config_line(line)
                if country_code and config:
                    country_configs[country_code].append({
                        'speed': speed,
                        'config': config
                    })
        
        # Build final configs array
        configs = []
        
        print("Processing configurations by country...")
        for country_code, config_list in country_configs.items():
            # if len(config_list) < 5:
            #     continue
            country_name, flag_emoji = get_country_info(country_code)
            
            print(f"Processing {len(config_list)} configs for {country_name} ({country_code})")
            
            # Sort by speed (highest first) for better organization
            config_list.sort(key=lambda x: x['speed'], reverse=True)
            
            # Process each config for this country
            content = ""
            for config_item in config_list:
                content += config_item['config'] +"\n"
                
                # Call the build_config function
            config_result = build_config(f"{flag_emoji} {country_name}", content, check=False)
            if config_result:
                configs.append(config_result)
        
        # Save to JSON file
        print(f"Saving {len(configs)} configurations to configs.json...")
        with open('configs.json', 'w', encoding='utf-8') as f:
            json.dump(configs, f, indent=2, ensure_ascii=False)
        
        print("✅ Successfully created configs.json")
        print(f"Total configurations processed: {len(configs)}")
        
        # Print summary by country
        country_summary = defaultdict(int)
        for country_code in country_configs.keys():
            country_name, _ = get_country_info(country_code)
            country_summary[country_name] = len(country_configs[country_code])
        
        print("\nSummary by country:")
        for country, count in sorted(country_summary.items()):
            print(f"  {country}: {count} configs")
            
    except requests.RequestException as e:
        print(f"❌ Error fetching data: {e}")
    except Exception as e:
        print(f"❌ Error processing data: {e}")

if __name__ == "__main__":
    fetch_and_process_configs()