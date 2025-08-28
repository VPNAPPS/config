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

def fetch_configs_from_url(url):
    """Fetch and parse configs from a given URL"""
    try:
        print(f"Fetching data from {url}...")
        response = requests.get(url)
        response.raise_for_status()
        
        # Parse the content
        lines = response.text.strip().split('\n')
        configs = []
        
        for line in lines:
            if line.strip():  # Skip empty lines
                country_code, speed, config = parse_config_line(line)
                if country_code and config:
                    configs.append({
                        'country_code': country_code,
                        'speed': speed,
                        'config': config
                    })
        
        return configs
        
    except requests.RequestException as e:
        print(f"❌ Error fetching data from {url}: {e}")
        return []
    except Exception as e:
        print(f"❌ Error processing data from {url}: {e}")
        return []

def extract_config_identifier(config):
    """Extract a unique identifier from a config string for comparison"""
    # Use the config string itself as identifier, or you could extract specific parts
    # depending on the config format (e.g., server address, port, etc.)
    return config.strip()

def fetch_and_process_configs():
    """Main function to fetch, parse, and process VPN configurations"""
    urls = {
        'main': "https://raw.githubusercontent.com/VPNAPPS/checker/refs/heads/main/configs.txt",
        'gonzo': "https://github.com/VPNAPPS/checker/raw/refs/heads/main/configs-gonzo.txt",
        'tuco': "https://github.com/VPNAPPS/checker/raw/refs/heads/main/configs-tuco.txt"
    }
    
    try:
        # Fetch configs from all URLs
        all_configs = {}
        for source, url in urls.items():
            all_configs[source] = fetch_configs_from_url(url)
            print(f"Fetched {len(all_configs[source])} configs from {source}")
        
        # Create a set of main config identifiers for comparison
        main_config_identifiers = set()
        for config_item in all_configs['main']:
            main_config_identifiers.add(extract_config_identifier(config_item['config']))
        
        print(f"Main configs set contains {len(main_config_identifiers)} unique configs")
        
        # Process gonzo and tuco configs, keeping only those that exist in main
        filtered_configs = []
        
        for source in ['gonzo', 'tuco']:
            print(f"\nProcessing {source} configs...")
            matching_configs = []
            
            for config_item in all_configs[source]:
                config_id = extract_config_identifier(config_item['config'])
                if config_id in main_config_identifiers:
                    matching_configs.append(config_item)
            
            print(f"Found {len(matching_configs)} {source} configs that match main configs")
            filtered_configs.extend(matching_configs)
        
        print(f"\nTotal filtered configs from gonzo and tuco: {len(filtered_configs)}")
        
        # Decide which configs to use
        if len(filtered_configs) >= 10:
            print("Using filtered configs from gonzo and tuco (>=10 configs found)")
            configs_to_process = filtered_configs
        else:
            print("Less than 10 filtered configs found, falling back to main configs")
            configs_to_process = all_configs['main']
        
        # Group configs by country
        country_configs = defaultdict(list)
        
        print(f"Processing {len(configs_to_process)} configurations...")
        for config_item in configs_to_process:
            country_code = config_item['country_code']
            country_configs[country_code].append({
                'speed': config_item['speed'],
                'config': config_item['config']
            })
        
        # Build final configs array
        configs = []
        
        print("Building final configurations by country...")
        for country_code, config_list in country_configs.items():
            # if len(config_list) < 5:
            #     continue
                
            country_name, flag_emoji = get_country_info(country_code)
            
            print(f"Processing {len(config_list)} configs for {country_name} ({country_code})")
            
            # Sort by speed (lowest first) for better organization
            config_list.sort(key=lambda x: x['speed'], reverse=False)
            
            # Process each config for this country
            content = ""
            for config_item in config_list:
                content += config_item['config'] + "\n"
            
            # Call the build_config function
            config_result = build_config(f"{flag_emoji} {country_name}", content, check=False)
            if config_result:
                configs.append(config_result)
        
        # Save to JSON file
        print(f"\nSaving {len(configs)} configurations to configs.json...")
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
            
    except Exception as e:
        print(f"❌ Error processing data: {e}")

if __name__ == "__main__":
    fetch_and_process_configs()