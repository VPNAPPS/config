import re
import json
import pycountry
from collections import defaultdict
import sys
import os

# Add parent directory to path to import create_configs_json
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
try:
    from create_configs_json import build_config
except ImportError:
    # Fallback if file is missing (for testing purposes)
    def build_config(name, content, check=False):
        return {"name": name, "content": content}

def country_code_to_flag(country_code):
    """Convert country code to flag emoji"""
    if len(country_code) == 2:
        return ''.join(chr(ord(c) + 0x1F1E6 - ord('A')) for c in country_code.upper())
    return '🏳️'

def get_country_info(country_code):
    """Get country name and flag emoji from country code using pycountry"""
    try:
        special_cases = {
            'HK': 'Hong Kong',
            'TW': 'Taiwan',
            'MO': 'Macau',
            'UK': 'United Kingdom',
            'US': 'United States',
            'RU': 'Russia',
            'IR': 'Iran'
        }
        
        country_code = country_code.upper().strip()
        
        if country_code in special_cases:
            country_name = special_cases[country_code]
        else:
            country = pycountry.countries.get(alpha_2=country_code)
            if country:
                country_name = country.name
            else:
                country_name = country_code
        
        flag_emoji = country_code_to_flag(country_code)
        return country_name, flag_emoji
        
    except Exception:
        return country_code, '🏳️'

def parse_config_line(line):
    """
    Parse a configuration line in the format: config_string#COUNTRY_CODE
    Example: ss://...@1.2.3.4:443#JP
    """
    line = line.strip()
    if not line:
        return None, None

    # Split from the right, max 1 split, to separate the hash tag
    parts = line.rsplit('#', 1)
    
    if len(parts) == 2:
        # We keep the full line as the config, including the hash/tag
        config = line 
        country_code = parts[1].strip()
        
        # Basic validation: country code should be 2 letters
        if len(country_code) == 2 and country_code.isalpha():
            return country_code.upper(), config
            
    return None, None

def process_local_configs():
    """Main function to read local file, parse, and process VPN configurations"""
    
    # Define the local file path (same directory as this script)
    file_path = os.path.join(os.path.dirname(__file__), 'configs.txt')
    
    if not os.path.exists(file_path):
        print(f"❌ Error: {file_path} not found!")
        return

    print(f"Reading configs from {file_path}...")
    
    country_configs = defaultdict(list)
    total_found = 0

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                country_code, config = parse_config_line(line)
                if country_code and config:
                    country_configs[country_code].append(config)
                    total_found += 1
        
        print(f"✅ Found {total_found} valid configurations.")
        
        # Build final configs array
        configs_json_output = []
        
        print("Building final configurations by country...")
        
        # Sort countries alphabetically for cleaner output
        sorted_countries = sorted(country_configs.keys())
        
        for country_code in sorted_countries:
            config_list = country_configs[country_code]
            country_name, flag_emoji = get_country_info(country_code)
            
            print(f"Processing {len(config_list)} configs for {country_name} ({country_code})")
            
            # Combine all configs for this country into one string
            content = "\n".join(config_list)
            
            # Call the build_config function
            config_result = build_config(f"{flag_emoji} {country_name}", content, check=False)
            if config_result:
                configs_json_output.append(config_result)
        
        # Save to JSON file
        output_file = 'configs.json'
        print(f"\nSaving {len(configs_json_output)} country groups to {output_file}...")
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(configs_json_output, f, indent=2, ensure_ascii=False)
        
        print(f"✅ Successfully created {output_file}")
        
        # Print summary by country
        print("\nSummary by country:")
        for country_code in sorted_countries:
            country_name, _ = get_country_info(country_code)
            print(f"  {country_name}: {len(country_configs[country_code])} configs")
            
    except Exception as e:
        print(f"❌ Error processing data: {e}")

if __name__ == "__main__":
    process_local_configs()
