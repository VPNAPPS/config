import os
import json
from pathlib import Path
from create_configs_json import build_config_json_from_proxies

FOLDERS = ['begz', 'yebe']
OUTPUT_FILE = 'configs.json'
CANDIDATE_FILES = ['configs.json', 'config.json']

merged_list = []

def load_json_from_folder(folder: str):
    for filename in CANDIDATE_FILES:
        path = Path(folder) / filename
        if path.exists():
            with open(path, 'r', encoding='utf-8') as f:
                print(f"Loading: {path}")
                try:
                    return json.load(f)
                except json.JSONDecodeError as e:
                    print(f"Invalid JSON in {path}: {e}")
                    return None
    print(f"No config file found in {folder}")
    return None

for folder in FOLDERS:
    data = load_json_from_folder(folder)
    if data is None:
        continue
    if isinstance(data, list):
        merged_list.extend(data)
    elif isinstance(data, dict):
        merged_list.append(data)
    else:
        print(f"Unsupported data type in {folder}: {type(data)}")

# Save raw merged list for debugging
with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
    json.dump(merged_list, f, ensure_ascii=False, indent=2)
    print(f"Merged config written to {OUTPUT_FILE}")

# Build merged config from outbounds
i = 0
proxies = []
for config in merged_list:
    i += 1
    outbounds = config.get("outbounds")
    if not outbounds:
        print(f"Warning: config #{i} has no 'outbounds'. Skipping.")
        continue
    for proxy in outbounds:
        if "proxy" in proxy.get("tag", ""):
            proxy["tag"] = f"proxy{i}"
            proxies.append(proxy)

# Final output
final_config = build_config_json_from_proxies("🤰 Mother of Configs", proxies)
with open("config.json", 'w', encoding='utf-8') as f:
    json.dump(final_config, f, ensure_ascii=False, indent=2)
    print(f"Final merged config written to config.json")
