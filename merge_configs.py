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
                return json.load(f)
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
        raise ValueError(f"Unsupported data type in {folder}: {type(data)}")

# Save the merged list
with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
    json.dump(merged_list, f, ensure_ascii=False, indent=2)
    print(f"Merged config written to {OUTPUT_FILE}")

i = 0
proxies = []
for config in merged_list:
    i+=1
    for proxy in config["outbounds"]:
        if "proxy" in proxy["tag"]:
            proxy["tag"] = f"proxy{i}"
            proxies.append(proxy)

with open("config.json", 'w', encoding='utf-8') as f:
    json.dump(build_config_json_from_proxies("🤰 Mother of Configs", proxies), f, ensure_ascii=False, indent=2)
    print(f"Merged config written to config.json")