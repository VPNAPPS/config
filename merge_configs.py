import os
import json
from pathlib import Path
from collections import defaultdict
import copy
from create_configs_json import build_config_json_from_proxies

FOLDERS = ["freesub"]
OUTPUT_FILE = "configs.json"
CANDIDATE_FILES = ["configs.json", "config.json"]

merged_list = []


def load_json_from_folder(folder: str):
    for filename in CANDIDATE_FILES:
        path = Path(folder) / filename
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                print(f"Loading: {path}")
                try:
                    return json.load(f)
                except json.JSONDecodeError as e:
                    print(f"Invalid JSON in {path}: {e}")
                    return None
    print(f"No config file found in {folder}")
    return None


def merge_configs_by_remarks(configs_list):
    """
    Merge configs with the same remarks, combining their proxy outbounds.
    """
    if len(FOLDERS) <= 1:
        # If only one folder or less, return configs as-is
        return configs_list

    # Group configs by remarks
    grouped_by_remarks = defaultdict(list)

    for config in configs_list:
        remarks = config.get("remarks", "no_remarks")
        grouped_by_remarks[remarks].append(config)

    merged_configs = []

    for remarks, config_group in grouped_by_remarks.items():
        if len(config_group) == 1:
            # Only one config with this remark, use as-is
            merged_configs.append(config_group[0])
        else:
            # Multiple configs with same remarks, merge their outbounds
            print(f"Merging {len(config_group)} configs with remarks: {remarks}")

            # Use the first config as base
            merged_config = copy.deepcopy(config_group[0])

            # Collect all proxy outbounds from all configs with this remark
            all_proxies = []
            base_outbounds = []

            # Get base outbounds (non-proxy) from the first config
            if "outbounds" in merged_config:
                for outbound in merged_config["outbounds"]:
                    if "proxy" not in outbound.get("tag", ""):
                        base_outbounds.append(outbound)
                    else:
                        all_proxies.append(outbound)

            # Collect proxies from other configs with same remarks
            for config in config_group[1:]:
                if "outbounds" in config:
                    for outbound in config["outbounds"]:
                        if "proxy" in outbound.get("tag", ""):
                            all_proxies.append(outbound)

            # Renumber proxy tags to avoid conflicts
            for i, proxy in enumerate(all_proxies, 1):
                proxy_copy = copy.deepcopy(proxy)
                proxy_copy["tag"] = f"proxy{i}"
                all_proxies[i - 1] = proxy_copy

            # Reconstruct outbounds: keep original proxy first, then all collected proxies, then base outbounds
            new_outbounds = []

            # Add original proxy (if exists)
            original_proxy = next(
                (
                    ob
                    for ob in merged_config.get("outbounds", [])
                    if ob.get("tag") == "proxy"
                ),
                None,
            )
            if original_proxy:
                new_outbounds.append(original_proxy)

            # Add all renamed proxies
            new_outbounds.extend(all_proxies)

            # Add base outbounds
            new_outbounds.extend(base_outbounds)

            # Update the merged config
            merged_config["outbounds"] = new_outbounds

            merged_configs.append(merged_config)

    return merged_configs


# Load configs from all folders
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

# Merge configs by remarks if multiple folders
merged_list = merge_configs_by_remarks(merged_list)

# Build merged config from outbounds
i = 0
proxies = []
for config in merged_list:
    outbounds = config.get("outbounds")
    if not outbounds:
        print(f"Warning: config has no 'outbounds'. Skipping.")
        continue
    for proxy in outbounds:
        if "proxy" in proxy.get("tag", ""):
            i += 1
            proxy_copy = copy.deepcopy(proxy)
            proxy_copy["tag"] = f"proxy{i}"
            proxies.append(proxy_copy)

# Final output
final_config = build_config_json_from_proxies("⚡️ Fastest Location", proxies)
final_config["ads"] = {
    "inter_bitcoin": None,
    "native_bitcoin": None,
    "bitcoin_ratio": 0.2,
    "bitcoin_maxretry": 2,
    "bitcoin": {
        "maxretry": 3,
        "mustwatch": False,
        "inter": None,
        "native": None,
        "ratio": 0.2,
        "timeout": 50000,  # ms
    },
    "zorp": {
        "maxretry": 3,
        "mustwatch": False,
        "inter": None,
        "native": None,
        "ratio": 0.2,
        "timeout": 50000,  # ms
    },
    "yellow": {
        "maxretry": 3,
        "mustwatch": False,
        "inter": None,
        "native": None,
        "ratio": 0.2,
        "timeout": 50000,  # ms
    },
    "foxray": {
        "maxretry": 3,
        "mustwatch": False,
        "inter": None,
        "native": None,
        "ratio": 0.2,
        "timeout": 50000,  # ms
    },
    "foxray_ratio": 0.2,
    "foxray_maxretry": 2,
    "inter_foxray": None,
    "native_foxray": None,
}
merged_list.insert(0, final_config)

with open("config.json", "w", encoding="utf-8") as f:
    json.dump(final_config, f, ensure_ascii=False, indent=2)
    print(f"Final merged config written to config.json")

# Save raw merged list for debugging
with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    json.dump(merged_list, f, ensure_ascii=False, indent=2)
    print(f"Merged config written to {OUTPUT_FILE}")
    print(f"Total configs after merging: {len(merged_list)}")
