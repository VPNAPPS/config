"""Merge the per-source configs into the final config.json / configs.json.

Each source folder (see ``SOURCE_FOLDERS``) produces a list of "config" objects
(one per country) whose ``outbounds`` hold the proxy entries. This script:

  1. loads every source folder,
  2. merges configs that share the same remarks so each country appears once,
  3. builds a single "Fastest Location" config containing every proxy, and
  4. writes ``config.json`` (just the fastest config) and ``configs.json``
     (the fastest config followed by all per-country configs).
"""

import json
import copy
from pathlib import Path
from collections import defaultdict

from create_configs_json import build_config_json_from_proxies

SOURCE_FOLDERS = ["freesub", "ala"]
CANDIDATE_FILES = ["configs.json", "config.json"]

FASTEST_REMARKS = "⚡️ Fastest Location"
FASTEST_CONFIG_FILE = "config.json"
ALL_CONFIGS_FILE = "configs.json"

# The Android client passes the chosen config to its VPN service through a Binder
# transaction, which has a hard ~1 MB limit (TransactionTooLargeException). Each
# proxy is ~900 bytes once parceled, so we cap every config's proxy count to keep
# it well under that limit. 450 still gives the leastPing balancer plenty to pick
# from while leaving a wide safety margin (~400 KB parceled).
MAX_PROXIES_PER_CONFIG = 450

# Ad-network settings attached to the fastest config (timeouts are in ms).
ADS_CONFIG = {
    "inter_bitcoin": None,
    "native_bitcoin": None,
    "bitcoin_ratio": 0.5,
    "bitcoin_maxretry": 2,
    "bitcoin": {
        "maxretry": 3,
        "mustwatch": False,
        "inter": None,
        "native": None,
        "ratio": 0.5,
        "timeout": 90000,
    },
    "zorp": {
        "maxretry": 3,
        "mustwatch": False,
        "inter": None,
        "native": None,
        "ratio": 0.5,
        "timeout": 90000,
    },
    "yellow": {
        "maxretry": 3,
        "mustwatch": False,
        "inter": None,
        "native": None,
        "ratio": 0.5,
        "timeout": 90000,
    },
    "foxray": {
        "maxretry": 3,
        "mustwatch": False,
        "inter": None,
        "native": None,
        "ratio": 0.5,
        "timeout": 90000,
    },
    "foxray_ratio": 0.5,
    "foxray_maxretry": 2,
    "inter_foxray": None,
    "native_foxray": None,
}


def is_proxy(outbound):
    """Whether an outbound is a proxy (vs. a static one like direct/block)."""
    return "proxy" in outbound.get("tag", "")


def load_source(folder):
    """Load the first available config file from a source folder."""
    for filename in CANDIDATE_FILES:
        path = Path(folder) / filename
        if path.exists():
            print(f"Loading: {path}")
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except json.JSONDecodeError as e:
                print(f"Invalid JSON in {path}: {e}")
                return None
    print(f"No config file found in {folder}")
    return None


def load_all_sources(folders):
    """Load and flatten the configs from every source folder."""
    configs = []
    for folder in folders:
        data = load_source(folder)
        if data is None:
            continue
        if isinstance(data, list):
            configs.extend(data)
        elif isinstance(data, dict):
            configs.append(data)
        else:
            print(f"Unsupported data type in {folder}: {type(data)}")
    return configs


def merge_by_remarks(configs):
    """Merge configs that share the same remarks, combining their proxies."""
    if len(SOURCE_FOLDERS) <= 1:
        # Nothing to cross-merge with a single source.
        return configs

    grouped = defaultdict(list)
    for config in configs:
        grouped[config.get("remarks", "no_remarks")].append(config)

    merged = []
    for remarks, group in grouped.items():
        if len(group) == 1:
            merged.append(group[0])
            continue

        print(f"Merging {len(group)} configs with remarks: {remarks}")
        base = copy.deepcopy(group[0])

        # Split the base config's outbounds, then add every other config's proxies.
        proxies = []
        base_outbounds = []
        for outbound in base.get("outbounds", []):
            (proxies if is_proxy(outbound) else base_outbounds).append(outbound)
        for config in group[1:]:
            proxies.extend(ob for ob in config.get("outbounds", []) if is_proxy(ob))

        # Renumber the collected proxies (as copies) to avoid tag collisions.
        proxies = [copy.deepcopy(p) for p in proxies]
        for i, proxy in enumerate(proxies, 1):
            proxy["tag"] = f"proxy{i}"

        # Keep the original "proxy" first, then the renumbered set, then statics.
        original_proxy = next(
            (ob for ob in base.get("outbounds", []) if ob.get("tag") == "proxy"),
            None,
        )
        base["outbounds"] = (
            ([original_proxy] if original_proxy else []) + proxies + base_outbounds
        )
        merged.append(base)

    return merged


def collect_all_proxies(configs):
    """Gather the unique proxies across all configs (as tagless copies)."""
    all_outbounds = []
    for config in configs:
        outbounds = config.get("outbounds")
        if not outbounds:
            print("Warning: config has no 'outbounds'. Skipping.")
            continue
        all_outbounds.extend(outbounds)
    return dedupe_proxies(all_outbounds)


def dedupe_proxies(outbounds):
    """Return unique proxy outbounds as tagless copies, preserving order.

    Proxies are compared by their definition (ignoring the ``tag``, which we
    assign ourselves), since the per-source fan-out produces many exact dupes.
    """
    unique = []
    seen = set()
    for outbound in outbounds:
        if not is_proxy(outbound):
            continue
        proxy = copy.deepcopy(outbound)
        proxy.pop("tag", None)
        fingerprint = json.dumps(proxy, sort_keys=True, ensure_ascii=False)
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        unique.append(proxy)
    return unique


def cap_and_number(proxies):
    """Cap to MAX_PROXIES_PER_CONFIG and assign proxy1/proxy2/... tags in place.

    The template's balancer selector (``["proxy"]``) is a prefix match and its
    ``fallbackTag`` is ``proxy1``, so 1-based ``proxyN`` tags are what's expected.
    """
    proxies = proxies[:MAX_PROXIES_PER_CONFIG]
    for i, proxy in enumerate(proxies, 1):
        proxy["tag"] = f"proxy{i}"
    return proxies


def cap_config_proxies(config):
    """De-duplicate and cap a single config's proxies in place."""
    outbounds = config.get("outbounds")
    if not outbounds:
        return config
    proxies = cap_and_number(dedupe_proxies(outbounds))
    others = [ob for ob in outbounds if not is_proxy(ob)]
    config["outbounds"] = proxies + others
    return config


def write_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def main():
    configs = load_all_sources(SOURCE_FOLDERS)
    configs = merge_by_remarks(configs)

    # Build the Fastest Location config from the full de-duplicated proxy pool.
    fastest_proxies = collect_all_proxies(configs)
    total_unique = len(fastest_proxies)
    fastest_proxies = cap_and_number(fastest_proxies)
    if total_unique > MAX_PROXIES_PER_CONFIG:
        print(
            f"Capping fastest-location proxies from {total_unique} to "
            f"{MAX_PROXIES_PER_CONFIG} to stay under the Android Binder size limit"
        )
    fastest_config = build_config_json_from_proxies(FASTEST_REMARKS, fastest_proxies)
    fastest_config["ads"] = ADS_CONFIG

    # De-duplicate + cap every per-country config so none can exceed the limit.
    for config in configs:
        cap_config_proxies(config)

    configs.insert(0, fastest_config)

    write_json(FASTEST_CONFIG_FILE, fastest_config)
    print(f"Final merged config written to {FASTEST_CONFIG_FILE}")

    write_json(ALL_CONFIGS_FILE, configs)
    print(f"Merged config written to {ALL_CONFIGS_FILE}")
    print(f"Total configs after merging: {len(configs)}")


if __name__ == "__main__":
    main()
