#!/usr/bin/env python3
"""CLI entry point: run collectors and normalizer."""

import argparse
import sys
import os

def main():
    parser = argparse.ArgumentParser(description="Threat Intel Reference Pipeline")
    parser.add_argument(
        "--collector",
        choices=["malwarebazaar", "threatfox", "yaraify", "mitre_attack", "misp_galaxy", "all"],
        default="all",
        help="Run a specific collector or all (default: all)",
    )
    parser.add_argument("--skip-normalize", action="store_true", help="Skip normalization step")
    args = parser.parse_args()

    data_dir = os.path.join(os.path.dirname(__file__), "data")
    raw_dir = os.path.join(data_dir, "raw")
    normalized_dir = os.path.join(data_dir, "normalized")
    os.makedirs(raw_dir, exist_ok=True)
    os.makedirs(normalized_dir, exist_ok=True)

    collectors_to_run = []
    if args.collector == "all":
        collectors_to_run = ["malwarebazaar", "threatfox", "yaraify", "mitre_attack", "misp_galaxy"]
    else:
        collectors_to_run = [args.collector]

    from collectors.malwarebazaar import MalwareBazaarCollector
    from collectors.threatfox import ThreatFoxCollector
    from collectors.yaraify import YARAifyCollector
    from collectors.mitre_attack import MitreAttackCollector
    from collectors.misp_galaxy import MispGalaxyCollector

    collector_map = {
        "malwarebazaar": MalwareBazaarCollector,
        "threatfox": ThreatFoxCollector,
        "yaraify": YARAifyCollector,
        "mitre_attack": MitreAttackCollector,
        "misp_galaxy": MispGalaxyCollector,
    }

    failed = []
    for name in collectors_to_run:
        print(f"[*] Running collector: {name}")
        try:
            collector = collector_map[name](raw_dir)
            collector.run()
            print(f"[+] {name} completed successfully")
        except Exception as e:
            print(f"[-] {name} failed: {e}", file=sys.stderr)
            failed.append(name)

    if not args.skip_normalize:
        print("[*] Running normalizer")
        from normalizer.normalize import Normalizer
        normalizer = Normalizer(raw_dir, normalized_dir)
        normalizer.run()
        print("[+] Normalization complete")

    if failed:
        print(f"\n[!] Failed collectors: {', '.join(failed)}", file=sys.stderr)
        # Don't exit 1 — partial data is still valuable


if __name__ == "__main__":
    main()
