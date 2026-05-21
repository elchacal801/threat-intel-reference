#!/usr/bin/env python3
"""CLI entry point: run collectors, enrichers, and normalizer."""

import argparse
import sys
import os

ALL_COLLECTORS = ["malwarebazaar", "threatfox", "yaraify", "mitre_attack", "misp_galaxy", "urlhaus", "otx"]
ALL_ENRICHERS = ["hybrid_analysis", "virustotal"]


def main():
    parser = argparse.ArgumentParser(description="Threat Intel Reference Pipeline")
    parser.add_argument(
        "--collector",
        choices=ALL_COLLECTORS + ["all"],
        default=None,
        help="Run a specific collector or all",
    )
    parser.add_argument(
        "--enricher",
        choices=ALL_ENRICHERS + ["all"],
        default=None,
        help="Run a specific enricher or all",
    )
    parser.add_argument("--skip-normalize", action="store_true", help="Skip normalization step")
    args = parser.parse_args()

    # Default: run all collectors if neither --collector nor --enricher specified
    if not args.collector and not args.enricher:
        args.collector = "all"

    data_dir = os.path.join(os.path.dirname(__file__), "data")
    raw_dir = os.path.join(data_dir, "raw")
    normalized_dir = os.path.join(data_dir, "normalized")
    os.makedirs(raw_dir, exist_ok=True)
    os.makedirs(normalized_dir, exist_ok=True)

    from collectors.malwarebazaar import MalwareBazaarCollector
    from collectors.threatfox import ThreatFoxCollector
    from collectors.yaraify import YARAifyCollector
    from collectors.mitre_attack import MitreAttackCollector
    from collectors.misp_galaxy import MispGalaxyCollector
    from collectors.urlhaus import URLhausCollector
    from collectors.otx import OTXCollector
    from collectors.hybrid_analysis import HybridAnalysisEnricher
    from collectors.virustotal import VirusTotalEnricher

    collector_map = {
        "malwarebazaar": MalwareBazaarCollector,
        "threatfox": ThreatFoxCollector,
        "yaraify": YARAifyCollector,
        "mitre_attack": MitreAttackCollector,
        "misp_galaxy": MispGalaxyCollector,
        "urlhaus": URLhausCollector,
        "otx": OTXCollector,
    }

    enricher_map = {
        "hybrid_analysis": HybridAnalysisEnricher,
        "virustotal": VirusTotalEnricher,
    }

    failed = []

    # Run collectors
    if args.collector:
        collectors_to_run = ALL_COLLECTORS if args.collector == "all" else [args.collector]
        for name in collectors_to_run:
            print(f"[*] Running collector: {name}")
            try:
                collector = collector_map[name](raw_dir)
                collector.run()
                print(f"[+] {name} completed successfully")
            except Exception as e:
                print(f"[-] {name} failed: {e}", file=sys.stderr)
                failed.append(name)

    # Run enrichers
    if args.enricher:
        enrichers_to_run = ALL_ENRICHERS if args.enricher == "all" else [args.enricher]
        for name in enrichers_to_run:
            print(f"[*] Running enricher: {name}")
            try:
                enricher = enricher_map[name](raw_dir)
                enricher.run()
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
        print(f"\n[!] Failed: {', '.join(failed)}", file=sys.stderr)


if __name__ == "__main__":
    main()
