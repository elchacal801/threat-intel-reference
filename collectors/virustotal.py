"""Enricher for VirusTotal — per-hash lookup with rate limiting and state tracking."""

import csv
import os
import time
from datetime import datetime, timezone

from collectors.base import BaseCollector

API_URL = "https://www.virustotal.com/api/v3/files"
ENV_VAR = "VT_API_KEY"


class VirusTotalEnricher(BaseCollector):
    batch_size = 125  # 500/day / 4 runs

    @property
    def source_name(self):
        return "vt_enrichment"

    @property
    def fieldnames(self):
        return [
            "sha256", "vt_classification", "vt_detection_rate",
            "vt_family", "vt_tags", "enriched_date",
        ]

    def _load_enriched_hashes(self):
        """Load set of already-enriched hashes from state file."""
        state_path = os.path.join(self.output_dir, "vt_enriched_hashes.txt")
        hashes = set()
        if os.path.exists(state_path):
            with open(state_path, encoding="utf-8") as f:
                for line in f:
                    h = line.strip()
                    if h:
                        hashes.add(h)
        return hashes

    def _save_enriched_hash(self, sha256):
        """Append a hash to the state file."""
        state_path = os.path.join(self.output_dir, "vt_enriched_hashes.txt")
        with open(state_path, "a", encoding="utf-8") as f:
            f.write(sha256 + "\n")

    def _load_existing_rows(self):
        """Load existing enrichment results."""
        path = os.path.join(self.output_dir, f"{self.source_name}.csv")
        if not os.path.exists(path):
            return []
        with open(path, newline="", encoding="utf-8") as f:
            return list(csv.DictReader(f))

    def _get_hashes_to_enrich(self):
        """Get priority-ordered list of hashes needing enrichment."""
        enriched = self._load_enriched_hashes()
        mb_path = os.path.join(self.output_dir, "malwarebazaar.csv")
        if not os.path.exists(mb_path):
            return []

        unattributed = []
        no_signal = []
        rest = []

        with open(mb_path, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                sha256 = row.get("sha256", "").strip()
                if not sha256 or sha256 in enriched:
                    continue
                family = row.get("family", "").strip()
                clamav = row.get("clamav_detection", "").strip()
                tags = row.get("tags", "").strip()

                if not family:
                    unattributed.append(sha256)
                elif not clamav and not tags:
                    no_signal.append(sha256)
                else:
                    rest.append(sha256)

        return unattributed + no_signal + rest

    def _lookup_hash(self, sha256):
        """Look up a single hash on VirusTotal."""
        resp = self.session.get(f"{API_URL}/{sha256}", timeout=30)
        resp.raise_for_status()
        data = resp.json().get("data", {}).get("attributes", {})

        stats = data.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total = sum(stats.values())

        ptc = data.get("popular_threat_classification", {})
        categories = ptc.get("popular_threat_category", [])
        names = ptc.get("popular_threat_name", [])
        tags = data.get("tags", [])

        return {
            "sha256": sha256,
            "vt_classification": categories[0].get("value", "") if categories else "",
            "vt_detection_rate": f"{malicious}/{total}" if total else "",
            "vt_family": names[0].get("value", "") if names else "",
            "vt_tags": "|".join(tags) if isinstance(tags, list) else "",
            "enriched_date": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }

    def collect(self):
        api_key = self.get_api_key(ENV_VAR)
        self.session.headers["x-apikey"] = api_key

        all_rows = self._load_existing_rows()
        hashes = self._get_hashes_to_enrich()

        batch = hashes[:self.batch_size]
        print(f"    VT enrichment: {len(batch)} hashes this batch ({len(hashes)} total remaining)")

        for i, sha256 in enumerate(batch):
            try:
                row = self._lookup_hash(sha256)
                all_rows.append(row)
                self._save_enriched_hash(sha256)
                print(f"    [{i+1}/{len(batch)}] {sha256[:16]}... -> {row['vt_family'] or 'unknown'}")
            except Exception as e:
                print(f"    [{i+1}/{len(batch)}] {sha256[:16]}... FAILED: {e}")
            time.sleep(2)

        return all_rows
