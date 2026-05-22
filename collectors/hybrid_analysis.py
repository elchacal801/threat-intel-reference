"""Enricher for Hybrid Analysis — detonation feed + per-hash behavioral data.

Two phases:
1. Fetch latest 250 from detonation feed (discover new hashes)
2. Per-hash enrichment via POST /search/hash (get behavioral data: domains, IPs, family)
"""

import csv
import os
import time

from collectors.base import BaseCollector

FEED_URL = "https://www.hybrid-analysis.com/api/v2/feed/detonation"
SEARCH_URL = "https://www.hybrid-analysis.com/api/v2/search/hash"
ENV_VAR = "HYBRID_ANALYSIS_API_KEY"
ENRICH_BATCH_SIZE = 100


class HybridAnalysisEnricher(BaseCollector):
    @property
    def source_name(self):
        return "hybrid_analysis"

    @property
    def fieldnames(self):
        return [
            "sha256", "verdict", "vx_family", "av_detect_pct",
            "contacted_domains", "contacted_ips", "analysis_date",
        ]

    def _load_existing_hashes(self):
        """Load hashes from previous run to avoid re-adding from feed."""
        path = os.path.join(self.output_dir, f"{self.source_name}.csv")
        hashes = set()
        if os.path.exists(path):
            with open(path, newline="", encoding="utf-8") as f:
                for row in csv.DictReader(f):
                    h = row.get("sha256", "").strip()
                    if h:
                        hashes.add(h)
        return hashes

    def _load_existing_rows(self):
        """Load existing rows to preserve them."""
        path = os.path.join(self.output_dir, f"{self.source_name}.csv")
        if not os.path.exists(path):
            return []
        with open(path, newline="", encoding="utf-8") as f:
            return list(csv.DictReader(f))

    def _load_enriched_hashes(self):
        """Load set of hashes already enriched via per-hash lookup."""
        state_path = os.path.join(self.output_dir, "ha_enriched_hashes.txt")
        hashes = set()
        if os.path.exists(state_path):
            with open(state_path, encoding="utf-8") as f:
                for line in f:
                    h = line.strip()
                    if h:
                        hashes.add(h)
        return hashes

    def _save_enriched_hash(self, sha256):
        """Append a hash to the enrichment state file."""
        state_path = os.path.join(self.output_dir, "ha_enriched_hashes.txt")
        with open(state_path, "a", encoding="utf-8") as f:
            f.write(sha256 + "\n")

    def _parse_entry(self, entry):
        """Parse a feed or search result into a row dict."""
        domains = entry.get("domains", []) or []
        hosts = entry.get("hosts", []) or []
        av_detect = entry.get("av_detect", "")
        if isinstance(av_detect, str):
            av_detect = av_detect.rstrip("%")
        return {
            "sha256": entry.get("sha256", ""),
            "verdict": entry.get("verdict", ""),
            "vx_family": entry.get("vx_family") or "",
            "av_detect_pct": av_detect,
            "contacted_domains": "|".join(domains[:20]) if isinstance(domains, list) else "",
            "contacted_ips": "|".join(hosts[:20]) if isinstance(hosts, list) else "",
            "analysis_date": entry.get("analysis_start_time", ""),
        }

    def _enrich_hash(self, sha256):
        """Call POST /search/hash for a single hash, return parsed row or None."""
        resp = self.session.post(SEARCH_URL, data={"hash": sha256}, timeout=30)
        resp.raise_for_status()
        results = resp.json()
        if not results:
            return None
        entry = results[0] if isinstance(results, list) else results
        return self._parse_entry(entry)

    def collect(self):
        api_key = self.get_api_key(ENV_VAR)
        self.session.headers["api-key"] = api_key
        self.session.headers["User-Agent"] = "Falcon Sandbox"

        seen = self._load_existing_hashes()
        all_rows = self._load_existing_rows()

        # Phase 1: Detonation feed (discover new hashes)
        print("    Fetching HA detonation feed...")
        try:
            resp = self.session.get(FEED_URL, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            entries = data.get("data", []) if isinstance(data, dict) else data
            for entry in entries:
                sha256 = entry.get("sha256", "")
                if sha256 and sha256 not in seen:
                    seen.add(sha256)
                    all_rows.append(self._parse_entry(entry))
        except Exception as e:
            print(f"    Feed fetch failed: {e}")

        # Phase 2: Per-hash enrichment for rows missing behavioral data
        enriched_set = self._load_enriched_hashes()
        to_enrich = [
            r["sha256"] for r in all_rows
            if r["sha256"] and r["sha256"] not in enriched_set
        ]
        batch = to_enrich[:ENRICH_BATCH_SIZE]
        print(f"    HA enrichment: {len(batch)} hashes this batch ({len(to_enrich)} remaining)")

        # Build index for in-place updates
        row_index = {r["sha256"]: r for r in all_rows}

        for i, sha256 in enumerate(batch):
            try:
                enriched = self._enrich_hash(sha256)
                if enriched:
                    existing = row_index.get(sha256)
                    if existing:
                        for key in ["vx_family", "av_detect_pct", "contacted_domains",
                                    "contacted_ips", "analysis_date"]:
                            if enriched.get(key):
                                existing[key] = enriched[key]
                self._save_enriched_hash(sha256)
                family = enriched.get("vx_family", "") if enriched else "no data"
                domains = enriched.get("contacted_domains", "") if enriched else ""
                print(f"    [{i+1}/{len(batch)}] {sha256[:16]}... -> {family} ({len(domains.split('|')) if domains else 0} domains)")
            except Exception as e:
                print(f"    [{i+1}/{len(batch)}] {sha256[:16]}... FAILED: {e}")
                if "429" in str(e) or "Too Many" in str(e):
                    print("    Rate limited, stopping enrichment early.")
                    break
            time.sleep(2)

        print(f"    Total HA entries: {len(all_rows)}")
        return all_rows
