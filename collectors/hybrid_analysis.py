"""Enricher for Hybrid Analysis — detonation feed + per-hash behavioral data."""

import csv
import os
import time

from collectors.base import BaseCollector

FEED_URL = "https://www.hybrid-analysis.com/api/v2/feed/detonation"
SEARCH_URL = "https://www.hybrid-analysis.com/api/v2/search/hash"
ENV_VAR = "HYBRID_ANALYSIS_API_KEY"


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
        """Load hashes from previous run to avoid re-querying."""
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

    def collect(self):
        api_key = self.get_api_key(ENV_VAR)
        self.session.headers["api-key"] = api_key
        self.session.headers["User-Agent"] = "Falcon Sandbox"

        seen = self._load_existing_hashes()
        all_rows = self._load_existing_rows()

        # 1. Detonation feed (latest 250, free)
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

        print(f"    Total HA entries: {len(all_rows)}")
        return all_rows
