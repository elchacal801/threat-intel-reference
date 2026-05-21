# V2: High-Impact Sources — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add 4 new threat intelligence sources (URLhaus, AlienVault OTX, Hybrid Analysis, VirusTotal) with behavioral hash→domain data and VT-based PUP/PUA classification.

**Architecture:** Two tiers — bulk collectors (URLhaus, OTX) join the daily pipeline; per-hash enrichers (HA, VT) run on a separate 6-hour cron with rate limiting and state tracking. Normalizer gains a new behavioral_indicators output and 4 new columns on malware_samples.

**Tech Stack:** Python 3.12, requests, GitHub Actions, existing BaseCollector pattern

---

## File Map

```
# New files
collectors/urlhaus.py            # URLhaus recent payloads + URLs
collectors/otx.py                # AlienVault OTX subscribed pulses
collectors/hybrid_analysis.py    # HA feed + per-hash behavioral lookup
collectors/virustotal.py         # VT per-hash enrichment with state tracking
tests/test_urlhaus.py
tests/test_otx.py
tests/test_hybrid_analysis.py
tests/test_virustotal.py
.github/workflows/enrichment.yml # 6-hour cron for enrichers

# Modified files
normalizer/classifier.py         # Add vt_classification parameter
normalizer/normalize.py          # Load enrichment data, new outputs, new sample columns
run_pipeline.py                  # Add new collectors + --enricher subcommand
.github/workflows/daily-update.yml  # Add URLhaus + OTX steps
```

---

### Task 1: URLhaus Collector

**Files:**
- Create: `collectors/urlhaus.py`
- Create: `tests/test_urlhaus.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_urlhaus.py`:

```python
import os
import csv
import tempfile
from unittest.mock import patch, MagicMock
import pytest
from collectors.urlhaus import URLhausCollector

SAMPLE_PAYLOADS_RESPONSE = {
    "query_status": "ok",
    "payloads": [
        {
            "sha256_hash": "a" * 64,
            "md5_hash": "b" * 32,
            "file_type": "exe",
            "signature": "Emotet",
            "firstseen": "2024-01-15",
            "urls": [
                {"url": "https://evil.com/malware.exe", "url_status": "online"},
                {"url": "https://bad.org/payload.bin", "url_status": "offline"},
            ],
        },
    ],
}

SAMPLE_URLS_RESPONSE = {
    "query_status": "ok",
    "urls": [
        {
            "url": "https://another.net/dropper.js",
            "host": "another.net",
            "url_status": "online",
            "threat": "malware_download",
            "tags": ["js", "dropper"],
            "dateadded": "2024-02-01",
            "payloads": [
                {
                    "sha256_hash": "c" * 64,
                    "md5_hash": "d" * 32,
                    "file_type": "js",
                    "signature": "SocGholish",
                },
            ],
        },
    ],
}


@patch("collectors.urlhaus.URLhausCollector.get_api_key", return_value="fake_key")
@patch("requests.Session.post")
@patch("requests.Session.get")
def test_collect_merges_payloads_and_urls(mock_get, mock_post, mock_key):
    mock_post_resp = MagicMock()
    mock_post_resp.status_code = 200
    mock_post_resp.json.return_value = SAMPLE_PAYLOADS_RESPONSE
    mock_post.return_value = mock_post_resp

    mock_get_resp = MagicMock()
    mock_get_resp.status_code = 200
    mock_get_resp.json.return_value = SAMPLE_URLS_RESPONSE
    mock_get.return_value = mock_get_resp

    with tempfile.TemporaryDirectory() as tmpdir:
        collector = URLhausCollector(tmpdir)
        rows = collector.collect()

    # Payload entry produces 2 rows (2 URLs for same hash)
    # URL entry produces 1 row
    assert len(rows) >= 3
    hashes = [r["sha256"] for r in rows]
    assert "a" * 64 in hashes
    assert "c" * 64 in hashes
    emotet_rows = [r for r in rows if r["sha256"] == "a" * 64]
    assert emotet_rows[0]["signature"] == "Emotet"
    assert "evil.com" in emotet_rows[0]["host"]


@patch("collectors.urlhaus.URLhausCollector.get_api_key", return_value="fake_key")
@patch("requests.Session.post")
@patch("requests.Session.get")
def test_run_writes_csv(mock_get, mock_post, mock_key):
    mock_post_resp = MagicMock()
    mock_post_resp.status_code = 200
    mock_post_resp.json.return_value = SAMPLE_PAYLOADS_RESPONSE
    mock_post.return_value = mock_post_resp

    mock_get_resp = MagicMock()
    mock_get_resp.status_code = 200
    mock_get_resp.json.return_value = SAMPLE_URLS_RESPONSE
    mock_get.return_value = mock_get_resp

    with tempfile.TemporaryDirectory() as tmpdir:
        collector = URLhausCollector(tmpdir)
        collector.run()
        path = os.path.join(tmpdir, "urlhaus.csv")
        assert os.path.exists(path)
        with open(path, newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        assert len(rows) >= 3
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_urlhaus.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Write the implementation**

Create `collectors/urlhaus.py`:

```python
"""Collector for URLhaus (abuse.ch) — payload hashes linked to malicious URLs."""

from urllib.parse import urlparse

from collectors.base import BaseCollector

PAYLOADS_URL = "https://urlhaus-api.abuse.ch/v1/payloads/recent/"
URLS_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
ENV_VAR = "URLHAUS_API_KEY"


class URLhausCollector(BaseCollector):
    @property
    def source_name(self):
        return "urlhaus"

    @property
    def fieldnames(self):
        return [
            "sha256", "md5", "url", "host", "url_status",
            "file_type", "signature", "tags", "first_seen",
        ]

    def _extract_host(self, url):
        """Extract hostname from a URL."""
        try:
            return urlparse(url).hostname or ""
        except Exception:
            return ""

    def collect(self):
        api_key = self.get_api_key(ENV_VAR)
        self.session.headers["Auth-Key"] = api_key

        seen = set()  # (sha256, url) pairs for dedup
        rows = []

        # 1. Recent payloads with linked URLs
        print("    Fetching recent payloads...")
        try:
            resp = self.session.post(PAYLOADS_URL, data={"limit": 1000}, timeout=60)
            resp.raise_for_status()
            result = resp.json()
            for payload in result.get("payloads", []):
                sha256 = payload.get("sha256_hash", "")
                md5 = payload.get("md5_hash", "")
                for url_entry in payload.get("urls", []):
                    url = url_entry.get("url", "")
                    key = (sha256, url)
                    if key in seen:
                        continue
                    seen.add(key)
                    rows.append({
                        "sha256": sha256,
                        "md5": md5,
                        "url": url,
                        "host": self._extract_host(url),
                        "url_status": url_entry.get("url_status", ""),
                        "file_type": payload.get("file_type", ""),
                        "signature": payload.get("signature") or "",
                        "tags": "",
                        "first_seen": payload.get("firstseen", ""),
                    })
        except Exception as e:
            print(f"    Payloads fetch failed: {e}")

        # 2. Recent URLs with payload hashes
        print("    Fetching recent URLs...")
        try:
            resp = self.session.get(URLS_URL, params={"limit": 1000}, timeout=60)
            resp.raise_for_status()
            result = resp.json()
            for url_entry in result.get("urls", []):
                url = url_entry.get("url", "")
                host = url_entry.get("host", "") or self._extract_host(url)
                tags_list = url_entry.get("tags") or []
                tags = "|".join(tags_list) if isinstance(tags_list, list) else str(tags_list)
                for payload in url_entry.get("payloads", []):
                    sha256 = payload.get("sha256_hash", "")
                    key = (sha256, url)
                    if key in seen:
                        continue
                    seen.add(key)
                    rows.append({
                        "sha256": sha256,
                        "md5": payload.get("md5_hash", ""),
                        "url": url,
                        "host": host,
                        "url_status": url_entry.get("url_status", ""),
                        "file_type": payload.get("file_type", ""),
                        "signature": payload.get("signature") or "",
                        "tags": tags,
                        "first_seen": url_entry.get("dateadded", ""),
                    })
        except Exception as e:
            print(f"    URLs fetch failed: {e}")

        print(f"    Total URL-hash pairs: {len(rows)}")
        return rows
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_urlhaus.py -v`
Expected: 2 passed

- [ ] **Step 5: Commit**

```bash
git add collectors/urlhaus.py tests/test_urlhaus.py
git commit -m "feat: add URLhaus collector with payload-URL hash linkage"
```

---

### Task 2: AlienVault OTX Collector

**Files:**
- Create: `collectors/otx.py`
- Create: `tests/test_otx.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_otx.py`:

```python
import os
import csv
import tempfile
from unittest.mock import patch, MagicMock
import pytest
from collectors.otx import OTXCollector

SAMPLE_PULSES_RESPONSE = {
    "results": [
        {
            "id": "pulse-001",
            "name": "Emotet Campaign 2024",
            "created": "2024-01-15T12:00:00",
            "tags": ["emotet", "banking"],
            "malware_families": [{"display_name": "Emotet"}],
            "indicators": [
                {"type": "FileHash-SHA256", "indicator": "a" * 64},
                {"type": "domain", "indicator": "evil.example.com"},
                {"type": "IPv4", "indicator": "1.2.3.4"},
                {"type": "email", "indicator": "skip@this.com"},
            ],
        },
    ],
    "next": None,
}


@patch("collectors.otx.OTXCollector.get_api_key", return_value="fake_key")
@patch("requests.Session.get")
def test_collect_extracts_relevant_indicators(mock_get, mock_key):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = SAMPLE_PULSES_RESPONSE
    mock_get.return_value = mock_resp

    with tempfile.TemporaryDirectory() as tmpdir:
        collector = OTXCollector(tmpdir)
        rows = collector.collect()

    # Should have 3 rows (email type is filtered out)
    assert len(rows) == 3
    types = [r["ioc_type"] for r in rows]
    assert "FileHash-SHA256" in types
    assert "domain" in types
    assert "IPv4" in types
    assert "email" not in types
    assert rows[0]["family"] == "Emotet"
    assert rows[0]["pulse_name"] == "Emotet Campaign 2024"


@patch("collectors.otx.OTXCollector.get_api_key", return_value="fake_key")
@patch("requests.Session.get")
def test_run_writes_csv(mock_get, mock_key):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = SAMPLE_PULSES_RESPONSE
    mock_get.return_value = mock_resp

    with tempfile.TemporaryDirectory() as tmpdir:
        collector = OTXCollector(tmpdir)
        collector.run()
        path = os.path.join(tmpdir, "otx_pulses.csv")
        assert os.path.exists(path)
        with open(path, newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        assert len(rows) == 3
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_otx.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Write the implementation**

Create `collectors/otx.py`:

```python
"""Collector for AlienVault OTX — subscribed pulse indicators."""

from collectors.base import BaseCollector

API_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"
ENV_VAR = "OTX_API_KEY"

RELEVANT_TYPES = {"FileHash-SHA256", "FileHash-MD5", "IPv4", "domain", "URL", "hostname"}


class OTXCollector(BaseCollector):
    @property
    def source_name(self):
        return "otx_pulses"

    @property
    def fieldnames(self):
        return [
            "ioc_type", "ioc_value", "family", "pulse_name",
            "pulse_id", "created", "tags",
        ]

    def collect(self):
        api_key = self.get_api_key(ENV_VAR)
        self.session.headers["X-OTX-API-KEY"] = api_key

        rows = []
        page = 1
        max_pages = 20  # Safety limit

        while page <= max_pages:
            print(f"    Fetching OTX pulses page {page}...")
            try:
                resp = self.session.get(
                    API_URL,
                    params={"limit": 50, "page": page},
                    timeout=30,
                )
                resp.raise_for_status()
                data = resp.json()
            except Exception as e:
                print(f"    OTX page {page} failed: {e}")
                break

            pulses = data.get("results", [])
            if not pulses:
                break

            for pulse in pulses:
                pulse_id = pulse.get("id", "")
                pulse_name = pulse.get("name", "")
                created = pulse.get("created", "")
                tags_list = pulse.get("tags", [])
                tags = "|".join(tags_list) if isinstance(tags_list, list) else ""

                families = pulse.get("malware_families", [])
                family = families[0].get("display_name", "") if families else ""

                for indicator in pulse.get("indicators", []):
                    ioc_type = indicator.get("type", "")
                    if ioc_type not in RELEVANT_TYPES:
                        continue
                    rows.append({
                        "ioc_type": ioc_type,
                        "ioc_value": indicator.get("indicator", ""),
                        "family": family,
                        "pulse_name": pulse_name,
                        "pulse_id": pulse_id,
                        "created": created,
                        "tags": tags,
                    })

            if not data.get("next"):
                break
            page += 1

        print(f"    Total OTX indicators: {len(rows)}")
        return rows
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_otx.py -v`
Expected: 2 passed

- [ ] **Step 5: Commit**

```bash
git add collectors/otx.py tests/test_otx.py
git commit -m "feat: add AlienVault OTX collector with pulse indicators"
```

---

### Task 3: Hybrid Analysis Enricher

**Files:**
- Create: `collectors/hybrid_analysis.py`
- Create: `tests/test_hybrid_analysis.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_hybrid_analysis.py`:

```python
import os
import csv
import tempfile
from unittest.mock import patch, MagicMock
import pytest
from collectors.hybrid_analysis import HybridAnalysisEnricher

SAMPLE_FEED_RESPONSE = {
    "data": [
        {
            "sha256": "a" * 64,
            "verdict": "malicious",
            "vx_family": "Emotet",
            "av_detect": "75%",
            "analysis_start_time": "2024-01-15T10:00:00",
        },
    ],
}

SAMPLE_SEARCH_RESPONSE = [
    {
        "sha256": "b" * 64,
        "verdict": "malicious",
        "vx_family": "AgentTesla",
        "av_detect": "60%",
        "analysis_start_time": "2024-02-01T10:00:00",
        "domains": ["c2.evil.com", "exfil.bad.org"],
        "hosts": ["1.2.3.4", "5.6.7.8"],
    },
]


@patch("collectors.hybrid_analysis.HybridAnalysisEnricher.get_api_key", return_value="fake_key")
@patch("requests.Session.get")
def test_collect_from_feed(mock_get, mock_key):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = SAMPLE_FEED_RESPONSE
    mock_resp.headers = {"Api-Limits": "100"}
    mock_get.return_value = mock_resp

    with tempfile.TemporaryDirectory() as tmpdir:
        enricher = HybridAnalysisEnricher(tmpdir)
        rows = enricher.collect()

    assert len(rows) >= 1
    assert rows[0]["sha256"] == "a" * 64
    assert rows[0]["vx_family"] == "Emotet"


@patch("collectors.hybrid_analysis.HybridAnalysisEnricher.get_api_key", return_value="fake_key")
@patch("requests.Session.get")
def test_run_writes_csv(mock_get, mock_key):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = SAMPLE_FEED_RESPONSE
    mock_resp.headers = {"Api-Limits": "100"}
    mock_get.return_value = mock_resp

    with tempfile.TemporaryDirectory() as tmpdir:
        enricher = HybridAnalysisEnricher(tmpdir)
        enricher.run()
        path = os.path.join(tmpdir, "hybrid_analysis.csv")
        assert os.path.exists(path)
        with open(path, newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        assert len(rows) >= 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_hybrid_analysis.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Write the implementation**

Create `collectors/hybrid_analysis.py`:

```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_hybrid_analysis.py -v`
Expected: 2 passed

- [ ] **Step 5: Commit**

```bash
git add collectors/hybrid_analysis.py tests/test_hybrid_analysis.py
git commit -m "feat: add Hybrid Analysis enricher with detonation feed"
```

---

### Task 4: VirusTotal Enricher

**Files:**
- Create: `collectors/virustotal.py`
- Create: `tests/test_virustotal.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_virustotal.py`:

```python
import os
import csv
import tempfile
from unittest.mock import patch, MagicMock
import pytest
from collectors.virustotal import VirusTotalEnricher

SAMPLE_VT_RESPONSE = {
    "data": {
        "attributes": {
            "sha256": "a" * 64,
            "last_analysis_stats": {"malicious": 45, "undetected": 27},
            "popular_threat_classification": {
                "suggested_threat_label": "trojan.emotet/heodo",
                "popular_threat_category": [{"value": "trojan"}],
                "popular_threat_name": [{"value": "emotet"}],
            },
            "tags": ["pe", "trojan"],
        },
    },
}


@patch("collectors.virustotal.VirusTotalEnricher.get_api_key", return_value="fake_key")
@patch("collectors.virustotal.VirusTotalEnricher._get_hashes_to_enrich")
@patch("requests.Session.get")
def test_collect_enriches_hash(mock_get, mock_hashes, mock_key):
    mock_hashes.return_value = ["a" * 64]

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = SAMPLE_VT_RESPONSE
    mock_get.return_value = mock_resp

    with tempfile.TemporaryDirectory() as tmpdir:
        enricher = VirusTotalEnricher(tmpdir)
        enricher.batch_size = 1
        rows = enricher.collect()

    assert len(rows) == 1
    assert rows[0]["sha256"] == "a" * 64
    assert rows[0]["vt_family"] == "emotet"
    assert rows[0]["vt_detection_rate"] == "45/72"
    assert rows[0]["vt_classification"] == "trojan"


@patch("collectors.virustotal.VirusTotalEnricher.get_api_key", return_value="fake_key")
@patch("collectors.virustotal.VirusTotalEnricher._get_hashes_to_enrich")
@patch("requests.Session.get")
def test_run_writes_csv_and_state(mock_get, mock_hashes, mock_key):
    mock_hashes.return_value = ["a" * 64]

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = SAMPLE_VT_RESPONSE
    mock_get.return_value = mock_resp

    with tempfile.TemporaryDirectory() as tmpdir:
        enricher = VirusTotalEnricher(tmpdir)
        enricher.batch_size = 1
        enricher.run()

        csv_path = os.path.join(tmpdir, "vt_enrichment.csv")
        assert os.path.exists(csv_path)

        state_path = os.path.join(tmpdir, "vt_enriched_hashes.txt")
        assert os.path.exists(state_path)
        with open(state_path) as f:
            hashes = f.read().strip().split("\n")
        assert "a" * 64 in hashes
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_virustotal.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Write the implementation**

Create `collectors/virustotal.py`:

```python
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
            time.sleep(2)  # Stay within 4 req/min

        return all_rows
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_virustotal.py -v`
Expected: 2 passed

- [ ] **Step 5: Commit**

```bash
git add collectors/virustotal.py tests/test_virustotal.py
git commit -m "feat: add VirusTotal enricher with priority queue and state tracking"
```

---

### Task 5: Update Classifier

**Files:**
- Modify: `normalizer/classifier.py`
- Modify: `tests/test_classifier.py`

- [ ] **Step 1: Add new test cases for vt_classification**

Add to `tests/test_classifier.py`:

```python
def test_vt_classification_adware():
    assert classify(clamav="", tags="", misp_classification="", vt_classification="adware") == "adware"

def test_vt_classification_pup():
    assert classify(clamav="", tags="", misp_classification="", vt_classification="pup") == "pup"

def test_vt_after_misp():
    # MISP takes priority over VT
    assert classify(clamav="", tags="", misp_classification="riskware", vt_classification="adware") == "riskware"

def test_vt_trojan_stays_malware():
    # VT "trojan" category should not override — it's already malware
    assert classify(clamav="", tags="", vt_classification="trojan") == "malware"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_classifier.py -v`
Expected: FAIL — `classify() got an unexpected keyword argument 'vt_classification'`

- [ ] **Step 3: Update the classifier**

Replace `normalizer/classifier.py`:

```python
"""Classification logic: malware vs pup/pua/adware/riskware.

Rules applied in priority order. First match wins.
"""

VT_PUP_CATEGORIES = {"adware", "pup", "pua", "riskware"}


def classify(clamav: str = "", tags: str = "", misp_classification: str = "",
             vt_classification: str = "") -> str:
    """Classify a sample based on ClamAV signature, tags, MISP type, and VT classification.

    Args:
        clamav: ClamAV detection name (e.g., "PUA.Win32.Adware.Foo")
        tags: Pipe-separated tags (e.g., "stealer|adware|packed")
        misp_classification: Classification from MISP Galaxy (e.g., "adware")
        vt_classification: Classification from VirusTotal popular_threat_classification

    Returns:
        One of: "malware", "pup", "pua", "adware", "riskware"
    """
    clamav_lower = clamav.lower()
    tags_lower = tags.lower()
    tag_set = set(tags_lower.split("|")) if tags_lower else set()

    if clamav_lower.startswith("pua."):
        return "pua"
    if clamav_lower.startswith("adware."):
        return "adware"
    if "adware" in tag_set:
        return "adware"
    if "pup" in tag_set:
        return "pup"
    if "pua" in tag_set:
        return "pua"
    if "riskware" in tag_set:
        return "riskware"
    if "bundler" in tag_set:
        return "pua"
    if misp_classification and misp_classification.lower() in VT_PUP_CATEGORIES:
        return misp_classification.lower()
    if vt_classification and vt_classification.lower() in VT_PUP_CATEGORIES:
        return vt_classification.lower()
    return "malware"
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_classifier.py -v`
Expected: All passed (original 11 + 4 new = 15)

- [ ] **Step 5: Commit**

```bash
git add normalizer/classifier.py tests/test_classifier.py
git commit -m "feat: add vt_classification to classifier priority chain"
```

---

### Task 6: Update Normalizer

**Files:**
- Modify: `normalizer/normalize.py`
- Modify: `tests/test_normalize.py`

- [ ] **Step 1: Add test for behavioral indicators and new sample columns**

Add to `tests/test_normalize.py` (at the end of the file):

```python
def test_normalizer_produces_behavioral_indicators(pipeline_dirs):
    raw_dir, norm_dir = pipeline_dirs

    # Add urlhaus raw data
    write_csv(
        os.path.join(raw_dir, "urlhaus.csv"),
        ["sha256", "md5", "url", "host", "url_status", "file_type", "signature", "tags", "first_seen"],
        [{"sha256": "a" * 64, "md5": "c" * 32, "url": "https://evil.com/mal.exe",
          "host": "evil.com", "url_status": "online", "file_type": "exe",
          "signature": "AgentTesla", "tags": "", "first_seen": "2024-01-01"}],
    )

    # Add hybrid analysis raw data
    write_csv(
        os.path.join(raw_dir, "hybrid_analysis.csv"),
        ["sha256", "verdict", "vx_family", "av_detect_pct", "contacted_domains", "contacted_ips", "analysis_date"],
        [{"sha256": "a" * 64, "verdict": "malicious", "vx_family": "AgentTesla",
          "av_detect_pct": "75", "contacted_domains": "c2.evil.com|exfil.bad.org",
          "contacted_ips": "1.2.3.4", "analysis_date": "2024-01-15"}],
    )

    normalizer = Normalizer(raw_dir, norm_dir)
    normalizer.run()

    # Check behavioral indicators file exists and has data
    bi_path = os.path.join(norm_dir, "behavioral_indicators.csv")
    assert os.path.exists(bi_path)
    with open(bi_path, newline="", encoding="utf-8") as f:
        bi_rows = list(csv.DictReader(f))
    # Should have: evil.com (urlhaus) + c2.evil.com + exfil.bad.org (HA domains) + 1.2.3.4 (HA ip)
    assert len(bi_rows) >= 3


def test_normalizer_adds_vt_columns(pipeline_dirs):
    raw_dir, norm_dir = pipeline_dirs

    # Add VT enrichment data
    write_csv(
        os.path.join(raw_dir, "vt_enrichment.csv"),
        ["sha256", "vt_classification", "vt_detection_rate", "vt_family", "vt_tags", "enriched_date"],
        [{"sha256": "a" * 64, "vt_classification": "trojan", "vt_detection_rate": "45/72",
          "vt_family": "agenttesla", "vt_tags": "pe|trojan", "enriched_date": "2024-01-15"}],
    )

    normalizer = Normalizer(raw_dir, norm_dir)
    normalizer.run()

    with open(os.path.join(norm_dir, "malware_samples.csv"), newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    sample = next((r for r in rows if r["sha256"] == "a" * 64), None)
    assert sample is not None
    assert sample["vt_detection_rate"] == "45/72"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_normalize.py::test_normalizer_produces_behavioral_indicators -v`
Expected: FAIL (no behavioral_indicators.csv produced)

- [ ] **Step 3: Update the normalizer**

Update `normalizer/normalize.py`. The changes are:

**a) Add new fieldnames constants (after existing ones around line 28):**

```python
BEHAVIORAL_FIELDNAMES = [
    "sha256", "indicator_type", "indicator_value", "source", "family", "first_seen",
]
```

**b) Update SAMPLE_FIELDNAMES to include new columns (replace existing line 11-15):**

```python
SAMPLE_FIELDNAMES = [
    "sha256", "sha1", "md5", "family", "family_aliases", "classification",
    "tags", "confidence", "clamav_detection", "first_seen", "last_seen",
    "source", "mitre_techniques",
    "contacted_domains", "contacted_ips", "vt_classification", "vt_detection_rate",
]
```

**c) Add new instance variables in `__init__` (after `_mitre_technique_details`):**

```python
        self._ha_data: dict[str, dict] = {}  # sha256 -> HA row
        self._vt_data: dict[str, dict] = {}  # sha256 -> VT row
        self._urlhaus_data: dict[str, list[dict]] = {}  # sha256 -> list of URL rows
```

**d) Add loader methods (after `_load_mitre_techniques`):**

```python
    def _load_hybrid_analysis(self):
        path = os.path.join(self.raw_dir, "hybrid_analysis.csv")
        if not os.path.exists(path):
            return
        with open(path, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                sha256 = row.get("sha256", "").strip()
                if sha256:
                    self._ha_data[sha256] = row

    def _load_vt_enrichment(self):
        path = os.path.join(self.raw_dir, "vt_enrichment.csv")
        if not os.path.exists(path):
            return
        with open(path, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                sha256 = row.get("sha256", "").strip()
                if sha256:
                    self._vt_data[sha256] = row

    def _load_urlhaus(self):
        path = os.path.join(self.raw_dir, "urlhaus.csv")
        if not os.path.exists(path):
            return
        with open(path, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                sha256 = row.get("sha256", "").strip()
                if sha256:
                    if sha256 not in self._urlhaus_data:
                        self._urlhaus_data[sha256] = []
                    self._urlhaus_data[sha256].append(row)
```

**e) Call loaders in `run()` (after `_load_mapping_rules()`):**

```python
        self._load_hybrid_analysis()
        self._load_vt_enrichment()
        self._load_urlhaus()
```

**f) Add behavioral indicators collection and write (in `run()`, after building techniques):**

```python
        behavioral = self._build_behavioral_indicators(samples)
```

And add the write call:

```python
        self._write_csv_and_json("behavioral_indicators", BEHAVIORAL_FIELDNAMES, behavioral)
```

**g) Update `_collect_samples` to enrich with HA/VT/URLhaus data.** After building each sample dict (the `samples[sha256] = {...}` block), add:

```python
                # Enrich from Hybrid Analysis
                ha_entry = self._ha_data.get(sha256)
                contacted_domains = ""
                contacted_ips = ""
                if ha_entry:
                    contacted_domains = ha_entry.get("contacted_domains", "")
                    contacted_ips = ha_entry.get("contacted_ips", "")

                # Enrich from URLhaus (add hosts to contacted_domains)
                urlhaus_entries = self._urlhaus_data.get(sha256, [])
                if urlhaus_entries:
                    uh_hosts = [e.get("host", "") for e in urlhaus_entries if e.get("host")]
                    if uh_hosts:
                        existing = set(contacted_domains.split("|")) if contacted_domains else set()
                        existing.update(uh_hosts)
                        existing.discard("")
                        contacted_domains = "|".join(sorted(existing)[:10])

                # Enrich from VirusTotal
                vt_entry = self._vt_data.get(sha256)
                vt_classification = ""
                vt_detection_rate = ""
                if vt_entry:
                    vt_classification = vt_entry.get("vt_classification", "")
                    vt_detection_rate = vt_entry.get("vt_detection_rate", "")

                samples[sha256] = {
                    ...existing fields...,
                    "contacted_domains": contacted_domains,
                    "contacted_ips": contacted_ips,
                    "vt_classification": vt_classification,
                    "vt_detection_rate": vt_detection_rate,
                }
```

And update the `classify()` call to pass `vt_classification`:

```python
                classification = classify(
                    clamav=clamav, tags=tags,
                    misp_classification=misp_class,
                    vt_classification=vt_classification,
                )
```

**h) Add `_build_behavioral_indicators` method:**

```python
    def _build_behavioral_indicators(self, samples):
        """Build behavioral indicators from HA + URLhaus data."""
        indicators = []

        for sample in samples:
            sha256 = sample.get("sha256", "")
            family = sample.get("family", "")

            # From Hybrid Analysis
            ha_entry = self._ha_data.get(sha256)
            if ha_entry:
                for domain in (ha_entry.get("contacted_domains", "") or "").split("|"):
                    if domain:
                        indicators.append({
                            "sha256": sha256, "indicator_type": "domain",
                            "indicator_value": domain, "source": "hybrid_analysis",
                            "family": family, "first_seen": ha_entry.get("analysis_date", ""),
                        })
                for ip in (ha_entry.get("contacted_ips", "") or "").split("|"):
                    if ip:
                        indicators.append({
                            "sha256": sha256, "indicator_type": "ip",
                            "indicator_value": ip, "source": "hybrid_analysis",
                            "family": family, "first_seen": ha_entry.get("analysis_date", ""),
                        })

            # From URLhaus
            for uh_entry in self._urlhaus_data.get(sha256, []):
                host = uh_entry.get("host", "")
                url = uh_entry.get("url", "")
                if url:
                    indicators.append({
                        "sha256": sha256, "indicator_type": "url",
                        "indicator_value": url, "source": "urlhaus",
                        "family": family, "first_seen": uh_entry.get("first_seen", ""),
                    })
                if host:
                    indicators.append({
                        "sha256": sha256, "indicator_type": "domain",
                        "indicator_value": host, "source": "urlhaus",
                        "family": family, "first_seen": uh_entry.get("first_seen", ""),
                    })

        return indicators
```

**i) Update `_collect_iocs` to also load URLhaus + OTX data** (append to the existing iocs list):

After the ThreatFox section, add:

```python
        # URLhaus IOCs
        uh_path = os.path.join(self.raw_dir, "urlhaus.csv")
        if os.path.exists(uh_path):
            with open(uh_path, newline="", encoding="utf-8") as f:
                for row in csv.DictReader(f):
                    family_raw = row.get("signature", "")
                    family = self.mapper.resolve(family_raw) if family_raw else ""
                    iocs.append({
                        "ioc_type": "url",
                        "ioc_value": row.get("url", ""),
                        "family": family or family_raw,
                        "confidence": "",
                        "threat_type": "payload_delivery",
                        "first_seen": row.get("first_seen", ""),
                        "last_seen": "",
                        "source": "urlhaus",
                    })

        # OTX IOCs
        otx_path = os.path.join(self.raw_dir, "otx_pulses.csv")
        if os.path.exists(otx_path):
            with open(otx_path, newline="", encoding="utf-8") as f:
                for row in csv.DictReader(f):
                    family_raw = row.get("family", "")
                    family = self.mapper.resolve(family_raw) if family_raw else ""
                    iocs.append({
                        "ioc_type": row.get("ioc_type", ""),
                        "ioc_value": row.get("ioc_value", ""),
                        "family": family or family_raw,
                        "confidence": "",
                        "threat_type": "",
                        "first_seen": row.get("created", ""),
                        "last_seen": "",
                        "source": "otx",
                    })
```

**j) Update stats dict in `run()` to include behavioral count:**

```python
        stats = {
            "total_samples": len(samples),
            "total_malware": len(malware),
            "total_pup_pua": len(pup_pua),
            "total_families": len(families),
            "total_iocs": len(iocs),
            "total_behavioral_indicators": len(behavioral),
            "last_updated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
```

- [ ] **Step 4: Run all normalizer tests**

Run: `python -m pytest tests/test_normalize.py -v`
Expected: All passed (original 6 + 2 new = 8)

- [ ] **Step 5: Commit**

```bash
git add normalizer/normalize.py tests/test_normalize.py
git commit -m "feat: integrate enrichment data into normalizer with behavioral indicators and VT columns"
```

---

### Task 7: Update run_pipeline.py

**Files:**
- Modify: `run_pipeline.py`

- [ ] **Step 1: Update the CLI entry point**

Replace `run_pipeline.py`:

```python
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
```

- [ ] **Step 2: Verify CLI help works**

Run: `python run_pipeline.py --help`
Expected: Shows --collector and --enricher options with all choices

- [ ] **Step 3: Commit**

```bash
git add run_pipeline.py
git commit -m "feat: add --enricher subcommand and new collectors to pipeline"
```

---

### Task 8: GitHub Actions Workflows

**Files:**
- Modify: `.github/workflows/daily-update.yml`
- Create: `.github/workflows/enrichment.yml`

- [ ] **Step 1: Update daily-update.yml**

Add these steps between the existing MISP Galaxy collector step and the normalizer step:

```yaml
      - name: Run URLhaus collector
        env:
          URLHAUS_API_KEY: ${{ secrets.URLHAUS_API_KEY }}
        run: python run_pipeline.py --collector urlhaus --skip-normalize
        continue-on-error: true

      - name: Run OTX collector
        env:
          OTX_API_KEY: ${{ secrets.OTX_API_KEY }}
        run: python run_pipeline.py --collector otx --skip-normalize
        continue-on-error: true
```

Also update the normalizer step to pass all env vars:

```yaml
      - name: Run normalizer
        env:
          MALWAREBAZAAR_API_KEY: ${{ secrets.MALWAREBAZAAR_API_KEY }}
          THREATFOX_API_KEY: ${{ secrets.THREATFOX_API_KEY }}
          YARAIFY_API_KEY: ${{ secrets.YARAIFY_API_KEY }}
          URLHAUS_API_KEY: ${{ secrets.URLHAUS_API_KEY }}
          OTX_API_KEY: ${{ secrets.OTX_API_KEY }}
        run: |
          python -c "
          from normalizer.normalize import Normalizer
          normalizer = Normalizer('data/raw', 'data/normalized')
          normalizer.run()
          "
```

- [ ] **Step 2: Create enrichment.yml**

Create `.github/workflows/enrichment.yml`:

```yaml
name: Hash Enrichment
# Runs every 6 hours to enrich samples via Hybrid Analysis and VirusTotal
on:
  schedule:
    - cron: '0 */6 * * *'
  workflow_dispatch:

permissions:
  contents: write

jobs:
  enrich:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install dependencies
        run: pip install -r requirements.txt

      - name: Run Hybrid Analysis enricher
        env:
          HYBRID_ANALYSIS_API_KEY: ${{ secrets.HYBRID_ANALYSIS_API_KEY }}
        run: python run_pipeline.py --enricher hybrid_analysis --skip-normalize
        continue-on-error: true

      - name: Run VirusTotal enricher
        env:
          VT_API_KEY: ${{ secrets.VT_API_KEY }}
        run: python run_pipeline.py --enricher virustotal --skip-normalize
        continue-on-error: true

      - name: Run normalizer
        env:
          MALWAREBAZAAR_API_KEY: ${{ secrets.MALWAREBAZAAR_API_KEY }}
          THREATFOX_API_KEY: ${{ secrets.THREATFOX_API_KEY }}
          YARAIFY_API_KEY: ${{ secrets.YARAIFY_API_KEY }}
        run: |
          python -c "
          from normalizer.normalize import Normalizer
          normalizer = Normalizer('data/raw', 'data/normalized')
          normalizer.run()
          "

      - name: Check for changes
        id: changes
        run: |
          git diff --quiet data/ && echo "changed=false" >> $GITHUB_OUTPUT || echo "changed=true" >> $GITHUB_OUTPUT

      - name: Commit and push
        if: steps.changes.outputs.changed == 'true'
        run: |
          git config user.name "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"

          git add data/
          git commit -m "data: enrichment update $(date -u +%Y-%m-%d-%H%M)"
          git push
```

- [ ] **Step 3: Validate YAML**

Run: `python -c "import yaml; yaml.safe_load(open('.github/workflows/daily-update.yml')); yaml.safe_load(open('.github/workflows/enrichment.yml')); print('YAML valid')"`
Expected: `YAML valid`

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/daily-update.yml .github/workflows/enrichment.yml
git commit -m "ci: add enrichment workflow and URLhaus/OTX to daily pipeline"
```

---

### Task 9: Integration Test

**Files:** None new — validates everything end-to-end.

- [ ] **Step 1: Run the full test suite**

Run: `python -m pytest tests/ -v`
Expected: All tests pass (~40+ tests)

- [ ] **Step 2: Test the enricher CLI**

Run: `python run_pipeline.py --enricher hybrid_analysis --skip-normalize 2>&1 || true`
Expected: Prints "Running enricher: hybrid_analysis" then fails with missing API key (expected in local dev)

Run: `python run_pipeline.py --enricher virustotal --skip-normalize 2>&1 || true`
Expected: Prints "Running enricher: virustotal" then fails with missing API key

- [ ] **Step 3: Test the new collectors CLI**

Run: `python run_pipeline.py --collector urlhaus --skip-normalize 2>&1 || true`
Expected: Prints "Running collector: urlhaus" then fails with missing API key

Run: `python run_pipeline.py --collector otx --skip-normalize 2>&1 || true`
Expected: Prints "Running collector: otx" then fails with missing API key

- [ ] **Step 4: Run normalizer with existing data to verify no regressions**

Run: `python -c "from normalizer.normalize import Normalizer; Normalizer('data/raw', 'data/normalized').run()"`
Expected: Normalizer completes, produces all output files including behavioral_indicators.csv

- [ ] **Step 5: Commit and push**

```bash
git add -A
git commit -m "chore: V2 high-impact sources complete"
git push
```
