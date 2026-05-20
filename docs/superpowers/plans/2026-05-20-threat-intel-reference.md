# Threat Intelligence Reference Database — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a public GitHub repo that aggregates malware/PUP/PUA threat intelligence from multiple free sources into daily-updated CSV/JSON reference files with a static search UI.

**Architecture:** Python collector scripts pull from 5 free TI sources (MalwareBazaar, ThreatFox, YARAify, MITRE ATT&CK, MISP Galaxy) into raw CSVs. A normalizer merges and classifies them into unified output files. GitHub Actions runs the pipeline daily. A vanilla HTML/JS site on GitHub Pages provides search and browsing.

**Tech Stack:** Python 3.12, requests, GitHub Actions, static HTML/CSS/JS

---

## File Map

```
threat-intel-reference/
├── collectors/
│   ├── __init__.py              # Empty init
│   ├── base.py                  # BaseCollector class (shared HTTP/CSV logic)
│   ├── malwarebazaar.py         # MalwareBazaar daily dump collector
│   ├── threatfox.py             # ThreatFox full export collector
│   ├── yaraify.py               # YARAify YARA rules collector
│   ├── mitre_attack.py          # MITRE ATT&CK STIX collector
│   └── misp_galaxy.py           # MISP Galaxy cluster collector
├── normalizer/
│   ├── __init__.py              # Empty init
│   ├── family_mapping.py        # Loads malware_name_mapping regexes, resolves aliases
│   ├── classifier.py            # Classification logic (malware vs pup/pua/adware/riskware)
│   └── normalize.py             # Main normalizer: merge raw → normalized CSVs + JSON
├── tests/
│   ├── __init__.py
│   ├── test_family_mapping.py
│   ├── test_classifier.py
│   ├── test_normalize.py
│   ├── test_malwarebazaar.py
│   ├── test_threatfox.py
│   ├── test_yaraify.py
│   ├── test_mitre_attack.py
│   └── test_misp_galaxy.py
├── data/
│   ├── raw/                     # Populated by collectors
│   └── normalized/              # Populated by normalizer
├── docs/
│   ├── index.html
│   ├── search.html
│   ├── families.html
│   ├── about.html
│   ├── style.css
│   └── app.js
├── .github/
│   └── workflows/
│       ├── daily-update.yml
│       └── manual-trigger.yml
├── run_pipeline.py              # CLI entry point: run collectors + normalizer
├── requirements.txt
├── config.example.yml
└── README.md
```

---

### Task 1: Project Scaffolding

**Files:**
- Create: `requirements.txt`
- Create: `config.example.yml`
- Create: `run_pipeline.py`
- Create: `collectors/__init__.py`
- Create: `normalizer/__init__.py`
- Create: `tests/__init__.py`
- Create: `data/raw/.gitkeep`
- Create: `data/normalized/.gitkeep`

- [ ] **Step 1: Create requirements.txt**

```
requests>=2.31.0
PyYAML>=6.0.1
```

- [ ] **Step 2: Create config.example.yml**

```yaml
# Copy this to config.yml and fill in your API keys.
# Alternatively, set these as environment variables.
malwarebazaar_api_key: "YOUR_KEY_HERE"
threatfox_api_key: "YOUR_KEY_HERE"
yaraify_api_key: "YOUR_KEY_HERE"
```

- [ ] **Step 3: Create run_pipeline.py**

```python
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
        sys.exit(1)


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Create empty __init__.py files and .gitkeep files**

Create empty files at:
- `collectors/__init__.py`
- `normalizer/__init__.py`
- `tests/__init__.py`
- `data/raw/.gitkeep`
- `data/normalized/.gitkeep`

- [ ] **Step 5: Install dependencies and verify**

Run: `pip install -r requirements.txt`
Expected: Successfully installed requests and PyYAML

- [ ] **Step 6: Commit**

```bash
git add requirements.txt config.example.yml run_pipeline.py collectors/__init__.py normalizer/__init__.py tests/__init__.py data/raw/.gitkeep data/normalized/.gitkeep
git commit -m "chore: scaffold project structure with entry point and config"
```

---

### Task 2: Base Collector

**Files:**
- Create: `collectors/base.py`
- Create: `tests/test_base_collector.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_base_collector.py`:

```python
import os
import csv
import tempfile
import pytest
from collectors.base import BaseCollector


class DummyCollector(BaseCollector):
    def collect(self):
        return [
            {"sha256": "abc123", "family": "testfam"},
            {"sha256": "def456", "family": "otherfam"},
        ]

    @property
    def source_name(self):
        return "dummy"

    @property
    def fieldnames(self):
        return ["sha256", "family"]


def test_run_writes_csv():
    with tempfile.TemporaryDirectory() as tmpdir:
        collector = DummyCollector(tmpdir)
        collector.run()
        output_path = os.path.join(tmpdir, "dummy.csv")
        assert os.path.exists(output_path)
        with open(output_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        assert len(rows) == 2
        assert rows[0]["sha256"] == "abc123"
        assert rows[1]["family"] == "otherfam"


def test_run_overwrites_existing():
    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = os.path.join(tmpdir, "dummy.csv")
        with open(output_path, "w") as f:
            f.write("old data")
        collector = DummyCollector(tmpdir)
        collector.run()
        with open(output_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        assert len(rows) == 2


def test_get_env_or_config_from_env(monkeypatch):
    monkeypatch.setenv("DUMMY_API_KEY", "env_key_123")
    with tempfile.TemporaryDirectory() as tmpdir:
        collector = DummyCollector(tmpdir)
        assert collector.get_api_key("DUMMY_API_KEY") == "env_key_123"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_base_collector.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'collectors.base'`

- [ ] **Step 3: Write the implementation**

Create `collectors/base.py`:

```python
"""Base collector class with shared HTTP/CSV logic."""

import csv
import os
from abc import ABC, abstractmethod

import requests


class BaseCollector(ABC):
    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        self.session = requests.Session()

    @property
    @abstractmethod
    def source_name(self) -> str:
        """Short name used for the output filename (e.g., 'malwarebazaar')."""

    @property
    @abstractmethod
    def fieldnames(self) -> list[str]:
        """CSV column names for this collector's output."""

    @abstractmethod
    def collect(self) -> list[dict]:
        """Fetch data from the source. Returns a list of row dicts."""

    def run(self):
        """Run the collector and write results to CSV."""
        rows = self.collect()
        output_path = os.path.join(self.output_dir, f"{self.source_name}.csv")
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=self.fieldnames, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)
        print(f"  Wrote {len(rows)} rows to {output_path}")

    def get_api_key(self, env_var: str) -> str:
        """Get API key from environment variable. Raises if not found."""
        key = os.environ.get(env_var)
        if not key:
            raise ValueError(f"API key not found. Set the {env_var} environment variable.")
        return key
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_base_collector.py -v`
Expected: 3 passed

- [ ] **Step 5: Commit**

```bash
git add collectors/base.py tests/test_base_collector.py
git commit -m "feat: add BaseCollector with CSV output and env-based auth"
```

---

### Task 3: MalwareBazaar Collector

**Files:**
- Create: `collectors/malwarebazaar.py`
- Create: `tests/test_malwarebazaar.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_malwarebazaar.py`:

```python
import json
import os
import csv
import tempfile
from unittest.mock import patch, MagicMock
import pytest
from collectors.malwarebazaar import MalwareBazaarCollector


SAMPLE_RESPONSE = {
    "query_status": "ok",
    "data": [
        {
            "sha256_hash": "a" * 64,
            "sha1_hash": "b" * 40,
            "md5_hash": "c" * 32,
            "file_name": "evil.exe",
            "file_type": "exe",
            "file_size": 12345,
            "signature": "AgentTesla",
            "first_seen": "2024-01-15 10:30:00",
            "last_seen": "2024-06-01 08:00:00",
            "tags": ["agenttesla", "stealer"],
            "clamav": ["Win.Trojan.AgentTesla-1234"],
            "reporter": "abuse_ch",
            "imphash": "d" * 32,
            "tlsh": "T1" + "e" * 68,
            "ssdeep": "384:abc:def",
        },
        {
            "sha256_hash": "f" * 64,
            "sha1_hash": "0" * 40,
            "md5_hash": "1" * 32,
            "file_name": "adware.apk",
            "file_type": "apk",
            "file_size": 9999,
            "signature": None,
            "first_seen": "2024-03-10 12:00:00",
            "last_seen": None,
            "tags": ["adware"],
            "clamav": ["PUA.AndroidOS.Adware-5678"],
            "reporter": "user123",
            "imphash": None,
            "tlsh": None,
            "ssdeep": None,
        },
    ],
}


@patch("collectors.malwarebazaar.MalwareBazaarCollector.get_api_key", return_value="fake_key")
@patch("requests.Session.post")
def test_collect_parses_response(mock_post, mock_key):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = SAMPLE_RESPONSE
    mock_post.return_value = mock_resp

    with tempfile.TemporaryDirectory() as tmpdir:
        collector = MalwareBazaarCollector(tmpdir)
        rows = collector.collect()

    assert len(rows) == 2
    assert rows[0]["sha256"] == "a" * 64
    assert rows[0]["family"] == "AgentTesla"
    assert rows[0]["tags"] == "agenttesla|stealer"
    assert rows[0]["clamav_detection"] == "Win.Trojan.AgentTesla-1234"
    assert rows[1]["sha256"] == "f" * 64
    assert rows[1]["family"] == ""
    assert rows[1]["clamav_detection"] == "PUA.AndroidOS.Adware-5678"


@patch("collectors.malwarebazaar.MalwareBazaarCollector.get_api_key", return_value="fake_key")
@patch("requests.Session.post")
def test_run_writes_csv(mock_post, mock_key):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = SAMPLE_RESPONSE
    mock_post.return_value = mock_resp

    with tempfile.TemporaryDirectory() as tmpdir:
        collector = MalwareBazaarCollector(tmpdir)
        collector.run()
        path = os.path.join(tmpdir, "malwarebazaar.csv")
        assert os.path.exists(path)
        with open(path, newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        assert len(rows) == 2
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_malwarebazaar.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Write the implementation**

Create `collectors/malwarebazaar.py`:

```python
"""Collector for MalwareBazaar (abuse.ch) recent samples."""

from collectors.base import BaseCollector

API_URL = "https://mb-api.abuse.ch/api/v1/"
ENV_VAR = "MALWAREBAZAAR_API_KEY"


class MalwareBazaarCollector(BaseCollector):
    @property
    def source_name(self):
        return "malwarebazaar"

    @property
    def fieldnames(self):
        return [
            "sha256", "sha1", "md5", "file_name", "file_type", "file_size",
            "family", "tags", "clamav_detection", "first_seen", "last_seen",
            "imphash", "tlsh", "ssdeep",
        ]

    def collect(self):
        api_key = self.get_api_key(ENV_VAR)
        self.session.headers["Auth-Key"] = api_key

        all_rows = []
        # Fetch the most recent 1000 samples (API max per request)
        resp = self.session.post(API_URL, data={"query": "get_recent", "selector": "1000"})
        resp.raise_for_status()
        result = resp.json()

        if result.get("query_status") != "ok":
            print(f"  MalwareBazaar query_status: {result.get('query_status')}")
            return all_rows

        for sample in result.get("data", []):
            tags_list = sample.get("tags") or []
            clamav_list = sample.get("clamav") or []

            all_rows.append({
                "sha256": sample.get("sha256_hash", ""),
                "sha1": sample.get("sha1_hash", ""),
                "md5": sample.get("md5_hash", ""),
                "file_name": sample.get("file_name", ""),
                "file_type": sample.get("file_type", ""),
                "file_size": sample.get("file_size", ""),
                "family": sample.get("signature") or "",
                "tags": "|".join(tags_list) if isinstance(tags_list, list) else str(tags_list),
                "clamav_detection": clamav_list[0] if clamav_list else "",
                "first_seen": sample.get("first_seen", ""),
                "last_seen": sample.get("last_seen") or "",
                "imphash": sample.get("imphash") or "",
                "tlsh": sample.get("tlsh") or "",
                "ssdeep": sample.get("ssdeep") or "",
            })

        return all_rows
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_malwarebazaar.py -v`
Expected: 2 passed

- [ ] **Step 5: Commit**

```bash
git add collectors/malwarebazaar.py tests/test_malwarebazaar.py
git commit -m "feat: add MalwareBazaar collector with recent samples endpoint"
```

---

### Task 4: ThreatFox Collector

**Files:**
- Create: `collectors/threatfox.py`
- Create: `tests/test_threatfox.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_threatfox.py`:

```python
import os
import csv
import io
import tempfile
import zipfile
from unittest.mock import patch, MagicMock
import pytest
from collectors.threatfox import ThreatFoxCollector


SAMPLE_CSV = '''"ioc_id","ioc_type","ioc_value","threat_type","malware","malware_alias","malware_printable","confidence_level","first_seen_utc","last_seen_utc","reporter","tags"
"1","ip:port","1.2.3.4:443","botnet_cc","win.cobalt_strike","CobaltStrike","Cobalt Strike","75","2024-01-01 00:00:00","2024-06-01 00:00:00","abuse_ch","cobalt-strike"
"2","sha256_hash","aaaa","payload","win.emotet","Emotet,Heodo","Emotet","90","2024-02-01 00:00:00","","reporter2","emotet|heodo"
'''


@patch("collectors.threatfox.ThreatFoxCollector.get_api_key", return_value="fake_key")
@patch("requests.Session.get")
def test_collect_parses_csv_export(mock_get, mock_key):
    # Build a zip containing the CSV
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w") as zf:
        zf.writestr("full_export.csv", SAMPLE_CSV)
    zip_buf.seek(0)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.content = zip_buf.read()
    mock_get.return_value = mock_resp

    with tempfile.TemporaryDirectory() as tmpdir:
        collector = ThreatFoxCollector(tmpdir)
        rows = collector.collect()

    assert len(rows) == 2
    assert rows[0]["ioc_value"] == "1.2.3.4:443"
    assert rows[0]["family"] == "Cobalt Strike"
    assert rows[0]["confidence"] == "75"
    assert rows[0]["ioc_type"] == "ip:port"
    assert rows[1]["family"] == "Emotet"
    assert rows[1]["family_aliases"] == "Emotet,Heodo"


@patch("collectors.threatfox.ThreatFoxCollector.get_api_key", return_value="fake_key")
@patch("requests.Session.get")
def test_run_writes_csv(mock_get, mock_key):
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w") as zf:
        zf.writestr("full_export.csv", SAMPLE_CSV)
    zip_buf.seek(0)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.content = zip_buf.read()
    mock_get.return_value = mock_resp

    with tempfile.TemporaryDirectory() as tmpdir:
        collector = ThreatFoxCollector(tmpdir)
        collector.run()
        path = os.path.join(tmpdir, "threatfox.csv")
        assert os.path.exists(path)
        with open(path, newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        assert len(rows) == 2
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_threatfox.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Write the implementation**

Create `collectors/threatfox.py`:

```python
"""Collector for ThreatFox (abuse.ch) full IOC export."""

import csv
import io
import zipfile

from collectors.base import BaseCollector

EXPORT_URL = "https://threatfox-api.abuse.ch/v2/files/exports/{api_key}/full.csv.zip"
ENV_VAR = "THREATFOX_API_KEY"


class ThreatFoxCollector(BaseCollector):
    @property
    def source_name(self):
        return "threatfox"

    @property
    def fieldnames(self):
        return [
            "ioc_id", "ioc_type", "ioc_value", "threat_type",
            "family", "family_aliases", "confidence",
            "first_seen", "last_seen", "tags",
        ]

    def collect(self):
        api_key = self.get_api_key(ENV_VAR)
        url = EXPORT_URL.format(api_key=api_key)
        resp = self.session.get(url)
        resp.raise_for_status()

        rows = []
        with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
            # Find the CSV file inside the zip
            csv_names = [n for n in zf.namelist() if n.endswith(".csv")]
            if not csv_names:
                print("  No CSV found in ThreatFox export zip")
                return rows

            with zf.open(csv_names[0]) as csv_file:
                text = io.TextIOWrapper(csv_file, encoding="utf-8")
                # Skip comment lines starting with #
                lines = [line for line in text if not line.startswith("#")]
                reader = csv.DictReader(lines)

                for row in reader:
                    rows.append({
                        "ioc_id": row.get("ioc_id", "").strip('"'),
                        "ioc_type": row.get("ioc_type", "").strip('"'),
                        "ioc_value": row.get("ioc_value", "").strip('"'),
                        "threat_type": row.get("threat_type", "").strip('"'),
                        "family": row.get("malware_printable", "").strip('"'),
                        "family_aliases": row.get("malware_alias", "").strip('"'),
                        "confidence": row.get("confidence_level", "").strip('"'),
                        "first_seen": row.get("first_seen_utc", "").strip('"'),
                        "last_seen": row.get("last_seen_utc", "").strip('"'),
                        "tags": row.get("tags", "").strip('"'),
                    })

        return rows
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_threatfox.py -v`
Expected: 2 passed

- [ ] **Step 5: Commit**

```bash
git add collectors/threatfox.py tests/test_threatfox.py
git commit -m "feat: add ThreatFox collector using full CSV export"
```

---

### Task 5: YARAify Collector

**Files:**
- Create: `collectors/yaraify.py`
- Create: `tests/test_yaraify.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_yaraify.py`:

```python
import os
import csv
import tempfile
from unittest.mock import patch, MagicMock
import pytest
from collectors.yaraify import YARAifyCollector


SAMPLE_RESPONSE = {
    "query_status": "ok",
    "data": [
        {
            "rule_name": "win_agenttesla_w0",
            "author": "abuse.ch",
            "description": "Detects AgentTesla",
            "malpedia_family": "win.agenttesla",
            "yarahub_rule_matching_tlp": "TLP:WHITE",
            "yarahub_rule_sharing_tlp": "TLP:WHITE",
            "yarahub_uuid": "uuid-1234",
            "date": "2024-01-15",
        },
        {
            "rule_name": "win_emotet_w1",
            "author": "researcher",
            "description": "Detects Emotet",
            "malpedia_family": "win.emotet",
            "yarahub_rule_matching_tlp": "TLP:WHITE",
            "yarahub_rule_sharing_tlp": "TLP:GREEN",
            "yarahub_uuid": "uuid-5678",
            "date": "2024-02-20",
        },
    ],
}


@patch("collectors.yaraify.YARAifyCollector.get_api_key", return_value="fake_key")
@patch("requests.Session.post")
def test_collect_parses_response(mock_post, mock_key):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = SAMPLE_RESPONSE
    mock_post.return_value = mock_resp

    with tempfile.TemporaryDirectory() as tmpdir:
        collector = YARAifyCollector(tmpdir)
        rows = collector.collect()

    assert len(rows) == 2
    assert rows[0]["rule_name"] == "win_agenttesla_w0"
    assert rows[0]["malpedia_family"] == "win.agenttesla"
    assert rows[1]["malpedia_family"] == "win.emotet"


@patch("collectors.yaraify.YARAifyCollector.get_api_key", return_value="fake_key")
@patch("requests.Session.post")
def test_run_writes_csv(mock_post, mock_key):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = SAMPLE_RESPONSE
    mock_post.return_value = mock_resp

    with tempfile.TemporaryDirectory() as tmpdir:
        collector = YARAifyCollector(tmpdir)
        collector.run()
        path = os.path.join(tmpdir, "yaraify_rules.csv")
        assert os.path.exists(path)
        with open(path, newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        assert len(rows) == 2
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_yaraify.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Write the implementation**

Create `collectors/yaraify.py`:

```python
"""Collector for YARAify (abuse.ch) deployed YARA rules with family mappings."""

from collectors.base import BaseCollector

API_URL = "https://yaraify-api.abuse.ch/api/v1/"
ENV_VAR = "YARAIFY_API_KEY"


class YARAifyCollector(BaseCollector):
    @property
    def source_name(self):
        return "yaraify_rules"

    @property
    def fieldnames(self):
        return [
            "rule_name", "author", "description", "malpedia_family",
            "matching_tlp", "sharing_tlp", "yarahub_uuid", "date",
        ]

    def collect(self):
        api_key = self.get_api_key(ENV_VAR)
        self.session.headers["Auth-Key"] = api_key

        resp = self.session.post(API_URL, data={"query": "recent_yararules"})
        resp.raise_for_status()
        result = resp.json()

        if result.get("query_status") != "ok":
            print(f"  YARAify query_status: {result.get('query_status')}")
            return []

        rows = []
        for rule in result.get("data", []):
            rows.append({
                "rule_name": rule.get("rule_name", ""),
                "author": rule.get("author", ""),
                "description": rule.get("description", ""),
                "malpedia_family": rule.get("malpedia_family", ""),
                "matching_tlp": rule.get("yarahub_rule_matching_tlp", ""),
                "sharing_tlp": rule.get("yarahub_rule_sharing_tlp", ""),
                "yarahub_uuid": rule.get("yarahub_uuid", ""),
                "date": rule.get("date", ""),
            })

        return rows
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_yaraify.py -v`
Expected: 2 passed

- [ ] **Step 5: Commit**

```bash
git add collectors/yaraify.py tests/test_yaraify.py
git commit -m "feat: add YARAify collector for YARA rule-to-family mappings"
```

---

### Task 6: MITRE ATT&CK Collector

**Files:**
- Create: `collectors/mitre_attack.py`
- Create: `tests/test_mitre_attack.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_mitre_attack.py`:

```python
import os
import csv
import tempfile
from unittest.mock import patch, MagicMock
import pytest
from collectors.mitre_attack import MitreAttackCollector


SAMPLE_STIX_BUNDLE = {
    "type": "bundle",
    "objects": [
        {
            "type": "malware",
            "id": "malware--abcd-1234",
            "name": "Emotet",
            "description": "A modular banking trojan.",
            "x_mitre_aliases": ["Emotet", "Heodo", "Geodo"],
            "labels": ["malware"],
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "S0367"}
            ],
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--efgh-5678",
            "name": "Command and Scripting Interpreter",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1059"}
            ],
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "execution"}
            ],
        },
        {
            "type": "relationship",
            "id": "relationship--rel-001",
            "relationship_type": "uses",
            "source_ref": "malware--abcd-1234",
            "target_ref": "attack-pattern--efgh-5678",
        },
        {
            "type": "identity",
            "id": "identity--ignore",
            "name": "MITRE",
        },
    ],
}


@patch("requests.Session.get")
def test_collect_extracts_malware_and_techniques(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = SAMPLE_STIX_BUNDLE
    mock_get.return_value = mock_resp

    with tempfile.TemporaryDirectory() as tmpdir:
        collector = MitreAttackCollector(tmpdir)
        rows = collector.collect()

    # Should produce one row per malware object
    assert len(rows) == 1
    assert rows[0]["name"] == "Emotet"
    assert rows[0]["mitre_id"] == "S0367"
    assert rows[0]["aliases"] == "Emotet|Heodo|Geodo"
    assert rows[0]["techniques"] == "T1059"


@patch("requests.Session.get")
def test_run_writes_csv(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = SAMPLE_STIX_BUNDLE
    mock_get.return_value = mock_resp

    with tempfile.TemporaryDirectory() as tmpdir:
        collector = MitreAttackCollector(tmpdir)
        collector.run()
        path = os.path.join(tmpdir, "mitre_attack.csv")
        assert os.path.exists(path)
        with open(path, newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        assert len(rows) == 1
        assert rows[0]["techniques"] == "T1059"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_mitre_attack.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Write the implementation**

Create `collectors/mitre_attack.py`:

```python
"""Collector for MITRE ATT&CK enterprise malware and technique relationships."""

from collectors.base import BaseCollector

STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"


class MitreAttackCollector(BaseCollector):
    @property
    def source_name(self):
        return "mitre_attack"

    @property
    def fieldnames(self):
        return ["mitre_id", "name", "description", "aliases", "techniques"]

    def collect(self):
        resp = self.session.get(STIX_URL)
        resp.raise_for_status()
        bundle = resp.json()

        objects = bundle.get("objects", [])

        # Index attack-patterns by STIX id to ATT&CK technique ID
        pattern_id_map = {}
        for obj in objects:
            if obj.get("type") == "attack-pattern":
                ext_refs = obj.get("external_references", [])
                for ref in ext_refs:
                    if ref.get("source_name") == "mitre-attack":
                        pattern_id_map[obj["id"]] = ref["external_id"]
                        break

        # Index malware by STIX id
        malware_map = {}
        for obj in objects:
            if obj.get("type") != "malware":
                continue
            if obj.get("x_mitre_deprecated", False):
                continue

            mitre_id = ""
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    mitre_id = ref["external_id"]
                    break

            aliases = obj.get("x_mitre_aliases", [obj.get("name", "")])

            malware_map[obj["id"]] = {
                "mitre_id": mitre_id,
                "name": obj.get("name", ""),
                "description": (obj.get("description", "") or "")[:500],
                "aliases": "|".join(aliases),
                "technique_ids": [],
            }

        # Collect malware to technique relationships
        for obj in objects:
            if obj.get("type") != "relationship":
                continue
            if obj.get("relationship_type") != "uses":
                continue
            src = obj.get("source_ref", "")
            tgt = obj.get("target_ref", "")
            if src in malware_map and tgt in pattern_id_map:
                malware_map[src]["technique_ids"].append(pattern_id_map[tgt])

        rows = []
        for entry in malware_map.values():
            rows.append({
                "mitre_id": entry["mitre_id"],
                "name": entry["name"],
                "description": entry["description"],
                "aliases": entry["aliases"],
                "techniques": "|".join(sorted(set(entry["technique_ids"]))),
            })

        return rows
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_mitre_attack.py -v`
Expected: 2 passed

- [ ] **Step 5: Commit**

```bash
git add collectors/mitre_attack.py tests/test_mitre_attack.py
git commit -m "feat: add MITRE ATT&CK collector extracting malware-technique relationships"
```

---

### Task 7: MISP Galaxy Collector

**Files:**
- Create: `collectors/misp_galaxy.py`
- Create: `tests/test_misp_galaxy.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_misp_galaxy.py`:

```python
import os
import csv
import json
import tempfile
from unittest.mock import patch, MagicMock
import pytest
from collectors.misp_galaxy import MispGalaxyCollector


SAMPLE_MALPEDIA_CLUSTER = {
    "values": [
        {
            "value": "Emotet",
            "description": "A modular banking trojan turned botnet.",
            "uuid": "uuid-001",
            "meta": {
                "synonyms": ["Heodo", "Geodo"],
                "refs": ["https://malpedia.caad.fkie.fraunhofer.de/details/win.emotet"],
                "type": [],
            },
        },
        {
            "value": "Adware.BrowserAssistant",
            "description": "Browser adware that injects ads.",
            "uuid": "uuid-002",
            "meta": {
                "synonyms": ["BrowserAssistant"],
                "refs": [],
                "type": ["adware"],
            },
        },
    ],
}

SAMPLE_RANSOMWARE_CLUSTER = {
    "values": [
        {
            "value": "LockBit",
            "description": "Ransomware-as-a-service operation.",
            "uuid": "uuid-003",
            "meta": {
                "synonyms": ["LockBit 2.0", "LockBit 3.0"],
                "refs": [],
            },
        },
    ],
}


@patch("requests.Session.get")
def test_collect_merges_clusters(mock_get):
    def side_effect(url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        if "malpedia" in url:
            resp.json.return_value = SAMPLE_MALPEDIA_CLUSTER
        elif "ransomware" in url:
            resp.json.return_value = SAMPLE_RANSOMWARE_CLUSTER
        else:
            resp.json.return_value = {"values": []}
        return resp

    mock_get.side_effect = side_effect

    with tempfile.TemporaryDirectory() as tmpdir:
        collector = MispGalaxyCollector(tmpdir)
        rows = collector.collect()

    names = [r["canonical_name"] for r in rows]
    assert "Emotet" in names
    assert "LockBit" in names
    assert "Adware.BrowserAssistant" in names

    emotet = next(r for r in rows if r["canonical_name"] == "Emotet")
    assert "Heodo" in emotet["aliases"]
    assert "Geodo" in emotet["aliases"]

    adware = next(r for r in rows if r["canonical_name"] == "Adware.BrowserAssistant")
    assert adware["classification"] == "adware"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_misp_galaxy.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Write the implementation**

Create `collectors/misp_galaxy.py`:

```python
"""Collector for MISP Galaxy malware family clusters."""

from collectors.base import BaseCollector

CLUSTER_BASE = "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters"
CLUSTER_FILES = [
    "malpedia.json",
    "ransomware.json",
    "rat.json",
    "botnet.json",
    "banker.json",
    "exploit-kit.json",
    "backdoor.json",
    "mitre-enterprise-attack-malware.json",
]

PUP_TYPE_KEYWORDS = {"adware", "pup", "pua", "riskware", "bundler", "potentially unwanted"}


class MispGalaxyCollector(BaseCollector):
    @property
    def source_name(self):
        return "misp_galaxy_families"

    @property
    def fieldnames(self):
        return [
            "canonical_name", "aliases", "classification",
            "description", "uuid", "source_cluster",
        ]

    def collect(self):
        seen_uuids = set()
        rows = []

        for filename in CLUSTER_FILES:
            url = f"{CLUSTER_BASE}/{filename}"
            try:
                resp = self.session.get(url)
                resp.raise_for_status()
                cluster = resp.json()
            except Exception as e:
                print(f"  Skipping {filename}: {e}")
                continue

            for entry in cluster.get("values", []):
                uuid = entry.get("uuid", "")
                if uuid in seen_uuids:
                    continue
                seen_uuids.add(uuid)

                meta = entry.get("meta", {})
                synonyms = meta.get("synonyms", [])
                type_list = meta.get("type", [])

                classification = "malware"
                if isinstance(type_list, list):
                    for t in type_list:
                        if isinstance(t, str) and t.lower() in PUP_TYPE_KEYWORDS:
                            classification = t.lower()
                            break

                rows.append({
                    "canonical_name": entry.get("value", ""),
                    "aliases": "|".join(synonyms),
                    "classification": classification,
                    "description": (entry.get("description", "") or "")[:500],
                    "uuid": uuid,
                    "source_cluster": filename,
                })

        return rows
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_misp_galaxy.py -v`
Expected: 1 passed

- [ ] **Step 5: Commit**

```bash
git add collectors/misp_galaxy.py tests/test_misp_galaxy.py
git commit -m "feat: add MISP Galaxy collector merging multiple malware clusters"
```

---

### Task 8: Family Mapping (Alias Resolution)

**Files:**
- Create: `normalizer/family_mapping.py`
- Create: `tests/test_family_mapping.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_family_mapping.py`:

```python
import os
import tempfile
import pytest
from normalizer.family_mapping import FamilyMapper


SAMPLE_MAPPING_CSV = '''"^(emotet|heodo|geodo)$",emotet,malpedia
"^(cobalt[-_ ]?strike|cobaltstrike|beacon)$",cobalt_strike,common
"^agent[-_ ]?tesla$",agenttesla,malpedia
'''


def test_resolve_known_alias():
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "mapping.csv")
        with open(path, "w") as f:
            f.write(SAMPLE_MAPPING_CSV)
        mapper = FamilyMapper(path)

    assert mapper.resolve("Heodo") == "emotet"
    assert mapper.resolve("geodo") == "emotet"
    assert mapper.resolve("emotet") == "emotet"


def test_resolve_cobalt_strike_variations():
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "mapping.csv")
        with open(path, "w") as f:
            f.write(SAMPLE_MAPPING_CSV)
        mapper = FamilyMapper(path)

    assert mapper.resolve("CobaltStrike") == "cobalt_strike"
    assert mapper.resolve("Cobalt Strike") == "cobalt_strike"
    assert mapper.resolve("cobalt-strike") == "cobalt_strike"
    assert mapper.resolve("beacon") == "cobalt_strike"


def test_resolve_unknown_returns_lowered_input():
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "mapping.csv")
        with open(path, "w") as f:
            f.write(SAMPLE_MAPPING_CSV)
        mapper = FamilyMapper(path)

    assert mapper.resolve("UnknownMalware") == "unknownmalware"
    assert mapper.resolve("") == ""


def test_resolve_with_misp_aliases():
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "mapping.csv")
        with open(path, "w") as f:
            f.write(SAMPLE_MAPPING_CSV)
        mapper = FamilyMapper(path)

    # Simulate adding MISP aliases
    mapper.add_aliases("emotet", ["Emotet", "Heodo", "MealyBug"])
    assert mapper.resolve("MealyBug") == "emotet"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_family_mapping.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Write the implementation**

Create `normalizer/family_mapping.py`:

```python
"""Alias resolution using certtools/malware_name_mapping regexes + MISP Galaxy synonyms."""

import csv
import re


MAPPING_URL = "https://raw.githubusercontent.com/certtools/malware_name_mapping/main/mapping.csv"


class FamilyMapper:
    def __init__(self, mapping_path: str | None = None):
        self._regex_rules: list[tuple[re.Pattern, str]] = []
        self._alias_map: dict[str, str] = {}  # lowered alias to canonical name

        if mapping_path:
            self._load_csv(mapping_path)

    def _load_csv(self, path: str):
        """Load regex rules from a certtools/malware_name_mapping CSV."""
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) < 2:
                    continue
                pattern_str = row[0].strip().strip('"')
                canonical = row[1].strip().strip('"')
                try:
                    compiled = re.compile(pattern_str, re.IGNORECASE)
                    self._regex_rules.append((compiled, canonical))
                except re.error:
                    continue

    def add_aliases(self, canonical: str, aliases: list[str]):
        """Register additional aliases (e.g., from MISP Galaxy synonyms)."""
        canonical_lower = canonical.lower()
        for alias in aliases:
            self._alias_map[alias.lower()] = canonical_lower

    def resolve(self, name: str) -> str:
        """Resolve a malware name to its canonical form.

        Checks regex rules first, then the alias map.
        Returns lowercased input if no match found.
        """
        if not name:
            return ""

        name_lower = name.lower().strip()

        # Try regex rules first
        for pattern, canonical in self._regex_rules:
            if pattern.match(name_lower):
                return canonical

        # Try alias map
        if name_lower in self._alias_map:
            return self._alias_map[name_lower]

        return name_lower

    @classmethod
    def from_url(cls, url: str = MAPPING_URL) -> "FamilyMapper":
        """Download the mapping CSV from GitHub and build a mapper."""
        import requests
        resp = requests.get(url)
        resp.raise_for_status()

        import tempfile
        import os
        tmpdir = tempfile.mkdtemp()
        path = os.path.join(tmpdir, "mapping.csv")
        with open(path, "w", encoding="utf-8") as f:
            f.write(resp.text)

        return cls(path)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_family_mapping.py -v`
Expected: 4 passed

- [ ] **Step 5: Commit**

```bash
git add normalizer/family_mapping.py tests/test_family_mapping.py
git commit -m "feat: add FamilyMapper for alias resolution via regex rules"
```

---

### Task 9: Classifier

**Files:**
- Create: `normalizer/classifier.py`
- Create: `tests/test_classifier.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_classifier.py`:

```python
import pytest
from normalizer.classifier import classify


def test_clamav_pua_prefix():
    assert classify(clamav="PUA.Win32.Adware.SomeApp", tags="") == "pua"


def test_clamav_adware_prefix():
    assert classify(clamav="Adware.AndroidOS.Ewind", tags="") == "adware"


def test_tag_adware():
    assert classify(clamav="", tags="stealer|adware|packed") == "adware"


def test_tag_pup():
    assert classify(clamav="", tags="pup|downloader") == "pup"


def test_tag_pua():
    assert classify(clamav="", tags="pua") == "pua"


def test_tag_riskware():
    assert classify(clamav="", tags="riskware") == "riskware"


def test_tag_bundler():
    assert classify(clamav="", tags="bundler|installer") == "pua"


def test_default_malware():
    assert classify(clamav="Win.Trojan.Generic", tags="trojan|packed") == "malware"


def test_empty_inputs():
    assert classify(clamav="", tags="") == "malware"


def test_clamav_takes_priority_over_tags():
    # ClamAV says PUA, tags say riskware. ClamAV wins (rule 1 before rule 5)
    assert classify(clamav="PUA.Win32.Something", tags="riskware") == "pua"


def test_misp_classification_override():
    assert classify(clamav="", tags="", misp_classification="adware") == "adware"


def test_misp_only_used_when_others_empty():
    # ClamAV PUA takes priority over MISP riskware
    assert classify(clamav="PUA.Win32.X", tags="", misp_classification="riskware") == "pua"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_classifier.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Write the implementation**

Create `normalizer/classifier.py`:

```python
"""Classification logic: malware vs pup/pua/adware/riskware.

Rules applied in priority order. First match wins.
"""


def classify(clamav: str = "", tags: str = "", misp_classification: str = "") -> str:
    """Classify a sample based on ClamAV signature, tags, and MISP type.

    Args:
        clamav: ClamAV detection name (e.g., "PUA.Win32.Adware.Foo")
        tags: Pipe-separated tags (e.g., "stealer|adware|packed")
        misp_classification: Classification from MISP Galaxy (e.g., "adware")

    Returns:
        One of: "malware", "pup", "pua", "adware", "riskware"
    """
    clamav_lower = clamav.lower()
    tags_lower = tags.lower()
    tag_set = set(tags_lower.split("|")) if tags_lower else set()

    # Rule 1: ClamAV PUA prefix
    if clamav_lower.startswith("pua."):
        return "pua"

    # Rule 2: ClamAV Adware prefix
    if clamav_lower.startswith("adware."):
        return "adware"

    # Rule 3: Tag "adware"
    if "adware" in tag_set:
        return "adware"

    # Rule 4: Tag "pup" or "pua"
    if "pup" in tag_set:
        return "pup"
    if "pua" in tag_set:
        return "pua"

    # Rule 5: Tag "riskware"
    if "riskware" in tag_set:
        return "riskware"

    # Rule 6: Tag "bundler"
    if "bundler" in tag_set:
        return "pua"

    # Rule 7: MISP Galaxy classification
    if misp_classification and misp_classification.lower() in ("adware", "pup", "pua", "riskware"):
        return misp_classification.lower()

    # Rule 9: Default
    return "malware"
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_classifier.py -v`
Expected: 11 passed

- [ ] **Step 5: Commit**

```bash
git add normalizer/classifier.py tests/test_classifier.py
git commit -m "feat: add classifier with priority-ordered PUP/PUA detection rules"
```

---

### Task 10: Normalizer (Merge Raw to Normalized)

**Files:**
- Create: `normalizer/normalize.py`
- Create: `tests/test_normalize.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_normalize.py`:

```python
import csv
import json
import os
import tempfile
import pytest
from normalizer.normalize import Normalizer


def write_csv(path, fieldnames, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


@pytest.fixture
def pipeline_dirs():
    with tempfile.TemporaryDirectory() as tmpdir:
        raw_dir = os.path.join(tmpdir, "raw")
        norm_dir = os.path.join(tmpdir, "normalized")
        os.makedirs(raw_dir)
        os.makedirs(norm_dir)

        # Write raw malwarebazaar data
        write_csv(
            os.path.join(raw_dir, "malwarebazaar.csv"),
            ["sha256", "sha1", "md5", "file_name", "file_type", "file_size",
             "family", "tags", "clamav_detection", "first_seen", "last_seen",
             "imphash", "tlsh", "ssdeep"],
            [
                {
                    "sha256": "a" * 64, "sha1": "b" * 40, "md5": "c" * 32,
                    "file_name": "evil.exe", "file_type": "exe", "file_size": "1234",
                    "family": "AgentTesla", "tags": "stealer|keylogger",
                    "clamav_detection": "Win.Trojan.AgentTesla", "first_seen": "2024-01-01",
                    "last_seen": "2024-06-01", "imphash": "", "tlsh": "", "ssdeep": "",
                },
                {
                    "sha256": "d" * 64, "sha1": "e" * 40, "md5": "f" * 32,
                    "file_name": "adware.exe", "file_type": "exe", "file_size": "5678",
                    "family": "", "tags": "adware|bundler",
                    "clamav_detection": "PUA.Win32.Adware.InstallCore", "first_seen": "2024-02-01",
                    "last_seen": "", "imphash": "", "tlsh": "", "ssdeep": "",
                },
            ],
        )

        # Write raw threatfox data
        write_csv(
            os.path.join(raw_dir, "threatfox.csv"),
            ["ioc_id", "ioc_type", "ioc_value", "threat_type", "family",
             "family_aliases", "confidence", "first_seen", "last_seen", "tags"],
            [
                {
                    "ioc_id": "1", "ioc_type": "ip:port", "ioc_value": "1.2.3.4:443",
                    "threat_type": "botnet_cc", "family": "Emotet",
                    "family_aliases": "Emotet,Heodo", "confidence": "90",
                    "first_seen": "2024-01-15", "last_seen": "", "tags": "emotet",
                },
            ],
        )

        # Write raw MISP galaxy data
        write_csv(
            os.path.join(raw_dir, "misp_galaxy_families.csv"),
            ["canonical_name", "aliases", "classification", "description", "uuid", "source_cluster"],
            [
                {
                    "canonical_name": "Emotet", "aliases": "Heodo|Geodo",
                    "classification": "malware", "description": "Banking trojan.",
                    "uuid": "uuid-1", "source_cluster": "malpedia.json",
                },
                {
                    "canonical_name": "InstallCore", "aliases": "InstallCore PUA",
                    "classification": "adware", "description": "Adware bundler.",
                    "uuid": "uuid-2", "source_cluster": "malpedia.json",
                },
            ],
        )

        # Write raw MITRE data
        write_csv(
            os.path.join(raw_dir, "mitre_attack.csv"),
            ["mitre_id", "name", "description", "aliases", "techniques"],
            [
                {
                    "mitre_id": "S0367", "name": "Emotet",
                    "description": "Banking trojan.", "aliases": "Emotet|Heodo|Geodo",
                    "techniques": "T1059|T1547",
                },
            ],
        )

        # Write empty yaraify
        write_csv(
            os.path.join(raw_dir, "yaraify_rules.csv"),
            ["rule_name", "author", "description", "malpedia_family",
             "matching_tlp", "sharing_tlp", "yarahub_uuid", "date"],
            [],
        )

        yield raw_dir, norm_dir


def test_normalizer_produces_all_output_files(pipeline_dirs):
    raw_dir, norm_dir = pipeline_dirs
    normalizer = Normalizer(raw_dir, norm_dir)
    normalizer.run()

    expected_files = [
        "malware_samples.csv", "malware_samples.json",
        "pup_pua_samples.csv", "pup_pua_samples.json",
        "malware_families.csv", "malware_families.json",
        "iocs.csv", "iocs.json",
        "techniques.csv", "techniques.json",
        "stats.json",
    ]
    for fname in expected_files:
        assert os.path.exists(os.path.join(norm_dir, fname)), f"Missing: {fname}"


def test_normalizer_splits_malware_vs_pup(pipeline_dirs):
    raw_dir, norm_dir = pipeline_dirs
    normalizer = Normalizer(raw_dir, norm_dir)
    normalizer.run()

    with open(os.path.join(norm_dir, "malware_samples.csv"), newline="", encoding="utf-8") as f:
        malware_rows = list(csv.DictReader(f))
    with open(os.path.join(norm_dir, "pup_pua_samples.csv"), newline="", encoding="utf-8") as f:
        pup_rows = list(csv.DictReader(f))

    # "a"*64 is AgentTesla (malware), "d"*64 has PUA ClamAV (pup_pua)
    malware_hashes = [r["sha256"] for r in malware_rows]
    pup_hashes = [r["sha256"] for r in pup_rows]

    assert "a" * 64 in malware_hashes
    assert "d" * 64 in pup_hashes


def test_normalizer_writes_iocs(pipeline_dirs):
    raw_dir, norm_dir = pipeline_dirs
    normalizer = Normalizer(raw_dir, norm_dir)
    normalizer.run()

    with open(os.path.join(norm_dir, "iocs.csv"), newline="", encoding="utf-8") as f:
        ioc_rows = list(csv.DictReader(f))

    assert len(ioc_rows) >= 1
    assert ioc_rows[0]["ioc_value"] == "1.2.3.4:443"
    assert ioc_rows[0]["confidence"] == "90"


def test_normalizer_writes_families(pipeline_dirs):
    raw_dir, norm_dir = pipeline_dirs
    normalizer = Normalizer(raw_dir, norm_dir)
    normalizer.run()

    with open(os.path.join(norm_dir, "malware_families.csv"), newline="", encoding="utf-8") as f:
        family_rows = list(csv.DictReader(f))

    names = [r["canonical_name"] for r in family_rows]
    assert "Emotet" in names


def test_normalizer_json_mirrors_match_csv(pipeline_dirs):
    raw_dir, norm_dir = pipeline_dirs
    normalizer = Normalizer(raw_dir, norm_dir)
    normalizer.run()

    with open(os.path.join(norm_dir, "malware_samples.csv"), newline="", encoding="utf-8") as f:
        csv_rows = list(csv.DictReader(f))
    with open(os.path.join(norm_dir, "malware_samples.json"), encoding="utf-8") as f:
        json_rows = json.load(f)

    assert len(csv_rows) == len(json_rows)


def test_stats_json(pipeline_dirs):
    raw_dir, norm_dir = pipeline_dirs
    normalizer = Normalizer(raw_dir, norm_dir)
    normalizer.run()

    with open(os.path.join(norm_dir, "stats.json"), encoding="utf-8") as f:
        stats = json.load(f)

    assert "total_samples" in stats
    assert "total_families" in stats
    assert "total_pup_pua" in stats
    assert "last_updated" in stats
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_normalize.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Write the implementation**

Create `normalizer/normalize.py`:

```python
"""Main normalizer: merge raw collector CSVs into normalized output files."""

import csv
import json
import os
from datetime import datetime, timezone

from normalizer.classifier import classify
from normalizer.family_mapping import FamilyMapper

SAMPLE_FIELDNAMES = [
    "sha256", "sha1", "md5", "family", "family_aliases", "classification",
    "tags", "confidence", "clamav_detection", "first_seen", "last_seen",
    "source", "mitre_techniques",
]

FAMILY_FIELDNAMES = [
    "canonical_name", "aliases", "classification", "description",
    "mitre_techniques", "sources",
]

IOC_FIELDNAMES = [
    "ioc_type", "ioc_value", "family", "confidence",
    "threat_type", "first_seen", "last_seen", "source",
]

TECHNIQUE_FIELDNAMES = [
    "technique_id", "technique_name", "tactic", "families",
]


class Normalizer:
    def __init__(self, raw_dir: str, output_dir: str):
        self.raw_dir = raw_dir
        self.output_dir = output_dir
        self.mapper = FamilyMapper()
        self._misp_families: dict[str, dict] = {}
        self._mitre_data: dict[str, dict] = {}
        self._mitre_technique_to_families: dict[str, set] = {}

    def run(self):
        self._load_misp_galaxy()
        self._load_mitre_attack()
        self._load_mapping_rules()

        samples = self._collect_samples()
        iocs = self._collect_iocs()
        families = self._build_family_list(samples)
        techniques = self._build_technique_list()

        malware = [s for s in samples if s["classification"] == "malware"]
        pup_pua = [s for s in samples if s["classification"] != "malware"]

        self._write_csv_and_json("malware_samples", SAMPLE_FIELDNAMES, malware)
        self._write_csv_and_json("pup_pua_samples", SAMPLE_FIELDNAMES, pup_pua)
        self._write_csv_and_json("malware_families", FAMILY_FIELDNAMES, families)
        self._write_csv_and_json("iocs", IOC_FIELDNAMES, iocs)
        self._write_csv_and_json("techniques", TECHNIQUE_FIELDNAMES, techniques)

        stats = {
            "total_samples": len(samples),
            "total_malware": len(malware),
            "total_pup_pua": len(pup_pua),
            "total_families": len(families),
            "total_iocs": len(iocs),
            "last_updated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        stats_path = os.path.join(self.output_dir, "stats.json")
        with open(stats_path, "w", encoding="utf-8") as f:
            json.dump(stats, f, indent=2)

        print(f"  Normalized: {len(malware)} malware, {len(pup_pua)} PUP/PUA, "
              f"{len(families)} families, {len(iocs)} IOCs")

    def _load_mapping_rules(self):
        """Try to load malware_name_mapping regexes. Fall back to MISP aliases only."""
        try:
            self.mapper = FamilyMapper.from_url()
        except Exception as e:
            print(f"  Could not load malware_name_mapping: {e}. Using MISP aliases only.")

        # Add MISP Galaxy synonyms to the mapper
        for name, data in self._misp_families.items():
            aliases_str = data.get("aliases", "")
            if aliases_str:
                alias_list = aliases_str.split("|")
                self.mapper.add_aliases(name, alias_list)

    def _load_misp_galaxy(self):
        path = os.path.join(self.raw_dir, "misp_galaxy_families.csv")
        if not os.path.exists(path):
            return
        with open(path, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                name = row.get("canonical_name", "")
                if name:
                    self._misp_families[name] = row

    def _load_mitre_attack(self):
        path = os.path.join(self.raw_dir, "mitre_attack.csv")
        if not os.path.exists(path):
            return
        with open(path, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                name = row.get("name", "")
                if name:
                    self._mitre_data[name.lower()] = row
                    # Build technique to families index
                    techniques = row.get("techniques", "")
                    if techniques:
                        for tid in techniques.split("|"):
                            if tid not in self._mitre_technique_to_families:
                                self._mitre_technique_to_families[tid] = set()
                            self._mitre_technique_to_families[tid].add(name)

    def _collect_samples(self):
        """Read malwarebazaar raw CSV, classify, and normalize."""
        samples = {}  # keyed by sha256

        path = os.path.join(self.raw_dir, "malwarebazaar.csv")
        if not os.path.exists(path):
            return list(samples.values())

        with open(path, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                sha256 = row.get("sha256", "").strip()
                if not sha256:
                    continue

                family_raw = row.get("family", "")
                family = self.mapper.resolve(family_raw) if family_raw else ""
                tags = row.get("tags", "")
                clamav = row.get("clamav_detection", "")

                # Look up MISP classification for this family
                misp_class = ""
                if family_raw:
                    misp_entry = self._misp_families.get(family_raw)
                    if misp_entry:
                        misp_class = misp_entry.get("classification", "")

                classification = classify(clamav=clamav, tags=tags, misp_classification=misp_class)

                # Look up aliases
                family_aliases = ""
                if family_raw and family_raw in self._misp_families:
                    family_aliases = self._misp_families[family_raw].get("aliases", "")

                # Look up MITRE techniques
                mitre_techniques = ""
                mitre_entry = self._mitre_data.get(family.lower()) or self._mitre_data.get(family_raw.lower())
                if mitre_entry:
                    mitre_techniques = mitre_entry.get("techniques", "")

                samples[sha256] = {
                    "sha256": sha256,
                    "sha1": row.get("sha1", ""),
                    "md5": row.get("md5", ""),
                    "family": family or family_raw,
                    "family_aliases": family_aliases,
                    "classification": classification,
                    "tags": tags,
                    "confidence": "",
                    "clamav_detection": clamav,
                    "first_seen": row.get("first_seen", ""),
                    "last_seen": row.get("last_seen", ""),
                    "source": "malwarebazaar",
                    "mitre_techniques": mitre_techniques,
                }

        return list(samples.values())

    def _collect_iocs(self):
        """Read threatfox raw CSV and normalize."""
        iocs = []
        path = os.path.join(self.raw_dir, "threatfox.csv")
        if not os.path.exists(path):
            return iocs

        with open(path, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                family_raw = row.get("family", "")
                family = self.mapper.resolve(family_raw) if family_raw else ""

                iocs.append({
                    "ioc_type": row.get("ioc_type", ""),
                    "ioc_value": row.get("ioc_value", ""),
                    "family": family or family_raw,
                    "confidence": row.get("confidence", ""),
                    "threat_type": row.get("threat_type", ""),
                    "first_seen": row.get("first_seen", ""),
                    "last_seen": row.get("last_seen", ""),
                    "source": "threatfox",
                })

        return iocs

    def _build_family_list(self, samples):
        """Build the malware_families output from MISP Galaxy + observed samples."""
        families = {}

        # Start with MISP Galaxy families
        for name, data in self._misp_families.items():
            mitre_entry = self._mitre_data.get(name.lower())
            techniques = mitre_entry.get("techniques", "") if mitre_entry else ""

            families[name.lower()] = {
                "canonical_name": name,
                "aliases": data.get("aliases", ""),
                "classification": data.get("classification", "malware"),
                "description": data.get("description", ""),
                "mitre_techniques": techniques,
                "sources": "misp_galaxy",
            }

        # Add families observed in samples but not in MISP
        for sample in samples:
            family = sample.get("family", "")
            if not family:
                continue
            key = family.lower()
            if key not in families:
                families[key] = {
                    "canonical_name": family,
                    "aliases": sample.get("family_aliases", ""),
                    "classification": sample.get("classification", "malware"),
                    "description": "",
                    "mitre_techniques": sample.get("mitre_techniques", ""),
                    "sources": "malwarebazaar",
                }
            else:
                existing = families[key]
                if "malwarebazaar" not in existing["sources"]:
                    existing["sources"] += "|malwarebazaar"

        return list(families.values())

    def _build_technique_list(self):
        """Build techniques output from MITRE ATT&CK data."""
        techniques = []
        for tid, family_set in sorted(self._mitre_technique_to_families.items()):
            techniques.append({
                "technique_id": tid,
                "technique_name": "",  # Names not in the raw CSV; enrichable later
                "tactic": "",
                "families": "|".join(sorted(family_set)),
            })
        return techniques

    def _write_csv_and_json(self, basename, fieldnames, rows):
        csv_path = os.path.join(self.output_dir, f"{basename}.csv")
        json_path = os.path.join(self.output_dir, f"{basename}.json")

        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(rows, f, indent=2, default=str)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_normalize.py -v`
Expected: 6 passed

- [ ] **Step 5: Commit**

```bash
git add normalizer/normalize.py tests/test_normalize.py
git commit -m "feat: add normalizer merging raw data into classified output files"
```

---

### Task 11: GitHub Actions Workflows

**Files:**
- Create: `.github/workflows/daily-update.yml`
- Create: `.github/workflows/manual-trigger.yml`

- [ ] **Step 1: Create the daily update workflow**

Create `.github/workflows/daily-update.yml`:

```yaml
name: Daily Threat Intel Update

on:
  schedule:
    - cron: '0 6 * * *'  # 6 AM UTC daily
  workflow_dispatch:

permissions:
  contents: write

jobs:
  update:
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

      - name: Run MalwareBazaar collector
        env:
          MALWAREBAZAAR_API_KEY: ${{ secrets.MALWAREBAZAAR_API_KEY }}
        run: python run_pipeline.py --collector malwarebazaar --skip-normalize
        continue-on-error: true

      - name: Run ThreatFox collector
        env:
          THREATFOX_API_KEY: ${{ secrets.THREATFOX_API_KEY }}
        run: python run_pipeline.py --collector threatfox --skip-normalize
        continue-on-error: true

      - name: Run YARAify collector
        env:
          YARAIFY_API_KEY: ${{ secrets.YARAIFY_API_KEY }}
        run: python run_pipeline.py --collector yaraify --skip-normalize
        continue-on-error: true

      - name: Run MITRE ATT&CK collector
        run: python run_pipeline.py --collector mitre_attack --skip-normalize
        continue-on-error: true

      - name: Run MISP Galaxy collector
        run: python run_pipeline.py --collector misp_galaxy --skip-normalize
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

          SAMPLE_COUNT=$(python -c "import json; d=json.load(open('data/normalized/stats.json')); print(d['total_samples'])")
          FAMILY_COUNT=$(python -c "import json; d=json.load(open('data/normalized/stats.json')); print(d['total_families'])")

          git add data/
          git commit -m "data: daily update $(date -u +%Y-%m-%d) (${SAMPLE_COUNT} samples, ${FAMILY_COUNT} families)"
          git push
```

- [ ] **Step 2: Create the manual trigger workflow**

Create `.github/workflows/manual-trigger.yml`:

```yaml
name: Manual Pipeline Run

on:
  workflow_dispatch:
    inputs:
      collector:
        description: 'Collector to run (or "all")'
        required: false
        default: 'all'
        type: choice
        options:
          - all
          - malwarebazaar
          - threatfox
          - yaraify
          - mitre_attack
          - misp_galaxy

permissions:
  contents: write

jobs:
  run:
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

      - name: Run pipeline
        env:
          MALWAREBAZAAR_API_KEY: ${{ secrets.MALWAREBAZAAR_API_KEY }}
          THREATFOX_API_KEY: ${{ secrets.THREATFOX_API_KEY }}
          YARAIFY_API_KEY: ${{ secrets.YARAIFY_API_KEY }}
        run: python run_pipeline.py --collector ${{ inputs.collector }}

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
          git commit -m "data: manual update $(date -u +%Y-%m-%d) (${{ inputs.collector }})"
          git push
```

- [ ] **Step 3: Verify YAML syntax**

Run: `python -c "import yaml; yaml.safe_load(open('.github/workflows/daily-update.yml')); yaml.safe_load(open('.github/workflows/manual-trigger.yml')); print('YAML valid')"`
Expected: `YAML valid`

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/daily-update.yml .github/workflows/manual-trigger.yml
git commit -m "ci: add daily update and manual trigger GitHub Actions workflows"
```

---

### Task 12: GitHub Pages — Dashboard and Style

**Files:**
- Create: `docs/index.html`
- Create: `docs/style.css`

- [ ] **Step 1: Create the CSS**

Create `docs/style.css` with a dark theme (GitHub-dark inspired):
- CSS custom properties for colors: bg (#0d1117), surface (#161b22), border (#30363d), text (#e6edf3), accent (#58a6ff), plus semantic colors for malware (red), pup (orange), families (purple), iocs (blue), total (green)
- Base reset, body font stack, `.container` max-width 1200px
- Nav bar with logo + links, active state
- `.stats-grid` using CSS grid with auto-fit columns
- `.stat-card` with label + value, color-coded by `.value.malware`, `.value.pup`, etc.
- Table styles with sticky headers, border-collapse, alternating borders
- `.badge` inline-block with colored backgrounds for each classification
- Form inputs (text, select) and buttons styled for dark theme
- `.filters` flex row with gap, wrapping
- `.pagination` centered flex row
- `.loading` centered muted text
- Footer with top border

See the spec document `docs/superpowers/specs/2026-05-20-threat-intel-reference-design.md` for the full CSS. The CSS is purely cosmetic and contains no logic.

- [ ] **Step 2: Create the dashboard HTML**

Create `docs/index.html`:
- Standard HTML5 boilerplate with charset, viewport, title, stylesheet link
- Nav bar with links to all 4 pages, "Dashboard" marked active
- Main section with h1 "Dashboard", subtitle with `#last-updated` span
- Stats grid with 5 cards: Total Samples, Malware, PUP/PUA/Adware/Riskware, Families, IOCs — each with `id` attributes for JS population
- Footer crediting data sources
- Script tag loading `app.js`, then inline script calling `loadStats()` and setting textContent of each stat element

- [ ] **Step 3: Commit**

```bash
git add docs/index.html docs/style.css
git commit -m "feat: add GitHub Pages dashboard with stats cards"
```

---

### Task 13: GitHub Pages — App.js and Search Page

**Files:**
- Create: `docs/app.js`
- Create: `docs/search.html`

- [ ] **Step 1: Create app.js with data loading and search utilities**

Create `docs/app.js` with these functions:

- `rawUrl(path)` — builds raw GitHub content URL from configurable REPO_OWNER, REPO_NAME, BRANCH constants
- `fetchJSON(path)` — fetches and caches JSON data
- `loadStats()`, `loadMalwareSamples()`, `loadPupSamples()`, `loadFamilies()`, `loadIOCs()` — convenience wrappers
- `escapeHtml(str)` — uses `document.createElement('div')` + `textContent` for safe escaping
- `renderBadge(classification)` — creates a span element with appropriate badge class, returns the element (not HTML string)
- `renderTable(containerId, headers, rows, page, pageSize)` — builds table using DOM methods (`document.createElement`), not string concatenation. Creates thead/tbody, uses `textContent` for all data values, uses `renderBadge()` for classification columns, adds pagination buttons with click handlers
- `downloadCSV(rows, headers, filename)` — builds CSV string and triggers download via blob URL

**IMPORTANT:** All DOM rendering must use safe methods (`createElement`, `textContent`, `appendChild`). Do NOT use string-based HTML construction or assignment to element content properties that parse HTML. This prevents XSS if data contains malicious content.

- [ ] **Step 2: Create the search page**

Create `docs/search.html`:
- Nav bar with "Search" marked active
- Filters row: text input for search query, select for classification filter, select for source filter, Search button, Download CSV button
- Results container div
- Inline script that loads both malware and PUP samples via `Promise.all`, merges them, and provides `doSearch()` and `goToPage()` functions
- Search filters by checking if query appears in sha256, md5, family, tags, or clamav_detection fields (case-insensitive includes)
- Uses `renderTable()` from app.js for display

- [ ] **Step 3: Commit**

```bash
git add docs/app.js docs/search.html
git commit -m "feat: add search page with filtering, pagination, and CSV download"
```

---

### Task 14: GitHub Pages — Families and About Pages

**Files:**
- Create: `docs/families.html`
- Create: `docs/about.html`

- [ ] **Step 1: Create the families page**

Create `docs/families.html`:
- Nav bar with "Families" marked active
- Filter row: text input for name/alias search, select for classification, Filter button
- Table container div
- Inline script that loads families via `loadFamilies()`, provides `filterFamilies()` and `goToPage()` functions
- Table columns: Family, Aliases, Classification, Description, Techniques, Sources
- Uses `renderTable()` from app.js

- [ ] **Step 2: Create the about page**

Create `docs/about.html`:
- Nav bar with "About" marked active
- Sections: What is this?, Data Sources (table), Download Data (file list with code elements), Fork and Use Your Own Keys (numbered steps), Contributing (numbered steps)
- Static content, no JavaScript needed
- All links use `style="color:var(--accent)"` for visibility on dark background

- [ ] **Step 3: Commit**

```bash
git add docs/families.html docs/about.html
git commit -m "feat: add families browser and about page for GitHub Pages"
```

---

### Task 15: README

**Files:**
- Create: `README.md`

- [ ] **Step 1: Create the README**

Create `README.md` with sections:
- Title and one-line description
- "What's in the data?" — table of normalized output files
- "Data Sources" — bulleted list with links to each source
- "How it works" — 3-step pipeline description
- "Quick start" subsections: Use the data (curl example), Run locally (clone + pip + env vars + run), Fork and use your own keys (4-step guide)
- "Classification" — table of classification rules matching the spec
- "Contributing" — link to about page
- "License" — note about source terms

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: add README with usage, data sources, and contributing guide"
```

---

### Task 16: Integration Test — Full Pipeline

**Files:** None new. Validates existing code end-to-end.

- [ ] **Step 1: Run the full test suite**

Run: `python -m pytest tests/ -v`
Expected: All tests pass (approximately 20+ tests across all test files)

- [ ] **Step 2: Run a dry pipeline locally (MITRE + MISP only, no API keys needed)**

Run: `python run_pipeline.py --collector mitre_attack --skip-normalize && python run_pipeline.py --collector misp_galaxy --skip-normalize`
Expected: `data/raw/mitre_attack.csv` and `data/raw/misp_galaxy_families.csv` are created with real data

- [ ] **Step 3: Verify the raw files have data**

Run: `wc -l data/raw/mitre_attack.csv data/raw/misp_galaxy_families.csv`
Expected: Both files have multiple rows (MITRE should have 400+ malware entries, MISP should have 2000+)

- [ ] **Step 4: Run the normalizer on the available raw data**

Run: `python -c "from normalizer.normalize import Normalizer; Normalizer('data/raw', 'data/normalized').run()"`
Expected: Normalized files created in `data/normalized/`, stats.json shows counts

- [ ] **Step 5: Verify normalized output**

Run: `python -c "import json; s=json.load(open('data/normalized/stats.json')); print(f'Samples: {s[\"total_samples\"]}, Families: {s[\"total_families\"]}, PUP/PUA: {s[\"total_pup_pua\"]}')" && head -5 data/normalized/malware_families.csv`
Expected: Non-zero counts for samples and families

- [ ] **Step 6: Commit the initial data**

```bash
git add data/
git commit -m "data: initial seed from MITRE ATT&CK and MISP Galaxy"
```

- [ ] **Step 7: Final commit**

```bash
git add -A
git commit -m "chore: complete v1 threat intel reference project"
```
