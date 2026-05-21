# V2: High-Impact Sources — Design Spec

## Overview

Add 4 new threat intelligence sources to the existing pipeline, structured as two tiers: bulk collectors (URLhaus, AlienVault OTX) that run in the daily pipeline, and per-hash enrichers (Hybrid Analysis, VirusTotal) that run separately on a 6-hour cron with rate limiting. Produces a new behavioral indicators file linking hashes to contacted domains/IPs, and enriches existing sample data with VT classifications.

## New Data Sources

### Tier 1 — Bulk Collectors (daily pipeline)

| Source | What We Pull | Auth | Rate Limits |
|---|---|---|---|
| **URLhaus** (abuse.ch) | Recent payloads + URLs — hash→URL→domain linkage | Auth-Key (free, abuse.ch) | None documented |
| **AlienVault OTX** | Subscribed pulse indicators — IOCs with family associations | X-OTX-API-KEY (free) | Generous, undisclosed |

### Tier 2 — Per-Hash Enrichers (6-hour cron)

| Source | What We Pull | Auth | Rate Limits |
|---|---|---|---|
| **Hybrid Analysis** | Detonation feed + hash lookups — behavioral data (contacted domains/IPs, verdict) | api-key header (free) | Dynamic, in response headers |
| **VirusTotal** | Per-hash enrichment — multi-AV verdicts, popular_threat_classification | x-apikey header (free) | 500/day, 4 req/min |

## New Files

### Collectors

- `collectors/urlhaus.py` — URLhaus recent payloads + URLs collector
- `collectors/otx.py` — AlienVault OTX subscribed pulses collector
- `collectors/hybrid_analysis.py` — Hybrid Analysis feed + hash lookup enricher
- `collectors/virustotal.py` — VirusTotal per-hash enricher

### Tests

- `tests/test_urlhaus.py`
- `tests/test_otx.py`
- `tests/test_hybrid_analysis.py`
- `tests/test_virustotal.py`

### Raw Data

- `data/raw/urlhaus.csv`
- `data/raw/otx_pulses.csv`
- `data/raw/hybrid_analysis.csv`
- `data/raw/vt_enrichment.csv`
- `data/raw/vt_enriched_hashes.txt` — state file tracking which hashes have been enriched

### Normalized Data (new)

- `data/normalized/behavioral_indicators.csv` — hash→domain/IP associations
- `data/normalized/behavioral_indicators.json`

### Workflow

- `.github/workflows/enrichment.yml` — 6-hour cron for HA + VT enrichment

## Collector Specifications

### URLhaus Collector (`collectors/urlhaus.py`)

**API calls:**
1. `POST https://urlhaus-api.abuse.ch/v1/payloads/recent/` — recent payloads with linked URLs
2. `GET https://urlhaus-api.abuse.ch/v1/urls/recent/` with `limit=1000` — recent malicious URLs with payload hashes

**Output schema (`data/raw/urlhaus.csv`):**

| Column | Type | Source |
|---|---|---|
| `sha256` | string | payload hash |
| `md5` | string | payload hash |
| `url` | string | serving URL |
| `host` | string | domain/IP from URL |
| `url_status` | string | online/offline/unknown |
| `file_type` | string | e.g., exe, dll, doc |
| `signature` | string | malware family name |
| `tags` | string | pipe-separated |
| `first_seen` | datetime | |

**Deduplication:** By sha256+url pair (same hash served from multiple URLs = multiple rows).

### AlienVault OTX Collector (`collectors/otx.py`)

**API calls:**
1. `GET https://otx.alienvault.com/api/v1/pulses/subscribed` — paginated, extract all indicators from subscribed pulses
2. Filter to relevant indicator types: FileHash-SHA256, FileHash-MD5, IPv4, domain, URL, hostname

**Output schema (`data/raw/otx_pulses.csv`):**

| Column | Type | Source |
|---|---|---|
| `ioc_type` | string | FileHash-SHA256 / IPv4 / domain / URL / hostname |
| `ioc_value` | string | the indicator value |
| `family` | string | from pulse malware_families[0].display_name |
| `pulse_name` | string | name of the containing pulse |
| `pulse_id` | string | OTX pulse ID |
| `created` | datetime | pulse creation date |
| `tags` | string | pipe-separated pulse tags |

**Pagination:** Use `limit=50` and `page` parameter, iterate until no more results.

### Hybrid Analysis Enricher (`collectors/hybrid_analysis.py`)

**API calls:**
1. `GET https://www.hybrid-analysis.com/api/v2/feed/detonation` — latest 250 detonated samples (no per-hash cost)
2. `GET https://www.hybrid-analysis.com/api/v2/search/hash` with sha256 — per-hash lookup for existing MalwareBazaar samples

**Output schema (`data/raw/hybrid_analysis.csv`):**

| Column | Type | Source |
|---|---|---|
| `sha256` | string | sample hash |
| `verdict` | int | 1 (benign) to 5 (malicious) |
| `vx_family` | string | malware family |
| `av_detect_pct` | float | AV detection percentage |
| `contacted_domains` | string | pipe-separated domains from behavioral report |
| `contacted_ips` | string | pipe-separated IPs from behavioral report |
| `analysis_date` | datetime | |

**Accumulation:** Like MalwareBazaar, preserves existing data and only adds new hashes. Reads `data/raw/hybrid_analysis.csv` on startup to avoid re-querying known hashes.

**Rate limiting:** Check response headers for remaining quota. Sleep between requests. Stop if quota exhausted.

### VirusTotal Enricher (`collectors/virustotal.py`)

**API calls:**
1. `GET https://www.virustotal.com/api/v3/files/{sha256}` — per-hash lookup

**Priority queue:**
1. Samples with empty `family` field (unattributed)
2. Samples with no classification signal (no ClamAV, no tags)
3. All other samples, newest `first_seen` first

**Output schema (`data/raw/vt_enrichment.csv`):**

| Column | Type | Source |
|---|---|---|
| `sha256` | string | sample hash |
| `vt_classification` | string | from popular_threat_classification.suggested_threat_label category |
| `vt_detection_rate` | string | e.g., "45/72" |
| `vt_family` | string | from popular_threat_classification.popular_threat_name |
| `vt_tags` | string | pipe-separated |
| `enriched_date` | datetime | |

**State tracking:** `data/raw/vt_enriched_hashes.txt` — one sha256 per line. Checked before each lookup to avoid re-enriching. Appended after each successful lookup.

**Batch size:** 125 hashes per run (500/day ÷ 4 runs at 6-hour intervals). 2-second delay between requests to stay within 4 req/min.

## Normalizer Updates

### New output: `behavioral_indicators.csv`

| Column | Type | Description |
|---|---|---|
| `sha256` | string | Sample hash (links to malware_samples) |
| `indicator_type` | string | `domain` / `ip` / `url` |
| `indicator_value` | string | The actual domain, IP, or URL |
| `source` | string | `hybrid_analysis` / `urlhaus` |
| `family` | string | Canonical family name |
| `first_seen` | datetime | When the association was first observed |

Built from: Hybrid Analysis `contacted_domains`/`contacted_ips` + URLhaus `url`/`host` fields. One row per indicator per sample.

### Updated `malware_samples.csv` — 4 new columns

| Column | Source | Description |
|---|---|---|
| `contacted_domains` | HA + URLhaus | Pipe-separated domains (top 10, summary) |
| `contacted_ips` | HA | Pipe-separated IPs (top 10) |
| `vt_classification` | VT | `malware`/`pup`/`pua`/`adware`/`riskware` |
| `vt_detection_rate` | VT | e.g., `45/72` |

These columns are populated by joining enrichment CSVs during normalization. Samples without enrichment data get empty values.

### Updated `iocs.csv` — new rows

OTX pulse IOCs and URLhaus URLs merge into the existing IOCs file:
- OTX entries: `source` = `otx`, `confidence` from pulse metadata
- URLhaus entries: `source` = `urlhaus`, `confidence` = empty (URLhaus doesn't score confidence)

### Updated classification logic

New rule 8 added to `normalizer/classifier.py`:

```
1. ClamAV starts with PUA. → pua
2. ClamAV starts with Adware. → adware
3. Tags contain adware → adware
4. Tags contain pup/pua → pup/pua
5. Tags contain riskware → riskware
6. Tags contain bundler → pua
7. MISP Galaxy family type → as labeled
8. VT popular_threat_classification → as labeled  [NEW]
9. Default → malware
```

The classifier function gets a new `vt_classification` parameter.

## GitHub Actions

### Updated `daily-update.yml`

Add two new collector steps (between existing collectors and normalizer):

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

### New `enrichment.yml`

```yaml
name: Hash Enrichment
on:
  schedule:
    - cron: '0 */6 * * *'  # Every 6 hours
  workflow_dispatch:
```

Steps:
1. Checkout, setup Python, install deps
2. Run Hybrid Analysis enricher (feed + batch of hash lookups)
3. Run VirusTotal enricher (batch of 125 hashes)
4. Run normalizer (to integrate enrichment data into normalized files)
5. Commit and push if changed

### New Secrets Required

| Secret | Source |
|---|---|
| `URLHAUS_API_KEY` | abuse.ch auth portal |
| `OTX_API_KEY` | otx.alienvault.com registration |
| `HYBRID_ANALYSIS_API_KEY` | hybrid-analysis.com registration |
| `VT_API_KEY` | virustotal.com (already added) |

## Updated `run_pipeline.py`

Add new collectors to the collector map:

```python
from collectors.urlhaus import URLhausCollector
from collectors.otx import OTXCollector

collector_map = {
    ...existing...
    "urlhaus": URLhausCollector,
    "otx": OTXCollector,
}
```

Add new enricher subcommand:

```python
parser.add_argument(
    "--enricher",
    choices=["hybrid_analysis", "virustotal", "all"],
    help="Run a specific enricher",
)
```

Enrichers are separate from collectors — they read existing raw data to determine which hashes to look up.

## Technology Stack (unchanged)

- Python 3.12, requests, PyYAML
- GitHub Actions
- Static HTML/CSS/JS for GitHub Pages
- CSV/JSON data format
