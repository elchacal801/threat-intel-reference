# Threat Intelligence Reference Database — Design Spec

## Overview

A public GitHub repository that aggregates threat intelligence from multiple free sources into a unified, daily-updated reference database of known malware, PUPs, PUAs, adware, and riskware. Data is published as downloadable CSV/JSON files with a lightweight GitHub Pages search UI on top.

The repo is vendor-neutral — designed as a general-purpose community reference, not tied to any specific endpoint detection product.

## Data Sources

### v1 (Launch)

| Source | What We Pull | Auth |
|---|---|---|
| **MalwareBazaar** (abuse.ch) | Daily sample dump — hashes, family signatures, tags, ClamAV detections | API key (free) |
| **ThreatFox** (abuse.ch) | Full IOC export — indicators with confidence scores, family names | API key (free) |
| **YARAify** (abuse.ch) | YARA rule set — rule-to-family mappings, ClamAV matches | API key (free) |
| **MITRE ATT&CK** | STIX JSON dump from GitHub — technique-to-malware mappings | None (public repo) |
| **MISP Galaxy** | Malware family definitions, aliases, descriptions from GitHub | None (public repo) |
| **malware_name_mapping** (certtools) | Regex-based alias-to-canonical-name resolution from GitHub | None (public repo) |

### v2 (Follow-up)

| Source | What We Pull | Auth |
|---|---|---|
| **VirusTotal** | Selective hash enrichment — multi-AV verdicts, `popular_threat_classification` | API key (free, 500/day) |
| **Hybrid Analysis** | Sandbox verdicts, family classification | API key (free) |
| **AlienVault OTX** | Community pulses — IOCs, family names, YARA rules | API key (free) |
| **URLhaus** | Payload hashes + family tags from malicious URLs | API key (free) |
| **GitHub Pages UI** | Searchable/filterable web frontend | N/A |

## Repository Structure

```
threat-intel-reference/
├── .github/
│   └── workflows/
│       ├── daily-update.yml          # Main daily cron (6 AM UTC)
│       └── manual-trigger.yml        # workflow_dispatch for testing
├── collectors/                       # Python scripts, one per source
│   ├── malwarebazaar.py
│   ├── threatfox.py
│   ├── yaraify.py
│   ├── mitre_attack.py
│   └── misp_galaxy.py
├── normalizer/
│   ├── normalize.py                  # Merges raw → normalized
│   └── family_mapping.py            # Alias resolution using malware_name_mapping regexes
├── data/
│   ├── raw/                          # One CSV per source, as-ingested
│   │   ├── malwarebazaar.csv
│   │   ├── threatfox.csv
│   │   ├── yaraify_rules.csv
│   │   ├── mitre_attack.csv
│   │   └── misp_galaxy_families.csv
│   └── normalized/                   # Merged, deduplicated, categorized
│       ├── malware_samples.csv
│       ├── malware_samples.json
│       ├── pup_pua_samples.csv
│       ├── pup_pua_samples.json
│       ├── malware_families.csv
│       ├── malware_families.json
│       ├── iocs.csv
│       ├── iocs.json
│       ├── techniques.csv
│       └── techniques.json
├── docs/                             # GitHub Pages source (static HTML + JS)
│   ├── index.html                    # Dashboard
│   ├── search.html                   # Search/filter UI
│   ├── families.html                 # Family browser
│   ├── about.html                    # Project info + contributing
│   ├── style.css
│   └── app.js
├── tests/                            # Unit tests for collectors + normalizer
├── requirements.txt
├── config.example.yml                # Template showing required secrets
└── README.md
```

## Data Schema

### Normalized Files

**`malware_samples.csv` / `pup_pua_samples.csv`:**

| Column | Type | Description |
|---|---|---|
| `sha256` | string | Primary key |
| `sha1` | string | |
| `md5` | string | |
| `family` | string | Canonical family name (normalized via alias mapping) |
| `family_aliases` | string | Pipe-separated known aliases |
| `classification` | enum | `malware` / `pup` / `pua` / `adware` / `riskware` |
| `tags` | string | Pipe-separated tags from source(s) |
| `confidence` | int | 0-100 where available (ThreatFox), null otherwise |
| `clamav_detection` | string | ClamAV signature name if available |
| `first_seen` | datetime | UTC timestamp |
| `last_seen` | datetime | UTC timestamp |
| `source` | string | Which source(s) contributed this entry |
| `mitre_techniques` | string | Pipe-separated ATT&CK technique IDs |

The split between the two files is based on the `classification` field: `malware` goes to `malware_samples.csv`, everything else (`pup`/`pua`/`adware`/`riskware`) goes to `pup_pua_samples.csv`. A hash appearing in both categories (rare but possible across sources) appears in both files.

**`malware_families.csv`:**

| Column | Type | Description |
|---|---|---|
| `canonical_name` | string | Primary family name |
| `aliases` | string | Pipe-separated aliases |
| `classification` | enum | `malware` / `pup` / `pua` / `adware` / `riskware` |
| `description` | string | Short description from MISP Galaxy |
| `mitre_techniques` | string | Associated ATT&CK technique IDs |
| `sources` | string | Which sources reference this family |

**`iocs.csv`:**

| Column | Type | Description |
|---|---|---|
| `ioc_type` | enum | `hash` / `ip` / `domain` / `url` |
| `ioc_value` | string | The indicator value |
| `family` | string | Canonical family name |
| `confidence` | int | 0-100 |
| `threat_type` | string | From ThreatFox |
| `first_seen` | datetime | UTC timestamp |
| `last_seen` | datetime | UTC timestamp |
| `source` | string | |

**`techniques.csv`:**

| Column | Type | Description |
|---|---|---|
| `technique_id` | string | MITRE ATT&CK ID (e.g., T1059) |
| `technique_name` | string | Human-readable name |
| `tactic` | string | ATT&CK tactic category |
| `families` | string | Pipe-separated families that use this technique |

### JSON mirrors

Each normalized CSV has a corresponding JSON file with the same data structured as an array of objects. The JSON files are consumed by the GitHub Pages frontend.

## GitHub Actions Pipeline

### `daily-update.yml`

**Schedule:** `cron: '0 6 * * *'` (6 AM UTC daily)

**Steps:**

1. Checkout repository
2. Setup Python 3.12 + install `requirements.txt`
3. Run collectors (parallel via matrix or sequential):
   - `malwarebazaar.py` → `data/raw/malwarebazaar.csv`
   - `threatfox.py` → `data/raw/threatfox.csv`
   - `yaraify.py` → `data/raw/yaraify_rules.csv`
   - `mitre_attack.py` → `data/raw/mitre_attack.csv`
   - `misp_galaxy.py` → `data/raw/misp_galaxy_families.csv`
4. Run normalizer:
   - Load `malware_name_mapping` regex rules
   - Merge all raw files into unified schema
   - Resolve aliases → canonical family names
   - Classify each entry (see classification logic below)
   - Deduplicate by sha256
   - Split into malware vs PUP/PUA files
   - Write normalized CSVs + JSON mirrors
5. Generate `data/stats.json` (total families, samples, PUPs, last updated)
6. Commit and push if data changed
   - Commit message: `data: daily update YYYY-MM-DD (X new samples, Y families)`

**Failure handling:** If a single collector fails (source is down), the pipeline continues with the remaining sources. The failed source's raw file is left unchanged from the previous run. A warning is logged in the Action output.

### `manual-trigger.yml`

Same pipeline triggered via `workflow_dispatch`. Accepts an optional `source` input to run a single collector for testing.

### Secrets Required

| Secret | Source | Required |
|---|---|---|
| `MALWAREBAZAAR_API_KEY` | abuse.ch auth portal | Yes |
| `THREATFOX_API_KEY` | abuse.ch auth portal | Yes |
| `YARAIFY_API_KEY` | abuse.ch auth portal | Yes |
| `VT_API_KEY` | virustotal.com | v2 only |

## Classification Logic

PUP/PUA detection is the hardest part since most sources don't label these explicitly. The normalizer applies these rules in priority order:

1. ClamAV signature starts with `PUA.` → `pua`
2. ClamAV signature starts with `Adware.` → `adware`
3. Tags contain `adware` → `adware`
4. Tags contain `pup` or `pua` → `pup` or `pua` respectively
5. Tags contain `riskware` → `riskware`
6. Tags contain `bundler` → `pua`
7. MISP Galaxy family has a type indicating adware/pup/riskware → classified accordingly
8. ThreatFox `threat_type` field → direct mapping where applicable
9. Everything else defaults to `malware`

A sample can only have one classification. If multiple rules match, the first matching rule wins.

## GitHub Pages Site

Static HTML + vanilla JS in `docs/`. No build step, no framework, no npm.

**Pages:**

- **Dashboard (`index.html`)** — summary stats from `stats.json`: total samples, families, PUP/PUA vs malware breakdown, source counts, last updated timestamp
- **Search (`search.html`)** — text search across hashes, family names, tags. Filters: classification type, source, confidence range. Pagination at 50 results/page. CSV download button on results.
- **Families (`families.html`)** — browsable table of all canonical families with alias counts, classification, associated techniques
- **About (`about.html`)** — project description, data source documentation, contributing guide, fork-and-use-your-own-keys instructions

**Data loading:** JSON files fetched client-side from raw GitHub URLs (`https://raw.githubusercontent.com/{owner}/{repo}/main/data/normalized/*.json`). For large files, we may need to split into chunks or use pagination in a future version.

## Technology Stack

- **Language:** Python 3.12
- **Dependencies:** `requests`, `pyyaml`, `csv` (stdlib). No heavy frameworks.
- **CI:** GitHub Actions
- **Frontend:** Static HTML, vanilla CSS, vanilla JS
- **Data format:** CSV (primary) + JSON (for frontend)

## Future Considerations (v2+)

- VirusTotal enrichment worker (rate-limited at 500/day, prioritizing hashes with no classification)
- Hybrid Analysis / OTX / URLhaus collectors
- Data file chunking if normalized files exceed ~50MB
- SQLite release artifact for power users
- Contributor workflow for adding new sources via PR
