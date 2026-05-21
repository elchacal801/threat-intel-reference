# Threat Intel Reference

A daily-updated, open-source reference database of known malware, PUPs, PUAs, adware, and riskware — aggregated from multiple free threat intelligence sources.

## What's in the data?

| File | Description |
|---|---|
| `data/normalized/malware_samples.csv` | All malware samples with hashes, family names, classifications |
| `data/normalized/pup_pua_samples.csv` | PUP/PUA/adware/riskware samples |
| `data/normalized/malware_families.csv` | Canonical family list with aliases and descriptions |
| `data/normalized/iocs.csv` | IOCs (IPs, domains, URLs, hashes) with confidence scores |
| `data/normalized/techniques.csv` | MITRE ATT&CK technique-to-family mappings |
| `data/raw/` | Raw per-source CSVs before normalization |

All files available as both CSV and JSON.

## Data Sources

- **[MalwareBazaar](https://bazaar.abuse.ch)** — Malware sample hashes, family signatures, ClamAV detections
- **[ThreatFox](https://threatfox.abuse.ch)** — IOCs with confidence scores and family attribution
- **[YARAify](https://yaraify.abuse.ch)** — YARA rule-to-malware-family mappings
- **[MITRE ATT&CK](https://attack.mitre.org)** — Technique-to-malware relationships
- **[MISP Galaxy](https://github.com/MISP/misp-galaxy)** — Malware family taxonomy with aliases

Family name normalization powered by [malware_name_mapping](https://github.com/certtools/malware_name_mapping).

## How it works

A GitHub Actions pipeline runs daily at 6 AM UTC:

1. **Collectors** pull data from each source into `data/raw/`
2. **Normalizer** merges, deduplicates, classifies (malware vs PUP/PUA), and resolves family aliases
3. **Output** is committed as updated CSV/JSON files in `data/normalized/`

## Quick start

### Use the data

Download any CSV directly:

```bash
curl -O https://raw.githubusercontent.com/elchacal801/threat-intel-reference/main/data/normalized/malware_samples.csv
```

### Run locally

```bash
git clone https://github.com/elchacal801/threat-intel-reference.git
cd threat-intel-reference
pip install -r requirements.txt

export MALWAREBAZAAR_API_KEY="your_key"
export THREATFOX_API_KEY="your_key"
export YARAIFY_API_KEY="your_key"

python run_pipeline.py
```

### Fork & use your own keys

1. Fork this repo
2. Get free API keys at [auth.abuse.ch](https://auth.abuse.ch)
3. Add as GitHub Secrets: `MALWAREBAZAAR_API_KEY`, `THREATFOX_API_KEY`, `YARAIFY_API_KEY`
4. Enable Actions — the daily cron will start updating your fork

## Classification

Samples are classified using these signals (first match wins):

| Signal | Classification |
|---|---|
| ClamAV signature starts with `PUA.` | pua |
| ClamAV signature starts with `Adware.` | adware |
| Tags contain `adware` | adware |
| Tags contain `pup` / `pua` | pup / pua |
| Tags contain `riskware` | riskware |
| Tags contain `bundler` | pua |
| MISP Galaxy family type | as labeled |
| Default | malware |

## Contributing

See the [About page](https://elchacal801.github.io/threat-intel-reference/about.html) for instructions on adding new data sources.

## License

Data is sourced from publicly available threat intelligence feeds. Each source has its own terms of use. See the respective source websites for details.
