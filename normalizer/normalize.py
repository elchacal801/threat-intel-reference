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
    "contacted_domains", "contacted_ips", "vt_classification", "vt_detection_rate",
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

BEHAVIORAL_FIELDNAMES = [
    "sha256", "indicator_type", "indicator_value", "source", "family", "first_seen",
]


class Normalizer:
    def __init__(self, raw_dir: str, output_dir: str):
        self.raw_dir = raw_dir
        self.output_dir = output_dir
        self.mapper = FamilyMapper()
        self._misp_families: dict[str, dict] = {}
        self._misp_families_lower: dict[str, dict] = {}
        self._mitre_data: dict[str, dict] = {}
        self._mitre_technique_to_families: dict[str, set] = {}
        self._mitre_technique_details: dict[str, dict] = {}
        self._ha_data: dict[str, dict] = {}
        self._vt_data: dict[str, dict] = {}
        self._urlhaus_data: dict[str, list[dict]] = {}

    def run(self):
        self._load_misp_galaxy()
        self._load_mitre_attack()
        self._load_mitre_techniques()
        self._load_mapping_rules()
        self._load_hybrid_analysis()
        self._load_vt_enrichment()
        self._load_urlhaus()

        samples = self._collect_samples()
        iocs = self._collect_iocs()
        families = self._build_family_list(samples)
        techniques = self._build_technique_list()
        behavioral = self._build_behavioral_indicators(samples)

        malware = [s for s in samples if s["classification"] == "malware"]
        pup_pua = [s for s in samples if s["classification"] != "malware"]

        self._write_csv_and_json("malware_samples", SAMPLE_FIELDNAMES, malware)
        self._write_csv_and_json("pup_pua_samples", SAMPLE_FIELDNAMES, pup_pua)
        self._write_csv_and_json("malware_families", FAMILY_FIELDNAMES, families)
        self._write_csv_and_json("iocs", IOC_FIELDNAMES, iocs)
        self._write_csv_and_json("techniques", TECHNIQUE_FIELDNAMES, techniques)
        self._write_csv_and_json("behavioral_indicators", BEHAVIORAL_FIELDNAMES, behavioral)

        stats = {
            "total_samples": len(samples),
            "total_malware": len(malware),
            "total_pup_pua": len(pup_pua),
            "total_families": len(families),
            "total_iocs": len(iocs),
            "total_behavioral_indicators": len(behavioral),
            "last_updated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        stats_path = os.path.join(self.output_dir, "stats.json")
        with open(stats_path, "w", encoding="utf-8") as f:
            json.dump(stats, f, indent=2)

        print(f"  Normalized: {len(malware)} malware, {len(pup_pua)} PUP/PUA, "
              f"{len(families)} families, {len(iocs)} IOCs, {len(behavioral)} behavioral")

    # --- Loaders ---

    def _load_mapping_rules(self):
        try:
            self.mapper = FamilyMapper.from_url()
        except Exception as e:
            print(f"  Could not load malware_name_mapping: {e}. Using MISP aliases only.")
        for name, data in self._misp_families.items():
            aliases_str = data.get("aliases", "")
            if aliases_str:
                self.mapper.add_aliases(name, aliases_str.split("|"))

    def _load_misp_galaxy(self):
        path = os.path.join(self.raw_dir, "misp_galaxy_families.csv")
        if not os.path.exists(path):
            return
        with open(path, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                name = row.get("canonical_name", "")
                if name:
                    self._misp_families[name] = row
                    self._misp_families_lower[name.lower()] = row

    def _load_mitre_attack(self):
        path = os.path.join(self.raw_dir, "mitre_attack.csv")
        if not os.path.exists(path):
            return
        with open(path, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                name = row.get("name", "")
                if name:
                    self._mitre_data[name.lower()] = row
                    techniques = row.get("techniques", "")
                    if techniques:
                        for tid in techniques.split("|"):
                            if tid not in self._mitre_technique_to_families:
                                self._mitre_technique_to_families[tid] = set()
                            self._mitre_technique_to_families[tid].add(name)

    def _load_mitre_techniques(self):
        path = os.path.join(self.raw_dir, "mitre_techniques.csv")
        if not os.path.exists(path):
            return
        with open(path, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                tid = row.get("technique_id", "")
                if tid:
                    self._mitre_technique_details[tid] = row

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

    # --- Collectors ---

    def _collect_samples(self):
        samples = {}
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

                # MISP family lookup (case-insensitive)
                misp_class = ""
                misp_entry = None
                for lookup_key in [family_raw, family_raw.lower(), family]:
                    if lookup_key:
                        misp_entry = self._misp_families_lower.get(lookup_key.lower())
                        if misp_entry:
                            misp_class = misp_entry.get("classification", "")
                            break

                # Enrichment data
                ha_entry = self._ha_data.get(sha256)
                vt_entry = self._vt_data.get(sha256)
                vt_classification = vt_entry.get("vt_classification", "") if vt_entry else ""
                vt_detection_rate = vt_entry.get("vt_detection_rate", "") if vt_entry else ""

                classification = classify(
                    clamav=clamav, tags=tags,
                    misp_classification=misp_class,
                    vt_classification=vt_classification,
                )

                family_aliases = misp_entry.get("aliases", "") if misp_entry else ""

                mitre_techniques = ""
                mitre_entry = self._mitre_data.get(family.lower()) or self._mitre_data.get(family_raw.lower())
                if mitre_entry:
                    mitre_techniques = mitre_entry.get("techniques", "")

                # Contacted domains from HA + URLhaus
                contacted_domains = ""
                contacted_ips = ""
                if ha_entry:
                    contacted_domains = ha_entry.get("contacted_domains", "")
                    contacted_ips = ha_entry.get("contacted_ips", "")

                urlhaus_entries = self._urlhaus_data.get(sha256, [])
                if urlhaus_entries:
                    uh_hosts = [e.get("host", "") for e in urlhaus_entries if e.get("host")]
                    if uh_hosts:
                        existing = set(contacted_domains.split("|")) if contacted_domains else set()
                        existing.update(uh_hosts)
                        existing.discard("")
                        contacted_domains = "|".join(sorted(existing)[:10])

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
                    "contacted_domains": contacted_domains,
                    "contacted_ips": contacted_ips,
                    "vt_classification": vt_classification,
                    "vt_detection_rate": vt_detection_rate,
                }

        return list(samples.values())

    def _collect_iocs(self):
        iocs = []

        # ThreatFox
        tf_path = os.path.join(self.raw_dir, "threatfox.csv")
        if os.path.exists(tf_path):
            with open(tf_path, newline="", encoding="utf-8") as f:
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

        # URLhaus
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

        # OTX
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

        return iocs

    def _build_family_list(self, samples):
        families = {}

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
        techniques = []
        for tid, family_set in sorted(self._mitre_technique_to_families.items()):
            details = self._mitre_technique_details.get(tid, {})
            techniques.append({
                "technique_id": tid,
                "technique_name": details.get("technique_name", ""),
                "tactic": details.get("tactic", ""),
                "families": "|".join(sorted(family_set)),
            })
        return techniques

    def _build_behavioral_indicators(self, samples):
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
                url = uh_entry.get("url", "")
                host = uh_entry.get("host", "")
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

    def _write_csv_and_json(self, basename, fieldnames, rows):
        csv_path = os.path.join(self.output_dir, f"{basename}.csv")
        json_path = os.path.join(self.output_dir, f"{basename}.json")
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(rows, f, indent=2, default=str)
