"""Collector for MITRE ATT&CK enterprise malware and technique relationships.

Produces two output files:
- mitre_attack.csv: malware entries with technique IDs
- mitre_techniques.csv: technique ID -> name + tactic lookup
"""

import csv
import os

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

        # Build technique metadata: STIX id -> {technique_id, name, tactic}
        pattern_id_map = {}
        technique_details = {}
        for obj in objects:
            if obj.get("type") == "attack-pattern":
                if obj.get("x_mitre_deprecated", False):
                    continue
                ext_refs = obj.get("external_references", [])
                technique_id = ""
                for ref in ext_refs:
                    if ref.get("source_name") == "mitre-attack":
                        technique_id = ref["external_id"]
                        pattern_id_map[obj["id"]] = technique_id
                        break

                # Extract tactics from kill chain phases
                tactics = []
                for phase in obj.get("kill_chain_phases", []):
                    if phase.get("kill_chain_name") == "mitre-attack":
                        tactics.append(phase["phase_name"])

                if technique_id:
                    technique_details[technique_id] = {
                        "technique_id": technique_id,
                        "technique_name": obj.get("name", ""),
                        "tactic": "|".join(tactics),
                    }

        # Write technique lookup file
        tech_path = os.path.join(self.output_dir, "mitre_techniques.csv")
        with open(tech_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["technique_id", "technique_name", "tactic"])
            writer.writeheader()
            for td in sorted(technique_details.values(), key=lambda x: x["technique_id"]):
                writer.writerow(td)
        print(f"  Wrote {len(technique_details)} techniques to {tech_path}")

        # Build malware entries
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
