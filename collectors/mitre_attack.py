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

        pattern_id_map = {}
        for obj in objects:
            if obj.get("type") == "attack-pattern":
                ext_refs = obj.get("external_references", [])
                for ref in ext_refs:
                    if ref.get("source_name") == "mitre-attack":
                        pattern_id_map[obj["id"]] = ref["external_id"]
                        break

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
