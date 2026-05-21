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
