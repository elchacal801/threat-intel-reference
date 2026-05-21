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
            csv_names = [n for n in zf.namelist() if n.endswith(".csv")]
            if not csv_names:
                print("  No CSV found in ThreatFox export zip")
                return rows

            with zf.open(csv_names[0]) as csv_file:
                text = io.TextIOWrapper(csv_file, encoding="utf-8")
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
