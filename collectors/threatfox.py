"""Collector for ThreatFox (abuse.ch) full IOC export.

The ThreatFox CSV export has:
- Comment lines starting with #
- One comment line containing the CSV header (quoted, with commas)
- Data lines with quoted values
"""

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

    def _get_field(self, row, *candidates):
        """Try multiple column names, return the first non-empty value found."""
        for key in candidates:
            val = row.get(key, "")
            if val:
                return val.strip().strip('"')
        return ""

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

                comment_lines = []
                data_lines = []
                for line in text:
                    if line.startswith("#"):
                        comment_lines.append(line)
                    else:
                        stripped = line.strip()
                        if stripped:
                            data_lines.append(line)

                if not data_lines:
                    print("  ThreatFox CSV has no data lines")
                    return rows

                # Find the header: comment line with quoted CSV fields
                header_line = None
                for cline in comment_lines:
                    content = cline.lstrip("#").strip()
                    if '"' in content and "," in content:
                        header_line = content

                if not header_line:
                    print("  Could not find header in ThreatFox comment lines")
                    return rows

                # Clean header: strip quotes
                header_line = header_line.replace('"', '')
                lines = [header_line + "\n"] + data_lines

                reader = csv.DictReader(lines)
                print(f"    ThreatFox CSV headers: {reader.fieldnames}")

                for row in reader:
                    parsed = {
                        "ioc_id": self._get_field(row, "ioc_id"),
                        "ioc_type": self._get_field(row, "ioc_type"),
                        "ioc_value": self._get_field(row, "ioc_value", "ioc"),
                        "threat_type": self._get_field(row, "threat_type"),
                        "family": self._get_field(row, "malware_printable"),
                        "family_aliases": self._get_field(row, "malware_alias"),
                        "confidence": self._get_field(row, "confidence_level"),
                        "first_seen": self._get_field(row, "first_seen_utc"),
                        "last_seen": self._get_field(row, "last_seen_utc"),
                        "tags": self._get_field(row, "tags"),
                    }
                    # Only add rows that have at least an IOC value
                    if parsed["ioc_value"]:
                        rows.append(parsed)

        if rows:
            sample = rows[0]
            populated = sum(1 for v in sample.values() if v)
            print(f"    Sample row: {populated}/{len(sample)} fields populated")
            print(f"    First IOC: type={sample['ioc_type']} family={sample['family']} conf={sample['confidence']}")
        else:
            print("    WARNING: No rows with ioc_value found")

        return rows
