"""Collector for ThreatFox (abuse.ch) full IOC export.

The ThreatFox CSV export format:
- Comment lines starting with #
- One comment line is the CSV header (quoted fields, 15 columns)
- Data lines with quoted values
- Header: first_seen_utc,ioc_id,ioc_value,ioc_type,threat_type,
          fk_malware,malware_alias,malware_printable,last_seen_utc,
          confidence_level,is_compromised,reference,tags,anonymous,reporter
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

    def _clean(self, val):
        """Strip quotes and whitespace from a value."""
        if not val:
            return ""
        return val.strip().strip('"').strip()

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

                # Keep header WITH quotes so csv.reader handles quoting consistently
                lines = [header_line + "\n"] + data_lines

                reader = csv.DictReader(lines, quotechar='"', skipinitialspace=True)
                # DictReader will strip quotes from header names automatically
                print(f"    ThreatFox CSV headers ({len(reader.fieldnames)}): {reader.fieldnames[:8]}...")

                for row in reader:
                    parsed = {
                        "ioc_id": self._clean(row.get("ioc_id", "")),
                        "ioc_type": self._clean(row.get("ioc_type", "")),
                        "ioc_value": self._clean(row.get("ioc_value", "") or row.get("ioc", "")),
                        "threat_type": self._clean(row.get("threat_type", "")),
                        "family": self._clean(row.get("malware_printable", "")),
                        "family_aliases": self._clean(row.get("malware_alias", "")),
                        "confidence": self._clean(row.get("confidence_level", "")),
                        "first_seen": self._clean(row.get("first_seen_utc", "")),
                        "last_seen": self._clean(row.get("last_seen_utc", "")),
                        "tags": self._clean(row.get("tags", "")),
                    }
                    if parsed["ioc_value"]:
                        rows.append(parsed)

        if rows:
            sample = rows[0]
            populated = sum(1 for v in sample.values() if v)
            print(f"    Sample row: {populated}/{len(sample)} fields populated")
            print(f"    First IOC: type={sample['ioc_type']} family={sample['family']} conf={sample['confidence']}")
            # Validate: check row 30 for column alignment
            if len(rows) > 30:
                r30 = rows[30]
                ls = r30.get("last_seen", "")
                if ls and not ls[:2].isdigit() and ls != "":
                    print(f"    WARNING: Column misalignment detected at row 30: last_seen={ls!r}")
                else:
                    print(f"    Column alignment check passed (row 30 last_seen={ls!r})")
        else:
            print("    WARNING: No rows with ioc_value found")

        return rows
