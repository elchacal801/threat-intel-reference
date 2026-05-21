"""Collector for ThreatFox (abuse.ch) full IOC export.

The ThreatFox CSV export has comment lines starting with # and
all field values (including headers) wrapped in double quotes.
"""

import csv
import io
import zipfile

from collectors.base import BaseCollector

EXPORT_URL = "https://threatfox-api.abuse.ch/v2/files/exports/{api_key}/full.csv.zip"
ENV_VAR = "THREATFOX_API_KEY"

# Map from raw CSV column names (after stripping quotes) to our output fields
COLUMN_MAP = {
    "ioc_id": "ioc_id",
    "ioc_type": "ioc_type",
    "ioc_type_desc": None,
    "ioc": "ioc_value",
    "ioc_value": "ioc_value",
    "threat_type": "threat_type",
    "threat_type_desc": None,
    "malware_printable": "family",
    "malware_alias": "family_aliases",
    "malware": None,
    "confidence_level": "confidence",
    "first_seen_utc": "first_seen",
    "last_seen_utc": "last_seen",
    "reporter": None,
    "reference": None,
    "tags": "tags",
}


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

                # ThreatFox CSV format:
                # - Multiple comment lines starting with #
                # - The LAST comment line is the header (e.g., # "first_seen_utc","ioc_id",...)
                # - Data lines follow without #
                comment_lines = []
                data_lines = []
                for line in text:
                    if line.startswith("#"):
                        comment_lines.append(line)
                    else:
                        data_lines.append(line)

                if not data_lines:
                    print("  ThreatFox CSV has no data lines")
                    return rows

                # The last comment line is the header row — strip the leading "# "
                if comment_lines:
                    header_line = comment_lines[-1].lstrip("#").strip()
                    # Strip quotes from header names
                    header_line = header_line.replace('"', '')
                    # Prepend header to data lines
                    lines = [header_line + "\n"] + data_lines
                else:
                    # No comment lines — first data line is the header
                    lines = data_lines
                    lines[0] = lines[0].replace('"', '')

                reader = csv.DictReader(lines)
                actual_headers = reader.fieldnames
                print(f"    ThreatFox CSV headers: {actual_headers[:8]}...")

                for row in reader:
                    # Strip surrounding quotes from all values
                    cleaned = {k: (v or "").strip('"').strip() for k, v in row.items()}

                    # Map columns using flexible lookup
                    def get_field(output_name):
                        """Try to find a value by checking all known source column names."""
                        for src_col, dst_col in COLUMN_MAP.items():
                            if dst_col == output_name and src_col in cleaned:
                                val = cleaned[src_col]
                                if val:
                                    return val
                        return ""

                    rows.append({
                        "ioc_id": get_field("ioc_id"),
                        "ioc_type": get_field("ioc_type"),
                        "ioc_value": get_field("ioc_value"),
                        "threat_type": get_field("threat_type"),
                        "family": get_field("family"),
                        "family_aliases": get_field("family_aliases"),
                        "confidence": get_field("confidence"),
                        "first_seen": get_field("first_seen"),
                        "last_seen": get_field("last_seen"),
                        "tags": get_field("tags"),
                    })

        if rows:
            # Log a sample row for debugging
            sample = rows[0]
            populated = sum(1 for v in sample.values() if v)
            print(f"    Sample row has {populated}/{len(sample)} fields populated")
            if populated == 0:
                print(f"    WARNING: First row is empty. Raw keys: {list(row.items())[:5]}")

        return rows
