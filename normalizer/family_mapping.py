"""Alias resolution using certtools/malware_name_mapping regexes + MISP Galaxy synonyms."""

import csv
import re


MAPPING_URL = "https://raw.githubusercontent.com/certtools/malware_name_mapping/master/mapping.csv"


class FamilyMapper:
    def __init__(self, mapping_path: str | None = None):
        self._regex_rules: list[tuple[re.Pattern, str]] = []
        self._alias_map: dict[str, str] = {}

        if mapping_path:
            self._load_csv(mapping_path)

    def _load_csv(self, path: str):
        """Load regex rules from a certtools/malware_name_mapping CSV."""
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) < 2:
                    continue
                pattern_str = row[0].strip().strip('"')
                canonical = row[1].strip().strip('"')
                try:
                    compiled = re.compile(pattern_str, re.IGNORECASE)
                    self._regex_rules.append((compiled, canonical))
                except re.error:
                    continue

    def add_aliases(self, canonical: str, aliases: list[str]):
        """Register additional aliases (e.g., from MISP Galaxy synonyms)."""
        canonical_lower = canonical.lower()
        for alias in aliases:
            self._alias_map[alias.lower()] = canonical_lower

    def resolve(self, name: str) -> str:
        """Resolve a malware name to its canonical form.

        Checks regex rules first, then the alias map.
        Returns lowercased input if no match found.
        """
        if not name:
            return ""

        name_lower = name.lower().strip()

        for pattern, canonical in self._regex_rules:
            if pattern.match(name_lower):
                return canonical

        if name_lower in self._alias_map:
            return self._alias_map[name_lower]

        return name_lower

    @classmethod
    def from_url(cls, url: str = MAPPING_URL) -> "FamilyMapper":
        """Download the mapping CSV from GitHub and build a mapper."""
        import requests
        resp = requests.get(url)
        resp.raise_for_status()

        import tempfile
        import os
        tmpdir = tempfile.mkdtemp()
        path = os.path.join(tmpdir, "mapping.csv")
        with open(path, "w", encoding="utf-8") as f:
            f.write(resp.text)

        return cls(path)
