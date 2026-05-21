"""Base collector class with shared HTTP/CSV logic."""

import csv
import os
from abc import ABC, abstractmethod

import requests


class BaseCollector(ABC):
    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        self.session = requests.Session()

    @property
    @abstractmethod
    def source_name(self) -> str:
        """Short name used for the output filename (e.g., 'malwarebazaar')."""

    @property
    @abstractmethod
    def fieldnames(self) -> list[str]:
        """CSV column names for this collector's output."""

    @abstractmethod
    def collect(self) -> list[dict]:
        """Fetch data from the source. Returns a list of row dicts."""

    def run(self):
        """Run the collector and write results to CSV."""
        rows = self.collect()
        output_path = os.path.join(self.output_dir, f"{self.source_name}.csv")
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=self.fieldnames, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)
        print(f"  Wrote {len(rows)} rows to {output_path}")

    def get_api_key(self, env_var: str) -> str:
        """Get API key from environment variable. Raises if not found."""
        key = os.environ.get(env_var)
        if not key:
            raise ValueError(f"API key not found. Set the {env_var} environment variable.")
        return key
