import os
import csv
import tempfile
import pytest
from collectors.base import BaseCollector


class DummyCollector(BaseCollector):
    def collect(self):
        return [
            {"sha256": "abc123", "family": "testfam"},
            {"sha256": "def456", "family": "otherfam"},
        ]

    @property
    def source_name(self):
        return "dummy"

    @property
    def fieldnames(self):
        return ["sha256", "family"]


def test_run_writes_csv():
    with tempfile.TemporaryDirectory() as tmpdir:
        collector = DummyCollector(tmpdir)
        collector.run()
        output_path = os.path.join(tmpdir, "dummy.csv")
        assert os.path.exists(output_path)
        with open(output_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        assert len(rows) == 2
        assert rows[0]["sha256"] == "abc123"
        assert rows[1]["family"] == "otherfam"


def test_run_overwrites_existing():
    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = os.path.join(tmpdir, "dummy.csv")
        with open(output_path, "w") as f:
            f.write("old data")
        collector = DummyCollector(tmpdir)
        collector.run()
        with open(output_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        assert len(rows) == 2


def test_get_env_or_config_from_env(monkeypatch):
    monkeypatch.setenv("DUMMY_API_KEY", "env_key_123")
    with tempfile.TemporaryDirectory() as tmpdir:
        collector = DummyCollector(tmpdir)
        assert collector.get_api_key("DUMMY_API_KEY") == "env_key_123"
