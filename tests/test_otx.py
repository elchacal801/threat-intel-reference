import os
import csv
import tempfile
from unittest.mock import patch, MagicMock
import pytest
from collectors.otx import OTXCollector

SAMPLE_PULSES_RESPONSE = {
    "results": [
        {
            "id": "pulse-001", "name": "Emotet Campaign 2024",
            "created": "2024-01-15T12:00:00",
            "tags": ["emotet", "banking"],
            "malware_families": [{"display_name": "Emotet"}],
            "indicators": [
                {"type": "FileHash-SHA256", "indicator": "a" * 64},
                {"type": "domain", "indicator": "evil.example.com"},
                {"type": "IPv4", "indicator": "1.2.3.4"},
                {"type": "email", "indicator": "skip@this.com"},
            ],
        },
    ],
    "next": None,
}

@patch("collectors.otx.OTXCollector.get_api_key", return_value="fake_key")
@patch("requests.Session.get")
def test_collect_extracts_relevant_indicators(mock_get, mock_key):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = SAMPLE_PULSES_RESPONSE
    mock_get.return_value = mock_resp

    with tempfile.TemporaryDirectory() as tmpdir:
        collector = OTXCollector(tmpdir)
        rows = collector.collect()
    assert len(rows) == 3
    types = [r["ioc_type"] for r in rows]
    assert "FileHash-SHA256" in types
    assert "domain" in types
    assert "IPv4" in types
    assert "email" not in types
    assert rows[0]["family"] == "Emotet"

@patch("collectors.otx.OTXCollector.get_api_key", return_value="fake_key")
@patch("requests.Session.get")
def test_run_writes_csv(mock_get, mock_key):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = SAMPLE_PULSES_RESPONSE
    mock_get.return_value = mock_resp

    with tempfile.TemporaryDirectory() as tmpdir:
        collector = OTXCollector(tmpdir)
        collector.run()
        path = os.path.join(tmpdir, "otx_pulses.csv")
        assert os.path.exists(path)
        with open(path, newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        assert len(rows) == 3
