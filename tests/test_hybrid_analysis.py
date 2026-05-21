import os
import csv
import tempfile
from unittest.mock import patch, MagicMock
import pytest
from collectors.hybrid_analysis import HybridAnalysisEnricher

SAMPLE_FEED_RESPONSE = {
    "data": [
        {
            "sha256": "a" * 64, "verdict": "malicious",
            "vx_family": "Emotet", "av_detect": "75%",
            "analysis_start_time": "2024-01-15T10:00:00",
            "domains": ["c2.evil.com"], "hosts": ["1.2.3.4"],
        },
    ],
}

@patch("collectors.hybrid_analysis.HybridAnalysisEnricher.get_api_key", return_value="fake_key")
@patch("requests.Session.get")
def test_collect_from_feed(mock_get, mock_key):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = SAMPLE_FEED_RESPONSE
    mock_resp.headers = {"Api-Limits": "100"}
    mock_get.return_value = mock_resp

    with tempfile.TemporaryDirectory() as tmpdir:
        enricher = HybridAnalysisEnricher(tmpdir)
        rows = enricher.collect()
    assert len(rows) >= 1
    assert rows[0]["sha256"] == "a" * 64
    assert rows[0]["vx_family"] == "Emotet"
    assert rows[0]["contacted_domains"] == "c2.evil.com"

@patch("collectors.hybrid_analysis.HybridAnalysisEnricher.get_api_key", return_value="fake_key")
@patch("requests.Session.get")
def test_run_writes_csv(mock_get, mock_key):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = SAMPLE_FEED_RESPONSE
    mock_resp.headers = {"Api-Limits": "100"}
    mock_get.return_value = mock_resp

    with tempfile.TemporaryDirectory() as tmpdir:
        enricher = HybridAnalysisEnricher(tmpdir)
        enricher.run()
        path = os.path.join(tmpdir, "hybrid_analysis.csv")
        assert os.path.exists(path)
        with open(path, newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        assert len(rows) >= 1
