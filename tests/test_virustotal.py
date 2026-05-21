import os
import csv
import tempfile
from unittest.mock import patch, MagicMock
import pytest
from collectors.virustotal import VirusTotalEnricher

SAMPLE_VT_RESPONSE = {
    "data": {
        "attributes": {
            "sha256": "a" * 64,
            "last_analysis_stats": {"malicious": 45, "undetected": 27},
            "popular_threat_classification": {
                "suggested_threat_label": "trojan.emotet/heodo",
                "popular_threat_category": [{"value": "trojan"}],
                "popular_threat_name": [{"value": "emotet"}],
            },
            "tags": ["pe", "trojan"],
        },
    },
}

@patch("collectors.virustotal.VirusTotalEnricher.get_api_key", return_value="fake_key")
@patch("collectors.virustotal.VirusTotalEnricher._get_hashes_to_enrich")
@patch("requests.Session.get")
def test_collect_enriches_hash(mock_get, mock_hashes, mock_key):
    mock_hashes.return_value = ["a" * 64]
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = SAMPLE_VT_RESPONSE
    mock_get.return_value = mock_resp

    with tempfile.TemporaryDirectory() as tmpdir:
        enricher = VirusTotalEnricher(tmpdir)
        enricher.batch_size = 1
        rows = enricher.collect()
    assert len(rows) == 1
    assert rows[0]["sha256"] == "a" * 64
    assert rows[0]["vt_family"] == "emotet"
    assert rows[0]["vt_detection_rate"] == "45/72"
    assert rows[0]["vt_classification"] == "trojan"

@patch("collectors.virustotal.VirusTotalEnricher.get_api_key", return_value="fake_key")
@patch("collectors.virustotal.VirusTotalEnricher._get_hashes_to_enrich")
@patch("requests.Session.get")
def test_run_writes_csv_and_state(mock_get, mock_hashes, mock_key):
    mock_hashes.return_value = ["a" * 64]
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = SAMPLE_VT_RESPONSE
    mock_get.return_value = mock_resp

    with tempfile.TemporaryDirectory() as tmpdir:
        enricher = VirusTotalEnricher(tmpdir)
        enricher.batch_size = 1
        enricher.run()
        csv_path = os.path.join(tmpdir, "vt_enrichment.csv")
        assert os.path.exists(csv_path)
        state_path = os.path.join(tmpdir, "vt_enriched_hashes.txt")
        assert os.path.exists(state_path)
        with open(state_path) as f:
            hashes = f.read().strip().split("\n")
        assert "a" * 64 in hashes
