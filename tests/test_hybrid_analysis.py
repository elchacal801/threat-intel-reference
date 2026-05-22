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

SAMPLE_SEARCH_RESPONSE = [
    {
        "sha256": "a" * 64, "verdict": "malicious",
        "vx_family": "Emotet", "av_detect": "80%",
        "analysis_start_time": "2024-01-15T10:00:00",
        "domains": ["c2.evil.com", "exfil.bad.org"],
        "hosts": ["1.2.3.4", "5.6.7.8"],
    },
]


@patch("collectors.hybrid_analysis.HybridAnalysisEnricher.get_api_key", return_value="fake_key")
@patch("requests.Session.post")
@patch("requests.Session.get")
def test_collect_from_feed(mock_get, mock_post, mock_key):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = SAMPLE_FEED_RESPONSE
    mock_get.return_value = mock_resp

    # POST for enrichment returns empty (no enrichment data)
    mock_post_resp = MagicMock()
    mock_post_resp.status_code = 200
    mock_post_resp.json.return_value = []
    mock_post.return_value = mock_post_resp

    with tempfile.TemporaryDirectory() as tmpdir:
        enricher = HybridAnalysisEnricher(tmpdir)
        rows = enricher.collect()

    assert len(rows) >= 1
    assert rows[0]["sha256"] == "a" * 64
    assert rows[0]["vx_family"] == "Emotet"
    assert rows[0]["contacted_domains"] == "c2.evil.com"


@patch("collectors.hybrid_analysis.HybridAnalysisEnricher.get_api_key", return_value="fake_key")
@patch("requests.Session.post")
@patch("requests.Session.get")
def test_enrich_hash_merges_behavioral_data(mock_get, mock_post, mock_key):
    # Feed returns hash with empty behavioral data
    feed_response = {
        "data": [
            {
                "sha256": "b" * 64, "verdict": 40,
                "vx_family": "", "av_detect": "",
                "analysis_start_time": "",
                "domains": [], "hosts": [],
            },
        ],
    }
    mock_feed_resp = MagicMock()
    mock_feed_resp.status_code = 200
    mock_feed_resp.json.return_value = feed_response
    mock_get.return_value = mock_feed_resp

    # Per-hash search returns full behavioral data
    mock_search_resp = MagicMock()
    mock_search_resp.status_code = 200
    mock_search_resp.json.return_value = [
        {
            "sha256": "b" * 64, "verdict": "malicious",
            "vx_family": "AgentTesla", "av_detect": "65%",
            "analysis_start_time": "2024-02-01T12:00:00",
            "domains": ["steal.evil.com", "c2.bad.org"],
            "hosts": ["10.0.0.1"],
        },
    ]
    mock_post.return_value = mock_search_resp

    with tempfile.TemporaryDirectory() as tmpdir:
        enricher = HybridAnalysisEnricher(tmpdir)
        rows = enricher.collect()

    assert len(rows) == 1
    row = rows[0]
    assert row["sha256"] == "b" * 64
    # Behavioral data should be merged from enrichment
    assert row["vx_family"] == "AgentTesla"
    assert "steal.evil.com" in row["contacted_domains"]
    assert "10.0.0.1" in row["contacted_ips"]


@patch("collectors.hybrid_analysis.HybridAnalysisEnricher.get_api_key", return_value="fake_key")
@patch("requests.Session.post")
@patch("requests.Session.get")
def test_enrichment_skips_already_enriched(mock_get, mock_post, mock_key):
    mock_feed_resp = MagicMock()
    mock_feed_resp.status_code = 200
    mock_feed_resp.json.return_value = {
        "data": [{"sha256": "c" * 64, "verdict": 50}],
    }
    mock_get.return_value = mock_feed_resp

    with tempfile.TemporaryDirectory() as tmpdir:
        # Pre-populate state file
        with open(os.path.join(tmpdir, "ha_enriched_hashes.txt"), "w") as f:
            f.write("c" * 64 + "\n")

        enricher = HybridAnalysisEnricher(tmpdir)
        enricher.collect()

    # POST should NOT be called since hash is already enriched
    mock_post.assert_not_called()


@patch("collectors.hybrid_analysis.HybridAnalysisEnricher.get_api_key", return_value="fake_key")
@patch("requests.Session.post")
@patch("requests.Session.get")
def test_run_writes_csv(mock_get, mock_post, mock_key):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = SAMPLE_FEED_RESPONSE
    mock_get.return_value = mock_resp

    mock_post_resp = MagicMock()
    mock_post_resp.status_code = 200
    mock_post_resp.json.return_value = SAMPLE_SEARCH_RESPONSE
    mock_post.return_value = mock_post_resp

    with tempfile.TemporaryDirectory() as tmpdir:
        enricher = HybridAnalysisEnricher(tmpdir)
        enricher.run()
        path = os.path.join(tmpdir, "hybrid_analysis.csv")
        assert os.path.exists(path)
        with open(path, newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        assert len(rows) >= 1
