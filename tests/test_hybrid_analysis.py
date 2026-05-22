import os
import csv
import tempfile
from unittest.mock import patch, MagicMock
import pytest
from collectors.hybrid_analysis import HybridAnalysisEnricher, FEED_URL, SEARCH_URL

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


def _mock_get_side_effect(feed_data, search_data):
    """Create a side_effect function that returns different data for feed vs search URLs."""
    def side_effect(url=None, *args, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        if url and "search" in url:
            resp.json.return_value = search_data
        else:
            resp.json.return_value = feed_data
        return resp
    return side_effect


@patch("collectors.hybrid_analysis.HybridAnalysisEnricher.get_api_key", return_value="fake_key")
@patch("requests.Session.get")
def test_collect_from_feed(mock_get, mock_key):
    mock_get.side_effect = _mock_get_side_effect(SAMPLE_FEED_RESPONSE, [])

    with tempfile.TemporaryDirectory() as tmpdir:
        enricher = HybridAnalysisEnricher(tmpdir)
        rows = enricher.collect()

    assert len(rows) >= 1
    assert rows[0]["sha256"] == "a" * 64
    assert rows[0]["vx_family"] == "Emotet"
    assert rows[0]["contacted_domains"] == "c2.evil.com"


@patch("collectors.hybrid_analysis.HybridAnalysisEnricher.get_api_key", return_value="fake_key")
@patch("requests.Session.get")
def test_enrich_hash_merges_behavioral_data(mock_get, mock_key):
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
    search_response = [
        {
            "sha256": "b" * 64, "verdict": "malicious",
            "vx_family": "AgentTesla", "av_detect": "65%",
            "analysis_start_time": "2024-02-01T12:00:00",
            "domains": ["steal.evil.com", "c2.bad.org"],
            "hosts": ["10.0.0.1"],
        },
    ]
    mock_get.side_effect = _mock_get_side_effect(feed_response, search_response)

    with tempfile.TemporaryDirectory() as tmpdir:
        enricher = HybridAnalysisEnricher(tmpdir)
        rows = enricher.collect()

    assert len(rows) == 1
    row = rows[0]
    assert row["sha256"] == "b" * 64
    assert row["vx_family"] == "AgentTesla"
    assert "steal.evil.com" in row["contacted_domains"]
    assert "10.0.0.1" in row["contacted_ips"]


@patch("collectors.hybrid_analysis.HybridAnalysisEnricher.get_api_key", return_value="fake_key")
@patch("requests.Session.get")
def test_enrichment_skips_already_enriched(mock_get, mock_key):
    mock_get.side_effect = _mock_get_side_effect(
        {"data": [{"sha256": "c" * 64, "verdict": 50}]}, []
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        # Pre-populate state file
        with open(os.path.join(tmpdir, "ha_enriched_hashes.txt"), "w") as f:
            f.write("c" * 64 + "\n")

        enricher = HybridAnalysisEnricher(tmpdir)
        enricher.collect()

    # GET should only be called once (for feed), not for search
    assert mock_get.call_count == 1


@patch("collectors.hybrid_analysis.HybridAnalysisEnricher.get_api_key", return_value="fake_key")
@patch("requests.Session.get")
def test_run_writes_csv(mock_get, mock_key):
    mock_get.side_effect = _mock_get_side_effect(SAMPLE_FEED_RESPONSE, SAMPLE_SEARCH_RESPONSE)

    with tempfile.TemporaryDirectory() as tmpdir:
        enricher = HybridAnalysisEnricher(tmpdir)
        enricher.run()
        path = os.path.join(tmpdir, "hybrid_analysis.csv")
        assert os.path.exists(path)
        with open(path, newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        assert len(rows) >= 1
