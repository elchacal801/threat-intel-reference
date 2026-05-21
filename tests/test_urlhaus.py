import os
import csv
import tempfile
from unittest.mock import patch, MagicMock
import pytest
from collectors.urlhaus import URLhausCollector

SAMPLE_PAYLOADS_RESPONSE = {
    "query_status": "ok",
    "payloads": [
        {
            "sha256_hash": "a" * 64, "md5_hash": "b" * 32,
            "file_type": "exe", "signature": "Emotet", "firstseen": "2024-01-15",
            "urls": [
                {"url": "https://evil.com/malware.exe", "url_status": "online"},
                {"url": "https://bad.org/payload.bin", "url_status": "offline"},
            ],
        },
    ],
}

SAMPLE_URLS_RESPONSE = {
    "query_status": "ok",
    "urls": [
        {
            "url": "https://another.net/dropper.js", "host": "another.net",
            "url_status": "online", "threat": "malware_download",
            "tags": ["js", "dropper"], "dateadded": "2024-02-01",
            "payloads": [
                {"sha256_hash": "c" * 64, "md5_hash": "d" * 32,
                 "file_type": "js", "signature": "SocGholish"},
            ],
        },
    ],
}

@patch("collectors.urlhaus.URLhausCollector.get_api_key", return_value="fake_key")
@patch("requests.Session.post")
@patch("requests.Session.get")
def test_collect_merges_payloads_and_urls(mock_get, mock_post, mock_key):
    mock_post_resp = MagicMock()
    mock_post_resp.status_code = 200
    mock_post_resp.json.return_value = SAMPLE_PAYLOADS_RESPONSE
    mock_post.return_value = mock_post_resp
    mock_get_resp = MagicMock()
    mock_get_resp.status_code = 200
    mock_get_resp.json.return_value = SAMPLE_URLS_RESPONSE
    mock_get.return_value = mock_get_resp

    with tempfile.TemporaryDirectory() as tmpdir:
        collector = URLhausCollector(tmpdir)
        rows = collector.collect()
    assert len(rows) >= 3
    hashes = [r["sha256"] for r in rows]
    assert "a" * 64 in hashes
    assert "c" * 64 in hashes
    emotet_rows = [r for r in rows if r["sha256"] == "a" * 64]
    assert emotet_rows[0]["signature"] == "Emotet"
    assert "evil.com" in emotet_rows[0]["host"]

@patch("collectors.urlhaus.URLhausCollector.get_api_key", return_value="fake_key")
@patch("requests.Session.post")
@patch("requests.Session.get")
def test_run_writes_csv(mock_get, mock_post, mock_key):
    mock_post_resp = MagicMock()
    mock_post_resp.status_code = 200
    mock_post_resp.json.return_value = SAMPLE_PAYLOADS_RESPONSE
    mock_post.return_value = mock_post_resp
    mock_get_resp = MagicMock()
    mock_get_resp.status_code = 200
    mock_get_resp.json.return_value = SAMPLE_URLS_RESPONSE
    mock_get.return_value = mock_get_resp

    with tempfile.TemporaryDirectory() as tmpdir:
        collector = URLhausCollector(tmpdir)
        collector.run()
        path = os.path.join(tmpdir, "urlhaus.csv")
        assert os.path.exists(path)
        with open(path, newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        assert len(rows) >= 3
