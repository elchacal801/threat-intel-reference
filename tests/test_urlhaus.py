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
            "urlhaus_download": "https://evil.com/malware.exe",
            "file_size": 12345, "imphash": None, "ssdeep": None, "tlsh": None,
        },
    ],
}

SAMPLE_URLS_RESPONSE = {
    "query_status": "ok",
    "urls": [
        {
            "id": "123", "url": "https://another.net/dropper.js", "host": "another.net",
            "url_status": "online", "threat": "malware_download",
            "tags": ["js", "dropper"], "date_added": "2024-02-01",
            "reporter": "abuse_ch", "larted": "true",
        },
    ],
}

@patch("collectors.urlhaus.URLhausCollector.get_api_key", return_value="fake_key")
@patch("requests.Session.get")
def test_collect_gets_payloads_and_urls(mock_get, mock_key):
    def side_effect(url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        if "payloads" in url:
            resp.json.return_value = SAMPLE_PAYLOADS_RESPONSE
        else:
            resp.json.return_value = SAMPLE_URLS_RESPONSE
        return resp
    mock_get.side_effect = side_effect

    with tempfile.TemporaryDirectory() as tmpdir:
        collector = URLhausCollector(tmpdir)
        rows = collector.collect()
    assert len(rows) == 2
    # First row is from payloads
    assert rows[0]["sha256"] == "a" * 64
    assert rows[0]["signature"] == "Emotet"
    assert rows[0]["host"] == "evil.com"
    # Second row is from URLs
    assert rows[1]["url"] == "https://another.net/dropper.js"
    assert rows[1]["host"] == "another.net"
    assert rows[1]["sha256"] == ""  # URLs don't have hashes

@patch("collectors.urlhaus.URLhausCollector.get_api_key", return_value="fake_key")
@patch("requests.Session.get")
def test_run_writes_csv(mock_get, mock_key):
    def side_effect(url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        if "payloads" in url:
            resp.json.return_value = SAMPLE_PAYLOADS_RESPONSE
        else:
            resp.json.return_value = SAMPLE_URLS_RESPONSE
        return resp
    mock_get.side_effect = side_effect

    with tempfile.TemporaryDirectory() as tmpdir:
        collector = URLhausCollector(tmpdir)
        collector.run()
        path = os.path.join(tmpdir, "urlhaus.csv")
        assert os.path.exists(path)
        with open(path, newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        assert len(rows) == 2
