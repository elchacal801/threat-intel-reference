import os
import csv
import tempfile
from unittest.mock import patch, MagicMock
import pytest
from collectors.yaraify import YARAifyCollector

SAMPLE_RESPONSE = {
    "query_status": "ok",
    "data": [
        {
            "rule_name": "win_agenttesla_w0", "author": "abuse.ch",
            "description": "Detects AgentTesla", "malpedia_family": "win.agenttesla",
            "yarahub_rule_matching_tlp": "TLP:WHITE", "yarahub_rule_sharing_tlp": "TLP:WHITE",
            "yarahub_uuid": "uuid-1234", "date": "2024-01-15",
        },
        {
            "rule_name": "win_emotet_w1", "author": "researcher",
            "description": "Detects Emotet", "malpedia_family": "win.emotet",
            "yarahub_rule_matching_tlp": "TLP:WHITE", "yarahub_rule_sharing_tlp": "TLP:GREEN",
            "yarahub_uuid": "uuid-5678", "date": "2024-02-20",
        },
    ],
}

@patch("collectors.yaraify.YARAifyCollector.get_api_key", return_value="fake_key")
@patch("requests.Session.post")
def test_collect_parses_response(mock_post, mock_key):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = SAMPLE_RESPONSE
    mock_post.return_value = mock_resp
    with tempfile.TemporaryDirectory() as tmpdir:
        collector = YARAifyCollector(tmpdir)
        rows = collector.collect()
    assert len(rows) == 2
    assert rows[0]["rule_name"] == "win_agenttesla_w0"
    assert rows[0]["malpedia_family"] == "win.agenttesla"
    assert rows[1]["malpedia_family"] == "win.emotet"

@patch("collectors.yaraify.YARAifyCollector.get_api_key", return_value="fake_key")
@patch("requests.Session.post")
def test_run_writes_csv(mock_post, mock_key):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = SAMPLE_RESPONSE
    mock_post.return_value = mock_resp
    with tempfile.TemporaryDirectory() as tmpdir:
        collector = YARAifyCollector(tmpdir)
        collector.run()
        path = os.path.join(tmpdir, "yaraify_rules.csv")
        assert os.path.exists(path)
        with open(path, newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        assert len(rows) == 2
