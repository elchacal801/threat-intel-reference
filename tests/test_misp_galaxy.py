import os
import csv
import json
import tempfile
from unittest.mock import patch, MagicMock
import pytest
from collectors.misp_galaxy import MispGalaxyCollector

SAMPLE_MALPEDIA_CLUSTER = {
    "values": [
        {
            "value": "Emotet", "description": "A modular banking trojan turned botnet.",
            "uuid": "uuid-001",
            "meta": {"synonyms": ["Heodo", "Geodo"],
                     "refs": ["https://malpedia.caad.fkie.fraunhofer.de/details/win.emotet"],
                     "type": []},
        },
        {
            "value": "Adware.BrowserAssistant", "description": "Browser adware that injects ads.",
            "uuid": "uuid-002",
            "meta": {"synonyms": ["BrowserAssistant"], "refs": [], "type": ["adware"]},
        },
    ],
}

SAMPLE_RANSOMWARE_CLUSTER = {
    "values": [
        {
            "value": "LockBit", "description": "Ransomware-as-a-service operation.",
            "uuid": "uuid-003",
            "meta": {"synonyms": ["LockBit 2.0", "LockBit 3.0"], "refs": []},
        },
    ],
}

@patch("requests.Session.get")
def test_collect_merges_clusters(mock_get):
    def side_effect(url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        if "malpedia" in url:
            resp.json.return_value = SAMPLE_MALPEDIA_CLUSTER
        elif "ransomware" in url:
            resp.json.return_value = SAMPLE_RANSOMWARE_CLUSTER
        else:
            resp.json.return_value = {"values": []}
        return resp
    mock_get.side_effect = side_effect
    with tempfile.TemporaryDirectory() as tmpdir:
        collector = MispGalaxyCollector(tmpdir)
        rows = collector.collect()
    names = [r["canonical_name"] for r in rows]
    assert "Emotet" in names
    assert "LockBit" in names
    assert "Adware.BrowserAssistant" in names
    emotet = next(r for r in rows if r["canonical_name"] == "Emotet")
    assert "Heodo" in emotet["aliases"]
    adware = next(r for r in rows if r["canonical_name"] == "Adware.BrowserAssistant")
    assert adware["classification"] == "adware"
