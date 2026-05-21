import os
import csv
import tempfile
from unittest.mock import patch, MagicMock
import pytest
from collectors.mitre_attack import MitreAttackCollector

SAMPLE_STIX_BUNDLE = {
    "type": "bundle",
    "objects": [
        {
            "type": "malware", "id": "malware--abcd-1234", "name": "Emotet",
            "description": "A modular banking trojan.",
            "x_mitre_aliases": ["Emotet", "Heodo", "Geodo"], "labels": ["malware"],
            "external_references": [{"source_name": "mitre-attack", "external_id": "S0367"}],
        },
        {
            "type": "attack-pattern", "id": "attack-pattern--efgh-5678",
            "name": "Command and Scripting Interpreter",
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1059"}],
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
        },
        {
            "type": "relationship", "id": "relationship--rel-001",
            "relationship_type": "uses", "source_ref": "malware--abcd-1234",
            "target_ref": "attack-pattern--efgh-5678",
        },
        {"type": "identity", "id": "identity--ignore", "name": "MITRE"},
    ],
}

@patch("requests.Session.get")
def test_collect_extracts_malware_and_techniques(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = SAMPLE_STIX_BUNDLE
    mock_get.return_value = mock_resp
    with tempfile.TemporaryDirectory() as tmpdir:
        collector = MitreAttackCollector(tmpdir)
        rows = collector.collect()
    assert len(rows) == 1
    assert rows[0]["name"] == "Emotet"
    assert rows[0]["mitre_id"] == "S0367"
    assert rows[0]["aliases"] == "Emotet|Heodo|Geodo"
    assert rows[0]["techniques"] == "T1059"

@patch("requests.Session.get")
def test_run_writes_csv(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = SAMPLE_STIX_BUNDLE
    mock_get.return_value = mock_resp
    with tempfile.TemporaryDirectory() as tmpdir:
        collector = MitreAttackCollector(tmpdir)
        collector.run()
        path = os.path.join(tmpdir, "mitre_attack.csv")
        assert os.path.exists(path)
        with open(path, newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        assert len(rows) == 1
        assert rows[0]["techniques"] == "T1059"
