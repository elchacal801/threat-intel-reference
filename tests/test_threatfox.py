import os
import csv
import io
import tempfile
import zipfile
from unittest.mock import patch, MagicMock
import pytest
from collectors.threatfox import ThreatFoxCollector

SAMPLE_CSV = '''"ioc_id","ioc_type","ioc_value","threat_type","malware","malware_alias","malware_printable","confidence_level","first_seen_utc","last_seen_utc","reporter","tags"
"1","ip:port","1.2.3.4:443","botnet_cc","win.cobalt_strike","CobaltStrike","Cobalt Strike","75","2024-01-01 00:00:00","2024-06-01 00:00:00","abuse_ch","cobalt-strike"
"2","sha256_hash","aaaa","payload","win.emotet","Emotet,Heodo","Emotet","90","2024-02-01 00:00:00","","reporter2","emotet|heodo"
'''

@patch("collectors.threatfox.ThreatFoxCollector.get_api_key", return_value="fake_key")
@patch("requests.Session.get")
def test_collect_parses_csv_export(mock_get, mock_key):
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w") as zf:
        zf.writestr("full_export.csv", SAMPLE_CSV)
    zip_buf.seek(0)
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.content = zip_buf.read()
    mock_get.return_value = mock_resp
    with tempfile.TemporaryDirectory() as tmpdir:
        collector = ThreatFoxCollector(tmpdir)
        rows = collector.collect()
    assert len(rows) == 2
    assert rows[0]["ioc_value"] == "1.2.3.4:443"
    assert rows[0]["family"] == "Cobalt Strike"
    assert rows[0]["confidence"] == "75"
    assert rows[1]["family"] == "Emotet"
    assert rows[1]["family_aliases"] == "Emotet,Heodo"

@patch("collectors.threatfox.ThreatFoxCollector.get_api_key", return_value="fake_key")
@patch("requests.Session.get")
def test_run_writes_csv(mock_get, mock_key):
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w") as zf:
        zf.writestr("full_export.csv", SAMPLE_CSV)
    zip_buf.seek(0)
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.content = zip_buf.read()
    mock_get.return_value = mock_resp
    with tempfile.TemporaryDirectory() as tmpdir:
        collector = ThreatFoxCollector(tmpdir)
        collector.run()
        path = os.path.join(tmpdir, "threatfox.csv")
        assert os.path.exists(path)
        with open(path, newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        assert len(rows) == 2
