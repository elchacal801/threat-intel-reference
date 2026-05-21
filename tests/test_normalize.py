import csv
import json
import os
import tempfile
import pytest
from normalizer.normalize import Normalizer


def write_csv(path, fieldnames, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


@pytest.fixture
def pipeline_dirs():
    with tempfile.TemporaryDirectory() as tmpdir:
        raw_dir = os.path.join(tmpdir, "raw")
        norm_dir = os.path.join(tmpdir, "normalized")
        os.makedirs(raw_dir)
        os.makedirs(norm_dir)

        write_csv(
            os.path.join(raw_dir, "malwarebazaar.csv"),
            ["sha256", "sha1", "md5", "file_name", "file_type", "file_size",
             "family", "tags", "clamav_detection", "first_seen", "last_seen",
             "imphash", "tlsh", "ssdeep"],
            [
                {"sha256": "a" * 64, "sha1": "b" * 40, "md5": "c" * 32,
                 "file_name": "evil.exe", "file_type": "exe", "file_size": "1234",
                 "family": "AgentTesla", "tags": "stealer|keylogger",
                 "clamav_detection": "Win.Trojan.AgentTesla", "first_seen": "2024-01-01",
                 "last_seen": "2024-06-01", "imphash": "", "tlsh": "", "ssdeep": ""},
                {"sha256": "d" * 64, "sha1": "e" * 40, "md5": "f" * 32,
                 "file_name": "adware.exe", "file_type": "exe", "file_size": "5678",
                 "family": "", "tags": "adware|bundler",
                 "clamav_detection": "PUA.Win32.Adware.InstallCore", "first_seen": "2024-02-01",
                 "last_seen": "", "imphash": "", "tlsh": "", "ssdeep": ""},
            ],
        )

        write_csv(
            os.path.join(raw_dir, "threatfox.csv"),
            ["ioc_id", "ioc_type", "ioc_value", "threat_type", "family",
             "family_aliases", "confidence", "first_seen", "last_seen", "tags"],
            [{"ioc_id": "1", "ioc_type": "ip:port", "ioc_value": "1.2.3.4:443",
              "threat_type": "botnet_cc", "family": "Emotet",
              "family_aliases": "Emotet,Heodo", "confidence": "90",
              "first_seen": "2024-01-15", "last_seen": "", "tags": "emotet"}],
        )

        write_csv(
            os.path.join(raw_dir, "misp_galaxy_families.csv"),
            ["canonical_name", "aliases", "classification", "description", "uuid", "source_cluster"],
            [
                {"canonical_name": "Emotet", "aliases": "Heodo|Geodo",
                 "classification": "malware", "description": "Banking trojan.",
                 "uuid": "uuid-1", "source_cluster": "malpedia.json"},
                {"canonical_name": "InstallCore", "aliases": "InstallCore PUA",
                 "classification": "adware", "description": "Adware bundler.",
                 "uuid": "uuid-2", "source_cluster": "malpedia.json"},
            ],
        )

        write_csv(
            os.path.join(raw_dir, "mitre_attack.csv"),
            ["mitre_id", "name", "description", "aliases", "techniques"],
            [{"mitre_id": "S0367", "name": "Emotet",
              "description": "Banking trojan.", "aliases": "Emotet|Heodo|Geodo",
              "techniques": "T1059|T1547"}],
        )

        write_csv(
            os.path.join(raw_dir, "yaraify_rules.csv"),
            ["rule_name", "author", "description", "malpedia_family",
             "matching_tlp", "sharing_tlp", "yarahub_uuid", "date"],
            [],
        )

        yield raw_dir, norm_dir


def test_normalizer_produces_all_output_files(pipeline_dirs):
    raw_dir, norm_dir = pipeline_dirs
    normalizer = Normalizer(raw_dir, norm_dir)
    normalizer.run()
    expected = [
        "malware_samples.csv", "malware_samples.json",
        "pup_pua_samples.csv", "pup_pua_samples.json",
        "malware_families.csv", "malware_families.json",
        "iocs.csv", "iocs.json",
        "techniques.csv", "techniques.json",
        "stats.json",
    ]
    for fname in expected:
        assert os.path.exists(os.path.join(norm_dir, fname)), f"Missing: {fname}"


def test_normalizer_splits_malware_vs_pup(pipeline_dirs):
    raw_dir, norm_dir = pipeline_dirs
    normalizer = Normalizer(raw_dir, norm_dir)
    normalizer.run()
    with open(os.path.join(norm_dir, "malware_samples.csv"), newline="", encoding="utf-8") as f:
        malware_rows = list(csv.DictReader(f))
    with open(os.path.join(norm_dir, "pup_pua_samples.csv"), newline="", encoding="utf-8") as f:
        pup_rows = list(csv.DictReader(f))
    malware_hashes = [r["sha256"] for r in malware_rows]
    pup_hashes = [r["sha256"] for r in pup_rows]
    assert "a" * 64 in malware_hashes
    assert "d" * 64 in pup_hashes


def test_normalizer_writes_iocs(pipeline_dirs):
    raw_dir, norm_dir = pipeline_dirs
    normalizer = Normalizer(raw_dir, norm_dir)
    normalizer.run()
    with open(os.path.join(norm_dir, "iocs.csv"), newline="", encoding="utf-8") as f:
        ioc_rows = list(csv.DictReader(f))
    assert len(ioc_rows) >= 1
    assert ioc_rows[0]["ioc_value"] == "1.2.3.4:443"
    assert ioc_rows[0]["confidence"] == "90"


def test_normalizer_writes_families(pipeline_dirs):
    raw_dir, norm_dir = pipeline_dirs
    normalizer = Normalizer(raw_dir, norm_dir)
    normalizer.run()
    with open(os.path.join(norm_dir, "malware_families.csv"), newline="", encoding="utf-8") as f:
        family_rows = list(csv.DictReader(f))
    names = [r["canonical_name"] for r in family_rows]
    assert "Emotet" in names


def test_normalizer_json_mirrors_match_csv(pipeline_dirs):
    raw_dir, norm_dir = pipeline_dirs
    normalizer = Normalizer(raw_dir, norm_dir)
    normalizer.run()
    with open(os.path.join(norm_dir, "malware_samples.csv"), newline="", encoding="utf-8") as f:
        csv_rows = list(csv.DictReader(f))
    with open(os.path.join(norm_dir, "malware_samples.json"), encoding="utf-8") as f:
        json_rows = json.load(f)
    assert len(csv_rows) == len(json_rows)


def test_stats_json(pipeline_dirs):
    raw_dir, norm_dir = pipeline_dirs
    normalizer = Normalizer(raw_dir, norm_dir)
    normalizer.run()
    with open(os.path.join(norm_dir, "stats.json"), encoding="utf-8") as f:
        stats = json.load(f)
    assert "total_samples" in stats
    assert "total_families" in stats
    assert "total_pup_pua" in stats
    assert "last_updated" in stats


def test_normalizer_produces_behavioral_indicators(pipeline_dirs):
    raw_dir, norm_dir = pipeline_dirs
    write_csv(
        os.path.join(raw_dir, "urlhaus.csv"),
        ["sha256", "md5", "url", "host", "url_status", "file_type", "signature", "tags", "first_seen"],
        [{"sha256": "a" * 64, "md5": "c" * 32, "url": "https://evil.com/mal.exe",
          "host": "evil.com", "url_status": "online", "file_type": "exe",
          "signature": "AgentTesla", "tags": "", "first_seen": "2024-01-01"}],
    )
    write_csv(
        os.path.join(raw_dir, "hybrid_analysis.csv"),
        ["sha256", "verdict", "vx_family", "av_detect_pct", "contacted_domains", "contacted_ips", "analysis_date"],
        [{"sha256": "a" * 64, "verdict": "malicious", "vx_family": "AgentTesla",
          "av_detect_pct": "75", "contacted_domains": "c2.evil.com|exfil.bad.org",
          "contacted_ips": "1.2.3.4", "analysis_date": "2024-01-15"}],
    )
    normalizer = Normalizer(raw_dir, norm_dir)
    normalizer.run()
    bi_path = os.path.join(norm_dir, "behavioral_indicators.csv")
    assert os.path.exists(bi_path)
    with open(bi_path, newline="", encoding="utf-8") as f:
        bi_rows = list(csv.DictReader(f))
    assert len(bi_rows) >= 3


def test_normalizer_adds_vt_columns(pipeline_dirs):
    raw_dir, norm_dir = pipeline_dirs
    write_csv(
        os.path.join(raw_dir, "vt_enrichment.csv"),
        ["sha256", "vt_classification", "vt_detection_rate", "vt_family", "vt_tags", "enriched_date"],
        [{"sha256": "a" * 64, "vt_classification": "trojan", "vt_detection_rate": "45/72",
          "vt_family": "agenttesla", "vt_tags": "pe|trojan", "enriched_date": "2024-01-15"}],
    )
    normalizer = Normalizer(raw_dir, norm_dir)
    normalizer.run()
    with open(os.path.join(norm_dir, "malware_samples.csv"), newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    sample = next((r for r in rows if r["sha256"] == "a" * 64), None)
    assert sample is not None
    assert sample["vt_detection_rate"] == "45/72"
