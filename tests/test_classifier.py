import pytest
from normalizer.classifier import classify

def test_clamav_pua_prefix():
    assert classify(clamav="PUA.Win32.Adware.SomeApp", tags="") == "pua"

def test_clamav_adware_prefix():
    assert classify(clamav="Adware.AndroidOS.Ewind", tags="") == "adware"

def test_tag_adware():
    assert classify(clamav="", tags="stealer|adware|packed") == "adware"

def test_tag_pup():
    assert classify(clamav="", tags="pup|downloader") == "pup"

def test_tag_pua():
    assert classify(clamav="", tags="pua") == "pua"

def test_tag_riskware():
    assert classify(clamav="", tags="riskware") == "riskware"

def test_tag_bundler():
    assert classify(clamav="", tags="bundler|installer") == "pua"

def test_default_malware():
    assert classify(clamav="Win.Trojan.Generic", tags="trojan|packed") == "malware"

def test_empty_inputs():
    assert classify(clamav="", tags="") == "malware"

def test_clamav_takes_priority_over_tags():
    assert classify(clamav="PUA.Win32.Something", tags="riskware") == "pua"

def test_misp_classification_override():
    assert classify(clamav="", tags="", misp_classification="adware") == "adware"

def test_misp_only_used_when_others_empty():
    assert classify(clamav="PUA.Win32.X", tags="", misp_classification="riskware") == "pua"

def test_vt_classification_adware():
    assert classify(clamav="", tags="", misp_classification="", vt_classification="adware") == "adware"

def test_vt_classification_pup():
    assert classify(clamav="", tags="", misp_classification="", vt_classification="pup") == "pup"

def test_vt_after_misp():
    assert classify(clamav="", tags="", misp_classification="riskware", vt_classification="adware") == "riskware"

def test_vt_trojan_stays_malware():
    assert classify(clamav="", tags="", vt_classification="trojan") == "malware"
