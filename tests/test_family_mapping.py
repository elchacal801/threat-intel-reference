import os
import tempfile
import pytest
from normalizer.family_mapping import FamilyMapper

SAMPLE_MAPPING_CSV = '''"^(emotet|heodo|geodo)$",emotet,malpedia
"^(cobalt[-_ ]?strike|cobaltstrike|beacon)$",cobalt_strike,common
"^agent[-_ ]?tesla$",agenttesla,malpedia
'''

def test_resolve_known_alias():
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "mapping.csv")
        with open(path, "w") as f:
            f.write(SAMPLE_MAPPING_CSV)
        mapper = FamilyMapper(path)
    assert mapper.resolve("Heodo") == "emotet"
    assert mapper.resolve("geodo") == "emotet"
    assert mapper.resolve("emotet") == "emotet"

def test_resolve_cobalt_strike_variations():
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "mapping.csv")
        with open(path, "w") as f:
            f.write(SAMPLE_MAPPING_CSV)
        mapper = FamilyMapper(path)
    assert mapper.resolve("CobaltStrike") == "cobalt_strike"
    assert mapper.resolve("Cobalt Strike") == "cobalt_strike"
    assert mapper.resolve("cobalt-strike") == "cobalt_strike"
    assert mapper.resolve("beacon") == "cobalt_strike"

def test_resolve_unknown_returns_lowered_input():
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "mapping.csv")
        with open(path, "w") as f:
            f.write(SAMPLE_MAPPING_CSV)
        mapper = FamilyMapper(path)
    assert mapper.resolve("UnknownMalware") == "unknownmalware"
    assert mapper.resolve("") == ""

def test_resolve_with_misp_aliases():
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "mapping.csv")
        with open(path, "w") as f:
            f.write(SAMPLE_MAPPING_CSV)
        mapper = FamilyMapper(path)
    mapper.add_aliases("emotet", ["Emotet", "Heodo", "MealyBug"])
    assert mapper.resolve("MealyBug") == "emotet"
