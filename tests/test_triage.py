"""Offline tests for triage.py - matcher and verdict composition.

No network, no API key, no Streamlit required.
Run: pytest -q
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from triage import (  # noqa: E402
    VERDICT_AFFECTED,
    VERDICT_CANNOT,
    VERDICT_NOT_AFFECTED,
    _live_extract,
    _live_grounding,
    build_claim,
    compose_verdict,
    load_mock_responses,
    match_device,
    parse_decide,
    parse_grounding,
    parse_inventory,
    parse_version,
    run_triage,
    unwrap_extract_fields,
    unwrap_extract_result,
    version_matches,
)

EXTRACT_AFFECTED = {
    "vendor": "Acme Networks (Cisco-style sample)",
    "products": ["Catalyst 9300"],
    "affected_versions": ["17.9.1", "17.9.2", "17.9.3", "17.9.4", "17.9.5"],
    "advisory_id": "SYN-CSC-2026-1101",
    "severity": "High",
    "fixed_version": "IOS XE 17.9.6 or later",
    "action_deadline": "2026-11-20",
}


def device(hostname="SW-01", model="Catalyst 9300", version="17.9.4"):
    return {"hostname": hostname, "model": model, "version": version}


# ------------------------- inventory parsing -------------------------

def test_parse_inventory_lines():
    text = "A, Catalyst 9300, 17.9.4\n\n# comment\nB, Nexus 3064, 7.0(3)I4(4)\n"
    devices = parse_inventory(text)
    assert len(devices) == 2
    assert devices[0]["hostname"] == "A"
    assert devices[1]["version"] == "7.0(3)I4(4)"


# ------------------------- version matching --------------------------

def test_version_exact_match():
    assert version_matches("17.9.4", "17.9.4") is True
    assert version_matches("17.9.6", "17.9.4") is False


def test_version_wildcard():
    assert version_matches("17.9.4", "17.9.x") is True
    assert version_matches("17.10.1", "17.9.x") is False


def test_version_range():
    assert version_matches("17.9.3", "17.9.1-17.9.5") is True
    assert version_matches("17.9.9", "17.9.1-17.9.5") is False
    assert version_matches("17.9.1", "17.9.1-17.9.5") is True
    assert version_matches("17.9.5", "17.9.1-17.9.5") is True


def test_version_unparseable_returns_none():
    assert parse_version("unknown") is None
    assert parse_version("") is None
    assert version_matches("unknown", "17.9.4") is None


# ------------------------- matcher -----------------------------------

def test_matcher_exact_affected():
    result = match_device(device(), EXTRACT_AFFECTED)
    assert result["status"] == VERDICT_AFFECTED
    assert result["candidate"] is True


def test_matcher_range_affected():
    extracted = dict(EXTRACT_AFFECTED)
    extracted["affected_versions"] = ["17.9.1-17.9.5"]
    result = match_device(device(version="17.9.3"), extracted)
    assert result["status"] == VERDICT_AFFECTED
    result_out = match_device(device(version="17.9.9"), extracted)
    assert result_out["status"] == VERDICT_NOT_AFFECTED


def test_matcher_wildcard_affected():
    extracted = dict(EXTRACT_AFFECTED)
    extracted["affected_versions"] = ["17.9.x"]
    assert match_device(device(version="17.9.2"), extracted)["status"] == VERDICT_AFFECTED


def test_matcher_not_affected_version():
    result = match_device(device(version="17.9.6"), EXTRACT_AFFECTED)
    assert result["status"] == VERDICT_NOT_AFFECTED
    assert result["candidate"] is True


def test_matcher_different_product_not_affected():
    result = match_device(
        device(hostname="MX-01", model="MX480", version="21.4R1"),
        EXTRACT_AFFECTED,
    )
    # Advisory is about Catalyst 9300 only; an MX device is conclusively out.
    assert result["status"] == VERDICT_NOT_AFFECTED
    assert result["candidate"] is False


def test_matcher_product_absent_cannot_determine():
    extracted = dict(EXTRACT_AFFECTED)
    extracted["products"] = []
    result = match_device(device(), extracted)
    assert result["status"] == VERDICT_CANNOT


def test_matcher_no_affected_versions_cannot_determine():
    extracted = dict(EXTRACT_AFFECTED)
    extracted["affected_versions"] = []
    result = match_device(device(), extracted)
    assert result["status"] == VERDICT_CANNOT
    assert result["candidate"] is True


def test_matcher_unparseable_version_cannot_determine():
    result = match_device(device(version="unknown"), EXTRACT_AFFECTED)
    assert result["status"] == VERDICT_CANNOT
    assert result["candidate"] is True


def test_matcher_unparseable_never_not_affected():
    for bad in ("", "unknown", "-", "n/a"):
        result = match_device(device(version=bad), EXTRACT_AFFECTED)
        assert result["status"] != VERDICT_NOT_AFFECTED


# ------------------------- verdict composition -----------------------

def _decide(urgency="immediate", evidence_prob=0.95, evidence_value=True):
    return {
        "urgency": urgency,
        "urgency_immediate": {"value": urgency == "immediate",
                              "probability": 0.9 if urgency == "immediate" else 0.1},
        "urgency_planned": {"value": urgency == "planned",
                            "probability": 0.8 if urgency == "planned" else 0.2},
        "evidence_sufficient": {"value": evidence_value,
                                "probability": evidence_prob},
    }


def _grounding(supported=True):
    return {
        "verdict": "supported" if supported else "unsupported",
        "answers_question": supported,
        "supported": supported,
    }


def _affected_devices():
    return [match_device(device(), EXTRACT_AFFECTED)]


def _clean_devices():
    return [match_device(device(version="17.9.6"), EXTRACT_AFFECTED)]


def test_compose_affected_passes_through():
    composed = compose_verdict(_affected_devices(), _decide(), _grounding(True))
    assert composed["verdict"] == VERDICT_AFFECTED
    assert composed["urgency"] == "immediate"
    assert composed["warnings"] == []


def test_compose_not_affected_passes_through():
    composed = compose_verdict(_clean_devices(), _decide("monitor"), _grounding(True))
    assert composed["verdict"] == VERDICT_NOT_AFFECTED


def test_compose_grounding_overturn():
    composed = compose_verdict(_affected_devices(), _decide(), _grounding(False))
    assert composed["verdict"] == VERDICT_CANNOT
    assert any("grounding" in w for w in composed["warnings"])


def test_compose_low_sufficiency_downgrade():
    composed = compose_verdict(
        _affected_devices(),
        _decide(evidence_prob=0.2, evidence_value=False),
        _grounding(True),
    )
    assert composed["verdict"] == VERDICT_CANNOT
    assert any("insufficient" in w for w in composed["warnings"])


def test_compose_low_sufficiency_downgrades_not_affected_too():
    composed = compose_verdict(
        _clean_devices(),
        _decide("monitor", evidence_prob=0.1, evidence_value=False),
        _grounding(True),
    )
    assert composed["verdict"] == VERDICT_CANNOT


# ------------------------- mock pipeline (end to end) ----------------

def _run_sample(sample_id, sample_file):
    root = Path(__file__).resolve().parent.parent
    advisory = (root / "samples" / sample_file).read_text(encoding="utf-8")
    inventory = (root / "samples" / "inventory_sample.txt").read_text(encoding="utf-8")
    return run_triage(advisory, inventory, sample_id=sample_id, api_key=None)


def test_mock_sample1_affected():
    result = _run_sample("sample1", "sample1_affected.txt")
    assert result["mode"] == "mock"
    assert result["verdict"] == VERDICT_AFFECTED
    assert result["urgency"] == "immediate"
    assert result["clocked_calls"] == 3


def test_mock_sample2_not_affected():
    result = _run_sample("sample2", "sample2_not_affected.txt")
    assert result["verdict"] == VERDICT_NOT_AFFECTED


def test_mock_sample3_cannot_determine():
    result = _run_sample("sample3", "sample3_insufficient.txt")
    assert result["verdict"] == VERDICT_CANNOT


def test_mock_arbitrary_text_no_fabricated_verdict():
    result = run_triage(
        "Some random advisory with no sample marker and no versions.",
        "SW-01, Catalyst 9300, 17.9.4\n",
        sample_id=None,
        api_key=None,
    )
    assert result["verdict"] is None
    assert "error" in result
    assert "CLOCKED_API_KEY" in result["error"]


# ---------------- real Clocked response shapes (repair round 1) -------

WRAPPED_FIELDS = {
    "vendor": {"value": "Acme Networks", "start": 140, "end": 153,
               "confidence": 0.99, "p_verify": 0.99},
    "products": {"value": ["Catalyst 9300 Series Switches"],
                 "items": [{"value": "Catalyst 9300 Series Switches",
                            "start": 184, "end": 213, "confidence": 0.99}],
                 "confidence": 0.99},
    "affected_versions": {"value": ["17.9.4"], "items": [], "confidence": 0.99},
}


def test_unwrap_extract_fields_real_shape():
    plain = unwrap_extract_fields(WRAPPED_FIELDS)
    assert plain["vendor"] == "Acme Networks"
    assert plain["products"] == ["Catalyst 9300 Series Switches"]
    assert plain["affected_versions"] == ["17.9.4"]


def test_unwrap_extract_fields_plain_passthrough():
    plain = unwrap_extract_fields({"vendor": "X", "products": ["Y"]})
    assert plain == {"vendor": "X", "products": ["Y"]}


def test_unwrap_extract_result_keeps_raw():
    plain, raw = unwrap_extract_result({"fields": WRAPPED_FIELDS})
    assert plain["vendor"] == "Acme Networks"
    assert raw["vendor"]["start"] == 140
    assert raw["products"]["items"][0]["value"] == "Catalyst 9300 Series Switches"


def test_live_extract_unwraps_with_fake_client():
    class FakeClient(object):
        def extract(self, **kwargs):
            return {"fields": WRAPPED_FIELDS}

    plain, raw = _live_extract(FakeClient(), "any advisory text")
    assert plain["products"] == ["Catalyst 9300 Series Switches"]
    assert raw["vendor"]["confidence"] == 0.99
    # The matcher must see the unwrapped list, not the raw dict object.
    result = match_device(device(), dict(plain, affected_versions=["17.9.4"]))
    assert result["status"] == VERDICT_AFFECTED


def test_parse_decide_noul_shape():
    parsed = parse_decide({"answers": {
        "urgency_immediate": {"type": "noul", "noul": 0.91},
        "urgency_planned": {"type": "noul", "noul": 0.32},
        "evidence_sufficient": {"type": "noul", "noul": 0.9904},
    }})
    assert parsed["urgency_immediate"] == {"value": True, "probability": 0.91}
    assert parsed["urgency_planned"]["value"] is False
    assert parsed["evidence_sufficient"]["probability"] == 0.9904
    assert parsed["urgency"] == "immediate"


def test_parse_decide_noul_low_probability_is_false():
    parsed = parse_decide({"answers": {
        "urgency_immediate": {"type": "noul", "noul": 0.0773},
        "urgency_planned": {"type": "noul", "noul": 0.0329},
        "evidence_sufficient": {"type": "noul", "noul": 0.18},
    }})
    assert parsed["urgency_immediate"]["value"] is False
    assert parsed["evidence_sufficient"]["value"] is False
    assert parsed["urgency"] == "monitor"


def test_parse_grounding_ungrounded_is_not_supported():
    # Regression: "ungrounded" contains the substring "grounded".
    parsed = parse_grounding({
        "grounded": 0.0026, "ungrounded": 0.9974, "verdict": "ungrounded",
        "threshold": 0.5, "answers_question": 0.9286,
        "claims": [{"supported": 0.0026, "verdict": "not_stated"}],
    })
    assert parsed["supported"] is False
    assert parsed["verdict"] == "ungrounded"


def test_parse_grounding_grounded_and_float_answers_question():
    parsed = parse_grounding({
        "grounded": 0.96, "ungrounded": 0.04, "verdict": "grounded",
        "threshold": 0.5, "answers_question": 0.95, "claims": [],
    })
    assert parsed["supported"] is True
    assert parsed["answers_question"] is True


def test_parse_grounding_probability_fallback_without_verdict():
    parsed = parse_grounding({"grounded": 0.7, "answers_question": 0.2})
    assert parsed["supported"] is True
    assert parsed["answers_question"] is False
    parsed_low = parse_grounding({"grounded": 0.2, "answers_question": 0.9})
    assert parsed_low["supported"] is False


def test_mock_responses_use_real_shapes():
    canned = load_mock_responses()
    for sample_id in ("sample1", "sample2", "sample3"):
        entry = canned[sample_id]
        for field in entry["extract"]["fields"].values():
            assert isinstance(field, dict) and "value" in field
        for answer in entry["decide"]["answers"].values():
            assert answer["type"] == "noul"
            assert isinstance(answer["noul"], float)
        grounding = entry["grounding"]
        assert grounding["verdict"] in ("grounded", "ungrounded")
        assert isinstance(grounding["answers_question"], float)
        assert isinstance(grounding["grounded"], float)


def test_mock_pipeline_extract_is_unwrapped_and_raw_kept():
    result = _run_sample("sample1", "sample1_affected.txt")
    assert result["extracted"]["products"] == ["Catalyst 9300 Series Switches"]
    raw_products = result["extract_raw"]["fields"]["products"]
    assert raw_products["value"] == ["Catalyst 9300 Series Switches"]
    assert "items" in raw_products


def test_mock_sample2_urgency_monitor():
    result = _run_sample("sample2", "sample2_not_affected.txt")
    assert result["urgency"] == "monitor"
    assert result["grounding"]["supported"] is True


def test_mock_sample3_grounding_ungrounded():
    result = _run_sample("sample3", "sample3_insufficient.txt")
    assert result["grounding"]["verdict"] == "ungrounded"
    assert result["grounding"]["supported"] is False
    assert result["decide"]["evidence_sufficient"]["probability"] == 0.18


# ---------------- repair round 2: grounding sees inventory ----------

def test_live_grounding_passes_advisory_and_inventory_documents():
    captured = {}

    class FakeGroundingClient(object):
        def grounding(self, **kwargs):
            captured.update(kwargs)
            return {"verdict": "grounded", "grounded": 0.93,
                    "ungrounded": 0.07, "answers_question": 0.9}

    result = _live_grounding(
        FakeGroundingClient(),
        "ADVISORY TEXT",
        "CORE-SW-01, Catalyst 9300, 17.9.4\n",
        "SYN-CSC-2026-1101 affects Catalyst 9300 (CORE-SW-01, version "
        "17.9.4), which is present in the inventory.",
    )
    assert result["verdict"] == "grounded"
    documents = captured["documents"]
    assert [doc["id"] for doc in documents] == ["advisory", "inventory"]
    assert documents[0]["text"] == "ADVISORY TEXT"
    assert "CORE-SW-01" in documents[1]["text"]


def test_compose_low_sufficiency_warning_keeps_small_probability():
    # Regression: round(prob, 2) printed 0.0 for a real 0.0036.
    composed = compose_verdict(
        _affected_devices(),
        _decide(evidence_prob=0.0036, evidence_value=False),
        _grounding(True),
    )
    assert composed["verdict"] == VERDICT_CANNOT
    warning = [w for w in composed["warnings"] if "insufficient" in w][0]
    assert "0.0036" in warning
    assert "(probability 0.0)" not in warning


def test_build_claim_products_join_unwrapped():
    devices = _clean_devices()
    claim = build_claim(VERDICT_NOT_AFFECTED, devices, EXTRACT_AFFECTED)
    assert "Catalyst 9300" in claim
    claim_str = build_claim(
        VERDICT_NOT_AFFECTED, devices,
        dict(EXTRACT_AFFECTED, products="Catalyst 9300"),
    )
    assert "Catalyst 9300" in claim_str
    assert "C, a, t" not in claim_str
