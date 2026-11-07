"""Offline tests for triage.py - matcher and verdict composition.

No network, no API key, no Streamlit required.
Run: pytest -q
"""

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest  # noqa: E402

import triage  # noqa: E402
from triage import (  # noqa: E402
    VERDICT_AFFECTED,
    VERDICT_CANNOT,
    VERDICT_NOT_AFFECTED,
    _live_extract,
    _live_grounding,
    build_claim,
    compose_verdict,
    constraint_matches,
    derive_version_constraints,
    generate_checklist,
    is_credit_error,
    load_mock_responses,
    match_device,
    normalize_extraction,
    parse_decide,
    parse_grounding,
    parse_inventory,
    parse_version,
    parse_version_constraint,
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
    assert result["clocked_calls"] == 4


def test_mock_override_beats_configured_key(monkeypatch):
    # The app's Demo override: mock=True must win over a configured
    # key - no key resolution, no Clocked call, canned verdict.
    monkeypatch.setenv("CLOCKED_API_KEY", "test-key-not-a-real-secret")
    root = Path(__file__).resolve().parent.parent
    advisory = (root / "samples" / "sample1_affected.txt").read_text(
        encoding="utf-8")
    inventory = (root / "samples" / "inventory_sample.txt").read_text(
        encoding="utf-8")
    result = run_triage(advisory, inventory, sample_id="sample1",
                        mock=True)
    assert result["mode"] == "mock"
    assert result["verdict"] == VERDICT_AFFECTED


def test_mock_sample2_not_affected():
    result = _run_sample("sample2", "sample2_not_affected.txt")
    assert result["verdict"] == VERDICT_NOT_AFFECTED


def test_mock_sample3_cannot_determine():
    result = _run_sample("sample3", "sample3_insufficient.txt")
    assert result["verdict"] == VERDICT_CANNOT


def _device_status(result, hostname):
    for row in result["device_results"]:
        if row["hostname"] == hostname:
            return row["status"]
    raise AssertionError("device %s not in results" % hostname)


def test_mock_sample4_arista_affected():
    result = _run_sample("sample4", "sample4_arista_affected.txt")
    assert result["mode"] == "mock"
    assert result["verdict"] == VERDICT_AFFECTED
    assert result["urgency"] == "immediate"
    assert result["clocked_calls"] == 4
    # DC-SW-01 runs EOS 4.30.5M on an Arista 7050SX3: listed as affected.
    assert _device_status(result, "DC-SW-01") == VERDICT_AFFECTED
    # DC-SW-02 is a 7050CX3 - a different product, conclusively out.
    assert _device_status(result, "DC-SW-02") == VERDICT_NOT_AFFECTED


def test_mock_sample5_juniper_affected():
    result = _run_sample("sample5", "sample5_juniper_affected.txt")
    assert result["mode"] == "mock"
    assert result["verdict"] == VERDICT_AFFECTED
    assert result["urgency"] == "immediate"
    assert result["clocked_calls"] == 4
    # AGG-RTR-01 (QFX5110) runs Junos 21.2R3, listed as affected -
    # unlike Sample 2, whose MX-only advisory leaves it not affected.
    assert _device_status(result, "AGG-RTR-01") == VERDICT_AFFECTED


def test_mock_sample4_detected_by_exact_text_without_sample_id():
    result = _run_sample(None, "sample4_arista_affected.txt")
    assert result["sample_id"] == "sample4"
    assert result["verdict"] == VERDICT_AFFECTED


def test_mock_sample5_detected_by_exact_text_without_sample_id():
    result = _run_sample(None, "sample5_juniper_affected.txt")
    assert result["sample_id"] == "sample5"
    assert result["verdict"] == VERDICT_AFFECTED


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


# --------- mock sample binding: exact text or no canned verdict ------
# Regression: a canned verdict was served for ANY text whenever a
# sample_id was passed (a stale UI picker value) or the sample's
# SYN-* marker appeared in the text. Canned responses are bound to
# the exact bundled sample texts only.

_SAMPLE_FILES_BY_ID = {
    "sample1": "sample1_affected.txt",
    "sample2": "sample2_not_affected.txt",
    "sample3": "sample3_insufficient.txt",
    "sample4": "sample4_arista_affected.txt",
    "sample5": "sample5_juniper_affected.txt",
    "sample6": "sample6_juniper_prior_to.txt",
    "sample7": "sample7_arista_conditional.txt",
}


def _load_bundled(filename):
    root = Path(__file__).resolve().parent.parent
    return (root / "samples" / filename).read_text(encoding="utf-8")


def test_mock_stale_sample_id_no_fabricated_verdict():
    # Non-sample text after a sample was "loaded" (its id passed
    # in): the result must be the standing samples-only outcome,
    # never that sample's canned verdict.
    result = run_triage(
        "Completely unrelated advisory about frobnicate routers.",
        _load_bundled("inventory_sample.txt"),
        sample_id="sample1",
        api_key=None,
    )
    assert result["verdict"] is None
    assert "error" in result
    assert "CLOCKED_API_KEY" in result["error"]


def test_mock_edited_sample_text_no_canned_verdict():
    # One version string edited, the SYN marker intact: neither
    # the explicit id nor the marker alone may select the canned
    # responses for the now-different text.
    advisory = _load_bundled("sample1_affected.txt")
    edited = advisory.replace("17.9.5", "17.9.99")
    assert edited != advisory
    assert "SYN-CSC-2026-1101" in edited
    for sample_id in ("sample1", None):
        result = run_triage(
            edited,
            _load_bundled("inventory_sample.txt"),
            sample_id=sample_id,
            api_key=None,
        )
        assert result["verdict"] is None
        assert "error" in result


def test_mock_marker_in_foreign_text_no_canned_verdict():
    result = run_triage(
        "SYN-CSC-2026-1101 some other body entirely, no versions.",
        _load_bundled("inventory_sample.txt"),
        sample_id=None,
        api_key=None,
    )
    assert result["verdict"] is None
    assert "error" in result


def test_mock_contradictory_sample_id_fails_closed():
    # The text is exactly sample2 but the caller claims sample1:
    # a disagreeing id must not serve either canned verdict.
    result = run_triage(
        _load_bundled("sample2_not_affected.txt"),
        _load_bundled("inventory_sample.txt"),
        sample_id="sample1",
        api_key=None,
    )
    assert result["verdict"] is None
    assert "error" in result


def test_mock_exact_sample_texts_still_canned():
    # All seven bundled samples keep their canned verdicts, with
    # an agreeing explicit id and with no id at all.
    inventory = _load_bundled("inventory_sample.txt")
    for sample_id, filename in _SAMPLE_FILES_BY_ID.items():
        advisory = _load_bundled(filename)
        for passed_id in (sample_id, None):
            result = run_triage(
                advisory, inventory,
                sample_id=passed_id, api_key=None,
            )
            assert result["mode"] == "mock"
            assert result["sample_id"] == sample_id
            assert result["verdict"] is not None


def test_detect_sample_id_requires_exact_text():
    advisory = _load_bundled("sample1_affected.txt")
    assert triage.detect_sample_id(advisory) == "sample1"
    assert triage.detect_sample_id(advisory, "sample1") == "sample1"
    assert triage.detect_sample_id(advisory, "sample2") is None
    assert triage.detect_sample_id(advisory + "\nEdited tail.") is None
    assert triage.detect_sample_id("SYN-CSC-2026-1101 marker only") is None
    assert triage.detect_sample_id("unrelated text", "sample1") is None


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
    for sample_id in ("sample1", "sample2", "sample3", "sample4",
                      "sample5", "sample6", "sample7"):
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


# ---------------- Korean localization (lang="ko") --------------------

HANGUL_RE = re.compile(r"[가-힣]")


def _has_hangul(text):
    return bool(HANGUL_RE.search(text or ""))


def _run_sample_ko(sample_id, sample_file):
    root = Path(__file__).resolve().parent.parent
    advisory = (root / "samples" / sample_file).read_text(encoding="utf-8")
    inventory = (root / "samples" / "inventory_sample.txt").read_text(encoding="utf-8")
    return run_triage(advisory, inventory, sample_id=sample_id,
                      api_key=None, lang="ko")


def test_mock_sample1_affected_ko():
    result = _run_sample_ko("sample1", "sample1_affected.txt")
    # Internal verdict/urgency constants stay English.
    assert result["verdict"] == VERDICT_AFFECTED
    assert result["urgency"] == "immediate"
    # Checklist and per-device reasons are Korean.
    assert result["checklist"]
    assert all(_has_hangul(item) for item in result["checklist"])
    assert any("영향받는 버전" in (row["reason"] or "")
               for row in result["device_results"])
    assert all(_has_hangul(row["reason"]) for row in result["device_results"])
    # The claim sent to Verify stays English.
    assert "affects" in result["claim"]
    assert not _has_hangul(result["claim"])


def test_mock_sample2_not_affected_ko():
    result = _run_sample_ko("sample2", "sample2_not_affected.txt")
    assert result["verdict"] == VERDICT_NOT_AFFECTED
    assert result["urgency"] == "monitor"
    assert result["checklist"]
    assert all(_has_hangul(item) for item in result["checklist"])
    assert all(_has_hangul(row["reason"]) for row in result["device_results"])


def test_mock_sample4_arista_affected_ko():
    result = _run_sample_ko("sample4", "sample4_arista_affected.txt")
    assert result["verdict"] == VERDICT_AFFECTED
    assert result["urgency"] == "immediate"
    assert _device_status(result, "DC-SW-01") == VERDICT_AFFECTED
    assert _device_status(result, "DC-SW-02") == VERDICT_NOT_AFFECTED
    assert result["checklist"]
    assert all(_has_hangul(item) for item in result["checklist"])
    assert all(_has_hangul(row["reason"]) for row in result["device_results"])
    assert not _has_hangul(result["claim"])


def test_mock_sample5_juniper_affected_ko():
    result = _run_sample_ko("sample5", "sample5_juniper_affected.txt")
    assert result["verdict"] == VERDICT_AFFECTED
    assert result["urgency"] == "immediate"
    assert _device_status(result, "AGG-RTR-01") == VERDICT_AFFECTED
    assert result["checklist"]
    assert all(_has_hangul(item) for item in result["checklist"])
    assert all(_has_hangul(row["reason"]) for row in result["device_results"])
    assert not _has_hangul(result["claim"])


def test_mock_sample3_cannot_determine_ko_warnings():
    result = _run_sample_ko("sample3", "sample3_insufficient.txt")
    assert result["verdict"] == VERDICT_CANNOT
    assert result["warnings"]
    assert all(_has_hangul(w) for w in result["warnings"])
    assert any("판정 불가" in w for w in result["warnings"])
    assert not any("CANNOT DETERMINE:" in w for w in result["warnings"])
    assert all(_has_hangul(item) for item in result["checklist"])


def test_match_device_reason_ko_direct():
    result = match_device(device(), EXTRACT_AFFECTED, lang="ko")
    assert result["status"] == VERDICT_AFFECTED
    assert _has_hangul(result["reason"])
    result_en = match_device(device(), EXTRACT_AFFECTED)
    assert not _has_hangul(result_en["reason"])


def test_generate_checklist_ko_variants():
    for verdict, urgency in ((VERDICT_AFFECTED, "immediate"),
                             (VERDICT_AFFECTED, "planned"),
                             (VERDICT_AFFECTED, "monitor"),
                             (VERDICT_NOT_AFFECTED, "monitor"),
                             (VERDICT_CANNOT, "monitor")):
        items = generate_checklist(verdict, urgency, lang="ko")
        assert items
        assert all(_has_hangul(item) for item in items)


def test_compose_verdict_ko_warnings():
    composed = compose_verdict(
        _affected_devices(),
        _decide(evidence_prob=0.2, evidence_value=False),
        _grounding(False),
        lang="ko",
    )
    assert composed["verdict"] == VERDICT_CANNOT
    assert len(composed["warnings"]) == 2
    assert all(_has_hangul(w) for w in composed["warnings"])


def test_mock_arbitrary_text_ko_error_notice():
    result = run_triage(
        "Some random advisory with no sample marker and no versions.",
        "SW-01, Catalyst 9300, 17.9.4\n",
        sample_id=None,
        api_key=None,
        lang="ko",
    )
    assert result["verdict"] is None
    assert _has_hangul(result["error"])
    assert "CLOCKED_API_KEY" in result["error"]


def test_mock_arbitrary_text_en_error_notice_no_key(monkeypatch):
    # No key and no override: the notice must keep the no-key
    # wording (live analysis needs CLOCKED_API_KEY).
    monkeypatch.delenv("CLOCKED_API_KEY", raising=False)
    result = run_triage(
        "Some random advisory with no sample marker and no versions.",
        "SW-01, Catalyst 9300, 17.9.4\n",
        sample_id=None,
        api_key=None,
        lang="en",
    )
    assert result["verdict"] is None
    assert "no CLOCKED_API_KEY is configured" in result["error"]
    assert "Demo mode is on" not in result["error"]


def test_mock_override_arbitrary_text_demo_notice_en(monkeypatch):
    # Key configured + Demo override on (mock=True): the notice
    # must NOT claim no key is configured - it says Demo mode is
    # on and how to get live analysis back.
    monkeypatch.setenv("CLOCKED_API_KEY", "test-key-not-a-real-secret")
    result = run_triage(
        "Some random advisory with no sample marker and no versions.",
        "SW-01, Catalyst 9300, 17.9.4\n",
        sample_id=None,
        mock=True,
        lang="en",
    )
    assert result["mode"] == "mock"
    assert result["verdict"] is None
    assert "Demo mode is on" in result["error"]
    assert "no CLOCKED_API_KEY is configured" not in result["error"]


def test_mock_override_arbitrary_text_demo_notice_ko(monkeypatch):
    monkeypatch.setenv("CLOCKED_API_KEY", "test-key-not-a-real-secret")
    result = run_triage(
        "Some random advisory with no sample marker and no versions.",
        "SW-01, Catalyst 9300, 17.9.4\n",
        sample_id=None,
        mock=True,
        lang="ko",
    )
    assert result["verdict"] is None
    assert _has_hangul(result["error"])
    assert "데모 모드가 켜져 있습니다" in result["error"]
    assert "CLOCKED_API_KEY가 설정되지 않아" not in result["error"]


def test_mock_forced_without_key_keeps_no_key_notice(monkeypatch):
    # mock=True with NO key configured is the app's no-key state
    # (Demo is the only mode), not a deliberate override: the
    # no-key wording still applies.
    monkeypatch.delenv("CLOCKED_API_KEY", raising=False)
    result = run_triage(
        "Some random advisory with no sample marker and no versions.",
        "SW-01, Catalyst 9300, 17.9.4\n",
        sample_id=None,
        api_key=None,
        mock=True,
        lang="en",
    )
    assert result["verdict"] is None
    assert "no CLOCKED_API_KEY is configured" in result["error"]


# ---------------- feature A: narrative version constraints ---------

def test_parse_version_constraint_forms():
    assert parse_version_constraint("before:21.4R2") == {
        "relation": "before", "version": "21.4R2"}
    assert parse_version_constraint("up_to:17.9.5") == {
        "relation": "up_to", "version": "17.9.5"}
    assert parse_version_constraint("train_before:4.30:4.30.6M") == {
        "relation": "train_before", "train": "4.30", "version": "4.30.6M"}
    assert parse_version_constraint("whenever:1.2") is None
    assert parse_version_constraint("before:") is None
    assert parse_version_constraint("train_before:4.30") is None
    assert parse_version_constraint("") is None


def test_constraint_before():
    constraint = {"relation": "before", "version": "21.4R2"}
    assert constraint_matches("21.4R1", constraint) is True
    assert constraint_matches("21.3R3", constraint) is True
    assert constraint_matches("21.4R2", constraint) is False
    assert constraint_matches("21.4R3", constraint) is False
    assert constraint_matches("22.1R1", constraint) is False


def test_constraint_up_to():
    constraint = {"relation": "up_to", "version": "17.9.5"}
    assert constraint_matches("17.9.5", constraint) is True
    assert constraint_matches("17.9.4", constraint) is True
    assert constraint_matches("17.9.6", constraint) is False


def test_constraint_train_before():
    constraint = {"relation": "train_before", "train": "4.30",
                  "version": "4.30.6M"}
    assert constraint_matches("4.30.5M", constraint) is True
    assert constraint_matches("4.30.6M", constraint) is False
    # Different trains never satisfy a train bound.
    assert constraint_matches("4.31.2F", constraint) is False
    assert constraint_matches("4.29.1F", constraint) is False


def test_constraint_suffix_ambiguity_is_unknown():
    # Numeric tuples equal but suffix letters differ (F vs M):
    # suffix ordering is vendor-specific, so this is unknown.
    assert constraint_matches(
        "4.30.5F", {"relation": "before", "version": "4.30.5M"}) is None
    assert constraint_matches(
        "4.30.5F", {"relation": "up_to", "version": "4.30.5M"}) is None
    assert constraint_matches(
        "4.30.5F", {"relation": "train_before", "train": "4.30",
                    "version": "4.30.5M"}) is None
    # Same suffix letter: the numeric comparison decides.
    assert constraint_matches(
        "4.30.5M", {"relation": "before", "version": "4.30.5M"}) is False
    assert constraint_matches(
        "4.30.5M", {"relation": "up_to", "version": "4.30.5M"}) is True


def test_constraint_unparseable_is_unknown():
    assert constraint_matches(
        "unknown", {"relation": "before", "version": "21.4R2"}) is None
    assert constraint_matches(
        "21.4R1", {"relation": "before", "version": "later"}) is None
    assert constraint_matches("21.4R1", {"relation": "sideways",
                                         "version": "21.4R2"}) is None


EXTRACT_CONSTRAINT = {
    "products": ["MX480"],
    "affected_versions": [],
    "version_constraints": ["before:21.4R2"],
}


def test_matcher_constraint_affected_when_list_empty():
    result = match_device(device(model="MX480", version="21.3R3"),
                          EXTRACT_CONSTRAINT)
    assert result["status"] == VERDICT_AFFECTED
    assert result["candidate"] is True
    assert "21.4R2" in result["reason"]
    assert "first fixed" in result["reason"]


def test_matcher_constraint_not_satisfied():
    result = match_device(device(model="MX480", version="21.4R2"),
                          EXTRACT_CONSTRAINT)
    assert result["status"] == VERDICT_NOT_AFFECTED
    assert result["candidate"] is True


def test_matcher_structured_constraint_form_accepted():
    extracted = {
        "products": ["MX480"],
        "affected_versions": [],
        "version_constraints": [
            {"relation": "before", "version": "21.4R2", "confidence": 0.99},
        ],
    }
    result = match_device(device(model="MX480", version="21.4R1"), extracted)
    assert result["status"] == VERDICT_AFFECTED


def test_matcher_decided_list_not_overridden_by_constraint():
    # The explicit list was compared and excluded this version, so
    # the list decided; a looser prose constraint must not override.
    extracted = {
        "products": ["MX480"],
        "affected_versions": ["21.4R1"],
        "version_constraints": ["before:21.4R2"],
    }
    result = match_device(device(model="MX480", version="21.3R3"), extracted)
    assert result["status"] == VERDICT_NOT_AFFECTED


def test_matcher_constraint_reason_ko():
    result = match_device(device(model="MX480", version="21.3R3"),
                          EXTRACT_CONSTRAINT, lang="ko")
    assert result["status"] == VERDICT_AFFECTED
    assert "최초 수정 버전 21.4R2" in result["reason"]


def test_normalize_extraction_structures_new_fields():
    plain = {
        "version_constraints": ["before:21.4R2", "not-a-constraint"],
        "applicability_conditions": [CONDITION_TEXT],
    }
    raw = {
        "version_constraints": {
            "value": ["before:21.4R2", "not-a-constraint"],
            "items": [{"value": "before:21.4R2", "confidence": 0.98}],
            "confidence": 0.9,
        },
        "applicability_conditions": {
            "value": [CONDITION_TEXT],
            "items": [{"value": CONDITION_TEXT, "confidence": 0.97}],
            "confidence": 0.9,
        },
    }
    normalized = normalize_extraction(plain, raw)
    assert normalized["version_constraints"] == [
        {"relation": "before", "version": "21.4R2", "confidence": 0.98}]
    assert normalized["conditions"] == [
        {"text": CONDITION_TEXT, "confidence": 0.97}]


def test_normalize_extraction_absent_fields_become_empty():
    normalized = normalize_extraction({"products": ["X"]}, {})
    assert normalized["version_constraints"] == []
    assert normalized["conditions"] == []


def test_mock_sample6_prior_to_affected():
    result = _run_sample("sample6", "sample6_juniper_prior_to.txt")
    assert result["mode"] == "mock"
    assert result["verdict"] == VERDICT_AFFECTED
    assert result["urgency"] == "immediate"
    assert result["clocked_calls"] == 4
    # CORE-RTR-01 (MX480, Junos 21.3R3) is affected via the prose
    # constraint, not via an explicit version list.
    assert _device_status(result, "CORE-RTR-01") == VERDICT_AFFECTED
    # The bundled mock mirrors the LIVE extract shape: the affected
    # field carries the verbatim prose statement and the
    # version_constraints field is EMPTY (Extract is span-based, so
    # a normalized token is not a span). The before:21.4R2
    # constraint in the result was therefore derived locally.
    assert result["extracted"]["affected_versions"] == [
        "Junos OS versions prior to 21.4R2"]
    raw_mock = load_mock_responses()["sample6"]["extract"]["fields"]
    assert raw_mock["version_constraints"]["value"] == []
    constraints = result["extracted"]["version_constraints"]
    assert constraints[0]["relation"] == "before"
    assert constraints[0]["version"] == "21.4R2"
    # Locally derived entries carry no extractor confidence.
    assert constraints[0]["confidence"] is None
    row = [r for r in result["device_results"]
           if r["hostname"] == "CORE-RTR-01"][0]
    assert "21.4R2" in row["reason"]
    # Sample 2's MX advisory must still leave this device alone:
    # 21.3R3 is not in its explicit affected list.
    result2 = _run_sample("sample2", "sample2_not_affected.txt")
    assert _device_status(result2, "CORE-RTR-01") == VERDICT_NOT_AFFECTED
    assert result2["verdict"] == VERDICT_NOT_AFFECTED


def test_mock_sample6_detected_by_exact_text_without_sample_id():
    result = _run_sample(None, "sample6_juniper_prior_to.txt")
    assert result["sample_id"] == "sample6"
    assert result["verdict"] == VERDICT_AFFECTED


def test_mock_sample6_affected_ko():
    result = _run_sample_ko("sample6", "sample6_juniper_prior_to.txt")
    assert result["verdict"] == VERDICT_AFFECTED
    assert result["urgency"] == "immediate"
    row = [r for r in result["device_results"]
           if r["hostname"] == "CORE-RTR-01"][0]
    assert row["status"] == VERDICT_AFFECTED
    assert "최초 수정 버전" in row["reason"]
    assert all(_has_hangul(item) for item in result["checklist"])
    assert not _has_hangul(result["claim"])


# ---------------- feature B: applicability conditions --------------

CONDITION_TEXT = ("applies only when TerminAttr is configured to "
                  "communicate with CloudVision Portal (CVP)")

EXTRACT_CONDITIONAL = {
    "products": ["Arista 7050SX3"],
    "affected_versions": ["4.30.5M"],
    "advisory_id": "SYN-ARS-2026-1107",
    "applicability_conditions": [CONDITION_TEXT],
}


def test_matcher_condition_gate_blocks_affected():
    result = match_device(device(model="Arista 7050SX3", version="4.30.5M"),
                          EXTRACT_CONDITIONAL)
    assert result["status"] == VERDICT_CANNOT
    assert result["candidate"] is True
    assert result["condition_gated"] is True
    assert "TerminAttr" in result["reason"]
    assert "does not confirm" in result["reason"]


def test_matcher_condition_gate_leaves_other_verdicts_alone():
    not_affected = match_device(
        device(model="Arista 7050SX3", version="4.31.2F"),
        EXTRACT_CONDITIONAL)
    assert not_affected["status"] == VERDICT_NOT_AFFECTED
    assert not_affected["condition_gated"] is False
    other_product = match_device(
        device(model="Catalyst 9300", version="4.30.5M"),
        EXTRACT_CONDITIONAL)
    assert other_product["status"] == VERDICT_NOT_AFFECTED
    assert other_product["condition_gated"] is False


def test_matcher_condition_gate_structured_conditions():
    extracted = dict(EXTRACT_CONDITIONAL)
    del extracted["applicability_conditions"]
    extracted["conditions"] = [{"text": CONDITION_TEXT, "confidence": 0.99}]
    result = match_device(device(model="Arista 7050SX3", version="4.30.5M"),
                          extracted)
    assert result["status"] == VERDICT_CANNOT
    assert result["condition_gated"] is True


def test_build_claim_condition_gate_states_match_and_condition():
    devices = [match_device(device(model="Arista 7050SX3",
                                   version="4.30.5M"),
                            EXTRACT_CONDITIONAL)]
    claim = build_claim(VERDICT_CANNOT, devices, EXTRACT_CONDITIONAL)
    assert "Arista 7050SX3" in claim
    assert "4.30.5M" in claim
    assert "TerminAttr" in claim
    assert "cannot be determined" in claim


def test_compose_verdict_condition_warning():
    composed = compose_verdict(_clean_devices(), _decide("monitor"),
                               _grounding(True),
                               conditions=[CONDITION_TEXT])
    assert any("Condition check required" in w
               for w in composed["warnings"])
    composed_ko = compose_verdict(_clean_devices(), _decide("monitor"),
                                  _grounding(True), lang="ko",
                                  conditions=[CONDITION_TEXT])
    assert any("조건 확인 필요" in w for w in composed_ko["warnings"])


def test_checklist_conditions_prepend_verification_steps():
    items = generate_checklist(VERDICT_CANNOT, "planned",
                               conditions=[CONDITION_TEXT])
    assert "show running-config | include TerminAttr" in items[0]
    # The standard cannot-determine steps still follow.
    assert len(items) > 1
    assert any("Do NOT treat this" in item for item in items[1:])


def test_checklist_conditions_generic_and_ko():
    generic = generate_checklist(VERDICT_CANNOT, "monitor",
                                 conditions=["Only when the FIPS module "
                                             "is enabled"])
    assert "FIPS module" in generic[0]
    ko_items = generate_checklist(VERDICT_CANNOT, "planned", lang="ko",
                                  conditions=[CONDITION_TEXT])
    assert "show running-config | include TerminAttr" in ko_items[0]
    assert _has_hangul(ko_items[0])


def test_mock_sample7_conditional_cannot_determine():
    result = _run_sample("sample7", "sample7_arista_conditional.txt")
    assert result["mode"] == "mock"
    assert result["verdict"] == VERDICT_CANNOT
    assert result["clocked_calls"] == 4
    row = [r for r in result["device_results"]
           if r["hostname"] == "DC-SW-01"][0]
    assert row["status"] == VERDICT_CANNOT
    assert row["condition_gated"] is True
    assert result["conditions"] == [CONDITION_TEXT]
    assert any("Condition check required" in w
               for w in result["warnings"])
    assert "show running-config | include TerminAttr" in result["checklist"][0]
    assert "TerminAttr" in result["claim"]
    # The gate applies even though Decide found the evidence
    # sufficient - conditions are a matcher-level rule.
    assert result["decide"]["evidence_sufficient"]["value"] is True
    # DC-SW-02 is a different product and stays conclusively out.
    assert _device_status(result, "DC-SW-02") == VERDICT_NOT_AFFECTED


def test_mock_sample7_detected_by_exact_text_without_sample_id():
    result = _run_sample(None, "sample7_arista_conditional.txt")
    assert result["sample_id"] == "sample7"
    assert result["verdict"] == VERDICT_CANNOT


def test_mock_sample7_cannot_determine_ko():
    result = _run_sample_ko("sample7", "sample7_arista_conditional.txt")
    assert result["verdict"] == VERDICT_CANNOT
    assert result["conditions"] == [CONDITION_TEXT]
    assert any("조건 확인 필요" in w for w in result["warnings"])
    row = [r for r in result["device_results"]
           if r["hostname"] == "DC-SW-01"][0]
    assert row["condition_gated"] is True
    assert _has_hangul(row["reason"])
    assert "show running-config | include TerminAttr" in result["checklist"][0]
    assert all(_has_hangul(item) for item in result["checklist"])
    assert not _has_hangul(result["claim"])


# --------- repair round: live-path regressions (samples 6-7) ------
#
# Both defects below passed every mock test and only appeared
# against the real API, whose Extract is span-based.

# The EXACT live sample7 condition span (offsets into the sample7
# advisory text; the verbatim span crosses a line break).
LIVE_CONDITION_TEXT = ("applies only when TerminAttr is configured\n"
                       "to communicate with CloudVision Portal (CVP)")

LIVE_CONDITIONS_FIELD = {
    "value": [],
    "items": [{"value": LIVE_CONDITION_TEXT, "start": 428, "end": 515,
               "confidence": 1.0, "p_verify": 1.0}],
    "confidence": 1.0,
}


def test_live_condition_span_survives_unwrap_and_normalize():
    # Defect 1: live, the extracted condition lived only in the
    # field's "items" (field-level "value" empty) and
    # unwrap_extract_fields never consulted "items", so conditions
    # came out [] and the condition gate never fired.
    plain, raw = unwrap_extract_result(
        {"fields": {"applicability_conditions": LIVE_CONDITIONS_FIELD}})
    assert plain["applicability_conditions"] == [LIVE_CONDITION_TEXT]
    normalized = normalize_extraction(plain, raw)
    assert [c["text"] for c in normalized["conditions"]] == [
        LIVE_CONDITION_TEXT]
    # The multi-line span survives intact, newline included.
    assert "\n" in normalized["conditions"][0]["text"]
    assert normalized["conditions"][0]["confidence"] == 1.0


def test_live_condition_wrapped_dicts_in_value_survive():
    # Variant of the same defect: the field "value" holds the
    # still-wrapped item dicts instead of plain strings.
    field = {
        "value": [{"value": LIVE_CONDITION_TEXT, "start": 428,
                   "end": 515, "confidence": 1.0}],
        "items": LIVE_CONDITIONS_FIELD["items"],
        "confidence": 1.0,
    }
    plain, raw = unwrap_extract_result(
        {"fields": {"applicability_conditions": field}})
    assert plain["applicability_conditions"] == [LIVE_CONDITION_TEXT]
    normalized = normalize_extraction(plain, raw)
    assert [c["text"] for c in normalized["conditions"]] == [
        LIVE_CONDITION_TEXT]


def test_live_run_triage_condition_gate_fires(monkeypatch):
    # End to end through the LIVE path with a stub client returning
    # the RECORDED live payload shapes: the main extract call
    # returns applicability_conditions EMPTY (the multi-field call
    # drops it), the affected item carries the vendor prefix
    # ("EOS 4.30.5M"), and only the focused conditions-only call
    # returns the condition. The gate must still fire.
    main_fields = {
        "vendor": {"value": "Arista-style Networks (synthetic sample)",
                   "start": 140, "end": 180, "confidence": 0.99},
        "products": {"value": ["Arista 7050SX3"],
                     "items": [{"value": "Arista 7050SX3", "start": 190,
                                "end": 204, "confidence": 0.99}],
                     "confidence": 0.99},
        "affected_versions": {
            "value": ["EOS 4.30.5M"],
            "items": [{"value": "EOS 4.30.5M", "start": 240, "end": 251,
                       "confidence": 0.99}],
            "confidence": 0.99},
        "applicability_conditions": {"value": [], "items": [],
                                     "confidence": 1.0},
        "advisory_id": {"value": "SYN-ARS-2026-1107", "start": 65,
                        "end": 82, "confidence": 0.99},
        "severity": {"value": "High", "start": 262, "end": 266,
                     "confidence": 0.99},
        "fixed_version": {"value": "EOS 4.30.6M or later",
                          "start": 706, "end": 726, "confidence": 0.99},
    }

    class StubClient(object):
        def __init__(self):
            self.extract_calls = []

        def extract(self, **kwargs):
            self.extract_calls.append(kwargs)
            fields = kwargs.get("fields") or {}
            if set(fields) == {"applicability_conditions", "workarounds"}:
                return {"fields": {
                    "applicability_conditions": LIVE_CONDITIONS_FIELD}}
            return {"fields": main_fields}

        def decide(self, **kwargs):
            return {"answers": {
                "urgency_immediate": {"type": "noul", "noul": 0.9},
                "urgency_planned": {"type": "noul", "noul": 0.8},
                "evidence_sufficient": {"type": "noul", "noul": 0.95},
            }}

        def grounding(self, **kwargs):
            return {"verdict": "grounded", "grounded": 0.95,
                    "ungrounded": 0.05, "answers_question": 0.93}

    stub = StubClient()
    monkeypatch.setattr(triage, "_make_client",
                        lambda api_key: stub)
    root = Path(__file__).resolve().parent.parent
    advisory = (root / "samples" / "sample7_arista_conditional.txt"
                ).read_text(encoding="utf-8")
    inventory = (root / "samples" / "inventory_sample.txt"
                 ).read_text(encoding="utf-8")
    result = run_triage(advisory, inventory, api_key="test-key")
    assert result["mode"] == "live"
    # Two extract calls happened: main + focused conditions pass.
    assert len(stub.extract_calls) == 2
    assert result["clocked_calls"] == 4
    assert result["conditions"] == [LIVE_CONDITION_TEXT]
    assert result["verdict"] == VERDICT_CANNOT
    row = [r for r in result["device_results"]
           if r["hostname"] == "DC-SW-01"][0]
    assert row["condition_gated"] is True
    assert "TerminAttr" in result["claim"]
    assert any("Condition check required" in w
               for w in result["warnings"])
    assert "show running-config | include TerminAttr" in (
        result["checklist"][0])


# ----- repair round 2: focused conditions call + version prefixes --
#
# Live diagnosis behind both: (1) with the full field set, the API
# returns applicability_conditions EMPTY even when the condition is
# plainly in the text; a focused single-field call returns it.
# (2) Live affected-version items carry vendor prefixes
# ("EOS 4.30.5M", "Junos OS 21.2R1") that the plain-list matcher
# could not compare against a bare device version.

class _RecordingExtractClient(object):
    def __init__(self, main_fields, focused_fields):
        self.main_fields = main_fields
        self.focused_fields = focused_fields
        self.calls = []

    def extract(self, **kwargs):
        self.calls.append(kwargs)
        fields = kwargs.get("fields") or {}
        if set(fields) == {"applicability_conditions", "workarounds"}:
            return {"fields": self.focused_fields}
        return {"fields": self.main_fields}


_MAIN_FIELDS_MIN = {
    "products": {"value": ["Arista 7050SX3"],
                 "items": [{"value": "Arista 7050SX3", "start": 190,
                            "end": 204, "confidence": 0.99}],
                 "confidence": 0.99},
    "affected_versions": {"value": ["EOS 4.30.5M"], "items": [],
                          "confidence": 0.99},
    "applicability_conditions": {"value": [], "items": [],
                                 "confidence": 1.0},
}


def test_live_extract_merges_focused_conditions():
    client = _RecordingExtractClient(
        _MAIN_FIELDS_MIN,
        {"applicability_conditions": LIVE_CONDITIONS_FIELD})
    plain, raw = _live_extract(client, "any advisory text")
    # Exactly two extract calls: main field set, then the focused
    # conditions-only pass.
    assert len(client.calls) == 2
    main_fields = client.calls[0]["fields"]
    focused_fields = client.calls[1]["fields"]
    assert set(focused_fields) == {"applicability_conditions",
                                       "workarounds"}
    # The focused call asks for the conditions with the SAME field
    # definition (description text) as the main call.
    assert focused_fields["applicability_conditions"] == \
        main_fields["applicability_conditions"]
    # version_constraints is dead weight in the live schema (a
    # normalized token is not a span; local derivation owns
    # constraints) and must not be requested by either call.
    assert "version_constraints" not in main_fields
    assert "version_constraints" not in focused_fields
    # The focused conditions win over the main call's empty value,
    # raw and plain together (confidence stays attached).
    assert plain["applicability_conditions"] == [LIVE_CONDITION_TEXT]
    assert raw["applicability_conditions"] == LIVE_CONDITIONS_FIELD
    normalized = normalize_extraction(plain, raw)
    assert [c["text"] for c in normalized["conditions"]] == [
        LIVE_CONDITION_TEXT]
    assert normalized["conditions"][0]["confidence"] == 1.0
    # Main-call fields are untouched by the merge.
    assert plain["products"] == ["Arista 7050SX3"]


def test_live_extract_focused_empty_keeps_main_conditions():
    main = dict(_MAIN_FIELDS_MIN)
    main["applicability_conditions"] = {
        "value": [CONDITION_TEXT],
        "items": [{"value": CONDITION_TEXT, "confidence": 0.9}],
        "confidence": 0.9}
    client = _RecordingExtractClient(
        main, {"applicability_conditions": {"value": [], "items": [],
                                            "confidence": 1.0}})
    plain, raw = _live_extract(client, "any advisory text")
    assert plain["applicability_conditions"] == [CONDITION_TEXT]
    normalized = normalize_extraction(plain, raw)
    assert [c["text"] for c in normalized["conditions"]] == [
        CONDITION_TEXT]
    assert normalized["conditions"][0]["confidence"] == 0.9


def test_matcher_prefixed_version_eos():
    extracted = {"products": ["Arista 7050SX3"],
                 "affected_versions": ["EOS 4.30.5M"]}
    hit = match_device(device(model="Arista 7050SX3",
                              version="4.30.5M"), extracted)
    assert hit["status"] == VERDICT_AFFECTED
    miss = match_device(device(model="Arista 7050SX3",
                               version="4.30.6M"), extracted)
    assert miss["status"] == VERDICT_NOT_AFFECTED


def test_matcher_prefixed_version_junos():
    extracted = {"products": ["QFX5110"],
                 "affected_versions": ["Junos OS 21.2R1",
                                       "Junos OS 21.2R2",
                                       "Junos OS 21.2R3"]}
    hit = match_device(device(model="QFX5110", version="21.2R3"),
                       extracted)
    assert hit["status"] == VERDICT_AFFECTED
    miss = match_device(device(model="QFX5110", version="21.2R4"),
                        extracted)
    assert miss["status"] == VERDICT_NOT_AFFECTED


def test_matcher_prefixed_version_feeds_condition_gate():
    # Sample 7's live shape combined: prefixed affected version AND
    # conditions - the match must happen first, then the gate.
    extracted = {"products": ["Arista 7050SX3"],
                 "affected_versions": ["EOS 4.30.5M"],
                 "applicability_conditions": [CONDITION_TEXT]}
    result = match_device(device(model="Arista 7050SX3",
                                 version="4.30.5M"), extracted)
    assert result["status"] == VERDICT_CANNOT
    assert result["condition_gated"] is True


def test_matcher_prose_items_not_reduced_to_tokens():
    # Prose statements carry version tokens but must stay
    # inconclusive - only the derived constraints may decide them.
    for text in ("Junos OS versions prior to 21.4R2",
                 "All releases up to and including 17.9.5",
                 "17.9.5 and earlier",
                 "EOS 4.30.5M or later"):
        extracted = {"products": ["MX480"],
                     "affected_versions": [text]}
        result = match_device(device(model="MX480", version="21.4R2"),
                              extracted)
        assert result["status"] == VERDICT_CANNOT, text


# ---------------- defect 2: local constraint derivation ------------

def _derived_pairs(affected, fixed=None):
    return [(d["relation"], d.get("train"), d["version"])
            for d in derive_version_constraints(affected, fixed)]


def test_derive_before_from_prior_to():
    assert _derived_pairs(
        ["Junos OS versions prior to 21.4R2"],
        "Junos OS 21.4R2 or later") == [("before", None, "21.4R2")]


def test_derive_before_from_earlier_than():
    assert _derived_pairs(
        ["Junos OS versions earlier than 21.4R2"]) == [
        ("before", None, "21.4R2")]


def test_derive_up_to_from_and_earlier():
    assert _derived_pairs(["17.9.5 and earlier"]) == [
        ("up_to", None, "17.9.5")]


def test_derive_up_to_from_up_to_and_including():
    assert _derived_pairs(
        ["All releases up to and including 17.9.5"]) == [
        ("up_to", None, "17.9.5")]


def test_derive_train_before_from_wildcard_train():
    assert _derived_pairs(
        ["EOS 4.30.x releases prior to 4.30.6M"],
        "EOS 4.30.6M or later") == [("train_before", "4.30", "4.30.6M")]


def test_derive_fixed_version_fallback():
    # The bound item names no version itself; the only bound
    # available is the stated first fixed release.
    assert _derived_pairs(
        ["All versions prior to the first fixed release"],
        "Junos OS 21.4R2 or later") == [("before", None, "21.4R2")]


def test_derive_plain_list_unchanged():
    # Plain decidable versions never yield constraints, even with a
    # fixed version present.
    assert derive_version_constraints(
        ["17.9.1", "17.9.2", "17.9.3"], "IOS XE 17.9.6 or later") == []
    assert derive_version_constraints(
        ["21.4R1", "21.4R2", "22.2R1"],
        "Junos OS 21.4R3 or later") == []


def test_derive_vague_prose_without_fixed_unchanged():
    assert derive_version_constraints(
        ["Certain legacy releases are impacted"], None) == []
    # A bound keyword with no token and no fixed version: nothing
    # safe to derive.
    assert derive_version_constraints(
        ["some versions before the fix"], None) == []
    assert derive_version_constraints([], "") == []


def test_derive_sample3_stays_constraint_free():
    canned = load_mock_responses()["sample3"]
    plain, raw = unwrap_extract_result(canned["extract"])
    normalized = normalize_extraction(plain, raw)
    assert normalized["version_constraints"] == []
    assert normalized["conditions"] == []


def test_normalize_merges_explicit_and_derived_deduped():
    plain = {
        "affected_versions": ["Junos OS versions prior to 21.4R2"],
        "version_constraints": ["before:21.4R2"],
        "fixed_version": "Junos OS 21.4R2 or later",
    }
    normalized = normalize_extraction(plain, {})
    constraints = normalized["version_constraints"]
    assert len(constraints) == 1
    assert constraints[0]["relation"] == "before"
    assert constraints[0]["version"] == "21.4R2"


def test_matcher_prose_entry_never_decides_not_affected():
    # Without normalization, a prose affected statement cannot be
    # decided by string comparison at all - it must yield CANNOT
    # DETERMINE for every device version, never a false NOT
    # AFFECTED (the matcher-level half of defect 2).
    extracted = {
        "products": ["MX480"],
        "affected_versions": ["Junos OS versions prior to 21.4R2"],
    }
    for version in ("21.3R3", "21.4R2", "22.1R1"):
        result = match_device(
            device(model="MX480", version=version), extracted)
        assert result["status"] == VERDICT_CANNOT


# --------------------- credit exhaustion -----------------------
# The hackathon credit balance can run out mid-run; the SDK then
# raises InsufficientCreditsError (HTTP 402) on every call. Live
# runs must translate that into a flagged, verdict-less result
# and stop calling, instead of failing obscurely per stage.

class InsufficientCreditsError(Exception):
    """Duck-typed stand-in for the SDK's credit error: detection
    keys on the class name / message, never on an SDK import."""


CREDIT_MESSAGE = ("Clocked API 402: Your credit allowance or "
                  "spending limit has been reached.")


def test_is_credit_error_by_class_name_and_message():
    assert is_credit_error(InsufficientCreditsError("402"))
    assert is_credit_error(Exception(CREDIT_MESSAGE))
    assert is_credit_error(Exception("SPENDING LIMIT reached"))
    assert not is_credit_error(Exception("boom"))
    assert not is_credit_error(ValueError("rate limit exceeded"))
    assert not is_credit_error(Exception("insufficient funds"))


class _CreditStubClient(object):
    """Live-client stub that raises the credit error at one
    chosen stage and records every call it receives."""

    def __init__(self, fail_on):
        self.calls = []
        self.fail_on = fail_on

    def extract(self, **kwargs):
        self.calls.append("extract")
        if self.fail_on == "extract":
            raise InsufficientCreditsError(CREDIT_MESSAGE)
        return {"fields": {}}

    def decide(self, **kwargs):
        self.calls.append("decide")
        if self.fail_on == "decide":
            raise InsufficientCreditsError(CREDIT_MESSAGE)
        return {"answers": {}}

    def grounding(self, **kwargs):
        self.calls.append("grounding")
        return {"verdict": "grounded", "grounded": 0.9,
                "ungrounded": 0.1, "answers_question": 0.9}


def test_live_credit_error_on_first_call_stops_the_run(monkeypatch):
    stub = _CreditStubClient("extract")
    monkeypatch.setattr(triage, "_make_client",
                        lambda api_key: stub)
    result = run_triage("some advisory", "SW-01, Catalyst 9300, 17.9.4",
                        api_key="test-key")
    assert result["credit_exhausted"] is True
    assert result["mode"] == "live"
    assert result["verdict"] is None
    assert "402" in result["error"]
    # Exactly one Clocked call happened: no retries, no later
    # stages.
    assert stub.calls == ["extract"]


def test_live_credit_error_at_decide_stops_before_grounding(monkeypatch):
    stub = _CreditStubClient("decide")
    monkeypatch.setattr(triage, "_make_client",
                        lambda api_key: stub)
    result = run_triage("some advisory", "SW-01, Catalyst 9300, 17.9.4",
                        api_key="test-key")
    assert result["credit_exhausted"] is True
    assert result["verdict"] is None
    # Main + focused extract went through; grounding never ran.
    assert stub.calls == ["extract", "extract", "decide"]


def test_live_non_credit_error_still_raises(monkeypatch):
    class _BoomClient(object):
        def extract(self, **kwargs):
            raise ValueError("boom")

    monkeypatch.setattr(triage, "_make_client",
                        lambda api_key: _BoomClient())
    with pytest.raises(ValueError):
        run_triage("some advisory", "SW-01, Catalyst 9300, 17.9.4",
                   api_key="test-key")
