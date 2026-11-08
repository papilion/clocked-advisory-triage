"""Mock Mode judging of the bundled feed fixtures (batch.py +
triage.py): the NVD/KEV fixtures are demo data, so a Demo run of
the feed pipeline must produce real verdicts for them - under the
same exact-text honesty binding as the seven bundled samples.
A feed-shaped text that is not exactly a fixture-produced text
(a one-character edit, an invented entry reusing a fixture CVE
id) still gets the standing samples-only outcome, never a
fabricated verdict.

No network and no Clocked calls. Run: pytest -q
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest  # noqa: E402

import batch  # noqa: E402
from batch import (  # noqa: E402
    bundled_feed_fixture_texts,
    run_batch,
    run_feed_pipeline,
)
from triage import detect_feed_fixture_id, run_triage  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent

INVENTORY_TEXT = (ROOT / "samples" / "inventory_sample.txt"
                  ).read_text(encoding="utf-8")

FEED_KEYS = {
    "feed_cve_2023_20198",
    "feed_cve_2023_36844",
    "feed_cve_2016_6894",
    "feed_cve_2026_7473",
}


@pytest.fixture(autouse=True)
def _no_api_key(monkeypatch):
    # Deterministic Mock Mode regardless of the caller's environment.
    monkeypatch.delenv("CLOCKED_API_KEY", raising=False)


def _judged_rows(rows):
    return [row for row in rows if row.get("triage")]


def test_mock_feed_pipeline_produces_verdicts_not_errors():
    rows, stats = run_feed_pipeline(INVENTORY_TEXT, mock=True)
    # Design section 3 (K-2): the range-less KEV-only item is a
    # local kev_unconfirmed row in Mock Mode too - it spends no
    # deep-triage budget, so deep_triaged is 3, not 4. Its grade
    # is the bgp-parity pass's intended change: CONDITION CHECK
    # REQUIRED (asserted in the spread test below).
    assert stats["deep_triaged"] == 3
    assert stats["kev_unconfirmed"] == 1
    assert stats["condition_check"] == 1
    judged = [row for row in _judged_rows(rows)
              if row["triage"]["mode"] == "mock"]
    assert len(judged) == 3
    for row in judged:
        assert row["status"] == "ok"
        result = row["triage"]
        assert result["mode"] == "mock"
        assert result["verdict"] in (
            "AFFECTED", "NOT AFFECTED", "CANNOT DETERMINE",
            "CONDITION CHECK REQUIRED")
        # The failure this suite guards: every judged row used to
        # come back as the canned-responses error instead.
        assert not result.get("error")
        assert result["sample_id"] in FEED_KEYS
    kev_row = [row for row in rows
               if row["label"] == "KEV CVE-2026-7473"][0]
    assert kev_row["basis"] == "local-screen"
    assert kev_row["triage"]["verdict"] == "CONDITION CHECK REQUIRED"
    assert kev_row["triage"]["clocked_calls"] == 0
    # Reason codes ride along in Mock Mode too - they are composed
    # locally on both the judged and the local paths (design §2).
    for row in judged:
        assert row["triage"]["reason_code"]
    assert kev_row["triage"]["reason_code"] == "KEV_NO_VERSION_RANGE"
    assert {d["reason_code"]
            for d in kev_row["triage"]["device_results"]
            if d["candidate"]} == {"KEV_NO_VERSION_RANGE"}


def test_mock_feed_pipeline_verdict_spread():
    rows, _stats = run_feed_pipeline(INVENTORY_TEXT, mock=True)
    by_label = {row["label"]: row for row in _judged_rows(rows)}

    # CVE-2023-20198 (Cisco IOS XE web UI privesc, CVSS 10.0): the
    # CSAF lists 17.9.4 and 17.6.5 as affected, and the sample
    # fleet runs exactly those releases.
    result = by_label["CVE-2023-20198"]["triage"]
    assert result["verdict"] == "AFFECTED"
    assert result["urgency"] == "immediate"
    affected = {d["hostname"] for d in result["device_results"]
                if d["status"] == "AFFECTED"}
    assert affected == {"CORE-SW-01", "WAN-RTR-01"}

    # CVE-2023-36844 covers Junos OS on EX Series only; the fleet
    # has QFX/MX Juniper devices but no EX Series.
    assert by_label["CVE-2023-36844"]["triage"]["verdict"] == \
        "NOT AFFECTED"

    # CVE-2016-6894 covers EOS 4.15-4.17 on the 7050 series; the
    # fleet's 7050s run 4.30/4.31 and are cleared by the ranges.
    result = by_label["CVE-2016-6894"]["triage"]
    assert result["verdict"] == "NOT AFFECTED"
    arista = {d["hostname"]: d for d in result["device_results"]
              if d["hostname"] in ("DC-SW-01", "DC-SW-02")}
    assert all(d["candidate"] for d in arista.values())
    assert all(d["status"] == "NOT AFFECTED" for d in arista.values())

    # CVE-2026-7473 is a KEV-only Arista EOS entry stating no
    # affected versions at all: the Arista devices are candidates,
    # the product match is settled, and the open question is the
    # version check - CONDITION CHECK REQUIRED (the K-2 grade).
    result = by_label["KEV CVE-2026-7473"]["triage"]
    assert result["verdict"] == "CONDITION CHECK REQUIRED"
    candidates = {d["hostname"] for d in result["device_results"]
                  if d["status"] == "CONDITION CHECK REQUIRED"}
    assert candidates == {"DC-SW-01", "DC-SW-02"}


def test_mock_feed_pipeline_judge_all_same_verdicts():
    rows, _stats = run_feed_pipeline(
        INVENTORY_TEXT, mock=True, judge_all=True)
    verdicts = {row["label"]: row["triage"]["verdict"]
                for row in _judged_rows(rows)}
    assert verdicts == {
        "KEV CVE-2026-7473": "CONDITION CHECK REQUIRED",
        "CVE-2023-20198": "AFFECTED",
        "CVE-2023-36844": "NOT AFFECTED",
        "CVE-2016-6894": "NOT AFFECTED",
    }


def test_bundled_feed_fixture_texts_cover_raw_and_traced():
    mapping = bundled_feed_fixture_texts()
    assert set(mapping) == FEED_KEYS
    # The two CVEs with bundled vendor documents (Cisco CSAF,
    # Juniper CNA) produce a raw and a traced judged text; the
    # untraceable two produce only the raw one.
    assert len(mapping["feed_cve_2023_20198"]) == 2
    assert len(mapping["feed_cve_2023_36844"]) == 2
    assert len(mapping["feed_cve_2016_6894"]) == 1
    assert len(mapping["feed_cve_2026_7473"]) == 1


def test_every_fixture_text_variant_judges_to_its_verdict():
    expected = {
        "feed_cve_2023_20198": "AFFECTED",
        "feed_cve_2023_36844": "NOT AFFECTED",
        "feed_cve_2016_6894": "NOT AFFECTED",
        "feed_cve_2026_7473": "CANNOT DETERMINE",
    }
    mapping = bundled_feed_fixture_texts()
    for key, texts in mapping.items():
        for text in texts:
            assert detect_feed_fixture_id(text) == key
            result = run_triage(text, INVENTORY_TEXT, mock=True)
            assert result["verdict"] == expected[key]
            assert result["sample_id"] == key


def test_edited_fixture_text_gets_no_canned_verdict():
    text = bundled_feed_fixture_texts()["feed_cve_2016_6894"][0]
    edited = text.replace("4.15.8M", "4.15.9M")
    assert edited != text
    assert detect_feed_fixture_id(edited) is None
    result = run_triage(edited, INVENTORY_TEXT, mock=True)
    assert result["verdict"] is None
    assert "bundled samples" in result["error"]


def test_invented_feed_shaped_text_gets_no_canned_verdict():
    # Same CVE id, same KEV shape, different vulnerability: a CVE
    # id substring alone must never be enough for a canned verdict.
    fake = (
        "KEV CVE-2026-7473 \u2014 Arista Extensible Operating System\n"
        "Date added: 2026-06-09\n"
        "Due date: 2026-06-23\n\n"
        "Arista Extensible Operating System Some Other "
        "Vulnerability\n"
        "Required action: Apply mitigations per vendor "
        "instructions.\n"
        "Known ransomware use: Unknown"
    )
    assert detect_feed_fixture_id(fake) is None
    result = run_triage(fake, INVENTORY_TEXT, mock=True)
    assert result["verdict"] is None
    assert "bundled samples" in result["error"]


def test_mock_listing_sample_path_unaffected():
    sample_text = (ROOT / "samples" / "sample1_affected.txt"
                   ).read_text(encoding="utf-8")
    entries = run_batch(
        ["https://example.invalid/sample1"], INVENTORY_TEXT,
        fetcher=lambda url: sample_text, mock=True)
    assert entries[0]["status"] == "ok"
    assert entries[0]["triage"]["verdict"] == "AFFECTED"
    assert entries[0]["triage"]["sample_id"] == "sample1"
