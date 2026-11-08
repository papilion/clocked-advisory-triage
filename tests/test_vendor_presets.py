"""Vendor listing presets: the Listing source's Cisco / Juniper /
Arista / Nokia / Extreme buttons run the feed pipeline scoped to
one vendor (batch.run_feed_pipeline(vendor=...)) - collection from
the structured sources (NVD / CISA KEV) and vendor tracing, never
the vendor's web listing. Covers the batch-level scoping (injected
fetchers), the live-path smoke for one vendor, the per-vendor Demo
outcomes over the bundled fixtures, and the AppTest surface
(verdict rendering, the Nokia/Extreme demo notice EN + KO).

No network and no Clocked calls: fetchers are stubbed or the
bundled fixtures answer. Run: pytest -q
"""

import copy
import datetime
import json
import sys
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest  # noqa: E402
from streamlit.testing.v1 import AppTest  # noqa: E402

import batch  # noqa: E402
from batch import collect_feed_items_year, run_feed_pipeline  # noqa: E402
from triage import parse_inventory  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
APP = str(ROOT / "app.py")

INVENTORY_TEXT = (ROOT / "samples" / "inventory_sample.txt"
                  ).read_text(encoding="utf-8")
DEVICES = parse_inventory(INVENTORY_TEXT)

NOW = datetime.datetime(2026, 11, 7, 12, 0, 0,
                        tzinfo=datetime.timezone.utc)


@pytest.fixture(autouse=True)
def _no_api_key(monkeypatch):
    # Deterministic Mock Mode regardless of the caller's environment.
    monkeypatch.delenv("CLOCKED_API_KEY", raising=False)


# ------------------------- injected payloads -----------------------

def _vuln(cve_id, published, description, configurations=None):
    cve = {"id": cve_id, "published": published,
           "descriptions": [{"lang": "en", "value": description}]}
    if configurations is not None:
        cve["configurations"] = configurations
    return {"cve": cve}


def _kev_entry(cve_id, vendor, product, added, due="2027-01-01"):
    return {"cveID": cve_id, "vendorProject": vendor,
            "product": product, "dateAdded": added, "dueDate": due,
            "vulnerabilityName": "%s flaw" % cve_id,
            "requiredAction": "Apply the vendor fix.",
            "knownRansomwareCampaignUse": "Unknown"}


def _term_fetcher(payloads, record=None):
    """payloads: {first keyword word (lowercase) -> payload}."""
    def fetch(url):
        if record is not None:
            record.append(url)
        query = urllib.parse.parse_qs(
            urllib.parse.urlparse(url).query)
        term = (query.get("keywordSearch") or [""])[0]
        key = term.split()[0].lower() if term.split() else ""
        return payloads[key]
    return fetch


# --------------------- collection scoping --------------------------

def test_collection_scoped_to_chosen_vendor():
    # Two vendors' NVD payloads and a mixed KEV catalog: scoped to
    # Cisco, only the Cisco query is ever issued and only Cisco
    # items come back - the Juniper payload is never even fetched
    # for content, and the Arista KEV entry does not pass.
    urls = []  # type: list
    nvd_fetcher = _term_fetcher({
        "cisco": {"vulnerabilities": [
            _vuln("CVE-2026-7001", "2026-10-01T00:00:00.000",
                  "Cisco IOS XE flaw.")]},
        "juniper": {"vulnerabilities": [
            _vuln("CVE-2026-7002", "2026-10-02T00:00:00.000",
                  "Juniper Junos OS flaw.")]},
    }, record=urls)
    catalog = {"vulnerabilities": [
        _kev_entry("CVE-2026-7001", "Cisco", "IOS XE", "2026-10-20"),
        _kev_entry("CVE-2026-7003", "Arista", "EOS", "2026-10-21"),
    ]}
    feed = collect_feed_items_year(
        DEVICES, nvd_fetcher=nvd_fetcher,
        kev_fetcher=lambda url: catalog, now=NOW, vendor="cisco")
    assert feed["nvd"]["queries"] == ["Cisco IOS XE"]
    terms = set()
    for url in urls:
        query = urllib.parse.parse_qs(
            urllib.parse.urlparse(url).query)
        terms.add((query.get("keywordSearch") or [""])[0])
    assert terms == {"Cisco IOS XE"}
    labels = [item["label"] for item in feed["items"]]
    assert labels == ["CVE-2026-7001"]
    # The recent Cisco KEV entry merged into its NVD item; the
    # Arista entry was scoped out (not counted, not merged).
    assert feed["items"][0]["kev"] is True
    assert feed["kev"]["count"] == 1
    assert feed["stats"]["total"] == 1


def test_collection_scoped_kev_only_item_for_chosen_vendor():
    # A KEV entry whose CVE has no NVD item becomes a KEV-only
    # item - but only for the scoped vendor.
    catalog = {"vulnerabilities": [
        _kev_entry("CVE-2026-7003", "Arista", "EOS", "2026-10-21"),
        _kev_entry("CVE-2026-7001", "Cisco", "IOS XE", "2026-10-20"),
    ]}
    feed = collect_feed_items_year(
        DEVICES,
        nvd_fetcher=_term_fetcher({"arista": {"vulnerabilities": []}}),
        kev_fetcher=lambda url: catalog, now=NOW, vendor="arista")
    assert feed["nvd"]["queries"] == ["Arista EOS"]
    assert [item["label"] for item in feed["items"]] == [
        "KEV CVE-2026-7003"]
    assert feed["stats"]["kev_only"] == 1


# --------------------- live-path smoke (injected) ------------------

def _fixture_record(cve_id):
    data = json.loads((ROOT / "samples" / "nvd_fixture.json")
                      .read_text(encoding="utf-8"))
    kept = [v for v in data["vulnerabilities"]
            if (v.get("cve") or {}).get("id") == cve_id]
    payload = copy.deepcopy(data)
    payload["vulnerabilities"] = kept
    payload["totalResults"] = len(kept)
    return payload


def test_pipeline_live_path_smoke_cisco():
    # mock=False (the live code path) with the network replaced by
    # injected fetchers serving the bundled Cisco record + CSAF
    # trace fixture; with no API key configured the judge falls
    # back to Mock Mode and the traced CSAF text earns its canned
    # AFFECTED verdict - the full vendor-scoped chain end to end.
    catalog = json.loads((ROOT / "samples" / "kev_fixture.json")
                         .read_text(encoding="utf-8"))
    rows, stats = run_feed_pipeline(
        INVENTORY_TEXT, mock=False, vendor="cisco",
        nvd_fetcher=_term_fetcher(
            {"cisco": _fixture_record("CVE-2023-20198")}),
        kev_fetcher=lambda url: catalog,
        trace_fetcher=batch._fixture_trace_text_fetcher,
        trace_json_fetcher=batch._fixture_trace_json_fetcher,
        now=NOW)
    assert stats["vendor"] == "cisco"
    assert stats["nvd"]["queries"] == ["Cisco IOS XE"]
    assert stats["collection"]["total"] == 1
    assert len(rows) == 1
    row = rows[0]
    assert row["label"] == "CVE-2023-20198"
    assert row["status"] == "ok"
    assert row["triage"]["verdict"] == "AFFECTED"
    assert not row["triage"].get("error")


# --------------------- demo outcomes (mock fixtures) ---------------

def test_demo_vendor_cisco_verdict():
    rows, stats = run_feed_pipeline(INVENTORY_TEXT, mock=True,
                                    vendor="cisco")
    assert stats["vendor"] == "cisco"
    assert [row["label"] for row in rows] == ["CVE-2023-20198"]
    row = rows[0]
    assert row["status"] == "ok"
    assert row["triage"]["verdict"] == "AFFECTED"
    assert not row["triage"].get("error")


def test_demo_vendor_juniper_verdict():
    rows, stats = run_feed_pipeline(INVENTORY_TEXT, mock=True,
                                    vendor="juniper")
    assert stats["vendor"] == "juniper"
    assert [row["label"] for row in rows] == ["CVE-2023-36844"]
    row = rows[0]
    assert row["status"] == "ok"
    assert row["triage"]["verdict"] == "NOT AFFECTED"
    assert not row["triage"].get("error")


def test_demo_vendor_arista_verdicts():
    rows, stats = run_feed_pipeline(INVENTORY_TEXT, mock=True,
                                    vendor="arista")
    assert stats["vendor"] == "arista"
    verdicts = {row["label"]: row["triage"]["verdict"]
                for row in rows}
    assert verdicts == {"KEV CVE-2026-7473":
                        "CONDITION CHECK REQUIRED",
                        "CVE-2016-6894": "NOT AFFECTED"}
    assert all(row["status"] == "ok" for row in rows)
    assert all(not row["triage"].get("error") for row in rows)


@pytest.mark.parametrize("vendor", ["nokia", "extreme"])
def test_demo_vendor_without_fixtures_collects_nothing(vendor):
    # Pipeline level: no fixture data exists for these vendors, so
    # the scoped collection honestly comes back empty - the app
    # turns this into the designed demo notice (AppTest below).
    rows, stats = run_feed_pipeline(INVENTORY_TEXT, mock=True,
                                    vendor=vendor)
    assert stats["vendor"] == vendor
    assert stats["collection"]["total"] == 0
    assert rows == []


# --------------------------- AppTest -------------------------------

def _fresh_batch_app():
    at = AppTest.from_file(APP)
    at.run()
    assert not at.exception
    assert at.radio[0].value == "batch"
    assert at.radio[1].value == "listing"
    return at


def _click_vendor(at, vendor):
    matches = [b for b in at.button
               if b.key == "vendor_preset_%s" % vendor]
    assert len(matches) == 1
    matches[0].click().run()
    assert not at.exception


def _click_run_batch(at):
    matches = [b for b in at.button
               if "Run Batch" in (b.label or "")
               or "배치 실행" in (b.label or "")]
    assert len(matches) == 1, "buttons: %r" % [b.label for b in at.button]
    matches[0].click().run()
    assert not at.exception


def test_app_vendor_preset_selects_and_clears_url():
    at = _fresh_batch_app()
    at.text_input[0].set_value("https://vendor.example/list").run()
    assert not at.exception
    _click_vendor(at, "cisco")
    assert at.session_state["listing_vendor"] == "cisco"
    # The URL field is cleared: while a preset is active the run
    # ignores it, and the UI must not suggest both are in play.
    assert at.session_state["listing_url"] == ""


def test_app_vendor_demo_cisco_run_renders_verdict():
    at = _fresh_batch_app()
    _click_vendor(at, "cisco")
    _click_run_batch(at)
    results = at.session_state["batch_results"]
    assert results is not None and len(results) == 1
    row = results[0]
    assert row["status"] == "ok"
    assert row["triage"]["verdict"] == "AFFECTED"
    assert at.session_state["vendor_info"] == {"vendor": "cisco"}
    assert at.session_state["feed_info"]["vendor"] == "cisco"
    captions = [c.value or "" for c in at.caption]
    assert any("Vendor listing" in c and "structured sources" in c
               for c in captions), captions


def test_app_vendor_demo_arista_run_renders_both_fixtures():
    at = _fresh_batch_app()
    _click_vendor(at, "arista")
    _click_run_batch(at)
    results = at.session_state["batch_results"]
    assert results is not None and len(results) == 2
    assert all(r["status"] == "ok" for r in results)
    assert {r["triage"]["verdict"] for r in results} == {
        "CONDITION CHECK REQUIRED", "NOT AFFECTED"}


def test_app_vendor_demo_nokia_notice():
    at = _fresh_batch_app()
    _click_vendor(at, "nokia")
    _click_run_batch(at)
    # Designed notice, not an empty table and not ERROR rows: no
    # results are produced at all, and the warning names the demo
    # coverage and the live-mode route.
    assert at.session_state["batch_results"] is None
    assert at.session_state["vendor_demo_notice"] == "nokia"
    warnings = [w.value or "" for w in at.warning]
    assert any("Demo data covers Cisco, Juniper and Arista only" in w
               and "Nokia" in w for w in warnings), warnings


def test_app_vendor_demo_extreme_notice():
    at = _fresh_batch_app()
    _click_vendor(at, "extreme")
    _click_run_batch(at)
    assert at.session_state["batch_results"] is None
    assert at.session_state["vendor_demo_notice"] == "extreme"
    warnings = [w.value or "" for w in at.warning]
    assert any("Extreme Networks" in w for w in warnings), warnings


def test_app_vendor_demo_nokia_notice_korean():
    at = AppTest.from_file(APP)
    at.run()
    assert not at.exception
    at.selectbox[0].set_value("한국어").run()
    assert not at.exception
    _click_vendor(at, "nokia")
    _click_run_batch(at)
    assert at.session_state["vendor_demo_notice"] == "nokia"
    warnings = [w.value or "" for w in at.warning]
    assert any("데모 데이터는 Cisco" in w and "Nokia" in w
               for w in warnings), warnings


def test_vendor_preset_nokia_caption_no_original():
    # Seeded-state render (the year-suite renderer pattern): a
    # Nokia vendor run carries the no-vendor-original caption; a
    # Cisco run does not.
    sentence = ("No vendor structured original is available for "
                "this vendor")
    for vendor, expected in (("nokia", True), ("cisco", False)):
        at = AppTest.from_file(APP)
        at.session_state["batch_results"] = []
        at.session_state["batch_source"] = "listing"
        at.session_state["vendor_info"] = {"vendor": vendor}
        at.session_state["feed_info"] = {
            "vendor": vendor, "nvd": {"count": 0},
            "kev": {"count": 0}, "screening": {},
            "collection": {}, "reachability": {}}
        at.run()
        assert not at.exception
        captions = [c.value or "" for c in at.caption]
        assert any(sentence in c for c in captions) is expected, \
            (vendor, captions)
