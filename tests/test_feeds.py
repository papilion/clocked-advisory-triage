"""Offline tests for the vulnerability-feed and file-upload
batch sources (batch.py collectors + Batch mode UI).

No network: feed fetchers are stubbed, and Mock Mode collection
reads the bundled fixture files. Triage runs in Mock Mode against
the bundled samples, like the rest of the batch suite.
Run: pytest -q
"""

import sys
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest  # noqa: E402

import batch  # noqa: E402
from batch import (  # noqa: E402
    FEED_ITEM_CAP,
    MAX_UPLOAD_FILES,
    FetchError,
    collect_feed_items,
    collect_kev_items,
    collect_nvd_items,
    inventory_vendors,
    run_batch_items,
    uploaded_file_to_item,
    uploaded_files_to_items,
)
from triage import parse_inventory  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def _no_api_key(monkeypatch):
    # Deterministic Mock Mode regardless of the caller's environment.
    monkeypatch.delenv("CLOCKED_API_KEY", raising=False)


def _sample_text(filename):
    # type: (str) -> str
    return (ROOT / "samples" / filename).read_text(encoding="utf-8")


def _sample_devices():
    return parse_inventory(_sample_text("inventory_sample.txt"))


# ------------------------- vendor derivation -------------------------

def test_inventory_vendors_from_sample_inventory():
    assert inventory_vendors(_sample_devices()) == [
        "cisco", "juniper", "arista"]


def test_inventory_vendors_from_product_families():
    devices = [
        {"hostname": "A", "model": "QFX5110", "version": "21.2R3"},
        {"hostname": "B", "model": "Something Else", "version": "1.0"},
        {"hostname": "C", "model": "Nokia 7750 SR", "version": "20.0"},
    ]
    assert inventory_vendors(devices) == ["juniper", "nokia"]
    assert inventory_vendors([]) == []


# ------------------------- NVD collection ----------------------------

def _nvd_vuln(cve_id, published, description, score=9.8,
              severity="CRITICAL"):
    return {"cve": {
        "id": cve_id,
        "published": published,
        "descriptions": [{"lang": "es", "value": "ignorado"},
                         {"lang": "en", "value": description}],
        "metrics": {"cvssMetricV31": [{"cvssData": {
            "baseScore": score, "baseSeverity": severity}}]},
        "references": [{"url": "https://vendor.example/%s" % cve_id},
                       {"url": "https://other.example/x"}],
    }}


def _nvd_fetcher_stub(payloads):
    """payloads: {first keyword word (lowercase) -> NVD response}."""
    def fetch(url):
        query = urllib.parse.parse_qs(
            urllib.parse.urlparse(url).query)
        term = (query.get("keywordSearch") or [""])[0]
        key = term.split()[0].lower() if term.split() else ""
        if key not in payloads:
            raise FetchError("HTTP 500")
        return payloads[key]
    return fetch


def test_nvd_collect_parse_sort_and_queries():
    payloads = {
        "cisco": {"vulnerabilities": [
            _nvd_vuln("CVE-2024-0002", "2024-05-01T00:00:00.000",
                      "Cisco IOS XE before 17.9.6 allows bad things."),
            _nvd_vuln("CVE-2024-0001", "2024-06-01T00:00:00.000",
                      "Cisco IOS XE flaw.", score=7.5,
                      severity="HIGH"),
        ]},
        "juniper": {"vulnerabilities": []},
        "arista": {"vulnerabilities": [
            _nvd_vuln("CVE-2024-0003", "2024-04-01T00:00:00.000",
                      "Arista EOS before 4.30.0F is affected."),
        ]},
    }
    result = collect_nvd_items(
        _sample_devices(), fetcher=_nvd_fetcher_stub(payloads))
    assert result["status"] == "ok"
    assert result["count"] == 3
    assert result["queries"] == ["Cisco IOS XE", "Juniper Junos",
                                 "Arista EOS"]
    # Round-robin across vendors (newest first within each vendor),
    # so the Arista item is not crowded out by Cisco's newer batch.
    assert [i["label"] for i in result["items"]] == [
        "CVE-2024-0001", "CVE-2024-0003", "CVE-2024-0002"]
    first = result["items"][0]
    assert first["url"] == ("https://nvd.nist.gov/vuln/detail/"
                            "CVE-2024-0001")
    assert first["text"].startswith(
        "CVE-2024-0001 \u2014 Cisco IOS XE\n"
        "Published: 2024-06-01\nCVSS: 7.5 (HIGH)")
    assert "Cisco IOS XE flaw." in first["text"]
    assert first["text"].endswith(
        "Reference: https://vendor.example/CVE-2024-0001")


def test_nvd_collect_dedupes_across_queries():
    shared = _nvd_vuln("CVE-2024-1111", "2024-01-01T00:00:00.000",
                       "Shared entry.")
    payloads = {"cisco": {"vulnerabilities": [shared]},
                "juniper": {"vulnerabilities": [shared]},
                "arista": {"vulnerabilities": []}}
    result = collect_nvd_items(
        _sample_devices(), fetcher=_nvd_fetcher_stub(payloads))
    assert result["count"] == 1
    assert result["items"][0]["label"] == "CVE-2024-1111"


def test_nvd_collect_cap():
    many = [_nvd_vuln("CVE-2024-%04d" % i,
                       "2024-01-%02dT00:00:00.000" % (i % 28 + 1),
                       "Cisco IOS XE entry %d." % i)
            for i in range(20)]
    devices = [{"hostname": "SW", "model": "Catalyst 9300",
                "version": "17.9.4"}]
    result = collect_nvd_items(
        devices, fetcher=_nvd_fetcher_stub(
            {"cisco": {"vulnerabilities": many}}))
    assert result["status"] == "ok"
    assert result["count"] == FEED_ITEM_CAP


def test_nvd_collect_all_queries_fail():
    def boom(url):
        raise FetchError("HTTP 503")
    result = collect_nvd_items(_sample_devices(), fetcher=boom)
    assert result["status"] == "fetch_failed"
    assert result["items"] == []
    assert "503" in result["reason"]


def test_nvd_collect_empty_and_no_vendors():
    empty = {"vulnerabilities": []}
    result = collect_nvd_items(
        _sample_devices(),
        fetcher=_nvd_fetcher_stub({"cisco": empty, "juniper": empty,
                                   "arista": empty}))
    assert result["status"] == "empty"
    assert result["count"] == 0

    devices = [{"hostname": "X", "model": "Generic Box",
                "version": "1.0"}]
    result = collect_nvd_items(devices, fetcher=_nvd_fetcher_stub({}))
    assert result["status"] == "no_vendors"
    assert result["queries"] == []


def test_nvd_item_without_metrics_or_references():
    vuln = {"cve": {"id": "CVE-2024-2222",
                    "published": "2024-02-02T10:00:00.000",
                    "descriptions": [
                        {"lang": "en", "value": "Bare entry."}]}}
    result = collect_nvd_items(
        [{"hostname": "SW", "model": "Catalyst 9300",
          "version": "17.9.4"}],
        fetcher=_nvd_fetcher_stub({"cisco": {"vulnerabilities": [vuln]}}))
    item = result["items"][0]
    assert "CVSS: not stated" in item["text"]
    assert "Reference:" not in item["text"]


# ------------------------- KEV collection ----------------------------

def _kev_entry(cve_id, vendor, product, added, due="2024-01-20"):
    return {"cveID": cve_id, "vendorProject": vendor,
            "product": product,
            "vulnerabilityName": "Vuln %s" % cve_id,
            "dateAdded": added, "dueDate": due,
            "requiredAction": "Apply mitigations per vendor "
                              "instructions.",
            "knownRansomwareCampaignUse": "Unknown"}


def test_kev_collect_filter_convert_sort():
    catalog = {"vulnerabilities": [
        _kev_entry("CVE-2024-1001", "Cisco", "IOS XE", "2024-01-05"),
        _kev_entry("CVE-2024-1002", "Acme", "Printer Firmware",
                   "2024-02-01"),
        _kev_entry("CVE-2024-1003", "Juniper", "Junos OS",
                   "2024-03-01"),
        # Model-token match: no inventory vendor name in the
        # fields, but the product names an inventory model word.
        _kev_entry("CVE-2024-1004", "ThirdParty", "Catalyst 9300 "
                   "Helper", "2024-01-15"),
    ]}
    result = collect_kev_items(
        _sample_devices(), fetcher=lambda url: catalog)
    assert result["status"] == "ok"
    assert [i["label"] for i in result["items"]] == [
        "KEV CVE-2024-1003", "KEV CVE-2024-1004", "KEV CVE-2024-1001"]
    first = result["items"][0]
    assert first["url"] == ("https://nvd.nist.gov/vuln/detail/"
                            "CVE-2024-1003")
    assert first["text"].startswith(
        "KEV CVE-2024-1003 \u2014 Juniper Junos OS\n"
        "Date added: 2024-03-01\nDue date: 2024-01-20")
    assert "Required action: Apply mitigations" in first["text"]


def test_kev_collect_failure_and_empty():
    def boom(url):
        raise FetchError("timeout")
    result = collect_kev_items(_sample_devices(), fetcher=boom)
    assert result["status"] == "fetch_failed"
    assert result["reason"] == "timeout"

    catalog = {"vulnerabilities": [
        _kev_entry("CVE-2024-2001", "Acme", "Printer", "2024-01-01")]}
    result = collect_kev_items(
        _sample_devices(), fetcher=lambda url: catalog)
    assert result["status"] == "empty"
    assert result["items"] == []


# ------------------------- fixtures (Mock Mode) ----------------------

def test_collect_feed_items_mock_fixtures_offline():
    feed = collect_feed_items(_sample_devices(), mock=True)
    assert feed["nvd"]["status"] == "ok"
    assert feed["kev"]["status"] == "ok"
    assert feed["nvd"]["count"] == 3
    assert feed["kev"]["count"] == 3
    labels = [item["label"] for item in feed["items"]]
    assert labels == ["CVE-2023-20198", "CVE-2023-36844",
                      "CVE-2016-6894",
                      "KEV CVE-2026-7473", "KEV CVE-2023-36844",
                      "KEV CVE-2023-20198"]
    # The NVD fixture CVE for Arista carries EOS version prose and
    # the KEV items carry the due date the action block needs.
    arista = feed["items"][2]
    assert "Arista EOS" in arista["text"]
    assert "DCS-7050" in arista["text"]
    assert "Due date: 2026-06-23" in feed["items"][3]["text"]


# ------------------------- run_batch_items ---------------------------

def test_run_batch_items_mock_verdicts_and_labels():
    inventory = _sample_text("inventory_sample.txt")
    items = [
        {"label": "CVE-FAKE-1", "url": "https://nvd.example/1",
         "text": _sample_text("sample1_affected.txt")},
        {"label": "notes.txt", "url": "",
         "text": _sample_text("sample7_arista_conditional.txt")},
    ]
    progress_calls = []
    results = run_batch_items(
        items, inventory,
        progress=lambda i, total, label: progress_calls.append(
            (i, total, label)))
    assert [r["status"] for r in results] == ["ok", "ok"]
    assert results[0]["label"] == "CVE-FAKE-1"
    assert results[0]["triage"]["verdict"] == "AFFECTED"
    assert results[1]["url"] == ""
    assert results[1]["triage"]["verdict"] == "CANNOT DETERMINE"
    assert progress_calls == [(0, 2, "CVE-FAKE-1"), (1, 2, "notes.txt")]


def test_run_batch_items_prefilter_skips_without_triage():
    inventory = _sample_text("inventory_sample.txt")
    items = [{"label": "printer.txt", "url": "",
              "text": "Office printer firmware 2.0 release notes."}]
    results = run_batch_items(items, inventory, prefilter=True)
    assert results[0]["status"] == "skipped"
    assert results[0]["skip_reason"] == "not_relevant"
    assert "triage" not in results[0]


# ------------------------- uploaded files ----------------------------

def test_uploaded_txt_passthrough():
    item = uploaded_file_to_item(
        "advisory.txt", "Advisory title\nBody line\n".encode("utf-8"))
    assert item == {"label": "advisory.txt", "url": "",
                    "text": "Advisory title\nBody line"}


def test_uploaded_html_by_name_and_by_content():
    html = ("<html><body><nav>menu</nav>"
            "<p>Real advisory body</p></body></html>")
    by_name = uploaded_file_to_item("page.html", html.encode("utf-8"))
    assert by_name["text"] == "Real advisory body"
    by_content = uploaded_file_to_item("page.txt", html.encode("utf-8"))
    assert by_content["text"] == "Real advisory body"


def test_uploaded_cp949_decoded():
    item = uploaded_file_to_item(
        "권고.txt", "보안 권고\n본문입니다".encode("cp949"))
    assert item["label"] == "권고.txt"
    assert item["text"] == "보안 권고\n본문입니다"


def test_uploaded_files_cap():
    files = [("f%02d.txt" % i, b"body") for i in range(12)]
    items = uploaded_files_to_items(files)
    assert len(items) == MAX_UPLOAD_FILES
    assert items[0]["label"] == "f00.txt"


# ------------------------- fleet-wide scope -------------------------
# Analysis coverage is the whole fleet, not just network gear:
# L4/load-balancer (ADC) gear, security appliances and servers are
# detected, queried and prefiltered on the same footing.

FLEET_INVENTORY = (
    "LB-01, F5 BIG-IP 4200, 17.1.0\n"
    "SRV-01, Windows Server 2022, 10.0.20348\n"
    "FW-01, FortiGate 100F, 7.4.3\n"
    "CORE-SW-01, Catalyst 9300, 17.9.4\n"
)


def test_fleet_wide_vendor_detection():
    devices = parse_inventory(FLEET_INVENTORY)
    vendors = inventory_vendors(devices)
    assert "f5" in vendors
    assert "microsoft" in vendors
    assert "fortinet" in vendors
    assert "cisco" in vendors


def test_fleet_wide_derived_nvd_queries():
    devices = parse_inventory(FLEET_INVENTORY)
    terms = batch._nvd_query_terms(devices)
    # One device each: the curated vendor wins the tie, then the
    # rest follow VENDOR_TOKENS order with derived product terms.
    assert terms == ["Cisco IOS XE", "F5 BIG-IP",
                     "Fortinet FortiGate", "Microsoft Windows"]


def test_fleet_wide_query_priority_by_device_count():
    devices = parse_inventory(
        "LB-01, F5 BIG-IP 4200, 17.1.0\n"
        "LB-02, F5 BIG-IP 4200, 17.1.0\n"
        "CORE-SW-01, Catalyst 9300, 17.9.4\n")
    terms = batch._nvd_query_terms(devices)
    # Two F5 devices outrank one Cisco device, curated map or not.
    assert terms == ["F5 BIG-IP", "Cisco IOS XE"]


def test_fleet_wide_prefilter_and_kev():
    devices = parse_inventory(FLEET_INVENTORY)
    tokens = batch.build_relevance_tokens(devices)
    assert batch.is_relevant(
        "F5 BIG-IP TMOS vulnerability in the load balancer "
        "module", tokens)
    assert batch.is_relevant(
        "Microsoft Windows Server privilege escalation advisory",
        tokens)
    assert not batch.is_relevant(
        "Acme OfficeJet Printer Firmware Advisory\n"
        "A firmware update for office inkjet printers improves "
        "photo printing quality.", tokens)
    # KEV filtering keys off the same vendor detection + device
    # tokens, so fleet vendors benefit with no separate change.
    catalog = {"vulnerabilities": [
        _kev_entry("CVE-2024-3001", "F5", "BIG-IP", "2024-03-01"),
        _kev_entry("CVE-2024-3002", "Acme", "Printer Firmware",
                   "2024-03-02"),
    ]}
    result = collect_kev_items(devices, fetcher=lambda url: catalog)
    assert [i["label"] for i in result["items"]] == [
        "KEV CVE-2024-3001"]


# ------------------------- batch UI (AppTest) ------------------------

from streamlit.testing.v1 import AppTest  # noqa: E402

APP = str(ROOT / "app.py")


def _fresh_batch_app():
    at = AppTest.from_file(APP)
    at.run()
    assert not at.exception
    return at


def _click_button(at, label_part):
    matches = [b for b in at.button if label_part in (b.label or "")]
    assert len(matches) == 1, "buttons: %r" % [b.label for b in at.button]
    matches[0].click().run()
    assert not at.exception


def test_feeds_source_mock_run_yields_summary():
    at = _fresh_batch_app()
    at.radio[1].set_value("feeds").run()
    assert not at.exception
    captions = [c.value or "" for c in at.caption]
    assert any("machine-readable feeds" in c for c in captions), captions

    _click_button(at, "Run Batch")
    feed_info = at.session_state["feed_info"]
    assert feed_info["nvd"]["count"] == 3
    assert feed_info["kev"]["count"] == 3
    captions = [c.value or "" for c in at.caption]
    assert any("NVD: 3 CVEs collected" in c and "KEV: 3 matches" in c
               for c in captions), captions
    results = at.session_state["batch_results"]
    assert results is not None
    assert len(results) == 6
    # Judging runs KEV-first (known-exploited entries get the
    # vendor-trace budget first), then the NVD items.
    assert results[0]["label"] == "KEV CVE-2026-7473"
    assert results[3]["label"] == "CVE-2023-20198"
    # Mock Mode tracing resolves the fixture-backed routes: the
    # Cisco NVD item via its CSAF fixture, both CVE-2023-36844
    # items via the CNA fixture - shown in the traced caption.
    captions = [c.value or "" for c in at.caption]
    assert any("Vendor-traced: 3 of 6" in c for c in captions), captions


def test_uploads_source_empty_run_shows_notice():
    at = _fresh_batch_app()
    at.radio[1].set_value("uploads").run()
    assert not at.exception
    captions = [c.value or "" for c in at.caption]
    assert any("your own browser" in c for c in captions), captions

    _click_button(at, "Run Batch")
    warnings = [w.value or "" for w in at.warning]
    assert any("Upload at least one advisory file" in w
               for w in warnings), warnings
    assert at.session_state["batch_results"] is None


def test_new_sources_render_korean():
    at = _fresh_batch_app()
    at.selectbox[0].set_value("한국어").run()
    assert not at.exception
    options = at.radio[1].options
    assert any("취약점 피드" in option for option in options), options
    assert any("권고 파일 업로드" in option for option in options), options
