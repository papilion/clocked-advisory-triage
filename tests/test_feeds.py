"""Offline tests for the vulnerability-feed and file-upload
batch sources (batch.py collectors + Batch mode UI).

No network: feed fetchers are stubbed, and Mock Mode collection
reads the bundled fixture files. Triage runs in Mock Mode against
the bundled samples, like the rest of the batch suite.
Run: pytest -q
"""

import datetime
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
        "cisco", "juniper", "arista", "nokia", "extreme"]


def test_inventory_vendors_from_product_families():
    devices = [
        {"hostname": "A", "model": "QFX5110", "version": "21.2R3"},
        {"hostname": "B", "model": "Something Else", "version": "1.0"},
        {"hostname": "C", "model": "Nokia 7750 SR", "version": "20.0"},
    ]
    assert inventory_vendors(devices) == ["juniper", "nokia"]
    assert inventory_vendors([]) == []


def test_inventory_vendors_nokia_extreme_signatures():
    # Signatures beyond the vendor name itself: Nokia's 7750 /
    # 7250 SR lines and Extreme's Summit / X450 / X650 EXOS
    # switches are recognized from the hardware model alone.
    devices = [
        {"hostname": "A", "model": "7750 SR-12",
         "version": "21.10.R1"},
        {"hostname": "B", "model": "7250 IXR-10",
         "version": "21.10.R1"},
        {"hostname": "C", "model": "Summit X450a-24x",
         "version": "12.4.4.10"},
        {"hostname": "D", "model": "X650-24x",
         "version": "15.3.5.2"},
    ]
    assert inventory_vendors(devices) == ["nokia", "extreme"]
    assert batch._device_vendor(devices[0]) == "nokia"
    assert batch._device_vendor(devices[1]) == "nokia"
    assert batch._device_vendor(devices[2]) == "extreme"
    assert batch._device_vendor(devices[3]) == "extreme"


def test_nvd_query_terms_include_nokia_and_extreme():
    devices = [
        {"hostname": "A", "model": "Nokia 7750 SR-12",
         "version": "21.10.R1"},
        {"hostname": "B", "model": "Extreme X450a-24x",
         "version": "12.4.4.10"},
    ]
    assert batch._nvd_query_terms(devices) == [
        "Nokia SR OS", "Extreme EXOS"]


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
        "nokia": {"vulnerabilities": []},
    }
    result = collect_nvd_items(
        _sample_devices(), fetcher=_nvd_fetcher_stub(payloads))
    assert result["status"] == "ok"
    assert result["count"] == 3
    # The query cap (6) admits all five sample vendors, Nokia and
    # Extreme included, in device-count order.
    assert result["queries"] == ["Cisco IOS XE", "Juniper Junos",
                                 "Arista EOS", "Nokia SR OS",
                                 "Extreme EXOS"]
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


def test_kev_collect_matches_nokia_and_extreme():
    # KEV matching runs off the same vendor detection as the NVD
    # queries: Nokia and Extreme catalog entries match an
    # inventory carrying their hardware, and unrelated vendors
    # stay out.
    devices = [
        {"hostname": "A", "model": "Nokia 7750 SR-12",
         "version": "21.10.R1"},
        {"hostname": "B", "model": "Extreme X450a-24x",
         "version": "12.4.4.10"},
    ]
    catalog = {"vulnerabilities": [
        _kev_entry("CVE-2024-3001", "Nokia", "SR OS",
                   "2024-01-05"),
        _kev_entry("CVE-2024-3002", "Extreme Networks", "EXOS",
                   "2024-02-01"),
        _kev_entry("CVE-2024-3003", "Acme", "Printer",
                   "2024-03-01"),
    ]}
    result = collect_kev_items(devices, fetcher=lambda url: catalog)
    assert result["status"] == "ok"
    assert [i["label"] for i in result["items"]] == [
        "KEV CVE-2024-3002", "KEV CVE-2024-3001"]


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
    # The shared merge (design section 4) makes one item per CVE:
    # 3 NVD items, two of which merge their KEV twins, plus the
    # one KEV-only item - 4 items, not 6.
    labels = [item["label"] for item in feed["items"]]
    assert labels == ["CVE-2023-20198", "CVE-2023-36844",
                      "CVE-2016-6894", "KEV CVE-2026-7473"]
    assert feed["stats"]["kev_merged"] == 2
    assert feed["stats"]["kev_only"] == 1
    merged = feed["items"][0]
    assert merged["kev"] is True
    assert merged["sources"] == ["NVD", "KEV"]
    assert feed["items"][1]["sources"] == ["NVD", "KEV"]
    assert feed["items"][2]["sources"] == ["NVD"]
    assert feed["items"][3]["sources"] == ["KEV"]
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
    # Sample 7's conditional advisory: gated grade (bgp parity §3).
    assert results[1]["triage"]["verdict"] == \
        "CONDITION CHECK REQUIRED"
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
    # KEV is windowed to the same 365 days as NVD: of the
    # fixture's 3 KEV matches only the 2026 entry is inside the
    # window; the two 2023 entries are excluded (and counted), so
    # nothing merges into the NVD items.
    assert feed_info["kev"]["count"] == 1
    assert feed_info["kev"]["older_excluded"] == 2
    # 3 NVD items + 1 in-window KEV-only item = 4 unique items,
    # all of which screen in as candidates against the sample
    # inventory (one Junos exact-version hit, the rest uncertain).
    # Their traces attach vendor ranges, but both traced items
    # have fleet devices inside those ranges, so the re-screen
    # clears none of them.
    assert feed_info["collection"]["total"] == 4
    assert feed_info["collection"]["kev_merged"] == 0
    assert feed_info["collection"]["kev_only"] == 1
    assert feed_info["collection"]["kev_older_excluded"] == 2
    assert feed_info["screening"]["candidates"] == 4
    assert feed_info["screening"]["local_not_affected"] == 0
    assert feed_info["rescreened_not_affected"] == 0
    assert feed_info["deep_triaged"] == 3
    assert feed_info["kev_unconfirmed"] == 1
    captions = [c.value or "" for c in at.caption]
    assert any("Collected last 365 days: NVD 3 · KEV 1" in c
               for c in captions), captions
    assert any("Local screening: 0 not affected by version range"
               in c and "3 deep-triaged" in c
               for c in captions), captions
    results = at.session_state["batch_results"]
    assert results is not None
    assert len(results) == 4
    # Rows sort KEV first, then newest: the in-window KEV-only
    # Arista item, then the NVD items newest-first (the two 2023
    # CVEs are plain NVD items now - their KEV entries fell
    # outside the 365-day window).
    assert [r["label"] for r in results] == [
        "KEV CVE-2026-7473", "CVE-2023-20198", "CVE-2023-36844",
        "CVE-2016-6894"]
    # Mock Mode tracing resolves the fixture-backed routes among
    # the candidates: the Cisco item via its CSAF fixture, the
    # Juniper item via the CNA fixture. The caption counts the
    # trace-for-screen pass over the candidates (4 attempted of
    # 4 candidates), not the deep-triaged subset.
    captions = [c.value or "" for c in at.caption]
    assert any("Vendor-traced: 4 of 4 candidates" in c
               for c in captions), captions


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


# ----------------- NVD windows / retry / key (design 1) -------------

_FEEDS_NOW = datetime.datetime(2026, 11, 7, 12, 0, 0,
                               tzinfo=datetime.timezone.utc)


def test_nvd_recent_window_always_present():
    urls = []

    def stub(url):
        urls.append(url)
        return {"vulnerabilities": [], "totalResults": 0}

    collect_nvd_items(_sample_devices(), fetcher=stub, now=_FEEDS_NOW)
    batch.collect_nvd_items_year(
        _sample_devices(), fetcher=stub, now=_FEEDS_NOW)
    assert urls
    for url in urls:
        query = urllib.parse.parse_qs(
            urllib.parse.urlparse(url).query)
        assert "pubStartDate" in query and "pubEndDate" in query
        start = datetime.datetime.fromisoformat(
            query["pubStartDate"][0])
        end = datetime.datetime.fromisoformat(query["pubEndDate"][0])
        assert end - start <= datetime.timedelta(days=120)
        assert end <= _FEEDS_NOW.replace(tzinfo=None) \
            + datetime.timedelta(days=1)
    ends = []
    for url in urls:
        query = urllib.parse.parse_qs(
            urllib.parse.urlparse(url).query)
        ends.append(datetime.datetime.fromisoformat(
            query["pubEndDate"][0]))
    # The newest window (and the recent collector) ends at now.
    assert abs(max(ends) - _FEEDS_NOW.replace(tzinfo=None)) \
        <= datetime.timedelta(days=1)


def test_nvd_retry_on_429_then_success():
    calls = []
    sleeps = []
    vuln = {"cve": {"id": "CVE-2026-1111",
                    "published": "2026-10-01T00:00:00.000",
                    "descriptions": [{"lang": "en", "value":
                                      "Cisco IOS XE flaw."}]}}

    def flaky(url):
        calls.append(url)
        if len(calls) == 1:
            raise FetchError("HTTP 429", status=429, retry_after=7)
        return {"vulnerabilities": [vuln]}

    result = collect_nvd_items(
        _sample_devices(), fetcher=flaky, vendor="cisco",
        sleep=sleeps.append)
    assert result["status"] == "ok"
    assert result["count"] == 1
    assert sleeps == [7.0]


def test_nvd_retry_exhausted_is_fetch_failed():
    calls = []
    sleeps = []

    def always_429(url):
        calls.append(url)
        raise FetchError("HTTP 429", status=429)

    result = collect_nvd_items(
        _sample_devices(), fetcher=always_429, vendor="cisco",
        sleep=sleeps.append)
    assert result["status"] == "fetch_failed"
    assert len(calls) == 1 + batch.NVD_MAX_RETRIES
    assert sleeps == [2.0, 5.0]


def test_nvd_no_retry_on_500():
    calls = []

    def fail_500(url):
        calls.append(url)
        raise FetchError("HTTP 500", status=500)

    result = collect_nvd_items(
        _sample_devices(), fetcher=fail_500, vendor="cisco",
        sleep=lambda seconds: None)
    assert result["status"] == "fetch_failed"
    assert len(calls) == 1
    assert "HTTP 500" in result["reason"]


def test_nvd_api_key_sent_as_header_not_url(monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "test-only")
    captured = {}

    def fake_fetch_json(url, timeout=15, headers=None):
        captured["url"] = url
        captured["headers"] = headers
        return {"vulnerabilities": []}

    monkeypatch.setattr(batch, "_fetch_json", fake_fetch_json)
    fetch = batch._nvd_fetcher(None, has_key=True)
    fetch("https://services.nvd.nist.gov/rest/json/cves/2.0?x=1")
    assert captured["headers"] == {"apiKey": "test-only"}
    assert "test-only" not in captured["url"]


# ----------------- KEV structured fields (design 3) -----------------

def test_kev_item_structured_fields():
    entry = _kev_entry("CVE-2026-1111", "Juniper", "Junos OS",
                       "2026-09-01", due="2026-10-01")
    entry["knownRansomwareCampaignUse"] = "Known"
    entry["requiredAction"] = "Apply fix."
    item = batch._kev_item(entry)
    assert item["required_action"] == "Apply fix."
    assert item["ransomware"] == "Known"
    assert item["vuln_name"] == "Vuln CVE-2026-1111"
    assert item["vendor_project"] == "Juniper"
    assert item["product_name"] == "Junos OS"
    assert item["due_date"] == "2026-10-01"
    assert item["sources"] == ["KEV"]
    # The text stays byte-identical to the long-standing format
    # (Mock Mode binds canned responses to exact item texts).
    assert item["text"] == (
        "KEV CVE-2026-1111 \u2014 Juniper Junos OS\n"
        "Date added: 2026-09-01\n"
        "Due date: 2026-10-01\n\n"
        "Vuln CVE-2026-1111\n"
        "Required action: Apply fix.\n"
        "Known ransomware use: Known")


def test_deep_triage_kev_text_cannot_be_affected():
    # The deep-path invariant (K-A) at the matcher level: an
    # Extract result shaped like a range-less KEV text (product
    # named, no affected versions, no constraints) can only be
    # CANNOT DETERMINE with the no_affected_versions reason.
    from triage import match_device
    device = {"hostname": "RTR-01", "model": "Juniper Junos OS MX480",
              "version": "21.3R3"}
    extracted = {"products": ["Junos OS"], "affected_versions": [],
                 "version_constraints": [],
                 "applicability_conditions": []}
    row = match_device(device, extracted)
    assert row["status"] == "CANNOT DETERMINE"
    assert row["reason"] == (
        "Product matches, but the advisory states no affected "
        "versions.")


# ----------------- shared merge (design 4) --------------------------

def test_merge_feed_items_precedence():
    rng = {"vendor": "cisco", "product": "ios_xe", "exact": None,
           "start_including": "17.9", "start_excluding": None,
           "end_including": None, "end_excluding": "17.9.5"}
    nvd_item = {"label": "CVE-2026-4001",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-4001",
                "text": "CVE-2026-4001 base text.",
                "published": "2026-08-01", "severity_rank": 3,
                "kev": False, "sources": ["NVD"],
                "cpe_ranges": [rng], "references": []}
    kev_item = batch._kev_item({
        "cveID": "CVE-2026-4001", "vendorProject": "Cisco",
        "product": "IOS XE", "dateAdded": "2026-09-01",
        "dueDate": "2026-12-01", "vulnerabilityName": "XE flaw",
        "requiredAction": "Apply fix.",
        "knownRansomwareCampaignUse": "Known"})
    items, stats = batch.merge_feed_items([nvd_item], [kev_item])
    assert stats == {"kev_merged": 1, "kev_only": 0}
    assert len(items) == 1
    merged = items[0]
    assert merged["sources"] == ["NVD", "KEV"]
    assert merged["severity_rank"] == 3
    assert merged["cpe_ranges"] == [rng]
    assert merged["label"] == "CVE-2026-4001"
    assert merged["published"] == "2026-08-01"
    assert merged["due_date"] == "2026-12-01"
    assert merged["ransomware"] == "Known"
    for line in ("CISA KEV: this CVE is in the Known Exploited "
                 "Vulnerabilities catalog.",
                 "Date added: 2026-09-01",
                 "Due date: 2026-12-01",
                 "Required action: Apply fix.",
                 "Known ransomware use: Known"):
        assert line in merged["text"]


def test_collect_feed_items_recent_merges_duplicates():
    vuln = {"cve": {"id": "CVE-2026-4001",
                    "published": "2026-08-01T00:00:00.000",
                    "descriptions": [{"lang": "en", "value":
                                      "Cisco IOS XE flaw."}]}}
    catalog = {"vulnerabilities": [
        _kev_entry("CVE-2026-4001", "Cisco", "IOS XE", "2026-09-01")]}
    feed = collect_feed_items(
        _sample_devices(),
        nvd_fetcher=_nvd_fetcher_stub(
            {"cisco": {"vulnerabilities": [vuln]}}),
        kev_fetcher=lambda url: catalog)
    assert feed["stats"]["kev_merged"] == 1
    matches = [item for item in feed["items"]
               if item["label"] == "CVE-2026-4001"]
    assert len(matches) == 1
    assert matches[0]["sources"] == ["NVD", "KEV"]
