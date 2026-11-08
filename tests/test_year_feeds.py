"""Offline tests for the full-year feed pipeline (batch.py):
365-day windowed NVD collection with pagination, KEV merging,
the local version-range screening, and the deep-triage budget.

No network and no Clocked calls: feed fetchers are stubbed and
triage runs in Mock Mode, like the rest of the feed suite.
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
    FULL_TRIAGE_CAP,
    _device_product_keys,
    _make_local_entry,
    _screen_item,
    collect_feed_items_year,
    collect_nvd_items_year,
    parse_inventory_csv,
    run_feed_pipeline,
    screen_feed_items,
)
from triage import parse_inventory, run_triage  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent

NOW = datetime.datetime(2026, 11, 7, 12, 0, 0,
                        tzinfo=datetime.timezone.utc)

CISCO_ONLY = [{"hostname": "SW-01", "model": "Catalyst 9300",
               "version": "17.9.4"}]

TWO_DEVICE_TEXT = ("SW-01, Catalyst 9300, 17.9.4\n"
                   "RTR-01, MX480, 21.3R3\n")


@pytest.fixture(autouse=True)
def _no_api_key(monkeypatch):
    # Deterministic Mock Mode regardless of the caller's environment.
    monkeypatch.delenv("CLOCKED_API_KEY", raising=False)


def _query(url):
    return urllib.parse.parse_qs(urllib.parse.urlparse(url).query)


def _vuln(cve_id, published, description, score=None, severity=None,
          configurations=None):
    cve = {"id": cve_id, "published": published,
           "descriptions": [{"lang": "en", "value": description}]}
    if score is not None:
        cve["metrics"] = {"cvssMetricV31": [{"cvssData": {
            "baseScore": score, "baseSeverity": severity or ""}}]}
    if configurations is not None:
        cve["configurations"] = configurations
    return {"cve": cve}


def _configs(product, vendor="cisco", **bounds):
    match = {"vulnerable": True,
             "criteria": "cpe:2.3:o:%s:%s:*:*:*:*:*:*:*:*"
                         % (vendor, product)}
    match.update(bounds)
    return [{"nodes": [{"operator": "OR", "cpeMatch": [match]}]}]


def _term_fetcher(payloads, record=None):
    """payloads: {first keyword word (lowercase) -> payload or
    callable(url) -> payload}."""
    def fetch(url):
        if record is not None:
            record.append(url)
        term = (_query(url).get("keywordSearch") or [""])[0]
        key = term.split()[0].lower() if term.split() else ""
        payload = payloads[key]
        return payload(url) if callable(payload) else payload
    return fetch


# ------------------------- window splitting --------------------------

def test_year_windows_cover_365_days_in_119_day_windows():
    urls = []
    result = collect_nvd_items_year(
        CISCO_ONLY, fetcher=_term_fetcher(
            {"cisco": {"vulnerabilities": [], "totalResults": 0}},
            record=urls),
        now=NOW)
    assert result["status"] == "empty"
    assert result["windows"] == 4
    spans = set()
    for url in urls:
        query = _query(url)
        start = datetime.datetime.fromisoformat(
            query["pubStartDate"][0])
        end = datetime.datetime.fromisoformat(query["pubEndDate"][0])
        spans.add((start, end))
    assert len(spans) == 4
    for start, end in spans:
        assert end - start <= datetime.timedelta(days=119)
    naive_now = NOW.replace(tzinfo=None)
    assert min(start for start, _end in spans) == \
        naive_now - datetime.timedelta(days=365)
    assert max(end for _start, end in spans) == naive_now


# ------------------------- pagination + dedupe -----------------------

def test_year_pagination_merges_pages_and_dedupes():
    def cisco_page(url):
        query = _query(url)
        start_index = int((query.get("startIndex") or ["0"])[0])
        if start_index == 0:
            return {"totalResults": 3, "vulnerabilities": [
                _vuln("CVE-2026-0001", "2026-05-01T00:00:00.000",
                      "Cisco IOS XE flaw one."),
                _vuln("CVE-2026-0002", "2026-06-01T00:00:00.000",
                      "Cisco IOS XE flaw two."),
            ]}
        assert start_index == 2
        return {"totalResults": 3, "vulnerabilities": [
            _vuln("CVE-2026-0003", "2026-07-01T00:00:00.000",
                  "Cisco IOS XE flaw three."),
        ]}

    result = collect_nvd_items_year(
        CISCO_ONLY,
        fetcher=_term_fetcher({"cisco": cisco_page}), now=NOW)
    assert result["status"] == "ok"
    # The same pages come back for all four windows; dedupe by
    # CVE id keeps exactly the three unique records.
    assert result["count"] == 3
    assert [item["label"] for item in result["items"]] == [
        "CVE-2026-0003", "CVE-2026-0002", "CVE-2026-0001"]
    assert result["truncated"] is False


def test_year_dedupe_prefers_record_with_configurations():
    bare = _vuln("CVE-2026-3001", "2026-03-01T00:00:00.000",
                 "Cisco IOS XE flaw.")
    rich = _vuln("CVE-2026-3001", "2026-03-01T00:00:00.000",
                 "Cisco IOS XE flaw.",
                 configurations=_configs(
                     "ios_xe", versionEndExcluding="17.9.5"))

    def cisco_page(url):
        query = _query(url)
        start = query["pubStartDate"][0]
        # The oldest window serves the bare record, later windows
        # the one carrying configurations.
        if start.startswith("2025-11-07"):
            return {"totalResults": 1, "vulnerabilities": [bare]}
        return {"totalResults": 1, "vulnerabilities": [rich]}

    result = collect_nvd_items_year(
        CISCO_ONLY,
        fetcher=_term_fetcher({"cisco": cisco_page}), now=NOW)
    assert result["count"] == 1
    item = result["items"][0]
    assert item["cpe_ranges"]
    assert item["cpe_ranges"][0]["product"] == "ios_xe"
    assert "Structured affected ranges (NVD CPE):" in item["text"]


def test_severity_rank_from_severity_word_and_score():
    assert batch._severity_rank(9.8, "CRITICAL") == 4
    assert batch._severity_rank(7.5, "HIGH") == 3
    assert batch._severity_rank(None, "MEDIUM") == 2
    assert batch._severity_rank(9.1, "") == 4
    assert batch._severity_rank(0.0, "") == 0
    assert batch._severity_rank(None, "") == 0


# ------------------------- KEV merge ---------------------------------

def _kev_entry(cve_id, vendor, product, added, due="2026-12-01"):
    return {"cveID": cve_id, "vendorProject": vendor,
            "product": product,
            "vulnerabilityName": "Vuln %s" % cve_id,
            "dateAdded": added, "dueDate": due,
            "requiredAction": "Apply mitigations per vendor "
                              "instructions.",
            "knownRansomwareCampaignUse": "Unknown"}


def test_year_kev_merges_into_nvd_items():
    devices = parse_inventory(TWO_DEVICE_TEXT)
    nvd_payload = {"totalResults": 1, "vulnerabilities": [
        _vuln("CVE-2026-4001", "2026-08-01T00:00:00.000",
              "Juniper Junos OS flaw.", score=8.8, severity="HIGH")]}
    catalog = {"vulnerabilities": [
        _kev_entry("CVE-2026-4001", "Juniper", "Junos OS",
                   "2026-09-01"),
        _kev_entry("CVE-2026-4002", "Juniper", "Junos OS",
                   "2026-09-02"),
        _kev_entry("CVE-2026-4999", "Acme", "Printer", "2026-09-03"),
    ]}
    feed = collect_feed_items_year(
        devices,
        nvd_fetcher=_term_fetcher(
            {"juniper": nvd_payload, "cisco": {"vulnerabilities": []}}),
        kev_fetcher=lambda url: catalog, now=NOW)
    assert feed["stats"]["total"] == 2
    assert feed["stats"]["kev_merged"] == 1
    assert feed["stats"]["kev_only"] == 1
    merged = feed["items"][0]
    assert merged["label"] == "CVE-2026-4001"
    assert merged["kev"] is True
    assert merged["severity_rank"] == 3
    assert merged["published"] == "2026-08-01"
    assert "Due date: 2026-12-01" in merged["text"]
    kev_only = feed["items"][1]
    assert kev_only["label"] == "KEV CVE-2026-4002"
    assert kev_only["kev"] is True


def test_kev_collect_min_date_window_excludes_and_counts():
    devices = parse_inventory(TWO_DEVICE_TEXT)
    catalog = {"vulnerabilities": [
        _kev_entry("CVE-2024-9001", "Cisco", "IOS XE", "2024-01-05"),
        _kev_entry("CVE-2026-9002", "Juniper", "Junos OS",
                   "2026-03-01"),
        _kev_entry("CVE-2026-9003", "Juniper", "Junos OS",
                   "not-a-date"),
    ]}
    result = batch.collect_kev_items(
        devices, fetcher=lambda url: catalog,
        min_date=datetime.date(2025, 11, 7))
    # The 2024 match is excluded BEFORE the cap and counted; the
    # undated entry is kept (an unparseable dateAdded is not
    # evidence of age).
    assert result["older_excluded"] == 1
    assert result["count"] == 2
    assert {i["label"] for i in result["items"]} == {
        "KEV CVE-2026-9002", "KEV CVE-2026-9003"}


def test_year_kev_older_than_window_neither_merges_nor_counts():
    devices = parse_inventory(TWO_DEVICE_TEXT)
    nvd_payload = {"totalResults": 1, "vulnerabilities": [
        _vuln("CVE-2026-7001", "2026-08-01T00:00:00.000",
              "Juniper Junos OS flaw.", score=8.8, severity="HIGH")]}
    catalog = {"vulnerabilities": [
        # Same CVE as the NVD item, but added to KEV years before
        # the window: it must not flag/merge into the NVD item.
        _kev_entry("CVE-2026-7001", "Juniper", "Junos OS",
                   "2023-05-01"),
        _kev_entry("CVE-2026-7002", "Juniper", "Junos OS",
                   "2026-09-02"),
    ]}
    feed = collect_feed_items_year(
        devices,
        nvd_fetcher=_term_fetcher(
            {"juniper": nvd_payload, "cisco": {"vulnerabilities": []}}),
        kev_fetcher=lambda url: catalog, now=NOW)
    assert feed["stats"]["kev_older_excluded"] == 1
    assert feed["stats"]["kev_merged"] == 0
    assert feed["stats"]["kev_only"] == 1
    assert feed["stats"]["total"] == 2
    assert feed["kev"]["older_excluded"] == 1
    nvd_item = feed["items"][0]
    assert nvd_item["label"] == "CVE-2026-7001"
    assert nvd_item["kev"] is False


# ------------------------- screening ---------------------------------

def _rng(product, vendor="cisco", exact=None, start_including=None,
         start_excluding=None, end_including=None,
         end_excluding=None):
    return {"vendor": vendor, "product": product, "exact": exact,
            "start_including": start_including,
            "start_excluding": start_excluding,
            "end_including": end_including,
            "end_excluding": end_excluding}


def _item(cve_id, ranges, text=None, kev=False,
          published="2026-06-01", rank=3):
    return {"label": cve_id,
            "url": "https://nvd.nist.gov/vuln/detail/%s" % cve_id,
            "text": text or ("%s advisory." % cve_id),
            "published": published, "severity_rank": rank,
            "kev": kev, "cpe_ranges": ranges}


def test_screen_in_range_is_candidate():
    item = _item("CVE-2026-5001", [
        _rng("ios_xe", start_including="17.9",
             end_excluding="17.9.5")])
    rows, candidates, stats = screen_feed_items(
        [item], TWO_DEVICE_TEXT)
    assert rows == []
    assert [c["label"] for c in candidates] == ["CVE-2026-5001"]
    assert stats == {"collected": 1, "not_in_fleet": 0,
                     "local_not_affected": 0, "candidates": 1,
                     "uncertain_candidates": 0,
                     "unmapped_products": 0}


def test_screen_out_of_range_is_local_not_affected_row():
    import app as app_module

    item = _item("CVE-2026-5002", [
        _rng("ios_xe", start_including="17.9",
             end_excluding="17.9.4")])
    rows, candidates, stats = screen_feed_items(
        [item], TWO_DEVICE_TEXT)
    assert candidates == []
    assert stats["local_not_affected"] == 1
    assert len(rows) == 1
    row = rows[0]
    assert row["status"] == "ok"
    assert row["basis"] == "local-screen"
    assert row["source_label"] == "Local version-range screen"
    triage_result = row["triage"]
    assert triage_result["verdict"] == "NOT AFFECTED"
    assert triage_result["urgency"] == "monitor"
    assert triage_result["clocked_calls"] == 0
    assert "No action required" in triage_result["action_required"]
    assert "outside every vendor-published affected range" in \
        triage_result["action_required"]
    device_results = triage_result["device_results"]
    assert [d["status"] for d in device_results] == [
        "NOT AFFECTED", "NOT AFFECTED"]
    assert device_results[0]["candidate"] is True
    assert device_results[1]["candidate"] is False
    # The exact field accesses the batch renderer and the action
    # summary perform must all work on the local result shape.
    for key in ("extracted", "conditions", "checklist", "claim",
                "grounding", "decide", "warnings", "device_results"):
        assert key in triage_result
    assert app_module._action_lines(
        triage_result, app_module.STRINGS["en"], "en") == [
            app_module.STRINGS["en"]["action_none"]]
    assert app_module._batch_advisory_label(row, "en") == \
        "CVE-2026-5002"


def test_screen_unbounded_range_is_uncertain_candidate():
    item = _item("CVE-2026-5003", [_rng("ios_xe")])
    _rows, candidates, stats = screen_feed_items(
        [item], TWO_DEVICE_TEXT)
    assert [c["label"] for c in candidates] == ["CVE-2026-5003"]
    assert stats["uncertain_candidates"] == 1


def test_screen_text_only_relation_is_candidate():
    item = _item("CVE-2026-5004", [],
                 text="Juniper Junos OS vulnerability in the "
                      "routing engine.")
    _rows, candidates, stats = screen_feed_items(
        [item], TWO_DEVICE_TEXT)
    assert [c["label"] for c in candidates] == ["CVE-2026-5004"]
    assert stats["uncertain_candidates"] == 1


def test_screen_product_not_in_fleet_is_screened_out():
    item = _item("CVE-2026-5005", [
        _rng("fortios", vendor="fortinet", start_including="7.0",
             end_excluding="7.4.4")],
        text="Fortinet FortiOS flaw.")
    rows, candidates, stats = screen_feed_items(
        [item], TWO_DEVICE_TEXT)
    assert rows == []
    assert candidates == []
    assert stats["not_in_fleet"] == 1


def test_screen_exact_version_uses_cpe_update_field():
    # Junos CPEs split "21.2R3" into version 21.2 + update r3; the
    # collector joins them, so an exact match is a range hit.
    ranges = batch._nvd_cpe_ranges({"configurations": _configs(
        "junos", vendor="juniper")})
    assert ranges == []  # wildcard version carries no information
    match = {"vulnerable": True,
             "criteria": "cpe:2.3:o:juniper:junos:21.2:r3:*:*:*:*:*:*"}
    configs = [{"nodes": [{"operator": "OR", "cpeMatch": [match]}]}]
    ranges = batch._nvd_cpe_ranges({"configurations": configs})
    assert ranges[0]["exact"] == "21.2r3"
    item = _item("CVE-2026-5006", ranges)
    _rows, candidates, stats = screen_feed_items(
        [item], "RTR-01, QFX5110, 21.2R3\n")
    assert [c["label"] for c in candidates] == ["CVE-2026-5006"]
    assert stats["uncertain_candidates"] == 0


def test_cpe_product_key_nokia_and_extreme():
    # Nokia SR OS CPEs (sr_os / sros spellings) and Extreme EXOS
    # CPEs normalize to the fleet product keys the sample Nokia /
    # Extreme devices carry.
    assert batch._cpe_product_key("nokia", "sr_os") == "nokia sr os"
    assert batch._cpe_product_key("nokia", "sros") == "nokia sr os"
    assert batch._cpe_product_key("Nokia", "7750_sros") == \
        "nokia sr os"
    assert batch._cpe_product_key("extreme", "exos") == \
        "extreme exos"
    assert batch._cpe_product_key("extremenetworks",
                                  "extremexos") == "extreme exos"
    assert batch._PRODUCT_KEY_DISPLAY["nokia sr os"] == "Nokia SR OS"
    assert batch._PRODUCT_KEY_DISPLAY["extreme exos"] == \
        "Extreme EXOS"


def test_device_product_keys_nokia_and_extreme():
    devices = parse_inventory(
        "NOKIA-7750-01, Nokia 7750 SR-12, 21.10.R1\n"
        "EXTREME-X450-01, Extreme X450a-24x, 12.4.4.10\n")
    assert batch._device_product_keys(devices[0]) == {"nokia sr os"}
    assert batch._device_product_keys(devices[1]) == \
        {"extreme exos"}


def test_screen_nokia_sr_os_and_extreme_exos_ranges():
    inventory = ("NOKIA-7750-01, Nokia 7750 SR-12, 21.10.R1\n"
                 "EXTREME-X450-01, Extreme X450a-24x, 12.4.4.10\n")
    # SR OS ranges covering only the 23.x branches: the fleet's
    # 21.10.R1 sits outside every range -> local NOT AFFECTED.
    cleared = _item("CVE-2026-7101", [
        _rng("sr_os", vendor="nokia", start_including="23.2")])
    # EXOS before 12.5 is affected: 12.4.4.10 is inside -> hit.
    hit = _item("CVE-2026-7102", [
        _rng("exos", vendor="extreme", end_excluding="12.5")])
    rows, candidates, stats = screen_feed_items(
        [cleared, hit], inventory)
    assert stats["local_not_affected"] == 1
    assert stats["candidates"] == 1
    assert [c["label"] for c in candidates] == ["CVE-2026-7102"]
    assert rows[0]["label"] == "CVE-2026-7101"
    assert rows[0]["triage"]["verdict"] == "NOT AFFECTED"


# ------------------------- pipeline: budget + ordering ---------------

def _bulk_pipeline_inputs(count=35):
    """35 Juniper Junos CVEs (text-related, no ranges, so all are
    uncertain candidates) with controlled priority signals:
    index 0 is old but CRITICAL, indices 1-2 are old/low but get
    KEV-merged, the rest are low severity, newest last."""
    vulns = []
    base = datetime.date(2026, 1, 1)
    for i in range(count):
        published = (base + datetime.timedelta(days=i)).isoformat()
        score, severity = (3.0, "LOW")
        if i == 0:
            score, severity = (9.8, "CRITICAL")
        vulns.append(_vuln(
            "CVE-2026-%04d" % (2000 + i),
            published + "T00:00:00.000",
            "Juniper Junos OS flaw %d." % i,
            score=score, severity=severity))
    nvd_payload = {"vulnerabilities": vulns}
    catalog = {"vulnerabilities": [
        _kev_entry("CVE-2026-2001", "Juniper", "Junos OS",
                   "2026-02-01"),
        _kev_entry("CVE-2026-2002", "Juniper", "Junos OS",
                   "2026-02-02"),
    ]}
    return nvd_payload, catalog


def test_pipeline_budget_ordering_and_exceeded_rows():
    nvd_payload, catalog = _bulk_pipeline_inputs()
    rows, stats = run_feed_pipeline(
        TWO_DEVICE_TEXT, mock=True,
        nvd_fetcher=_term_fetcher(
            {"juniper": nvd_payload,
             "cisco": {"vulnerabilities": []}}),
        kev_fetcher=lambda url: catalog, now=NOW)
    assert stats["screening"]["candidates"] == 35
    assert stats["deep_triaged"] == FULL_TRIAGE_CAP
    assert len(rows) == 35
    # Design section 3 (K-2): the two KEV-merged items carry no
    # version range from any source, so they leave the judged
    # pool as local kev_unconfirmed rows BEFORE budget slicing;
    # the freed slots flow to the next candidates, and only the
    # three oldest low-severity non-KEV items remain over budget.
    assert stats["kev_unconfirmed"] == 2
    kev_rows = [r for r in rows if r.get("due_date")]
    assert sorted(r["label"] for r in kev_rows) == [
        "CVE-2026-2001", "CVE-2026-2002"]
    budget_rows = [r for r in rows
                   if r.get("basis") == "local-screen"
                   and not r.get("due_date")]
    triaged_rows = [r for r in rows
                    if r.get("basis") != "local-screen"]
    assert len(triaged_rows) == FULL_TRIAGE_CAP
    assert len(budget_rows) == 3
    assert sorted(r["label"] for r in budget_rows) == [
        "CVE-2026-2003", "CVE-2026-2004", "CVE-2026-2005"]
    triaged_labels = {r["label"] for r in triaged_rows}
    assert "CVE-2026-2000" in triaged_labels  # old but CRITICAL
    for row in budget_rows:
        triage_result = row["triage"]
        assert triage_result["verdict"] == "CANNOT DETERMINE"
        assert triage_result["urgency"] == "monitor"
        assert "beyond this run's deep-triage budget" in \
            triage_result["action_required"]
    for row in kev_rows:
        # K-2 rows carry the CONDITION grade (bgp parity §3);
        # budget rows above stay CANNOT DETERMINE (rule A-3).
        assert row["triage"]["verdict"] == \
            "CONDITION CHECK REQUIRED"
        assert row["triage"]["clocked_calls"] == 0
    assert stats["condition_check"] == 2
    # Final row order: KEV first.
    assert rows[0]["kev"] is True
    assert rows[1]["kev"] is True


def test_pipeline_end_to_end_mocked_network():
    devices_text = ("SW-01, Catalyst 9300, 17.6.5\n"
                    "RTR-01, MX480, 21.3R3\n")
    hit = _vuln("CVE-2026-6001", "2026-05-01T00:00:00.000",
                "Cisco IOS XE flaw.", score=9.8, severity="CRITICAL",
                configurations=_configs(
                    "ios_xe", versionStartIncluding="17.6",
                    versionEndExcluding="17.6.6a"))
    cleared = _vuln("CVE-2026-6002", "2026-04-01T00:00:00.000",
                    "Juniper Junos OS flaw.", score=5.0,
                    severity="MEDIUM",
                    configurations=_configs(
                        "junos", vendor="juniper",
                        versionEndExcluding="20.4"))
    rows, stats = run_feed_pipeline(
        devices_text, mock=True,
        nvd_fetcher=_term_fetcher({
            "cisco": {"vulnerabilities": [hit]},
            "juniper": {"vulnerabilities": [cleared]}}),
        kev_fetcher=lambda url: {"vulnerabilities": []}, now=NOW)
    assert stats["collection"]["total"] == 2
    assert stats["screening"]["local_not_affected"] == 1
    assert stats["screening"]["candidates"] == 1
    assert stats["deep_triaged"] == 1
    assert len(rows) == 2
    local = [r for r in rows if r.get("basis") == "local-screen"]
    assert len(local) == 1
    assert local[0]["label"] == "CVE-2026-6002"
    assert local[0]["triage"]["verdict"] == "NOT AFFECTED"
    judged = [r for r in rows if r.get("basis") != "local-screen"]
    assert len(judged) == 1
    assert judged[0]["label"] == "CVE-2026-6001"
    assert judged[0]["status"] == "ok"


def test_pipeline_judge_all_lifts_budget():
    nvd_payload, catalog = _bulk_pipeline_inputs(count=12)
    rows, stats = run_feed_pipeline(
        TWO_DEVICE_TEXT, mock=True, judge_all=True,
        nvd_fetcher=_term_fetcher(
            {"juniper": nvd_payload,
             "cisco": {"vulnerabilities": []}}),
        kev_fetcher=lambda url: catalog, now=NOW)
    assert stats["budget"] == batch.JUDGE_ALL_CAP
    # K-2 again: the two range-less KEV-merged items are local
    # kev_unconfirmed rows even under Judge all - the other 10
    # are deep-triaged.
    assert stats["deep_triaged"] == 10
    assert stats["kev_unconfirmed"] == 2
    assert len(rows) == 12
    assert sum(1 for r in rows
               if r.get("basis") == "local-screen") == 2


def test_pipeline_credit_exhaustion_sets_stats_flag(monkeypatch):
    # Deep triage dies on Clocked credits: the surviving
    # candidate becomes a credit entry (never a verdict), the
    # run-level stats flag is set, and the local screening row
    # is produced exactly as before (it never spends calls).
    devices_text = ("SW-01, Catalyst 9300, 17.6.5\n"
                    "RTR-01, MX480, 21.3R3\n")
    hit = _vuln("CVE-2026-6001", "2026-05-01T00:00:00.000",
                "Cisco IOS XE flaw.", score=9.8, severity="CRITICAL",
                configurations=_configs(
                    "ios_xe", versionStartIncluding="17.6",
                    versionEndExcluding="17.6.6a"))
    cleared = _vuln("CVE-2026-6002", "2026-04-01T00:00:00.000",
                    "Juniper Junos OS flaw.", score=5.0,
                    severity="MEDIUM",
                    configurations=_configs(
                        "junos", vendor="juniper",
                        versionEndExcluding="20.4"))
    calls = []

    def fake_triage(text, devices_text, api_key=None, lang="en", mock=False):
        calls.append(text)
        return {"mode": "live", "credit_exhausted": True,
                "error": ("Clocked API 402: Your credit allowance "
                          "or spending limit has been reached."),
                "verdict": None, "devices": []}

    monkeypatch.setattr(batch, "run_triage", fake_triage)

    def no_trace(url):
        raise batch.FetchError("no fixture record")

    rows, stats = run_feed_pipeline(
        devices_text, mock=False, api_key="test-key",
        nvd_fetcher=_term_fetcher({
            "cisco": {"vulnerabilities": [hit]},
            "juniper": {"vulnerabilities": [cleared]}}),
        kev_fetcher=lambda url: {"vulnerabilities": []},
        trace_fetcher=no_trace, trace_json_fetcher=no_trace,
        now=NOW)
    assert stats["credit_exhausted"] is True
    assert stats["deep_triaged"] == 1
    # Fail fast: one attempted deep triage, exactly one call.
    assert len(calls) == 1
    credit_rows = [r for r in rows if r.get("credit_exhausted")]
    assert len(credit_rows) == 1
    assert credit_rows[0]["label"] == "CVE-2026-6001"
    assert credit_rows[0]["status"] == "error"
    assert "triage" not in credit_rows[0]
    local = [r for r in rows if r.get("basis") == "local-screen"]
    assert len(local) == 1
    assert local[0]["triage"]["verdict"] == "NOT AFFECTED"


def test_pipeline_mock_override_beats_configured_key(monkeypatch):
    # Demo override at pipeline level: with a key configured in
    # the environment, mock=True still answers collection and
    # tracing from the bundled fixtures AND judges the deep
    # triage in Mock Mode - no network, no Clocked calls, and no
    # credit state on the run.
    monkeypatch.setenv("CLOCKED_API_KEY", "test-key-not-a-real-secret")
    inventory_text = (ROOT / "samples" / "inventory_sample.txt"
                      ).read_text(encoding="utf-8")
    rows, stats = run_feed_pipeline(inventory_text, mock=True,
                                    now=NOW)
    assert stats["nvd"]["count"] == 3
    assert stats["kev"]["count"] == 1
    assert stats["credit_exhausted"] is False
    assert len(rows) == 4
    judged = [r for r in rows if r.get("triage")
              and r.get("basis") != "local-screen"]
    assert judged
    assert all(r["triage"]["mode"] == "mock" for r in judged)
    # The range-less KEV-only fixture item is the K-2 local row
    # (design section 3); it is not judged in any mode.
    kev_rows = [r for r in rows if r.get("basis") == "local-screen"]
    assert len(kev_rows) == 1
    assert kev_rows[0]["triage"]["mode"] == "local"


# ------------------------- stage progress --------------------------
# Every pipeline stage reports through the one progress(index,
# total, label) callback the UI renders, so a minutes-long feeds
# run never sits on the static "Collecting vulnerability feeds"
# spinner text: collection fires per completed vendor-window
# (plus once for the KEV fetch), screening fires once, tracing
# fires per attempted candidate, and deep triage keeps its
# per-item events.

def test_pipeline_progress_events_cover_all_stages():
    nvd_payload, catalog = _bulk_pipeline_inputs()
    events = []

    def record(index, total, label):
        events.append((index, total, label))

    _rows, stats = run_feed_pipeline(
        TWO_DEVICE_TEXT, mock=True, progress=record,
        nvd_fetcher=_term_fetcher(
            {"juniper": nvd_payload,
             "cisco": {"vulnerabilities": []}}),
        kev_fetcher=lambda url: catalog, now=NOW)
    assert events
    for index, total, _label in events:
        assert total > 0
        assert 0 <= index <= total
    collecting = [e for e in events
                  if e[2].startswith("Collecting NVD feeds")]
    kev_events = [e for e in events
                  if e[2].startswith("Collecting KEV feed")]
    screening = [e for e in events
                 if e[2] == "Screening against inventory"]
    tracing = [e for e in events
               if e[2].startswith("Tracing vendor source")]
    triage = [e for e in events
              if e[1] == FULL_TRIAGE_CAP
              and e[2].startswith("CVE-")]
    # Collection: 2 vendors x 4 windows = 8 events at total 8,
    # the running count in the label reaching the merged total;
    # the KEV fetch closes the stage at the same total.
    assert len(collecting) == 8
    assert all(e[1] == 8 for e in collecting)
    assert collecting[-1][0] == 8
    assert "35 collected" in collecting[-1][2]
    assert len(kev_events) == 1
    assert kev_events[0][:2] == (8, 8)
    # Screening: exactly one event.
    assert screening == [(1, 1, "Screening against inventory")]
    # Tracing: one event per attempted candidate, its total
    # matching the pipeline's traced_for_screen count.
    assert stats["traced_for_screen"] == 35
    assert len(tracing) == stats["traced_for_screen"]
    assert all(e[1] == stats["traced_for_screen"] for e in tracing)
    assert tracing[-1][0] == stats["traced_for_screen"]
    # Deep triage: per-item events forwarded from run_batch_items.
    assert len(triage) == stats["deep_triaged"] == FULL_TRIAGE_CAP

    def _positions(pred):
        return [i for i, e in enumerate(events) if pred(e)]

    # Stage order: collection -> KEV -> screening -> tracing ->
    # deep triage.
    assert max(_positions(
        lambda e: e[2].startswith("Collecting NVD"))) < \
        _positions(lambda e: e[2].startswith("Collecting KEV"))[0]
    assert _positions(
        lambda e: e[2].startswith("Collecting KEV"))[0] < \
        _positions(
            lambda e: e[2] == "Screening against inventory")[0]
    assert _positions(
        lambda e: e[2] == "Screening against inventory")[0] < \
        min(_positions(
            lambda e: e[2].startswith("Tracing vendor source")))
    assert max(_positions(
        lambda e: e[2].startswith("Tracing vendor source"))) < \
        min(_positions(
            lambda e: e[1] == FULL_TRIAGE_CAP
            and e[2].startswith("CVE-")))


def test_pipeline_progress_labels_korean():
    inventory_text = (ROOT / "samples" / "inventory_sample.txt"
                      ).read_text(encoding="utf-8")
    events = []
    _rows, _stats = run_feed_pipeline(
        inventory_text, mock=True, lang="ko",
        progress=lambda i, t, l: events.append((i, t, l)), now=NOW)
    labels = [e[2] for e in events]
    assert any(l.startswith("NVD 피드 수집 중") for l in labels)
    assert "인벤토리 대조 스크리닝" in labels
    assert any(l.startswith("제조사 원문 추적") for l in labels)
    for index, total, _label in events:
        assert total > 0
        assert 0 <= index <= total


# ------------------------- row-count invariant ----------------------
# Every collected item must be accounted for by exactly one row:
# a local screen row, a re-screened row, a deep-triaged row, or a
# budget row. Items screened out as not-in-fleet get NO row by
# design - they live only in the collection/screening counts -
# so the strict identity rows == collection total is asserted
# across the fleet-only fixture scenarios (which pin
# not_in_fleet == 0), and the general identity
# rows + not_in_fleet == total gets its own test below.

def _assert_row_invariant(rows, stats):
    assert stats["screening"]["not_in_fleet"] == 0
    assert len(rows) == stats["collection"]["total"]


def test_pipeline_row_count_matches_collection_total():
    # Bulk scenario WITH KEV merging: 35 NVD records, two of
    # which a KEV entry merges into - the collection total stays
    # 35 and every one of them must come back as a row.
    nvd_payload, catalog = _bulk_pipeline_inputs()
    rows, stats = run_feed_pipeline(
        TWO_DEVICE_TEXT, mock=True,
        nvd_fetcher=_term_fetcher(
            {"juniper": nvd_payload,
             "cisco": {"vulnerabilities": []}}),
        kev_fetcher=lambda url: catalog, now=NOW)
    assert stats["collection"]["kev_merged"] == 2
    assert stats["collection"]["total"] == 35
    _assert_row_invariant(rows, stats)

    # Mixed scenario: one local clear + one deep-triaged hit.
    hit = _vuln("CVE-2026-6001", "2026-05-01T00:00:00.000",
                "Cisco IOS XE flaw.", score=9.8, severity="CRITICAL",
                configurations=_configs(
                    "ios_xe", versionStartIncluding="17.6",
                    versionEndExcluding="17.6.6a"))
    cleared = _vuln("CVE-2026-6002", "2026-04-01T00:00:00.000",
                    "Juniper Junos OS flaw.", score=5.0,
                    severity="MEDIUM",
                    configurations=_configs(
                        "junos", vendor="juniper",
                        versionEndExcluding="20.4"))
    rows, stats = run_feed_pipeline(
        "SW-01, Catalyst 9300, 17.6.5\nRTR-01, MX480, 21.3R3\n",
        mock=True,
        nvd_fetcher=_term_fetcher({
            "cisco": {"vulnerabilities": [hit]},
            "juniper": {"vulnerabilities": [cleared]}}),
        kev_fetcher=lambda url: {"vulnerabilities": []}, now=NOW)
    assert stats["collection"]["total"] == 2
    _assert_row_invariant(rows, stats)

    # Judge-all scenario (budget lifted, so no budget rows).
    nvd_payload, catalog = _bulk_pipeline_inputs(count=12)
    rows, stats = run_feed_pipeline(
        TWO_DEVICE_TEXT, mock=True, judge_all=True,
        nvd_fetcher=_term_fetcher(
            {"juniper": nvd_payload,
             "cisco": {"vulnerabilities": []}}),
        kev_fetcher=lambda url: catalog, now=NOW)
    assert stats["collection"]["total"] == 12
    _assert_row_invariant(rows, stats)

    # Re-screen scenario: one candidate cleared by its traced
    # CNA ranges, one survivor deep-triaged - still one row per
    # collected item.
    cleared = _vuln("CVE-2026-8001", "2026-09-01T00:00:00.000",
                    "Juniper Junos OS flaw.", score=8.8,
                    severity="HIGH")
    survivor = _vuln("CVE-2026-8002", "2026-08-01T00:00:00.000",
                     "Juniper Junos OS flaw.", score=5.0,
                     severity="MEDIUM")

    def json_fetch_clear(url):
        if url == batch.cvelist_url("CVE-2026-8001"):
            return _clearing_cna("CVE-2026-8001")
        raise batch.FetchError("no fixture record")

    rows, stats = run_feed_pipeline(
        JUNIPER_ONLY_TEXT, mock=True,
        nvd_fetcher=_term_fetcher(
            {"juniper": {"vulnerabilities": [cleared, survivor]}}),
        kev_fetcher=lambda url: {"vulnerabilities": []},
        trace_json_fetcher=json_fetch_clear, now=NOW)
    assert stats["collection"]["total"] == 2
    _assert_row_invariant(rows, stats)

    # Re-screen promotion scenario: 31 candidates for a budget
    # of 30, one re-screened clear - 31 rows, no budget rows.
    vulns = []
    base = datetime.date(2026, 1, 1)
    for i in range(31):
        published = (base + datetime.timedelta(days=i)).isoformat()
        score, severity = (3.0, "LOW")
        if i == 0:
            score, severity = (9.8, "CRITICAL")
        vulns.append(_vuln(
            "CVE-2026-%04d" % (8100 + i),
            published + "T00:00:00.000",
            "Juniper Junos OS flaw %d." % i,
            score=score, severity=severity))

    def json_fetch_promote(url):
        if url == batch.cvelist_url("CVE-2026-8100"):
            return _clearing_cna("CVE-2026-8100")
        raise batch.FetchError("no fixture record")

    rows, stats = run_feed_pipeline(
        JUNIPER_ONLY_TEXT, mock=True,
        nvd_fetcher=_term_fetcher({"juniper": {
            "vulnerabilities": vulns}}),
        kev_fetcher=lambda url: {"vulnerabilities": []},
        trace_json_fetcher=json_fetch_promote, now=NOW)
    assert stats["collection"]["total"] == 31
    _assert_row_invariant(rows, stats)

    # Bundled-fixture scenario (the AppTest demo path): NVD and
    # KEV fixtures merged over the bundled sample inventory.
    inventory_text = (ROOT / "samples" / "inventory_sample.txt"
                      ).read_text(encoding="utf-8")
    rows, stats = run_feed_pipeline(inventory_text, mock=True,
                                    now=NOW)
    assert stats["collection"]["total"] == 4
    _assert_row_invariant(rows, stats)


def test_pipeline_row_accounting_identity_with_foreign_item():
    # The general accounting identity: rows + not_in_fleet ==
    # collection total, always - screen_feed_items partitions
    # every collected item into exactly one of {local row,
    # candidate, screened out}, and the pipeline turns every
    # candidate into exactly one row (re-screened, deep-triaged
    # or budget). So a hand tally of displayed rows against the
    # collected count can come up short only by exactly the
    # not-in-fleet count, never by a silent drop.
    #
    # This scenario also pins a conservative quirk: the FortiOS
    # item below arrives under the Juniper keyword query, and
    # the collector's header line names that query ("CVE-... -
    # Juniper Junos"), so the text scan ties it to the fleet's
    # Junos device with no ranges to clear it - it stays an
    # uncertain CANDIDATE (and gets a row) instead of screening
    # out. Screening errs toward judging, never toward dropping.
    foreign = _vuln("CVE-2026-9101", "2026-05-01T00:00:00.000",
                    "Fortinet FortiOS flaw.", score=5.0,
                    severity="MEDIUM",
                    configurations=_configs(
                        "fortios", vendor="fortinet",
                        versionStartIncluding="7.0",
                        versionEndExcluding="7.4.4"))
    local = _vuln("CVE-2026-9102", "2026-06-01T00:00:00.000",
                  "Juniper Junos OS flaw.", score=5.0,
                  severity="MEDIUM",
                  configurations=_configs(
                      "junos", vendor="juniper",
                      versionEndExcluding="20.4"))
    rows, stats = run_feed_pipeline(
        TWO_DEVICE_TEXT, mock=True,
        nvd_fetcher=_term_fetcher(
            {"juniper": {"vulnerabilities": [foreign, local]},
             "cisco": {"vulnerabilities": []}}),
        kev_fetcher=lambda url: {"vulnerabilities": []}, now=NOW)
    assert stats["collection"]["total"] == 2
    assert len(rows) + stats["screening"]["not_in_fleet"] == \
        stats["collection"]["total"]
    # Every collected item is accounted for: the Junos item as a
    # local clear, the FortiOS item as a judged candidate row.
    assert {r["label"] for r in rows} == {
        "CVE-2026-9101", "CVE-2026-9102"}


# ----------------- trace-assisted re-screening -----------------------
# Most fresh CVEs carry no NVD configurations at all, so the
# initial screen can only mark them uncertain. The pipeline
# traces candidates to the vendor original and re-screens on the
# ranges the vendor document carries: a candidate whose fleet
# devices all clear becomes a local NOT AFFECTED row and frees
# its deep-triage slot for the next candidate.

JUNIPER_ONLY_TEXT = "RTR-01, MX480, 21.3R3\n"


def _clearing_cna(cve_id):
    """A CNA record whose affected branches (23.2+, 24.2+) all
    sit above the test fleet's Junos 21.3R3."""
    return {
        "cveMetadata": {"cveId": cve_id},
        "containers": {"cna": {
            "affected": [{
                "vendor": "Juniper Networks", "product": "Junos OS",
                "versions": [
                    {"version": "23.2", "lessThan": "23.2R2",
                     "status": "affected"},
                    {"version": "24.2", "lessThan": "24.2R1",
                     "status": "affected"},
                ]}],
            "descriptions": [{"lang": "en", "value":
                              "Junos OS flaw in newer branches "
                              "only."}],
        }},
    }


def _spy_on_run_batch_items(monkeypatch):
    judged = []
    real = batch.run_batch_items

    def spy(items, *args, **kwargs):
        judged.extend(item["label"] for item in items)
        return real(items, *args, **kwargs)

    monkeypatch.setattr(batch, "run_batch_items", spy)
    return judged


def test_candidate_order_prefers_range_hit_within_tier():
    hit = _item("CVE-2026-8201", [], published="2026-01-01",
                rank=3)
    uncertain = _item("CVE-2026-8202", [], published="2026-06-01",
                      rank=3)
    ordered = batch._candidate_order([uncertain, hit],
                                     hit_ids={id(hit)})
    # Same KEV/severity tier: the confirmed range-hit outranks
    # the newer purely-uncertain item.
    assert ordered[0] is hit
    # ...but KEV membership still outranks a range hit.
    kev_item = _item("CVE-2026-8203", [], kev=True,
                     published="2025-12-01", rank=3)
    ordered = batch._candidate_order([hit, kev_item],
                                     hit_ids={id(hit)})
    assert ordered[0] is kev_item


def test_pipeline_rescreen_clears_candidate_without_triage_budget(
        monkeypatch):
    cleared = _vuln("CVE-2026-8001", "2026-09-01T00:00:00.000",
                    "Juniper Junos OS flaw.", score=8.8,
                    severity="HIGH")
    survivor = _vuln("CVE-2026-8002", "2026-08-01T00:00:00.000",
                     "Juniper Junos OS flaw.", score=5.0,
                     severity="MEDIUM")
    judged = _spy_on_run_batch_items(monkeypatch)

    def json_fetch(url):
        if url == batch.cvelist_url("CVE-2026-8001"):
            return _clearing_cna("CVE-2026-8001")
        raise batch.FetchError("no fixture record")

    rows, stats = run_feed_pipeline(
        JUNIPER_ONLY_TEXT, mock=True,
        nvd_fetcher=_term_fetcher(
            {"juniper": {"vulnerabilities": [cleared, survivor]}}),
        kev_fetcher=lambda url: {"vulnerabilities": []},
        trace_json_fetcher=json_fetch, now=NOW)
    # Both items enter as uncertain candidates (no NVD ranges);
    # the trace settles one of them locally.
    assert stats["screening"]["candidates"] == 2
    assert stats["traced_for_screen"] == 2
    assert stats["rescreened_not_affected"] == 1
    assert stats["screening"]["local_not_affected"] == 1
    assert stats["deep_triaged"] == 1
    # Deep triage received ONLY the survivor - the re-screened
    # item consumed no budget (and made no Clocked calls).
    assert judged == ["CVE-2026-8002"]
    row = {r["label"]: r for r in rows}["CVE-2026-8001"]
    assert row["basis"] == "local-screen"
    assert row["triage"]["verdict"] == "NOT AFFECTED"
    assert row["triage"]["clocked_calls"] == 0
    # The local row keeps the vendor trace as its shown source.
    assert row["source_label"] == "CVE CNA record"
    assert row["source_url"] == batch.cvelist_url("CVE-2026-8001")


def test_pipeline_rescreen_promotes_next_candidate_into_budget(
        monkeypatch):
    # 31 uncertain candidates for a budget of 30: the top one
    # (CRITICAL) re-screens clear from its CNA ranges, so the
    # lowest-priority item - a budget row under the old flow -
    # is deep-triaged instead.
    vulns = []
    base = datetime.date(2026, 1, 1)
    for i in range(31):
        published = (base + datetime.timedelta(days=i)).isoformat()
        score, severity = (3.0, "LOW")
        if i == 0:
            score, severity = (9.8, "CRITICAL")
        vulns.append(_vuln(
            "CVE-2026-%04d" % (8100 + i),
            published + "T00:00:00.000",
            "Juniper Junos OS flaw %d." % i,
            score=score, severity=severity))
    judged = _spy_on_run_batch_items(monkeypatch)

    def json_fetch(url):
        if url == batch.cvelist_url("CVE-2026-8100"):
            return _clearing_cna("CVE-2026-8100")
        raise batch.FetchError("no fixture record")

    rows, stats = run_feed_pipeline(
        JUNIPER_ONLY_TEXT, mock=True,
        nvd_fetcher=_term_fetcher({"juniper": {
            "vulnerabilities": vulns}}),
        kev_fetcher=lambda url: {"vulnerabilities": []},
        trace_json_fetcher=json_fetch, now=NOW)
    assert stats["screening"]["candidates"] == 31
    assert stats["traced_for_screen"] == 31
    assert stats["rescreened_not_affected"] == 1
    assert stats["deep_triaged"] == FULL_TRIAGE_CAP
    assert len(rows) == 31
    assert len(judged) == FULL_TRIAGE_CAP
    assert "CVE-2026-8100" not in judged
    # The freed slot went to the last candidate in priority
    # order (oldest of the LOW tier).
    assert "CVE-2026-8101" in judged
    budget_rows = [r for r in rows
                   if r.get("basis") == "local-screen"
                   and r["triage"]["verdict"] == "CANNOT DETERMINE"]
    assert budget_rows == []
    rescreened = [r for r in rows if r["label"] == "CVE-2026-8100"]
    assert len(rescreened) == 1
    assert rescreened[0]["triage"]["verdict"] == "NOT AFFECTED"
    assert rescreened[0]["source_label"] == "CVE CNA record"


# ------------------------- renderer (AppTest) ------------------------

from streamlit.testing.v1 import AppTest  # noqa: E402

APP = str(ROOT / "app.py")


def test_local_rows_render_in_batch_results():
    # Seed the batch results with one local NOT AFFECTED row and
    # one budget CANNOT DETERMINE row and let the real renderer
    # draw the summary table, the action summary and both detail
    # expanders - the local triage shape must not break any of it.
    cleared = _item("CVE-2026-5002", [
        _rng("ios_xe", start_including="17.9",
             end_excluding="17.9.4")])
    rows, _c, _s = screen_feed_items([cleared], TWO_DEVICE_TEXT)
    devices = parse_inventory(TWO_DEVICE_TEXT)
    evaluation = batch._screen_item(
        _item("CVE-2026-5007", [_rng("ios_xe")]), devices,
        [batch._device_product_keys(d) for d in devices])
    rows.append(batch._make_local_entry(
        _item("CVE-2026-5007", [_rng("ios_xe")]), devices,
        evaluation, "budget", "en", budget=FULL_TRIAGE_CAP))
    at = AppTest.from_file(APP)
    at.session_state["batch_results"] = rows
    at.session_state["batch_source"] = "feeds"
    at.run()
    assert not at.exception
    # Two dataframes: the batch summary table and the per-device
    # verdicts table rendered below it.
    assert len(at.dataframe) == 2
    expander_labels = [e.label for e in at.expander]
    assert any("CVE-2026-5002" in label
               and "NOT AFFECTED" in label
               for label in expander_labels), expander_labels
    assert any("CVE-2026-5007" in label
               and "CANNOT DETERMINE" in label
               for label in expander_labels), expander_labels
    # The budget row surfaces in the action summary with its
    # confirm action; the local NOT AFFECTED row needs none.
    markdown = "\n".join(m.value or "" for m in at.markdown)
    assert "CVE-2026-5007" in markdown
    assert "beyond this run's deep-triage budget" in markdown


# ------------------- per-device verdicts (app) ---------------------

from app import _device_verdict_summary  # noqa: E402


def _batch_row(label, device_rows, verdict="AFFECTED"):
    return {"status": "ok", "label": label, "url": "",
            "triage": {"verdict": verdict,
                       "device_results": device_rows}}


def _drow(hostname, model, version, candidate, status):
    return {"hostname": hostname, "model": model,
            "version": version, "candidate": candidate,
            "status": status, "reason": ""}


def test_device_verdict_summary_counts_and_order():
    devices = [
        {"hostname": "DC-SW-01", "model": "Arista 7050SX3",
         "version": "4.30.5M"},
        {"hostname": "CORE-RTR-01", "model": "MX480",
         "version": "21.3R3"},
        {"hostname": "IDLE-SW-01", "model": "Catalyst 9300",
         "version": "17.9.4"},
    ]
    rows = [
        _batch_row("CVE-2026-1111", [
            _drow("DC-SW-01", "Arista 7050SX3", "4.30.5M", True,
                  "AFFECTED"),
            _drow("CORE-RTR-01", "MX480", "21.3R3", True,
                  "NOT AFFECTED"),
            # Not a candidate: the advisory does not concern this
            # device's product at all - not a related row.
            _drow("IDLE-SW-01", "Catalyst 9300", "17.9.4", False,
                  "NOT AFFECTED"),
        ]),
        _batch_row("CVE-2026-2222", [
            _drow("CORE-RTR-01", "MX480", "21.3R3", True,
                  "CANNOT DETERMINE"),
            _drow("DC-SW-01", "Arista 7050SX3", "4.30.5M", False,
                  "NOT AFFECTED"),
        ], verdict="CANNOT DETERMINE"),
        # Skipped entries carry no per-device verdicts.
        {"status": "skipped", "label": "CVE-2026-3333", "url": ""},
    ]
    summary = _device_verdict_summary(rows, devices, "en")
    # Affected first, then CANNOT DETERMINE count descending,
    # then the device with no related advisories - still listed,
    # so the fleet is fully accounted for.
    assert [e["hostname"] for e in summary] == [
        "DC-SW-01", "CORE-RTR-01", "IDLE-SW-01"]
    dc, core, idle = summary
    assert dc["affected"] == ["CVE-2026-1111"]
    assert dc["related"] == 1
    assert core["cannot"] == ["CVE-2026-2222"]
    assert core["not_affected"] == 1
    assert core["related"] == 2
    assert idle["related"] == 0
    assert idle["affected"] == [] and idle["cannot"] == []
    assert idle["not_affected"] == 0
    assert idle["model"] == "Catalyst 9300"
    assert idle["version"] == "17.9.4"


def test_per_device_verdicts_section_renders():
    # Seed batch results produced against the bundled sample
    # inventory (the app's fallback when no CSV is uploaded): a
    # Mock-Mode triage of sample 1. The section must list every
    # one of the 11 sample devices - including the Nokia and
    # Extreme boxes no advisory in the run relates to.
    inventory_text = (ROOT / "samples" / "inventory_sample.txt"
                      ).read_text(encoding="utf-8")
    sample1 = (ROOT / "samples" / "sample1_affected.txt"
               ).read_text(encoding="utf-8")
    result = run_triage(sample1, inventory_text)
    rows = [{"status": "ok", "label": "sample1", "url": "",
             "triage": result}]
    at = AppTest.from_file(APP)
    at.session_state["batch_results"] = rows
    at.session_state["batch_source"] = "feeds"
    at.run()
    assert not at.exception
    headings = [h.value or "" for h in at.subheader]
    assert any("Per-device verdicts" in h
               for h in headings), headings
    # Batch summary table first, per-device table second.
    assert len(at.dataframe) == 2
    frame = at.dataframe[1].value
    assert len(frame) == 11
    frame_text = frame.to_string()
    assert "CORE-SW-01" in frame_text
    assert "NOKIA-7750-01" in frame_text
    assert "EXTREME-X450-01" in frame_text
    assert "No related advisories" in frame_text


def test_results_window_height_threshold():
    # The scroll-window policy: only lists longer than the
    # threshold get a fixed height; short lists render inline.
    import app as app_module
    assert app_module.RESULTS_SCROLL_THRESHOLD == 8
    assert app_module._results_window_height(8, 480) is None
    assert app_module._results_window_height(9, 480) == 480
    assert app_module._results_window_height(0, 560) is None
    assert app_module._results_window_height(35, 560) == 560


def test_long_batch_results_render_in_scroll_window():
    # 10 seeded rows (> the 8-row threshold): the summary table
    # and the per-item expanders render inside the fixed-height
    # scroll windows. AppTest does not introspect containers, so
    # this asserts the rendering survives the wrapping - both
    # tables and every expander still present, no exception.
    inventory_text = (ROOT / "samples" / "inventory_sample.txt"
                      ).read_text(encoding="utf-8")
    sample1 = (ROOT / "samples" / "sample1_affected.txt"
               ).read_text(encoding="utf-8")
    result = run_triage(sample1, inventory_text)
    rows = [{"status": "ok", "label": "sample1-%d" % i, "url": "",
             "triage": result} for i in range(10)]
    at = AppTest.from_file(APP)
    at.session_state["batch_results"] = rows
    at.session_state["batch_source"] = "feeds"
    at.run()
    assert not at.exception
    assert len(at.dataframe) == 2
    assert len(at.dataframe[0].value) == 10
    assert len(at.expander) == 10


# ------------------------- sample inventory CSV ----------------------

def test_sample_inventory_csv_parses_to_eight_devices():
    data = (ROOT / "samples" / "sample_inventory.csv").read_bytes()
    text, meta = parse_inventory_csv(data)
    assert meta["header_mode"] == "header"
    assert meta["rows_used"] == 8
    assert meta["rows_skipped"] == 0
    devices = parse_inventory(text)
    assert len(devices) == 8
    vendors = batch.inventory_vendors(devices)
    # The template spans the fleet-wide scope: network gear
    # (including Nokia SR OS and Extreme EXOS boxes), an F5 load
    # balancer, a firewall, and servers.
    for vendor in ("cisco", "juniper", "f5", "fortinet",
                   "microsoft", "nokia", "extreme"):
        assert vendor in vendors


# ------------------------- traced caption (AppTest) ------------------

def test_feeds_caption_counts_traced_candidates_not_triaged():
    # Regression test for the deployed "Vendor-traced: 80 of 30"
    # caption: the numerator is the trace-for-screen count and
    # the denominator is the CANDIDATE count - never the smaller
    # deep-triaged count the old caption divided by. The bundled
    # fixtures make the numbers deterministic: 4 collected items,
    # all 4 screen in as candidates, the trace pass attempts all
    # 4 (2 resolve to vendor documents), and 4 are deep-triaged.
    at = AppTest.from_file(APP)
    at.run()
    assert not at.exception
    at.radio[1].set_value("feeds").run()
    assert not at.exception
    matches = [b for b in at.button
               if "Run Batch" in (b.label or "")]
    assert len(matches) == 1, "buttons: %r" % [
        b.label for b in at.button]
    matches[0].click().run()
    assert not at.exception
    feed_info = at.session_state["feed_info"]
    assert feed_info["candidates"] == 4
    assert feed_info["traced_for_screen"] == 4
    captions = [c.value or "" for c in at.caption]
    assert any("Vendor-traced: 4 of 4 candidates" in c
               for c in captions), captions
    # The old form ("traced of deep-triaged advisories") is gone.
    assert not any("Vendor-traced: 2 of 4 advisories" in c
                   for c in captions), captions


# ----------------- NVD rate budget (design 1) -----------------------

def test_nvd_sleep_spacing_uses_key_budget(monkeypatch):
    empty = {"vulnerabilities": [], "totalResults": 0}
    sleeps = []
    monkeypatch.setenv("NVD_API_KEY", "test-only")
    result = collect_nvd_items_year(
        CISCO_ONLY, fetcher=_term_fetcher({"cisco": empty}),
        sleep=sleeps.append, now=NOW)
    assert result["rate_budget"] == "key"
    assert sleeps and all(
        value == batch.NVD_SLEEP_WITH_KEY for value in sleeps)
    sleeps = []
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    result = collect_nvd_items_year(
        CISCO_ONLY, fetcher=_term_fetcher({"cisco": empty}),
        sleep=sleeps.append, now=NOW)
    assert result["rate_budget"] == "no-key"
    assert sleeps and all(
        value == batch.NVD_SLEEP_NO_KEY for value in sleeps)
    assert result["requests_made"] == 4


# ----------------- CPE mapping (design 2) ---------------------------

def test_cpe_product_key_asa_ftd_and_cloudvision():
    assert batch._cpe_product_key("cisco", "asa") == "cisco asa-ftd"
    assert batch._cpe_product_key("cisco", "ftd") == "cisco asa-ftd"
    assert batch._cpe_product_key(
        "cisco", "firepower_threat_defense") == "cisco asa-ftd"
    assert batch._cpe_product_key(
        "arista", "cloudvision") == "arista cloudvision"
    assert batch._cpe_product_key("cisco", "ios") == "cisco ios"


def test_cpe_product_key_junos_evolved_is_separate():
    assert batch._cpe_product_key(
        "juniper", "junos_os_evolved") == "juniper junos evolved"
    assert batch._cpe_product_key(
        "juniper", "junos") == "juniper junos"


def test_device_product_keys_new_families():
    assert batch._device_product_keys(
        {"hostname": "FW-01", "model": "ASA5516-X",
         "version": "9.16.4"}) == {"cisco asa-ftd"}
    assert batch._device_product_keys(
        {"hostname": "RTR-01", "model": "MX480-EVO",
         "version": "23.4R1-EVO"}) == {"juniper junos evolved"}
    assert batch._device_product_keys(
        {"hostname": "CVP-01", "model": "Arista CloudVision",
         "version": "2023.2.1"}) == {"arista cloudvision"}
    assert batch._device_product_keys(
        {"hostname": "RTR-01", "model": "MX480",
         "version": "21.3R3"}) == {"juniper junos"}


def test_screen_evolved_range_does_not_clear_classic_junos():
    evolved = _item("CVE-2026-6101", [
        _rng("junos_os_evolved", vendor="juniper",
             start_including="23.0", end_excluding="23.4")])
    rows, candidates, _stats = screen_feed_items(
        [evolved], "RTR-01, MX480, 21.3R3\n")
    assert rows == []
    classic = _item("CVE-2026-6102", [
        _rng("junos", vendor="juniper",
             start_including="22.0", end_excluding="22.5")])
    rows, candidates, _stats = screen_feed_items(
        [classic], "RTR-01, MX480-EVO, 21.3R3\n")
    assert rows == []


def test_screen_asa_range_clears_only_asa_device():
    item = _item("CVE-2026-6103", [
        _rng("asa", start_including="9.14", end_excluding="9.16")])
    rows, candidates, _stats = screen_feed_items(
        [item], "FW-01, ASA5516-X, 9.18.2\n"
                "SW-01, Catalyst 9300, 17.9.4\n")
    assert candidates == []
    assert len(rows) == 1
    device_results = rows[0]["triage"]["device_results"]
    assert device_results[0]["candidate"] is True
    assert device_results[0]["status"] == "NOT AFFECTED"
    assert device_results[1]["candidate"] is False


def test_unmapped_product_never_local():
    item = _item("CVE-2026-6104", [
        _rng("quantum_gateway", vendor="checkpoint",
             end_excluding="1.0")],
        text="CVE-2026-6104 advisory.")
    rows, candidates, stats = screen_feed_items(
        [item], TWO_DEVICE_TEXT)
    assert rows == []
    assert stats["unmapped_products"] >= 1


def test_junos_s_release_orders_after_base_r():
    assert batch._eval_range(
        "21.2R3-S7",
        _rng("junos", vendor="juniper",
             end_excluding="21.2R3")) is False
    assert batch._eval_range(
        "21.2R2",
        _rng("junos", vendor="juniper",
             end_excluding="21.2R3-S7")) is True


def test_eos_letter_tie_stays_uncertain():
    item = _item("CVE-2026-6105", [
        _rng("eos", vendor="arista", exact="4.30.5F")])
    rows, candidates, stats = screen_feed_items(
        [item], "DC-SW-01, Arista 7050SX3, 4.30.5M\n")
    assert rows == []
    assert len(candidates) == 1
    assert stats["uncertain_candidates"] == 1


# ----------------- KEV verdict strength (design 3) ------------------

def _kev_only_pipeline(monkeypatch, kev_entries, nvd_payloads=None,
                       trace_json=None, lang="en"):
    judged = _spy_on_run_batch_items(monkeypatch)
    payloads = nvd_payloads or {
        "juniper": {"vulnerabilities": []},
        "cisco": {"vulnerabilities": []}}

    def boom_text(url):
        raise batch.FetchError("no page text")

    def boom_json(url):
        raise batch.FetchError("no record")

    rows, stats = run_feed_pipeline(
        TWO_DEVICE_TEXT, mock=True, lang=lang,
        nvd_fetcher=_term_fetcher(payloads),
        kev_fetcher=lambda url: {"vulnerabilities": kev_entries},
        trace_fetcher=boom_text,
        trace_json_fetcher=trace_json or boom_json, now=NOW)
    return rows, stats, judged


def test_pipeline_kev_no_range_becomes_kev_unconfirmed_row(
        monkeypatch):
    entry = _kev_entry("CVE-2026-6201", "Juniper", "Junos OS",
                       "2026-09-01", due="2026-12-01")
    rows, stats, judged = _kev_only_pipeline(monkeypatch, [entry])
    assert len(rows) == 1
    row = rows[0]
    assert row["basis"] == "local-screen"
    # K-2 grade (bgp parity §3): the product match is settled and
    # the open question is the version check - CONDITION, not
    # CANNOT.
    assert row["triage"]["verdict"] == "CONDITION CHECK REQUIRED"
    assert row["triage"]["clocked_calls"] == 0
    assert stats["condition_check"] == 1
    assert len(row["triage"]["conditions"]) == 1
    assert "KEV" in row["triage"]["conditions"][0]
    assert row["triage"]["extracted"]["action_deadline"] == \
        "2026-12-01"
    assert row["sources"] == ["KEV"]
    assert row["due_date"] == "2026-12-01"
    assert stats["kev_unconfirmed"] == 1
    assert stats["deep_triaged"] == 0
    assert judged == []


# ----------------- reason codes in the screen (§2) -------------------

def test_screen_eval_codes_suffix_mismatch_precedence():
    devices = parse_inventory("DC-SW-01, Arista 7050SX3, 4.30.5F\n")
    item = {"label": "CVE-2026-9201", "text": "Arista EOS flaw.",
            "cpe_ranges": [{"vendor": "Arista", "product": "EOS",
                        "vulnerable": True,
                        "end_including": "4.30.5M"}]}
    evaluation = _screen_item(
        item, devices, [_device_product_keys(d) for d in devices])
    assert evaluation["evals"] == ["uncertain"]
    assert evaluation["eval_codes"] == ["VERSION_SUFFIX_MISMATCH"]


def test_screen_eval_codes_partial_clear_is_range_partial():
    devices = parse_inventory("RTR-01, MX480, 21.4R3\n")
    item = {"label": "JSA-2026-1", "text": "Juniper Junos flaw.",
            "cpe_ranges": [{"vendor": "Juniper",
                            "product": "Junos OS",
                        "vulnerable": True, "partial": True,
                        "end_excluding": "21.4R2"}]}
    evaluation = _screen_item(
        item, devices, [_device_product_keys(d) for d in devices])
    assert evaluation["evals"] == ["uncertain"]
    assert evaluation["eval_codes"] == ["RANGE_PARTIAL"]


def test_local_entry_reason_codes_per_kind():
    devices = parse_inventory("RTR-01, MX480, 21.4R3\n")
    item = {"label": "CVE-2026-9202", "text": "Juniper Junos flaw."}
    cleared_eval = {"evals": ["cleared"],
                    "eval_codes": ["VERSION_OUT_OF_RANGE"],
                    "displays": ["Juniper Junos OS"],
                    "range_lines": []}
    entry = _make_local_entry(item, devices, cleared_eval,
                              "not_affected", "en")
    assert entry["triage"]["reason_code"] == "SCREEN_CLEARED"
    assert entry["triage"]["device_results"][0]["reason_code"] == \
        "VERSION_OUT_OF_RANGE"
    hit_eval = {"evals": ["hit"],
                "eval_codes": ["VERSION_TRAIN_EQUAL"],
                "displays": ["Juniper Junos OS"], "range_lines": []}
    entry = _make_local_entry(item, devices, hit_eval, "budget",
                              "en", budget=30)
    assert entry["triage"]["reason_code"] == "BUDGET_EXHAUSTED"
    assert entry["triage"]["device_results"][0]["reason_code"] == \
        "VERSION_TRAIN_EQUAL"
    kev_eval = {"evals": ["uncertain"],
                "eval_codes": ["NO_VERSION_EVIDENCE"],
                "displays": ["Juniper Junos OS"], "range_lines": []}
    entry = _make_local_entry(item, devices, kev_eval,
                              "kev_unconfirmed", "en")
    assert entry["triage"]["reason_code"] == "KEV_NO_VERSION_RANGE"
    assert entry["triage"]["device_results"][0]["reason_code"] == \
        "KEV_NO_VERSION_RANGE"


def test_local_entry_rows_localized_ko():
    devices = parse_inventory("RTR-01, MX480, 21.4R3\n")
    item = {"label": "CVE-2026-9203", "text": "Juniper Junos flaw."}
    cleared_eval = {"evals": ["cleared"],
                    "eval_codes": ["VERSION_OUT_OF_RANGE"],
                    "displays": ["Juniper Junos OS"],
                    "range_lines": []}
    entry = _make_local_entry(item, devices, cleared_eval,
                              "not_affected", "ko")
    reason = entry["triage"]["device_results"][0]["reason"]
    assert any("가" <= ch <= "힣" for ch in reason), reason


def test_device_summary_counts_condition_rows():
    rows = [{"status": "ok", "label": "KEV CVE-2026-7473",
             "url": "",
             "triage": {"device_results": [
                 {"hostname": "DC-SW-01",
                  "model": "Arista 7050SX3", "version": "4.30.5M",
                  "candidate": True,
                  "status": "CONDITION CHECK REQUIRED",
                  "reason": "gated"}]}}]
    summary = _device_verdict_summary(rows, [], "en")
    entry = [e for e in summary
             if e["hostname"] == "DC-SW-01"][0]
    assert entry["condition"] == ["KEV CVE-2026-7473"]
    assert entry["cannot"] == []
    assert entry["related"] == 1


def test_action_summary_includes_condition_rows():
    inventory_text = (ROOT / "samples" / "inventory_sample.txt"
                      ).read_text(encoding="utf-8")
    rows, _stats = run_feed_pipeline(inventory_text, mock=True)
    at = AppTest.from_file(APP)
    at.session_state["batch_results"] = rows
    at.session_state["batch_source"] = "feeds"
    at.run()
    assert not at.exception
    markdown = "\n".join(m.value or "" for m in at.markdown)
    # The KEV CONDITION row appears in the action summary, under
    # its extracted advisory ID (the summary table is a dataframe
    # and the per-item details are expanders, so this bolded
    # action-line pattern occurs only in the action summary).
    assert "- **#1 CVE-2026-7473**" in markdown


def test_pipeline_kev_with_traced_ranges_that_hit_still_deep_triaged(
        monkeypatch):
    entry = _kev_entry("CVE-2026-6202", "Juniper", "Junos OS",
                       "2026-09-01", due="2026-12-01")
    payload = {
        "cveMetadata": {"cveId": "CVE-2026-6202"},
        "containers": {"cna": {
            "affected": [{
                "vendor": "Juniper Networks", "product": "Junos OS",
                "versions": [{"version": "21.2",
                              "lessThan": "21.4R1",
                              "status": "affected"}]}],
            "descriptions": [{"lang": "en", "value":
                              "Junos OS flaw."}],
        }},
    }

    def trace_json(url):
        if url == batch.cvelist_url("CVE-2026-6202"):
            return payload
        raise batch.FetchError("no record")

    rows, stats, judged = _kev_only_pipeline(
        monkeypatch, [entry], trace_json=trace_json)
    assert judged == ["KEV CVE-2026-6202"]
    assert stats["kev_unconfirmed"] == 0
    assert stats["deep_triaged"] == 1


def test_pipeline_kev_with_nvd_ranges_cleared_is_not_affected(
        monkeypatch):
    vuln = _vuln(
        "CVE-2026-6203", "2026-08-01T00:00:00.000",
        "Juniper Junos OS flaw.", score=8.8, severity="HIGH",
        configurations=_configs(
            "junos", vendor="juniper",
            versionStartIncluding="22.0",
            versionEndExcluding="22.5"))
    entry = _kev_entry("CVE-2026-6203", "Juniper", "Junos OS",
                       "2026-09-01", due="2026-12-01")
    rows, stats, judged = _kev_only_pipeline(
        monkeypatch, [entry],
        nvd_payloads={
            "juniper": {"vulnerabilities": [vuln]},
            "cisco": {"vulnerabilities": []}})
    assert judged == []
    assert stats["kev_unconfirmed"] == 0
    assert len(rows) == 1
    row = rows[0]
    assert row["triage"]["verdict"] == "NOT AFFECTED"
    assert row["kev"] is True
    assert row["sources"] == ["NVD", "KEV"]


def test_kev_unconfirmed_warnings_overdue_and_ransomware():
    devices = parse_inventory(TWO_DEVICE_TEXT)
    overdue = _kev_entry("CVE-2026-6204", "Juniper", "Junos OS",
                         "2026-09-01", due="2026-01-01")
    overdue["knownRansomwareCampaignUse"] = "Known"
    item = batch._kev_item(overdue)
    evaluation = batch._evaluate_item(item, devices)
    row = batch._make_local_entry(
        item, devices, evaluation, "kev_unconfirmed", "en",
        today=datetime.date(2026, 11, 7))
    warnings = row["triage"]["warnings"]
    assert any("has passed" in w for w in warnings)
    assert any("Known ransomware use" in w for w in warnings)
    row_ko = batch._make_local_entry(
        item, devices, evaluation, "kev_unconfirmed", "ko",
        today=datetime.date(2026, 11, 7))
    warnings_ko = row_ko["triage"]["warnings"]
    assert any("지났습니다" in w for w in warnings_ko)
    assert any("랜섬웨어" in w for w in warnings_ko)
    calm = _kev_entry("CVE-2026-6205", "Juniper", "Junos OS",
                      "2026-09-01", due="2027-01-01")
    item2 = batch._kev_item(calm)
    row2 = batch._make_local_entry(
        item2, devices, batch._evaluate_item(item2, devices),
        "kev_unconfirmed", "en", today=datetime.date(2026, 11, 7))
    assert row2["triage"]["warnings"] == []


# ----------------- merge parity (design 4) --------------------------

def test_year_and_recent_merge_agree():
    from batch import collect_feed_items
    vuln = _vuln("CVE-2026-4001", "2026-08-01T00:00:00.000",
                 "Juniper Junos OS flaw.", score=8.8,
                 severity="HIGH")
    catalog = {"vulnerabilities": [
        _kev_entry("CVE-2026-4001", "Juniper", "Junos OS",
                   "2026-09-01")]}
    payloads = {"juniper": {"vulnerabilities": [vuln]},
                "cisco": {"vulnerabilities": []}}
    devices = parse_inventory(TWO_DEVICE_TEXT)
    recent = collect_feed_items(
        devices, nvd_fetcher=_term_fetcher(payloads),
        kev_fetcher=lambda url: catalog)
    year = collect_feed_items_year(
        devices, nvd_fetcher=_term_fetcher(payloads),
        kev_fetcher=lambda url: catalog, now=NOW)
    recent_merged = [i for i in recent["items"]
                     if i["label"] == "CVE-2026-4001"][0]
    year_merged = [i for i in year["items"]
                   if i["label"] == "CVE-2026-4001"][0]
    for key in ("sources", "kev", "due_date"):
        assert recent_merged[key] == year_merged[key]
    assert recent_merged["sources"] == ["NVD", "KEV"]


def test_app_summary_table_has_sources_column():
    cleared = _item("CVE-2026-6301", [
        _rng("ios_xe", start_including="17.9",
             end_excluding="17.9.4")])
    cleared["sources"] = ["NVD", "KEV"]
    cleared["kev"] = True
    rows, _c, _s = screen_feed_items([cleared], TWO_DEVICE_TEXT)
    devices = parse_inventory(TWO_DEVICE_TEXT)
    kev_entry = batch._make_local_entry(
        batch._kev_item(_kev_entry(
            "CVE-2026-6302", "Juniper", "Junos OS", "2026-09-01",
            due="2026-12-01")),
        devices,
        batch._evaluate_item(
            batch._kev_item(_kev_entry(
                "CVE-2026-6302", "Juniper", "Junos OS", "2026-09-01",
                due="2026-12-01")), devices),
        "kev_unconfirmed", "en", today=datetime.date(2026, 11, 7))
    rows.append(kev_entry)
    # An upload-shaped entry (no sources at all) must render "-",
    # never KeyError.
    rows.append({"status": "ok", "label": "notes.txt", "url": "",
                 "triage": {"verdict": "CANNOT DETERMINE",
                            "urgency": "monitor",
                            "device_results": [], "conditions": [],
                            "error": None}})
    at = AppTest.from_file(APP)
    at.session_state["batch_results"] = rows
    at.session_state["batch_source"] = "feeds"
    at.run()
    assert not at.exception
    frame = at.dataframe[0].value
    assert "Sources" in list(frame.columns)
    values = [str(v) for v in frame["Sources"]]
    assert "NVD + KEV" in values
    assert "KEV" in values
    assert "-" in values
    at.selectbox[0].set_value("한국어").run()
    assert not at.exception
    frame_ko = at.dataframe[0].value
    assert "출처" in list(frame_ko.columns)
    values_ko = [str(v) for v in frame_ko["출처"]]
    assert "NVD + KEV" in values_ko


# ---------------- EOS equality rules R1/R2 (bgp parity) -------------
#
# The 0137 / CVE-2026-7473 regression anchors (DESIGN-BGP-PARITY
# §1.6): Arista CNA publishes inclusive bounds at train precision,
# and the screen used to clear the train's own patch releases.

def _eos_rng(**kwargs):
    return _rng("eos", vendor="arista", **kwargs)


def test_eval_range_eos_train_bound_includes_train_members():
    rng = _eos_rng(start_including="4.28", end_including="4.31")
    # The headline case: 4.31.1F vs end_including "4.31" was False
    # (a false clear) before R1; it is inside now.
    assert batch._eval_range("4.31.1F", rng) is True
    assert batch._eval_range("4.30.5F", rng) is True
    assert batch._eval_range(
        "4.32.2F", _eos_rng(start_including="4.28",
                            end_including="4.32")) is True
    assert batch._eval_range(
        "4.35.1F", _eos_rng(start_including="4.28",
                            end_including="4.35")) is True
    # A device in the start train satisfies the start bound (real
    # comparison and R1 agree here), and one below the range stays
    # outside by the real numeric comparison.
    assert batch._eval_range("4.28.2F", rng) is True
    assert batch._eval_range("4.27.9F", rng) is False
    assert batch._eval_range(
        "4.28.2F", _eos_rng(start_including="4.29",
                            end_including="4.35")) is False


def test_eval_range_eos_r2_exact_and_suffix_mismatch():
    # R2: exact "4.36.0" names the same release as device 4.36.0F.
    assert batch._eval_range(
        "4.36.0F", _eos_rng(exact="4.36.0")) is True
    # F vs M: incomparable on every path - never True, never False.
    assert batch._eval_range(
        "4.30.5F", _eos_rng(exact="4.30.5M")) is None
    assert batch._eval_range(
        "4.30.5F", _eos_rng(end_including="4.30.5M")) is None


def test_eval_range_eos_rules_scoped_to_arista_key():
    # The identical bounds under a Cisco product keep the generic
    # outcomes: R1/R2 resolve from the range's own product key.
    rng = _rng("ios_xe", start_including="4.28",
               end_including="4.31")
    assert batch._eval_range("4.31.1F", rng) is False
    # And the one-sided exact stays behind the I-2 guard (None).
    assert batch._eval_range(
        "4.36.0F", _rng("ios_xe", exact="4.36.0")) is None


def test_eval_range_detail_reports_eos_flavours():
    assert batch._eval_range_detail(
        "4.31.1F", _eos_rng(end_including="4.31")) == \
        (True, "train_equal")
    assert batch._eval_range_detail(
        "4.36.0F", _eos_rng(exact="4.36.0")) == \
        (True, "suffix_equal")
    assert batch._eval_range_detail(
        "4.30.5F", _eos_rng(exact="4.30.5M")) == \
        (None, "suffix_mismatch")
    assert batch._eval_range_detail(
        "17.9.4", _rng("ios_xe", end_excluding="17.9.5")) == \
        (True, None)


def test_screen_item_0137_eval_is_hit_not_cleared():
    devices = parse_inventory(
        "DC-SW-01, Arista 7050SX3, 4.31.1F\n")
    item = _item("CVE-2026-7473", [
        _eos_rng(start_including="4.28", end_including="4.31")])
    evaluation = batch._screen_item(
        item, devices,
        [batch._device_product_keys(d) for d in devices])
    assert evaluation["evals"] == ["hit"]
    assert evaluation["outcome"] == "candidate"
    rows, candidates, stats = screen_feed_items(
        [item], "DC-SW-01, Arista 7050SX3, 4.31.1F\n")
    assert rows == []
    assert [c["label"] for c in candidates] == ["CVE-2026-7473"]
    assert stats["uncertain_candidates"] == 0
