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
    collect_feed_items_year,
    collect_nvd_items_year,
    parse_inventory_csv,
    run_feed_pipeline,
    screen_feed_items,
)
from triage import parse_inventory  # noqa: E402

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
                     "uncertain_candidates": 0}


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
    budget_rows = [r for r in rows if r.get("basis") == "local-screen"]
    triaged_rows = [r for r in rows
                    if r.get("basis") != "local-screen"]
    assert len(triaged_rows) == FULL_TRIAGE_CAP
    assert len(budget_rows) == 5
    # Priority is KEV > severity > recency, so the five items left
    # beyond the budget are the oldest low-severity non-KEV ones.
    assert sorted(r["label"] for r in budget_rows) == [
        "CVE-2026-2003", "CVE-2026-2004", "CVE-2026-2005",
        "CVE-2026-2006", "CVE-2026-2007"]
    triaged_labels = {r["label"] for r in triaged_rows}
    assert "CVE-2026-2000" in triaged_labels  # old but CRITICAL
    assert "CVE-2026-2001" in triaged_labels  # KEV wins over age
    assert "CVE-2026-2002" in triaged_labels
    for row in budget_rows:
        triage_result = row["triage"]
        assert triage_result["verdict"] == "CANNOT DETERMINE"
        assert triage_result["urgency"] == "monitor"
        assert "beyond this run's deep-triage budget" in \
            triage_result["action_required"]
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
    assert stats["deep_triaged"] == 12
    assert all(r.get("basis") != "local-screen" for r in rows)


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
    assert len(at.dataframe) == 1
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


# ------------------------- sample inventory CSV ----------------------

def test_sample_inventory_csv_parses_to_six_devices():
    data = (ROOT / "samples" / "sample_inventory.csv").read_bytes()
    text, meta = parse_inventory_csv(data)
    assert meta["header_mode"] == "header"
    assert meta["rows_used"] == 6
    assert meta["rows_skipped"] == 0
    devices = parse_inventory(text)
    assert len(devices) == 6
    vendors = batch.inventory_vendors(devices)
    # The template spans the fleet-wide scope: network gear, an
    # F5 load balancer, a firewall, and servers.
    for vendor in ("cisco", "juniper", "f5", "fortinet",
                   "microsoft"):
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
