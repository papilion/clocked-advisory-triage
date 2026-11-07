"""Offline tests for source reachability classification, the
probe, and the KEV catalog TTL cache / ETag revalidation
(design section 5).

No network: every fetcher is a stub, and the in-process feed
cache is reset per test. Run: pytest -q
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest  # noqa: E402

import batch  # noqa: E402
from batch import FetchError, collect_kev_items, run_feed_pipeline  # noqa: E402
from triage import parse_inventory  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent

INVENTORY_TEXT = (ROOT / "samples" / "inventory_sample.txt"
                  ).read_text(encoding="utf-8")


@pytest.fixture(autouse=True)
def _offline(monkeypatch):
    monkeypatch.delenv("CLOCKED_API_KEY", raising=False)
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    batch._FEED_CACHE.clear()
    yield
    batch._FEED_CACHE.clear()


def _probe_json_fetcher(kev_payload=None, counts=None):
    def fetch(url):
        if counts is not None:
            counts["json"] = counts.get("json", 0) + 1
        if "arista.com" in url:
            raise FetchError("challenge page (HTTP 200 HTML)",
                             status=200, content_type="text/html")
        if "cisa.gov" in url:
            return kev_payload if kev_payload is not None else {
                "vulnerabilities": [], "catalogVersion": "2026.11.06"}
        if "CVEProject" in url:
            return {"cveMetadata": {"cveId": "CVE-2023-36844"}}
        return {"vulnerabilities": [], "totalResults": 0}
    return fetch


def _probe_text_fetcher(counts=None):
    def fetch(url):
        if counts is not None:
            counts["text"] = counts.get("text", 0) + 1
        if "juniper" in url:
            return ("CEC Juniper Community - forums, knowledge "
                    "base and support navigation. " * 60)
        return ('<rss version="2.0"><channel>'
                '<link>https://sec.cloudapps.cisco.com/csaf</link>'
                '</channel></rss>')
    return fetch


def test_fetch_json_rejects_html_challenge(monkeypatch):
    def fake_raw_ex(url, timeout=15, headers=None):
        return ("<html><body>challenge</body></html>", "text/html",
                url, {}, 200)

    monkeypatch.setattr(batch, "_fetch_raw_ex", fake_raw_ex)
    with pytest.raises(FetchError) as excinfo:
        batch._fetch_json("https://vendor.example/advisory.json")
    assert "challenge" in str(excinfo.value)
    assert excinfo.value.status == 200
    assert batch._classify_error(excinfo.value) == \
        batch.REACH_CHALLENGE


def test_probe_arista_challenge_and_juniper_shell():
    result = batch.probe_sources(
        json_fetcher=_probe_json_fetcher(),
        text_fetcher=_probe_text_fetcher())
    assert result["arista_csaf"]["status"] == "blocked-challenge"
    assert result["juniper_jsa"]["status"] == "blocked-challenge"
    assert result["cisco_csaf"]["status"] == "ok"
    assert result["cna"]["status"] == "ok"
    assert result["nvd"]["status"] == "ok"
    assert result["kev"]["status"] == "ok"


def test_probe_nvd_zero_results_is_ok():
    result = batch.probe_sources(
        json_fetcher=_probe_json_fetcher(),
        text_fetcher=_probe_text_fetcher())
    assert result["nvd"]["status"] == "ok"


def test_probe_kev_requires_catalog_version():
    result = batch.probe_sources(
        json_fetcher=_probe_json_fetcher(
            kev_payload={"vulnerabilities": []}),
        text_fetcher=_probe_text_fetcher())
    assert result["kev"]["status"] == "invalid-content"
    batch._FEED_CACHE.clear()
    result = batch.probe_sources(
        json_fetcher=_probe_json_fetcher(),
        text_fetcher=_probe_text_fetcher())
    assert result["kev"]["status"] == "ok"
    assert "2026.11.06" in result["kev"]["detail"]


def test_probe_cached_within_ttl():
    counts = {}
    batch.probe_sources(
        json_fetcher=_probe_json_fetcher(counts=counts),
        text_fetcher=_probe_text_fetcher(counts=counts))
    first = dict(counts)
    assert first["json"] > 0 and first["text"] > 0
    batch.probe_sources(
        json_fetcher=_probe_json_fetcher(counts=counts),
        text_fetcher=_probe_text_fetcher(counts=counts))
    assert counts == first
    batch._FEED_CACHE.clear()
    batch.probe_sources(
        json_fetcher=_probe_json_fetcher(counts=counts),
        text_fetcher=_probe_text_fetcher(counts=counts))
    assert counts["json"] > first["json"]


_CATALOG = {"catalogVersion": "2026.11.06", "vulnerabilities": [
    {"cveID": "CVE-2026-1111", "vendorProject": "Cisco",
     "product": "IOS XE", "dateAdded": "2026-09-01",
     "dueDate": "2026-10-01", "vulnerabilityName": "XE flaw",
     "requiredAction": "Apply fix.",
     "knownRansomwareCampaignUse": "Unknown"}]}


def test_kev_catalog_ttl_cache_and_304(monkeypatch):
    devices = parse_inventory(INVENTORY_TEXT)
    calls = []

    def fake_200(url, timeout=15, headers=None):
        calls.append(dict(headers or {}))
        return (json.dumps(_CATALOG), "application/json", url,
                {"etag": '"v1"'}, 200)

    monkeypatch.setattr(batch, "_fetch_raw_ex", fake_200)
    first = collect_kev_items(devices)
    assert first["count"] == 1
    assert first["from_cache"] is False
    assert first["catalog_version"] == "2026.11.06"
    assert len(calls) == 1
    second = collect_kev_items(devices)
    assert second["from_cache"] is True
    assert len(calls) == 1  # TTL hit: no second HTTP request
    # Expire the entry; the revalidation must send the stored
    # ETag and serve the stored body on a 304.
    batch._FEED_CACHE.put(
        "kev_catalog", batch._FEED_CACHE.peek("kev_catalog"), -1)

    def fake_304(url, timeout=15, headers=None):
        calls.append(dict(headers or {}))
        raise FetchError("not modified", status=304)

    monkeypatch.setattr(batch, "_fetch_raw_ex", fake_304)
    third = collect_kev_items(devices)
    assert calls[-1].get("If-None-Match") == '"v1"'
    assert third["from_cache"] is True
    assert third["count"] == 1


def test_pipeline_reports_reachability_without_clocked_calls(
        monkeypatch):
    fake_reach = {key: {"status": "ok", "detail": "",
                        "http_status": 200}
                  for key in ("nvd", "kev", "cisco_csaf",
                              "arista_csaf", "juniper_jsa", "cna")}
    monkeypatch.setattr(batch, "probe_sources",
                        lambda *a, **k: fake_reach)

    def empty_fetcher(url):
        return {"vulnerabilities": [], "totalResults": 0}

    def boom(url):
        raise FetchError("no trace route")

    rows, stats = run_feed_pipeline(
        "RTR-01, MX480, 21.3R3\n", mock=False,
        nvd_fetcher=empty_fetcher,
        kev_fetcher=lambda url: {"vulnerabilities": []},
        trace_fetcher=boom, trace_json_fetcher=boom)
    assert set(stats["reachability"]) == {
        "nvd", "kev", "cisco_csaf", "arista_csaf", "juniper_jsa",
        "cna"}
    assert stats["deep_triaged"] == 0
    rows, stats = run_feed_pipeline(
        "RTR-01, MX480, 21.3R3\n", mock=True)
    assert stats["reachability"] == {}
