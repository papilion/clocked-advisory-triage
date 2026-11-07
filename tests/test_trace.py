"""Offline tests for vendor full-text tracing (batch.trace_items),
the NVD structured-range capture, and the batch runner's
source_label/source_url passthrough.

No network: every fetcher is stubbed, and Mock Mode tracing reads
the bundled CSAF/CNA fixture files. Run: pytest -q
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest  # noqa: E402

import batch  # noqa: E402
from batch import (  # noqa: E402
    FetchError,
    collect_feed_items,
    collect_nvd_items,
    cvelist_url,
    run_batch_items,
    trace_items,
)
from triage import parse_inventory  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent

CISCO_PUB_URL = (
    "https://sec.cloudapps.cisco.com/security/center/content/"
    "CiscoSecurityAdvisory/cisco-sa-iosxe-webui-privesc-j22SaA4z")
CISCO_CSAF_URL = (
    "https://sec.cloudapps.cisco.com/security/center/contentjson/"
    "CiscoSecurityAdvisory/cisco-sa-iosxe-webui-privesc-j22SaA4z/"
    "csaf/cisco-sa-iosxe-webui-privesc-j22SaA4z.json")
JSA_URL = "https://supportportal.juniper.net/JSA72300"


@pytest.fixture(autouse=True)
def _no_api_key(monkeypatch):
    # Deterministic Mock Mode regardless of the caller's environment.
    monkeypatch.delenv("CLOCKED_API_KEY", raising=False)


def _sample_text(filename):
    # type: (str) -> str
    return (ROOT / "samples" / filename).read_text(encoding="utf-8")


def _load_fixture(name):
    return json.loads((ROOT / "samples" / name).read_text(
        encoding="utf-8"))


def _cna_payload(cve_id, product, versions, description):
    return {
        "cveMetadata": {"cveId": cve_id},
        "containers": {"cna": {
            "affected": [{"vendor": "Vendor", "product": product,
                          "platforms": ["EX Series"],
                          "versions": versions}],
            "descriptions": [{"lang": "en", "value": description}],
            "references": [{"url": JSA_URL}],
        }},
    }


# ---------------------- NVD structured capture ----------------------

def test_nvd_item_references_and_cpe_ranges():
    vuln = {"cve": {
        "id": "CVE-2024-5000",
        "published": "2024-03-01T00:00:00.000",
        "descriptions": [{"lang": "en", "value": "A flaw."}],
        "references": [{"url": "https://vendor.example/adv"},
                       {"url": "https://other.example/x"},
                       {"url": "https://vendor.example/adv"}],
        "configurations": [{"nodes": [{"operator": "OR", "cpeMatch": [
            {"criteria": "cpe:2.3:o:cisco:ios_xe:*:*:*:*:*:*:*:*",
             "vulnerable": True,
             "versionStartIncluding": "17.6",
             "versionEndExcluding": "17.9.6"},
            {"criteria": "cpe:2.3:o:cisco:ios_xe:*:*:*:*:*:*:*:*",
             "vulnerable": True,
             "versionStartIncluding": "17.6",
             "versionEndExcluding": "17.9.6"},
            {"criteria": "cpe:2.3:o:cisco:ios_xe:17.9.4:*:*:*:*:*:*:*",
             "vulnerable": True},
            {"criteria": "cpe:2.3:h:cisco:catalyst_9300:-:*:*:*:*:*:*:*",
             "vulnerable": False},
        ]}]},
    ]}}
    devices = [{"hostname": "SW", "model": "Catalyst 9300",
                "version": "17.9.4"}]
    result = collect_nvd_items(
        devices, fetcher=lambda url: {"vulnerabilities": [vuln]})
    item = result["items"][0]
    # The full reference list survives (deduped, in order) - the
    # trace step follows these URLs.
    assert item["references"] == ["https://vendor.example/adv",
                                  "https://other.example/x"]
    assert "Structured affected ranges (NVD CPE):" in item["text"]
    assert ("- product ios_xe: versions >= 17.6 and < 17.9.6"
            in item["text"])
    assert "- product ios_xe: version 17.9.4" in item["text"]
    # The non-vulnerable hardware match contributes nothing.
    assert "catalyst_9300" not in item["text"]
    # Ranged line appears once despite the duplicated match.
    assert item["text"].count(">= 17.6 and < 17.9.6") == 1


# ------------------------- cvelist bucket ---------------------------

def test_cvelist_url_buckets():
    assert cvelist_url("CVE-2026-101943") == (
        "https://raw.githubusercontent.com/CVEProject/cvelistV5/"
        "main/cves/2026/101xxx/CVE-2026-101943.json")
    assert cvelist_url("CVE-2023-44189").endswith(
        "/2023/44xxx/CVE-2023-44189.json")
    assert cvelist_url("not-a-cve") == ""


# --------------------------- Cisco CSAF -----------------------------

def test_trace_cisco_csaf_via_derived_url():
    item = {"label": "CVE-2023-20198",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-20198",
            "text": "CVE-2023-20198 \u2014 Cisco IOS XE\n\nFeed body.",
            "references": [CISCO_PUB_URL]}
    fixture = _load_fixture("cisco_csaf_fixture.json")
    seen = []

    def json_fetch(url):
        seen.append(url)
        return fixture

    def text_fetch(url):
        raise FetchError("no page fetch expected")

    traced, stats = trace_items([item], fetcher=text_fetch,
                                json_fetcher=json_fetch)
    assert seen == [CISCO_CSAF_URL]
    assert stats == {"traced": 1, "attempted": 1,
                     "by_source": {"Cisco CSAF": 1}}
    out = traced[0]
    assert out["source_label"] == "Cisco CSAF"
    assert out["source_url"] == CISCO_CSAF_URL
    assert out["url"] == CISCO_CSAF_URL
    assert out["text"].startswith(
        "Multiple Vulnerabilities in Cisco IOS XE Software Web UI "
        "Feature")
    assert "Affected products/versions:" in out["text"]
    # Branch-path composition: family name + leaf version.
    assert "Cisco IOS XE Software 17.9.4" in out["text"]
    assert "Cisco IOS XE Software 17.6.5" in out["text"]
    assert ("Workarounds/Remediation: Cisco has released software "
            "updates" in out["text"])
    assert "NVD: https://nvd.nist.gov/vuln/detail/CVE-2023-20198" \
        in out["text"]
    assert "--- Feed summary ---\nCVE-2023-20198" in out["text"]
    # The caller's item was not mutated.
    assert "source_label" not in item


# -------------------------- Juniper routes --------------------------

def _juniper_item():
    return {"label": "CVE-2023-36844",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-36844",
            "text": "CVE-2023-36844 \u2014 Juniper Junos\n\nFeed body.",
            "references": [JSA_URL]}


def test_trace_juniper_jsa_full_text():
    page = "JSA72300 - J-Web vulnerability. " * 30  # > 400 chars

    def text_fetch(url):
        assert url == JSA_URL
        return page

    def json_fetch(url):
        raise AssertionError("CNA must not be fetched when JSA works")

    traced, stats = trace_items([_juniper_item()], fetcher=text_fetch,
                                json_fetcher=json_fetch)
    out = traced[0]
    assert stats["by_source"] == {"Juniper JSA": 1}
    assert out["source_label"] == "Juniper JSA"
    assert out["source_url"] == JSA_URL
    assert ("Vendor advisory (Juniper JSA): %s" % JSA_URL
            in out["text"])
    assert "J-Web vulnerability" in out["text"]


def test_trace_juniper_short_jsa_falls_back_to_cna():
    payload = _cna_payload(
        "CVE-2023-36844", "Junos OS",
        [{"version": "20.4", "lessThan": "20.4R3-S9",
          "status": "affected"},
         {"version": "21.2", "lessThan": "21.2R3-S6",
          "status": "affected"},
         {"version": "22.1", "status": "unaffected"}],
        "J-Web vulnerability description.")

    def text_fetch(url):
        return "too short"

    def json_fetch(url):
        assert url == cvelist_url("CVE-2023-36844")
        return payload

    traced, stats = trace_items([_juniper_item()], fetcher=text_fetch,
                                json_fetcher=json_fetch)
    out = traced[0]
    assert stats["by_source"] == {"CVE CNA record": 1}
    assert out["source_label"] == "CVE CNA record"
    assert ("Affected: Junos OS on EX Series: versions "
            "20.4 < 20.4R3-S9; 21.2 < 21.2R3-S6 (affected)"
            in out["text"])
    assert "J-Web vulnerability description." in out["text"]
    assert "22.1" not in out["text"]


# --------------------- Arista CSAF -> CNA fallback -------------------

def test_trace_arista_csaf_failure_falls_back_to_cna():
    item = {"label": "CVE-2024-9999",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-9999",
            "text": "CVE-2024-9999 \u2014 Arista EOS\n\nFeed body.",
            "references": [
                "https://www.arista.com/en/support/advisories-notices/"
                "security-advisory/24838-security-advisory-0199"]}
    payload = _cna_payload(
        "CVE-2024-9999", "EOS",
        [{"version": "4.30.0", "lessThan": "4.30.6M",
          "status": "affected"}],
        "Arista EOS flaw.")
    attempted = []

    def json_fetch(url):
        attempted.append(url)
        if "arista.com" in url:
            raise FetchError("HTTP 403")
        return payload

    def text_fetch(url):
        raise FetchError("unused")

    traced, stats = trace_items([item], fetcher=text_fetch,
                                json_fetcher=json_fetch)
    # Advisory 0199 -> CSAF file 199 (leading zeros stripped).
    assert attempted[0] == (
        "https://www.arista.com/assets/data/SecurityAdvisories/CSAF/"
        "arista_networks_security_advisory_199_CSAF.json")
    out = traced[0]
    assert stats["by_source"] == {"CVE CNA record": 1}
    assert out["source_label"] == "CVE CNA record"
    assert "Affected: EOS on EX Series" in out["text"]


# ------------------------- cap and failure ---------------------------

def test_trace_cap_respected():
    items = [{"label": "CVE-2024-%04d" % i,
              "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-%04d" % i,
              "text": "Feed body %d." % i}
             for i in range(12)]

    def json_fetch(url):
        cve_id = url.rsplit("/", 1)[-1].replace(".json", "")
        return _cna_payload(cve_id, "Widget",
                            [{"version": "1.0", "status": "affected"}],
                            "Description for %s." % cve_id)

    def text_fetch(url):
        raise FetchError("unused")

    traced, stats = trace_items(items, fetcher=text_fetch,
                                json_fetcher=json_fetch)
    assert stats["attempted"] == 10
    assert stats["traced"] == 10
    assert traced[0]["source_label"] == "CVE CNA record"
    assert "source_label" not in traced[10]
    assert "source_label" not in traced[11]
    assert traced[11]["text"] == "Feed body 11."


def test_trace_failure_leaves_item_unchanged():
    item = {"label": "CVE-2023-20198",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-20198",
            "text": "CVE-2023-20198 \u2014 Cisco IOS XE\n\nFeed body.",
            "references": [CISCO_PUB_URL]}

    def boom(url):
        raise FetchError("HTTP 503")

    traced, stats = trace_items([item], fetcher=boom,
                                json_fetcher=boom)
    assert stats == {"traced": 0, "attempted": 1, "by_source": {}}
    assert traced[0] == item
    assert "source_label" not in traced[0]


def test_trace_item_without_cve_not_attempted():
    item = {"label": "notes.txt", "url": "", "text": "No CVE here."}

    def boom(url):
        raise AssertionError("no fetch expected")

    traced, stats = trace_items([item], fetcher=boom,
                                json_fetcher=boom)
    assert stats == {"traced": 0, "attempted": 0, "by_source": {}}
    assert traced[0] == item


# --------------------- Mock Mode (bundled fixtures) ------------------

def test_trace_mock_mode_fixtures():
    devices = parse_inventory(_sample_text("inventory_sample.txt"))
    feed = collect_feed_items(devices, mock=True)
    ordered = list(feed["kev"]["items"]) + list(feed["nvd"]["items"])
    traced, stats = trace_items(ordered, mock=True)
    assert stats["attempted"] == 6
    assert stats["traced"] == 3
    assert stats["by_source"] == {"Cisco CSAF": 1,
                                  "CVE CNA record": 2}
    by_label = {}
    for entry in traced:
        by_label.setdefault(entry["label"], []).append(entry)
    cisco = by_label["CVE-2023-20198"][0]
    assert cisco["source_label"] == "Cisco CSAF"
    assert "Cisco IOS XE Software 17.9.4" in cisco["text"]
    # The Juniper CVE resolves through the CNA fixture on both its
    # KEV and NVD items (the fixture JSA fetch honestly fails over).
    for entry in by_label["KEV CVE-2023-36844"] + by_label["CVE-2023-36844"]:
        assert entry["source_label"] == "CVE CNA record"
        assert "20.4R3-S9" in entry["text"]
    # CVEs with no fixture record stay untraced - nothing borrowed.
    assert "source_label" not in by_label["KEV CVE-2026-7473"][0]
    assert "source_label" not in by_label["CVE-2016-6894"][0]


# --------------------- runner passthrough ----------------------------

def test_run_batch_items_source_passthrough():
    inventory = _sample_text("inventory_sample.txt")
    items = [
        {"label": "traced.txt", "url": "https://vendor.example/a",
         "text": _sample_text("sample1_affected.txt"),
         "source_label": "Cisco CSAF",
         "source_url": "https://vendor.example/a"},
        {"label": "printer.txt", "url": "",
         "text": "Office printer firmware 2.0 release notes.",
         "source_label": "CVE CNA record",
         "source_url": "https://records.example/b"},
    ]
    results = run_batch_items(items, inventory, prefilter=True)
    assert results[0]["status"] == "ok"
    assert results[0]["source_label"] == "Cisco CSAF"
    assert results[0]["source_url"] == "https://vendor.example/a"
    # Provenance survives even a prefilter skip.
    assert results[1]["status"] == "skipped"
    assert results[1]["source_label"] == "CVE CNA record"
    assert results[1]["source_url"] == "https://records.example/b"
