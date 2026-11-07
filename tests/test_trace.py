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
    assert stats == {"traced": 1, "attempted": 1, "fallbacks": 0,
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
    assert stats == {"traced": 0, "attempted": 1, "fallbacks": 0,
                     "by_source": {}}
    assert traced[0] == item
    assert "source_label" not in traced[0]


def test_trace_item_without_cve_not_attempted():
    item = {"label": "notes.txt", "url": "", "text": "No CVE here."}

    def boom(url):
        raise AssertionError("no fetch expected")

    traced, stats = trace_items([item], fetcher=boom,
                                json_fetcher=boom)
    assert stats == {"traced": 0, "attempted": 0, "fallbacks": 0,
                     "by_source": {}}
    assert traced[0] == item


# --------------------- Mock Mode (bundled fixtures) ------------------

def test_trace_mock_mode_fixtures():
    devices = parse_inventory(_sample_text("inventory_sample.txt"))
    feed = collect_feed_items(devices, mock=True)
    # The shared merge makes the recent collection one item per
    # CVE (4 items, not 6): tracing attempts those 4.
    traced, stats = trace_items(list(feed["items"]), mock=True)
    assert stats["attempted"] == 4
    assert stats["traced"] == 2
    assert stats["by_source"] == {"Cisco CSAF": 1,
                                  "CVE CNA record": 1}
    by_label = {}
    for entry in traced:
        by_label.setdefault(entry["label"], []).append(entry)
    cisco = by_label["CVE-2023-20198"][0]
    assert cisco["source_label"] == "Cisco CSAF"
    assert "Cisco IOS XE Software 17.9.4" in cisco["text"]
    # The Juniper CVE resolves through the CNA fixture on its one
    # merged item (the fixture JSA fetch honestly fails over).
    juniper = by_label["CVE-2023-36844"][0]
    assert juniper["source_label"] == "CVE CNA record"
    assert "20.4R3-S9" in juniper["text"]
    # CVEs with no fixture record stay untraced - nothing borrowed.
    assert "source_label" not in by_label["KEV CVE-2026-7473"][0]
    assert "source_label" not in by_label["CVE-2016-6894"][0]


# ------------------------- traced ranges ----------------------------

def test_trace_cna_attaches_traced_ranges():
    payload = _cna_payload(
        "CVE-2023-36844", "Junos OS",
        [{"version": "0", "lessThan": "20.4R3-S9",
          "status": "affected"},
         {"version": "21.2", "lessThan": "21.2R3-S6",
          "status": "affected"},
         {"version": "22.1", "status": "unaffected"}],
        "J-Web vulnerability description.")

    def text_fetch(url):
        return "too short"

    def json_fetch(url):
        return payload

    traced, stats = trace_items([_juniper_item()], fetcher=text_fetch,
                                json_fetcher=json_fetch)
    ranges = traced[0]["traced_ranges"]
    # The CNA "0" sentinel means "from the beginning": no lower
    # bound. A bounded branch keeps both bounds. The unaffected
    # entry contributes nothing.
    assert ranges == [
        {"vendor": "Vendor", "product": "Junos OS", "exact": None,
         "start_including": None, "start_excluding": None,
         "end_including": None, "end_excluding": "20.4R3-S9"},
        {"vendor": "Vendor", "product": "Junos OS", "exact": None,
         "start_including": "21.2", "start_excluding": None,
         "end_including": None, "end_excluding": "21.2R3-S6"},
    ]


def test_trace_cna_fixture_ranges_via_mock():
    traced, stats = trace_items([_juniper_item()], mock=True)
    assert traced[0]["source_label"] == "CVE CNA record"
    ranges = traced[0]["traced_ranges"]
    by_end = {r["end_excluding"]: r for r in ranges
              if r["end_excluding"]}
    assert by_end["20.4R3-S9"]["start_including"] is None
    assert by_end["21.2R3-S6"]["start_including"] == "21.2"
    # A comma-listed lessThan ("22.4R2-S2, 22.4R3") keeps the
    # earliest fix bound.
    assert by_end["22.4R2-S2"]["start_including"] == "22.4"
    # The branch wildcard (lessThan "21.1*") degrades to a lower
    # bound only - it can hold a candidate, never clear one.
    branch = [r for r in ranges if r["start_including"] == "21.1"]
    assert len(branch) == 1
    assert branch[0]["end_excluding"] is None
    assert branch[0]["exact"] is None


def test_trace_cisco_csaf_attaches_traced_ranges():
    item = {"label": "CVE-2023-20198",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-20198",
            "text": "CVE-2023-20198 \u2014 Cisco IOS XE\n\nFeed body.",
            "references": [CISCO_PUB_URL]}
    fixture = _load_fixture("cisco_csaf_fixture.json")

    def text_fetch(url):
        raise FetchError("no page fetch expected")

    traced, stats = trace_items(
        [item], fetcher=text_fetch,
        json_fetcher=lambda url: fixture)
    ranges = traced[0]["traced_ranges"]
    # CSAF product_status enumerates affected product versions:
    # one exact-version range per affected product.
    assert sorted(r["exact"] for r in ranges) == [
        "17.6.1", "17.6.5", "17.9.1", "17.9.4"]
    for rng in ranges:
        assert rng["vendor"] == "Cisco"
        # The parsed product token feeds the same product-key
        # mapping the screening applies to CPE products.
        assert batch._cpe_product_key(
            rng["vendor"], rng["product"]) == "cisco ios xe"


def test_trace_jsa_genuine_but_boundless_attaches_no_ranges():
    page = "JSA72300 - J-Web vulnerability. " * 30  # > 400 chars

    def text_fetch(url):
        return page

    def json_fetch(url):
        raise AssertionError("CNA must not be fetched when JSA works")

    traced, stats = trace_items([_juniper_item()], fetcher=text_fetch,
                                json_fetcher=json_fetch)
    assert traced[0]["source_label"] == "Juniper JSA"
    # Page text carries no structure to parse into ranges.
    assert "traced_ranges" not in traced[0]


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


# --------------------- JSA genuine check + ranges -------------------

def test_trace_jsa_community_shell_falls_back_to_cna():
    shell = ("CEC Juniper Community - Welcome to the community. "
             "Navigation: Home Forums Knowledge Base Support. "
             * 40)  # ~2500 chars, no JSA id, no bound phrases
    assert len(shell) > 2000
    assert "JSA72300" not in shell
    payload = _load_fixture("cve_cna_fixture.json")

    def text_fetch(url):
        return shell

    def json_fetch(url):
        return payload

    traced, stats = trace_items([_juniper_item()], fetcher=text_fetch,
                                json_fetcher=json_fetch)
    out = traced[0]
    assert out["source_label"] == "CVE CNA record"
    assert out["traced_ranges"]
    assert "CEC Juniper Community" not in out["text"]
    assert stats["fallbacks"] >= 1


def test_jsa_is_genuine_cases():
    url = "https://supportportal.juniper.net/JSA72300"
    genuine = ("JSA72300 - Junos OS: J-Web vulnerability. "
               "Affected releases prior to 21.2R3.")
    assert batch._jsa_is_genuine(genuine, url) is True
    shell = "CEC Juniper Community - forums and knowledge base."
    assert batch._jsa_is_genuine(shell, url) is False
    # An id from a numeric article slug, with no advisory marker
    # anywhere in the body, is not genuine.
    slug_url = ("https://supportportal.juniper.net/s/article/"
                "Some-Advisory-72300")
    bare = "72300 - lorem ipsum dolor sit amet, consectetur."
    assert batch._jsa_is_genuine(bare, slug_url) is False


def test_jsa_traced_ranges_prior_to_branches():
    text = ("Junos OS: 21.2 versions prior to 21.2R3-S7;\n"
            "22.1 versions prior to 22.1R2;")
    ranges = batch._jsa_traced_ranges(text)
    assert len(ranges) == 2
    assert all(r["partial"] is True for r in ranges)
    assert ranges[0]["start_including"] == "21.2"
    assert ranges[0]["end_excluding"] == "21.2R3-S7"
    assert ranges[1]["start_including"] == "22.1"
    assert ranges[1]["end_excluding"] == "22.1R2"
    for rng in ranges:
        assert batch._cpe_product_key(
            rng["vendor"], rng["product"]) == "juniper junos"


def test_jsa_partial_range_hit_but_no_clear():
    from batch import screen_feed_items
    ranges = batch._jsa_traced_ranges(
        "Junos OS: 21.2 versions prior to 21.2R3-S7;\n"
        "22.1 versions prior to 22.1R2;")
    item = {"label": "CVE-2026-6001",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-6001",
            "text": "CVE-2026-6001 Junos OS advisory.",
            "published": "2026-06-01", "severity_rank": 3,
            "kev": False, "cpe_ranges": list(ranges)}
    # 21.3R3 sits in NO stated branch, but the ranges are
    # partial, so absence is not a clear: candidate, no local row.
    rows, candidates, stats = screen_feed_items(
        [dict(item)], "RTR-01, MX480, 21.3R3\n")
    assert rows == []
    assert [c["label"] for c in candidates] == ["CVE-2026-6001"]
    assert stats["uncertain_candidates"] == 1
    # 21.2R1 is inside branch 1 (a partial hit): still a
    # candidate driven by the hit, never a local row.
    rows, candidates, stats = screen_feed_items(
        [dict(item)], "RTR-01, MX480, 21.2R1\n")
    assert rows == []
    assert [c["label"] for c in candidates] == ["CVE-2026-6001"]
    assert stats["uncertain_candidates"] == 0


def test_trace_arista_challenge_falls_back_and_counts():
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

    def json_fetch(url):
        if "arista.com" in url:
            raise FetchError("challenge page (HTTP 200 HTML)",
                             status=200, content_type="text/html")
        return payload

    def text_fetch(url):
        raise FetchError("unused")

    traced, stats = trace_items([item], fetcher=text_fetch,
                                json_fetcher=json_fetch)
    out = traced[0]
    assert out["source_label"] == "CVE CNA record"
    assert stats["fallbacks"] >= 1
    assert "challenge" not in out["text"]
