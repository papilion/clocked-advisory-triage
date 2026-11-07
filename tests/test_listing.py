"""Listing harvester, relevance prefilter, workarounds field, and
action composition (scope change: listing-first batch flow).

No network: harvest_links takes an injectable html_fetcher and
run_batch an injectable text fetcher; every fixture is inline.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from batch import (HARVEST_CAP, FetchError, build_relevance_tokens,
                   harvest_links, is_relevant, run_batch)  # noqa: E402
from triage import run_triage  # noqa: E402

SAMPLE_INVENTORY = (ROOT / "samples" / "inventory_sample.txt").read_text(encoding="utf-8")

from streamlit.testing.v1 import AppTest  # noqa: E402

CISCO_LISTING_URL = ("https://sec.cloudapps.cisco.com/security/"
                     "center/publicationListing.x")

LISTING_HTML = """
<html><head><title>Security Advisories</title></head><body>
<a href="/security/center/content/CiscoSecurityAdvisory/cisco-sa-2026-aaa">
  Cisco Security Advisory</a>
<a href="https://sec.cloudapps.cisco.com/security/center/viewAlert.x?id=7">
  Read the advisory</a>
<a href="/security/center/content/CiscoSecurityAdvisory/cisco-sa-2026-aaa">
  duplicate</a>
<a href="https://www.cisco.com/c/en/us/support/index.html">Support</a>
<a href="https://evil.example.com/security/advisory/9">off domain</a>
<a href="/c/en/us/about/legal.html">Legal</a>
</body></html>
"""

GITHUB_TREE_URL = ("https://github.com/papilion/clocked-advisory-triage/"
                   "tree/main/samples")

GITHUB_TREE_HTML = """
<html><body>
<a href="/papilion/clocked-advisory-triage/blob/main/samples/sample1_affected.txt">sample1_affected.txt</a>
<a href="/papilion/clocked-advisory-triage/blob/main/samples/sample7_arista_conditional.txt">sample7_arista_conditional.txt</a>
<a href="/papilion/clocked-advisory-triage/blob/main/samples/inventory_sample.txt">inventory_sample.txt</a>
<a href="/papilion/clocked-advisory-triage/blob/main/README.md">README.md</a>
<a href="/papilion/clocked-advisory-triage/tree/main/samples">samples</a>
</body></html>
"""

CHALLENGE_HTML = """
<html><head><title>Client Challenge</title></head>
<body><script src="https://challenges.cloudflare.com/turnstile.js">
</script><p>Checking your browser...</p></body></html>
"""

JS_SHELL_HTML = """
<html><head><title>Support Portal</title></head>
<body><div id="root"></div><script src="/static/app.js"></script>
</body></html>
"""


def _fetcher(html, final_url=None):
    def fetch(url):
        return html, final_url or url
    return fetch


# ----- harvester ---------------------------------------------------

def test_harvest_listing_filters_dedupes_and_domains():
    info = harvest_links(CISCO_LISTING_URL, html_fetcher=_fetcher(LISTING_HTML))
    assert info["status"] == "ok"
    assert info["found"] == 2
    assert info["urls"] == [
        ("https://sec.cloudapps.cisco.com/security/center/content/"
         "CiscoSecurityAdvisory/cisco-sa-2026-aaa"),
        "https://sec.cloudapps.cisco.com/security/center/viewAlert.x?id=7",
    ]


def test_harvest_github_tree_resolves_raw_urls():
    info = harvest_links(GITHUB_TREE_URL,
                         html_fetcher=_fetcher(GITHUB_TREE_HTML))
    assert info["status"] == "ok"
    base = ("https://raw.githubusercontent.com/papilion/"
            "clocked-advisory-triage/main/samples/")
    # Sample advisory files only: the inventory file and README are
    # not advisories even though the repo name contains "advisory".
    assert info["urls"] == [base + "sample1_affected.txt",
                            base + "sample7_arista_conditional.txt"]


def test_harvest_skips_self_links():
    html = ('<html><body>'
            '<a href="/security/center/publicationListing.x">'
            'Security Advisories</a>'
            '<a href="/security/advisory/real-1">real advisory</a>'
            '</body></html>')
    info = harvest_links(CISCO_LISTING_URL, html_fetcher=_fetcher(html))
    assert info["status"] == "ok"
    assert info["urls"] == [
        "https://sec.cloudapps.cisco.com/security/advisory/real-1"]


def test_harvest_challenge_page_is_blocked():
    info = harvest_links("https://vendor.example/list",
                         html_fetcher=_fetcher(CHALLENGE_HTML))
    assert info["status"] == "blocked"
    assert info["urls"] == []


def test_harvest_js_shell_is_empty():
    info = harvest_links("https://vendor.example/portal",
                         html_fetcher=_fetcher(JS_SHELL_HTML))
    assert info["status"] == "empty"
    assert info["urls"] == []


def test_harvest_fetch_failure():
    def failing(url):
        raise FetchError("HTTP 403")
    info = harvest_links("https://vendor.example/list",
                         html_fetcher=failing)
    assert info["status"] == "fetch_failed"
    assert "HTTP 403" in info["reason"]


def test_harvest_cap():
    anchors = "\n".join(
        '<a href="/security/advisory/item-%02d">advisory %02d</a>'
        % (i, i) for i in range(20))
    html = "<html><body>%s</body></html>" % anchors
    info = harvest_links("https://vendor.example/list",
                         html_fetcher=_fetcher(html))
    assert info["status"] == "ok"
    assert info["found"] == 20
    assert len(info["urls"]) == HARVEST_CAP == 15


# ----- relevance prefilter ------------------------------------------

IRRELEVANT_TEXT = ("Acme OfficeJet Printer Firmware Advisory\n"
                   "A firmware update for office inkjet printers "
                   "improves photo printing quality.")


def _sample_devices():
    from triage import parse_inventory
    return parse_inventory(SAMPLE_INVENTORY)


def test_prefilter_tokens_and_matching():
    tokens = build_relevance_tokens(_sample_devices())
    # Inventory-derived: model cores and words are represented.
    assert "catalyst9300" in tokens
    assert "catalyst" in tokens
    assert "7050sx3" in tokens
    # Generic vendor/network terms are always present.
    assert "juniper" in tokens and "switch" in tokens
    assert is_relevant("Cisco Catalyst 9300 / IOS XE advisory", tokens)
    assert is_relevant("Arista EOS release note", tokens)
    assert not is_relevant(IRRELEVANT_TEXT, tokens)
    # Word boundaries: "eos" inside "videos" must not hit.
    assert not is_relevant("Watch our videos about phones", tokens)


def _sample_texts():
    samples = {}
    for path in sorted((ROOT / "samples").glob("sample*.txt")):
        samples[path.name] = path.read_text(encoding="utf-8")
    return samples


def test_run_batch_prefilter_skips_irrelevant_without_triage():
    texts = _sample_texts()
    mapping = {
        "u-cisco": texts["sample1_affected.txt"],
        "u-printer": IRRELEVANT_TEXT,
        "u-arista": texts["sample4_arista_affected.txt"],
    }
    results = run_batch(list(mapping), SAMPLE_INVENTORY,
                        fetcher=mapping.get, prefilter=True)
    by_url = {r["url"]: r for r in results}
    assert by_url["u-cisco"]["status"] == "ok"
    assert by_url["u-cisco"]["triage"]["verdict"] == "AFFECTED"
    assert by_url["u-arista"]["triage"]["verdict"] == "AFFECTED"
    skipped = by_url["u-printer"]
    assert skipped["status"] == "skipped"
    assert skipped["skip_reason"] == "not_relevant"
    assert "triage" not in skipped  # no Clocked calls spent


def test_run_batch_without_prefilter_judges_everything():
    texts = _sample_texts()
    mapping = {"u-printer": IRRELEVANT_TEXT}
    results = run_batch(list(mapping), SAMPLE_INVENTORY,
                        fetcher=mapping.get, prefilter=False)
    assert results[0]["status"] == "ok"  # triaged, not skipped
    assert "triage" in results[0]


# ----- workarounds field ---------------------------------------------

def test_mock_sample7_carries_workaround():
    result = run_triage(_sample_texts()["sample7_arista_conditional.txt"],
                        SAMPLE_INVENTORY)
    workarounds = result["extracted"].get("workarounds") or []
    assert any("Restrict management-plane access" in w
               for w in workarounds)


def test_live_extract_merges_focused_workarounds():
    import triage
    from triage import _live_extract

    condition = {"value": [], "items": [], "confidence": 1.0}
    workaround_field = {
        "value": ["Disable the affected service until patched."],
        "items": [{"value": "Disable the affected service until patched.",
                   "confidence": 0.9}],
        "confidence": 0.9}

    class StubClient(object):
        def extract(self, **kwargs):
            fields = kwargs.get("fields") or {}
            if set(fields) == {"applicability_conditions", "workarounds"}:
                return {"fields": {
                    "applicability_conditions": condition,
                    "workarounds": workaround_field}}
            return {"fields": {"products": {"value": ["Acme 1"]}}}

    plain, raw = _live_extract(StubClient(), "any advisory text")
    assert plain["workarounds"] == [
        "Disable the affected service until patched."]
    normalized = triage.normalize_extraction(plain, raw)
    assert normalized["workarounds"] == [
        "Disable the affected service until patched."]


def test_normalize_workarounds_tolerates_shapes():
    import triage
    out = triage.normalize_extraction({"workarounds": "Single string"})
    assert out["workarounds"] == ["Single string"]
    out = triage.normalize_extraction(
        {"workarounds": [{"value": "wrapped"}, "", "  "]})
    assert out["workarounds"] == ["wrapped"]
    out = triage.normalize_extraction({})
    assert out["workarounds"] == []


# ----- action composition ---------------------------------------------

def _fake_result(verdict, **overrides):
    result = {
        "verdict": verdict,
        "extracted": {},
        "device_results": [],
        "conditions": [],
        "checklist": [],
    }
    result.update(overrides)
    return result


def test_action_lines_affected():
    import app
    s = app.STRINGS["en"]
    result = _fake_result(
        "AFFECTED",
        extracted={"fixed_version": "EOS 4.30.6M or later",
                   "action_deadline": "2026-12-10",
                   "workarounds": ["Restrict management-plane access."]},
        device_results=[{"hostname": "DC-SW-01", "status": "AFFECTED"},
                        {"hostname": "CORE-1", "status": "NOT AFFECTED"}])
    lines = app._action_lines(result, s, "en")
    joined = "\n".join(lines)
    assert "DC-SW-01" in joined and "CORE-1" not in joined
    assert "Upgrade to EOS 4.30.6M or later" in joined
    assert "Deadline: 2026-12-10" in joined
    assert "Restrict management-plane access." in joined
    one_liner = app._action_one_liner(result, s, "en")
    assert one_liner.startswith("DC-SW-01:")


def test_action_lines_cannot_determine_and_not_affected():
    import app
    s = app.STRINGS["ko"]
    cannot = _fake_result(
        "CANNOT DETERMINE",
        conditions=["TerminAttr가 CVP와 통신하도록 구성됨"],
        checklist=["show running-config | include TerminAttr",
                   "두 번째 항목", "세 번째 항목"],
        extracted={"workarounds": ["신뢰 네트워크로 제한"]})
    joined = "\n".join(app._action_lines(cannot, s, "ko"))
    assert "판정 전에 확인할 것" in joined
    assert "TerminAttr가 CVP와 통신하도록 구성됨" in joined
    assert "신뢰 네트워크로 제한" in joined
    none = _fake_result("NOT AFFECTED")
    assert app._action_lines(none, s, "ko") == ["조치가 필요 없습니다."]


# ----- AppTest: source switch and presets ------------------------------

def _fresh_batch_app():
    at = AppTest.from_file(str(ROOT / "app.py"))
    at.secrets["CLOCKED_API_KEY"] = "test-key-not-a-real-secret"
    at.run()
    assert not at.exception
    return at


def test_batch_defaults_to_listing_source_with_presets():
    at = _fresh_batch_app()
    assert at.radio[1].value == "listing"
    button_labels = [b.label for b in at.button]
    assert "Sample advisories (GitHub)" in button_labels
    assert "Cisco PSIRT" in button_labels


def test_preset_button_fills_listing_url():
    at = _fresh_batch_app()
    for button in at.button:
        if button.label == "Sample advisories (GitHub)":
            button.click().run()
            break
    assert not at.exception
    assert at.text_input[0].value == GITHUB_TREE_URL
