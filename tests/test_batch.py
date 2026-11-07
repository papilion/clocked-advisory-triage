"""Offline tests for batch.py and the Batch mode UI.

No network: fetching is stubbed or monkeypatched, triage runs in
Mock Mode against the bundled samples.
Run: pytest -q
"""

import email.message
import sys
import urllib.error
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest  # noqa: E402

import batch  # noqa: E402
from batch import (  # noqa: E402
    MAX_LINKS,
    FetchError,
    fetch_advisory_text,
    html_to_text,
    parse_inventory_csv,
    parse_link_list,
    run_batch,
    run_batch_items,
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


# ------------------------- inventory CSV -----------------------------

def test_csv_utf8_bom_english_headers():
    data = (
        "﻿hostname,model,version,serial\n"
        "SW-1,Catalyst 9300,17.9.4,SN-1\n"
        "SW-2,Nexus 3064,7.0(3)I4(4),SN-2\n"
    ).encode("utf-8")
    text, meta = parse_inventory_csv(data)
    assert meta["encoding"] == "utf-8-sig"
    assert meta["header_mode"] == "header"
    assert meta["rows_total"] == 2
    assert meta["rows_used"] == 2
    assert meta["rows_skipped"] == 0
    devices = parse_inventory(text)
    assert devices[0] == {"hostname": "SW-1", "model": "Catalyst 9300",
                          "version": "17.9.4"}
    assert devices[1]["version"] == "7.0(3)I4(4)"  # serial column ignored


def test_csv_cp949_korean_headers_semicolon():
    rows = "장비명;모델;버전\n코어-01;Catalyst 9300;17.9.4\n"
    text, meta = parse_inventory_csv(rows.encode("cp949"))
    assert meta["encoding"] == "cp949"
    assert meta["header_mode"] == "header"
    assert meta["rows_used"] == 1
    devices = parse_inventory(text)
    assert devices[0]["hostname"] == "코어-01"
    assert devices[0]["model"] == "Catalyst 9300"


def test_csv_vendor_prefixing():
    rows = ("host,model,version,vendor\n"
            "SW-1,9300,17.9.4,Cisco\n"
            "SW-2,Cisco Catalyst 9300,17.9.4,Cisco\n")
    text, meta = parse_inventory_csv(rows.encode("utf-8"))
    assert meta["rows_used"] == 2
    devices = parse_inventory(text)
    assert devices[0]["model"] == "Cisco 9300"               # prefixed
    assert devices[1]["model"] == "Cisco Catalyst 9300"      # not doubled


def test_csv_skips_incomplete_rows():
    rows = ("hostname,model,version\n"
            "SW-1,Catalyst 9300,17.9.4\n"
            "SW-2,,17.9.4\n"
            ",Nexus 3064,7.0(3)I4(4)\n"
            "SW-3,QFX5110,\n"
            "\n")
    text, meta = parse_inventory_csv(rows.encode("utf-8"))
    assert meta["rows_total"] == 4
    assert meta["rows_used"] == 1
    assert meta["rows_skipped"] == 3
    assert text == "SW-1, Catalyst 9300, 17.9.4"


def test_csv_positional_fallback_tab_delimited():
    data = b"A\tNexus 3064\t7.0(3)I4(4)\nB\tQFX5110\t21.2R3\n"
    text, meta = parse_inventory_csv(data)
    assert meta["header_mode"] == "positional"
    assert meta["rows_used"] == 2
    devices = parse_inventory(text)
    assert devices[1] == {"hostname": "B", "model": "QFX5110",
                          "version": "21.2R3"}


def test_csv_os_alias_and_extra_columns():
    rows = ("Device Name,OS Version,Model,IP Address,Region\n"
            "R-1,21.2R3,QFX5110,192.0.2.1,Seoul\n")
    text, meta = parse_inventory_csv(rows.encode("utf-8"))
    assert meta["header_mode"] == "header"
    devices = parse_inventory(text)
    assert devices[0] == {"hostname": "R-1", "model": "QFX5110",
                          "version": "21.2R3"}


def test_csv_empty_input():
    text, meta = parse_inventory_csv(b"")
    assert text == ""
    assert meta["rows_total"] == 0
    assert meta["rows_used"] == 0


# ------------------------- link list ---------------------------------

def test_parse_link_list_dedupes_and_skips_comments():
    text = ("# a comment\n"
            "\n"
            "https://vendor.example/a1\n"
            "  https://vendor.example/a2  \n"
            "https://vendor.example/a1\n"
            "not a url\n"
            "ftp://vendor.example/a3\n")
    urls, skipped = parse_link_list(text)
    assert urls == ["https://vendor.example/a1",
                    "https://vendor.example/a2"]
    assert skipped == 0


def test_parse_link_list_cap():
    text = "\n".join("https://vendor.example/a%d" % i for i in range(13))
    urls, skipped = parse_link_list(text)
    assert len(urls) == MAX_LINKS
    assert skipped == 3
    assert urls[0] == "https://vendor.example/a0"


# ------------------------- html -> text ------------------------------

def test_html_to_text_strips_script_style_nav():
    html = (
        "<html><head><title>T</title><style>.x{color:red}</style>"
        "<script>var secret = 1;</script></head><body>"
        "<nav>Home | Products | Support</nav>"
        "<h1>Security Advisory 2026-001</h1>"
        "<p>Affected versions: 17.9.1 &amp; earlier.</p>"
        "<p>Upgrade to 17.9.6.</p>"
        "<footer>copyright</footer></body></html>"
    )
    text = html_to_text(html)
    assert "Security Advisory 2026-001" in text
    assert "Affected versions: 17.9.1 & earlier." in text
    assert "Upgrade to 17.9.6." in text
    assert "var secret" not in text
    assert "color:red" not in text
    assert "Home | Products" not in text
    assert "copyright" not in text


# ------------------------- fetching (monkeypatched, offline) ---------

class _FakeResponse:
    def __init__(self, body, content_type="text/plain"):
        # type: (bytes, str) -> None
        self._body = body
        self.headers = email.message.Message()
        self.headers["Content-Type"] = content_type

    def read(self, size=-1):
        # type: (int) -> bytes
        if size is None or size < 0:
            return self._body
        return self._body[:size]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_fetch_plain_text_passthrough(monkeypatch):
    body = "Advisory text\nsecond line\n".encode("utf-8")
    monkeypatch.setattr(
        batch.urllib.request, "urlopen",
        lambda req, timeout=None: _FakeResponse(body))
    text = fetch_advisory_text("https://vendor.example/a.txt")
    assert text == "Advisory text\nsecond line"


def test_fetch_html_converted(monkeypatch):
    body = ("<html><body><nav>menu</nav>"
            "<p>Hello advisory</p></body></html>").encode("utf-8")
    monkeypatch.setattr(
        batch.urllib.request, "urlopen",
        lambda req, timeout=None: _FakeResponse(
            body, "text/html; charset=utf-8"))
    text = fetch_advisory_text("https://vendor.example/a")
    assert text == "Hello advisory"


def test_fetch_http_error_raises_fetch_error(monkeypatch):
    def _boom(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, 404, "Not Found",
                                     None, None)
    monkeypatch.setattr(batch.urllib.request, "urlopen", _boom)
    with pytest.raises(FetchError) as excinfo:
        fetch_advisory_text("https://vendor.example/missing")
    assert "404" in str(excinfo.value)


def test_fetch_empty_body_raises_fetch_error(monkeypatch):
    monkeypatch.setattr(
        batch.urllib.request, "urlopen",
        lambda req, timeout=None: _FakeResponse(b""))
    with pytest.raises(FetchError):
        fetch_advisory_text("https://vendor.example/empty")


# ------------------------- batch runner ------------------------------

_SAMPLE_BY_NAME = {
    "sample1_affected.txt": "sample1_affected.txt",
    "sample4_arista_affected.txt": "sample4_arista_affected.txt",
    "sample7_arista_conditional.txt": "sample7_arista_conditional.txt",
}


def _stub_fetcher(url):
    # type: (str) -> str
    name = url.rsplit("/", 1)[-1]
    if name not in _SAMPLE_BY_NAME:
        raise FetchError("HTTP 404")
    return _sample_text(_SAMPLE_BY_NAME[name])


def test_run_batch_mock_verdicts_and_failure_isolation():
    inventory = _sample_text("inventory_sample.txt")
    links = [
        "https://raw.example/samples/sample1_affected.txt",
        "https://raw.example/samples/missing.txt",
        "https://raw.example/samples/sample4_arista_affected.txt",
        "https://raw.example/samples/sample7_arista_conditional.txt",
    ]
    progress_calls = []
    results = run_batch(
        links, inventory, fetcher=_stub_fetcher,
        progress=lambda i, total, url: progress_calls.append((i, total)))

    assert [r["status"] for r in results] == [
        "ok", "fetch_failed", "ok", "ok"]
    assert results[1]["error"] == "HTTP 404"
    assert results[0]["triage"]["verdict"] == "AFFECTED"
    assert results[2]["triage"]["verdict"] == "AFFECTED"
    assert results[3]["triage"]["verdict"] == "CANNOT DETERMINE"
    # The conditional sample's gate surfaces through the batch too.
    assert results[3]["triage"]["conditions"]
    assert len(progress_calls) == 4
    assert progress_calls[0] == (0, 4)


def test_run_batch_korean_verdicts_stay_english_constants():
    inventory = _sample_text("inventory_sample.txt")
    results = run_batch(
        ["https://raw.example/samples/sample1_affected.txt"],
        inventory, lang="ko", fetcher=_stub_fetcher)
    assert results[0]["triage"]["verdict"] == "AFFECTED"
    # Reasons are localized even though the verdict constant is not.
    reasons = " ".join(d["reason"]
                       for d in results[0]["triage"]["device_results"])
    assert "영향받는 버전" in reasons


# --------------------- credit exhaustion -----------------------
# When the Clocked balance dies mid-batch, run_triage returns a
# verdict-less result flagged credit_exhausted (or, off the
# run_triage path, raises the credit exception). The batch must
# fail fast: no further triage calls, unjudged items become
# localized credit error rows - never verdicts - and verdicts
# already earned are kept.

_CREDIT_RESULT = {
    "mode": "live",
    "credit_exhausted": True,
    "error": ("Clocked API 402: Your credit allowance or "
              "spending limit has been reached."),
    "verdict": None,
    "devices": [],
}

_THREE_ITEMS = [
    {"label": "CVE-0001", "url": "", "text": "Advisory one text."},
    {"label": "CVE-0002", "url": "", "text": "Advisory two text."},
    {"label": "CVE-0003", "url": "", "text": "Advisory three text."},
]


def test_run_batch_items_credit_result_fails_fast(monkeypatch):
    calls = []

    def fake_triage(text, devices_text, api_key=None, lang="en", mock=False):
        calls.append(text)
        return dict(_CREDIT_RESULT)

    monkeypatch.setattr(batch, "run_triage", fake_triage)
    results = run_batch_items(_THREE_ITEMS, "inventory text")
    # One triage call total: after the first credit result the
    # remaining items are short-circuited, not judged.
    assert len(calls) == 1
    assert [r["status"] for r in results] == ["error"] * 3
    assert all(r["credit_exhausted"] is True for r in results)
    assert all("credits exhausted" in r["error"] for r in results)
    # No entry can be mistaken for a judgment.
    assert all("triage" not in r for r in results)
    assert [r["label"] for r in results] == [
        "CVE-0001", "CVE-0002", "CVE-0003"]


def test_run_batch_items_credit_exception_fails_fast(monkeypatch):
    class InsufficientCreditsError(Exception):
        pass

    calls = []

    def fake_triage(text, devices_text, api_key=None, lang="en", mock=False):
        calls.append(text)
        raise InsufficientCreditsError("402")

    monkeypatch.setattr(batch, "run_triage", fake_triage)
    results = run_batch_items(_THREE_ITEMS, "inventory text")
    assert len(calls) == 1
    assert [r["status"] for r in results] == ["error"] * 3
    assert all(r["credit_exhausted"] is True for r in results)


def test_run_batch_items_keeps_verdicts_before_credit_error(
        monkeypatch):
    outcomes = iter([
        {"mode": "live", "verdict": "NOT AFFECTED", "devices": []},
        dict(_CREDIT_RESULT),
    ])
    calls = []

    def fake_triage(text, devices_text, api_key=None, lang="en", mock=False):
        calls.append(text)
        return next(outcomes)

    monkeypatch.setattr(batch, "run_triage", fake_triage)
    results = run_batch_items(_THREE_ITEMS, "inventory text")
    assert len(calls) == 2
    assert results[0]["status"] == "ok"
    assert results[0]["triage"]["verdict"] == "NOT AFFECTED"
    assert results[1]["credit_exhausted"] is True
    assert results[2]["credit_exhausted"] is True
    assert "triage" not in results[2]


def test_run_batch_items_credit_message_is_localized(monkeypatch):
    def fake_triage(text, devices_text, api_key=None, lang="en", mock=False):
        return dict(_CREDIT_RESULT)

    monkeypatch.setattr(batch, "run_triage", fake_triage)
    results = run_batch_items(_THREE_ITEMS[:1], "inventory text",
                              lang="ko")
    assert "크레딧이 소진" in results[0]["error"]


def test_run_batch_credit_exhaustion_fails_fast(monkeypatch):
    calls = []

    def fake_triage(text, devices_text, api_key=None, lang="en", mock=False):
        calls.append(text)
        return dict(_CREDIT_RESULT)

    monkeypatch.setattr(batch, "run_triage", fake_triage)
    links = ["https://raw.example/samples/sample1_affected.txt",
             "https://raw.example/samples/sample4_arista_affected.txt",
             "https://raw.example/samples/sample7_arista_conditional.txt"]
    results = run_batch(links, _sample_text("inventory_sample.txt"),
                        fetcher=_stub_fetcher)
    assert len(calls) == 1
    assert [r["status"] for r in results] == ["error"] * 3
    assert all(r["credit_exhausted"] is True for r in results)


# --------------------- demo override (mock) ----------------------
# The app's Demo override threads mock=True into the runners:
# judging must stay in Mock Mode (canned verdicts, no Clocked
# calls) even when an API key is configured in the environment.

def test_run_batch_items_mock_override_beats_configured_key(
        monkeypatch):
    monkeypatch.setenv("CLOCKED_API_KEY", "test-key-not-a-real-secret")
    items = [{"label": "SAMPLE-1", "url": "",
              "text": _sample_text("sample1_affected.txt")}]
    results = run_batch_items(
        items, _sample_text("inventory_sample.txt"), mock=True)
    assert results[0]["status"] == "ok"
    assert results[0]["triage"]["mode"] == "mock"
    assert results[0]["triage"]["verdict"] == "AFFECTED"


def test_run_batch_mock_override_beats_configured_key(monkeypatch):
    monkeypatch.setenv("CLOCKED_API_KEY", "test-key-not-a-real-secret")
    links = ["https://raw.example/samples/sample1_affected.txt"]
    results = run_batch(links, _sample_text("inventory_sample.txt"),
                        fetcher=_stub_fetcher, mock=True)
    assert results[0]["status"] == "ok"
    assert results[0]["triage"]["mode"] == "mock"
    assert results[0]["triage"]["verdict"] == "AFFECTED"


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


def test_batch_mode_is_default_and_renders():
    at = _fresh_batch_app()
    assert at.radio[0].value == "batch"


def test_batch_credit_exhausted_shows_banner():
    # A credit-exhausted run's results carry flagged error
    # entries; the results area must lead with the Demo-mode
    # banner, in the exact prescribed wording.
    at = _fresh_batch_app()
    at.session_state["batch_results"] = [{
        "url": "", "label": "CVE-0001", "status": "error",
        "error": "Not judged - Clocked API credits exhausted.",
        "credit_exhausted": True,
    }]
    at.run()
    assert not at.exception
    warnings = [w.value or "" for w in at.warning]
    assert any(
        w == ("Clocked API credits exhausted — Live judging is "
              "unavailable right now. Switch to Demo mode to "
              "explore the seven bundled sample advisories (all "
              "verdict types, no API calls).")
        for w in warnings), warnings
    labels = [b.label or "" for b in at.button]
    # Default source is the listing page: vendor presets show
    # (the sample-link button lives in Link list source mode).
    assert any("Sample advisories (GitHub)" in label for label in labels)
    assert any("Run Batch" in label for label in labels)
    # Listing source by default: a URL text input, no links text
    # area (that appears in Link list source mode).
    assert len(at.text_area) == 0
    assert len(at.text_input) == 1
    assert at.text_input[0].value == ""


def _switch_source_to_links(at):
    # Radio order: [0] is the top mode switch, [1] the batch
    # source switch (listing is the default source).
    at.radio[1].set_value("links").run()
    assert not at.exception


def test_sample_links_button_fills_links_area():
    at = _fresh_batch_app()
    _switch_source_to_links(at)
    _click_button(at, "Load sample link list")
    lines = [ln for ln in at.text_area[0].value.splitlines() if ln.strip()]
    assert len(lines) == 7
    base = ("https://raw.githubusercontent.com/papilion/"
            "clocked-advisory-triage/main/samples/")
    assert lines[0] == base + "sample1_affected.txt"
    assert lines[3] == base + "sample4_arista_affected.txt"
    assert lines[6] == base + "sample7_arista_conditional.txt"


def test_run_batch_with_no_links_shows_notice():
    at = _fresh_batch_app()
    _switch_source_to_links(at)
    _click_button(at, "Run Batch")
    warnings = [w.value or "" for w in at.warning]
    assert any("at least one advisory link" in w for w in warnings), warnings
    assert at.session_state["batch_results"] is None


def test_batch_mode_korean_renders():
    at = _fresh_batch_app()
    at.selectbox[0].set_value("한국어").run()
    assert not at.exception
    assert at.session_state["lang"] == "ko"
    labels = [b.label or "" for b in at.button]
    assert any("샘플 권고 (GitHub)" in label for label in labels), labels
    assert any("배치 실행" in label for label in labels), labels
    _switch_source_to_links(at)
    _click_button(at, "샘플 링크 목록 불러오기")
    assert len([ln for ln in at.text_area[0].value.splitlines()
                if ln.strip()]) == 7
