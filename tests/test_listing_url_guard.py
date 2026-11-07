"""Listing URL presets + the un-harvestable vendor listing guard.

The Cisco / Juniper / Arista URL presets were removed from the
Listing source: those vendors' web listings are JavaScript-
rendered (Cisco PSIRT, Juniper) or bot-protected (Arista), so a
preset click could only end in a dead "no links found / blocked"
run. Only the bundled GitHub samples remain as a URL preset; the
structured vendor presets are the route for those vendors.

A hand-pasted URL for one of those same pages is guarded too:
app._unscrapable_listing_vendor recognizes it, the Run handler
skips the harvest entirely, and the UI renders the steering
notice (listing_unscrapable_notice) instead. The AppTest cases
prove the skip by spying on batch.harvest_links - app.py binds
the name from the batch module when AppTest execs it, so patching
the module attribute first is enough.

Offline: no API key is configured, so the app runs in Mock Mode.
Run: pytest -q
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest  # noqa: E402
from streamlit.testing.v1 import AppTest  # noqa: E402

import app  # noqa: E402
import batch  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
APP = str(ROOT / "app.py")

SAMPLES_URL = ("https://github.com/papilion/clocked-advisory-triage"
               "/tree/main/samples")
CISCO_URL = ("https://sec.cloudapps.cisco.com/security/center/"
             "publicationListing.x")
JUNIPER_URL = "https://supportportal.juniper.net/"
ARISTA_URL = ("https://www.arista.com/en/support/"
              "advisories-notices/security-advisories")


@pytest.fixture(autouse=True)
def _no_api_key(monkeypatch):
    # Deterministic Mock Mode regardless of the caller's environment.
    monkeypatch.delenv("CLOCKED_API_KEY", raising=False)


class _HarvestSpy(object):
    """Stand-in for batch.harvest_links recording its calls."""

    def __init__(self):
        self.calls = []

    def __call__(self, url, *args, **kwargs):
        self.calls.append(url)
        return {"status": "ok", "urls": [], "found": 0, "reason": ""}


# --------------------------- unit: presets -------------------------

def test_url_presets_only_samples():
    assert [key for key, _url in app.LISTING_PRESETS] == [
        "preset_samples"]
    assert app.LISTING_PRESETS[0][1] == SAMPLES_URL
    for lang in ("en", "ko"):
        assert set(app.STRINGS[lang]["preset_labels"]) == {
            "preset_samples"}


# --------------------------- unit: the guard -----------------------

@pytest.mark.parametrize("url,vendor", [
    (CISCO_URL, "cisco"),
    ("https://www.cisco.com/security/center/publicationListing.x",
     "cisco"),
    (JUNIPER_URL, "juniper"),
    ("https://supportportal.juniper.net/s/article/JSA-advisories",
     "juniper"),
    ("supportportal.juniper.net", "juniper"),  # scheme-less paste
    (ARISTA_URL, "arista"),
])
def test_guard_matches_vendor_listings(url, vendor):
    assert app._unscrapable_listing_vendor(url) == vendor


@pytest.mark.parametrize("url", [
    SAMPLES_URL,
    "https://vendor.example/advisories",
    "https://example.com/security/advisories",
    # Vendor home/product pages are not the advisory listings:
    # the harvest path for them is untouched by the guard.
    "https://www.arista.com/en/products/7050x3-series",
    "https://www.cisco.com/c/en/us/products/routers/index.html",
    "",
    "not a url",
])
def test_guard_ignores_other_urls(url):
    assert app._unscrapable_listing_vendor(url) is None


# --------------------------- AppTest -------------------------------

def _fresh_batch_app():
    at = AppTest.from_file(APP)
    at.run()
    assert not at.exception
    assert at.radio[0].value == "batch"
    assert at.radio[1].value == "listing"
    return at


def _click_run_batch(at):
    matches = [b for b in at.button
               if "Run Batch" in (b.label or "")
               or "배치 실행" in (b.label or "")]
    assert len(matches) == 1, "buttons: %r" % [b.label for b in at.button]
    matches[0].click().run()
    assert not at.exception


def test_app_url_preset_row_only_samples():
    at = _fresh_batch_app()
    labels = [b.label or "" for b in at.button]
    assert "Sample advisories (GitHub)" in labels
    assert "Cisco PSIRT" not in labels
    # The one remaining URL preset still fills the URL field.
    matches = [b for b in at.button
               if b.label == "Sample advisories (GitHub)"]
    assert len(matches) == 1
    matches[0].click().run()
    assert not at.exception
    assert at.session_state["listing_url"] == SAMPLES_URL


def test_app_guard_cisco_url_notice_no_harvest(monkeypatch):
    spy = _HarvestSpy()
    monkeypatch.setattr(batch, "harvest_links", spy)
    at = _fresh_batch_app()
    at.text_input[0].set_value(CISCO_URL).run()
    assert not at.exception
    _click_run_batch(at)
    assert spy.calls == []  # the dead harvest never happens
    assert at.session_state["listing_unscrapable"] == "cisco"
    assert at.session_state["harvest_info"] is None
    assert at.session_state["batch_results"] is None
    warnings = [w.value or "" for w in at.warning]
    assert any("cannot be collected directly" in w and "Cisco" in w
               and "vendor preset" in w for w in warnings), warnings


def test_app_guard_arista_url_notice_no_harvest(monkeypatch):
    spy = _HarvestSpy()
    monkeypatch.setattr(batch, "harvest_links", spy)
    at = _fresh_batch_app()
    at.text_input[0].set_value(ARISTA_URL).run()
    assert not at.exception
    _click_run_batch(at)
    assert spy.calls == []
    assert at.session_state["listing_unscrapable"] == "arista"
    assert at.session_state["harvest_info"] is None
    warnings = [w.value or "" for w in at.warning]
    assert any("cannot be collected directly" in w and "Arista" in w
               for w in warnings), warnings


def test_app_guard_juniper_url_notice_korean(monkeypatch):
    spy = _HarvestSpy()
    monkeypatch.setattr(batch, "harvest_links", spy)
    at = AppTest.from_file(APP)
    at.run()
    assert not at.exception
    at.selectbox[0].set_value("한국어").run()
    assert not at.exception
    at.text_input[0].set_value(JUNIPER_URL).run()
    assert not at.exception
    _click_run_batch(at)
    assert spy.calls == []
    assert at.session_state["listing_unscrapable"] == "juniper"
    warnings = [w.value or "" for w in at.warning]
    assert any("직접 수집할 수 없습니다" in w and "Juniper" in w
               for w in warnings), warnings


def test_app_normal_url_still_harvests(monkeypatch):
    spy = _HarvestSpy()
    monkeypatch.setattr(batch, "harvest_links", spy)
    at = _fresh_batch_app()
    at.text_input[0].set_value("https://vendor.example/advisories").run()
    assert not at.exception
    _click_run_batch(at)
    # The guard stays out of the way: the harvest runs exactly as
    # before and its outcome lands in session state.
    assert spy.calls == ["https://vendor.example/advisories"]
    assert at.session_state["listing_unscrapable"] is None
    assert at.session_state["harvest_info"]["status"] == "ok"
