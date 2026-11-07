"""AppTest coverage for app.py widget-state behavior.

Guards two UI regressions:
- Sample / Clear buttons must actually fill the key-bound text areas
  (the canonical on_click callback pattern).
- Run with an empty advisory must show a friendly notice instead of
  letting an SDK ValidationError traceback reach the page.

Offline: no API key is configured, so the app runs in Mock Mode and
no sample Run is performed here (button state only).
Run: pytest -q
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest  # noqa: E402
from streamlit.testing.v1 import AppTest  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
APP = str(ROOT / "app.py")


@pytest.fixture(autouse=True)
def _no_api_key(monkeypatch):
    # Deterministic Mock Mode regardless of the caller's environment.
    monkeypatch.delenv("CLOCKED_API_KEY", raising=False)


def _sample_text(filename):
    # type: (str) -> str
    return (ROOT / "samples" / filename).read_text(encoding="utf-8")


def _fresh_app():
    # The app now opens in Batch mode by default; these regression
    # tests cover the Paste mode, so switch the mode radio first.
    # All assertions below are unchanged.
    at = AppTest.from_file(APP)
    at.run()
    assert not at.exception
    assert at.radio[0].value == "batch"
    at.radio[0].set_value("paste").run()
    assert not at.exception
    return at


def _click_button(at, label_part):
    """Click the (single) button whose label contains label_part."""
    matches = [b for b in at.button if label_part in (b.label or "")]
    assert len(matches) == 1, "buttons: %r" % [b.label for b in at.button]
    matches[0].click().run()
    assert not at.exception


def test_sample1_button_fills_text_areas():
    at = _fresh_app()
    # Defaults: advisory empty, inventory prefilled with the bundle.
    assert at.text_area[0].value == ""
    assert at.text_area[1].value == _sample_text("inventory_sample.txt")

    _click_button(at, "Sample 1")
    assert at.text_area[0].value == _sample_text("sample1_affected.txt")
    assert at.text_area[1].value == _sample_text("inventory_sample.txt")


def test_sample7_button_fills_advisory():
    at = _fresh_app()
    _click_button(at, "Sample 7")
    assert at.text_area[0].value == _sample_text(
        "sample7_arista_conditional.txt")
    assert at.text_area[1].value == _sample_text("inventory_sample.txt")


def test_clear_after_sample_empties_advisory():
    at = _fresh_app()
    _click_button(at, "Sample 1")
    assert at.text_area[0].value != ""

    _click_button(at, "Clear")
    assert at.text_area[0].value == ""
    # Clear restores the bundled default inventory.
    assert at.text_area[1].value == _sample_text("inventory_sample.txt")


def test_run_with_empty_advisory_shows_notice():
    at = _fresh_app()
    assert at.text_area[0].value == ""

    _click_button(at, "Run Triage")
    assert not at.exception
    warnings = [w.value or "" for w in at.warning]
    assert any("Paste an advisory first" in w for w in warnings), warnings
    # No verdict result was produced by the blocked run.
    assert at.session_state["result"] is None


_CREDIT_RESULT_STATE = {
    "mode": "live",
    "credit_exhausted": True,
    "error": ("Clocked API 402: Your credit allowance or "
              "spending limit has been reached."),
    "verdict": None,
    "devices": [],
}


def test_paste_credit_exhausted_shows_banner():
    # A credit-exhausted single run renders the Demo-mode banner
    # (exact prescribed wording), not a verdict or a raw error.
    at = _fresh_app()
    at.session_state["result"] = dict(_CREDIT_RESULT_STATE)
    at.run()
    assert not at.exception
    warnings = [w.value or "" for w in at.warning]
    assert any(
        w == ("Clocked API credits exhausted — Live judging is "
              "unavailable right now. Switch to Demo mode to "
              "explore the seven bundled sample advisories (all "
              "verdict types, no API calls).")
        for w in warnings), warnings


# --------------------- demo override ------------------------------
# The Demo override checkbox (under the mode banner) forces Mock
# Mode even when an API key is configured - without it, a deployed
# app whose key lives in secrets could never reach Demo mode, and
# the credit-exhaustion banner's "switch to Demo mode" advice
# would be unactionable.


def _fresh_app_with_key():
    at = AppTest.from_file(APP)
    at.secrets["CLOCKED_API_KEY"] = "test-key-not-a-real-secret"
    at.run()
    assert not at.exception
    return at


def _demo_checkbox(at):
    matches = [c for c in at.checkbox
               if "Demo mode" in (c.label or "")]
    assert len(matches) == 1, "checkboxes: %r" % [
        c.label for c in at.checkbox]
    return matches[0]


def test_demo_override_defaults_on_without_key():
    at = AppTest.from_file(APP)
    at.run()
    assert not at.exception
    # No key: Demo is the only possible mode, so the override
    # defaults on and the MOCK banner renders as before.
    assert at.session_state["demo_override"] is True
    assert _demo_checkbox(at).value is True
    warnings = [w.value or "" for w in at.warning]
    assert any("Mode: MOCK" in w for w in warnings), warnings


def test_demo_override_defaults_off_with_key():
    at = _fresh_app_with_key()
    assert at.session_state["demo_override"] is False
    assert _demo_checkbox(at).value is False
    successes = [s.value or "" for s in at.success]
    assert any("Mode: LIVE" in s for s in successes), successes


def test_demo_override_on_with_key_sample_run_is_mock():
    at = _fresh_app_with_key()
    _demo_checkbox(at).set_value(True).run()
    assert not at.exception
    # The banner flips from LIVE to the Demo state.
    warnings = [w.value or "" for w in at.warning]
    assert any("Mode: DEMO" in w for w in warnings), warnings
    assert not any("Mode: LIVE" in (s.value or "")
                   for s in at.success)
    # A bundled sample now runs on canned responses even though
    # a (fake) key is configured: mock verdict, no API call.
    at.radio[0].set_value("paste").run()
    assert not at.exception
    _click_button(at, "Sample 1")
    _click_button(at, "Run Triage")
    result = at.session_state["result"]
    assert result["mode"] == "mock"
    assert result["verdict"] == "AFFECTED"
    infos = [i.value or "" for i in at.info]
    assert any("Demo data: this result used canned" in i
               for i in infos), infos
    # The override survives further reruns in session state.
    at.run()
    assert at.session_state["demo_override"] is True
    assert _demo_checkbox(at).value is True


def test_demo_override_arbitrary_text_shows_demo_notice():
    at = _fresh_app_with_key()
    _demo_checkbox(at).set_value(True).run()
    assert not at.exception
    at.radio[0].set_value("paste").run()
    assert not at.exception
    at.text_area[0].set_value(
        "Some random advisory with no sample marker and no "
        "versions.").run()
    assert not at.exception
    _click_button(at, "Run Triage")
    result = at.session_state["result"]
    # Demo-override wording: a key IS configured, so the notice
    # must not claim otherwise.
    assert result["verdict"] is None
    assert "Demo mode is on" in result["error"]
    assert "no CLOCKED_API_KEY is configured" not in result["error"]
    errors = [e.value or "" for e in at.error]
    assert any("Demo mode is on" in e for e in errors), errors


def test_feeds_under_override_with_key_uses_fixtures():
    at = _fresh_app_with_key()
    _demo_checkbox(at).set_value(True).run()
    assert not at.exception
    at.radio[1].set_value("feeds").run()
    assert not at.exception
    _click_button(at, "Run Batch")
    # Fixture counts, not live-feed counts: collection and
    # tracing answered from the bundled fixtures, and the deep
    # triage was judged in Mock Mode despite the configured key.
    feed_info = at.session_state["feed_info"]
    assert feed_info["nvd"]["count"] == 3
    assert feed_info["kev"]["count"] == 1
    results = at.session_state["batch_results"]
    assert results is not None
    assert len(results) == 4
    assert all(r["status"] == "ok" for r in results)
    judged = [r["triage"] for r in results if r.get("triage")
              and r.get("basis") != "local-screen"]
    assert judged
    assert all(t["mode"] == "mock" for t in judged)
    # The range-less KEV-only fixture item is the design's K-2
    # local row (section 3): local in every mode, never judged.
    kev_rows = [r for r in results
                if r.get("basis") == "local-screen"]
    assert len(kev_rows) == 1
    assert kev_rows[0]["triage"]["mode"] == "local"
    assert kev_rows[0]["triage"]["verdict"] == "CANNOT DETERMINE"


# --------- stale sample binding / stale mode results ---------------
# Regression: after loading a sample, editing its text in the area
# still ran with the stored sample_id, and Mock Mode served the
# untouched sample's canned verdict for the edited text. And a
# verdict produced under one mode lingered under the other mode's
# banner after toggling.


def test_edited_sample_text_does_not_reuse_canned_verdict():
    at = _fresh_app()  # no key -> Mock Mode
    _click_button(at, "Sample 1")
    assert at.session_state["sample_id"] == "sample1"
    # Edit one version string; the SYN marker stays in the text.
    edited = at.text_area[0].value.replace("17.9.5", "17.9.99")
    assert edited != at.text_area[0].value
    assert "SYN-CSC-2026-1101" in edited
    at.text_area[0].set_value(edited).run()
    assert not at.exception

    _click_button(at, "Run Triage")
    result = at.session_state["result"]
    # The standing Mock Mode outcome for arbitrary text - NOT
    # Sample 1's canned AFFECTED verdict.
    assert result["verdict"] is None
    assert "error" in result
    assert "CLOCKED_API_KEY" in result["error"]


def test_mode_toggle_clears_stale_results():
    at = _fresh_app_with_key()
    _demo_checkbox(at).set_value(True).run()
    assert not at.exception
    # Produce a real paste verdict in Demo mode.
    at.radio[0].set_value("paste").run()
    assert not at.exception
    _click_button(at, "Sample 1")
    _click_button(at, "Run Triage")
    assert at.session_state["result"]["verdict"] == "AFFECTED"
    # Produce real batch results in Demo mode (feeds fixtures).
    at.radio[0].set_value("batch").run()
    assert not at.exception
    at.radio[1].set_value("feeds").run()
    assert not at.exception
    _click_button(at, "Run Batch")
    assert at.session_state["batch_results"] is not None
    assert at.session_state["feed_info"] is not None
    # A plain rerun (no mode change) keeps both results.
    at.run()
    assert at.session_state["result"] is not None
    assert at.session_state["batch_results"] is not None
    # Flipping back to Live must not leave the Demo verdicts
    # standing under the LIVE banner.
    _demo_checkbox(at).set_value(False).run()
    assert not at.exception
    assert at.session_state["result"] is None
    assert at.session_state["batch_results"] is None
    assert at.session_state["feed_info"] is None


def test_paste_credit_exhausted_shows_banner_korean():
    # Switch language first: an AppTest widget interaction
    # re-registers the mode radio, so set Paste mode after the
    # language switch, then plant the result.
    at = AppTest.from_file(APP)
    at.run()
    assert not at.exception
    at.selectbox[0].set_value("한국어").run()
    assert not at.exception
    at.radio[0].set_value("paste").run()
    assert not at.exception
    at.session_state["result"] = dict(_CREDIT_RESULT_STATE)
    at.run()
    assert not at.exception
    warnings = [w.value or "" for w in at.warning]
    assert any(
        w == ("Clocked API 크레딧이 소진되어 라이브 판정을 사용할 수 "
              "없습니다. Demo 모드로 전환하면 번들 샘플 권고 7종(모든 "
              "판정 유형)을 API 호출 없이 체험할 수 있습니다.")
        for w in warnings), warnings
