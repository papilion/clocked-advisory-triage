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
    at = AppTest.from_file(APP)
    at.run()
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
