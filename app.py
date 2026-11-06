"""Streamlit UI for Advisory Triage for Network Operators.

UI only - all Clocked SDK access and verdict logic live in triage.py.
Python 3.9 compatible.
"""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import streamlit as st

from triage import run_triage

ROOT = Path(__file__).resolve().parent

SAMPLE_FILES = {
    "sample1": ("Sample 1 - Affected (Cisco-style)", "sample1_affected.txt"),
    "sample2": ("Sample 2 - Not affected (Juniper-style)", "sample2_not_affected.txt"),
    "sample3": ("Sample 3 - Insufficient evidence (KISA-style)", "sample3_insufficient.txt"),
}

VERDICT_STYLE = {
    "AFFECTED": ("#b00020", "white"),
    "NOT AFFECTED": ("#4a5568", "white"),
    "CANNOT DETERMINE": ("#b7791f", "white"),
}


def _load_sample(sample_id):
    # type: (str) -> str
    filename = SAMPLE_FILES[sample_id][1]
    path = ROOT / "samples" / filename
    return path.read_text(encoding="utf-8")


def _load_inventory_sample():
    # type: () -> str
    path = ROOT / "samples" / "inventory_sample.txt"
    return path.read_text(encoding="utf-8")


def _has_key():
    # type: () -> bool
    if os.environ.get("CLOCKED_API_KEY"):
        return True
    try:
        return bool(st.secrets.get("CLOCKED_API_KEY"))
    except Exception:
        return False


def _fmt_prob(prob):
    # type: (Optional[float]) -> str
    if prob is None:
        return "-"
    try:
        return "%.0f%%" % (float(prob) * 100)
    except (TypeError, ValueError):
        return "-"


def main():
    # type: () -> None
    st.set_page_config(page_title="Advisory Triage for Network Operators",
                       layout="wide")

    live = _has_key()
    mode_label = "LIVE" if live else "MOCK - Demo data"

    st.title("Advisory Triage for Network Operators")
    st.write(
        "Paste a vendor security advisory and your device inventory. "
        "In about a minute you get one defensible verdict per advisory: "
        "**AFFECTED**, **NOT AFFECTED**, or **CANNOT DETERMINE** - "
        "with the evidence shown, not hidden."
    )
    if live:
        st.success("Mode: LIVE - Clocked API key configured.")
    else:
        st.warning(
            "Mode: MOCK - Demo data. No CLOCKED_API_KEY is configured, so "
            "the bundled samples run on canned Clocked responses. Arbitrary "
            "pasted text needs a key for live analysis."
        )

    if "advisory_text" not in st.session_state:
        st.session_state["advisory_text"] = ""
    if "inventory_text" not in st.session_state:
        st.session_state["inventory_text"] = _load_inventory_sample()
    if "sample_id" not in st.session_state:
        st.session_state["sample_id"] = None
    if "result" not in st.session_state:
        st.session_state["result"] = None

    st.subheader("Bundled samples")
    cols = st.columns(4)
    for idx, sample_id in enumerate(["sample1", "sample2", "sample3"]):
        label = SAMPLE_FILES[sample_id][0]
        if cols[idx].button(label):
            st.session_state["advisory_text"] = _load_sample(sample_id)
            st.session_state["inventory_text"] = _load_inventory_sample()
            st.session_state["sample_id"] = sample_id
            st.session_state["result"] = None
    if cols[3].button("Clear"):
        st.session_state["advisory_text"] = ""
        st.session_state["sample_id"] = None
        st.session_state["result"] = None

    left, right = st.columns(2)

    with left:
        advisory_text = st.text_area(
            "Advisory text", height=320,
            value=st.session_state["advisory_text"],
            key="advisory_input",
        )
        inventory_text = st.text_area(
            "Inventory (one device per line: hostname, model, OS version)",
            height=180,
            value=st.session_state["inventory_text"],
            key="inventory_input",
        )
        run_clicked = st.button("Run Triage", type="primary")
        if run_clicked:
            st.session_state["advisory_text"] = advisory_text
            st.session_state["inventory_text"] = inventory_text
            with st.spinner("Running Extract -> match -> Decide -> Verify..."):
                st.session_state["result"] = run_triage(
                    advisory_text,
                    inventory_text,
                    sample_id=st.session_state.get("sample_id"),
                )

    result = st.session_state.get("result")  # type: Optional[Dict[str, Any]]
    with right:
        st.subheader("Verdict")
        if result is None:
            st.info("Load a sample (or paste an advisory) and click Run Triage.")
        elif result.get("error"):
            st.error(str(result.get("error")))
        else:
            _render_result(result)

    st.divider()
    st.caption(
        "Endpoints used per run: Clocked Extract, Clocked Decide, and "
        "Clocked Verify (the SDK's grounding endpoint) - exactly 3 Clocked "
        "calls. The inventory matcher is local and deterministic. "
        "No advisory or inventory data is stored by this app."
    )


def _render_result(result):
    # type: (Dict[str, Any]) -> None
    verdict = str(result.get("verdict") or "")
    bg, fg = VERDICT_STYLE.get(verdict, ("#333333", "white"))
    urgency = str(result.get("urgency") or "monitor")
    grounding = result.get("grounding") or {}
    grounding_status = "verified" if grounding.get("supported") else "NOT verified"

    st.markdown(
        (
            "<div style='background-color:%s;color:%s;padding:20px;"
            "border-radius:10px;text-align:center'>"
            "<div style='font-size:14px'>VERDICT</div>"
            "<div style='font-size:34px;font-weight:700'>%s</div>"
            "<div>Urgency: %s &nbsp;|&nbsp; Verify (grounding): %s</div>"
            "</div>"
        ) % (bg, fg, verdict, urgency.upper(), grounding_status),
        unsafe_allow_html=True,
    )

    if result.get("mode") == "mock":
        st.info("Demo data: this result used canned Mock Mode responses "
                "(sample: %s)." % (result.get("sample_id") or "unknown"))

    claim = result.get("claim")
    if claim:
        st.write("**Verdict claim:** %s" % claim)

    for warning in result.get("warnings") or []:
        st.warning(str(warning))

    st.write("**Per-device results**")
    device_rows = []  # type: List[Dict[str, Any]]
    for row in result.get("device_results") or []:
        device_rows.append({
            "device": row.get("hostname"),
            "model": row.get("model"),
            "version": row.get("version"),
            "candidate": "yes" if row.get("candidate") else "no",
            "result": row.get("status"),
            "reason": row.get("reason"),
        })
    if device_rows:
        st.table(device_rows)

    st.write("**Extracted fields (Clocked Extract)**")
    extracted = result.get("extracted") or {}
    field_rows = []  # type: List[Dict[str, Any]]
    for field_name in ("vendor", "products", "affected_versions",
                       "advisory_id", "cve_id", "severity",
                       "fixed_version", "action_deadline"):
        value = extracted.get(field_name)
        # Defensive: triage returns plain (unwrapped) values, but if a
        # raw value-wrapped object ever reaches the UI, show its value.
        if isinstance(value, dict) and "value" in value:
            value = value.get("value")
        if isinstance(value, list):
            value_text = ", ".join(str(v) for v in value) if value else "(not stated)"
        else:
            value_text = str(value) if value else "(not stated)"
        field_rows.append({"field": field_name, "value": value_text})
    st.table(field_rows)

    st.write("**Decide panel (Clocked Decide)**")
    decide = result.get("decide") or {}
    decide_rows = []  # type: List[Dict[str, Any]]
    for name in ("urgency_immediate", "urgency_planned", "evidence_sufficient"):
        entry = decide.get(name) or {}
        decide_rows.append({
            "question": name,
            "answer": entry.get("value"),
            "probability": _fmt_prob(entry.get("probability")),
        })
    if decide_rows:
        st.table(decide_rows)
    st.write("Overall urgency: **%s**" % urgency)

    st.write("**Next-action checklist**")
    for item in result.get("checklist") or []:
        st.write("- [ ] %s" % item)


if __name__ == "__main__":
    main()
