"""Streamlit UI for Advisory Triage for Network Operators.

UI only - all Clocked SDK access and verdict logic live in triage.py.

The UI is bilingual: a language toggle at the top switches between
English (default) and Korean. All user-visible strings come from the
STRINGS dict below; verdict/urgency values stay the English constants
from triage.py and are mapped to display text here.
Python 3.9 compatible.
"""

import os
import traceback
from pathlib import Path
from typing import Any, Dict, List, Optional

import streamlit as st

from triage import run_triage

ROOT = Path(__file__).resolve().parent

SAMPLE_FILES = {
    "sample1": "sample1_affected.txt",
    "sample2": "sample2_not_affected.txt",
    "sample3": "sample3_insufficient.txt",
    "sample4": "sample4_arista_affected.txt",
    "sample5": "sample5_juniper_affected.txt",
    "sample6": "sample6_juniper_prior_to.txt",
    "sample7": "sample7_arista_conditional.txt",
}

SAMPLE_ORDER = ["sample1", "sample2", "sample3", "sample4", "sample5",
                "sample6", "sample7"]

VERDICT_STYLE = {
    "AFFECTED": ("#b00020", "white"),
    "NOT AFFECTED": ("#4a5568", "white"),
    "CANNOT DETERMINE": ("#b7791f", "white"),
}

FIELD_ORDER = ("vendor", "products", "affected_versions",
               "version_constraints", "applicability_conditions",
               "advisory_id", "cve_id", "severity",
               "fixed_version", "action_deadline")

DECIDE_ORDER = ("urgency_immediate", "urgency_planned", "evidence_sufficient")

STRINGS = {
    "en": {
        "title": "Advisory Triage for Network Operators",
        "title_subtitle": "",
        "pitch": (
            "Paste a vendor security advisory and your device inventory. "
            "In about a minute you get one defensible verdict per advisory: "
            "**AFFECTED**, **NOT AFFECTED**, or **CANNOT DETERMINE** - "
            "with the evidence shown, not hidden."
        ),
        "mode_live": "Mode: LIVE - Clocked API key configured.",
        "mode_mock": (
            "Mode: MOCK - Demo data. No CLOCKED_API_KEY is configured, so "
            "the bundled samples run on canned Clocked responses. Arbitrary "
            "pasted text needs a key for live analysis."
        ),
        "samples_heading": "Bundled samples",
        "sample_labels": {
            "sample1": "Sample 1 - Affected (Cisco-style)",
            "sample2": "Sample 2 - Not affected (Juniper-style)",
            "sample3": "Sample 3 - Insufficient evidence (KISA-style)",
            "sample4": "Sample 4: Arista affected",
            "sample5": "Sample 5: Juniper affected",
            "sample6": "Sample 6: Juniper prior-to",
            "sample7": "Sample 7: Arista conditional",
        },
        "samples_note": "",
        "clear": "Clear",
        "advisory_label": "Advisory text",
        "advisory_placeholder": "Paste the full advisory text here...",
        "inventory_label": "Inventory (one device per line: hostname, model, OS version)",
        "inventory_placeholder": "CORE-SW-01, Catalyst 9300, 17.9.4",
        "run_button": "Run Triage",
        "empty_advisory": "Paste an advisory first — or click one of the samples above.",
        "run_failed": "The triage run failed. Please try again.",
        "error_details": "Error details",
        "spinner": "Running Extract -> match -> Decide -> Verify...",
        "verdict_heading": "Verdict",
        "empty_hint": "Load a sample (or paste an advisory) and click Run Triage.",
        "verdict_card_label": "VERDICT",
        "urgency_label": "Urgency",
        "verify_label": "Verify (grounding)",
        "verified": "verified",
        "not_verified": "NOT verified",
        "mock_result_note": "Demo data: this result used canned Mock Mode responses (sample: %s).",
        "claim_label": "Verdict claim:",
        "per_device_heading": "Per-device results",
        "device_col": "device",
        "model_col": "model",
        "version_col": "version",
        "candidate_col": "candidate",
        "result_col": "result",
        "reason_col": "reason",
        "yes": "yes",
        "no": "no",
        "extracted_heading": "Extracted fields (Clocked Extract)",
        "field_col": "field",
        "value_col": "value",
        "field_labels": {
            "vendor": "vendor",
            "products": "products",
            "affected_versions": "affected_versions",
            "version_constraints": "version_constraints",
            "applicability_conditions": "applicability_conditions",
            "advisory_id": "advisory_id",
            "cve_id": "cve_id",
            "severity": "severity",
            "fixed_version": "fixed_version",
            "action_deadline": "action_deadline",
        },
        "not_stated": "(not stated)",
        "decide_heading": "Decide panel (Clocked Decide)",
        "question_col": "question",
        "answer_col": "answer",
        "probability_col": "probability",
        "question_labels": {
            "urgency_immediate": "urgency_immediate",
            "urgency_planned": "urgency_planned",
            "evidence_sufficient": "evidence_sufficient",
        },
        "overall_urgency": "Overall urgency: **%s**",
        "checklist_heading": "Next-action checklist",
        "conditions_heading": "Applicability conditions to verify",
        "footer": (
            "Endpoints used per run: Clocked Extract (two passes - the main "
            "fields, plus a focused pass for applicability conditions only), "
            "Clocked Decide, and Clocked Verify (the SDK's grounding "
            "endpoint) - exactly 4 Clocked calls. The inventory matcher is "
            "local and deterministic. "
            "No advisory or inventory data is stored by this app."
        ),
    },
    "ko": {
        "title": "네트워크 운영자를 위한 권고 판정",
        "title_subtitle": "Advisory Triage for Network Operators",
        "pitch": (
            "벤더 보안 권고문과 장비 인벤토리를 붙여넣으세요. 약 1분 안에 "
            "권고문별로 근거가 함께 제시되는 판정 하나 — **해당 있음**, "
            "**해당 없음**, 또는 **판정 불가** — 를 받을 수 있습니다."
        ),
        "mode_live": "모드: 실시간(LIVE) - Clocked API 키가 설정되어 있습니다.",
        "mode_mock": (
            "모드: 데모 데이터(MOCK) - CLOCKED_API_KEY가 설정되지 않아 "
            "포함된 샘플이 저장된 Clocked 응답으로 실행됩니다. 임의의 "
            "텍스트를 실시간으로 분석하려면 키가 필요합니다."
        ),
        "samples_heading": "포함된 샘플",
        "sample_labels": {
            "sample1": "샘플 1 - 해당 있음 (Cisco 형식)",
            "sample2": "샘플 2 - 해당 없음 (Juniper 형식)",
            "sample3": "샘플 3 - 근거 부족 (KISA 형식)",
            "sample4": "샘플 4: Arista 해당",
            "sample5": "샘플 5: Juniper 해당",
            "sample6": "샘플 6: Juniper 이전 버전 표현",
            "sample7": "샘플 7: Arista 조건부",
        },
        "samples_note": "샘플 권고문과 인벤토리는 영문 문서입니다.",
        "clear": "지우기",
        "advisory_label": "권고문 텍스트",
        "advisory_placeholder": "권고문 전문을 붙여넣으세요...",
        "inventory_label": "인벤토리 (한 줄에 장비 하나: 호스트명, 모델, OS 버전)",
        "inventory_placeholder": "CORE-SW-01, Catalyst 9300, 17.9.4",
        "run_button": "판정 실행",
        "empty_advisory": "권고문을 먼저 붙여넣어 주세요 — 위 샘플 버튼을 눌러도 됩니다.",
        "run_failed": "판정 실행에 실패했습니다. 다시 시도해 주세요.",
        "error_details": "오류 상세",
        "spinner": "Extract -> 매칭 -> Decide -> Verify 실행 중...",
        "verdict_heading": "판정",
        "empty_hint": "샘플을 불러오거나 권고문을 붙여넣은 뒤 '판정 실행'을 클릭하세요.",
        "verdict_card_label": "판정",
        "urgency_label": "긴급도",
        "verify_label": "Verify (grounding)",
        "verified": "검증됨",
        "not_verified": "검증 안 됨",
        "mock_result_note": "데모 데이터: 이 결과는 저장된 데모 모드 응답을 사용했습니다 (샘플: %s).",
        "claim_label": "판정 문장 (영문 원문):",
        "per_device_heading": "장비별 판정 결과",
        "device_col": "장비",
        "model_col": "모델",
        "version_col": "버전",
        "candidate_col": "후보",
        "result_col": "판정",
        "reason_col": "사유",
        "yes": "예",
        "no": "아니요",
        "extracted_heading": "추출된 필드 (Clocked Extract)",
        "field_col": "필드",
        "value_col": "값",
        "field_labels": {
            "vendor": "벤더/발행사",
            "products": "제품",
            "affected_versions": "영향받는 버전",
            "version_constraints": "버전 조건",
            "applicability_conditions": "적용 조건",
            "advisory_id": "권고 ID",
            "cve_id": "CVE",
            "severity": "심각도",
            "fixed_version": "수정 버전",
            "action_deadline": "조치 기한",
        },
        "not_stated": "(명시되지 않음)",
        "decide_heading": "Decide 패널 (Clocked Decide)",
        "question_col": "질문",
        "answer_col": "답변",
        "probability_col": "확률",
        "question_labels": {
            "urgency_immediate": "긴급 대응 필요",
            "urgency_planned": "계획 대응",
            "evidence_sufficient": "근거 충분성",
        },
        "overall_urgency": "종합 긴급도: **%s**",
        "checklist_heading": "다음 조치 체크리스트",
        "conditions_heading": "확인 필요한 적용 조건",
        "footer": (
            "실행당 사용하는 엔드포인트: Clocked Extract(2회 - 본 필드 "
            "추출과 적용 조건 전용 집중 추출), Clocked Decide, "
            "Clocked Verify(SDK의 grounding 엔드포인트) - 정확히 4회 "
            "호출합니다. 인벤토리 매칭은 로컬에서 결정적으로 수행됩니다. "
            "이 앱은 권고문이나 인벤토리 데이터를 저장하지 않습니다."
        ),
    },
}  # type: Dict[str, Dict[str, Any]]

VERDICT_DISPLAY = {
    "en": {
        "AFFECTED": "AFFECTED",
        "NOT AFFECTED": "NOT AFFECTED",
        "CANNOT DETERMINE": "CANNOT DETERMINE",
    },
    "ko": {
        "AFFECTED": "해당 있음",
        "NOT AFFECTED": "해당 없음",
        "CANNOT DETERMINE": "판정 불가",
    },
}

URGENCY_DISPLAY = {
    "en": {
        "immediate": "immediate",
        "planned": "planned",
        "monitor": "monitor",
    },
    "ko": {
        "immediate": "긴급",
        "planned": "계획 대응",
        "monitor": "모니터링",
    },
}


def _load_sample(sample_id):
    # type: (str) -> str
    filename = SAMPLE_FILES[sample_id]
    path = ROOT / "samples" / filename
    return path.read_text(encoding="utf-8")


def _load_inventory_sample():
    # type: () -> str
    path = ROOT / "samples" / "inventory_sample.txt"
    return path.read_text(encoding="utf-8")


def _on_load_sample(sample_id):
    # type: (str) -> None
    """Sample-button callback.

    on_click callbacks run BEFORE the script reruns, i.e. before the
    text_area widgets are created, so writing the widget keys
    ("advisory_text" / "inventory_text") here is the canonical way to
    fill key-bound text areas. Assigning them in an `if st.button():`
    body during the same run is too late - the widget already holds
    its own state by then.
    """
    st.session_state["advisory_text"] = _load_sample(sample_id)
    st.session_state["inventory_text"] = _load_inventory_sample()
    st.session_state["sample_id"] = sample_id
    st.session_state["result"] = None
    st.session_state["notice_empty"] = False


def _on_clear():
    # type: () -> None
    """Clear-button callback: advisory emptied, inventory restored to
    the bundled default. Same on_click pattern as _on_load_sample."""
    st.session_state["advisory_text"] = ""
    st.session_state["inventory_text"] = _load_inventory_sample()
    st.session_state["sample_id"] = None
    st.session_state["result"] = None
    st.session_state["notice_empty"] = False


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


def _fmt_field_item(item):
    # type: (Any) -> str
    """Format one extracted-field list item for the fields table.

    Structured version constraints ({"relation", "version", ...})
    render back to their compact normalized string form; anything
    else renders as plain text.
    """
    if isinstance(item, dict) and item.get("relation"):
        if item.get("relation") == "train_before":
            return "train_before:%s:%s" % (item.get("train"),
                                           item.get("version"))
        return "%s:%s" % (item.get("relation"), item.get("version"))
    return str(item)


def main():
    # type: () -> None
    st.set_page_config(page_title="Advisory Triage for Network Operators",
                       layout="wide")

    if "lang" not in st.session_state:
        st.session_state["lang"] = "en"
    lang_choice = st.selectbox(
        "Language / 언어",
        ["English", "한국어"],
        index=0 if st.session_state["lang"] == "en" else 1,
    )
    lang = "ko" if lang_choice == "한국어" else "en"
    st.session_state["lang"] = lang
    s = STRINGS[lang]

    live = _has_key()

    st.title(s["title"])
    if s["title_subtitle"]:
        st.caption(s["title_subtitle"])
    st.write(s["pitch"])
    if live:
        st.success(s["mode_live"])
    else:
        st.warning(s["mode_mock"])

    # Widget state defaults. The two text areas below are keyed
    # "advisory_text" / "inventory_text", so the widget keys ARE these
    # session-state keys; setdefault must run before they are created.
    st.session_state.setdefault("advisory_text", "")
    st.session_state.setdefault("inventory_text", _load_inventory_sample())
    st.session_state.setdefault("sample_id", None)
    st.session_state.setdefault("result", None)
    st.session_state.setdefault("notice_empty", False)

    st.subheader(s["samples_heading"])
    if s["samples_note"]:
        st.caption(s["samples_note"])
    # Eight button slots in two rows of four: seven samples + Clear.
    # Filling the text areas happens in the on_click callbacks, which
    # run before the widgets are created on the rerun.
    button_cols = st.columns(4) + st.columns(4)
    for idx, sample_id in enumerate(SAMPLE_ORDER):
        label = s["sample_labels"][sample_id]
        button_cols[idx].button(label, on_click=_on_load_sample,
                                args=(sample_id,))
    button_cols[7].button(s["clear"], on_click=_on_clear)

    left, right = st.columns(2)

    with left:
        advisory_text = st.text_area(
            s["advisory_label"], height=320,
            placeholder=s["advisory_placeholder"],
            key="advisory_text",
        )
        inventory_text = st.text_area(
            s["inventory_label"],
            height=180,
            placeholder=s["inventory_placeholder"],
            key="inventory_text",
        )
        run_clicked = st.button(s["run_button"], type="primary")
        if run_clicked:
            if not advisory_text or not advisory_text.strip():
                # Never call the API with an empty advisory (the SDK
                # raises a ValidationError on it); show a friendly
                # localized notice instead.
                st.session_state["result"] = None
                st.session_state["notice_empty"] = True
            else:
                st.session_state["notice_empty"] = False
                try:
                    with st.spinner(s["spinner"]):
                        st.session_state["result"] = run_triage(
                            advisory_text,
                            inventory_text,
                            sample_id=st.session_state.get("sample_id"),
                            lang=lang,
                        )
                except Exception:
                    # Show a localized banner, not Streamlit's raw
                    # traceback; the detail stays in a collapsed
                    # expander for debugging.
                    st.session_state["result"] = {
                        "error": s["run_failed"],
                        "error_detail": traceback.format_exc(),
                    }

    result = st.session_state.get("result")  # type: Optional[Dict[str, Any]]
    with right:
        st.subheader(s["verdict_heading"])
        if st.session_state.get("notice_empty"):
            st.warning(s["empty_advisory"])
        elif result is None:
            st.info(s["empty_hint"])
        elif result.get("error"):
            st.error(str(result.get("error")))
            error_detail = result.get("error_detail")
            if error_detail:
                with st.expander(s["error_details"], expanded=False):
                    st.code(str(error_detail))
        else:
            _render_result(result, s, lang)

    st.divider()
    st.caption(s["footer"])


def _render_result(result, s, lang):
    # type: (Dict[str, Any], Dict[str, Any], str) -> None
    verdict = str(result.get("verdict") or "")
    bg, fg = VERDICT_STYLE.get(verdict, ("#333333", "white"))
    verdict_display = VERDICT_DISPLAY[lang].get(verdict, verdict)
    urgency = str(result.get("urgency") or "monitor")
    urgency_display = URGENCY_DISPLAY[lang].get(urgency, urgency)
    if lang == "en":
        urgency_card = urgency_display.upper()
    else:
        urgency_card = urgency_display
    grounding = result.get("grounding") or {}
    grounding_status = s["verified"] if grounding.get("supported") else s["not_verified"]

    st.markdown(
        (
            "<div style='background-color:%s;color:%s;padding:20px;"
            "border-radius:10px;text-align:center'>"
            "<div style='font-size:14px'>%s</div>"
            "<div style='font-size:34px;font-weight:700'>%s</div>"
            "<div>%s: %s &nbsp;|&nbsp; %s: %s</div>"
            "</div>"
        ) % (bg, fg, s["verdict_card_label"], verdict_display,
             s["urgency_label"], urgency_card,
             s["verify_label"], grounding_status),
        unsafe_allow_html=True,
    )

    if result.get("mode") == "mock":
        st.info(s["mock_result_note"] % (result.get("sample_id") or "unknown"))

    claim = result.get("claim")
    if claim:
        # The claim is the exact English sentence sent to Clocked
        # Verify; it is shown as-is under a localized label.
        st.write("**%s** %s" % (s["claim_label"], claim))

    for warning in result.get("warnings") or []:
        st.warning(str(warning))

    conditions = result.get("conditions") or []
    if conditions:
        st.write("**%s**" % s["conditions_heading"])
        for condition in conditions:
            st.write("- %s" % condition)

    st.write("**%s**" % s["per_device_heading"])
    device_rows = []  # type: List[Dict[str, Any]]
    for row in result.get("device_results") or []:
        status = str(row.get("status") or "")
        device_rows.append({
            s["device_col"]: row.get("hostname"),
            s["model_col"]: row.get("model"),
            s["version_col"]: row.get("version"),
            s["candidate_col"]: s["yes"] if row.get("candidate") else s["no"],
            s["result_col"]: VERDICT_DISPLAY[lang].get(status, status),
            s["reason_col"]: row.get("reason"),
        })
    if device_rows:
        st.table(device_rows)

    st.write("**%s**" % s["extracted_heading"])
    extracted = result.get("extracted") or {}
    field_rows = []  # type: List[Dict[str, Any]]
    for field_name in FIELD_ORDER:
        value = extracted.get(field_name)
        # Defensive: triage returns plain (unwrapped) values, but if a
        # raw value-wrapped object ever reaches the UI, show its value.
        if isinstance(value, dict) and "value" in value:
            value = value.get("value")
        if isinstance(value, list):
            value_text = (", ".join(_fmt_field_item(v) for v in value)
                          if value else s["not_stated"])
        else:
            value_text = str(value) if value else s["not_stated"]
        field_rows.append({s["field_col"]: s["field_labels"][field_name],
                           s["value_col"]: value_text})
    st.table(field_rows)

    st.write("**%s**" % s["decide_heading"])
    decide = result.get("decide") or {}
    decide_rows = []  # type: List[Dict[str, Any]]
    for name in DECIDE_ORDER:
        entry = decide.get(name) or {}
        decide_rows.append({
            s["question_col"]: s["question_labels"][name],
            s["answer_col"]: entry.get("value"),
            s["probability_col"]: _fmt_prob(entry.get("probability")),
        })
    if decide_rows:
        st.table(decide_rows)
    st.write(s["overall_urgency"] % urgency_display)

    st.write("**%s**" % s["checklist_heading"])
    for item in result.get("checklist") or []:
        st.write("- [ ] %s" % item)


if __name__ == "__main__":
    main()
