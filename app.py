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

from batch import (HARVEST_CAP, MAX_LINKS, collect_feed_items,
                   harvest_links, parse_inventory_csv, parse_link_list,
                   run_batch, run_batch_items, trace_items,
                   uploaded_files_to_items)
from triage import parse_inventory, run_triage

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

_SAMPLE_RAW_BASE = (
    "https://raw.githubusercontent.com/papilion/clocked-advisory-triage"
    "/main/samples/"
)

# Raw URLs of the bundled samples, in sample order - the batch demo
# fetches exactly these files, so the fetched texts hit the normal
# sample detection (marker + hash) in Mock and Live mode alike.
SAMPLE_LINKS = [_SAMPLE_RAW_BASE + SAMPLE_FILES[sid] for sid in SAMPLE_ORDER]

VERDICT_STYLE = {
    "AFFECTED": ("#b00020", "white"),
    "NOT AFFECTED": ("#4a5568", "white"),
    "CANNOT DETERMINE": ("#b7791f", "white"),
}

FIELD_ORDER = ("vendor", "products", "affected_versions",
               "version_constraints", "applicability_conditions",
               "workarounds",
               "advisory_id", "cve_id", "severity",
               "fixed_version", "action_deadline")

# Listing/board presets for batch auto-collection: (STRINGS key, URL).
LISTING_PRESETS = [
    ("preset_cisco",
     "https://sec.cloudapps.cisco.com/security/center/publicationListing.x"),
    ("preset_arista",
     "https://www.arista.com/en/support/advisories-notices/security-advisories"),
    ("preset_juniper", "https://supportportal.juniper.net/"),
    ("preset_samples",
     "https://github.com/papilion/clocked-advisory-triage/tree/main/samples"),
]

DECIDE_ORDER = ("urgency_immediate", "urgency_planned", "evidence_sufficient")

STRINGS = {
    "en": {
        "title": "Advisory Triage for Network Operators",
        "title_subtitle": "",
        "pitch": (
            "Bring a list of advisory links and your device inventory "
            "as CSV - or paste a single advisory. For each advisory you "
            "get one defensible verdict: **AFFECTED**, **NOT AFFECTED**, "
            "or **CANNOT DETERMINE** - with the evidence shown, not hidden."
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
            "workarounds": "workarounds",
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
        "mode_switch_label": "Input mode",
        "mode_batch": "Batch (links + CSV)",
        "mode_paste": "Paste (single advisory)",
        "batch_intro": (
            "Point at a vendor listing page and the advisory links "
            "are collected automatically (and pre-filtered to your "
            "fleet) - or paste the links yourself. Every advisory is "
            "triaged against the uploaded inventory CSV, with the "
            "required actions summarized first."
        ),
        "links_heading": "Advisory links",
        "links_label": "Advisory URLs (one per line)",
        "links_placeholder": "https://vendor.example/advisory-2026-001",
        "load_sample_links": "Load sample link list",
        "links_skipped_note": (
            "%d link(s) over the %d-link limit were skipped."
        ),
        "csv_heading": "Device inventory (CSV)",
        "csv_label": "Upload inventory CSV",
        "csv_fallback_note": (
            "No CSV uploaded - the bundled sample inventory "
            "(%d devices) will be used."
        ),
        "csv_meta": (
            "Rows: %d used of %d total, %d skipped - encoding: %s - "
            "headers: %s."
        ),
        "csv_headers_header": "header row",
        "csv_headers_positional": "none (positional: host, model, version)",
        "csv_preview_heading": "Inventory preview (first 10)",
        "csv_no_rows": "No usable device rows were found in that CSV.",
        "csv_parse_failed": "Could not parse that CSV file.",
        "run_batch_button": "Run Batch",
        "empty_links": (
            "Paste at least one advisory link first - or load the "
            "sample link list."
        ),
        "batch_progress": "Processing %d of %d: %s",
        "batch_summary_heading": "Batch summary",
        "col_number": "#",
        "col_advisory": "Advisory",
        "col_affected_count": "Affected devices",
        "col_conditions": "Conditions",
        "fetch_failed": "FETCH FAILED",
        "batch_error_label": "ERROR",
        "source_label": "Advisory source",
        "source_listing": "Listing page (auto-collect)",
        "source_links": "Link list",
        "source_feeds": "Vulnerability feeds (NVD / KEV)",
        "source_uploads": "Upload advisory files",
        "feeds_intro": (
            "Collect CVEs for the vendors in your inventory from the "
            "official machine-readable feeds - the NVD CVE API and "
            "CISA's Known Exploited Vulnerabilities (KEV) catalog - "
            "instead of scraping vendor portals, which mostly block "
            "automated collection. The queries are derived from the "
            "inventory below."
        ),
        "feeds_running": "Collecting vulnerability feeds (NVD / KEV)...",
        "feeds_collected": "NVD: %d CVEs collected · KEV: %d matches",
        "feeds_nvd_empty": "NVD: no CVEs found for the inventory vendors.",
        "feeds_nvd_failed": "NVD: feed could not be fetched (%s)",
        "feeds_nvd_no_vendors": (
            "NVD: no known vendor found in the inventory models."
        ),
        "feeds_kev_empty": "KEV: no catalog entries match the inventory.",
        "feeds_kev_failed": "KEV: feed could not be fetched (%s)",
        "feeds_traced": (
            "Vendor-traced: %d of %d advisories (sources: CSAF / "
            "JSA / CNA)"
        ),
        "vendor_source": "Vendor source: %s \u2014 %s",
        "uploads_intro": (
            "Upload advisory pages you saved from your own browser - "
            "vendor portals often block automated collection, so your "
            "browser does the collecting and this app does the "
            "judging. Up to 10 files."
        ),
        "uploads_label": "Advisory files (.txt, .html, .md)",
        "empty_uploads": "Upload at least one advisory file first.",
        "listing_url_label": "Listing / board URL",
        "listing_url_placeholder": "https://vendor.example/advisories",
        "preset_labels": {
            "preset_cisco": "Cisco PSIRT",
            "preset_arista": "Arista",
            "preset_juniper": "Juniper",
            "preset_samples": "Sample advisories (GitHub)",
        },
        "empty_listing": (
            "Enter a listing URL first - or pick a preset above."
        ),
        "harvest_running": "Collecting advisory links from the listing page...",
        "harvest_found": "Found %d advisory link(s) on the listing page.",
        "harvest_capped": (
            "Harvest cap %d reached: %d more link(s) were left out."
        ),
        "harvest_blocked": (
            "Auto-collection was blocked or failed for this source - "
            "paste the links directly in Link list mode instead."
        ),
        "harvest_empty": (
            "No advisory links were found on that page - it may need "
            "JavaScript or a login. Paste the links directly in Link "
            "list mode instead."
        ),
        "harvest_failed": "Could not fetch the listing page: %s",
        "judge_all_toggle": "Judge all advisories (skip the relevance filter)",
        "skipped_label": "SKIPPED",
        "skipped_reason": "Not related to the uploaded inventory",
        "action_heading": "Action required",
        "action_summary_heading": "Action summary",
        "action_affected": "Affected devices: %s",
        "action_upgrade_to": "Upgrade to %s",
        "action_apply_fix": "Apply the vendor fix",
        "action_deadline": "Deadline: %s",
        "action_workarounds": "Workarounds / mitigations:",
        "action_verify_first": "Verify before deciding:",
        "action_none": "No action required.",
    },
    "ko": {
        "title": "네트워크 운영자를 위한 권고 판정",
        "title_subtitle": "Advisory Triage for Network Operators",
        "pitch": (
            "권고문 링크 목록과 장비 인벤토리 CSV를 가져오세요 — 단일 "
            "권고문 붙여넣기도 됩니다. 권고문별로 근거가 함께 제시되는 "
            "판정 하나 — **해당 있음**, **해당 없음**, 또는 **판정 불가** "
            "— 를 받을 수 있습니다."
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
            "workarounds": "임시 조치",
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
        "mode_switch_label": "입력 방식",
        "mode_batch": "배치 (링크 + CSV)",
        "mode_paste": "붙여넣기 (단일 권고문)",
        "batch_intro": (
            "벤더 목록 페이지를 지정하면 권고 링크를 자동으로 수집하고 "
            "보유 장비와 무관한 권고는 걸러냅니다 — 링크를 직접 붙여넣어도 "
            "됩니다. 모든 권고는 업로드한 인벤토리 CSV와 대조 판정되고, "
            "필요한 조치가 먼저 요약됩니다."
        ),
        "links_heading": "권고문 링크",
        "links_label": "권고문 URL (한 줄에 하나씩)",
        "links_placeholder": "https://vendor.example/advisory-2026-001",
        "load_sample_links": "샘플 링크 목록 불러오기",
        "links_skipped_note": "%d개 링크가 %d개 제한을 초과해 건너뛰었습니다.",
        "csv_heading": "장비 인벤토리 (CSV)",
        "csv_label": "인벤토리 CSV 업로드",
        "csv_fallback_note": (
            "CSV가 업로드되지 않아 포함된 샘플 인벤토리(%d대)를 사용합니다."
        ),
        "csv_meta": "행: 전체 %d개 중 %d개 사용, %d개 건너뜀 - 인코딩: %s - 헤더: %s.",
        "csv_headers_header": "헤더 행",
        "csv_headers_positional": "없음 (위치 기준: 호스트, 모델, 버전)",
        "csv_preview_heading": "인벤토리 미리보기 (처음 10개)",
        "csv_no_rows": "이 CSV에서 사용할 수 있는 장비 행을 찾지 못했습니다.",
        "csv_parse_failed": "CSV 파일을 해석하지 못했습니다.",
        "run_batch_button": "배치 실행",
        "empty_links": (
            "권고문 링크를 하나 이상 입력해 주세요 - 샘플 링크 목록을 "
            "불러와도 됩니다."
        ),
        "batch_progress": "처리 중 %d/%d: %s",
        "batch_summary_heading": "배치 결과 요약",
        "col_number": "#",
        "col_advisory": "권고문",
        "col_affected_count": "해당 장비 수",
        "col_conditions": "조건 확인",
        "fetch_failed": "가져오기 실패",
        "batch_error_label": "오류",
        "source_label": "권고 소스",
        "source_listing": "목록 페이지 (자동 수집)",
        "source_links": "링크 목록",
        "source_feeds": "취약점 피드 (NVD / KEV)",
        "source_uploads": "권고 파일 업로드",
        "feeds_intro": (
            "벤더 포털은 자동 수집이 차단되는 경우가 많아, 대신 공식 "
            "기계 판독 피드 — NVD CVE API와 CISA 악용 확인 취약점(KEV) "
            "카탈로그 — 에서 인벤토리 벤더의 CVE를 수집합니다. 검색어는 "
            "아래 인벤토리에서 자동으로 도출됩니다."
        ),
        "feeds_running": "취약점 피드(NVD / KEV)를 수집하는 중...",
        "feeds_collected": "NVD: CVE %d건 수집 · KEV: %d건 일치",
        "feeds_nvd_empty": "NVD: 인벤토리 벤더에 대한 CVE를 찾지 못했습니다.",
        "feeds_nvd_failed": "NVD: 피드를 가져오지 못했습니다 (%s)",
        "feeds_nvd_no_vendors": (
            "NVD: 인벤토리 모델에서 알려진 벤더를 찾지 못했습니다."
        ),
        "feeds_kev_empty": "KEV: 인벤토리와 일치하는 카탈로그 항목이 없습니다.",
        "feeds_kev_failed": "KEV: 피드를 가져오지 못했습니다 (%s)",
        "feeds_traced": "제조사 원문 추적: %d/%d건 (출처: CSAF / JSA / CNA)",
        "vendor_source": "제조사 원문: %s \u2014 %s",
        "uploads_intro": (
            "본인 브라우저에서 저장한 권고 페이지를 올리세요 — 벤더 "
            "포털은 자동 수집을 막는 경우가 많아, 수집은 브라우저가 "
            "하고 판정은 이 앱이 합니다. 최대 10개 파일."
        ),
        "uploads_label": "권고 파일 (.txt, .html, .md)",
        "empty_uploads": "권고 파일을 하나 이상 먼저 업로드해 주세요.",
        "listing_url_label": "목록 / 게시판 URL",
        "listing_url_placeholder": "https://vendor.example/advisories",
        "preset_labels": {
            "preset_cisco": "Cisco PSIRT",
            "preset_arista": "Arista",
            "preset_juniper": "Juniper",
            "preset_samples": "샘플 권고 (GitHub)",
        },
        "empty_listing": "목록 URL을 먼저 입력해 주세요 — 위 프리셋을 눌러도 됩니다.",
        "harvest_running": "목록 페이지에서 권고 링크를 수집하는 중...",
        "harvest_found": "목록 페이지에서 권고 링크 %d개를 찾았습니다.",
        "harvest_capped": "수집 상한 %d개를 초과한 링크 %d개는 제외됐습니다.",
        "harvest_blocked": (
            "이 소스는 자동 수집이 차단되었거나 실패했습니다 — 링크 "
            "목록 모드에 링크를 직접 붙여넣어 주세요."
        ),
        "harvest_empty": (
            "해당 페이지에서 권고 링크를 찾지 못했습니다 — 자바스크립트나 "
            "로그인이 필요한 페이지일 수 있습니다. 링크 목록 모드에 "
            "직접 붙여넣어 주세요."
        ),
        "harvest_failed": "목록 페이지를 가져오지 못했습니다: %s",
        "judge_all_toggle": "모든 권고를 판정 (관련성 필터 건너뛰기)",
        "skipped_label": "건너뜀",
        "skipped_reason": "업로드한 인벤토리와 관련 없음",
        "action_heading": "조치 방법",
        "action_summary_heading": "조치 요약",
        "action_affected": "해당 장비: %s",
        "action_upgrade_to": "%s(으)로 업그레이드",
        "action_deadline": "조치 기한: %s",
        "action_apply_fix": "벤더 수정 사항 적용",
        "action_workarounds": "임시 조치 / 완화책:",
        "action_verify_first": "판정 전에 확인할 것:",
        "action_none": "조치가 필요 없습니다.",
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


def _on_load_sample_links():
    # type: () -> None
    """Batch-mode sample-links callback (same on_click pattern):
    fill the links area with the bundled samples' raw GitHub URLs
    and clear any previous batch results."""
    st.session_state["links_text"] = "\n".join(SAMPLE_LINKS)
    st.session_state["batch_results"] = None
    st.session_state["batch_notice_empty"] = False
    st.session_state["batch_error_detail"] = None


def _on_set_listing_url(url):
    # type: (str) -> None
    """Preset-button callback: fill the listing URL input and drop
    any stale harvest outcome."""
    st.session_state["listing_url"] = url
    st.session_state["harvest_info"] = None
    st.session_state["batch_results"] = None
    st.session_state["batch_notice_empty"] = False
    st.session_state["batch_notice_listing"] = False


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

    # Primary workflow switch: batch (links + CSV) is the default;
    # the original paste-a-single-advisory UI stays as the second mode.
    st.session_state.setdefault("ui_mode", "batch")
    ui_mode = st.radio(
        s["mode_switch_label"],
        ["batch", "paste"],
        key="ui_mode",
        format_func=lambda m: (s["mode_batch"] if m == "batch"
                               else s["mode_paste"]),
        horizontal=True,
    )

    if ui_mode == "batch":
        _render_batch_mode(s, lang)
    else:
        _render_paste_mode(s, lang)

    st.divider()
    st.caption(s["footer"])


def _render_paste_mode(s, lang):
    # type: (Dict[str, Any], str) -> None
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


def _render_batch_mode(s, lang):
    # type: (Dict[str, Any], str) -> None
    """Batch workflow: advisory links (harvested from a listing
    page, or pasted as a list) + inventory CSV in, an action
    summary, a summary table, and one detail expander per advisory
    out."""
    st.session_state.setdefault("links_text", "")
    st.session_state.setdefault("listing_url", "")
    st.session_state.setdefault("batch_source", "listing")
    st.session_state.setdefault("judge_all", False)
    st.session_state.setdefault("harvest_info", None)
    st.session_state.setdefault("batch_results", None)
    st.session_state.setdefault("batch_notice_empty", False)
    st.session_state.setdefault("batch_notice_listing", False)
    st.session_state.setdefault("batch_notice_uploads", False)
    st.session_state.setdefault("feed_info", None)
    st.session_state.setdefault("trace_info", None)
    st.session_state.setdefault("batch_error_detail", None)

    st.subheader(s["links_heading"])
    st.caption(s["batch_intro"])
    source_labels = {
        "listing": s["source_listing"],
        "links": s["source_links"],
        "feeds": s["source_feeds"],
        "uploads": s["source_uploads"],
    }
    source = st.radio(
        s["source_label"],
        ["listing", "links", "feeds", "uploads"],
        key="batch_source",
        format_func=lambda m: source_labels[m],
        horizontal=True,
    )
    urls = []  # type: List[str]
    listing_url = ""
    uploaded_files = None
    if source == "listing":
        preset_cols = st.columns(len(LISTING_PRESETS))
        for col, (preset_key, preset_url) in zip(preset_cols,
                                                 LISTING_PRESETS):
            col.button(s["preset_labels"][preset_key],
                       on_click=_on_set_listing_url, args=(preset_url,))
        listing_url = st.text_input(
            s["listing_url_label"],
            placeholder=s["listing_url_placeholder"],
            key="listing_url",
        )
    elif source == "links":
        st.button(s["load_sample_links"], on_click=_on_load_sample_links)
        links_text = st.text_area(
            s["links_label"], height=180,
            placeholder=s["links_placeholder"],
            key="links_text",
        )
        urls, links_skipped = parse_link_list(links_text)
        if links_skipped:
            st.caption(s["links_skipped_note"] % (links_skipped, MAX_LINKS))
    elif source == "feeds":
        st.caption(s["feeds_intro"])
    elif source == "uploads":
        st.caption(s["uploads_intro"])
        uploaded_files = st.file_uploader(
            s["uploads_label"], type=["txt", "html", "htm", "md"],
            accept_multiple_files=True, key="advisory_uploads")
    judge_all = st.checkbox(s["judge_all_toggle"], key="judge_all")

    st.subheader(s["csv_heading"])
    uploaded = st.file_uploader(s["csv_label"], type=["csv", "txt", "tsv"])
    devices_text = ""  # type: str
    if uploaded is not None:
        try:
            devices_text, meta = parse_inventory_csv(uploaded.getvalue())
        except Exception:
            st.error(s["csv_parse_failed"])
            devices_text, meta = "", None
        if meta is not None:
            header_desc = (s["csv_headers_header"]
                           if meta["header_mode"] == "header"
                           else s["csv_headers_positional"])
            st.caption(s["csv_meta"] % (meta["rows_used"],
                                         meta["rows_total"],
                                         meta["rows_skipped"],
                                         meta["encoding"], header_desc))
            devices = parse_inventory(devices_text)
            if devices:
                st.write("**%s**" % s["csv_preview_heading"])
                preview_rows = [{
                    s["device_col"]: d["hostname"],
                    s["model_col"]: d["model"],
                    s["version_col"]: d["version"],
                } for d in devices[:10]]
                st.table(preview_rows)
            else:
                st.warning(s["csv_no_rows"])
    else:
        devices_text = _load_inventory_sample()
        fallback_count = len(parse_inventory(devices_text))
        st.caption(s["csv_fallback_note"] % fallback_count)

    if st.button(s["run_batch_button"], type="primary"):
        st.session_state["batch_notice_empty"] = False
        st.session_state["batch_notice_listing"] = False
        st.session_state["batch_notice_uploads"] = False
        st.session_state["batch_error_detail"] = None
        st.session_state["feed_info"] = None
        st.session_state["trace_info"] = None

        def _run_judging(runner):
            # type: (Any) -> None
            """Run one batch runner behind the shared progress UI.
            Per-item failures are isolated inside the runners; an
            unexpected runner-level failure becomes the localized
            banner + collapsed traceback, same as paste mode."""
            progress_bar = st.progress(0)
            status_line = st.empty()

            def _progress(index, total, label):
                # type: (int, int, str) -> None
                progress_bar.progress(
                    int(index * 100 / max(total, 1)))
                status_line.caption(
                    s["batch_progress"] % (index + 1, total, label))

            try:
                st.session_state["batch_results"] = runner(_progress)
                st.session_state["batch_error_detail"] = None
            except Exception:
                st.session_state["batch_results"] = None
                st.session_state["batch_error_detail"] = (
                    traceback.format_exc())
            finally:
                progress_bar.empty()
                status_line.empty()

        run_urls = list(urls)
        items = None  # type: Optional[List[Dict[str, Any]]]
        if source == "listing":
            # Auto-collect first: harvest the listing page now (not
            # on every rerun) and keep the outcome in session state.
            st.session_state["batch_results"] = None
            if not (listing_url or "").strip():
                st.session_state["batch_notice_listing"] = True
                st.session_state["harvest_info"] = None
                run_urls = []
            else:
                try:
                    with st.spinner(s["harvest_running"]):
                        info = harvest_links(listing_url.strip())
                except Exception:
                    info = {"status": "fetch_failed", "urls": [],
                            "found": 0,
                            "reason": traceback.format_exc(limit=3)}
                st.session_state["harvest_info"] = info
                run_urls = list(info.get("urls") or [])
        elif source == "feeds":
            # Collect first (queries derive from the inventory);
            # in Mock Mode the bundled fixtures are read instead of
            # the network, so the demo path works offline. Then
            # trace to the vendor originals, KEV items first -
            # known-exploited entries get the trace budget before
            # the merely-published NVD ones.
            st.session_state["batch_results"] = None
            try:
                with st.spinner(s["feeds_running"]):
                    feed = collect_feed_items(
                        parse_inventory(devices_text),
                        mock=not _has_key())
                    if feed is not None and feed["items"]:
                        ordered = (list(feed["kev"]["items"])
                                   + list(feed["nvd"]["items"]))
                        items, trace_stats = trace_items(
                            ordered, mock=not _has_key())
                        st.session_state["trace_info"] = trace_stats
            except Exception:
                feed = None
                st.session_state["batch_error_detail"] = (
                    traceback.format_exc())
            if feed is not None:
                st.session_state["feed_info"] = feed
                # Zero collected items: the per-feed status lines
                # below explain the outcome; no batch is run.
        elif source == "uploads":
            st.session_state["batch_results"] = None
            file_pairs = [(f.name, f.getvalue())
                          for f in (uploaded_files or [])]
            if not file_pairs:
                # Friendly notice, same pattern as the empty-links
                # guard; never run a batch with no items.
                st.session_state["batch_notice_uploads"] = True
            else:
                items = uploaded_files_to_items(file_pairs)

        if source == "links" and not run_urls:
            # Friendly notice, same pattern as the empty-advisory
            # guard in paste mode; never call out with no links.
            st.session_state["batch_results"] = None
            st.session_state["batch_notice_empty"] = True
        elif source == "listing" and not run_urls:
            pass  # notice/harvest status below explains why
        elif items is not None:
            _run_judging(lambda progress: run_batch_items(
                items, devices_text, lang=lang, progress=progress,
                prefilter=not judge_all))
        elif source in ("links", "listing"):
            _run_judging(lambda progress: run_batch(
                run_urls, devices_text, lang=lang, progress=progress,
                prefilter=not judge_all))

    if st.session_state.get("batch_notice_empty"):
        st.warning(s["empty_links"])
    if st.session_state.get("batch_notice_listing"):
        st.warning(s["empty_listing"])
    if st.session_state.get("batch_notice_uploads"):
        st.warning(s["empty_uploads"])
    feed_info = st.session_state.get("feed_info")
    if source == "feeds" and feed_info:
        nvd_info = feed_info.get("nvd") or {}
        kev_info = feed_info.get("kev") or {}
        st.caption(s["feeds_collected"] % (nvd_info.get("count", 0),
                                           kev_info.get("count", 0)))
        trace_results = st.session_state.get("batch_results")
        if st.session_state.get("trace_info") and trace_results:
            traced_count = sum(
                1 for entry in trace_results
                if entry.get("source_label"))
            st.caption(s["feeds_traced"] % (traced_count,
                                            len(trace_results)))
        if nvd_info.get("status") == "empty":
            st.warning(s["feeds_nvd_empty"])
        elif nvd_info.get("status") == "no_vendors":
            st.warning(s["feeds_nvd_no_vendors"])
        elif nvd_info.get("status") == "fetch_failed":
            st.error(s["feeds_nvd_failed"] % (
                nvd_info.get("reason") or ""))
        if kev_info.get("status") == "empty":
            st.warning(s["feeds_kev_empty"])
        elif kev_info.get("status") == "fetch_failed":
            st.error(s["feeds_kev_failed"] % (
                kev_info.get("reason") or ""))
    harvest_info = st.session_state.get("harvest_info")
    if source == "listing" and harvest_info:
        harvest_status = harvest_info.get("status")
        if harvest_status == "ok":
            st.caption(s["harvest_found"] % harvest_info.get("found", 0))
            extra = int(harvest_info.get("found", 0)) - len(
                harvest_info.get("urls") or [])
            if extra > 0:
                st.caption(s["harvest_capped"] % (HARVEST_CAP, extra))
        elif harvest_status == "blocked":
            st.warning(s["harvest_blocked"])
        elif harvest_status == "empty":
            st.warning(s["harvest_empty"])
        elif harvest_status == "fetch_failed":
            st.error(s["harvest_failed"] % (
                harvest_info.get("reason") or ""))
    error_detail = st.session_state.get("batch_error_detail")
    if error_detail:
        st.error(s["run_failed"])
        with st.expander(s["error_details"], expanded=False):
            st.code(str(error_detail))

    batch_results = st.session_state.get("batch_results")
    if batch_results is not None:
        _render_batch_results(batch_results, s, lang)


def _batch_advisory_label(item, lang):
    # type: (Dict[str, Any], str) -> str
    """Display name for one batch entry: the extracted advisory ID
    when the triage produced one, else the pre-fetched item's label
    (CVE id, filename), else the fetched text's first line, else
    the URL."""
    triage_result = item.get("triage") or {}
    extracted = triage_result.get("extracted") or {}
    advisory_id = extracted.get("advisory_id")
    if advisory_id:
        return str(advisory_id)
    return str(item.get("label") or item.get("text_hint")
               or item.get("url") or "")


def _action_lines(result, s, lang):
    # type: (Dict[str, Any], Dict[str, Any], str) -> List[str]
    """Deterministic "Action required" lines for one triage result,
    composed only from the result itself (no extra API calls):
    AFFECTED -> affected hostnames + fixed version (or the vendor
    fix) + deadline + extracted workarounds; CANNOT DETERMINE ->
    the conditions / missing information to verify, then the same
    workarounds when stated; NOT AFFECTED -> no action."""
    verdict = str(result.get("verdict") or "")
    extracted = result.get("extracted") or {}
    workarounds = [str(w) for w in extracted.get("workarounds") or []]
    lines = []  # type: List[str]
    if verdict == "NOT AFFECTED":
        return [s["action_none"]]
    if verdict == "AFFECTED":
        hosts = [str(d.get("hostname"))
                 for d in result.get("device_results") or []
                 if d.get("status") == "AFFECTED"]
        if hosts:
            lines.append(s["action_affected"] % ", ".join(hosts))
        fixed = extracted.get("fixed_version")
        if fixed:
            lines.append(s["action_upgrade_to"] % str(fixed))
        else:
            lines.append(s["action_apply_fix"])
        deadline = extracted.get("action_deadline")
        if deadline:
            lines.append(s["action_deadline"] % str(deadline))
    elif verdict == "CANNOT DETERMINE":
        lines.append(s["action_verify_first"])
        for condition in result.get("conditions") or []:
            lines.append("- %s" % condition)
        if not result.get("conditions"):
            for item in (result.get("checklist") or [])[:2]:
                lines.append("- %s" % item)
    else:
        return []
    if workarounds:
        lines.append(s["action_workarounds"])
        for workaround in workarounds:
            lines.append("- %s" % workaround)
    return lines


def _action_one_liner(result, s, lang):
    # type: (Dict[str, Any], Dict[str, Any], str) -> str
    """One-line action for the batch action summary."""
    verdict = str(result.get("verdict") or "")
    extracted = result.get("extracted") or {}
    if verdict == "AFFECTED":
        fixed = extracted.get("fixed_version")
        text = (s["action_upgrade_to"] % str(fixed)) if fixed \
            else s["action_apply_fix"]
        hosts = [str(d.get("hostname"))
                 for d in result.get("device_results") or []
                 if d.get("status") == "AFFECTED"]
        if hosts:
            text = "%s: %s" % (", ".join(hosts), text)
        deadline = extracted.get("action_deadline")
        if deadline:
            text = "%s (%s)" % (text, s["action_deadline"] % str(deadline))
        return text
    if verdict == "CANNOT DETERMINE":
        conditions = result.get("conditions") or []
        if conditions:
            return "%s %s" % (s["action_verify_first"], conditions[0])
        checklist = result.get("checklist") or []
        if checklist:
            return str(checklist[0])
    return ""


def _render_batch_results(results, s, lang):
    # type: (List[Dict[str, Any]], Dict[str, Any], str) -> None
    # Action summary first: only the advisories that need action,
    # AFFECTED before CANNOT DETERMINE, one line + link each.
    actionable = []  # type: List[Any]
    for idx, item in enumerate(results, start=1):
        if item.get("status") != "ok":
            continue
        triage_result = item.get("triage") or {}
        if triage_result.get("error"):
            continue
        verdict = str(triage_result.get("verdict") or "")
        if verdict in ("AFFECTED", "CANNOT DETERMINE"):
            actionable.append((0 if verdict == "AFFECTED" else 1,
                                 idx, item))
    if actionable:
        actionable.sort(key=lambda entry: (entry[0], entry[1]))
        st.subheader(s["action_summary_heading"])
        for _rank, idx, item in actionable:
            triage_result = item.get("triage") or {}
            line = "- **#%d %s** - %s" % (
                idx, _batch_advisory_label(item, lang),
                _action_one_liner(triage_result, s, lang))
            url = item.get("url") or ""
            if url:
                # Uploaded files carry no URL: their line simply
                # omits the link instead of rendering an empty one.
                line = "%s - [%s](%s)" % (line, url, url)
            st.markdown(line)

    st.subheader(s["batch_summary_heading"])
    summary_rows = []  # type: List[Dict[str, Any]]
    for idx, item in enumerate(results, start=1):
        row = {s["col_number"]: idx,
               s["col_advisory"]: _batch_advisory_label(item, lang)}
        if item.get("status") == "fetch_failed":
            row[s["verdict_card_label"]] = s["fetch_failed"]
            row[s["urgency_label"]] = "-"
            row[s["col_affected_count"]] = "-"
            row[s["col_conditions"]] = "-"
        elif item.get("status") == "skipped":
            row[s["verdict_card_label"]] = s["skipped_label"]
            row[s["urgency_label"]] = "-"
            row[s["col_affected_count"]] = "-"
            row[s["col_conditions"]] = "-"
        elif item.get("status") != "ok":
            row[s["col_advisory"]] = item.get("url") or row[s["col_advisory"]]
            row[s["verdict_card_label"]] = s["batch_error_label"]
            row[s["urgency_label"]] = "-"
            row[s["col_affected_count"]] = "-"
            row[s["col_conditions"]] = "-"
        else:
            triage_result = item.get("triage") or {}
            if triage_result.get("error"):
                row[s["verdict_card_label"]] = s["batch_error_label"]
                row[s["urgency_label"]] = "-"
                row[s["col_affected_count"]] = "-"
                row[s["col_conditions"]] = "-"
            else:
                verdict = str(triage_result.get("verdict") or "")
                urgency = str(triage_result.get("urgency") or "monitor")
                row[s["verdict_card_label"]] = VERDICT_DISPLAY[lang].get(
                    verdict, verdict)
                row[s["urgency_label"]] = URGENCY_DISPLAY[lang].get(
                    urgency, urgency)
                row[s["col_affected_count"]] = sum(
                    1 for d in triage_result.get("device_results") or []
                    if d.get("status") == "AFFECTED")
                row[s["col_conditions"]] = (
                    s["yes"] if triage_result.get("conditions")
                    else s["no"])
        summary_rows.append(row)
    if summary_rows:
        st.dataframe(summary_rows, use_container_width=True,
                     hide_index=True)

    for idx, item in enumerate(results, start=1):
        triage_result = item.get("triage") or {}
        verdict = str(triage_result.get("verdict") or "")
        verdict_display = VERDICT_DISPLAY[lang].get(verdict, verdict)
        title = "#%d %s" % (idx, _batch_advisory_label(item, lang))
        if item.get("status") == "fetch_failed":
            title = "#%d %s - %s" % (idx, item.get("url") or "",
                                     s["fetch_failed"])
            verdict_display = ""
        elif item.get("status") == "skipped":
            title = "#%d %s - %s" % (
                idx, item.get("label") or item.get("text_hint")
                or item.get("url") or "",
                s["skipped_label"])
            verdict_display = ""
        if verdict_display:
            title = "%s - %s" % (title, verdict_display)
        with st.expander(title):
            st.caption(str(item.get("url") or item.get("label") or ""))
            if item.get("source_label"):
                st.caption(s["vendor_source"] % (
                    item.get("source_label"),
                    item.get("source_url") or item.get("url") or ""))
            if item.get("status") == "skipped":
                st.info(s["skipped_reason"])
            elif item.get("status") != "ok":
                st.error(str(item.get("error") or s["run_failed"]))
            elif triage_result.get("error"):
                st.error(str(triage_result.get("error")))
            else:
                _render_result(triage_result, s, lang)


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

    action_lines = _action_lines(result, s, lang)
    if action_lines:
        st.write("**%s**" % s["action_heading"])
        for action_line in action_lines:
            st.write(action_line)

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
