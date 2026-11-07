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

from batch import (HARVEST_CAP, MAX_LINKS, harvest_links,
                   parse_inventory_csv, parse_link_list, run_batch,
                   run_batch_items, run_feed_pipeline,
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
# sample detection (exact-text hash; see triage.detect_sample_id)
# in Mock and Live mode alike.
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

# Vendor listing presets inside the Listing source: vendor keys
# (batch.VENDOR_TOKENS) whose runs collect from structured sources
# (NVD / CISA KEV + vendor originals) through the feed pipeline
# instead of scraping the vendor's web listing.
VENDOR_PRESET_KEYS = ["cisco", "juniper", "arista", "nokia", "extreme"]

# Vendors with no bundled demo fixtures: a Demo-mode vendor run
# for one of these ends in the designed vendor_demo_unavailable
# notice instead of an empty result.
VENDOR_DEMO_UNAVAILABLE = ("nokia", "extreme")

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
        "mode_demo": (
            "Mode: DEMO - Demo override is on: canned responses, "
            "no API calls, even though an API key is configured."
        ),
        "demo_override_label": "Demo mode (canned responses, no API calls)",
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
        "credits_exhausted_banner": (
            "Clocked API credits exhausted — Live judging is "
            "unavailable right now. Switch to Demo mode to explore "
            "the seven bundled sample advisories (all verdict "
            "types, no API calls)."
        ),
        "error_details": "Error details",
        "spinner": "Running Extract -> match -> Decide -> Verify...",
        "verdict_heading": "Verdict",
        "empty_hint": "Load a sample (or paste an advisory) and click Run Triage.",
        "verdict_card_label": "VERDICT",
        "urgency_label": "Urgency",
        "verify_label": "Verify (grounding)",
        "verified": "verified",
        "not_verified": "NOT verified",
        "local_screen": "local screen (vendor ranges)",
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
        "csv_format_guide": (
            "**CSV format** - a header row is matched "
            "case-insensitively, in English or Korean:\n"
            "- **hostname** (required): `host`, `hostname`, `name`, "
            "`device`, `device name`, `장비명`, `호스트명`, `호스트`, "
            "`장비`, `기기명`\n"
            "- **model** (required): `model`, `모델`, `장비모델`, "
            "`모델명`, `device model`, `기종`\n"
            "- **version** (required, the OS/software version): "
            "`version`, `ver`, `os`, `os version`, `os버전`, `버전`, "
            "`펌웨어`, `firmware`, `software`, `sw version`\n"
            "- **vendor** (optional): `vendor`, `벤더`, `제조사`, "
            "`manufacturer`, `maker`, `브랜드` - prefixed to the "
            "model when it is not already there.\n"
            "No recognizable header row? Columns are read "
            "positionally as host, model, version. Encodings: UTF-8 "
            "or CP949. Delimiters: comma, semicolon, or tab."
        ),
        "csv_sample_download": "Download sample CSV",
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
            "inventory below. A full year of feed history is "
            "collected and screened locally against the vendors' "
            "structured version ranges at zero API cost; only the "
            "real candidates go to deep triage."
        ),
        "feeds_running": "Collecting vulnerability feeds (NVD / KEV)...",
        "feeds_collected": "NVD: %d CVEs collected · KEV: %d matches",
        "feeds_collected_year": (
            "Collected last 365 days: NVD %d · KEV %d"
        ),
        "feeds_screened": (
            "Local screening: %d not affected by version range · "
            "%d not in fleet · %d deep-triaged"
        ),
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
        "feeds_traced_candidates": (
            "Vendor-traced: %d of %d candidates (sources: CSAF / "
            "JSA / CNA)"
        ),
        "vendor_source": "Vendor source: %s \u2014 %s",
        "vendor_presets_heading": (
            "Vendor presets \u2014 structured sources (no web scraping)"
        ),
        "vendor_preset_labels": {
            "cisco": "Cisco",
            "juniper": "Juniper",
            "arista": "Arista",
            "nokia": "Nokia",
            "extreme": "Extreme Networks",
        },
        "vendor_selected": (
            "Vendor preset: %s \u2014 the batch run collects this "
            "vendor's advisories from structured sources (the NVD "
            "CVE API and CISA KEV, traced to the vendor's own "
            "texts); it does not scrape the vendor's web listing, "
            "which is JavaScript-rendered or bot-protected. The "
            "URL field above is ignored while a preset is active."
        ),
        "vendor_clear": "Clear vendor preset",
        "vendor_running": (
            "Collecting %s advisories from structured sources "
            "(NVD / KEV)..."
        ),
        "vendor_caption": (
            "Vendor listing \u2014 %s: collected from structured "
            "sources (NVD / CISA KEV + vendor original texts), "
            "last 365 days \u2014 not scraped from the vendor's "
            "web listing page."
        ),
        "vendor_demo_unavailable": (
            "Demo data covers Cisco, Juniper and Arista only "
            "\u2014 the bundled demo fixtures contain no %s "
            "advisories, so there is nothing honest to show for "
            "this vendor offline. Turn Demo mode off (live mode) "
            "to collect %s from the NVD / KEV feeds."
        ),
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
        "per_device_verdicts_heading": "Per-device verdicts",
        "col_affected_advisories": "Affected advisories",
        "no_related_advisories": "No related advisories",
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
        "mode_demo": (
            "모드: DEMO - Demo 모드가 강제 설정되어 고정 응답을 "
            "사용하며, API 키가 설정되어 있어도 API를 호출하지 "
            "않습니다."
        ),
        "demo_override_label": "Demo 모드 (고정 응답 사용, API 호출 없음)",
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
        "credits_exhausted_banner": (
            "Clocked API 크레딧이 소진되어 라이브 판정을 사용할 수 "
            "없습니다. Demo 모드로 전환하면 번들 샘플 권고 7종(모든 "
            "판정 유형)을 API 호출 없이 체험할 수 있습니다."
        ),
        "error_details": "오류 상세",
        "spinner": "Extract -> 매칭 -> Decide -> Verify 실행 중...",
        "verdict_heading": "판정",
        "empty_hint": "샘플을 불러오거나 권고문을 붙여넣은 뒤 '판정 실행'을 클릭하세요.",
        "verdict_card_label": "판정",
        "urgency_label": "긴급도",
        "verify_label": "Verify (grounding)",
        "verified": "검증됨",
        "not_verified": "검증 안 됨",
        "local_screen": "로컬 스크리닝 (벤더 범위 대조)",
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
        "csv_format_guide": (
            "**CSV 형식** - 헤더 행은 대소문자를 구분하지 않고 영어·"
            "한국어 모두 인식합니다:\n"
            "- **hostname** (필수): `host`, `hostname`, `name`, "
            "`device`, `device name`, `장비명`, `호스트명`, `호스트`, "
            "`장비`, `기기명`\n"
            "- **model** (필수): `model`, `모델`, `장비모델`, "
            "`모델명`, `device model`, `기종`\n"
            "- **version** (필수, OS/소프트웨어 버전): `version`, "
            "`ver`, `os`, `os version`, `os버전`, `버전`, `펌웨어`, "
            "`firmware`, `software`, `sw version`\n"
            "- **vendor** (선택): `vendor`, `벤더`, `제조사`, "
            "`manufacturer`, `maker`, `브랜드` - 모델명에 없으면 "
            "모델 앞에 붙습니다.\n"
            "인식되는 헤더가 없으면 열을 위치 기준(호스트, 모델, "
            "버전)으로 읽습니다. 인코딩: UTF-8 또는 CP949. 구분자: "
            "쉼표, 세미콜론, 탭."
        ),
        "csv_sample_download": "샘플 CSV 다운로드",
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
            "아래 인벤토리에서 자동으로 도출됩니다. 최근 365일 전체를 "
            "수집해 제조사의 구조화 버전 범위로 로컬 스크리닝하므로, "
            "API 호출은 실제 후보에만 쓰입니다."
        ),
        "feeds_running": "취약점 피드(NVD / KEV)를 수집하는 중...",
        "feeds_collected": "NVD: CVE %d건 수집 · KEV: %d건 일치",
        "feeds_collected_year": "최근 365일 수집: NVD %d건 · KEV %d건",
        "feeds_screened": (
            "로컬 스크리닝: 버전 범위 비해당 %d건 · 인벤토리 무관 "
            "%d건 · 정밀 판정 %d건"
        ),
        "feeds_nvd_empty": "NVD: 인벤토리 벤더에 대한 CVE를 찾지 못했습니다.",
        "feeds_nvd_failed": "NVD: 피드를 가져오지 못했습니다 (%s)",
        "feeds_nvd_no_vendors": (
            "NVD: 인벤토리 모델에서 알려진 벤더를 찾지 못했습니다."
        ),
        "feeds_kev_empty": "KEV: 인벤토리와 일치하는 카탈로그 항목이 없습니다.",
        "feeds_kev_failed": "KEV: 피드를 가져오지 못했습니다 (%s)",
        "feeds_traced": "제조사 원문 추적: %d/%d건 (출처: CSAF / JSA / CNA)",
        "feeds_traced_candidates": (
            "제조사 원문 추적: %d/%d 후보 (출처: CSAF / JSA / CNA)"
        ),
        "vendor_source": "제조사 원문: %s \u2014 %s",
        "vendor_presets_heading": (
            "제조사 프리셋 \u2014 구조화 소스 (웹 스크래핑 아님)"
        ),
        "vendor_preset_labels": {
            "cisco": "Cisco",
            "juniper": "Juniper",
            "arista": "Arista",
            "nokia": "Nokia",
            "extreme": "Extreme Networks",
        },
        "vendor_selected": (
            "제조사 프리셋: %s \u2014 배치 실행 시 이 제조사의 "
            "권고를 구조화 소스(NVD CVE API와 CISA KEV, 제조사 "
            "원문까지 추적)에서 수집합니다. 자바스크립트 "
            "렌더링이나 봇 차단으로 막힌 제조사 웹 목록 페이지를 "
            "긁는 방식이 아닙니다. 프리셋이 켜져 있는 동안 위 "
            "URL 입력란은 무시됩니다."
        ),
        "vendor_clear": "제조사 프리셋 해제",
        "vendor_running": (
            "구조화 소스(NVD / KEV)에서 %s 권고를 수집하는 중..."
        ),
        "vendor_caption": (
            "제조사 목록 \u2014 %s: 최근 365일치를 구조화 "
            "소스(NVD / CISA KEV + 제조사 원문)에서 수집했습니다 "
            "\u2014 제조사 웹 목록 페이지를 긁은 것이 아닙니다."
        ),
        "vendor_demo_unavailable": (
            "데모 데이터는 Cisco\u00b7Juniper\u00b7Arista만 "
            "다룹니다 \u2014 번들 데모 픽스처에는 %s 권고가 없어 "
            "오프라인으로 보여드릴 내용이 없습니다. %s 권고는 "
            "데모 모드를 끈 라이브 모드에서 NVD / KEV 피드로 "
            "수집해 주세요."
        ),
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
        "per_device_verdicts_heading": "장비별 판정",
        "col_affected_advisories": "해당 권고",
        "no_related_advisories": "관련 권고 없음",
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


def _sample_csv_bytes():
    # type: () -> bytes
    """Bytes of the bundled sample inventory CSV offered next to
    the uploader - the same file tests parse, so the download and
    the documented format can never drift apart."""
    path = ROOT / "samples" / "sample_inventory.csv"
    return path.read_bytes()


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


def _gated_sample_id(advisory_text):
    # type: (str) -> Optional[str]
    """The session's loaded-sample id, but only while the advisory
    text is still exactly that sample's bundled text.

    _on_load_sample stores the picker value in session state; the
    advisory text area stays editable afterwards, so the stored id
    goes stale the moment the user edits or replaces the text.
    Passing a stale id on would pin the run to the wrong sample
    (in Mock Mode, to its canned verdict). Any mismatch clears
    the id - the run then treats the text as arbitrary text.
    (triage.detect_sample_id independently revalidates the same
    way; this gate keeps the UI state honest at the source.)
    """
    sample_id = st.session_state.get("sample_id")
    if sample_id is None or sample_id not in SAMPLE_FILES:
        return None
    if (advisory_text or "").strip() != _load_sample(sample_id).strip():
        return None
    return sample_id


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
    any stale harvest outcome. Choosing a URL preset also clears
    a selected vendor preset - the last choice wins."""
    st.session_state["listing_url"] = url
    st.session_state["listing_vendor"] = None
    st.session_state["vendor_info"] = None
    st.session_state["vendor_demo_notice"] = None
    st.session_state["harvest_info"] = None
    st.session_state["batch_results"] = None
    st.session_state["batch_notice_empty"] = False
    st.session_state["batch_notice_listing"] = False


def _on_set_listing_vendor(vendor):
    # type: (str) -> None
    """Vendor-preset callback: select a structured-source vendor
    run for the Listing source. The free URL input is cleared as
    well - while a preset is active the run ignores it, and the
    UI must not suggest both are in play. Any stale harvest or
    run outcome is dropped, same as the URL presets do."""
    st.session_state["listing_vendor"] = vendor
    st.session_state["listing_url"] = ""
    st.session_state["harvest_info"] = None
    st.session_state["batch_results"] = None
    st.session_state["batch_notice_empty"] = False
    st.session_state["batch_notice_listing"] = False
    st.session_state["vendor_info"] = None
    st.session_state["vendor_demo_notice"] = None


def _on_clear_listing_vendor():
    # type: () -> None
    """Clear-vendor-preset callback: back to the free URL field."""
    st.session_state["listing_vendor"] = None
    st.session_state["vendor_info"] = None
    st.session_state["vendor_demo_notice"] = None


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
    # Demo override (keyed checkbox below the banner): with a key
    # configured it defaults off (Live judging); without a key,
    # Demo is the only possible mode, so it defaults - and stays -
    # on (the checkbox is disabled then). The banner reflects the
    # EFFECTIVE mode, read from session state before the checkbox
    # is created, so toggling re-renders it on the next run.
    st.session_state.setdefault("demo_override", not live)
    demo_mode = bool(st.session_state["demo_override"]) or not live

    # A verdict produced under one effective mode must never
    # linger under the other mode's banner: when the effective
    # mode flips (Demo override toggled, or key availability
    # changed between runs), drop the stored paste result and the
    # batch run's outputs. The first run only records the mode -
    # there is nothing stale to clear yet.
    _prev_demo_mode = st.session_state.setdefault(
        "_effective_demo_mode", demo_mode)
    if _prev_demo_mode != demo_mode:
        st.session_state["_effective_demo_mode"] = demo_mode
        st.session_state["result"] = None
        st.session_state["batch_results"] = None
        st.session_state["feed_info"] = None
        st.session_state["vendor_info"] = None
        st.session_state["vendor_demo_notice"] = None
        st.session_state["batch_error_detail"] = None

    st.title(s["title"])
    if s["title_subtitle"]:
        st.caption(s["title_subtitle"])
    st.write(s["pitch"])
    if not live:
        st.warning(s["mode_mock"])
    elif demo_mode:
        st.warning(s["mode_demo"])
    else:
        st.success(s["mode_live"])
    st.checkbox(s["demo_override_label"], key="demo_override",
                disabled=not live)

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
        _render_batch_mode(s, lang, demo_mode)
    else:
        _render_paste_mode(s, lang, demo_mode)

    st.divider()
    st.caption(s["footer"])


def _render_paste_mode(s, lang, demo_mode=False):
    # type: (Dict[str, Any], str, bool) -> None
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
                            sample_id=_gated_sample_id(advisory_text),
                            lang=lang,
                            mock=demo_mode,
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
        elif result.get("credit_exhausted"):
            # Credit exhaustion is a run state, not a failure:
            # one prominent banner, with the raw API detail kept
            # in the collapsed expander for debugging.
            st.warning(s["credits_exhausted_banner"])
            detail = result.get("error")
            if detail:
                with st.expander(s["error_details"], expanded=False):
                    st.code(str(detail))
        elif result.get("error"):
            st.error(str(result.get("error")))
            error_detail = result.get("error_detail")
            if error_detail:
                with st.expander(s["error_details"], expanded=False):
                    st.code(str(error_detail))
        else:
            _render_result(result, s, lang)


def _render_batch_mode(s, lang, demo_mode=False):
    # type: (Dict[str, Any], str, bool) -> None
    """Batch workflow: advisory links (harvested from a listing
    page, or pasted as a list) + inventory CSV in, an action
    summary, a summary table, and one detail expander per advisory
    out."""
    st.session_state.setdefault("links_text", "")
    st.session_state.setdefault("listing_url", "")
    st.session_state.setdefault("listing_vendor", None)
    st.session_state.setdefault("vendor_info", None)
    st.session_state.setdefault("vendor_demo_notice", None)
    st.session_state.setdefault("batch_source", "listing")
    st.session_state.setdefault("judge_all", False)
    st.session_state.setdefault("harvest_info", None)
    st.session_state.setdefault("batch_results", None)
    st.session_state.setdefault("batch_notice_empty", False)
    st.session_state.setdefault("batch_notice_listing", False)
    st.session_state.setdefault("batch_notice_uploads", False)
    st.session_state.setdefault("feed_info", None)
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
        # Vendor presets: a vendor LISTING that never touches the
        # vendor's web page - the run collects that vendor from
        # the structured feeds through the feed pipeline (see the
        # Run handler). Explicit widget keys keep these buttons
        # distinct from the URL presets above (labels repeat).
        st.caption(s["vendor_presets_heading"])
        vendor_cols = st.columns(len(VENDOR_PRESET_KEYS))
        for col, vendor_key in zip(vendor_cols, VENDOR_PRESET_KEYS):
            col.button(s["vendor_preset_labels"][vendor_key],
                       on_click=_on_set_listing_vendor,
                       args=(vendor_key,),
                       key="vendor_preset_%s" % vendor_key)
        listing_vendor = st.session_state.get("listing_vendor")
        if listing_vendor:
            st.info(s["vendor_selected"]
                    % s["vendor_preset_labels"][listing_vendor])
            st.button(s["vendor_clear"],
                      on_click=_on_clear_listing_vendor)
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
    st.markdown(s["csv_format_guide"])
    st.download_button(
        s["csv_sample_download"], data=_sample_csv_bytes(),
        file_name="sample_inventory.csv", mime="text/csv")
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
        st.session_state["vendor_info"] = None
        st.session_state["vendor_demo_notice"] = None

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
                # Per-item events fire BEFORE an item with a
                # 0-based index (so +1 is the item being worked
                # on); pipeline stage events report a completed
                # count instead. Clamp the displayed count to the
                # total so neither convention can render as
                # "N+1 of N" at a stage boundary.
                status_line.caption(
                    s["batch_progress"] % (
                        min(index + 1, total), total, label))

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
            vendor = st.session_state.get("listing_vendor")
            if vendor:
                # Vendor preset run: the feed pipeline scoped to
                # the one vendor - collection from the structured
                # sources (NVD / KEV), screening, vendor tracing
                # and judging exactly as a feeds run, presented
                # under the vendor caption below. In Demo mode
                # Nokia / Extreme have no bundled fixture data:
                # the run ends in the designed notice instead of
                # an empty table.
                if demo_mode and vendor in VENDOR_DEMO_UNAVAILABLE:
                    st.session_state["vendor_demo_notice"] = vendor
                else:
                    def _run_vendor(progress, _vendor=vendor):
                        # type: (Any, str) -> List[Dict[str, Any]]
                        rows, stats = run_feed_pipeline(
                            devices_text, lang=lang,
                            judge_all=judge_all, progress=progress,
                            mock=demo_mode, vendor=_vendor)
                        st.session_state["feed_info"] = stats
                        st.session_state["vendor_info"] = {
                            "vendor": _vendor}
                        return rows

                    with st.spinner(
                            s["vendor_running"]
                            % s["vendor_preset_labels"][vendor]):
                        _run_judging(_run_vendor)
            elif not (listing_url or "").strip():
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
            # One pipeline (batch.run_feed_pipeline): collect a
            # full year of feed history, screen it locally against
            # the vendors' structured version ranges (zero API
            # calls), trace the surviving candidates to their
            # vendor originals, and deep-triage only those - KEV
            # first, within the run's budget. In Mock Mode the
            # bundled fixtures answer the feed fetches, so the
            # demo path works offline. The "Judge all" toggle lifts
            # the deep-triage budget for this source.
            st.session_state["batch_results"] = None

            def _run_feeds(progress):
                # type: (Any) -> List[Dict[str, Any]]
                rows, stats = run_feed_pipeline(
                    devices_text, lang=lang, judge_all=judge_all,
                    progress=progress, mock=demo_mode)
                st.session_state["feed_info"] = stats
                return rows

            with st.spinner(s["feeds_running"]):
                _run_judging(_run_feeds)
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
                prefilter=not judge_all, mock=demo_mode))
        elif source in ("links", "listing"):
            _run_judging(lambda progress: run_batch(
                run_urls, devices_text, lang=lang, progress=progress,
                prefilter=not judge_all, mock=demo_mode))

    if st.session_state.get("batch_notice_empty"):
        st.warning(s["empty_links"])
    if st.session_state.get("batch_notice_listing"):
        st.warning(s["empty_listing"])
    if st.session_state.get("batch_notice_uploads"):
        st.warning(s["empty_uploads"])
    vendor_demo_notice = st.session_state.get("vendor_demo_notice")
    if source == "listing" and vendor_demo_notice:
        notice_label = s["vendor_preset_labels"].get(
            vendor_demo_notice, vendor_demo_notice)
        st.warning(s["vendor_demo_unavailable"]
                   % (notice_label, notice_label))
    feed_info = st.session_state.get("feed_info")
    vendor_info = st.session_state.get("vendor_info")
    if feed_info and (source == "feeds"
                      or (source == "listing" and vendor_info)):
        if vendor_info:
            # A vendor listing run is a feed pipeline run under a
            # vendor scope - label it as such (structured sources,
            # never the vendor's web listing) before the shared
            # feed counts.
            st.caption(s["vendor_caption"]
                       % s["vendor_preset_labels"].get(
                           vendor_info.get("vendor"),
                           vendor_info.get("vendor")))
        nvd_info = feed_info.get("nvd") or {}
        kev_info = feed_info.get("kev") or {}
        st.caption(s["feeds_collected_year"] % (
            nvd_info.get("count", 0), kev_info.get("count", 0)))
        screening = feed_info.get("screening") or {}
        st.caption(s["feeds_screened"] % (
            screening.get("local_not_affected", 0),
            screening.get("not_in_fleet", 0),
            feed_info.get("deep_triaged", 0)))
        if "traced_for_screen" in feed_info and \
                "candidates" in feed_info:
            # Feed pipeline: the trace pass ran over the screened
            # candidates (up to its cap), NOT over the deep-triaged
            # subset - say "traced_for_screen of candidates", or
            # the numbers read as nonsense (80 of 30).
            if feed_info.get("traced_for_screen"):
                st.caption(s["feeds_traced_candidates"] % (
                    feed_info.get("traced_for_screen", 0),
                    feed_info.get("candidates", 0)))
        elif feed_info.get("traced"):
            st.caption(s["feeds_traced"] % (
                feed_info.get("traced", 0),
                feed_info.get("deep_triaged", 0)))
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
        _render_batch_results(
            batch_results, s, lang,
            devices=parse_inventory(devices_text))


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


def _device_verdict_summary(results, devices, lang):
    # type: (List[Dict[str, Any]], List[Dict[str, str]], str) -> List[Dict[str, Any]]
    """Aggregate batch results per inventory device, from the
    rows already produced - no extra pipeline or API work.

    Every parsed-inventory device is seeded in, so the fleet is
    fully accounted for; hosts that appear only in result rows
    are added with the row's model/version. Only CANDIDATE device
    rows count as related to a device: a non-candidate row means
    the advisory does not concern that device's product at all
    (its NOT AFFECTED there is the matcher's "different product",
    not a verdict about the device), so a device whose rows are
    all non-candidate - or which never appears - has zero related
    advisories. Returns entries {hostname, model, version,
    affected: [labels], cannot: [labels], not_affected: int,
    related: int} sorted affected-first, then CANNOT DETERMINE
    count descending, then hostname."""
    by_host = {}  # type: Dict[str, Dict[str, Any]]

    def _entry(hostname, model, version):
        # type: (str, str, str) -> Dict[str, Any]
        entry = by_host.get(hostname)
        if entry is None:
            entry = {"hostname": hostname, "model": model,
                     "version": version, "affected": [],
                     "cannot": [], "not_affected": 0, "related": 0}
            by_host[hostname] = entry
        return entry

    for device in devices or []:
        _entry(str(device.get("hostname") or ""),
               str(device.get("model") or ""),
               str(device.get("version") or ""))
    for item in results or []:
        if item.get("status") != "ok":
            continue
        triage_result = item.get("triage") or {}
        if triage_result.get("error"):
            continue
        label = _batch_advisory_label(item, lang)
        for row in triage_result.get("device_results") or []:
            if not row.get("candidate"):
                continue
            entry = _entry(str(row.get("hostname") or ""),
                           str(row.get("model") or ""),
                           str(row.get("version") or ""))
            entry["related"] += 1
            status = str(row.get("status") or "")
            if status == "AFFECTED":
                entry["affected"].append(label)
            elif status == "CANNOT DETERMINE":
                entry["cannot"].append(label)
            elif status == "NOT AFFECTED":
                entry["not_affected"] += 1
    summary = [entry for entry in by_host.values()
               if entry["hostname"]]
    summary.sort(key=lambda e: (0 if e["affected"] else 1,
                                -len(e["cannot"]),
                                e["hostname"].lower()))
    return summary


def _render_batch_results(results, s, lang, devices=None):
    # type: (List[Dict[str, Any]], Dict[str, Any], str, Optional[List[Dict[str, str]]]) -> None
    # Credit exhaustion is a run-level state, not a verdict: when
    # any entry carries the flag, one prominent banner sits above
    # everything else in the results area (the unjudged entries
    # below render as plain error rows).
    if any(item.get("credit_exhausted") for item in results):
        st.warning(s["credits_exhausted_banner"])
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

    # Per-device verdicts: the same result rows re-aggregated by
    # host, so the fleet reads as a checklist - every inventory
    # device accounted for, affected advisories named inline and
    # the cannot-determine ones listed per device below the
    # table.
    device_summary = _device_verdict_summary(
        results, devices or [], lang)
    if device_summary:
        verdict_display = VERDICT_DISPLAY[lang]
        st.subheader(s["per_device_verdicts_heading"])
        device_rows = []  # type: List[Dict[str, Any]]
        for entry in device_summary:
            if entry["affected"]:
                advisories = ", ".join(entry["affected"])
            elif not entry["related"]:
                advisories = s["no_related_advisories"]
            else:
                advisories = "-"
            device_rows.append({
                s["device_col"]: entry["hostname"],
                s["model_col"]: entry["model"],
                s["version_col"]: entry["version"],
                verdict_display["AFFECTED"]: len(entry["affected"]),
                verdict_display["CANNOT DETERMINE"]:
                    len(entry["cannot"]),
                verdict_display["NOT AFFECTED"]:
                    entry["not_affected"],
                s["col_affected_advisories"]: advisories,
            })
        st.dataframe(device_rows, use_container_width=True,
                     hide_index=True)
        for entry in device_summary:
            if entry["cannot"]:
                st.caption("%s - %s: %s" % (
                    entry["hostname"],
                    verdict_display["CANNOT DETERMINE"],
                    ", ".join(entry["cannot"])))

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
    if result.get("basis") == "local-screen":
        grounding_status = s["local_screen"]
    else:
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
