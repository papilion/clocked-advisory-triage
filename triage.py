"""Core triage logic for Advisory Triage for Network Operators.

All Clocked SDK access lives in this module (and nowhere else).
Pipeline per run (exactly 4 Clocked calls in live mode):
  1. extract   - pull structured fields from the advisory text
  1b. extract  - focused second pass carrying only
                 applicability_conditions and workarounds: measured
                 live, span extraction of those fields is unreliable
                 inside the full-field call (conditions came back
                 empty even when the condition sentence was plainly
                 in the text), while the focused call returns them
                 reliably
  2. (local)   - deterministic matcher: extracted product/version vs inventory
  3. decide    - urgency + evidence sufficiency, with probabilities
  4. grounding - Verify step: check the verdict claim against the
                 advisory AND the inventory it was matched against

Robustness features in the matcher:
  - Narrative version conditions: Extract returns verbatim spans,
    so prose statements like "versions prior to 21.4R2" are turned
    into constraints ("before:21.4R2", "up_to:X",
    "train_before:T:B") by deterministic LOCAL derivation in
    normalize_extraction (normalized tokens are not requested from
    Extract - they are not spans - but the parser still merges in
    any a response carries), and evaluated deterministically when the
    explicit affected-version list does not decide a device.
  - Applicability conditions: when an advisory applies only under a
    stated condition (e.g. a feature configured a certain way), a
    product+version match is gated to CANNOT DETERMINE - the
    inventory cannot confirm the condition - with the condition
    named in the reason, the warnings, and the checklist.

Mock Mode: when no CLOCKED_API_KEY is available, canned responses from
mock_responses.json are used for the bundled samples. Arbitrary
pasted text in Mock Mode does NOT get a fabricated verdict; the caller
is told a key is needed for live analysis.

Display text (reasons, warnings, checklists) can be localized with
run_triage(..., lang="ko"); verdict constants, the grounding claim,
and all Clocked prompts always stay English.

Python 3.9 compatible: typing.Optional / Union only, no PEP 604 unions.
"""

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

BASE_URL = "https://clocked.rezolve.ai/clocked"
ROOT = Path(__file__).resolve().parent

VERDICT_AFFECTED = "AFFECTED"
VERDICT_NOT_AFFECTED = "NOT AFFECTED"
VERDICT_CANNOT = "CANNOT DETERMINE"


# --------------------------------------------------------------------------
# Localization (display text only)
#
# Internal verdict constants, the grounding claim, and all Clocked
# prompts stay English regardless of `lang`; only user-facing text
# generated here (match reasons, warnings, checklists, Mock Mode
# notice) is localized. Supported languages: "en" (default), "ko".
# --------------------------------------------------------------------------

def _normalize_lang(lang):
    # type: (Optional[str]) -> str
    return "ko" if lang == "ko" else "en"


REASON_STRINGS = {
    "en": {
        "no_product": "Advisory extraction named no product; cannot determine.",
        "different_product": "Device product is not one of the products named in the advisory.",
        "no_affected_versions": "Product matches, but the advisory states no affected versions.",
        "unparseable_version": "Product matches, but the device version %r is unparseable.",
        "version_affected": "Version %s is listed as affected (%s).",
        "version_inconclusive": "Product matches, but version comparison was inconclusive.",
        "version_not_affected": "Product matches, but version %s is not in the affected list.",
        "version_constraint_before": (
            "Version %s is before %s, the first fixed release stated "
            "in the advisory."
        ),
        "version_constraint_up_to": (
            "Version %s is at or before %s, the last affected version "
            "stated in the advisory."
        ),
        "version_constraint_train_before": (
            "Version %s is in the %s train and before %s, the first "
            "fixed release stated in the advisory."
        ),
        "version_constraint_not_satisfied": (
            "Product matches, but version %s does not satisfy the "
            "version condition stated in the advisory."
        ),
        "condition_gate": (
            "Matches the affected product and version, but the "
            "advisory applies only when: %s - the inventory does "
            "not confirm this."
        ),
    },
    "ko": {
        "no_product": "권고문 추출 결과에 제품이 명시되지 않아 판정할 수 없습니다.",
        "different_product": "이 장비의 제품은 권고문에 명시된 제품에 해당하지 않습니다.",
        "no_affected_versions": "제품은 일치하지만 권고문에 영향받는 버전이 명시되지 않았습니다.",
        "unparseable_version": "제품은 일치하지만 장비 버전 %r을(를) 해석할 수 없습니다.",
        "version_affected": "버전 %s이(가) 영향받는 버전(%s)으로 명시되어 있습니다.",
        "version_inconclusive": "제품은 일치하지만 버전 비교 결과를 확정할 수 없습니다.",
        "version_not_affected": "제품은 일치하지만 버전 %s은(는) 영향받는 버전에 포함되지 않습니다.",
        "version_constraint_before": (
            "버전 %s이(가) 권고문에 명시된 최초 수정 버전 %s보다 이전입니다."
        ),
        "version_constraint_up_to": (
            "버전 %s이(가) 권고문에 명시된 마지막 영향 버전 %s 이하입니다."
        ),
        "version_constraint_train_before": (
            "버전 %s이(가) %s 트레인에 속하고 권고문에 명시된 최초 수정 "
            "버전 %s보다 이전입니다."
        ),
        "version_constraint_not_satisfied": (
            "제품은 일치하지만 버전 %s은(는) 권고문에 명시된 버전 조건을 "
            "충족하지 않습니다."
        ),
        "condition_gate": (
            "영향받는 제품과 버전은 일치하지만, 이 권고문은 다음 조건에서만 "
            "적용됩니다: %s - 인벤토리에서 이 조건을 확인할 수 없습니다."
        ),
    },
}

WARNING_STRINGS = {
    "en": {
        "low_sufficiency": (
            "CANNOT DETERMINE: Decide rated the advisory evidence as "
            "insufficient (probability %s)."
        ),
        "grounding": (
            "CANNOT DETERMINE: Verify (grounding) did not verify the "
            "verdict claim against the advisory and inventory texts "
            "(verdict=%r, answers_question=%r)."
        ),
        "condition_check": "Condition check required: %s",
    },
    "ko": {
        "low_sufficiency": (
            "판정 불가: Decide가 권고문의 근거가 충분하지 않다고 "
            "판단했습니다 (확률 %s)."
        ),
        "grounding": (
            "판정 불가: Verify(grounding)가 판정 문장을 권고문과 "
            "인벤토리 원문으로 검증하지 못했습니다 "
            "(verdict=%r, answers_question=%r)."
        ),
        "condition_check": "조건 확인 필요: %s",
    },
}

# Notice returned when Mock Mode cannot judge arbitrary text
# (no bundled sample matched). Two contexts, two wordings:
# MOCK_ERROR_STRINGS is the no-key case - Mock Mode is the only
# mode available, so the notice points at setting a key.
# MOCK_DEMO_ERROR_STRINGS is the Demo-override case - a key IS
# configured and the user turned Demo mode on on purpose, so
# claiming "no key is configured" would be false; the notice
# points at turning Demo mode off instead.
MOCK_ERROR_STRINGS = {
    "en": (
        "Mock Mode: no CLOCKED_API_KEY is configured, so live "
        "analysis is unavailable. Use one of the bundled samples "
        "for the demo, or set CLOCKED_API_KEY for live analysis "
        "of arbitrary text."
    ),
    "ko": (
        "데모 데이터 모드: CLOCKED_API_KEY가 설정되지 않아 실시간 "
        "분석을 사용할 수 없습니다. 데모는 포함된 샘플을 사용하거나, "
        "임의의 텍스트를 실시간으로 분석하려면 CLOCKED_API_KEY를 "
        "설정하세요."
    ),
}

MOCK_DEMO_ERROR_STRINGS = {
    "en": (
        "Demo mode is on: canned responses cover only the seven "
        "bundled samples. Turn Demo mode off to run live analysis "
        "of arbitrary text."
    ),
    "ko": (
        "데모 모드가 켜져 있습니다: 고정 응답은 번들로 제공되는 "
        "7개 샘플에만 적용됩니다. 임의의 텍스트를 실시간으로 "
        "분석하려면 데모 모드를 끄세요."
    ),
}

GENERIC_PRODUCT_WORDS = {
    "series", "switch", "switches", "router", "routers", "family",
    "devices", "device", "platform", "platforms", "products", "product",
}


# --------------------------------------------------------------------------
# Inventory parsing
# --------------------------------------------------------------------------

def parse_inventory(inventory_text):
    # type: (str) -> List[Dict[str, str]]
    """Parse 'hostname, model, OS version' lines into device dicts."""
    devices = []  # type: List[Dict[str, str]]
    for raw_line in (inventory_text or "").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) >= 3:
            devices.append({
                "hostname": parts[0],
                "model": parts[1],
                "version": ",".join(parts[2:]).strip(),
            })
        elif len(parts) == 2:
            devices.append({"hostname": parts[0], "model": parts[1], "version": ""})
        else:
            devices.append({"hostname": parts[0], "model": "", "version": ""})
    return devices


# --------------------------------------------------------------------------
# Version helpers
# --------------------------------------------------------------------------

def parse_version(version_text):
    # type: (str) -> Optional[Tuple[int, ...]]
    """Return a numeric tuple for a version string, or None if unparseable."""
    if not version_text:
        return None
    text = str(version_text).strip()
    if not text or not any(ch.isdigit() for ch in text):
        return None
    numbers = re.findall(r"\d+", text)
    if not numbers:
        return None
    try:
        return tuple(int(n) for n in numbers)
    except ValueError:
        return None


def _norm_version_text(version_text):
    # type: (str) -> str
    return re.sub(r"\s+", "", str(version_text or "")).strip().lower()


def version_matches(device_version, affected_entry):
    # type: (str, str) -> Optional[bool]
    """Does device_version match one affected entry?

    Supports exact matches, wildcards (17.9.x), and hyphen ranges
    (17.9.1-17.9.5). Returns None when the comparison cannot be made
    (unparseable device version).
    """
    device_norm = _norm_version_text(device_version)
    entry_norm = _norm_version_text(affected_entry)
    if not device_norm or not entry_norm:
        return None
    if device_norm == entry_norm:
        return True

    # Wildcard, e.g. 17.9.x
    if "x" in entry_norm.split("."):
        entry_parts = entry_norm.split(".")
        device_parts = device_norm.split(".")
        if len(device_parts) >= len(entry_parts):
            ok = True
            for idx, part in enumerate(entry_parts):
                if part == "x":
                    continue
                if device_parts[idx] != part:
                    ok = False
                    break
            return ok
        return False

    # Hyphen range, e.g. 17.9.1-17.9.5
    if "-" in entry_norm and not entry_norm.startswith("-"):
        low_text, _, high_text = entry_norm.partition("-")
        low = parse_version(low_text)
        high = parse_version(high_text)
        device_tuple = parse_version(device_version)
        if low is None or high is None or device_tuple is None:
            return None
        width = max(len(low), len(high), len(device_tuple))
        padded_device = device_tuple + (0,) * (width - len(device_tuple))
        padded_low = low + (0,) * (width - len(low))
        padded_high = high + (0,) * (width - len(high))
        return padded_low <= padded_device <= padded_high

    # Plain exact-style entry that did not match literally: only call it
    # a non-match when both sides are parseable versions.
    if parse_version(device_version) is None:
        return None
    return False


# --------------------------------------------------------------------------
# Narrative version constraints ("prior to X" and friends)
#
# Normalized constraint strings look like "before:21.4R2",
# "up_to:17.9.5", "train_before:4.30:4.30.6M".
# parse_version_constraint turns those into structured dicts and
# constraint_matches evaluates them deterministically.
#
# Where the strings come from: Extract is span-based and returns
# verbatim text, so a normalized token is usually NOT a span and the
# version_constraints field comes back empty live. The reliable
# source is local and deterministic: derive_version_constraints
# scans the verbatim affected-version statements (and, as a guarded
# fallback, the fixed version) for bound phrases and builds the same
# structured constraints. Explicit tokens Extract does emit are kept
# and merged (see normalize_extraction).
# --------------------------------------------------------------------------

def parse_version_constraint(text):
    # type: (str) -> Optional[Dict[str, Any]]
    """Parse a normalized constraint string into a structured dict.

    Returns {"relation": ..., "version": ..., ["train": ...]} or
    None when the string is not a recognized constraint form.
    """
    raw = str(text or "").strip()
    lowered = raw.lower()
    if lowered.startswith("train_before:"):
        parts = raw[len("train_before:"):].split(":")
        if len(parts) != 2:
            return None
        train = parts[0].strip()
        bound = parts[1].strip()
        if not train or not bound:
            return None
        return {"relation": "train_before", "train": train,
                "version": bound}
    if lowered.startswith("before:"):
        bound = raw[len("before:"):].strip()
        if not bound:
            return None
        return {"relation": "before", "version": bound}
    if lowered.startswith("up_to:"):
        bound = raw[len("up_to:"):].strip()
        if not bound:
            return None
        return {"relation": "up_to", "version": bound}
    return None


def _version_letters(version_text):
    # type: (str) -> str
    """All letters of a version string, lowercased, in order.

    Used as a tie-break signature: '4.30.5M' -> 'm', '21.4R2' -> 'r'.
    """
    return "".join(ch for ch in str(version_text or "").lower()
                   if ch.isalpha())


def _compare_versions(device_text, bound_text):
    # type: (str, str) -> Optional[int]
    """Compare two versions numerically: -1, 0, or 1.

    Returns None when either side is unparseable, or when the numeric
    tuples are EQUAL but the letter signatures differ (e.g. device
    4.30.5F vs bound 4.30.5M): suffix ordering is vendor-specific, so
    that case is unknown and must never be guessed.
    """
    device_tuple = parse_version(device_text)
    bound_tuple = parse_version(bound_text)
    if device_tuple is None or bound_tuple is None:
        return None
    width = max(len(device_tuple), len(bound_tuple))
    padded_device = device_tuple + (0,) * (width - len(device_tuple))
    padded_bound = bound_tuple + (0,) * (width - len(bound_tuple))
    if padded_device < padded_bound:
        return -1
    if padded_device > padded_bound:
        return 1
    if _version_letters(device_text) != _version_letters(bound_text):
        return None
    return 0


def constraint_matches(device_version, constraint):
    # type: (str, Dict[str, Any]) -> Optional[bool]
    """Evaluate one structured constraint against a device version.

    before:       device < bound
    up_to:        device <= bound
    train_before: device major.minor digits == train digits AND
                  device < bound
    Returns None when the comparison cannot be made.
    """
    if not isinstance(constraint, dict):
        return None
    relation = constraint.get("relation")
    bound = constraint.get("version")
    if not bound:
        return None
    if relation == "train_before":
        train_tuple = parse_version(constraint.get("train"))
        device_tuple = parse_version(device_version)
        if train_tuple is None or device_tuple is None:
            return None
        if device_tuple[:len(train_tuple)] != train_tuple:
            return False
        compared = _compare_versions(device_version, bound)
        if compared is None:
            return None
        return compared < 0
    compared = _compare_versions(device_version, bound)
    if compared is None:
        return None
    if relation == "before":
        return compared < 0
    if relation == "up_to":
        return compared <= 0
    return None


# --------------------------------------------------------------------------
# Local derivation of version constraints from prose statements
# --------------------------------------------------------------------------

_BOUND_BEFORE_RE = re.compile(
    r"\b(prior\s+to|before|earlier\s+than)\b", re.IGNORECASE)
_BOUND_UP_TO_RE = re.compile(
    r"\b(and\s+earlier|or\s+earlier|up\s+to\s+and\s+including)\b",
    re.IGNORECASE)
_BOUND_KEYWORD_RE = re.compile(r"\b(prior|before|earlier)\b",
                               re.IGNORECASE)


# Wording that marks an affected-version item as a prose STATEMENT
# (a bound or a qualifier) rather than a plain version - used both
# by _is_decidable_list_entry and _prefixed_version_token.
_PROSE_ITEM_RE = re.compile(
    r"\b(prior|before|earlier|later|including|versions|releases)\b"
    r"|\bup\s+to\b",
    re.IGNORECASE)


def _is_plain_version_item(text):
    # type: (str) -> bool
    """True when a string is a single decidable version entry.

    Plain entries ("17.9.4", "21.4R2", "17.9.x", "17.9.1-17.9.5",
    "7.0(3)I4(4)") are decided by version_matches directly. Anything
    with whitespace or prose wording is a statement, not a version.
    """
    stripped = str(text or "").strip()
    if not stripped or not stripped[0].isdigit():
        return False
    if any(ch.isspace() for ch in stripped):
        return False
    if not re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z.\-+()]*", stripped):
        return False
    return parse_version(stripped) is not None


def _is_decidable_list_entry(entry):
    # type: (Any) -> bool
    """True when an affected-version entry can decide a device.

    Tolerates spaces around range hyphens ("17.9.1 - 17.9.5") by
    checking the whitespace-free form; multi-word prose stays
    undecidable. Prose wording is checked on the ORIGINAL text
    first: digit-leading prose ("17.9.5 and earlier") would
    otherwise squash into a pseudo-version ("17.9.5andearlier")
    and manufacture a decision the statement never made.
    """
    text = str(entry or "").strip()
    if _PROSE_ITEM_RE.search(text):
        return False
    if _is_plain_version_item(text):
        return True
    squashed = re.sub(r"\s+", "", text)
    return bool(squashed) and squashed[0].isdigit() \
        and _is_plain_version_item(squashed)


def _version_token(text):
    # type: (str) -> Optional[str]
    """First plain-version token in a phrase, or None.

    Vendor prefixes and filler words ("Junos OS", "or later") are
    skipped naturally: they are not plain version items.
    """
    words = re.findall(r"[A-Za-z0-9][A-Za-z0-9.\-+()]*",
                       str(text or ""))
    for word in words:
        token = word.strip(".")
        if _is_plain_version_item(token):
            return token
    return None


def _prefixed_version_token(text):
    # type: (str) -> Optional[str]
    """Version token of a vendor-prefixed version item, or None.

    Live extraction returns affected-version items with vendor
    prefixes - "EOS 4.30.5M", "Junos OS 21.2R1" - which are plain
    versions once the prefix is dropped: exactly one plain-version
    token, no other digit-bearing word, and no prose wording.
    Anything else (bound phrases like "versions prior to X",
    "X and earlier", "up to and including X", or an item carrying
    several version tokens) is a statement, not a version: returns
    None so the item stays undecidable and the constraint
    derivation speaks for it.
    """
    stripped = str(text or "").strip()
    if not stripped or _PROSE_ITEM_RE.search(stripped):
        return None
    words = re.findall(r"[A-Za-z0-9][A-Za-z0-9.\-+()]*", stripped)
    tokens = []  # type: List[str]
    for word in words:
        token = word.strip(".")
        if _is_plain_version_item(token):
            tokens.append(token)
    if len(tokens) != 1:
        return None
    token = tokens[0]
    for word in words:
        if word.strip(".") != token \
                and any(ch.isdigit() for ch in word):
            return None
    return token


def _train_token(text):
    # type: (str) -> Optional[str]
    """Release-train prefix from a wildcard token ("4.30.x" -> "4.30")."""
    for word in re.findall(r"[A-Za-z0-9][A-Za-z0-9.]*",
                           str(text or "")):
        parts = word.strip(".").split(".")
        if len(parts) >= 2 and parts[-1].lower() == "x" \
                and all(p.isdigit() for p in parts[:-1]):
            return ".".join(parts[:-1])
    return None


def derive_version_constraints(affected_versions, fixed_version=None):
    # type: (Any, Optional[str]) -> List[Dict[str, Any]]
    """Derive structured constraints from prose affected statements.

    Rules (all deterministic, shared by the mock and live paths):
    - An item containing a bound phrase yields a constraint whose
      bound is the version token in that item: "prior to / before /
      earlier than X" -> before:X; "X and earlier / or earlier /
      up to and including X" -> up_to:X; a wildcard train token in
      the item ("4.30.x ... prior to 4.30.6M") -> train_before.
    - Conservative fallback: when NO item is a plain decidable
      version, at least one item carries a bound keyword, and a
      fixed version is stated, derive before:<fixed version token>.
    - Plain version items never yield constraints, and vague prose
      without a bound keyword yields none either.

    Returned entries carry "confidence": None (locally derived, not
    an extractor probability).
    """
    items = []  # type: List[str]
    if isinstance(affected_versions, str):
        items = [affected_versions]
    elif isinstance(affected_versions, (list, tuple)):
        items = [str(v) for v in affected_versions]

    derived = []  # type: List[Dict[str, Any]]
    seen = set()  # type: set

    def _add(entry):
        # type: (Dict[str, Any]) -> None
        key = (entry["relation"], entry["version"], entry.get("train"))
        if key not in seen:
            seen.add(key)
            derived.append(entry)

    any_plain = any(_is_plain_version_item(item) for item in items)
    bound_keyword_seen = False
    for item in items:
        if _is_plain_version_item(item):
            continue
        if _BOUND_KEYWORD_RE.search(item):
            bound_keyword_seen = True
        before_match = _BOUND_BEFORE_RE.search(item)
        up_to_match = _BOUND_UP_TO_RE.search(item)
        if before_match:
            token = _version_token(item[before_match.end():]) \
                or _version_token(item)
            if token and not token.lower().endswith(".x"):
                train = _train_token(item)
                if train:
                    _add({"relation": "train_before", "train": train,
                          "version": token, "confidence": None})
                else:
                    _add({"relation": "before", "version": token,
                          "confidence": None})
        elif up_to_match:
            token = _version_token(item[:up_to_match.start()]) \
                or _version_token(item)
            if token and not token.lower().endswith(".x"):
                _add({"relation": "up_to", "version": token,
                      "confidence": None})

    if not derived and not any_plain and bound_keyword_seen \
            and fixed_version:
        token = _version_token(str(fixed_version))
        if token and not token.lower().endswith(".x"):
            _add({"relation": "before", "version": token,
                  "confidence": None})
    return derived


# --------------------------------------------------------------------------
# Product matching + deterministic matcher (0 API calls)
# --------------------------------------------------------------------------

def _product_core(product_text):
    # type: (str) -> str
    words = re.findall(r"[a-z0-9]+", str(product_text or "").lower())
    core_words = [w for w in words if w not in GENERIC_PRODUCT_WORDS]
    return "".join(core_words)


def product_matches(device_model, products):
    # type: (str, List[str]) -> bool
    """True when the device model corresponds to any extracted product."""
    model_norm = re.sub(r"[^a-z0-9]", "", str(device_model or "").lower())
    if not model_norm:
        return False
    for product in products or []:
        core = _product_core(product)
        if core and core in model_norm:
            return True
        # Fallback: every significant token of the product appears in model.
        tokens = [w for w in re.findall(r"[a-z0-9]+", str(product).lower())
                  if w not in GENERIC_PRODUCT_WORDS]
        model_tokens = re.findall(r"[a-z0-9]+", str(device_model or "").lower())
        if tokens and all(t in model_tokens for t in tokens):
            return True
    return False


def _row(hostname, model, version, candidate, status, reason,
         condition_gated=False):
    # type: (str, str, str, bool, str, str, bool) -> Dict[str, Any]
    return {
        "hostname": hostname, "model": model, "version": version,
        "candidate": candidate, "status": status, "reason": reason,
        "condition_gated": condition_gated,
    }


def _constraint_reason(reasons, constraint, version):
    # type: (Dict[str, str], Dict[str, Any], str) -> str
    relation = constraint.get("relation")
    bound = constraint.get("version")
    if relation == "train_before":
        return reasons["version_constraint_train_before"] % (
            version, constraint.get("train"), bound)
    if relation == "up_to":
        return reasons["version_constraint_up_to"] % (version, bound)
    return reasons["version_constraint_before"] % (version, bound)


def match_device(device, extracted, lang="en"):
    # type: (Dict[str, str], Dict[str, Any], str) -> Dict[str, Any]
    """Match one device against extracted advisory fields.

    Rules:
    - No product extracted at all            -> CANNOT DETERMINE
    - Device product differs from advisory   -> NOT AFFECTED
    - Product matches, nothing to compare    -> CANNOT DETERMINE
      (no affected versions AND no version constraints)
    - Product matches, version unparseable   -> CANNOT DETERMINE
    - Product matches, version in affected   -> AFFECTED
    - Product matches, version not affected  -> NOT AFFECTED
    - When the explicit affected-version list does not decide the
      device (an entry comparison is inconclusive, the list is
      empty, or its entries are prose statements like "versions
      prior to 21.4R2" that string comparison cannot decide), the
      advisory's version constraints ("before:X" etc., as emitted by
      Extract or derived locally from the prose) decide instead; a
      definitive all-False list of decidable entries is a decision
      and is never overridden by constraints.
    - Affected-list items may carry a vendor prefix ("EOS 4.30.5M",
      "Junos OS 21.2R1" - the shape live extraction returns); those
      are decided via their version token (_prefixed_version_token).
      Items with prose wording are never reduced to a token.
    - Applicability conditions gate AFFECTED: a device that matches
      product and version but whose advisory carries conditions the
      inventory cannot confirm becomes CANNOT DETERMINE
      (condition_gated=True), never AFFECTED.

    `lang` localizes only the human-readable reason string; the
    status values stay the English VERDICT_* constants.
    """
    reasons = REASON_STRINGS[_normalize_lang(lang)]
    products = extracted.get("products") or []
    if isinstance(products, str):
        products = [products]
    affected_versions = extracted.get("affected_versions") or []
    if isinstance(affected_versions, str):
        affected_versions = [affected_versions]
    constraints = _structured_constraints(extracted)
    conditions = _structured_conditions(extracted)

    hostname = device.get("hostname", "")
    model = device.get("model", "")
    version = device.get("version", "")

    if not products:
        return _row(hostname, model, version, False, VERDICT_CANNOT,
                    reasons["no_product"])

    if not product_matches(model, products):
        return _row(hostname, model, version, False,
                    VERDICT_NOT_AFFECTED, reasons["different_product"])

    # Product matches from here on: this device is a candidate.
    if not affected_versions and not constraints:
        return _row(hostname, model, version, True, VERDICT_CANNOT,
                    reasons["no_affected_versions"])

    if parse_version(version) is None:
        return _row(hostname, model, version, True, VERDICT_CANNOT,
                    reasons["unparseable_version"] % version)

    status = None  # type: Optional[str]
    reason = None  # type: Optional[str]

    saw_unknown = False
    decidable_entries = []  # type: List[Any]
    for entry in affected_versions:
        if _is_decidable_list_entry(entry):
            decidable_entries.append(entry)
            continue
        prefixed_token = _prefixed_version_token(entry)
        if prefixed_token is not None:
            # Vendor-prefixed plain version ("EOS 4.30.5M",
            # "Junos OS 21.2R1" - the shape live extraction returns):
            # decidable via its extracted version token.
            decidable_entries.append(prefixed_token)
        else:
            # Prose entries ("Junos OS versions prior to 21.4R2")
            # state a bound, not a version: string comparison cannot
            # decide them, and counting one as a decided non-match
            # would manufacture a false NOT AFFECTED. The derived
            # constraints below speak for these entries instead.
            saw_unknown = True
    for entry in decidable_entries:
        result = version_matches(version, str(entry))
        if result is True:
            status = VERDICT_AFFECTED
            reason = reasons["version_affected"] % (version, entry)
            break
        if result is None:
            saw_unknown = True
    if status is None and decidable_entries and not saw_unknown:
        # Every decidable list entry was compared and none matched:
        # the list decided. Constraints must not override a decided
        # list.
        status = VERDICT_NOT_AFFECTED
        reason = reasons["version_not_affected"] % version

    if status is None and constraints:
        # The list did not decide (inconclusive entry, or empty):
        # fall back to the normalized prose constraints.
        outcomes = [(constraint_matches(version, c), c)
                    for c in constraints]
        matched = [c for outcome, c in outcomes if outcome is True]
        if matched:
            status = VERDICT_AFFECTED
            reason = _constraint_reason(reasons, matched[0], version)
        elif any(outcome is None for outcome, _c in outcomes):
            status = VERDICT_CANNOT
            reason = reasons["version_inconclusive"]
        else:
            status = VERDICT_NOT_AFFECTED
            reason = reasons["version_constraint_not_satisfied"] % version

    if status is None:
        if saw_unknown:
            status = VERDICT_CANNOT
            reason = reasons["version_inconclusive"]
        else:
            status = VERDICT_CANNOT
            reason = reasons["no_affected_versions"]

    if status == VERDICT_AFFECTED and conditions:
        # Applicability gate: matching product and version is not
        # enough when the advisory only applies under conditions the
        # inventory does not speak to (Arista 0201 pattern).
        condition_text = "; ".join(c["text"] for c in conditions)
        return _row(hostname, model, version, True, VERDICT_CANNOT,
                    reasons["condition_gate"] % condition_text,
                    condition_gated=True)

    return _row(hostname, model, version, True, status, reason or "")


def match_inventory(devices, extracted, lang="en"):
    # type: (List[Dict[str, str]], Dict[str, Any], str) -> List[Dict[str, Any]]
    return [match_device(device, extracted, lang=lang) for device in devices]


def base_verdict(device_results):
    # type: (List[Dict[str, Any]]) -> str
    if any(r.get("status") == VERDICT_AFFECTED for r in device_results):
        return VERDICT_AFFECTED
    if any(r.get("status") == VERDICT_CANNOT and r.get("candidate")
           for r in device_results):
        return VERDICT_CANNOT
    if any(r.get("status") == VERDICT_CANNOT for r in device_results):
        # Only reachable when extraction itself was insufficient
        # (e.g. no product named) - that is a genuine cannot-determine.
        if device_results and all(r.get("status") == VERDICT_CANNOT
                                  for r in device_results):
            return VERDICT_CANNOT
    return VERDICT_NOT_AFFECTED


# --------------------------------------------------------------------------
# Defensive parsing of Clocked responses
# --------------------------------------------------------------------------

def _item_plain_value(item):
    # type: (Any) -> Any
    """Plain value of one list-field item (wrapped dict or plain)."""
    if isinstance(item, dict) and "value" in item:
        return item.get("value")
    return item


def _plain_field_value(entry):
    # type: (Any) -> Any
    """Plain value of one raw extract field.

    The field-level "value" is authoritative when it carries data,
    but the live API sometimes leaves it empty (or holds still-
    wrapped item dicts) while the extracted spans live only in the
    "items" array - observed live for applicability_conditions,
    whose multi-line span never reached the plain fields when only
    "value" was consulted. Fall back to the items in that case so a
    returned extraction is never silently dropped.
    """
    if not isinstance(entry, dict):
        return entry
    if "value" not in entry and "items" not in entry:
        return entry
    items = entry.get("items")
    item_values = []  # type: List[Any]
    if isinstance(items, list):
        item_values = [_item_plain_value(item) for item in items]
    value = entry.get("value")
    if isinstance(value, list):
        plain_items = [_item_plain_value(item) for item in value]
        if plain_items:
            return plain_items
        return item_values
    if value is None:
        if item_values:
            return item_values
        return None
    if isinstance(value, dict) and "value" in value:
        return value.get("value")
    return value


def unwrap_extract_fields(fields):
    # type: (Any) -> Dict[str, Any]
    """Unwrap Clocked extract fields to plain values.

    Real API shape: fields[name] is an object
    {"value": <scalar or list>, "start": ..., "end": ...,
     "confidence": ..., "p_verify": ...} (list fields also carry
    "items": [{value, start, end, confidence}, ...]).
    Internal code (matcher, claim builder, UI) works on the plain
    values only; the raw object stays available via extract_raw.
    Plain (already-unwrapped) values pass through unchanged, so live
    and mock responses share this one unwrap path.
    """
    plain = {}  # type: Dict[str, Any]
    if not isinstance(fields, dict):
        return plain
    for name, entry in fields.items():
        plain[name] = _plain_field_value(entry)
    return plain


def unwrap_extract_result(extract_result):
    # type: (Any) -> Tuple[Dict[str, Any], Dict[str, Any]]
    """Return (plain fields, raw fields dict) for an extract result.

    Accepts either a full result {"fields": {...}} or a bare fields
    dict. Raw fields are returned untouched (positions/confidence).
    """
    raw_fields = {}  # type: Dict[str, Any]
    if isinstance(extract_result, dict):
        nested = extract_result.get("fields")
        if isinstance(nested, dict):
            raw_fields = nested
        else:
            raw_fields = extract_result
    return unwrap_extract_fields(raw_fields), raw_fields


def _item_confidence(raw_field, index, fallback=None):
    # type: (Any, int, Optional[float]) -> Optional[float]
    """Best per-item confidence from a raw (wrapped) extract field."""
    if isinstance(raw_field, dict):
        items = raw_field.get("items")
        if isinstance(items, list) and 0 <= index < len(items):
            item = items[index]
            if isinstance(item, dict):
                conf = item.get("confidence")
                if isinstance(conf, (int, float)):
                    return float(conf)
        conf = raw_field.get("confidence")
        if isinstance(conf, (int, float)):
            return float(conf)
    return fallback


def _structured_constraints(extracted):
    # type: (Dict[str, Any]) -> List[Dict[str, Any]]
    """Structured version constraints from an extracted dict.

    Accepts both the normalized form (dicts with a "relation") and
    raw normalized strings ("before:21.4R2"), so the matcher works
    whether or not normalize_extraction has run.
    """
    raw = (extracted or {}).get("version_constraints") or []
    if isinstance(raw, str):
        raw = [raw]
    structured = []  # type: List[Dict[str, Any]]
    for item in raw:
        if isinstance(item, dict) and item.get("relation"):
            structured.append(item)
        elif isinstance(item, str):
            parsed = parse_version_constraint(item)
            if parsed is not None:
                structured.append(parsed)
    return structured


def _structured_conditions(extracted):
    # type: (Dict[str, Any]) -> List[Dict[str, Any]]
    """Applicability conditions as [{"text": ..., "confidence": ...}].

    Reads the normalized "conditions" key first, then the raw
    extracted "applicability_conditions" list of plain strings.
    """
    raw = (extracted or {}).get("conditions")
    if not raw:
        raw = (extracted or {}).get("applicability_conditions") or []
    if isinstance(raw, str):
        raw = [raw]
    conditions = []  # type: List[Dict[str, Any]]
    for item in raw:
        if isinstance(item, dict) and item.get("text"):
            conditions.append({"text": str(item.get("text")),
                               "confidence": item.get("confidence")})
        elif isinstance(item, dict) and isinstance(item.get("value"), str) \
                and item.get("value", "").strip():
            # Still-wrapped item dict that survived unwrapping.
            conditions.append({"text": item["value"],
                               "confidence": item.get("confidence")})
        elif isinstance(item, str) and item.strip():
            conditions.append({"text": item, "confidence": None})
    return conditions


def normalize_extraction(extracted, raw_fields=None):
    # type: (Dict[str, Any], Optional[Dict[str, Any]]) -> Dict[str, Any]
    """Return a copy of plain extracted fields in canonical form.

    - "version_constraints": [{"relation", "version",
      "train" (train_before only), "confidence"}] parsed from the
      normalized strings Extract emitted (unparseable strings are
      dropped - they must never influence a verdict), MERGED with
      constraints derived locally from the prose affected-version
      statements (derive_version_constraints). Dedupe is by
      (relation, version, train); explicit entries win and keep
      their extractor confidence, derived ones carry None.
    - "conditions": [{"text", "confidence"}] from the extracted
      "applicability_conditions" strings (the plain strings stay
      under "applicability_conditions" for display).
    Absent source fields normalize to empty lists (backward
    compatible with advisories that state neither).
    """
    normalized = dict(extracted or {})
    raw_fields = raw_fields or {}

    plain_constraints = normalized.get("version_constraints") or []
    if isinstance(plain_constraints, str):
        plain_constraints = [plain_constraints]
    raw_constraints = raw_fields.get("version_constraints")
    structured = []  # type: List[Dict[str, Any]]
    seen_keys = set()  # type: set
    for index, item in enumerate(plain_constraints):
        if isinstance(item, dict) and item.get("relation"):
            entry = dict(item)
        elif isinstance(item, dict) \
                and isinstance(item.get("value"), str):
            # Still-wrapped item dict that survived unwrapping.
            parsed_constraint = parse_version_constraint(item["value"])
            if parsed_constraint is None:
                continue
            entry = dict(parsed_constraint)
        elif isinstance(item, str):
            parsed_constraint = parse_version_constraint(item)
            if parsed_constraint is None:
                continue
            entry = dict(parsed_constraint)
        else:
            continue
        entry["confidence"] = _item_confidence(
            raw_constraints, index, entry.get("confidence"))
        seen_keys.add((entry.get("relation"), entry.get("version"),
                       entry.get("train")))
        structured.append(entry)
    for derived_entry in derive_version_constraints(
            normalized.get("affected_versions"),
            normalized.get("fixed_version")):
        key = (derived_entry["relation"], derived_entry["version"],
               derived_entry.get("train"))
        if key not in seen_keys:
            seen_keys.add(key)
            structured.append(derived_entry)
    normalized["version_constraints"] = structured

    plain_conditions = normalized.get("applicability_conditions")
    if plain_conditions is None:
        plain_conditions = normalized.get("conditions") or []
    if isinstance(plain_conditions, str):
        plain_conditions = [plain_conditions]
    raw_conditions = raw_fields.get("applicability_conditions")
    conditions = []  # type: List[Dict[str, Any]]
    for index, item in enumerate(plain_conditions):
        if isinstance(item, dict) and item.get("text"):
            entry = {"text": str(item.get("text"))}
            fallback = item.get("confidence")
        elif isinstance(item, dict) \
                and isinstance(item.get("value"), str) \
                and item.get("value", "").strip():
            # Still-wrapped item dict that survived unwrapping.
            entry = {"text": item["value"]}
            fallback = item.get("confidence")
        elif isinstance(item, str) and item.strip():
            entry = {"text": item}
            fallback = None
        else:
            continue
        entry["confidence"] = _item_confidence(
            raw_conditions, index, fallback)
        conditions.append(entry)
    normalized["conditions"] = conditions

    # Workarounds: a plain list of strings for display (the Action
    # block); tolerate a bare string or still-wrapped item dicts.
    plain_workarounds = normalized.get("workarounds") or []
    if isinstance(plain_workarounds, str):
        plain_workarounds = [plain_workarounds]
    workarounds = []  # type: List[str]
    for item in plain_workarounds:
        if isinstance(item, dict) and isinstance(item.get("value"), str):
            item = item["value"]
        if isinstance(item, str) and item.strip():
            workarounds.append(item)
    normalized["workarounds"] = workarounds
    return normalized


def _as_bool_probability(answer_obj):
    # type: (Any) -> Tuple[Optional[bool], Optional[float]]
    """Normalise a decide answer into (bool value, probability of true)."""
    if isinstance(answer_obj, bool):
        return answer_obj, 1.0 if answer_obj else 0.0
    if not isinstance(answer_obj, dict):
        return None, None
    # Real API shape: {"type": "noul", "noul": <float P(true)>}
    noul = answer_obj.get("noul")
    if isinstance(noul, bool):
        return noul, 1.0 if noul else 0.0
    if isinstance(noul, (int, float)):
        prob_noul = float(noul)
        return prob_noul >= 0.5, prob_noul
    prob = None  # type: Optional[float]
    for key in ("probability", "prob", "confidence", "p_true", "score"):
        value = answer_obj.get(key)
        if isinstance(value, (int, float)):
            prob = float(value)
            break
    value_bool = None  # type: Optional[bool]
    for key in ("answer", "value", "result", "decision"):
        raw = answer_obj.get(key)
        if isinstance(raw, bool):
            value_bool = raw
            break
        if isinstance(raw, str):
            lowered = raw.strip().lower()
            if lowered in ("true", "yes"):
                value_bool = True
                break
            if lowered in ("false", "no"):
                value_bool = False
                break
    if value_bool is None and prob is not None:
        value_bool = prob >= 0.5
    if prob is None and value_bool is not None:
        prob = 1.0 if value_bool else 0.0
    return value_bool, prob


def parse_decide(decide_result):
    # type: (Dict[str, Any]) -> Dict[str, Any]
    answers = {}
    if isinstance(decide_result, dict):
        answers = decide_result.get("answers") or {}
    parsed = {}  # type: Dict[str, Any]
    for name in ("urgency_immediate", "urgency_planned", "evidence_sufficient"):
        value_bool, prob = _as_bool_probability(answers.get(name))
        parsed[name] = {"value": value_bool, "probability": prob}
    immediate = parsed.get("urgency_immediate") or {}
    planned = parsed.get("urgency_planned") or {}
    if immediate.get("value"):
        urgency = "immediate"
    elif planned.get("value"):
        urgency = "planned"
    else:
        urgency = "monitor"
    parsed["urgency"] = urgency
    return parsed


def parse_grounding(grounding_result):
    # type: (Dict[str, Any]) -> Dict[str, Any]
    """Parse a Verify (grounding) result.

    Real API shape: {"grounded": float, "ungrounded": float,
    "verdict": "grounded"|"ungrounded", "threshold": 0.5,
    "answers_question": <float probability>, "claims": [...]}.

    Supported iff the top-level verdict is exactly "grounded" OR the
    grounded probability is >= 0.5. Exact matching matters: the old
    substring check matched "grounded" inside "ungrounded" and wrongly
    marked rejected claims as supported.
    """
    empty = {"verdict": "", "answers_question": None, "supported": False,
             "grounded": None, "ungrounded": None}
    if not isinstance(grounding_result, dict):
        return empty
    verdict_text = str(grounding_result.get("verdict") or "").strip().lower()

    def _prob(key):
        # type: (str) -> Optional[float]
        raw = grounding_result.get(key)
        if isinstance(raw, bool):
            return 1.0 if raw else 0.0
        if isinstance(raw, (int, float)):
            return float(raw)
        return None

    grounded_prob = _prob("grounded")
    ungrounded_prob = _prob("ungrounded")

    answers_raw = grounding_result.get("answers_question")
    answers_question = None  # type: Optional[bool]
    if isinstance(answers_raw, bool):
        answers_question = answers_raw
    elif isinstance(answers_raw, (int, float)):
        answers_question = float(answers_raw) >= 0.5

    if verdict_text == "grounded":
        supported = True
    elif verdict_text == "ungrounded":
        supported = False
    elif grounded_prob is not None:
        supported = grounded_prob >= 0.5
    elif verdict_text in ("supported", "verified", "true", "pass"):
        supported = True
    elif verdict_text in ("unsupported", "contradicted", "insufficient",
                          "insufficient_evidence", "false", "unverified",
                          "not_stated", "no evidence"):
        supported = False
    elif answers_question is not None:
        supported = answers_question
    else:
        supported = False
    return {
        "verdict": verdict_text,
        "answers_question": answers_question,
        "supported": supported,
        "grounded": grounded_prob,
        "ungrounded": ungrounded_prob,
    }


# --------------------------------------------------------------------------
# Verdict composition (pure, testable offline)
# --------------------------------------------------------------------------

def compose_verdict(device_results, decide_parsed, grounding_parsed,
                    lang="en", conditions=None):
    # type: (List[Dict[str, Any]], Dict[str, Any], Dict[str, Any], str, Optional[List[str]]) -> Dict[str, Any]
    warnings_text = WARNING_STRINGS[_normalize_lang(lang)]
    verdict = base_verdict(device_results)
    warnings = []  # type: List[str]
    urgency = str(decide_parsed.get("urgency") or "monitor")

    if conditions:
        # The condition gate lives in the matcher (it applies
        # regardless of Decide's evidence probability); composition
        # only surfaces what has to be checked.
        warnings.append(
            warnings_text["condition_check"] % "; ".join(conditions))

    evidence = decide_parsed.get("evidence_sufficient") or {}
    evidence_prob = evidence.get("probability")
    evidence_value = evidence.get("value")
    low_sufficiency = False
    if evidence_value is False:
        low_sufficiency = True
    if isinstance(evidence_prob, (int, float)) and evidence_prob < 0.5:
        low_sufficiency = True
    if low_sufficiency:
        verdict = VERDICT_CANNOT
        warnings.append(
            warnings_text["low_sufficiency"] % (
                "unknown" if evidence_prob is None
                else "%.4g" % float(evidence_prob))
        )

    if not grounding_parsed.get("supported"):
        verdict = VERDICT_CANNOT
        warnings.append(
            warnings_text["grounding"] % (
                grounding_parsed.get("verdict"),
                grounding_parsed.get("answers_question"))
        )

    return {"verdict": verdict, "urgency": urgency, "warnings": warnings}


def _products_text(extracted):
    # type: (Dict[str, Any]) -> str
    raw_products = extracted.get("products") or []
    if isinstance(raw_products, str):
        return raw_products
    # Plain (unwrapped) representation: a list of product names.
    return ", ".join(str(p) for p in raw_products)


def build_claim(verdict, device_results, extracted):
    # type: (str, List[Dict[str, Any]], Dict[str, Any]) -> str
    advisory_id = extracted.get("advisory_id") or "the advisory"
    affected = [r for r in device_results if r.get("status") == VERDICT_AFFECTED]
    if verdict == VERDICT_AFFECTED and affected:
        first = affected[0]
        return ("%s affects %s (%s, version %s), which is present in the inventory."
                % (advisory_id, first.get("model"), first.get("hostname"),
                   first.get("version")))
    if verdict == VERDICT_NOT_AFFECTED:
        products = _products_text(extracted) or "the named products"
        return ("No device in the inventory is affected: the advisory covers %s, "
                "and no inventoried device runs an affected version." % products)
    if verdict == VERDICT_CANNOT:
        # Condition-gated case: state BOTH the product/version match
        # and the unconfirmed condition, so Verify can check the
        # claim against the advisory + inventory documents.
        conditions = _structured_conditions(extracted)
        gated = [r for r in device_results if r.get("condition_gated")]
        if conditions and gated:
            first = gated[0]
            condition_text = "; ".join(c["text"] for c in conditions)
            return (
                "%s covers %s; %s (%s, version %s) matches the affected "
                "product and version, but the advisory applies only "
                "when: %s. The inventory does not state whether this "
                "condition holds, so affectedness cannot be determined."
                % (advisory_id, _products_text(extracted),
                   first.get("model"), first.get("hostname"),
                   first.get("version"), condition_text))
    return ("The available advisory information is insufficient to determine "
            "whether any inventoried device is affected by %s." % advisory_id)


CHECKLIST_STRINGS = {
    "en": {
        "affected_immediate": [
            "Open an urgent change/incident record for the affected device(s) today.",
            "Restrict management access to trusted networks as an interim workaround.",
            "Schedule installation of the fixed version before the advisory deadline.",
            "Snapshot configs and verify backups before upgrading.",
            "Re-run this triage after the upgrade to confirm the verdict clears.",
        ],
        "affected_planned": [
            "Open a planned change record for the affected device(s).",
            "Schedule the fixed-version upgrade inside the next maintenance window.",
            "Verify config backups before the change window.",
            "Re-run this triage after the upgrade to confirm the verdict clears.",
        ],
        "affected_monitor": [
            "Record the affected device(s) on the watch list.",
            "Plan the fixed-version upgrade in a routine maintenance window.",
            "Re-check the advisory for updates before the deadline.",
        ],
        "not_affected": [
            "File this triage result with the advisory for audit evidence.",
            "No device change is required for this advisory.",
            "Re-run if the inventory changes or the advisory is revised.",
        ],
        "cannot_determine": [
            "Do NOT treat this as 'not affected' - the evidence is insufficient.",
            "Obtain the authoritative advisory with affected and fixed versions.",
            "Confirm the exact OS version of every candidate device.",
            "Re-run this triage once complete version information is available.",
        ],
    },
    "ko": {
        "affected_immediate": [
            "오늘 안에 영향받는 장비에 대한 긴급 변경/장애 대응 기록을 여세요.",
            "임시 조치로 관리 접근을 신뢰할 수 있는 네트워크로 제한하세요.",
            "권고문 기한 전에 수정 버전을 설치할 일정을 잡으세요.",
            "업그레이드 전에 설정을 백업하고 백업이 정상인지 확인하세요.",
            "업그레이드 후 이 판정을 다시 실행해 판정이 해소됐는지 확인하세요.",
        ],
        "affected_planned": [
            "영향받는 장비에 대한 계획 변경 기록을 여세요.",
            "다음 정기 점검 시간 안에 수정 버전 업그레이드를 일정에 넣으세요.",
            "변경 작업 전에 설정 백업을 확인하세요.",
            "업그레이드 후 이 판정을 다시 실행해 판정이 해소됐는지 확인하세요.",
        ],
        "affected_monitor": [
            "영향받는 장비를 주시 목록에 등록하세요.",
            "정기 점검 시간에 수정 버전 업그레이드를 계획하세요.",
            "기한 전에 권고문이 업데이트됐는지 다시 확인하세요.",
        ],
        "not_affected": [
            "이 판정 결과를 권고문과 함께 감사 근거로 보관하세요.",
            "이 권고문으로는 장비 변경이 필요하지 않습니다.",
            "인벤토리가 바뀌거나 권고문이 개정되면 다시 실행하세요.",
        ],
        "cannot_determine": [
            "이 결과를 '해당 없음'으로 취급하지 마세요 - 근거가 충분하지 않습니다.",
            "영향받는 버전과 수정 버전이 명시된 공식 권고문을 확보하세요.",
            "후보 장비 전체의 정확한 OS 버전을 확인하세요.",
            "버전 정보가 완비되면 이 판정을 다시 실행하세요.",
        ],
    },
}


CONDITION_CHECK_STRINGS = {
    "en": {
        "generic": (
            "Verify whether this condition holds on each candidate "
            "device: %s"
        ),
        "terminattr": (
            "On each matched device, check the running configuration "
            "for TerminAttr / CloudVision (CVP) configuration (e.g. "
            "'show running-config | include TerminAttr')."
        ),
    },
    "ko": {
        "generic": "후보 장비 각각에서 다음 조건이 충족되는지 확인하세요: %s",
        "terminattr": (
            "후보 장비 각각의 실행 설정에서 TerminAttr / CloudVision(CVP) "
            "설정을 확인하세요 (예: 'show running-config | "
            "include TerminAttr')."
        ),
    },
}


def _condition_check_steps(conditions, lang):
    # type: (List[str], str) -> List[str]
    strings = CONDITION_CHECK_STRINGS[_normalize_lang(lang)]
    steps = []  # type: List[str]
    for condition in conditions:
        if "terminattr" in str(condition).lower():
            steps.append(strings["terminattr"])
        else:
            steps.append(strings["generic"] % condition)
    return steps


def generate_checklist(verdict, urgency, lang="en", conditions=None):
    # type: (str, str, str, Optional[List[str]]) -> List[str]
    checklists = CHECKLIST_STRINGS[_normalize_lang(lang)]
    if verdict == VERDICT_AFFECTED:
        if urgency == "immediate":
            return list(checklists["affected_immediate"])
        if urgency == "planned":
            return list(checklists["affected_planned"])
        return list(checklists["affected_monitor"])
    if verdict == VERDICT_NOT_AFFECTED:
        return list(checklists["not_affected"])
    items = list(checklists["cannot_determine"])
    if conditions:
        # Condition-gated cannot-determine: the fastest path to a
        # firm verdict is verifying each condition, so those steps
        # go first.
        return _condition_check_steps(conditions, lang) + items
    return items


# --------------------------------------------------------------------------
# Mock Mode
# --------------------------------------------------------------------------

def load_mock_responses():
    # type: () -> Dict[str, Any]
    mock_path = ROOT / "mock_responses.json"
    with mock_path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


_SAMPLE_FILE_IDS = {
    "sample1_affected.txt": "sample1",
    "sample2_not_affected.txt": "sample2",
    "sample3_insufficient.txt": "sample3",
    "sample4_arista_affected.txt": "sample4",
    "sample5_juniper_affected.txt": "sample5",
    "sample6_juniper_prior_to.txt": "sample6",
    "sample7_arista_conditional.txt": "sample7",
}


def _exact_sample_match(advisory_text):
    # type: (str) -> Optional[str]
    """The bundled sample whose file content the text exactly is,
    or None. The comparison is a SHA-256 over both sides stripped,
    so trailing-whitespace differences (e.g. a fetched copy) still
    count as the same sample, but any content edit does not."""
    text = advisory_text or ""
    digest = hashlib.sha256(text.strip().encode("utf-8")).hexdigest()
    samples_dir = ROOT / "samples"
    for filename, sid in _SAMPLE_FILE_IDS.items():
        path = samples_dir / filename
        if path.exists():
            sample_digest = hashlib.sha256(
                path.read_text(encoding="utf-8").strip().encode("utf-8")
            ).hexdigest()
            if digest == sample_digest:
                return sid
    return None


def detect_sample_id(advisory_text, sample_id=None):
    # type: (str, Optional[str]) -> Optional[str]
    """Identify the bundled sample a text IS, for Mock Mode.

    Strict on purpose: canned Extract/Decide/Verify responses are
    served ONLY for an exact text match against a bundled sample
    file (see _exact_sample_match). Two weaker signals are NOT
    sufficient, because each was observed serving a canned verdict
    for text it did not describe:

    - a caller-supplied `sample_id` (e.g. a UI picker value left
      in session state after the user edited or replaced the
      loaded sample's text) - it is treated as a hint that must
      AGREE with the exact match; a disagreeing id fails closed
      and no canned verdict is served at all;
    - the sample's SYN-* marker appearing in the text - a marker
      inside otherwise different (e.g. edited) text proves
      nothing about the rest of the advisory.

    Returns None when the text is not exactly a bundled sample;
    the Mock Mode caller then produces the standing "samples
    only / API key needed" outcome instead of a verdict.
    """
    matched = _exact_sample_match(advisory_text)
    if matched is None:
        return None
    if sample_id is not None and sample_id != matched:
        return None
    return matched


# --------------------------------------------------------------------------
# Live Clocked calls (the ONLY place the SDK is used)
# --------------------------------------------------------------------------

def _get_api_key(explicit_key=None):
    # type: (Optional[str]) -> Optional[str]
    if explicit_key:
        return explicit_key
    env_key = os.environ.get("CLOCKED_API_KEY")
    if env_key:
        return env_key
    try:
        import streamlit as st  # local import: triage must work without UI
        secrets_key = st.secrets.get("CLOCKED_API_KEY")  # type: ignore
        if secrets_key:
            return str(secrets_key)
    except Exception:
        pass
    return None


def _make_client(api_key):
    # type: (str) -> Any
    from clocked_sdk import Clocked  # SDK import lives only in this module
    try:
        return Clocked(api_key=api_key, base_url=BASE_URL)
    except TypeError:
        try:
            return Clocked(api_key)
        except TypeError:
            return Clocked(api_key=api_key)


def is_credit_error(exc):
    # type: (BaseException) -> bool
    """True when a live-call failure is Clocked credit exhaustion
    (HTTP 402: the account's credit allowance / spending limit has
    been reached), as opposed to a transient or per-request error.

    Duck-typed on purpose - this module never imports the SDK
    outside _make_client: the SDK exception's class name carries
    "InsufficientCredits", and its message (like any HTTP-level
    rendering of the same 402) names the "credit allowance" or
    the "spending limit". Credit exhaustion is terminal for the
    whole run - every later call would fail the same way - so
    callers fail fast on it instead of retrying per item.
    """
    if "InsufficientCredits" in exc.__class__.__name__:
        return True
    message = str(exc).lower()
    return "credit allowance" in message or \
        "spending limit" in message


# The applicability_conditions field definition is shared verbatim
# by the main extract call and the focused conditions-only call:
# identical description text, so both passes ask for the same thing.
_CONDITIONS_FIELD = {
    "description": (
        "Conditions that must hold for the advisory to apply, "
        "beyond product and version - for example a feature "
        "or configuration that must be enabled - quoted or "
        "closely paraphrased from the advisory. Empty when "
        "the advisory applies to the listed products and "
        "versions unconditionally."
    ),
    "list": True,
}

# Workarounds ride along in the focused extract pass (same
# span-extraction reliability reasoning as conditions) and feed the
# deterministic "Action required" block in the UI.
_WORKAROUNDS_FIELD = {
    "description": (
        "Workarounds, mitigations, or interim protective measures "
        "the advisory itself states - quoted or closely paraphrased "
        "from the advisory. Empty when the advisory states none."
    ),
    "list": True,
}


def _plain_list_strings(plain_fields, field_name):
    # type: (Dict[str, Any], str) -> List[str]
    """Non-empty strings of a list field from plain (unwrapped)
    fields."""
    value = plain_fields.get(field_name)
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        return []
    return [str(v) for v in value
            if isinstance(v, str) and v.strip()]


def _condition_strings(plain_fields):
    # type: (Dict[str, Any]) -> List[str]
    """Non-empty condition strings from plain (unwrapped) fields."""
    return _plain_list_strings(plain_fields, "applicability_conditions")


def _live_extract(client, advisory_text):
    # type: (Any, str) -> Tuple[Dict[str, Any], Dict[str, Any]]
    """Return (plain fields, raw fields) via the shared unwrap path.

    Two Extract calls: the main field set, then a FOCUSED call
    carrying only applicability_conditions and workarounds.
    Measured live, span extraction reliability drops as the field
    count grows: inside the full call the conditions field came
    back empty even when the condition sentence was plainly in the
    text, while the focused call returned it reliably. Per field,
    the focused result wins when it carries values; otherwise the
    main call's value stands (both raw and plain are swapped
    together, so per-item confidences stay attached to the winning
    field).

    The schema deliberately does NOT request a version_constraints
    field: a normalized token ("before:21.4R2") is not a text span,
    so the span extractor never emits one - that field was dead
    weight live. Local derivation from the verbatim prose owns
    constraints (see derive_version_constraints); the parser still
    tolerates the field when a response carries it.
    """
    result = client.extract(
        text=advisory_text,
        instructions=(
            "Extract the fields verbatim from this network security advisory. "
            "Do not infer values that are not stated; leave a field empty "
            "when the advisory does not state it. "
            "applicability_conditions and workarounds are "
            "restatements of what the advisory states, per their "
            "field descriptions."
        ),
        fields={
            "vendor": "Vendor or issuing organisation named in the advisory",
            "products": {"description": "Product names or models affected", "list": True},
            "affected_versions": {"description": "Software versions listed as affected", "list": True},
            "applicability_conditions": _CONDITIONS_FIELD,
            "workarounds": _WORKAROUNDS_FIELD,
            "advisory_id": "Advisory identifier",
            "cve_id": "CVE identifier, if any",
            "severity": "Severity rating as stated",
            "fixed_version": "Fixed / remediated software version, if stated",
            "action_deadline": "Action deadline date, if stated",
        },
    )
    # Real fields are value-wrapped objects; unwrap to plain values
    # here (shared with Mock Mode) and keep the raw objects separate.
    plain, raw = unwrap_extract_result(result)

    focused = client.extract(
        text=advisory_text,
        instructions=(
            "Extract ONLY two fields from this network security "
            "advisory: (1) the applicability conditions - conditions "
            "that must hold for the advisory to apply, beyond product "
            "and version - and (2) the workarounds or mitigations "
            "the advisory states. Do not infer anything that is not "
            "stated; leave a field empty when the advisory states "
            "none."
        ),
        fields={"applicability_conditions": _CONDITIONS_FIELD,
                "workarounds": _WORKAROUNDS_FIELD},
    )
    focused_plain, focused_raw = unwrap_extract_result(focused)
    for field_name in ("applicability_conditions", "workarounds"):
        if _plain_list_strings(focused_plain, field_name):
            plain[field_name] = focused_plain.get(field_name)
            if field_name in focused_raw:
                raw = dict(raw)
                raw[field_name] = focused_raw[field_name]
    return plain, raw


def _live_decide(client, advisory_text, extracted, device_results):
    # type: (Any, str, Dict[str, Any], List[Dict[str, Any]]) -> Dict[str, Any]
    summary_lines = [
        "Advisory fields: %s" % json.dumps(extracted, ensure_ascii=False),
        "Per-device matcher results:",
    ]
    for row in device_results:
        summary_lines.append("- %s (%s, %s): %s - %s" % (
            row.get("hostname"), row.get("model"), row.get("version"),
            row.get("status"), row.get("reason")))
    state = "\n".join(summary_lines) + "\n\nAdvisory text:\n" + advisory_text[:6000]
    result = client.decide(
        state=state,
        questions={
            "urgency_immediate": {
                "type": "noul",
                "instructions": "Is immediate action (today) required?",
                "criteria": {
                    "true": "A device is affected AND severity is High or Critical, or the deadline is imminent.",
                    "false": "No device is affected, or the work can safely wait for a planned window.",
                },
            },
            "urgency_planned": {
                "type": "noul",
                "instructions": "Should the work be scheduled in a planned maintenance window?",
                "criteria": {
                    "true": "A device is affected and remediation should be scheduled, but not necessarily today.",
                    "false": "No device is affected, or action is already immediate, or only monitoring is warranted.",
                },
            },
            "evidence_sufficient": {
                "type": "noul",
                "instructions": "Does the advisory contain enough information to decide affectedness?",
                "criteria": {
                    "true": "The advisory names products AND affected versions (a fixed version is a plus).",
                    "false": "Products or affected versions are missing, so affectedness cannot be decided reliably.",
                },
            },
        },
    )
    return result if isinstance(result, dict) else {}


def _live_grounding(client, advisory_text, inventory_text, claim):
    # type: (Any, str, str, str) -> Dict[str, Any]
    # The claim asserts inventory facts as well as advisory facts
    # (e.g. "device X is present in the inventory"), so Verify must
    # see BOTH source texts; with the advisory alone such a claim is
    # correctly judged not_stated / ungrounded.
    result = client.grounding(
        documents=[
            {"id": "advisory", "text": advisory_text},
            {"id": "inventory", "text": inventory_text},
        ],
        question="Do the advisory and inventory support the following verdict claim?",
        answer=claim,
        evidence="all",
    )
    return result if isinstance(result, dict) else {}


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------

def _live_result(key, advisory_text, inventory_text, devices, lang):
    # type: (str, str, str, List[Dict[str, str]], str) -> Dict[str, Any]
    """The Live Mode pipeline: Extract -> local matcher -> Decide
    -> Verify (grounding), composed into the result dict. Any
    exception from a Clocked call propagates to run_triage, which
    owns the credit-exhaustion translation."""
    client = _make_client(key)
    extracted, extract_raw_fields = _live_extract(client, advisory_text)
    extracted = normalize_extraction(extracted, extract_raw_fields)
    # Matcher runs between extract and decide in live mode too.
    # The copy fed to Decide (and used for the grounding claim)
    # is always English, so API inputs never depend on `lang`;
    # a second, localized copy is produced for display only.
    # Matching is local and deterministic, so this costs no
    # Clocked calls and both copies always agree on status.
    device_results_live = match_inventory(devices, extracted)
    decide_result = _live_decide(client, advisory_text, extracted,
                                 device_results_live)
    decide_parsed_live = parse_decide(decide_result)
    preliminary = base_verdict(device_results_live)
    claim_live = build_claim(preliminary, device_results_live, extracted)
    grounding_result = _live_grounding(
        client, advisory_text, inventory_text, claim_live)
    if lang == "en":
        device_results = device_results_live
    else:
        device_results = match_inventory(devices, extracted, lang=lang)
    decide_parsed = decide_parsed_live
    grounding_parsed = parse_grounding(grounding_result)
    condition_texts = [c["text"]
                       for c in extracted.get("conditions") or []]
    composed = compose_verdict(device_results, decide_parsed,
                               grounding_parsed, lang=lang,
                               conditions=condition_texts)
    final_verdict = composed["verdict"]
    claim = build_claim(final_verdict, device_results, extracted)
    return {
        "mode": "live",
        "sample_id": None,
        "extracted": extracted,
        "extract_raw": {"fields": extract_raw_fields},
        "decide_raw": decide_result,
        "decide": decide_parsed,
        "grounding_raw": grounding_result,
        "grounding": grounding_parsed,
        "device_results": device_results,
        "verdict": final_verdict,
        "urgency": composed["urgency"],
        "warnings": composed["warnings"],
        "conditions": condition_texts,
        "claim": claim,
        "checklist": generate_checklist(final_verdict,
                                        composed["urgency"],
                                        lang=lang,
                                        conditions=condition_texts),
        "clocked_calls": 4,
    }


def run_triage(advisory_text, inventory_text, sample_id=None, api_key=None,
               lang="en", mock=False):
    # type: (str, str, Optional[str], Optional[str], str, bool) -> Dict[str, Any]
    """Run the full pipeline. Returns a result dict for the UI / tests.

    `lang` ("en" default, or "ko") localizes display text only:
    per-device reasons, warnings, the checklist, and the Mock Mode
    notice. Verdict constants, the grounding claim, and every Clocked
    prompt stay English.

    `mock=True` forces Mock Mode (canned responses for the bundled
    samples) even when an API key is configured - the app's Demo
    override threads through here, so no Clocked call is made.
    When Mock Mode then cannot judge arbitrary text, the notice
    wording follows the context: Demo-override wording when a key
    is configured (resolving the key string here only picks the
    wording - it is never used for a call in Mock Mode), no-key
    wording otherwise.
    """
    lang = _normalize_lang(lang)
    devices = parse_inventory(inventory_text)
    key = None if mock else _get_api_key(api_key)
    mode = "live" if key else "mock"

    if mode == "mock":
        detected = detect_sample_id(advisory_text, sample_id)
        if detected is None:
            # The app passes mock=True both for "no key, Mock is
            # the only mode" and for "key configured, Demo override
            # on"; only the latter may use the Demo wording.
            demo_override = mock and bool(_get_api_key(api_key))
            notice_strings = (MOCK_DEMO_ERROR_STRINGS if demo_override
                              else MOCK_ERROR_STRINGS)
            return {
                "mode": mode,
                "error": notice_strings[lang],
                "verdict": None,
                "devices": devices,
            }
        canned = load_mock_responses().get(detected) or {}
        extract_result = canned.get("extract") or {}
        # Mock responses use the real wrapped shapes; the same shared
        # unwrap path as live mode turns them into plain values.
        extracted, _mock_raw_fields = unwrap_extract_result(extract_result)
        extracted = normalize_extraction(extracted, _mock_raw_fields)
        decide_result = canned.get("decide") or {}
        grounding_result = canned.get("grounding") or {}
        used_sample = detected
    else:
        try:
            return _live_result(str(key), advisory_text, inventory_text,
                                devices, lang)
        except Exception as exc:
            if not is_credit_error(exc):
                raise
            # Credit exhaustion is terminal for the run: the
            # exception already stopped the call sequence, and the
            # result carries the flag (plus the raw error detail)
            # instead of a verdict, so the UI can banner it and
            # batch runners can fail fast without further calls.
            return {
                "mode": mode,
                "credit_exhausted": True,
                "error": str(exc) or exc.__class__.__name__,
                "verdict": None,
                "devices": devices,
            }

    # Mock path composition (shared logic with live path).
    device_results = match_inventory(devices, extracted, lang=lang)
    decide_parsed = parse_decide(decide_result)
    grounding_parsed = parse_grounding(grounding_result)
    condition_texts = [c["text"]
                       for c in extracted.get("conditions") or []]
    composed = compose_verdict(device_results, decide_parsed,
                               grounding_parsed, lang=lang,
                               conditions=condition_texts)
    final_verdict = composed["verdict"]
    claim = build_claim(final_verdict, device_results, extracted)
    return {
        "mode": mode,
        "sample_id": used_sample,
        "extracted": extracted,
        "extract_raw": extract_result,
        "decide_raw": decide_result,
        "decide": decide_parsed,
        "grounding_raw": grounding_result,
        "grounding": grounding_parsed,
        "device_results": device_results,
        "verdict": final_verdict,
        "urgency": composed["urgency"],
        "warnings": composed["warnings"],
        "conditions": condition_texts,
        "claim": claim,
        "checklist": generate_checklist(final_verdict,
                                        composed["urgency"], lang=lang,
                                        conditions=condition_texts),
        "clocked_calls": 4,
    }
