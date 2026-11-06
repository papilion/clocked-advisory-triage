"""Core triage logic for Advisory Triage for Network Operators.

All Clocked SDK access lives in this module (and nowhere else).
Pipeline per run (exactly 3 Clocked calls in live mode):
  1. extract   - pull structured fields from the advisory text
  2. (local)   - deterministic matcher: extracted product/version vs inventory
  3. decide    - urgency + evidence sufficiency, with probabilities
  4. grounding - Verify step: check the verdict claim against the
                 advisory AND the inventory it was matched against

Mock Mode: when no CLOCKED_API_KEY is available, canned responses from
mock_responses.json are used for the three bundled samples. Arbitrary
pasted text in Mock Mode does NOT get a fabricated verdict; the caller
is told a key is needed for live analysis.

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


def match_device(device, extracted):
    # type: (Dict[str, str], Dict[str, Any]) -> Dict[str, Any]
    """Match one device against extracted advisory fields.

    Rules:
    - No product extracted at all            -> CANNOT DETERMINE
    - Device product differs from advisory   -> NOT AFFECTED
    - Product matches, no affected versions  -> CANNOT DETERMINE
    - Product matches, version unparseable   -> CANNOT DETERMINE
    - Product matches, version in affected   -> AFFECTED
    - Product matches, version not affected  -> NOT AFFECTED
    """
    products = extracted.get("products") or []
    if isinstance(products, str):
        products = [products]
    affected_versions = extracted.get("affected_versions") or []
    if isinstance(affected_versions, str):
        affected_versions = [affected_versions]

    hostname = device.get("hostname", "")
    model = device.get("model", "")
    version = device.get("version", "")

    if not products:
        return {
            "hostname": hostname, "model": model, "version": version,
            "candidate": False, "status": VERDICT_CANNOT,
            "reason": "Advisory extraction named no product; cannot determine.",
        }

    if not product_matches(model, products):
        return {
            "hostname": hostname, "model": model, "version": version,
            "candidate": False, "status": VERDICT_NOT_AFFECTED,
            "reason": "Device product is not one of the products named in the advisory.",
        }

    # Product matches from here on: this device is a candidate.
    if not affected_versions:
        return {
            "hostname": hostname, "model": model, "version": version,
            "candidate": True, "status": VERDICT_CANNOT,
            "reason": "Product matches, but the advisory states no affected versions.",
        }

    if parse_version(version) is None:
        return {
            "hostname": hostname, "model": model, "version": version,
            "candidate": True, "status": VERDICT_CANNOT,
            "reason": "Product matches, but the device version %r is unparseable." % version,
        }

    saw_unknown = False
    for entry in affected_versions:
        result = version_matches(version, str(entry))
        if result is True:
            return {
                "hostname": hostname, "model": model, "version": version,
                "candidate": True, "status": VERDICT_AFFECTED,
                "reason": "Version %s is listed as affected (%s)." % (version, entry),
            }
        if result is None:
            saw_unknown = True

    if saw_unknown:
        return {
            "hostname": hostname, "model": model, "version": version,
            "candidate": True, "status": VERDICT_CANNOT,
            "reason": "Product matches, but version comparison was inconclusive.",
        }

    return {
        "hostname": hostname, "model": model, "version": version,
        "candidate": True, "status": VERDICT_NOT_AFFECTED,
        "reason": "Product matches, but version %s is not in the affected list." % version,
    }


def match_inventory(devices, extracted):
    # type: (List[Dict[str, str]], Dict[str, Any]) -> List[Dict[str, Any]]
    return [match_device(device, extracted) for device in devices]


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

def unwrap_extract_fields(fields):
    # type: (Any) -> Dict[str, Any]
    """Unwrap Clocked extract fields to plain values.

    Real API shape: fields[name] is an object
    {"value": <scalar or list>, "start": ..., "end": ...,
     "confidence": ..., "p_verify": ...} (list fields also carry
    "items": [{value, start, end, confidence}, ...]).
    Internal code (matcher, claim builder, UI) works on the plain
    "value" only; the raw object stays available via extract_raw.
    Plain (already-unwrapped) values pass through unchanged, so live
    and mock responses share this one unwrap path.
    """
    plain = {}  # type: Dict[str, Any]
    if not isinstance(fields, dict):
        return plain
    for name, entry in fields.items():
        if isinstance(entry, dict) and "value" in entry:
            plain[name] = entry.get("value")
        else:
            plain[name] = entry
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

def compose_verdict(device_results, decide_parsed, grounding_parsed):
    # type: (List[Dict[str, Any]], Dict[str, Any], Dict[str, Any]) -> Dict[str, Any]
    verdict = base_verdict(device_results)
    warnings = []  # type: List[str]
    urgency = str(decide_parsed.get("urgency") or "monitor")

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
            "CANNOT DETERMINE: Decide rated the advisory evidence as "
            "insufficient (probability %s)." % (
                "unknown" if evidence_prob is None
                else "%.4g" % float(evidence_prob))
        )

    if not grounding_parsed.get("supported"):
        verdict = VERDICT_CANNOT
        warnings.append(
            "CANNOT DETERMINE: Verify (grounding) did not verify the "
            "verdict claim against the advisory and inventory texts "
            "(verdict=%r, answers_question=%r)." % (
                grounding_parsed.get("verdict"),
                grounding_parsed.get("answers_question"))
        )

    return {"verdict": verdict, "urgency": urgency, "warnings": warnings}


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
        raw_products = extracted.get("products") or []
        if isinstance(raw_products, str):
            products = raw_products
        else:
            # Plain (unwrapped) representation: a list of product names.
            products = ", ".join(str(p) for p in raw_products)
        products = products or "the named products"
        return ("No device in the inventory is affected: the advisory covers %s, "
                "and no inventoried device runs an affected version." % products)
    return ("The available advisory information is insufficient to determine "
            "whether any inventoried device is affected by %s." % advisory_id)


def generate_checklist(verdict, urgency):
    # type: (str, str) -> List[str]
    if verdict == VERDICT_AFFECTED:
        if urgency == "immediate":
            return [
                "Open an urgent change/incident record for the affected device(s) today.",
                "Restrict management access to trusted networks as an interim workaround.",
                "Schedule installation of the fixed version before the advisory deadline.",
                "Snapshot configs and verify backups before upgrading.",
                "Re-run this triage after the upgrade to confirm the verdict clears.",
            ]
        if urgency == "planned":
            return [
                "Open a planned change record for the affected device(s).",
                "Schedule the fixed-version upgrade inside the next maintenance window.",
                "Verify config backups before the change window.",
                "Re-run this triage after the upgrade to confirm the verdict clears.",
            ]
        return [
            "Record the affected device(s) on the watch list.",
            "Plan the fixed-version upgrade in a routine maintenance window.",
            "Re-check the advisory for updates before the deadline.",
        ]
    if verdict == VERDICT_NOT_AFFECTED:
        return [
            "File this triage result with the advisory for audit evidence.",
            "No device change is required for this advisory.",
            "Re-run if the inventory changes or the advisory is revised.",
        ]
    return [
        "Do NOT treat this as 'not affected' - the evidence is insufficient.",
        "Obtain the authoritative advisory with affected and fixed versions.",
        "Confirm the exact OS version of every candidate device.",
        "Re-run this triage once complete version information is available.",
    ]


# --------------------------------------------------------------------------
# Mock Mode
# --------------------------------------------------------------------------

def load_mock_responses():
    # type: () -> Dict[str, Any]
    mock_path = ROOT / "mock_responses.json"
    with mock_path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def detect_sample_id(advisory_text, sample_id=None):
    # type: (str, Optional[str]) -> Optional[str]
    if sample_id:
        return sample_id
    text = advisory_text or ""
    markers = {
        "SYN-CSC-2026-1101": "sample1",
        "SYN-JUN-2026-1102": "sample2",
        "SYN-KISA-2026-1103": "sample3",
    }
    for marker, sid in markers.items():
        if marker in text:
            return sid
    digest = hashlib.sha256(text.strip().encode("utf-8")).hexdigest()
    samples_dir = ROOT / "samples"
    file_map = {
        "sample1_affected.txt": "sample1",
        "sample2_not_affected.txt": "sample2",
        "sample3_insufficient.txt": "sample3",
    }
    for filename, sid in file_map.items():
        path = samples_dir / filename
        if path.exists():
            sample_digest = hashlib.sha256(
                path.read_text(encoding="utf-8").strip().encode("utf-8")
            ).hexdigest()
            if digest == sample_digest:
                return sid
    return None


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


def _live_extract(client, advisory_text):
    # type: (Any, str) -> Tuple[Dict[str, Any], Dict[str, Any]]
    """Return (plain fields, raw fields) via the shared unwrap path."""
    result = client.extract(
        text=advisory_text,
        instructions=(
            "Extract the fields verbatim from this network security advisory. "
            "Do not infer values that are not stated; leave a field empty "
            "when the advisory does not state it."
        ),
        fields={
            "vendor": "Vendor or issuing organisation named in the advisory",
            "products": {"description": "Product names or models affected", "list": True},
            "affected_versions": {"description": "Software versions listed as affected", "list": True},
            "advisory_id": "Advisory identifier",
            "cve_id": "CVE identifier, if any",
            "severity": "Severity rating as stated",
            "fixed_version": "Fixed / remediated software version, if stated",
            "action_deadline": "Action deadline date, if stated",
        },
    )
    # Real fields are value-wrapped objects; unwrap to plain values
    # here (shared with Mock Mode) and keep the raw objects separate.
    return unwrap_extract_result(result)


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

def run_triage(advisory_text, inventory_text, sample_id=None, api_key=None):
    # type: (str, str, Optional[str], Optional[str]) -> Dict[str, Any]
    """Run the full pipeline. Returns a result dict for the UI / tests."""
    devices = parse_inventory(inventory_text)
    key = _get_api_key(api_key)
    mode = "live" if key else "mock"

    if mode == "mock":
        detected = detect_sample_id(advisory_text, sample_id)
        if detected is None:
            return {
                "mode": mode,
                "error": (
                    "Mock Mode: no CLOCKED_API_KEY is configured, so live "
                    "analysis is unavailable. Use one of the bundled samples "
                    "for the demo, or set CLOCKED_API_KEY for live analysis "
                    "of arbitrary text."
                ),
                "verdict": None,
                "devices": devices,
            }
        canned = load_mock_responses().get(detected) or {}
        extract_result = canned.get("extract") or {}
        # Mock responses use the real wrapped shapes; the same shared
        # unwrap path as live mode turns them into plain values.
        extracted, _mock_raw_fields = unwrap_extract_result(extract_result)
        decide_result = canned.get("decide") or {}
        grounding_result = canned.get("grounding") or {}
        used_sample = detected
    else:
        client = _make_client(str(key))
        extracted, extract_raw_fields = _live_extract(client, advisory_text)
        decide_result = {}
        grounding_result = {}
        used_sample = None
        # Matcher runs between extract and decide in live mode too;
        # device_results is computed below before decide is called.
        device_results_live = match_inventory(devices, extracted)
        decide_result = _live_decide(client, advisory_text, extracted,
                                     device_results_live)
        decide_parsed_live = parse_decide(decide_result)
        preliminary = base_verdict(device_results_live)
        claim_live = build_claim(preliminary, device_results_live, extracted)
        grounding_result = _live_grounding(
            client, advisory_text, inventory_text, claim_live)
        # Reuse the shared composition path below.
        device_results = device_results_live
        decide_parsed = decide_parsed_live
        grounding_parsed = parse_grounding(grounding_result)
        composed = compose_verdict(device_results, decide_parsed, grounding_parsed)
        final_verdict = composed["verdict"]
        claim = build_claim(final_verdict, device_results, extracted)
        return {
            "mode": mode,
            "sample_id": used_sample,
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
            "claim": claim,
            "checklist": generate_checklist(final_verdict, composed["urgency"]),
            "clocked_calls": 3,
        }

    # Mock path composition (shared logic with live path).
    device_results = match_inventory(devices, extracted)
    decide_parsed = parse_decide(decide_result)
    grounding_parsed = parse_grounding(grounding_result)
    composed = compose_verdict(device_results, decide_parsed, grounding_parsed)
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
        "claim": claim,
        "checklist": generate_checklist(final_verdict, composed["urgency"]),
        "clocked_calls": 3,
    }
