"""Batch-mode support for Advisory Triage for Network Operators.

Everything the batch workflow needs that is NOT Clocked access (all
Clocked SDK use stays in triage.py):

  - parse_inventory_csv: a full device inventory uploaded as CSV
    (flexible headers, CP949-friendly decoding) turned into the
    canonical "host, model, version" text parse_inventory accepts.
  - parse_link_list: the advisory-URL list from the UI, cleaned and
    capped at MAX_LINKS.
  - fetch_advisory_text: download one advisory page with urllib and
    reduce HTML to readable text with a stdlib html.parser extractor
    (no new dependencies).
  - run_batch: fetch + triage each link independently against one
    inventory; one failure never aborts the batch. The fetcher is
    injectable so tests run fully offline.

Python 3.9 compatible: typing.Optional / Union only, no PEP 604 unions.
"""

import csv
import datetime
import os
import io
import json
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from triage import (GENERIC_PRODUCT_WORDS, REASON_STRINGS,
                    VERDICT_AFFECTED, VERDICT_CANNOT,
                    VERDICT_CONDITION, VERDICT_NOT_AFFECTED,
                    _compare_versions,
                    _compare_versions_detail, _normalize_lang,
                    _product_core, _row, build_claim,
                    generate_checklist, is_credit_error, parse_inventory,
                    product_matches, run_triage, version_matches,
                    version_matches_detail)

MAX_LINKS = 10
HARVEST_CAP = 15
MAX_DOWNLOAD_BYTES = 2 * 1024 * 1024
MAX_TEXT_CHARS = 40000
FETCH_TIMEOUT = 15

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0 Safari/537.36 AdvisoryTriage/1.0"
)


class FetchError(Exception):
    """One advisory link could not be fetched (short reason as text).

    Optional structured attributes (defaults keep every existing
    raise/except site working): `status` is the HTTP status when
    one is known, `retry_after` the parsed Retry-After seconds,
    `content_type` the response content type when known."""

    def __init__(self, message, status=None, retry_after=None,
                 content_type=""):
        super().__init__(message)
        self.status = status
        self.retry_after = retry_after
        self.content_type = content_type or ""


# ---------------------------------------------------------------------------
# Inventory CSV
# ---------------------------------------------------------------------------

def _norm_header(cell):
    # type: (Any) -> str
    """Normalize a header cell for alias matching: lowercase, no
    spaces/underscores, no BOM."""
    text = str(cell or "").replace("\ufeff", "").strip().lower()
    return re.sub(r"[\s_]+", "", text)


# Normalized alias sets (after _norm_header).
_HEADER_ALIASES = {
    "hostname": {"host", "hostname", "name", "device", "devicename",
                 "장비명", "호스트명", "호스트", "장비", "기기명"},
    "model": {"model", "모델", "장비모델", "모델명", "devicemodel", "기종"},
    "version": {"version", "ver", "os", "osversion", "os버전", "버전",
                "펌웨어", "firmware", "software", "swversion"},
    "vendor": {"vendor", "벤더", "제조사", "manufacturer", "maker", "브랜드"},
}  # type: Dict[str, Any]


def _decode_bytes(data):
    # type: (bytes) -> Tuple[str, str]
    """Decode CSV bytes: utf-8-sig -> utf-8 -> cp949 (Korean Excel)."""
    if data.startswith(b"\xef\xbb\xbf"):
        return data.decode("utf-8-sig"), "utf-8-sig"
    try:
        return data.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        pass
    try:
        return data.decode("cp949"), "cp949"
    except UnicodeDecodeError:
        return data.decode("cp949", errors="replace"), "cp949"


def _map_header(row):
    # type: (List[str]) -> Dict[str, int]
    """Map field name -> column index from a header row ({} if the
    row does not carry hostname+model+version headers)."""
    mapping = {}  # type: Dict[str, int]
    for idx, cell in enumerate(row):
        key = _norm_header(cell)
        if not key:
            continue
        for field, aliases in _HEADER_ALIASES.items():
            if key in aliases and field not in mapping:
                mapping[field] = idx
    if all(f in mapping for f in ("hostname", "model", "version")):
        return mapping
    return {}


def parse_inventory_csv(data):
    # type: (bytes) -> Tuple[str, Dict[str, Any]]
    """Parse an uploaded inventory CSV into canonical inventory text.

    Returns (devices_text, meta) where devices_text is one
    "host, model, version" line per usable row - exactly what
    triage.parse_inventory accepts - and meta is
    {rows_total, rows_used, rows_skipped, encoding, header_mode}
    with header_mode "header" or "positional" (columns taken as
    host, model, version when no recognizable header row exists).
    """
    meta = {"rows_total": 0, "rows_used": 0, "rows_skipped": 0,
            "encoding": "utf-8", "header_mode": "positional"}
    if not data:
        return "", meta
    text, encoding = _decode_bytes(bytes(data))
    meta["encoding"] = encoding
    if not text.strip():
        return "", meta

    sample = "\n".join(text.splitlines()[:20])
    try:
        delimiter = csv.Sniffer().sniff(sample, delimiters=",;\t").delimiter
    except csv.Error:
        delimiter = ","
    reader = csv.reader(io.StringIO(text), delimiter=delimiter)
    rows = [row for row in reader
            if row and any(str(cell).strip() for cell in row)]
    if not rows:
        return "", meta

    mapping = _map_header(rows[0])
    if mapping:
        meta["header_mode"] = "header"
        data_rows = rows[1:]
    else:
        mapping = {"hostname": 0, "model": 1, "version": 2}
        data_rows = rows

    def _cell(row, field):
        # type: (List[str], str) -> str
        idx = mapping.get(field)
        if idx is None or idx >= len(row):
            return ""
        return str(row[idx]).strip()

    lines = []  # type: List[str]
    for row in data_rows:
        meta["rows_total"] += 1
        host = _cell(row, "hostname")
        model = _cell(row, "model")
        version = _cell(row, "version")
        vendor = _cell(row, "vendor")
        if not host or not model or not version:
            meta["rows_skipped"] += 1
            continue
        if vendor and vendor.lower() not in model.lower():
            model = "%s %s" % (vendor, model)
        lines.append("%s, %s, %s" % (host, model, version))
        meta["rows_used"] += 1
    return "\n".join(lines), meta


# ---------------------------------------------------------------------------
# Advisory link list
# ---------------------------------------------------------------------------

def parse_link_list(text):
    # type: (str) -> Tuple[List[str], int]
    """Clean the links text area into a capped URL list.

    One URL per line; blanks and #-comments are skipped, only
    http/https lines are kept, duplicates are removed preserving
    order, and the list is capped at MAX_LINKS. Returns
    (urls, skipped) where skipped counts valid URLs dropped by
    the cap.
    """
    seen = set()
    valid = []  # type: List[str]
    for raw_line in (text or "").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        lowered = line.lower()
        if not (lowered.startswith("http://")
                or lowered.startswith("https://")):
            continue
        if line in seen:
            continue
        seen.add(line)
        valid.append(line)
    skipped = max(0, len(valid) - MAX_LINKS)
    return valid[:MAX_LINKS], skipped


# ---------------------------------------------------------------------------
# Fetching one advisory page
# ---------------------------------------------------------------------------

_SKIP_TAGS = {"script", "style", "nav", "head", "noscript", "header",
              "footer", "form", "button", "select", "textarea", "svg",
              "iframe"}
_BLOCK_TAGS = {"p", "div", "br", "li", "tr", "h1", "h2", "h3", "h4",
               "h5", "h6", "section", "article", "table", "ul", "ol",
               "pre", "blockquote"}


class _TextExtractor(HTMLParser):
    """Minimal HTML -> readable text: skips script/style/nav and
    friends, breaks lines at block elements, entities decoded."""

    def __init__(self):
        # type: () -> None
        HTMLParser.__init__(self, convert_charrefs=True)
        self._skip = 0
        self._parts = []  # type: List[str]

    def handle_starttag(self, tag, attrs):
        if tag in _SKIP_TAGS:
            self._skip += 1
        elif not self._skip and tag in _BLOCK_TAGS:
            self._parts.append("\n")

    def handle_startendtag(self, tag, attrs):
        if not self._skip and tag == "br":
            self._parts.append("\n")

    def handle_endtag(self, tag):
        if tag in _SKIP_TAGS:
            if self._skip:
                self._skip -= 1
        elif not self._skip and tag in _BLOCK_TAGS:
            self._parts.append("\n")

    def handle_data(self, data):
        if not self._skip:
            self._parts.append(data)


def html_to_text(html_text):
    # type: (str) -> str
    parser = _TextExtractor()
    try:
        parser.feed(html_text or "")
        parser.close()
    except Exception:
        pass
    raw = "".join(parser._parts)
    lines = []
    for line in raw.splitlines():
        cleaned = re.sub(r"\s+", " ", line).strip()
        if cleaned:
            lines.append(cleaned)
    return "\n".join(lines)


REACH_OK = "ok"
REACH_CHALLENGE = "blocked-challenge"
REACH_HTTP = "http-error"
REACH_NETWORK = "network-error"
REACH_INVALID = "invalid-content"


def _parse_retry_after(value):
    # type: (Any) -> Optional[float]
    """Parse a Retry-After header value: seconds form only; the
    HTTP-date form returns None (callers fall back to backoff)."""
    if value is None:
        return None
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


def _looks_like_html(text, content_type):
    # type: (str, str) -> bool
    """True when a response body is an HTML page (by content type
    or by a leading markup marker) - the shape of a bot-challenge
    or portal-shell page served with HTTP 200."""
    if "html" in str(content_type or "").lower():
        return True
    head = str(text or "").lstrip()[:512].lower()
    return head.startswith("<") and ("<html" in head
                                     or "<!doctype" in head)


def _classify_error(exc):
    # type: (Any) -> str
    """Classify a fetch failure into a REACH_* string for the
    reachability probe and feed reporting."""
    status = getattr(exc, "status", None)
    message = str(exc or "")
    if status == 200 or "challenge" in message.lower():
        return REACH_CHALLENGE
    if status:
        return REACH_HTTP
    if message.startswith("timeout") or message.startswith(
            "network error"):
        return REACH_NETWORK
    return REACH_INVALID


def _fetch_raw_ex(url, timeout=FETCH_TIMEOUT, headers=None):
    # type: (str, float, Optional[Dict[str, str]]) -> Tuple[str, str, str, Dict[str, str], int]
    """Download a URL once. Returns (decoded_text, content_type,
    final_url_after_redirects, response_headers_lowercased,
    status). Raises FetchError on any failure, carrying the HTTP
    status / Retry-After / content type when known; an HTTP 304
    is raised as FetchError("not modified", status=304) so the
    cache layer can catch exactly that."""
    request_headers = {"User-Agent": USER_AGENT,
                       "Accept": "text/html, text/plain, */*"}
    if headers:
        request_headers.update(headers)
    request = urllib.request.Request(url, headers=request_headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            content_type = ""
            charset = None
            final_url = url
            status = 200
            response_headers = {}  # type: Dict[str, str]
            try:
                content_type = response.headers.get("Content-Type") or ""
                charset = response.headers.get_content_charset()
                final_url = response.geturl() or url
                status = int(getattr(response, "status", 200) or 200)
                response_headers = {
                    str(k).lower(): str(v)
                    for k, v in response.headers.items()}
            except Exception:
                pass
            raw = response.read(MAX_DOWNLOAD_BYTES + 1)
    except urllib.error.HTTPError as exc:
        error_headers = {}  # type: Dict[str, str]
        try:
            if exc.headers:
                error_headers = {
                    str(k).lower(): str(v)
                    for k, v in exc.headers.items()}
        except Exception:
            pass
        retry_after = _parse_retry_after(
            error_headers.get("retry-after"))
        error_type = error_headers.get("content-type", "")
        if exc.code == 304:
            raise FetchError("not modified", status=304,
                             retry_after=retry_after,
                             content_type=error_type)
        raise FetchError("HTTP %d" % exc.code, status=exc.code,
                         retry_after=retry_after,
                         content_type=error_type)
    except (TimeoutError, socket.timeout):
        raise FetchError("timeout")
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", exc)
        if "timed out" in str(reason).lower():
            raise FetchError("timeout")
        raise FetchError("network error: %s" % str(reason)[:120])
    except Exception as exc:  # malformed URL, TLS, http.client, ...
        raise FetchError("fetch failed: %s" % str(exc)[:120])

    if not raw:
        raise FetchError("empty response")
    raw = raw[:MAX_DOWNLOAD_BYTES]
    try:
        text = raw.decode(charset or "utf-8")
    except (UnicodeDecodeError, LookupError):
        text = raw.decode("utf-8", errors="replace")
    return text, content_type, final_url, response_headers, status


def _fetch_raw(url, timeout=FETCH_TIMEOUT):
    # type: (str, float) -> Tuple[str, str, str]
    """Download a URL once. Returns (decoded_text, content_type,
    final_url_after_redirects). Raises FetchError on any failure.
    Thin 3-tuple wrapper over _fetch_raw_ex."""
    text, content_type, final_url, _headers, _status = _fetch_raw_ex(
        url, timeout=timeout)
    return text, content_type, final_url


def fetch_advisory_text(url, timeout=FETCH_TIMEOUT):
    # type: (str, float) -> str
    """Download one advisory page and return readable text.

    HTML pages are reduced to text; plain-text responses pass
    through. The result is capped at MAX_TEXT_CHARS. Raises
    FetchError with a short reason on any failure.
    """
    text, content_type, _final_url = _fetch_raw(url, timeout=timeout)
    head = text.lstrip()[:64].lower()
    if "html" in content_type.lower() or head.startswith(
            ("<!doctype", "<html", "<head", "<body")):
        text = html_to_text(text)
    text = text.strip()
    if not text:
        raise FetchError("empty response")
    return text[:MAX_TEXT_CHARS]


def fetch_listing_html(url, timeout=FETCH_TIMEOUT):
    # type: (str, float) -> Tuple[str, str]
    """Download a listing/board page as raw HTML for link
    harvesting. Returns (html, final_url). Raises FetchError."""
    html, _content_type, final_url = _fetch_raw(url, timeout=timeout)
    return html, final_url


# ---------------------------------------------------------------------------
# Listing harvester: collect advisory links from a board page
# ---------------------------------------------------------------------------

# Advisory-ish link patterns, matched case-insensitively against an
# anchor's href or text: vendor-neutral wording, Cisco's cisco-sa
# slugs, Juniper's JSA numbers, and the GitHub demo tree's sample
# file names.
_ADVISORY_LINK_RE = re.compile(
    r"(advisory|advisories|cisco-sa|JSA\d{4,}|security-advis"
    r"|/advisories/|sample\d+_)",
    re.IGNORECASE,
)

# GitHub demo tree: only the sample advisory FILES are candidates
# (the repository name itself contains "advisory", so the generic
# pattern would match every file in the repo, inventory included).
_GITHUB_SAMPLE_FILE_RE = re.compile(r"sample\d+_", re.IGNORECASE)

_GITHUB_BLOB_RE = re.compile(r"^/([^/]+)/([^/]+)/blob/([^/]+)/(.+)$")

_CHALLENGE_MARKERS = ("client challenge", "just a moment",
                      "challenge-platform", "challenges.cloudflare.com",
                      "cf-chl", "attention required")


class _AnchorExtractor(HTMLParser):
    """Collect (href, text) pairs and the page <title>."""

    def __init__(self):
        # type: () -> None
        HTMLParser.__init__(self, convert_charrefs=True)
        self.anchors = []  # type: List[Tuple[str, str]]
        self.title = ""
        self._href = None  # type: Optional[str]
        self._text = []  # type: List[str]
        self._in_title = False

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            href = dict(attrs).get("href")
            if href:
                self._href = href
                self._text = []
        elif tag == "title":
            self._in_title = True

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.anchors.append(
                (self._href, " ".join("".join(self._text).split())))
            self._href = None
            self._text = []
        elif tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)
        if self._in_title:
            self.title += data


def _registrable_domain(host):
    # type: (str) -> str
    """Approximate registrable domain: last two labels, or three
    for two-letter TLDs under a common second-level label
    (example.co.kr)."""
    host = (host or "").lower().split(":")[0]
    parts = [p for p in host.split(".") if p]
    if len(parts) <= 2:
        return host
    if len(parts[-1]) == 2 and parts[-2] in ("co", "com", "net", "org",
                                             "ac", "go"):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _github_raw_url(absolute_url):
    # type: (str) -> Optional[str]
    """Map a github.com blob URL to its raw.githubusercontent.com
    equivalent; None when the URL is not a blob link."""
    parsed = urllib.parse.urlparse(absolute_url)
    if parsed.netloc.lower() != "github.com":
        return None
    match = _GITHUB_BLOB_RE.match(parsed.path)
    if not match:
        return None
    owner, repo, branch, rest = match.groups()
    return "https://raw.githubusercontent.com/%s/%s/%s/%s" % (
        owner, repo, branch, rest)


def harvest_links(listing_url, html_fetcher=None):
    # type: (str, Optional[Callable[[str], Tuple[str, str]]]) -> Dict[str, Any]
    """Collect advisory links from a listing/board page.

    Returns {"status", "urls", "found", "reason"}:
      - "ok": urls are the deduped candidate advisory links
        (same registrable domain as the listing, advisory-ish href
        or anchor text), capped at HARVEST_CAP; "found" counts the
        deduped candidates before the cap.
      - "blocked": the page looks like a bot/Cloudflare challenge.
      - "empty": the page fetched fine but carries no advisory
        links (e.g. a JavaScript shell that renders client-side).
      - "fetch_failed": the listing itself could not be fetched;
        "reason" carries the FetchError text.
    GitHub tree pages are special-cased: file (blob) links that
    match the sample pattern are resolved to raw.githubusercontent
    URLs so the batch fetcher gets the file contents directly.
    `html_fetcher(url) -> (html, final_url)` is injectable for
    offline tests.
    """
    fetcher = html_fetcher or fetch_listing_html
    try:
        html, final_url = fetcher(listing_url)
    except Exception as exc:
        return {"status": "fetch_failed", "urls": [], "found": 0,
                "reason": str(exc) or exc.__class__.__name__}

    parser = _AnchorExtractor()
    try:
        parser.feed(html or "")
        parser.close()
    except Exception:
        pass

    lowered_html = (html or "").lower()
    title = (parser.title or "").strip().lower()
    if (any(marker in title for marker in _CHALLENGE_MARKERS)
            or "challenge-platform" in lowered_html
            or "challenges.cloudflare.com" in lowered_html):
        return {"status": "blocked", "urls": [], "found": 0,
                "reason": "challenge page"}

    listing_host = urllib.parse.urlparse(final_url).netloc
    listing_domain = _registrable_domain(listing_host)
    is_github = listing_host.lower() == "github.com"
    self_urls = {listing_url.split("#")[0].rstrip("/"),
                 final_url.split("#")[0].rstrip("/")}

    seen = set()
    candidates = []  # type: List[str]
    for href, anchor_text in parser.anchors:
        absolute = urllib.parse.urljoin(final_url, href)
        parsed = urllib.parse.urlparse(absolute)
        if parsed.scheme not in ("http", "https"):
            continue
        if absolute.split("#")[0].rstrip("/") in self_urls:
            continue  # nav self-link to the listing page itself
        if is_github:
            raw_url = _github_raw_url(absolute)
            if raw_url is None:
                continue
            filename = parsed.path.rsplit("/", 1)[-1]
            if not _GITHUB_SAMPLE_FILE_RE.search(filename):
                continue
            resolved = raw_url
        else:
            if _registrable_domain(parsed.netloc) != listing_domain:
                continue
            if not (_ADVISORY_LINK_RE.search(absolute)
                    or _ADVISORY_LINK_RE.search(anchor_text)):
                continue
            resolved = absolute.split("#")[0]
        if resolved in seen:
            continue
        seen.add(resolved)
        candidates.append(resolved)

    if not candidates:
        return {"status": "empty", "urls": [], "found": 0,
                "reason": "no advisory links found"}
    return {"status": "ok",
            "urls": candidates[:HARVEST_CAP],
            "found": len(candidates),
            "reason": ""}


# ---------------------------------------------------------------------------
# Inventory relevance prefilter (no Clocked calls spent on misses)
# ---------------------------------------------------------------------------

VENDOR_TOKENS = ["cisco", "juniper", "arista", "nokia", "extreme",
                 "f5", "paloalto", "fortinet", "a10", "piolink",
                 "arbor", "checkpoint", "ahnlab", "microsoft",
                 "vmware", "dell", "hpe", "lenovo", "supermicro",
                 "citrix", "broadcom"]

GENERIC_NETWORK_TOKENS = [
    "switch", "router", "ios xe", "junos", "eos", "nexus",
    "catalyst", "qfx", "mx series", "ethernet", "firewall",
    "ips", "ids", "waf", "vpn", "ssl vpn", "load balancer", "adc",
    "ddos", "windows", "linux", "rhel", "rocky linux", "ubuntu",
    "debian", "vmware", "esxi", "proxmox", "server", "appliance",
]


def _device_tokens(devices):
    # type: (List[Dict[str, str]]) -> Set[str]
    """Tokens from the inventory itself only: normalized model
    cores plus significant model words (no vendor/generic
    additions)."""
    tokens = set()  # type: Set[str]
    for device in devices or []:
        model = str((device or {}).get("model") or "")
        core = _product_core(model)
        if core:
            tokens.add(core)
        for word in re.findall(r"[a-z0-9]+", model.lower()):
            if len(word) >= 3 and word not in GENERIC_PRODUCT_WORDS:
                tokens.add(word)
    return tokens


def build_relevance_tokens(devices):
    # type: (List[Dict[str, str]]) -> Set[str]
    """Match tokens for the relevance prefilter: the inventory's
    own product space (normalized model cores + significant model
    words), the known fleet vendor names, and generic fleet terms
    (network gear, security appliances, load balancers, servers).
    An advisory mentioning none of these is not about this fleet
    at all."""
    tokens = set(VENDOR_TOKENS) | set(GENERIC_NETWORK_TOKENS)
    tokens |= _device_tokens(devices)
    return tokens


def _relevance_pattern(tokens):
    # type: (Set[str]) -> Any
    ordered = sorted((t for t in tokens if t),
                     key=len, reverse=True)
    body = "|".join(re.escape(t) for t in ordered)
    return re.compile(r"(?<![a-z0-9])(?:%s)(?![a-z0-9])" % body,
                      re.IGNORECASE)


def is_relevant(text, tokens):
    # type: (str, Set[str]) -> bool
    """True when the advisory text mentions any relevance token
    (word-boundary match, case-insensitive)."""
    if not text or not tokens:
        return False
    return _relevance_pattern(tokens).search(text) is not None


# ---------------------------------------------------------------------------
# Vulnerability feeds (NVD + CISA KEV) and uploaded advisory files
#
# Real vendor portals mostly block server-side collection (bot
# challenges, JavaScript-rendered listings), so the batch offers two
# channels that work anyway: the official machine-readable feeds
# (NVD CVE API, CISA KEV catalog), queried for the vendors actually
# present in the inventory, and advisory files the operator saved
# from their own browser. Both produce plain "items" -
# {"label", "url", "text"} dicts - that flow through the exact same
# judging path as fetched links (run_batch_items below).
# ---------------------------------------------------------------------------

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_FEED_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
                "known_exploited_vulnerabilities.json")
NVD_API_KEY_ENV = "NVD_API_KEY"
NVD_SLEEP_WITH_KEY = 0.65      # 50 req / 30 s  ->  >= 0.6 s spacing
NVD_SLEEP_NO_KEY = 6.1         #  5 req / 30 s  ->  >= 6.0 s spacing
NVD_MAX_RETRIES = 2            # extra attempts on 429/403 only
NVD_RETRY_BACKOFF = (2.0, 5.0)  # seconds, used when no Retry-After
NVD_RETRY_AFTER_CAP = 30.0
NVD_RESULTS_PER_PAGE = 10
NVD_QUERY_CAP = 6
FEED_ITEM_CAP = 15
MAX_UPLOAD_FILES = 10

_SAMPLES_DIR = Path(__file__).resolve().parent / "samples"

# Deterministic vendor -> NVD keyword map for the core network
# vendors. Any other vendor found in the inventory gets a derived
# query ("<Vendor> <top product token from its model text>") - see
# _nvd_query_terms.
FEED_VENDOR_KEYWORDS = {
    "cisco": "Cisco IOS XE",
    "juniper": "Juniper Junos",
    "arista": "Arista EOS",
    "nokia": "Nokia SR OS",
    "extreme": "Extreme EXOS",
}

# Display names used to build derived NVD queries for vendors
# outside the curated keyword map.
VENDOR_DISPLAY_NAMES = {
    "f5": "F5",
    "paloalto": "Palo Alto",
    "fortinet": "Fortinet",
    "a10": "A10",
    "piolink": "Piolink",
    "arbor": "Arbor",
    "checkpoint": "Check Point",
    "ahnlab": "AhnLab",
    "microsoft": "Microsoft",
    "vmware": "VMware",
    "dell": "Dell",
    "hpe": "HPE",
    "lenovo": "Lenovo",
    "supermicro": "Supermicro",
    "citrix": "Citrix",
    "broadcom": "Broadcom",
}

_VENDOR_MODEL_RES = (
    ("cisco", re.compile(r"cisco|catalyst|nexus|\basr\b|ios[\s-]?xe",
                         re.IGNORECASE)),
    ("juniper", re.compile(r"juniper|junos|\bqfx|\bmx\d|\bex\d|\bsrx"
                           r"|\bacx|\bptx", re.IGNORECASE)),
    ("arista", re.compile(r"arista", re.IGNORECASE)),
    ("nokia", re.compile(r"nokia|\b7750\b|\b7250\b|sr[\s-]?os"
                         r"|\bsros\b", re.IGNORECASE)),
    ("extreme", re.compile(r"extreme|extremexos|\bexos\b|summit"
                           r"|\bx450|\bx650", re.IGNORECASE)),
    ("f5", re.compile(r"\bf5\b|big[\s-]?ip", re.IGNORECASE)),
    ("paloalto", re.compile(r"palo\s*alto|paloalto|pan[\s-]?os"
                            r"|\bpa-\d", re.IGNORECASE)),
    ("fortinet", re.compile(r"fortinet|forti", re.IGNORECASE)),
    ("a10", re.compile(r"\ba10\b|a10 networks|\bthunder\b",
                        re.IGNORECASE)),
    ("piolink", re.compile(r"piolink", re.IGNORECASE)),
    ("arbor", re.compile(r"arbor|netscout", re.IGNORECASE)),
    ("checkpoint", re.compile(r"check\s*point|checkpoint",
                              re.IGNORECASE)),
    ("ahnlab", re.compile(r"ahnlab|trusguard|안랩", re.IGNORECASE)),
    ("microsoft", re.compile(r"microsoft|windows", re.IGNORECASE)),
    ("vmware", re.compile(r"vmware|esxi|vsphere", re.IGNORECASE)),
    ("dell", re.compile(r"\bdell\b|poweredge", re.IGNORECASE)),
    ("hpe", re.compile(r"\bhpe\b|hewlett|proliant", re.IGNORECASE)),
    ("lenovo", re.compile(r"lenovo|thinksystem", re.IGNORECASE)),
    ("supermicro", re.compile(r"supermicro", re.IGNORECASE)),
    ("citrix", re.compile(r"citrix|netscaler", re.IGNORECASE)),
    ("broadcom", re.compile(r"broadcom|symantec", re.IGNORECASE)),
)


def inventory_vendors(devices):
    # type: (List[Dict[str, str]]) -> List[str]
    """Vendors actually present in the inventory, in the fixed
    VENDOR_TOKENS order. Detected from the model text - which is
    also where parse_inventory_csv puts an explicit CSV vendor
    column - via vendor names and signature product families
    (Catalyst/Nexus/ASR -> Cisco, QFX/MX/EX/SRX -> Juniper, ...)."""
    found = set()  # type: Set[str]
    for device in devices or []:
        model = str((device or {}).get("model") or "")
        for vendor, pattern in _VENDOR_MODEL_RES:
            if pattern.search(model):
                found.add(vendor)
    return [vendor for vendor in VENDOR_TOKENS if vendor in found]


def _device_vendor(device):
    # type: (Dict[str, str]) -> Optional[str]
    """The single vendor a device is attributed to: the first
    matching signature in VENDOR_TOKENS order, or None."""
    model = str((device or {}).get("model") or "")
    for vendor, pattern in _VENDOR_MODEL_RES:
        if pattern.search(model):
            return vendor
    return None


def _vendor_product_token(devices, vendor):
    # type: (List[Dict[str, str]], str) -> str
    """Top product token for a vendor: the first significant model
    word (hyphenated names kept whole, original case preserved)
    among the devices attributed to that vendor - e.g. "BIG-IP"
    from "F5 BIG-IP 4200", "Windows" from "Windows Server 2022".
    Vendor-name words themselves are skipped. "" when none."""
    own_words = {vendor}
    display = VENDOR_DISPLAY_NAMES.get(vendor, "")
    for word in re.findall(r"[a-z0-9]+", display.lower()):
        own_words.add(word)
    for device in devices or []:
        if _device_vendor(device) != vendor:
            continue
        model = str((device or {}).get("model") or "")
        for token in re.findall(r"[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*",
                                model):
            lowered = token.lower()
            if len(token) < 3 or lowered in GENERIC_PRODUCT_WORDS:
                continue
            if lowered in own_words:
                continue
            return token
    return ""


def _nvd_query_terms(devices):
    # type: (List[Dict[str, str]]) -> List[str]
    """NVD keyword queries for the vendors present in the
    inventory: at most NVD_QUERY_CAP, prioritized by device count
    (curated-keyword vendors first on a tie, then VENDOR_TOKENS
    order). Curated vendors use FEED_VENDOR_KEYWORDS; any other
    vendor gets "<Vendor> <top product token>" derived from its
    own model text (bare vendor name when no token stands out)."""
    vendors = inventory_vendors(devices)
    counts = {}  # type: Dict[str, int]
    for device in devices or []:
        vendor = _device_vendor(device)
        if vendor:
            counts[vendor] = counts.get(vendor, 0) + 1

    def sort_key(vendor):
        # type: (str) -> Tuple[int, int, int]
        return (-counts.get(vendor, 0),
                0 if vendor in FEED_VENDOR_KEYWORDS else 1,
                VENDOR_TOKENS.index(vendor))

    terms = []  # type: List[str]
    for vendor in sorted(vendors, key=sort_key)[:NVD_QUERY_CAP]:
        if vendor in FEED_VENDOR_KEYWORDS:
            terms.append(FEED_VENDOR_KEYWORDS[vendor])
            continue
        display = VENDOR_DISPLAY_NAMES.get(vendor, vendor)
        token = _vendor_product_token(devices, vendor)
        terms.append("%s %s" % (display, token) if token else display)
    return terms


def _vendor_query_term(vendor, devices):
    # type: (str, List[Dict[str, str]]) -> str
    """The single NVD keyword query for one explicitly chosen
    vendor (vendor listing runs): the curated keyword for the core
    network vendors; any other vendor gets the same derived
    "<Vendor> <top product token>" form _nvd_query_terms builds,
    from that vendor's own devices (bare display name when no
    token stands out)."""
    if vendor in FEED_VENDOR_KEYWORDS:
        return FEED_VENDOR_KEYWORDS[vendor]
    display = VENDOR_DISPLAY_NAMES.get(vendor, vendor)
    token = _vendor_product_token(devices, vendor)
    return "%s %s" % (display, token) if token else display


def _nvd_api_key():
    # type: () -> Optional[str]
    """The configured NVD API key (env only - app.py mirrors the
    Streamlit secret into the env), or None."""
    return os.environ.get(NVD_API_KEY_ENV) or None


def _nvd_sleep_seconds(has_key):
    # type: (bool) -> float
    """Request spacing honouring the official NVD budget for the
    key state: 50 requests / 30 s with a key, 5 / 30 s without."""
    return NVD_SLEEP_WITH_KEY if has_key else NVD_SLEEP_NO_KEY


def _nvd_fetcher(fetcher, has_key):
    # type: (Optional[Callable[[str], Any]], bool) -> Callable[[str], Any]
    """The fetcher to use for NVD calls. An injected fetcher is
    returned unchanged (it keeps the one-argument fetch(url)
    signature). The default fetcher gains the API key as the
    `apiKey` header when one is configured - the key travels
    only in the header, never in a URL."""
    if fetcher is not None:
        return fetcher
    if has_key:
        key = _nvd_api_key()

        def fetch_with_key(url):
            # type: (str) -> Any
            return _fetch_json(url, headers={"apiKey": key})

        return fetch_with_key
    return _fetch_json


def _fetch_with_retry(fetch, url, sleep):
    # type: (Callable[[str], Any], str, Optional[Callable[[float], None]]) -> Any
    """Call fetch(url), retrying rate-limit failures (an error
    carrying status 429 or 403) up to NVD_MAX_RETRIES extra
    times. The wait is the error's Retry-After (capped) when it
    carries one, else the next NVD_RETRY_BACKOFF value, via the
    injected `sleep` callable (no-op when sleep is None). Errors
    without a status attribute (plain stub FetchErrors) and all
    other statuses propagate immediately."""
    attempt = 0
    while True:
        try:
            return fetch(url)
        except Exception as exc:
            status = getattr(exc, "status", None)
            if status not in (429, 403) or attempt >= NVD_MAX_RETRIES:
                raise
            retry_after = getattr(exc, "retry_after", None)
            if retry_after is not None:
                delay = min(float(retry_after), NVD_RETRY_AFTER_CAP)
            else:
                delay = NVD_RETRY_BACKOFF[
                    min(attempt, len(NVD_RETRY_BACKOFF) - 1)]
            if sleep is not None:
                try:
                    sleep(delay)
                except Exception:
                    pass
            attempt += 1


def _nvd_recent_window(now):
    # type: (datetime.datetime) -> Tuple[str, str]
    """(pubStartDate, pubEndDate) strings for the recent
    collector's 119-day window, formatted exactly like the year
    collector's _nvd_ts so the two cannot drift apart."""
    return (_nvd_ts(now - datetime.timedelta(days=119)),
            _nvd_ts(now))


def _fetch_json(url, timeout=FETCH_TIMEOUT, headers=None):
    # type: (str, float, Optional[Dict[str, str]]) -> Any
    """GET a URL and parse the body as JSON. Raises FetchError.
    An HTML body (a bot-challenge or portal shell served with
    HTTP 200) is rejected with a challenge-named error instead of
    the generic invalid-JSON one, so callers can tell a blocked
    vendor source from a truncated body."""
    text, content_type, _final_url, _headers, _status = _fetch_raw_ex(
        url, timeout=timeout, headers=headers)
    if _looks_like_html(text, content_type):
        raise FetchError("challenge page (HTTP 200 HTML)", status=200,
                         content_type=content_type)
    try:
        return json.loads(text)
    except ValueError:
        raise FetchError("invalid JSON response")


def _cpe_unescape(field):
    # type: (str) -> str
    return re.sub(r"\\(.)", r"\1", field or "")


def _nvd_cpe_ranges(vuln, cap=40):
    # type: (Any, int) -> List[Dict[str, Any]]
    """Machine-readable affected ranges from the NVD record's
    structured configurations: every vulnerable cpeMatch becomes
    {"vendor", "product", "exact", "start_including",
    "start_excluding", "end_including", "end_excluding"} with None
    for absent bounds. A boundless match falls back to its exact
    CPE version (the update field joins it - Junos CPEs split
    "21.2R3" into version 21.2 + update r3); a match whose version
    is a wildcard ("*"/"-") carries no information and is dropped.
    Deduped, capped. These dicts drive BOTH the human-readable
    range lines in the item text and the local version-range
    screening (zero API calls)."""
    ranges = []  # type: List[Dict[str, Any]]
    seen = set()  # type: Set[Tuple[Any, ...]]

    def walk_node(node):
        # type: (Any) -> bool
        for match in (node or {}).get("cpeMatch") or []:
            if not (match or {}).get("vulnerable"):
                continue
            fields = str(match.get("criteria") or "").split(":")
            if len(fields) < 5:
                continue
            product = _cpe_unescape(fields[4])
            if not product:
                continue
            entry = {
                "vendor": _cpe_unescape(fields[3]),
                "product": product,
                "exact": None,
                "start_including": match.get("versionStartIncluding")
                or None,
                "start_excluding": match.get("versionStartExcluding")
                or None,
                "end_including": match.get("versionEndIncluding")
                or None,
                "end_excluding": match.get("versionEndExcluding")
                or None,
            }  # type: Dict[str, Any]
            if not any(entry[key] for key in (
                    "start_including", "start_excluding",
                    "end_including", "end_excluding")):
                version = _cpe_unescape(fields[5]) if len(fields) > 5 \
                    else ""
                if version in ("", "*", "-"):
                    continue
                update = _cpe_unescape(fields[6]) if len(fields) > 6 \
                    else ""
                if update and update not in ("*", "-"):
                    version = version + update
                entry["exact"] = version
            key = (entry["vendor"], entry["product"], entry["exact"],
                   entry["start_including"], entry["start_excluding"],
                   entry["end_including"], entry["end_excluding"])
            if key in seen:
                continue
            seen.add(key)
            ranges.append(entry)
            if len(ranges) >= cap:
                return True
        for sub in (node or {}).get("nodes") or []:
            if walk_node(sub):
                return True
        return False

    for wrap in (vuln or {}).get("configurations") or []:
        for node in (wrap or {}).get("nodes") or []:
            if walk_node(node):
                return ranges
    return ranges


def _range_display(rng):
    # type: (Dict[str, Any]) -> str
    """One structured range as a display line (no leading dash):
    "product ios_xe: versions >= 17.9 and < 17.9.4a", or the
    exact-version form for a boundless match."""
    bounds = []  # type: List[str]
    if rng.get("start_including"):
        bounds.append(">= %s" % rng["start_including"])
    if rng.get("start_excluding"):
        bounds.append("> %s" % rng["start_excluding"])
    if rng.get("end_including"):
        bounds.append("<= %s" % rng["end_including"])
    if rng.get("end_excluding"):
        bounds.append("< %s" % rng["end_excluding"])
    if bounds:
        return "product %s: versions %s" % (
            rng.get("product") or "", " and ".join(bounds))
    if rng.get("exact"):
        return "product %s: version %s" % (
            rng.get("product") or "", rng["exact"])
    return "product %s" % (rng.get("product") or "")


def _nvd_cpe_range_lines(vuln, cap=12):
    # type: (Any, int) -> List[str]
    """Deterministic affected-range lines from the NVD record's
    structured configurations (see _nvd_cpe_ranges): the
    machine-readable half of the advisory that the prose
    description often omits, rendered as text for the item body."""
    return ["- " + _range_display(rng)
            for rng in _nvd_cpe_ranges(vuln, cap=cap)]


_SEVERITY_RANKS = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1,
                   "NONE": 0}


def _severity_rank(score, severity):
    # type: (Any, str) -> int
    """Ordering rank for triage priority: critical 4, high 3,
    medium 2, low 1, none/unknown 0. The stated severity word
    wins; the numeric CVSS score is the fallback."""
    rank = _SEVERITY_RANKS.get(str(severity or "").strip().upper())
    if rank is not None:
        return rank
    try:
        value = float(score)
    except (TypeError, ValueError):
        return 0
    if value >= 9.0:
        return 4
    if value >= 7.0:
        return 3
    if value >= 4.0:
        return 2
    if value > 0.0:
        return 1
    return 0


def _nvd_item(vuln, keyword):
    # type: (Any, str) -> Optional[Dict[str, Any]]
    """Convert one NVD API vulnerability entry into a batch item,
    or None when it carries no CVE id. The English description is
    kept verbatim: it carries the affected-version prose ("EOS
    before 4.14.5...") the extraction/matching already handles.
    The item also keeps the record's full reference list (the
    vendor-trace step follows those URLs to the vendor original)
    and a deterministic "Structured affected ranges (NVD CPE)"
    section parsed from configurations[] - whose structured form
    also rides on the item as "cpe_ranges" for the local
    version-range screening, alongside "published" (ISO date),
    "severity_rank" (CVSS ordering) and "kev" (False until a KEV
    merge says otherwise)."""
    cve = (vuln or {}).get("cve") or {}
    cve_id = str(cve.get("id") or "").strip()
    if not cve_id:
        return None
    description = ""
    for entry in cve.get("descriptions") or []:
        if (entry or {}).get("lang") == "en":
            description = str(entry.get("value") or "")
            break
    score = None  # type: Any
    severity = ""
    metrics = cve.get("metrics") or {}
    for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(metric_key) or []
        if entries:
            data = (entries[0] or {}).get("cvssData") or {}
            score = data.get("baseScore")
            severity = str(data.get("baseSeverity") or "")
            break
    published_raw = str(cve.get("published") or "")
    references = []  # type: List[str]
    for entry in cve.get("references") or []:
        url = str((entry or {}).get("url") or "").strip()
        if url and url not in references:
            references.append(url)
    reference = references[0] if references else ""
    lines = ["%s \u2014 %s" % (cve_id, keyword),
             "Published: %s" % (published_raw[:10] or "not stated")]
    if score is not None:
        lines.append("CVSS: %s (%s)" % (score, severity or "not stated"))
    else:
        lines.append("CVSS: not stated")
    text = "\n".join(lines) + "\n\n" + description.strip()
    range_lines = _nvd_cpe_range_lines(cve)
    if range_lines:
        text += ("\n\nStructured affected ranges (NVD CPE):\n"
                 + "\n".join(range_lines))
    if reference:
        text += "\n\nReference: %s" % reference
    return {"label": cve_id,
            "url": "https://nvd.nist.gov/vuln/detail/%s" % cve_id,
            "text": text,
            "references": references,
            "published": published_raw[:10],
            "severity_rank": _severity_rank(score, severity),
            "kev": False,
            "sources": ["NVD"],
            "cpe_ranges": _nvd_cpe_ranges(cve),
            "_published": published_raw}


def collect_nvd_items(devices, fetcher=None, vendor=None, sleep=None,
                      now=None):
    # type: (List[Dict[str, str]], Optional[Callable[[str], Any]], Optional[str], Optional[Callable[[float], None]], Optional[datetime.datetime]) -> Dict[str, Any]
    """Query the NVD CVE API once per vendor present in the
    inventory (_nvd_query_terms: curated keywords for the core
    network vendors, derived "<Vendor> <product>" terms for the
    rest; at most NVD_QUERY_CAP queries) and convert the results
    into batch items, capped at FEED_ITEM_CAP, deduped by CVE id.
    The cap is shared round-robin across the per-vendor queries
    (newest first within each vendor) so a single vendor's
    publication batch cannot crowd out the others. With `vendor`
    (a VENDOR_TOKENS key) the run is scoped to that one vendor:
    its single query term, whether or not the inventory holds
    devices of that vendor.

    Returns {"items", "status", "count", "queries", "reason"} with
    status "ok" | "empty" | "fetch_failed" | "no_vendors" - an
    honest outcome, never fabricated items. `fetcher(url) -> parsed
    JSON` is injectable for offline tests.
    """
    has_key = bool(_nvd_api_key())
    fetch = _nvd_fetcher(fetcher, has_key)
    queries = ([_vendor_query_term(vendor, devices)] if vendor
               else _nvd_query_terms(devices))
    result = {"items": [], "status": "empty", "count": 0,
              "queries": queries, "reason": "",
              "rate_budget": "key" if has_key else "no-key",
              "requests_made": 0}  # type: Dict[str, Any]
    if not queries:
        result["status"] = "no_vendors"
        return result
    per_query = []  # type: List[List[Dict[str, Any]]]
    seen = set()  # type: set
    errors = []  # type: List[str]
    # NVD keyword search returns the OLDEST matches first, which is
    # backwards for triage: restrict to the most recent 119 days
    # (the API caps a publication-date window at 120 days) so the
    # first page holds current CVEs. Every request carries the
    # window - no code path may call NVD_API_URL without one.
    moment = now or datetime.datetime.now(datetime.timezone.utc)
    pub_start, pub_end = _nvd_recent_window(moment)
    for query_index, term in enumerate(queries):
        if sleep is not None and query_index > 0:
            try:
                sleep(_nvd_sleep_seconds(has_key))
            except Exception:
                pass
        url = NVD_API_URL + "?" + urllib.parse.urlencode(
            {"keywordSearch": term,
             "resultsPerPage": NVD_RESULTS_PER_PAGE,
             "pubStartDate": pub_start,
             "pubEndDate": pub_end})
        try:
            result["requests_made"] += 1
            data = _fetch_with_retry(fetch, url, sleep)
        except Exception as exc:
            errors.append(str(exc) or exc.__class__.__name__)
            per_query.append([])
            continue
        bucket = []  # type: List[Dict[str, Any]]
        for vuln in (data or {}).get("vulnerabilities") or []:
            item = _nvd_item(vuln, term)
            if item is not None and item["label"] not in seen:
                seen.add(item["label"])
                bucket.append(item)
        bucket.sort(key=lambda item: item.get("_published") or "",
                    reverse=True)
        per_query.append(bucket)
    # Round-robin across queries so one vendor's publication batch
    # cannot crowd the others out of the cap; within each vendor the
    # order stays newest-first.
    items = []  # type: List[Dict[str, Any]]
    depth = 0
    while len(items) < FEED_ITEM_CAP:
        progressed = False
        for bucket in per_query:
            if depth < len(bucket):
                progressed = True
                item = dict(bucket[depth])
                item.pop("_published", None)
                items.append(item)
                if len(items) >= FEED_ITEM_CAP:
                    break
        if not progressed:
            break
        depth += 1
    result["items"] = items
    result["count"] = len(items)
    if items:
        result["status"] = "ok"
    elif errors and len(errors) == len(queries):
        result["status"] = "fetch_failed"
        result["reason"] = errors[0]
    elif errors:
        result["reason"] = errors[0]
    return result


def _kev_item(entry):
    # type: (Dict[str, Any]) -> Dict[str, Any]
    """Convert one CISA KEV catalog entry into a batch item. The
    "Due date:" line is deliberate: the existing Extract pass picks
    it up as the action deadline in the Action block."""
    cve_id = str(entry.get("cveID") or "").strip()
    text = (
        "KEV %s \u2014 %s %s\n"
        "Date added: %s\n"
        "Due date: %s\n\n"
        "%s\n"
        "Required action: %s\n"
        "Known ransomware use: %s"
    ) % (
        cve_id,
        str(entry.get("vendorProject") or ""),
        str(entry.get("product") or ""),
        str(entry.get("dateAdded") or ""),
        str(entry.get("dueDate") or ""),
        str(entry.get("vulnerabilityName") or ""),
        str(entry.get("requiredAction") or ""),
        str(entry.get("knownRansomwareCampaignUse") or ""),
    )
    return {"label": "KEV %s" % cve_id,
            "url": "https://nvd.nist.gov/vuln/detail/%s" % cve_id,
            "text": text,
            "published": str(entry.get("dateAdded") or ""),
            "date_added": str(entry.get("dateAdded") or ""),
            "due_date": str(entry.get("dueDate") or ""),
            "severity_rank": 4,
            "kev": True,
            "sources": ["KEV"],
            "required_action": str(entry.get("requiredAction") or ""),
            "ransomware": str(
                entry.get("knownRansomwareCampaignUse") or ""),
            "vuln_name": str(entry.get("vulnerabilityName") or ""),
            "vendor_project": str(entry.get("vendorProject") or ""),
            "product_name": str(entry.get("product") or ""),
            "cpe_ranges": []}


class _TTLCache:
    """Tiny in-process TTL cache: {key: (expires_monotonic,
    value_dict)}. Single-threaded Streamlit execution makes a
    lock unnecessary. `get` honours expiry; `peek` returns the
    stored value even when expired (the KEV catalog layer needs
    the stored validators for a conditional revalidation)."""

    def __init__(self):
        self._store = {}  # type: Dict[str, Tuple[float, Dict[str, Any]]]

    def get(self, key):
        # type: (str) -> Optional[Dict[str, Any]]
        entry = self._store.get(key)
        if entry is None:
            return None
        expires, value = entry
        if time.monotonic() >= expires:
            return None
        return value

    def peek(self, key):
        # type: (str) -> Optional[Dict[str, Any]]
        entry = self._store.get(key)
        if entry is None:
            return None
        return entry[1]

    def put(self, key, value, ttl):
        # type: (str, Dict[str, Any], float) -> None
        self._store[key] = (time.monotonic() + float(ttl), value)

    def clear(self):
        # type: () -> None
        self._store.clear()


_FEED_CACHE = _TTLCache()

KEV_CACHE_TTL = 900


def _fetch_kev_catalog(fetcher=None):
    # type: (Optional[Callable[[str], Any]]) -> Tuple[Any, bool]
    """Fetch the CISA KEV catalog JSON, returning (data,
    from_cache). An injected fetcher (tests / Mock Mode) is
    called directly and never touches the cache. The default
    path serves an unexpired cache entry with no HTTP, and on
    expiry revalidates with the stored ETag / Last-Modified
    validators: a 304 re-serves the stored body and renews the
    TTL; a 200 stores the body and the new validators."""
    if fetcher is not None:
        return fetcher(KEV_FEED_URL), False
    cached = _FEED_CACHE.get("kev_catalog")
    if cached is not None:
        return cached.get("data"), True
    stale = _FEED_CACHE.peek("kev_catalog") or {}
    headers = {}  # type: Dict[str, str]
    if stale.get("etag"):
        headers["If-None-Match"] = str(stale["etag"])
    if stale.get("last_modified"):
        headers["If-Modified-Since"] = str(stale["last_modified"])
    try:
        text, content_type, _final_url, response_headers, _status = (
            _fetch_raw_ex(KEV_FEED_URL, headers=headers or None))
    except FetchError as exc:
        if getattr(exc, "status", None) == 304 \
                and stale.get("data") is not None:
            _FEED_CACHE.put("kev_catalog", stale, KEV_CACHE_TTL)
            return stale.get("data"), True
        raise
    if _looks_like_html(text, content_type):
        raise FetchError("challenge page (HTTP 200 HTML)", status=200,
                         content_type=content_type)
    try:
        data = json.loads(text)
    except ValueError:
        raise FetchError("invalid JSON response")
    value = {"data": data,
             "etag": response_headers.get("etag"),
             "last_modified": response_headers.get("last-modified"),
             "fetched_at": time.time()}  # type: Dict[str, Any]
    _FEED_CACHE.put("kev_catalog", value, KEV_CACHE_TTL)
    return data, False


def _parse_iso_date(value):
    # type: (Any) -> Optional[datetime.date]
    """Parse the leading YYYY-MM-DD of an ISO date/datetime
    string, or None when it does not parse (callers treat an
    unparseable date as undated, never as excludable evidence)."""
    text = str(value or "").strip()[:10]
    try:
        return datetime.date.fromisoformat(text)
    except ValueError:
        return None


def collect_kev_items(devices, fetcher=None, cap=FEED_ITEM_CAP,
                      min_date=None, vendor=None):
    # type: (List[Dict[str, str]], Optional[Callable[[str], Any]], int, Optional[datetime.date], Optional[str]) -> Dict[str, Any]
    """Fetch the CISA KEV catalog once and keep the entries whose
    vendorProject/product mentions an inventory vendor or a
    significant inventory model token. With `vendor` (a
    VENDOR_TOKENS key) the match narrows to that one vendor: its
    name, plus the model tokens of the inventory devices
    attributed to it. Returns {"items", "status",
    "count", "reason", "older_excluded"} with status "ok" |
    "empty" | "fetch_failed". Matches are newest-first
    (dateAdded) and capped at `cap` (FEED_ITEM_CAP for the
    recent-items collector; the year pipeline passes
    KEV_YEAR_CAP). When `min_date` (a datetime.date) is given,
    matches whose dateAdded falls before it are excluded BEFORE
    the cap applies and counted in "older_excluded" - the year
    pipeline passes the start of its 365-day window so KEV covers
    the same lookback as NVD instead of the catalog's whole
    history. Entries with an unparseable dateAdded are kept: an
    undated entry is not evidence of age. `fetcher(url) ->
    parsed JSON` is injectable."""
    result = {"items": [], "status": "empty", "count": 0,
              "reason": "", "older_excluded": 0,
              "catalog_version": "", "from_cache": False}  # type: Dict[str, Any]
    try:
        data, from_cache = _fetch_kev_catalog(fetcher)
    except Exception as exc:
        result["status"] = "fetch_failed"
        result["reason"] = str(exc) or exc.__class__.__name__
        return result
    result["from_cache"] = bool(from_cache)
    result["catalog_version"] = str(
        (data or {}).get("catalogVersion") or "")
    vendors = inventory_vendors(devices)
    tokens = set(vendors) | _device_tokens(devices)
    if vendor:
        own_devices = [device for device in devices or []
                       if _device_vendor(device) == vendor]
        vendors = [vendor]
        tokens = {vendor} | _device_tokens(own_devices)
    pattern = _relevance_pattern(tokens) if tokens else None
    matched = []  # type: List[Dict[str, Any]]
    for entry in (data or {}).get("vulnerabilities") or []:
        if not isinstance(entry, dict):
            continue
        fields = "%s %s" % (entry.get("vendorProject") or "",
                            entry.get("product") or "")
        lowered = fields.lower()
        if any(vendor in lowered for vendor in vendors):
            pass
        elif pattern is not None and pattern.search(fields):
            pass
        else:
            continue
        if min_date is not None:
            added = _parse_iso_date(entry.get("dateAdded"))
            if added is not None and added < min_date:
                result["older_excluded"] += 1
                continue
        matched.append(entry)
    matched.sort(key=lambda e: str(e.get("dateAdded") or ""),
                 reverse=True)
    items = [_kev_item(entry) for entry in matched[:cap]]
    result["items"] = items
    result["count"] = len(items)
    if items:
        result["status"] = "ok"
    return result


def _load_fixture_json(filename):
    # type: (str) -> Any
    with (_SAMPLES_DIR / filename).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _fixture_nvd_fetcher(url):
    # type: (str) -> Any
    """Mock Mode NVD stand-in: the bundled fixture payload, filtered
    to the queried vendor's first keyword word - the same filtering
    the real keyword search performs server-side - so the shared
    collect path behaves identically offline."""
    data = _load_fixture_json("nvd_fixture.json")
    query = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    term = (query.get("keywordSearch") or [""])[0]
    vendor_word = term.split()[0].lower() if term.split() else ""
    if not vendor_word:
        return data
    kept = []
    for vuln in data.get("vulnerabilities") or []:
        descriptions = ((vuln or {}).get("cve") or {}).get(
            "descriptions") or []
        text = " ".join(str((d or {}).get("value") or "")
                        for d in descriptions)
        if vendor_word in text.lower():
            kept.append(vuln)
    filtered = dict(data)
    filtered["vulnerabilities"] = kept
    return filtered


def _fixture_kev_fetcher(url):
    # type: (str) -> Any
    return _load_fixture_json("kev_fixture.json")


def _derived_sources(item):
    # type: (Dict[str, Any]) -> List[str]
    """An item's feed sources: its explicit "sources" when set,
    else derived (["KEV"] for a KEV-flagged item, ["NVD"] when it
    names a CVE). Upload-shaped items derive []."""
    explicit = (item or {}).get("sources")
    if explicit:
        return [str(source) for source in explicit]
    if (item or {}).get("kev"):
        return ["KEV"]
    if _item_cve_id(item or {}):
        return ["NVD"]
    return []


def _merge_kev_fields(target, kev_item):
    # type: (Dict[str, Any], Dict[str, Any]) -> Dict[str, Any]
    """Merge a KEV item's facts into its NVD twin (mutates and
    returns the NVD item): the known-exploited flag, due/date
    fields and the previously dropped required action /
    ransomware / vulnerability name ride as structured fields,
    and the KEV block is appended to the text - its first lines
    keep the existing wording verbatim, the two new lines are
    additive. Ranges, published date, severity rank, label and
    URL stay the NVD item's (the severity pin is deliberate:
    KEV priority comes from the kev flag sort, not severity)."""
    target["kev"] = True
    target["due_date"] = kev_item.get("due_date") or ""
    target["date_added"] = kev_item.get("date_added") or ""
    target["required_action"] = kev_item.get("required_action") or ""
    target["ransomware"] = kev_item.get("ransomware") or ""
    target["vuln_name"] = kev_item.get("vuln_name") or ""
    sources = []  # type: List[str]
    for source in _derived_sources(target) + _derived_sources(kev_item):
        if source not in sources:
            sources.append(source)
    ordered = [s for s in ("NVD", "KEV") if s in sources]
    ordered += [s for s in sources if s not in ordered]
    target["sources"] = ordered
    target["text"] = (
        str(target.get("text") or "")
        + "\n\nCISA KEV: this CVE is in the Known Exploited "
          "Vulnerabilities catalog.\nDate added: %s\nDue date: %s"
          "\nRequired action: %s\nKnown ransomware use: %s"
        % (kev_item.get("date_added") or "",
           kev_item.get("due_date") or "",
           kev_item.get("required_action") or "",
           kev_item.get("ransomware") or ""))
    return target


def merge_feed_items(nvd_items, kev_items):
    # type: (List[Dict[str, Any]], List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], Dict[str, int]]
    """The one shared feed merge: one CVE is one item however
    many feeds name it. NVD items form the base; a KEV item for
    the same CVE merges in place via _merge_kev_fields; KEV-only
    items append. Every returned item is stamped with its
    "sources". Returns (items, {"kev_merged", "kev_only"})."""
    items = []  # type: List[Dict[str, Any]]
    by_cve = {}  # type: Dict[str, Dict[str, Any]]
    for item in nvd_items or []:
        items.append(item)
        cve_id = _item_cve_id(item)
        if cve_id:
            by_cve[cve_id] = item
    kev_merged = 0
    kev_only = 0
    for kev_item in kev_items or []:
        cve_id = _item_cve_id(kev_item)
        target = by_cve.get(cve_id) if cve_id else None
        if target is None:
            items.append(kev_item)
            kev_only += 1
            continue
        _merge_kev_fields(target, kev_item)
        kev_merged += 1
    for item in items:
        if not item.get("sources"):
            item["sources"] = _derived_sources(item)
    return items, {"kev_merged": kev_merged, "kev_only": kev_only}


def collect_feed_items(devices, mock=False, nvd_fetcher=None,
                       kev_fetcher=None, vendor=None):
    # type: (List[Dict[str, str]], bool, Optional[Callable[[str], Any]], Optional[Callable[[str], Any]], Optional[str]) -> Dict[str, Any]
    """Collect batch items from both feeds. Returns {"items",
    "nvd", "kev"} where "nvd"/"kev" are the per-feed outcome dicts
    from collect_nvd_items / collect_kev_items. With mock=True and
    no injected fetchers, the bundled fixture files are read
    instead of the network, so the demo path works offline.
    `vendor` scopes both feeds to one vendor (see the collectors).
    """
    if mock:
        if nvd_fetcher is None:
            nvd_fetcher = _fixture_nvd_fetcher
        if kev_fetcher is None:
            kev_fetcher = _fixture_kev_fetcher
    nvd = collect_nvd_items(devices, fetcher=nvd_fetcher,
                            vendor=vendor)
    kev = collect_kev_items(devices, fetcher=kev_fetcher,
                            vendor=vendor)
    items, merge_stats = merge_feed_items(nvd["items"], kev["items"])
    stats = {"nvd_count": nvd["count"], "kev_count": kev["count"],
             "kev_merged": merge_stats["kev_merged"],
             "kev_only": merge_stats["kev_only"],
             "total": len(items)}  # type: Dict[str, Any]
    return {"items": items, "nvd": nvd, "kev": kev, "stats": stats}


# ---------------------------------------------------------------------------
# Full-year feed collection
#
# The recent-items collector above answers "what is new this
# quarter". Operations needs the whole lookback: collect_feed_
# items_year gathers a full 365 days - NVD queried in consecutive
# publication-date windows of at most 119 days (the API caps one
# window at 120 days), paginated inside each window, and the KEV
# catalog matched within the same 365-day window (older matches
# are excluded and counted, never merged). KEV entries merge into
# the NVD item of the same CVE (known-exploited flag + due date),
# so one CVE is one item however many feeds name it. The result
# is deliberately
# NOT judged item by item - screen_feed_items below settles most
# of it locally, and run_feed_pipeline spends Clocked calls only
# on the real candidates.
# ---------------------------------------------------------------------------

NVD_YEAR_DAYS = 365
NVD_WINDOW_DAYS = 119
NVD_PAGE_SIZE = 500
NVD_VENDOR_YEAR_CAP = 1000
KEV_YEAR_CAP = 300
FEED_SLEEP_SECONDS = 0.65  # deprecated alias of NVD_SLEEP_WITH_KEY
FULL_TRIAGE_CAP = 30
JUDGE_ALL_CAP = 200
# Candidates traced for the post-trace re-screen in one pipeline
# run - deliberately larger than FULL_TRIAGE_CAP: a trace is a
# plain HTTP fetch, and every candidate it clears locally frees
# a deep-triage slot for the next one.
TRACE_SCREEN_CAP = 80

# Stage-progress labels for the feed pipeline, localized like
# triage's display strings: the pipeline's `lang` picks the set
# and every stage reports through the one progress(index, total,
# label) callback the UI renders as a bar plus counts, so a
# minutes-long run never sits on a static spinner text.
PROGRESS_STRINGS = {
    "en": {
        "collecting_nvd": "Collecting NVD feeds - %d collected",
        "collecting_kev": "Collecting KEV feed - %d matched",
        "screening": "Screening against inventory",
        "tracing": "Tracing vendor source - %s",
    },
    "ko": {
        "collecting_nvd": "NVD 피드 수집 중 - 누적 %d건",
        "collecting_kev": "KEV 피드 수집 중 - 누적 %d건",
        "screening": "인벤토리 대조 스크리닝",
        "tracing": "제조사 원문 추적 - %s",
    },
}


def _emit_progress(progress, index, total, label):
    # type: (Optional[Callable[[int, int, str], None]], int, int, str) -> None
    """Fire one progress event, following the runners' habit: no
    callback (or a stage whose total is 0) means no event, and a
    misbehaving callback never breaks the run."""
    if progress is None or total <= 0:
        return
    try:
        progress(index, total, label)
    except Exception:
        pass


# Message carried by batch entries that were never judged because
# the run's Clocked credits ran out (see _credit_entry). Localized
# like the runners' other display text; the verdict constants are
# never involved - a credit entry is an error row, not a judgment.
CREDIT_STRINGS = {
    "en": "Not judged - Clocked API credits exhausted.",
    "ko": "판정되지 않음 - Clocked API 크레딧이 소진되었습니다.",
}

# KEV local-screen strings (kind "kev_unconfirmed"): a KEV-listed
# product match with no version range from any source earns a
# dedicated CONDITION CHECK REQUIRED reason + checklist, never a
# firmer verdict - KEV membership is priority evidence, not
# version evidence (design rules K-2 / K-A / K-C).
KEV_STRINGS = {
    "en": {
        "reason": ("In CISA KEV (known exploited) for %s, but "
                   "neither KEV, NVD, nor the vendor original "
                   "states affected versions - version %s cannot "
                   "be confirmed or cleared from structured "
                   "evidence."),
        "condition": ("KEV-listed product matches this device; "
                      "confirm the installed version is not "
                      "affected (no version range is published "
                      "in KEV)."),
        "check_version": ("Confirm the exact installed version "
                          "of %s on each candidate device "
                          "against the vendor advisory for this "
                          "CVE."),
        "check_action": ("Apply the KEV required action by the "
                         "due date %s: %s"),
        "check_ransomware": ("KEV marks this CVE as known "
                             "ransomware use - check for "
                             "compromise indicators before "
                             "routine patching."),
        "warn_overdue": ("KEV due date %s has passed - treat "
                         "as overdue until the version check "
                         "clears each device."),
        "warn_ransomware": ("Known ransomware use (CISA KEV) - "
                            "prioritise the version check."),
        "action": ("Verify versions manually for %s: this CVE "
                   "is in CISA KEV (known exploited) but no "
                   "source publishes an affected-version range, "
                   "so local screening cannot settle it."),
    },
    "ko": {
        "reason": ("CISA KEV(악용 확인)에 등재된 %s 취약점이지만 "
                   "KEV·NVD·제조사 원문 어디에도 영향 버전 범위가 "
                   "없어 버전 %s을(를) 구조화 근거로 확정도 제외도 "
                   "할 수 없습니다."),
        "condition": ("KEV 등재 제품이 이 장비와 일치합니다. 설치 "
                      "버전이 영향받지 않는지 확인하세요(KEV에는 "
                      "버전 범위가 없습니다)."),
        "check_version": ("후보 장비마다 %s의 정확한 설치 버전을 "
                          "이 CVE의 제조사 권고와 대조해 확인하세요."),
        "check_action": ("기한 %s까지 KEV 필수 조치를 적용하세요: %s"),
        "check_ransomware": ("KEV가 이 CVE를 랜섬웨어 악용으로 "
                             "표시합니다 - 정기 패치 전에 침해 "
                             "지표부터 확인하세요."),
        "warn_overdue": ("KEV 기한 %s이(가) 지났습니다 - 버전 "
                         "확인으로 각 장비가 제외될 때까지 기한 "
                         "초과로 취급하세요."),
        "warn_ransomware": ("랜섬웨어 악용 확인(CISA KEV) - 버전 "
                            "확인을 우선하세요."),
        "action": ("%s 버전을 수동으로 확인하세요: 이 CVE는 CISA "
                   "KEV(악용 확인)에 등재됐지만 어떤 소스도 영향 "
                   "버전 범위를 공개하지 않아 로컬 스크리닝으로 "
                   "확정할 수 없습니다."),
    },
}


# Local-screen device-row sentences for _make_local_entry kinds
# "not_affected" (cleared) and "budget" (hit / uncertain but never
# deep-triaged), modelled on KEV_STRINGS. The EN templates
# reproduce the sentences that used to be hardcoded in
# _make_local_entry byte-for-byte; KO gains real translations
# (previously a KO run showed these rows in English).
LOCAL_ROW_STRINGS = {
    "en": {
        "cleared": ("Version %s is outside every vendor-published "
                    "affected range for %s (local version-range "
                    "screen; no API calls)."),
        "hit_unjudged": ("Version %s falls inside a "
                         "vendor-published affected range for %s, "
                         "but deep triage did not run for this "
                         "item (deep-triage budget %d) - "
                         "unconfirmed."),
        "uncertain_unjudged": ("Local screening could not settle "
                               "version %s against the "
                               "vendor-published ranges for %s, "
                               "and deep triage did not run for "
                               "this item (deep-triage budget %d)."),
    },
    "ko": {
        "cleared": ("버전 %s은(는) %s에 대한 제조사 공개 영향 범위를 "
                    "모두 벗어났습니다(로컬 버전 범위 스크리닝; API "
                    "호출 없음)."),
        "hit_unjudged": ("버전 %s은(는) %s에 대한 제조사 공개 영향 "
                         "범위 안에 있지만, 이 항목은 심층 판정이 "
                         "실행되지 않았습니다(심층 판정 예산 %d) - "
                         "미확인."),
        "uncertain_unjudged": ("로컬 스크리닝으로 버전 %s을(를) "
                               "%s에 대한 제조사 공개 범위와 확정할 "
                               "수 없었고, 이 항목은 심층 판정이 "
                               "실행되지 않았습니다(심층 판정 "
                               "예산 %d)."),
    },
}


def _credit_entry(base, lang, text=""):
    # type: (Dict[str, Any], str, str) -> Dict[str, Any]
    """The entry for an item that was never judged because the
    run's Clocked credits are exhausted: the runners' standard
    error-row shape (status "error" + message), so it cannot be
    mistaken for a verdict, with a localized message saying why
    and the "credit_exhausted" flag the UI banner and the feed
    stats key on. `text`, when given, also fills text_hint the
    same way _judge_entry does."""
    entry = dict(base)
    if text:
        hint = ""
        for line in text.splitlines():
            if line.strip():
                hint = line.strip()[:80]
                break
        entry["text_hint"] = hint
    entry["status"] = "error"
    entry["error"] = CREDIT_STRINGS[_normalize_lang(lang)]
    entry["credit_exhausted"] = True
    return entry


def _nvd_windows(now, days=NVD_YEAR_DAYS):
    # type: (datetime.datetime, int) -> List[Tuple[datetime.datetime, datetime.datetime]]
    """Consecutive [start, end] publication windows covering the
    last `days` days, each at most NVD_WINDOW_DAYS long, oldest
    first."""
    end = now
    start = now - datetime.timedelta(days=days)
    windows = []  # type: List[Tuple[datetime.datetime, datetime.datetime]]
    cursor = start
    while cursor < end:
        window_end = min(
            cursor + datetime.timedelta(days=NVD_WINDOW_DAYS), end)
        windows.append((cursor, window_end))
        cursor = window_end
    return windows


def _nvd_ts(moment):
    # type: (datetime.datetime) -> str
    return moment.strftime("%Y-%m-%dT%H:%M:%S.000")


def collect_nvd_items_year(devices, fetcher=None, sleep=None, now=None,
                           progress=None, lang="en", vendor=None):
    # type: (List[Dict[str, str]], Optional[Callable[[str], Any]], Optional[Callable[[float], None]], Optional[datetime.datetime], Optional[Callable[[int, int, str], None]], str, Optional[str]) -> Dict[str, Any]
    """Collect a full year of NVD CVEs for the inventory vendors.

    Same query derivation as collect_nvd_items (at most
    NVD_QUERY_CAP vendor queries; a single term when `vendor`
    scopes the run to one chosen vendor), but each query walks the last
    NVD_YEAR_DAYS in <=119-day windows and paginates within a
    window (resultsPerPage=NVD_PAGE_SIZE, startIndex) until
    totalResults is exhausted. A per-vendor hard cap of
    NVD_VENDOR_YEAR_CAP unique CVEs applies; hitting it (or a
    window whose total could not be fully read) sets "truncated".
    Records are deduped by CVE id across windows and vendors,
    preferring the record that carries configurations (the
    structured ranges the screening lives on). `sleep(seconds)`,
    when given, is called before every HTTP request after the
    first - the live pipeline passes time.sleep; tests pass None.
    Returns collect_nvd_items' keys plus {"windows", "truncated"}.

    `progress`, when given, is called once per completed
    vendor-window as progress(windows_done, vendors x windows,
    label) with the running unique-CVE count in the label - the
    collection stage takes most of a feed run's wall time, so it
    reports like every other stage instead of leaving the UI on
    a static spinner.
    """
    has_key = bool(_nvd_api_key())
    fetch = _nvd_fetcher(fetcher, has_key)
    queries = ([_vendor_query_term(vendor, devices)] if vendor
               else _nvd_query_terms(devices))
    result = {"items": [], "status": "empty", "count": 0,
              "queries": queries, "reason": "", "windows": 0,
              "truncated": False,
              "rate_budget": "key" if has_key else "no-key",
              "requests_made": 0}  # type: Dict[str, Any]
    if not queries:
        result["status"] = "no_vendors"
        return result
    moment = now or datetime.datetime.now(datetime.timezone.utc)
    windows = _nvd_windows(moment)
    result["windows"] = len(windows)
    total_windows = len(queries) * len(windows)
    windows_done = [0]
    labels = PROGRESS_STRINGS[_normalize_lang(lang)]
    by_id = {}  # type: Dict[str, Tuple[Any, str]]
    errors = []  # type: List[str]
    requests_made = [0]

    def fetch_page(url):
        # type: (str) -> Any
        if sleep is not None and requests_made[0] > 0:
            try:
                sleep(_nvd_sleep_seconds(has_key))
            except Exception:
                pass

        def counting_fetch(target_url):
            # type: (str) -> Any
            requests_made[0] += 1
            return fetch(target_url)

        return _fetch_with_retry(counting_fetch, url, sleep)

    for term in queries:
        vendor_count = 0
        for window_start, window_end in windows:
            start_index = 0
            while True:
                if vendor_count >= NVD_VENDOR_YEAR_CAP:
                    result["truncated"] = True
                    break
                url = NVD_API_URL + "?" + urllib.parse.urlencode(
                    {"keywordSearch": term,
                     "resultsPerPage": NVD_PAGE_SIZE,
                     "startIndex": start_index,
                     "pubStartDate": _nvd_ts(window_start),
                     "pubEndDate": _nvd_ts(window_end)})
                try:
                    data = fetch_page(url)
                except Exception as exc:
                    errors.append(str(exc) or exc.__class__.__name__)
                    break
                vulns = (data or {}).get("vulnerabilities") or []
                total = (data or {}).get("totalResults")
                new_ids = 0
                for vuln in vulns:
                    cve = (vuln or {}).get("cve") or {}
                    cve_id = str(cve.get("id") or "").strip()
                    if not cve_id:
                        continue
                    if cve_id in by_id:
                        kept = (by_id[cve_id][0] or {}).get("cve") or {}
                        if not kept.get("configurations") \
                                and cve.get("configurations"):
                            by_id[cve_id] = (vuln, term)
                        continue
                    by_id[cve_id] = (vuln, term)
                    vendor_count += 1
                    new_ids += 1
                fetched = start_index + len(vulns)
                if not vulns:
                    break
                if total is not None:
                    if fetched >= int(total):
                        break
                elif len(vulns) < NVD_PAGE_SIZE or new_ids == 0:
                    break
                start_index = fetched
            windows_done[0] += 1
            _emit_progress(progress, windows_done[0], total_windows,
                           labels["collecting_nvd"] % len(by_id))
    items = []  # type: List[Dict[str, Any]]
    for vuln, term in by_id.values():
        item = _nvd_item(vuln, term)
        if item is not None:
            item.pop("_published", None)
            items.append(item)
    items.sort(key=lambda it: str(it.get("published") or ""),
               reverse=True)
    result["requests_made"] = requests_made[0]
    result["items"] = items
    result["count"] = len(items)
    if items:
        result["status"] = "ok"
    elif errors and requests_made[0] > 0 \
            and len(errors) >= len(queries) * len(windows):
        result["status"] = "fetch_failed"
        result["reason"] = errors[0]
    elif errors:
        result["reason"] = errors[0]
    return result


def collect_feed_items_year(devices, mock=False, nvd_fetcher=None,
                            kev_fetcher=None, sleep=None, now=None,
                            progress=None, lang="en", vendor=None):
    # type: (List[Dict[str, str]], bool, Optional[Callable[[str], Any]], Optional[Callable[[str], Any]], Optional[Callable[[float], None]], Optional[datetime.datetime], Optional[Callable[[int, int, str], None]], str, Optional[str]) -> Dict[str, Any]
    """Collect a full year from both feeds and merge by CVE id.

    NVD items form the base; a KEV entry for the same CVE merges
    into its NVD item (kev=True, due date kept, and the KEV facts
    appended to the item text where the Extract pass and the
    Action block can use them); KEV-only entries are included as
    their own items. Both feeds cover the SAME 365-day lookback:
    KEV matches whose dateAdded predates the window are excluded
    before merging (so an old KEV entry never flags an NVD item
    either) and counted in stats as "kev_older_excluded".
    Returns {"items", "nvd", "kev", "stats"} where the per-feed
    dicts keep their status/count/reason (and NVD's
    windows/truncated, KEV's older_excluded) and "stats" carries
    the merge counts. With `vendor` (a VENDOR_TOKENS key) both
    feeds are scoped to that one vendor - the vendor listing runs.
    With mock=True and no injected fetchers,
    the bundled fixtures answer instead of the network.
    `progress` is forwarded to the NVD collector (one event per
    completed vendor-window) and fires once more when the KEV
    fetch completes, at the same vendors x windows total."""
    if mock:
        if nvd_fetcher is None:
            nvd_fetcher = _fixture_nvd_fetcher
        if kev_fetcher is None:
            kev_fetcher = _fixture_kev_fetcher
    moment = now or datetime.datetime.now(datetime.timezone.utc)
    nvd = collect_nvd_items_year(devices, fetcher=nvd_fetcher,
                                 sleep=sleep, now=moment,
                                 progress=progress, lang=lang,
                                 vendor=vendor)
    kev_min_date = (moment - datetime.timedelta(
        days=NVD_YEAR_DAYS)).date()
    kev = collect_kev_items(devices, fetcher=kev_fetcher,
                            cap=KEV_YEAR_CAP, min_date=kev_min_date,
                            vendor=vendor)
    total_windows = len(nvd.get("queries") or []) \
        * int(nvd.get("windows") or 0)
    _emit_progress(
        progress, total_windows, total_windows,
        PROGRESS_STRINGS[_normalize_lang(lang)]["collecting_kev"]
        % int(kev.get("count") or 0))
    items, merge_stats = merge_feed_items(nvd["items"], kev["items"])
    nvd_info = {key: value for key, value in nvd.items()
                if key != "items"}
    kev_info = {key: value for key, value in kev.items()
                if key != "items"}
    stats = {"nvd_count": nvd["count"], "kev_count": kev["count"],
             "kev_merged": merge_stats["kev_merged"],
             "kev_only": merge_stats["kev_only"],
             "kev_older_excluded": kev.get("older_excluded", 0),
             "total": len(items), "windows": nvd.get("windows", 0),
             "truncated": bool(nvd.get("truncated"))}
    return {"items": items, "nvd": nvd_info, "kev": kev_info,
            "stats": stats}


# ---------------------------------------------------------------------------
# Local version-range screening (zero API calls)
#
# A year of feeds is hundreds of CVEs; judging every one with the
# full Clocked pipeline would be slow and wasteful when the
# vendor's own structured ranges already settle most of them.
# screen_feed_items evaluates each collected item's CPE ranges
# (item["cpe_ranges"], plus any item["traced_ranges"] a vendor
# trace attached - see _evaluate_item) against the inventory
# LOCALLY, reusing triage's device parsing and version
# comparison:
#   - a device version inside an affected range -> candidate-hit
#   - ranges exist and the version is outside all of them ->
#     the device is cleared
#   - no ranges, or a comparison that cannot be made (e.g. a
#     suffix-letter tie) -> uncertain
# An item with a hit or an uncertain related device goes to deep
# triage; an item whose related devices are ALL cleared becomes a
# local NOT AFFECTED row (basis "local-screen"); an item about no
# inventoried product is screened out entirely (counted, not
# shown). Local verdicts come from the vendor-published ranges,
# never from a model.
# ---------------------------------------------------------------------------

LOCAL_SCREEN_LABEL = "Local version-range screen"

_PRODUCT_KEY_DISPLAY = {
    "cisco ios xe": "Cisco IOS XE",
    "cisco ios": "Cisco IOS",
    "cisco nx-os": "Cisco NX-OS",
    "cisco asa-ftd": "Cisco ASA / FTD",
    "juniper junos": "Juniper Junos OS",
    "juniper junos evolved": "Juniper Junos OS Evolved",
    "arista eos": "Arista EOS",
    "arista cloudvision": "Arista CloudVision",
    "nokia sr os": "Nokia SR OS",
    "extreme exos": "Extreme EXOS",
    "f5 big-ip": "F5 BIG-IP",
    "palo alto pan-os": "Palo Alto PAN-OS",
    "fortinet fortios": "Fortinet FortiOS",
    "microsoft windows": "Microsoft Windows",
    "vmware esxi": "VMware ESXi",
}

# Text phrases that identify a product family when an item carries
# no structured ranges (KEV entries, range-less NVD records).
# Ordered: specific phrases before their prefixes ("ios xe"
# before the bare "eos" catch is irrelevant, but "windows server"
# precedes "windows" for display fidelity only - both map alike).
_TEXT_PRODUCT_PHRASES = [
    ("ios xe", "cisco ios xe"), ("ios-xe", "cisco ios xe"),
    ("nx-os", "cisco nx-os"), ("nx os", "cisco nx-os"),
    ("junos os evolved", "juniper junos evolved"),
    ("junos evolved", "juniper junos evolved"),
    ("junos", "juniper junos"),
    ("cloudvision", "arista cloudvision"),
    ("cvp", "arista cloudvision"),
    ("firepower", "cisco asa-ftd"), ("asa", "cisco asa-ftd"),
    ("big-ip", "f5 big-ip"), ("bigip", "f5 big-ip"),
    ("pan-os", "palo alto pan-os"),
    ("fortios", "fortinet fortios"),
    ("windows server", "microsoft windows"),
    ("windows", "microsoft windows"),
    ("esxi", "vmware esxi"), ("vsphere", "vmware esxi"),
    ("sr os", "nokia sr os"), ("sros", "nokia sr os"),
    ("extremexos", "extreme exos"), ("exos", "extreme exos"),
    ("eos", "arista eos"),
]

_CPE_VENDOR_KEYS = [
    ("juniper", "juniper"), ("cisco", "cisco"), ("arista", "arista"),
    ("palo", "paloalto"), ("fortinet", "fortinet"),
    ("microsoft", "microsoft"), ("vmware", "vmware"),
    ("nokia", "nokia"), ("extreme", "extreme"),
    ("citrix", "citrix"), ("broadcom", "broadcom"),
    ("check_point", "checkpoint"), ("checkpoint", "checkpoint"),
    ("netscout", "arbor"), ("arbor", "arbor"),
    ("supermicro", "supermicro"), ("lenovo", "lenovo"),
    ("dell", "dell"), ("f5", "f5"), ("a10", "a10"),
    ("hp", "hpe"), ("ahnlab", "ahnlab"), ("piolink", "piolink"),
]


def _cpe_product_key(vendor, product):
    # type: (Any, Any) -> Optional[str]
    """Normalize a CPE vendor/product pair to a fleet product key
    ("juniper junos", "cisco ios xe", ...), or None when the
    product is outside the explicit map - the caller then falls
    back to token overlap via triage.product_matches."""
    p = str(product or "").lower().replace("_", "-")
    v = str(vendor or "").lower()
    if "junos" in p and ("evolved" in p or "_evo" in p
                         or p.endswith("-evo")):
        return "juniper junos evolved"
    if "junos" in p:
        return "juniper junos"
    if "ios-xe" in p:
        return "cisco ios xe"
    if "nx-os" in p:
        return "cisco nx-os"
    if p == "ios" and "cisco" in v:
        return "cisco ios"
    if (p in ("asa", "ftd", "adaptive-security-appliance")
            or p.startswith("firepower")
            or p.startswith("secure-firewall")):
        return "cisco asa-ftd"
    if p in ("cloudvision", "cvp", "cloudvision-portal"):
        return "arista cloudvision"
    if p == "eos" and ("arista" in v or not v):
        return "arista eos"
    if p.startswith("big-ip"):
        return "f5 big-ip"
    if "pan-os" in p:
        return "palo alto pan-os"
    if "fortios" in p:
        return "fortinet fortios"
    if p.startswith("windows"):
        return "microsoft windows"
    if "esxi" in p or p == "vsphere":
        return "vmware esxi"
    if "sr-os" in p or "sros" in p:
        return "nokia sr os"
    if p == "exos" or "extremexos" in p:
        return "extreme exos"
    return None


def _cpe_vendor_key(vendor):
    # type: (Any) -> Optional[str]
    """Map a CPE vendor string ("paloaltonetworks", "f5") to a
    VENDOR_TOKENS key, or None."""
    v = str(vendor or "").lower()
    for needle, key in _CPE_VENDOR_KEYS:
        if needle in v:
            return key
    return None


def _device_product_keys(device):
    # type: (Dict[str, str]) -> Set[str]
    """Product keys a device plausibly runs, from its model text
    and detected vendor. Hardware families imply their OS
    (Catalyst/ASR/ISR run IOS XE, Nexus runs NX-OS, every Juniper
    box runs Junos, every Arista box runs EOS); an unrecognized
    Cisco model keeps both Cisco OS keys so a range check clears
    it only when BOTH families' ranges exclude its version -
    a false candidate is cheaper than a false clear."""
    model = str((device or {}).get("model") or "")
    version = str((device or {}).get("version") or "")
    lowered = model.lower()
    combined = (model + " " + version).lower()
    vendor = _device_vendor(device)
    keys = set()  # type: Set[str]
    evolved = ("evolved" in combined
               or re.search(r"-evo\b|\bevo\b", combined))
    if evolved and (vendor == "juniper" or "junos" in combined
                    or vendor is not None and "junos" in lowered):
        keys.add("juniper junos evolved")
    elif vendor == "juniper" or "junos" in lowered:
        keys.add("juniper junos")
    cloudvision = ("cloudvision" in lowered
                   or re.search(r"\bcvp\b", lowered))
    if cloudvision:
        keys.add("arista cloudvision")
    if not cloudvision and (vendor == "arista"
                            or re.search(r"\beos\b", lowered)):
        keys.add("arista eos")
    if ("firepower" in lowered or "secure firewall" in lowered
            or re.search(r"\basa\d|\basa\b|\bftd\b", lowered)):
        keys.add("cisco asa-ftd")
    if vendor == "nokia" or "sr os" in lowered or "sros" in lowered:
        keys.add("nokia sr os")
    if vendor == "extreme" or "exos" in lowered:
        keys.add("extreme exos")
    if "nexus" in lowered or "nx-os" in lowered:
        keys.add("cisco nx-os")
    if "ios xe" in lowered or "ios-xe" in lowered:
        keys.add("cisco ios xe")
    if vendor == "cisco":
        if any(word in lowered for word in
               ("catalyst", "asr", "isr", "csr")):
            keys.add("cisco ios xe")
        if not keys:
            keys.update(("cisco ios", "cisco ios xe"))
    if "big-ip" in lowered or "bigip" in lowered:
        keys.add("f5 big-ip")
    if vendor == "paloalto" or "pan-os" in lowered:
        keys.add("palo alto pan-os")
    if "forti" in lowered:
        keys.add("fortinet fortios")
    if "windows" in lowered:
        keys.add("microsoft windows")
    if "esxi" in lowered or "vsphere" in lowered:
        keys.add("vmware esxi")
    return keys


def _eval_range(device_version, rng):
    # type: (str, Dict[str, Any]) -> Optional[bool]
    """Evaluate one structured range against a device version:
    True inside, False outside, None when the comparison cannot
    be made (unparseable version, or a numeric tie with differing
    letter suffixes - triage._compare_versions refuses to guess
    those, and so does the screen)."""
    return _eval_range_detail(device_version, rng)[0]


def _eval_range_detail(device_version, rng):
    # type: (str, Dict[str, Any]) -> Tuple[Optional[bool], Optional[str]]
    """_eval_range plus the deciding comparison's flavour:
    "train_equal" / "suffix_equal" when an EOS equality rule
    (R1/R2) decided a bound, "suffix_mismatch" / "unparseable"
    when the evaluation is inconclusive for that reason, else
    None. The bool is exactly _eval_range's result.

    EOS context is resolved from the range dict itself: the
    range's vendor/product must map to the "arista eos" fleet
    product key - the same key _screen_item groups ranges by.
    Unmapped ranges (key None) keep the generic comparison, so
    R1/R2 can never leak into another vendor's ranges."""
    eos = _cpe_product_key(rng.get("vendor"),
                           rng.get("product")) == "arista eos"
    if rng.get("exact"):
        result, detail = version_matches_detail(
            device_version, str(rng["exact"]), eos_rules=eos)
        if result is False and "*" not in str(rng["exact"]) \
                and "-" not in str(rng["exact"]):
            compared, cmp_detail = _compare_versions_detail(
                device_version, str(rng["exact"]), eos_rules=eos)
            if compared is None:
                # A plain exact version whose comparison cannot be
                # made (numeric tie with differing letter suffixes,
                # e.g. EOS 4.30.5F vs 4.30.5M) is inconclusive,
                # never a clear (invariant I-2).
                return None, cmp_detail
        return result, detail
    checks = []  # type: List[Tuple[Optional[bool], Optional[int], Optional[str]]]
    bounds = (
        ("start_including", lambda c: c >= 0),
        ("start_excluding", lambda c: c > 0),
        ("end_including", lambda c: c <= 0),
        ("end_excluding", lambda c: c < 0),
    )
    for field, predicate in bounds:
        bound = rng.get(field)
        if bound:
            compared, cmp_detail = _compare_versions_detail(
                device_version, str(bound), eos_rules=eos)
            checks.append((None if compared is None
                            else bool(predicate(compared)),
                           compared, cmp_detail))
    if not checks:
        return None, None
    if any(check is False for check, _compared, _detail in checks):
        return False, None
    if any(check is None for check, _compared, _detail in checks):
        details = [detail for check, _compared, detail in checks
                   if check is None]
        if "suffix_mismatch" in details:
            return None, "suffix_mismatch"
        if "unparseable" in details:
            return None, "unparseable"
        return None, None
    for _check, compared, cmp_detail in checks:
        if compared == 0 \
                and cmp_detail in ("train_equal", "suffix_equal"):
            return True, cmp_detail
    return True, None


def _screen_item(item, devices, device_keys_list):
    # type: (Dict[str, Any], List[Dict[str, str]], List[Set[str]]) -> Dict[str, Any]
    """Screen one collected item against the inventory devices.

    Returns {"outcome", "evals", "eval_codes", "has_hit",
    "displays", "range_lines"} where "evals" aligns with
    `devices` and holds "hit" | "cleared" | "uncertain" |
    "unrelated" per device, "eval_codes" is the parallel
    reason-code list (design §2.2/§2.3: the deciding range's
    flavour for a hit, the uncertainty precedence for an
    uncertain device), and
    "outcome" is "candidate" (hit or uncertain related device),
    "local" (related devices all cleared) or "out" (no inventoried
    product involved)."""
    ranges = (item or {}).get("cpe_ranges") or []
    ranges_by_key = {}  # type: Dict[str, List[Dict[str, Any]]]
    unmapped = []  # type: List[Dict[str, Any]]
    item_keys = set()  # type: Set[str]
    displays = []  # type: List[str]
    range_lines = []  # type: List[str]
    for rng in ranges:
        if not isinstance(rng, dict):
            continue
        line = _range_display(rng)
        if line not in range_lines:
            range_lines.append(line)
        key = _cpe_product_key(rng.get("vendor"), rng.get("product"))
        if key is not None:
            item_keys.add(key)
            ranges_by_key.setdefault(key, []).append(rng)
            display = _PRODUCT_KEY_DISPLAY.get(key, key)
        else:
            unmapped.append(rng)
            display = ("%s %s" % (rng.get("vendor") or "",
                                  rng.get("product") or "")).strip()
        if display and display not in displays:
            displays.append(display)
    text = str((item or {}).get("text") or "")
    lowered = text.lower()
    for phrase, key in _TEXT_PRODUCT_PHRASES:
        if re.search(r"(?<![a-z0-9])%s(?![a-z0-9])" % re.escape(phrase),
                     lowered):
            item_keys.add(key)
            display = _PRODUCT_KEY_DISPLAY.get(key, key)
            if display not in displays:
                displays.append(display)

    evals = []  # type: List[str]
    eval_codes = []  # type: List[Optional[str]]
    any_related = False
    for device, device_keys in zip(devices, device_keys_list):
        shared = item_keys & device_keys
        device_ranges = []  # type: List[Dict[str, Any]]
        for key in shared:
            device_ranges.extend(ranges_by_key.get(key) or [])
        related = bool(shared)
        unmapped_related = False
        for rng in unmapped:
            display = ("%s %s" % (rng.get("vendor") or "",
                                  rng.get("product") or "")).strip()
            if display and product_matches(
                    str(device.get("model") or ""), [display]):
                related = True
                unmapped_related = True
                device_ranges.append(rng)
        if not related:
            evals.append("unrelated")
            eval_codes.append("PRODUCT_MISMATCH")
            continue
        any_related = True
        if not device_ranges:
            evals.append("uncertain")
            eval_codes.append("NO_VERSION_EVIDENCE")
            continue
        detailed = [_eval_range_detail(
            str(device.get("version") or ""), rng)
            for rng in device_ranges]
        outcomes = [outcome for outcome, _detail in detailed]
        if any(outcome is True for outcome in outcomes):
            evals.append("hit")
            hit_details = [detail for outcome, detail in detailed
                           if outcome is True]
            if "train_equal" in hit_details:
                eval_codes.append("VERSION_TRAIN_EQUAL")
            elif "suffix_equal" in hit_details:
                eval_codes.append("VERSION_SUFFIX_EQUAL")
            else:
                eval_codes.append("VERSION_IN_RANGE")
        elif all(outcome is False for outcome in outcomes):
            # A clear from partially parsed ranges (JSA prose
            # extraction) is not evidence of absence: downgrade
            # to uncertain. A hit from a partial range stays a
            # hit - the device is inside a stated branch.
            if any(rng.get("partial") for rng in device_ranges):
                evals.append("uncertain")
                eval_codes.append("RANGE_PARTIAL")
            else:
                evals.append("cleared")
                eval_codes.append("VERSION_OUT_OF_RANGE")
        else:
            evals.append("uncertain")
            details = [detail for _outcome, detail in detailed]
            if "suffix_mismatch" in details:
                eval_codes.append("VERSION_SUFFIX_MISMATCH")
            elif "unparseable" in details:
                eval_codes.append("VERSION_UNPARSEABLE")
            elif any(rng.get("partial") for rng in device_ranges):
                eval_codes.append("RANGE_PARTIAL")
            elif unmapped_related:
                eval_codes.append("PRODUCT_UNMAPPED")
            else:
                eval_codes.append("VERSION_INCONCLUSIVE")

    if not any_related:
        # No product-level relation: fall back to vendor-level.
        # Same vendor but an unidentifiable product is uncertain
        # (a candidate), never a clear - the screen only clears on
        # structured ranges.
        item_vendors = set()  # type: Set[str]
        for rng in ranges:
            if isinstance(rng, dict):
                vendor_key = _cpe_vendor_key(rng.get("vendor"))
                if vendor_key:
                    item_vendors.add(vendor_key)
        fleet_vendors = set(inventory_vendors(devices))
        if not item_vendors:
            for vendor in fleet_vendors:
                display = VENDOR_DISPLAY_NAMES.get(vendor, vendor)
                if vendor in lowered or display.lower() in lowered:
                    item_vendors.add(vendor)
        shared_vendors = item_vendors & fleet_vendors
        if shared_vendors:
            evals = [
                "uncertain" if _device_vendor(device) in shared_vendors
                else "unrelated"
                for device in devices]
            eval_codes = [
                "PRODUCT_UNMAPPED" if ev == "uncertain"
                else "PRODUCT_MISMATCH"
                for ev in evals]
            any_related = any(ev == "uncertain" for ev in evals)

    has_hit = any(ev == "hit" for ev in evals)
    if not any_related:
        outcome = "out"
    elif has_hit or any(ev == "uncertain" for ev in evals):
        outcome = "candidate"
    else:
        outcome = "local"
    return {"outcome": outcome, "evals": evals,
            "eval_codes": eval_codes, "has_hit": has_hit,
            "displays": displays, "range_lines": range_lines[:12]}


def _merged_ranges_item(item):
    # type: (Dict[str, Any]) -> Dict[str, Any]
    """Copy of a feed item with its traced ranges (item
    ["traced_ranges"], attached by trace_items from the vendor
    original) folded into "cpe_ranges", so the one screening
    evaluation sees every structured range the item carries,
    whatever feed or vendor document it came from."""
    merged = dict(item or {})
    ranges = list(merged.get("cpe_ranges") or [])
    for rng in merged.get("traced_ranges") or []:
        if isinstance(rng, dict) and rng not in ranges:
            ranges.append(rng)
    merged["cpe_ranges"] = ranges
    return merged


def _evaluate_item(item, devices, device_keys_list=None):
    # type: (Dict[str, Any], List[Dict[str, str]], Optional[List[Set[str]]]) -> Dict[str, Any]
    """The single per-item screening evaluation (see
    _screen_item), over the item's NVD CPE ranges PLUS any ranges
    its vendor trace attached. screen_feed_items runs it on the
    freshly collected items; run_feed_pipeline runs it again on
    traced candidates, where the vendor original often settles a
    record the feed left range-less. Returns _screen_item's
    evaluation dict."""
    if device_keys_list is None:
        device_keys_list = [_device_product_keys(device)
                            for device in devices]
    return _screen_item(_merged_ranges_item(item), devices,
                        device_keys_list)


def _make_local_entry(item, devices, evaluation, kind, lang,
                      budget=0, today=None):
    # type: (Dict[str, Any], List[Dict[str, str]], Dict[str, Any], str, str, int, Optional[datetime.date]) -> Dict[str, Any]
    """Build a batch entry whose triage result was produced
    LOCALLY (no Clocked calls), in the exact run_triage result
    shape the renderer and the action summary consume.

    kind "not_affected": screening cleared every related device -
    verdict NOT AFFECTED. kind "budget": a candidate the deep-
    triage budget did not reach - verdict CANNOT DETERMINE with
    the reason stated plainly. kind "kev_unconfirmed": a KEV item
    whose product matches but for which no source publishes a
    version range - verdict CONDITION CHECK REQUIRED with the
    dedicated KEV reason, condition and checklist (the product
    match is the settled fact; the open question is exactly the
    version/condition check - KEV membership alone never settles
    more than that). All carry basis
    "local-screen" and the "Local version-range screen" source
    label. `today` (a datetime.date) drives the overdue-due-date
    warning deterministically; it defaults to the real today."""
    lang = _normalize_lang(lang)
    reasons = REASON_STRINGS[lang]
    displays = evaluation.get("displays") or []
    product_label = ", ".join(displays) if displays \
        else "the named product"
    cve_id = _item_cve_id(item)
    label = str((item or {}).get("label") or cve_id or "")
    evals = evaluation.get("evals") or []
    if kind == "not_affected":
        verdict = VERDICT_NOT_AFFECTED
    elif kind == "kev_unconfirmed":
        verdict = VERDICT_CONDITION
    else:
        verdict = VERDICT_CANNOT
    eval_codes = evaluation.get("eval_codes") or []
    row_strings = LOCAL_ROW_STRINGS[lang]
    device_rows = []  # type: List[Dict[str, Any]]
    for index, (device, ev) in enumerate(zip(devices, evals)):
        hostname = str(device.get("hostname") or "")
        model = str(device.get("model") or "")
        version = str(device.get("version") or "")
        eval_code = eval_codes[index] \
            if index < len(eval_codes) else None
        if ev == "unrelated":
            device_rows.append(_row(
                hostname, model, version, False, VERDICT_NOT_AFFECTED,
                reasons["different_product"],
                reason_code="PRODUCT_MISMATCH"))
        elif kind == "not_affected":
            device_rows.append(_row(
                hostname, model, version, True, VERDICT_NOT_AFFECTED,
                row_strings["cleared"] % (version, product_label),
                reason_code=eval_code or "VERSION_OUT_OF_RANGE"))
        elif kind == "kev_unconfirmed":
            device_rows.append(_row(
                hostname, model, version, True, VERDICT_CONDITION,
                KEV_STRINGS[lang]["reason"] % (product_label,
                                               version),
                reason_code="KEV_NO_VERSION_RANGE"))
        elif ev == "hit":
            device_rows.append(_row(
                hostname, model, version, True, VERDICT_CANNOT,
                row_strings["hit_unjudged"] % (
                    version, product_label, budget),
                reason_code=eval_code or "VERSION_IN_RANGE"))
        else:
            device_rows.append(_row(
                hostname, model, version, True, VERDICT_CANNOT,
                row_strings["uncertain_unjudged"] % (
                    version, product_label, budget),
                reason_code=eval_code or "VERSION_INCONCLUSIVE"))
    if kind == "not_affected":
        action_required = (
            "No action required - fleet versions are outside every "
            "vendor-published affected range for %s (screened "
            "locally)." % product_label)
        checklist = generate_checklist(VERDICT_NOT_AFFECTED,
                                       "monitor", lang=lang)
        warnings = []  # type: List[str]
        conditions = []  # type: List[str]
    elif kind == "kev_unconfirmed":
        kev_strings = KEV_STRINGS[lang]
        action_required = kev_strings["action"] % product_label
        conditions = [kev_strings["condition"]]
        kev_steps = [kev_strings["check_version"] % product_label]
        due_date = str((item or {}).get("due_date") or "")
        required_action = str((item or {}).get("required_action")
                              or "")
        if due_date or required_action:
            kev_steps.append(kev_strings["check_action"] % (
                due_date or "the KEV due date", required_action))
        ransomware = str((item or {}).get("ransomware") or "")
        if ransomware == "Known":
            kev_steps.append(kev_strings["check_ransomware"])
        checklist = kev_steps + generate_checklist(
            VERDICT_CONDITION, "monitor", lang=lang)
        warnings = []
        run_today = today or datetime.date.today()
        due_parsed = _parse_iso_date(due_date)
        if due_parsed is not None and due_parsed < run_today:
            warnings.append(kev_strings["warn_overdue"] % due_date)
        if ransomware == "Known":
            warnings.append(kev_strings["warn_ransomware"])
    else:
        action_required = (
            "Confirm the affected versions for %s manually, or "
            "re-run with Judge all: structured screening was "
            "inconclusive and this item was beyond this run's "
            "deep-triage budget (%d)." % (product_label, budget))
        checklist = [action_required] + generate_checklist(
            VERDICT_CANNOT, "monitor", lang=lang)
        warnings = [
            "Deep-triage budget reached: this verdict comes from "
            "local screening only - no Clocked calls were spent "
            "on this item."]
        conditions = []
    ranges = (item or {}).get("cpe_ranges") or []
    vendor_text = ""
    if ranges and isinstance(ranges[0], dict):
        vendor_text = str(ranges[0].get("vendor") or "")
    extracted = {
        "vendor": vendor_text,
        "products": displays,
        "affected_versions": evaluation.get("range_lines") or [],
        "advisory_id": cve_id or label,
        "cve_id": cve_id,
        "severity": "",
        "fixed_version": None,
        "action_deadline": (item or {}).get("due_date") or None,
    }
    triage_result = {
        "mode": "local",
        "sample_id": None,
        "basis": "local-screen",
        "extracted": extracted,
        "extract_raw": {"fields": {}},
        "decide_raw": {},
        "decide": {
            "urgency_immediate": {"value": None, "probability": None},
            "urgency_planned": {"value": None, "probability": None},
            "evidence_sufficient": {"value": None,
                                    "probability": None},
            "urgency": "monitor",
        },
        "grounding_raw": {},
        "grounding": {"verdict": "local-screen",
                      "answers_question": None, "supported": True,
                      "grounded": None, "ungrounded": None},
        "device_results": device_rows,
        "verdict": verdict,
        "reason_code": {"not_affected": "SCREEN_CLEARED",
                        "kev_unconfirmed": "KEV_NO_VERSION_RANGE",
                        "budget": "BUDGET_EXHAUSTED"}[kind],
        "urgency": "monitor",
        "warnings": warnings,
        "conditions": conditions,
        "claim": build_claim(verdict, device_rows, extracted),
        "checklist": checklist,
        "clocked_calls": 0,
        "action_required": action_required,
    }
    hint = ""
    for line in str((item or {}).get("text") or "").splitlines():
        if line.strip():
            hint = line.strip()[:80]
            break
    entry = {"url": str((item or {}).get("url") or ""),
             "label": label,
             "status": "ok",
             "text_hint": hint,
             "source_label": LOCAL_SCREEN_LABEL,
             "basis": "local-screen",
             "kev": bool((item or {}).get("kev")),
             "published": str((item or {}).get("published") or ""),
             "sources": _derived_sources(item or {}),
             "triage": triage_result}  # type: Dict[str, Any]
    if kind == "kev_unconfirmed":
        # Only local KEV rows carry an entry-level due date (the
        # detail view's KEV-due source badge keys on it).
        entry["due_date"] = str((item or {}).get("due_date") or "")
    return entry


def screen_feed_items(items, inventory_text, lang="en"):
    # type: (List[Dict[str, Any]], str, str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]
    """Screen collected feed items against the inventory locally
    (see the section header). Devices are parsed with triage's
    parse_inventory - the same parser the judging path uses.

    Returns (local_rows, candidates, screen_stats): local_rows
    are batch entries with a locally produced NOT AFFECTED triage
    result; candidates are the item dicts that still need deep
    triage; screen_stats is {"collected", "not_in_fleet",
    "local_not_affected", "candidates", "uncertain_candidates"}
    where uncertain_candidates counts the candidates no device
    was range-hit by (they are candidates on uncertainty alone).
    """
    devices = parse_inventory(inventory_text)
    device_keys_list = [_device_product_keys(device)
                        for device in devices]
    local_rows = []  # type: List[Dict[str, Any]]
    candidates = []  # type: List[Dict[str, Any]]
    stats = {"collected": len(items or []), "not_in_fleet": 0,
             "local_not_affected": 0, "candidates": 0,
             "uncertain_candidates": 0,
             "unmapped_products": 0}  # type: Dict[str, Any]
    unmapped_seen = set()  # type: Set[str]
    for item in items or []:
        for rng in _merged_ranges_item(item).get("cpe_ranges") or []:
            if isinstance(rng, dict) and _cpe_product_key(
                    rng.get("vendor"), rng.get("product")) is None:
                unmapped_seen.add("%s:%s" % (
                    rng.get("vendor") or "", rng.get("product") or ""))
        evaluation = _evaluate_item(item, devices, device_keys_list)
        outcome = evaluation["outcome"]
        if outcome == "out":
            stats["not_in_fleet"] += 1
        elif outcome == "local":
            local_rows.append(_make_local_entry(
                item, devices, evaluation, "not_affected", lang))
            stats["local_not_affected"] += 1
        else:
            candidates.append(item)
            stats["candidates"] += 1
            if not evaluation["has_hit"]:
                stats["uncertain_candidates"] += 1
    stats["unmapped_products"] = len(unmapped_seen)
    return local_rows, candidates, stats


# ---------------------------------------------------------------------------
# Feed pipeline: collect a year -> screen locally -> trace ->
# re-screen on the traced vendor ranges -> deep-triage only the
# surviving candidates
# ---------------------------------------------------------------------------

def _candidate_order(items, hit_ids=None):
    # type: (List[Dict[str, Any]], Optional[Set[int]]) -> List[Dict[str, Any]]
    """Deep-triage priority: known-exploited (KEV) first, then
    severity rank descending, then - within the same KEV/severity
    tier - items some fleet device was range-HIT by (confirmed
    exposure; `hit_ids` holds their id()) ahead of purely
    uncertain ones, then most recently published. (Stable sorts
    applied in reverse priority order.)"""
    ordered = sorted(items, key=lambda it: str(it.get("published")
                                               or ""),
                     reverse=True)
    if hit_ids:
        ordered.sort(key=lambda it: 0 if id(it) in hit_ids else 1)
    ordered.sort(key=lambda it: -int(it.get("severity_rank") or 0))
    ordered.sort(key=lambda it: 0 if it.get("kev") else 1)
    return ordered


def _entry_verdict_rank(entry):
    # type: (Dict[str, Any]) -> int
    verdict = str(((entry or {}).get("triage") or {}).get("verdict")
                  or "")
    return {VERDICT_AFFECTED: 0, VERDICT_CONDITION: 1,
            VERDICT_CANNOT: 2,
            VERDICT_NOT_AFFECTED: 3}.get(verdict, 2)


def run_feed_pipeline(inventory_text, api_key=None, lang="en",
                      judge_all=False, progress=None, mock=False,
                      nvd_fetcher=None, kev_fetcher=None,
                      trace_fetcher=None, trace_json_fetcher=None,
                      sleep=None, now=None, vendor=None):
    # type: (str, Optional[str], str, bool, Optional[Callable[[int, int, str], None]], bool, Optional[Callable[[str], Any]], Optional[Callable[[str], Any]], Optional[Callable[[str], str]], Optional[Callable[[str], Any]], Optional[Callable[[float], None]], Optional[datetime.datetime], Optional[str]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]
    """Run the feeds source end to end.

    Collect a full year (collect_feed_items_year) -> screen
    locally (screen_feed_items; zero API calls) -> trace the
    candidates to their vendor originals (trace_items, up to
    TRACE_SCREEN_CAP in priority order) -> RE-SCREEN each traced
    candidate on the ranges its vendor document attached: when
    every related fleet device clears, the candidate becomes a
    local NOT AFFECTED row (vendor source label kept) and spends
    NO deep-triage budget -> deep-triage the surviving candidates
    with run_batch_items. `mock=True` covers the WHOLE pipeline:
    the bundled fixtures answer collection and tracing, and the
    deep triage itself is judged in Mock Mode (run_batch_items
    receives mock too), so a mock run makes no network or Clocked
    calls even when an API key is configured. Most fresh CVEs
    carry no NVD ranges at all, so the trace is what makes the
    screen effective. The
    deep-triage budget is FULL_TRIAGE_CAP, or JUDGE_ALL_CAP when
    judge_all is set; candidates beyond it become local CANNOT
    DETERMINE rows that say so plainly. Returns (rows, stats):
    rows are batch entries sorted KEV first, then AFFECTED >
    CONDITION CHECK REQUIRED > CANNOT DETERMINE > NOT AFFECTED,
    then newest published;
    stats carries the per-feed outcome dicts, the collection
    stats, the screening stats (whose local_not_affected count
    includes the re-screened clears), the trace outcome,
    "traced_for_screen" (candidates the trace-for-screen pass
    attempted), "rescreened_not_affected" and the budget actually
    used. stats["credit_exhausted"] reports whether the deep
    triage hit Clocked credit exhaustion (its entries then carry
    the flag too; the local screening rows are unaffected). With
    `vendor` (a VENDOR_TOKENS key) the collection is scoped to
    that one vendor - the vendor listing runs: the same pipeline,
    fed only that vendor's NVD query and KEV matches, screened
    and judged against the full inventory as usual; stats then
    carries "vendor" so the UI can label the run honestly as a
    structured-source vendor listing. In
    live mode (not mock, no injected fetchers) NVD
    requests are spaced with time.sleep. `progress`, when given,
    reports EVERY stage through the one callback - collection
    (per vendor-window, then the KEV fetch), the local screening
    (a single event), the trace-for-screen pass (per attempted
    candidate) and the deep triage (per item, via run_batch_items)
    - so the UI's bar and counts move from the first seconds of
    the run instead of only during the final stage.
    """
    if sleep is None and not mock and nvd_fetcher is None:
        sleep = time.sleep
    devices = parse_inventory(inventory_text)
    device_keys_list = [_device_product_keys(device)
                        for device in devices]
    feed = collect_feed_items_year(
        devices, mock=mock, nvd_fetcher=nvd_fetcher,
        kev_fetcher=kev_fetcher, sleep=sleep, now=now,
        progress=progress, lang=lang, vendor=vendor)
    local_rows, candidates, screen_stats = screen_feed_items(
        feed["items"], inventory_text, lang=lang)
    _emit_progress(
        progress, 1, 1,
        PROGRESS_STRINGS[_normalize_lang(lang)]["screening"])
    budget = JUDGE_ALL_CAP if judge_all else FULL_TRIAGE_CAP
    hit_ids = set()  # type: Set[int]
    for item in candidates:
        if _evaluate_item(item, devices,
                          device_keys_list)["has_hit"]:
            hit_ids.add(id(item))
    ordered = _candidate_order(candidates, hit_ids=hit_ids)
    traced_pool, trace_stats = trace_items(
        ordered[:TRACE_SCREEN_CAP], mock=mock,
        fetcher=trace_fetcher, json_fetcher=trace_json_fetcher,
        cap=TRACE_SCREEN_CAP, progress=progress, lang=lang)
    rows = list(local_rows)  # type: List[Dict[str, Any]]
    rescreened = 0
    survivors = []  # type: List[Dict[str, Any]]
    for item in traced_pool:
        evaluation = _evaluate_item(item, devices, device_keys_list)
        if evaluation["outcome"] == "local":
            entry = _make_local_entry(
                _merged_ranges_item(item), devices, evaluation,
                "not_affected", lang)
            # The verdict is local, but the evidence is the
            # vendor's own document - the UI shows that source.
            if (item or {}).get("source_label"):
                entry["source_label"] = str(item["source_label"])
            if (item or {}).get("source_url"):
                entry["source_url"] = str(item["source_url"])
            rows.append(entry)
            rescreened += 1
            continue
        survivors.append(item)
    survivors.extend(ordered[TRACE_SCREEN_CAP:])
    # K-2 partition: a KEV survivor with no version range from
    # any source (NVD, KEV itself, or a trace) becomes a local
    # kev_unconfirmed row - deep triage cannot manufacture
    # version evidence from a range-less text, so it spends no
    # budget here and the freed slots flow to range-bearing
    # candidates.
    run_today = (now or datetime.datetime.now(
        datetime.timezone.utc)).date()
    kev_local_items = []  # type: List[Dict[str, Any]]
    rest = []  # type: List[Dict[str, Any]]
    for survivor in survivors:
        if survivor.get("kev") and not _merged_ranges_item(
                survivor)["cpe_ranges"]:
            kev_local_items.append(survivor)
        else:
            rest.append(survivor)
    for kev_item in kev_local_items:
        evaluation = _evaluate_item(kev_item, devices,
                                    device_keys_list)
        rows.append(_make_local_entry(
            _merged_ranges_item(kev_item), devices, evaluation,
            "kev_unconfirmed", lang, today=run_today))
    survivors = rest
    judged_items = survivors[:budget]
    over_items = survivors[budget:]
    entries = run_batch_items(
        judged_items, inventory_text, api_key=api_key, lang=lang,
        progress=progress, prefilter=False, mock=mock)
    # Run-level credit state for the UI banner: run_batch_items
    # fails fast on the first 402, so any credit entry among the
    # deep-triage results means the run's Clocked calls died part
    # way (local rows above and below are unaffected - they never
    # spend calls).
    credit_exhausted = any(
        bool(entry.get("credit_exhausted")) for entry in entries)
    for item, entry in zip(judged_items, entries):
        entry["kev"] = bool((item or {}).get("kev"))
        entry["published"] = str((item or {}).get("published") or "")
        entry["sources"] = _derived_sources(item or {})
        rows.append(entry)
    for item in over_items:
        evaluation = _evaluate_item(item, devices, device_keys_list)
        rows.append(_make_local_entry(
            _merged_ranges_item(item), devices, evaluation,
            "budget", lang, budget=budget))
    rows.sort(key=lambda e: str(e.get("published") or ""),
              reverse=True)
    rows.sort(key=_entry_verdict_rank)
    rows.sort(key=lambda e: 0 if e.get("kev") else 1)
    screen_stats["local_not_affected"] += rescreened
    reachability = {} if mock else probe_sources()
    # Additive stat: entries whose final verdict is the CONDITION
    # grade (K-2 local rows plus any deep-triaged gated entries).
    # No existing key is renamed - "kev_unconfirmed" still counts
    # the K-2 rows specifically.
    condition_check = sum(
        1 for row in rows
        if str((row.get("triage") or {}).get("verdict") or "")
        == VERDICT_CONDITION)
    stats = {"nvd": feed["nvd"], "kev": feed["kev"],
             "vendor": vendor,
             "collection": feed["stats"], "screening": screen_stats,
             "traced": trace_stats.get("traced", 0),
             "trace_stats": trace_stats,
             "traced_for_screen": trace_stats.get("attempted", 0),
             "rescreened_not_affected": rescreened,
             "deep_triaged": len(judged_items),
             "kev_unconfirmed": len(kev_local_items),
             "condition_check": condition_check,
             "reachability": reachability,
             "budget": budget,
             "candidates": len(candidates),
             "credit_exhausted": credit_exhausted}
    return rows, stats


def uploaded_file_to_item(name, data):
    # type: (str, bytes) -> Dict[str, Any]
    """Turn one uploaded advisory file into a batch item: bytes are
    decoded with the inventory CSV chain (utf-8-sig -> utf-8 ->
    cp949), HTML (by .html/.htm name or by content) is reduced to
    text with the same converter as fetched pages, and the text is
    capped at MAX_TEXT_CHARS. The item URL is empty - the filename
    is the label."""
    text, _encoding = _decode_bytes(bytes(data or b""))
    lowered = (name or "").lower()
    head = text.lstrip()[:64].lower()
    if lowered.endswith((".html", ".htm")) or head.startswith(
            ("<!doctype", "<html", "<head", "<body")):
        text = html_to_text(text)
    return {"label": name or "upload", "url": "",
            "text": text.strip()[:MAX_TEXT_CHARS]}


def uploaded_files_to_items(files):
    # type: (List[Tuple[str, bytes]]) -> List[Dict[str, Any]]
    """Convert (filename, bytes) pairs into batch items, capped at
    MAX_UPLOAD_FILES."""
    items = []  # type: List[Dict[str, Any]]
    for name, data in list(files or [])[:MAX_UPLOAD_FILES]:
        items.append(uploaded_file_to_item(name, data))
    return items


# ---------------------------------------------------------------------------
# Vendor full-text tracing
#
# A feed entry is a summary; the verdict-grade evidence lives in
# the vendor's own advisory. trace_items follows each item's CVE
# references to that original, in a fixed route order:
#   Cisco   -> the advisory's CSAF 2.0 JSON (public, structured:
#              product_status + remediations), derived from the
#              publication URL when no direct CSAF link is listed.
#   Juniper -> the JSA article's full text (affected/fixed lists).
#   Arista  -> the advisory's CSAF JSON under
#              /assets/data/SecurityAdvisories/CSAF/.
#   any     -> the vendor-submitted CVE record (CNA container in
#              the CVEProject cvelistV5 mirror): structured
#              affected[] version ranges straight from the vendor.
# A traced item's text becomes "<vendor text>\n\n--- Feed summary
# ---\n<original feed text>", its url/source_url point at the
# vendor original, and source_label names the route. When every
# route fails the item is returned unchanged - tracing never
# fabricates an advisory.
# ---------------------------------------------------------------------------

TRACE_CAP = 10
TRACE_TEXT_CAP = 8000
JSA_MIN_TEXT_CHARS = 400

_CVE_ID_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_CISCO_ADVISORY_RE = re.compile(r"/content/CiscoSecurityAdvisory/"
                                r"([A-Za-z0-9\-]+)")
_ARISTA_ADVISORY_RE = re.compile(r"/security-advisory/(\d+)"
                                 r"-security-advisory-(\d+)")
_JSA_URL_RE = re.compile(r"supportportal\.juniper\.net/"
                         r"(?:JSA\d+|s/article/\S*[Jj][Ss][Aa]\d+)")


def _item_cve_id(item):
    # type: (Dict[str, Any]) -> str
    """The item's CVE id (uppercased), from its label first, then
    its text; "" when the item names none."""
    for source in (str((item or {}).get("label") or ""),
                   str((item or {}).get("text") or "")):
        match = _CVE_ID_RE.search(source)
        if match:
            return match.group(0).upper()
    return ""


def _item_references(item):
    # type: (Dict[str, Any]) -> List[str]
    """Reference URLs for tracing: the item's stored reference
    list, plus any URL appearing in its text, deduped in order."""
    refs = []  # type: List[str]
    for url in (item or {}).get("references") or []:
        url = str(url).strip()
        if url and url not in refs:
            refs.append(url)
    for url in re.findall(r"https?://[^\s\"'<>\)\]]+",
                          str((item or {}).get("text") or "")):
        url = url.rstrip(".,;")
        if url and url not in refs:
            refs.append(url)
    return refs


def cvelist_url(cve_id):
    # type: (str) -> str
    """The CVEProject cvelistV5 raw URL for a CVE id: records live
    under cves/<year>/<bucket>/ where the bucket is the numeric
    part with its last three digits replaced by "xxx"
    (CVE-2026-101943 -> 101xxx, CVE-2023-44189 -> 44xxx)."""
    match = re.match(r"CVE-(\d{4})-(\d+)$", (cve_id or "").upper())
    if not match:
        return ""
    year, digits = match.groups()
    bucket = digits[:-3] + "xxx" if len(digits) > 3 else digits + "xxx"
    return ("https://raw.githubusercontent.com/CVEProject/"
            "cvelistV5/main/cves/%s/%s/%s.json"
            % (year, bucket, cve_id.upper()))


def _cisco_csaf_url(refs):
    # type: (List[str]) -> str
    for url in refs:
        if ("contentjson" in url and "/csaf/" in url
                and url.split("?")[0].endswith(".json")):
            return url.split("?")[0]
    for url in refs:
        match = _CISCO_ADVISORY_RE.search(url)
        if match:
            advisory_id = match.group(1)
            return ("https://sec.cloudapps.cisco.com/security/center/"
                    "contentjson/CiscoSecurityAdvisory/%s/csaf/%s.json"
                    % (advisory_id, advisory_id))
    return ""


def _juniper_jsa_url(refs):
    # type: (List[str]) -> str
    for url in refs:
        if _JSA_URL_RE.search(url):
            return url
    return ""


def _arista_csaf_url(refs):
    # type: (List[str]) -> str
    for url in refs:
        match = _ARISTA_ADVISORY_RE.search(url)
        if match:
            number = match.group(2).lstrip("0") or "0"
            return ("https://www.arista.com/assets/data/"
                    "SecurityAdvisories/CSAF/arista_networks_"
                    "security_advisory_%s_CSAF.json" % number)
    return ""


def _join_product_path(parts):
    # type: (List[str]) -> str
    """Compose a full product name from CSAF branch path segments,
    dropping segments that are prefixes of (or prefixed by) their
    neighbours: ["Cisco", "Cisco IOS XE Software", "17.9",
    "17.9.4"] -> "Cisco IOS XE Software 17.9.4"."""
    result = ""
    for part in parts:
        if not part:
            continue
        if not result:
            result = part
            continue
        last = result.rsplit(" ", 1)[-1]
        if part == result or part == last or result.startswith(part):
            continue
        if part.startswith(result):
            result = part
            continue
        if part.startswith(last):
            result = result[:len(result) - len(last)] + part
            continue
        if last.startswith(part):
            continue
        result = "%s %s" % (result, part)
    return result


def _csaf_product_names(product_tree):
    # type: (Dict[str, Any]) -> Dict[str, str]
    """Map CSAF product_ids to display names: full_product_names
    first, then branch leaves (name composed from the branch
    path, since leaf products often carry only a version)."""
    names = {}  # type: Dict[str, str]
    for entry in (product_tree or {}).get("full_product_names") or []:
        product_id = (entry or {}).get("product_id")
        if product_id:
            names[str(product_id)] = str(entry.get("name") or product_id)

    def walk(branch, path):
        # type: (Dict[str, Any], List[str]) -> None
        name = str((branch or {}).get("name") or "")
        product = (branch or {}).get("product") or {}
        product_id = product.get("product_id")
        if product_id and str(product_id) not in names:
            leaf = str(product.get("name") or name)
            names[str(product_id)] = _join_product_path(path + [leaf])
        for sub in (branch or {}).get("branches") or []:
            walk(sub, path + ([name] if name else []))

    for top in (product_tree or {}).get("branches") or []:
        walk(top, [])
    return names


def _cap_names(names, cap=40):
    # type: (List[str], int) -> str
    unique = []  # type: List[str]
    for name in names:
        if name and name not in unique:
            unique.append(name)
    if len(unique) > cap:
        return "; ".join(unique[:cap]) + "; +%d more" % (
            len(unique) - cap)
    return "; ".join(unique)


def _csaf_vendor_text(data, cve_id, source_label, csaf_url):
    # type: (Any, str, str, str) -> str
    """Compose the vendor text from a CSAF 2.0 document, or ""
    when the document carries nothing usable for this CVE (no
    matching vulnerability, no product status, no notes)."""
    if not isinstance(data, dict):
        return ""
    document = data.get("document") or {}
    title = str(document.get("title") or "").strip()
    names = _csaf_product_names(data.get("product_tree") or {})
    vulns = [v for v in data.get("vulnerabilities") or []
             if isinstance(v, dict)]
    chosen = [v for v in vulns
              if str(v.get("cve") or "").upper() == cve_id] or vulns
    affected = []  # type: List[str]
    fixed = []  # type: List[str]
    notes = []  # type: List[str]
    remediations = []  # type: List[str]
    for vuln in chosen:
        status = vuln.get("product_status") or {}
        for key in ("first_affected", "known_affected"):
            affected.extend(names.get(str(pid), str(pid))
                            for pid in status.get(key) or [])
        for key in ("first_fixed", "fixed"):
            fixed.extend(names.get(str(pid), str(pid))
                         for pid in status.get(key) or [])
        for note in vuln.get("notes") or []:
            if (note or {}).get("category") in (
                    "summary", "details", "description", "general"):
                text = str(note.get("text") or "").strip()
                if text and text not in notes:
                    notes.append(text)
        for fix in vuln.get("remediations") or []:
            text = str((fix or {}).get("details")
                       or (fix or {}).get("description") or "").strip()
            if text and text not in remediations:
                remediations.append(text)
    if not (affected or fixed or notes):
        return ""
    lines = [title or cve_id,
             "Vendor advisory (%s): %s" % (source_label, csaf_url)]
    if affected:
        lines.append("Affected products/versions: %s"
                     % _cap_names(affected))
    if fixed:
        lines.append("Fixed in: %s" % _cap_names(fixed))
    lines.extend(notes)
    if remediations:
        lines.append("Workarounds/Remediation: %s"
                     % " ".join(remediations))
    return "\n".join(lines)[:TRACE_TEXT_CAP]


def _cna_vendor_text(data, cve_id):
    # type: (Any, str) -> str
    """Compose the vendor text from a CVE 5.x record's CNA
    container (the vendor's own submission: structured affected[]
    version ranges + description), or "" when the record is for a
    different CVE or carries nothing usable."""
    if not isinstance(data, dict):
        return ""
    record_id = str((data.get("cveMetadata") or {}).get("cveId")
                    or "").upper()
    if record_id and record_id != cve_id:
        return ""
    cna = (data.get("containers") or {}).get("cna") or {}
    affected_lines = []  # type: List[str]
    for entry in cna.get("affected") or []:
        product = str((entry or {}).get("product") or "").strip()
        platforms = [str(p) for p in (entry or {}).get("platforms")
                     or []]
        segments = []  # type: List[str]
        for version in (entry or {}).get("versions") or []:
            if str((version or {}).get("status") or "") != "affected":
                continue
            segment = str(version.get("version") or "")
            if version.get("lessThan"):
                segment += " < %s" % version["lessThan"]
            elif version.get("lessThanOrEqual"):
                segment += " <= %s" % version["lessThanOrEqual"]
            segment = segment.strip()
            if segment:
                segments.append(segment)
        if not segments:
            continue
        line = product
        if platforms:
            line += " on %s" % ", ".join(platforms)
        affected_lines.append("%s: versions %s (affected)"
                              % (line, "; ".join(segments)))
    description = ""
    for entry in cna.get("descriptions") or []:
        if (entry or {}).get("lang") == "en":
            description = str(entry.get("value") or "").strip()
            break
    if not (affected_lines or description):
        return ""
    lines = ["Vendor-submitted CVE record (CNA): %s" % cve_id]
    lines.extend("Affected: %s" % line for line in affected_lines)
    if description:
        lines.append(description)
    lines.append("Fixed/releases info is in the description/"
                 "references when present.")
    return "\n".join(lines)[:TRACE_TEXT_CAP]


def _cna_traced_ranges(data, cap=40):
    # type: (Any, int) -> List[Dict[str, Any]]
    """Machine-readable affected ranges from a CVE 5.x record's
    CNA affected[] - the same data _cna_vendor_text renders as
    prose, kept in the range-dict shape _nvd_cpe_ranges produces
    ({"vendor", "product", "exact", "start_including",
    "start_excluding", "end_including", "end_excluding"}) so the
    local screening can evaluate a traced record exactly like an
    NVD configuration. Mapping: {version: B, lessThan: L} is
    [B, L); version "0" is the CNA sentinel for "from the
    beginning" (no lower bound); a lessThan list ("22.4R2-S2,
    22.4R3") keeps the first, earliest-fix bound. A branch
    wildcard (lessThan "21.1*", version "21.1*") degrades to a
    lower bound only: it can hold an item as a candidate, never
    produce a false clear. A boundless entry is one exact
    version. Deduped, capped."""
    ranges = []  # type: List[Dict[str, Any]]
    seen = set()  # type: Set[Tuple[Any, ...]]
    if not isinstance(data, dict):
        return ranges
    cna = (data.get("containers") or {}).get("cna") or {}
    for entry in cna.get("affected") or []:
        if not isinstance(entry, dict):
            continue
        vendor = str(entry.get("vendor") or "")
        product = str(entry.get("product") or "").strip()
        if not product:
            continue
        for version_entry in entry.get("versions") or []:
            if not isinstance(version_entry, dict):
                continue
            if str(version_entry.get("status") or "") != "affected":
                continue
            base = str(version_entry.get("version") or "").strip()
            less_than = str(version_entry.get("lessThan") or "")
            less_than = less_than.split(",")[0].strip()
            less_eq = str(version_entry.get("lessThanOrEqual")
                          or "")
            less_eq = less_eq.split(",")[0].strip()
            wildcard = ("*" in less_than or "*" in less_eq
                        or "*" in base)
            if "*" in less_than:
                less_than = ""
            if "*" in less_eq:
                less_eq = ""
            rng = {"vendor": vendor, "product": product,
                   "exact": None, "start_including": None,
                   "start_excluding": None, "end_including": None,
                   "end_excluding": None}  # type: Dict[str, Any]
            if less_than:
                rng["end_excluding"] = less_than
            elif less_eq:
                rng["end_including"] = less_eq
            if rng["end_excluding"] or rng["end_including"]:
                if base and base != "0" and "*" not in base:
                    rng["start_including"] = base
            elif base and base not in ("0", "*"):
                if wildcard:
                    prefix = base.replace("*", "").strip(" .")
                    if not prefix:
                        continue
                    rng["start_including"] = prefix
                else:
                    rng["exact"] = base
            else:
                continue
            key = (rng["vendor"], rng["product"], rng["exact"],
                   rng["start_including"], rng["start_excluding"],
                   rng["end_including"], rng["end_excluding"])
            if key in seen:
                continue
            seen.add(key)
            ranges.append(rng)
            if len(ranges) >= cap:
                return ranges
    return ranges


_CSAF_VERSION_TAIL_RE = re.compile(r"^(.+?)\s+(\d[\w.\-+]*)$")


def _csaf_name_range(publisher, name):
    # type: (str, str) -> Optional[Dict[str, Any]]
    """One CSAF affected product name ("Cisco IOS XE Software
    17.9.4") as an exact-version range dict, or None when the
    name carries no trailing version token. CSAF product_status
    enumerates affected product VERSIONS rather than ranges, so
    exact is the honest mapping. The publisher's first word is
    dropped from the front of the family when it repeats there,
    so the product token resembles its CPE form
    ("ios_xe_software")."""
    match = _CSAF_VERSION_TAIL_RE.match(str(name or "").strip())
    if not match:
        return None
    family = match.group(1).strip()
    version = match.group(2)
    if not family:
        return None
    words = family.split()
    publisher_words = str(publisher or "").split()
    if publisher_words and words \
            and words[0].lower() == publisher_words[0].lower():
        words = words[1:]
    if not words:
        return None
    product = "_".join(word.lower() for word in words)
    return {"vendor": str(publisher or ""), "product": product,
            "exact": version, "start_including": None,
            "start_excluding": None, "end_including": None,
            "end_excluding": None}


def _csaf_traced_ranges(data, cve_id, cap=40):
    # type: (Any, str, int) -> List[Dict[str, Any]]
    """Machine-readable affected ranges from a CSAF 2.0 document:
    the product_status first_affected/known_affected product ids
    of the chosen vulnerabilities (same selection as
    _csaf_vendor_text), resolved to names via the product tree
    and parsed into exact-version range dicts. Best effort:
    names without a parseable version contribute nothing."""
    ranges = []  # type: List[Dict[str, Any]]
    seen = set()  # type: Set[Tuple[Any, ...]]
    if not isinstance(data, dict):
        return ranges
    document = data.get("document") or {}
    publisher = str((document.get("publisher") or {}).get("name")
                    or "")
    names = _csaf_product_names(data.get("product_tree") or {})
    vulns = [v for v in data.get("vulnerabilities") or []
             if isinstance(v, dict)]
    chosen = [v for v in vulns
              if str(v.get("cve") or "").upper() == cve_id] or vulns
    for vuln in chosen:
        status = vuln.get("product_status") or {}
        for key in ("first_affected", "known_affected"):
            for pid in status.get(key) or []:
                name = names.get(str(pid), str(pid))
                rng = _csaf_name_range(publisher, name)
                if rng is None:
                    continue
                marker = (rng["vendor"], rng["product"],
                          rng["exact"], rng["start_including"],
                          rng["start_excluding"],
                          rng["end_including"],
                          rng["end_excluding"])
                if marker in seen:
                    continue
                seen.add(marker)
                ranges.append(rng)
                if len(ranges) >= cap:
                    return ranges
    return ranges


CISCO_CSAF_RSS_URL = ("https://sec.cloudapps.cisco.com/security/"
                      "center/csaf_20.xml")
JUNIPER_JSA_PROBE_URL = "https://supportportal.juniper.net/JSA73153"
ARISTA_CSAF_PROBE_URL = (
    "https://www.arista.com/assets/data/SecurityAdvisories/CSAF/"
    "arista_networks_security_advisory_199_CSAF.json")
PROBE_TTL_SECONDS = 300

_JSA_MARKERS = ("junos", "jsa", "affected", "prior to", "problem:",
                "workaround")


def _jsa_is_genuine(text, url):
    # type: (Any, Any) -> bool
    """True only when a fetched JSA page is the genuine article:
    the JSA id derived from the URL appears in the text AND at
    least one advisory marker is present. The measured CEC
    Juniper Community portal shell is long and mentions Juniper,
    but never names the article's JSA id - length alone and
    vendor name alone both pass it, so neither suffices."""
    body = str(text or "")
    if not body:
        return False
    url_text = str(url or "")
    match = re.search(r"JSA\d+", url_text, re.IGNORECASE)
    jsa_id = match.group(0) if match else ""
    if not jsa_id:
        slug = re.search(r"/s/article/\S*?(\d{4,})", url_text)
        jsa_id = slug.group(1) if slug else ""
    if not jsa_id:
        return False
    lowered = body.lower()
    if jsa_id.lower() not in lowered:
        return False
    return any(marker in lowered for marker in _JSA_MARKERS)


_JSA_VERSION_TOKEN_RE = re.compile(
    r"\d+(?:\.\d+)+(?:[A-Za-z][0-9A-Za-z.\-]*)?"
    r"|\d+[A-Za-z][0-9A-Za-z.\-]*")
_JSA_BOUND_INCLUSIVE = ("and earlier", "up to and including")
_JSA_BOUND_EXCLUSIVE = ("prior to", "before", "earlier than")


def _jsa_version_tokens(line):
    # type: (str) -> List[str]
    """Version tokens on one JSA line, in order (a local helper
    in the shape of triage's version-token normaliser: digit-led
    tokens such as 21.2 or 21.2R3-S7)."""
    return _JSA_VERSION_TOKEN_RE.findall(str(line or ""))


def _jsa_traced_ranges(text):
    # type: (Any) -> List[Dict[str, Any]]
    """Deterministic affected ranges from JSA prose, scoped to
    the bound-phrase family the matcher already trusts ("prior
    to" / "before" / "earlier than" -> end-exclusive; "and
    earlier" / "up to and including" -> end-inclusive). The
    bound is the LAST version token on a kept line; the FIRST
    token is the branch base when the line also names versions
    ("21.2 versions prior to 21.2R3-S7" -> [21.2, 21.2R3-S7)).
    Every range is stamped "partial": True - extraction may
    convict (a hit stays a hit) but never acquit (the screen
    downgrades partial clears to uncertain). Conservative
    abort: a version-bearing releases/versions line near a kept
    line that itself yields no range voids the whole extraction.
    Classic Junos only; Evolved is out of scope here."""
    lines = []  # type: List[str]
    for chunk in str(text or "").splitlines():
        lines.extend(part.strip() for part in chunk.split(";"))
    kept = {}  # type: Dict[int, Dict[str, Any]]
    for index, line in enumerate(lines):
        lowered = line.lower()
        inclusive = any(phrase in lowered
                        for phrase in _JSA_BOUND_INCLUSIVE)
        exclusive = any(phrase in lowered
                        for phrase in _JSA_BOUND_EXCLUSIVE)
        if not (inclusive or exclusive):
            continue
        tokens = _jsa_version_tokens(line)
        if not tokens:
            continue
        rng = {"vendor": "Juniper Networks", "product": "Junos OS",
               "exact": None, "start_including": None,
               "start_excluding": None, "end_including": None,
               "end_excluding": None,
               "partial": True}  # type: Dict[str, Any]
        if inclusive:
            rng["end_including"] = tokens[-1]
        else:
            rng["end_excluding"] = tokens[-1]
        if len(tokens) >= 2 and "version" in lowered:
            rng["start_including"] = tokens[0]
        kept[index] = rng
    if not kept:
        return []
    for index, line in enumerate(lines):
        if index in kept:
            continue
        lowered = line.lower()
        if ("releases" in lowered or "versions" in lowered) \
                and _jsa_version_tokens(line) \
                and any(abs(index - kept_index) <= 3
                        for kept_index in kept):
            return []
    return [kept[index] for index in sorted(kept)]


def probe_sources(fetcher=None, json_fetcher=None, text_fetcher=None,
                  now=None):
    # type: (Optional[Callable[[str], Any]], Optional[Callable[[str], Any]], Optional[Callable[[str], str]], Optional[datetime.datetime]) -> Dict[str, Dict[str, Any]]
    """Probe each feed/vendor source's reachability IN THIS
    environment and classify the outcome honestly: HTTP 200 is
    not success - bodies are validated (JSON shape, RSS markers,
    the JSA genuine test, the CNA record id). Returns {source:
    {"status": REACH_*, "detail": str, "http_status"}} keyed
    nvd / kev / cisco_csaf / arista_csaf / juniper_jsa / cna.
    One source's failure never aborts the others; results are
    cached in-process for PROBE_TTL_SECONDS. Probing spends
    zero Clocked calls and never alters collection."""
    cached = _FEED_CACHE.get("probe")
    if cached is not None and isinstance(cached.get("result"), dict):
        return cached["result"]
    has_key = bool(_nvd_api_key())
    if json_fetcher is not None:
        nvd_fetch = _nvd_fetcher(json_fetcher, has_key)
        json_fetch = json_fetcher
    elif fetcher is not None:
        nvd_fetch = fetcher
        json_fetch = fetcher
    else:
        nvd_fetch = _nvd_fetcher(None, has_key)
        json_fetch = _fetch_json
    if text_fetcher is not None:
        text_fetch = text_fetcher
    elif fetcher is not None:
        text_fetch = fetcher
    else:
        def text_fetch(url):
            # type: (str) -> str
            return _fetch_raw(url)[0]

    def failed(exc):
        # type: (Exception) -> Dict[str, Any]
        return {"status": _classify_error(exc),
                "detail": str(exc) or exc.__class__.__name__,
                "http_status": getattr(exc, "status", None)}

    result = {}  # type: Dict[str, Dict[str, Any]]
    moment = now or datetime.datetime.now(datetime.timezone.utc)
    pub_start, pub_end = _nvd_recent_window(moment)
    nvd_url = NVD_API_URL + "?" + urllib.parse.urlencode(
        {"keywordSearch": "Cisco", "resultsPerPage": 1,
         "pubStartDate": pub_start, "pubEndDate": pub_end})
    try:
        data = _fetch_with_retry(nvd_fetch, nvd_url, None)
        if isinstance(data, dict) and "vulnerabilities" in data \
                and "totalResults" in data:
            result["nvd"] = {
                "status": REACH_OK,
                "detail": "totalResults: %s" % data.get("totalResults"),
                "http_status": 200}
        else:
            result["nvd"] = {"status": REACH_INVALID,
                             "detail": "unexpected NVD response shape",
                             "http_status": 200}
    except Exception as exc:
        result["nvd"] = failed(exc)
    try:
        if json_fetcher is not None or fetcher is not None:
            kev_data = json_fetch(KEV_FEED_URL)
        else:
            kev_data, _from_cache = _fetch_kev_catalog(None)
        catalog_version = str((kev_data or {}).get("catalogVersion")
                              or "")
        if isinstance((kev_data or {}).get("vulnerabilities"), list) \
                and catalog_version:
            result["kev"] = {"status": REACH_OK,
                             "detail": catalog_version,
                             "http_status": 200}
        else:
            result["kev"] = {"status": REACH_INVALID,
                             "detail": "missing catalogVersion",
                             "http_status": 200}
    except Exception as exc:
        result["kev"] = failed(exc)
    try:
        body = str(text_fetch(CISCO_CSAF_RSS_URL) or "")
        if ("<rss" in body or "<feed" in body) \
                and "csaf" in body.lower():
            result["cisco_csaf"] = {"status": REACH_OK, "detail": "",
                                    "http_status": 200}
        elif _looks_like_html(body, ""):
            result["cisco_csaf"] = {
                "status": REACH_CHALLENGE,
                "detail": "HTML page, not the CSAF RSS feed",
                "http_status": 200}
        else:
            result["cisco_csaf"] = {
                "status": REACH_INVALID,
                "detail": "no RSS/feed body with CSAF links",
                "http_status": 200}
    except Exception as exc:
        result["cisco_csaf"] = failed(exc)
    try:
        arista_data = json_fetch(ARISTA_CSAF_PROBE_URL)
        if isinstance(arista_data, dict) \
                and "document" in arista_data \
                and "vulnerabilities" in arista_data:
            result["arista_csaf"] = {"status": REACH_OK, "detail": "",
                                     "http_status": 200}
        else:
            result["arista_csaf"] = {
                "status": REACH_INVALID,
                "detail": "unexpected CSAF response shape",
                "http_status": 200}
    except Exception as exc:
        result["arista_csaf"] = failed(exc)
    try:
        jsa_body = str(text_fetch(JUNIPER_JSA_PROBE_URL) or "")
        if _jsa_is_genuine(jsa_body, JUNIPER_JSA_PROBE_URL):
            result["juniper_jsa"] = {"status": REACH_OK, "detail": "",
                                     "http_status": 200}
        else:
            result["juniper_jsa"] = {
                "status": REACH_CHALLENGE,
                "detail": "portal shell, not the JSA article",
                "http_status": 200}
    except Exception as exc:
        result["juniper_jsa"] = failed(exc)
    try:
        cna_data = json_fetch(cvelist_url("CVE-2023-36844"))
        record_id = str(((cna_data or {}).get("cveMetadata") or {}
                         ).get("cveId") or "")
        if record_id.upper() == "CVE-2023-36844":
            result["cna"] = {"status": REACH_OK, "detail": "",
                             "http_status": 200}
        else:
            result["cna"] = {"status": REACH_INVALID,
                             "detail": "CNA record id mismatch",
                             "http_status": 200}
    except Exception as exc:
        result["cna"] = failed(exc)
    _FEED_CACHE.put("probe", {"result": result}, PROBE_TTL_SECONDS)
    return result


def _trace_one(item, text_fetch, json_fetch):
    # type: (Dict[str, Any], Callable[[str], str], Callable[[str], Any]) -> Optional[Tuple[str, str, str, List[Dict[str, Any]]]]
    """Follow one item to its vendor original. Returns
    (vendor_text, source_url, source_label, traced_ranges,
    was_fallback) or None when every route fails. traced_ranges
    are the vendor document's affected ranges in screening
    range-dict shape (the JSA route contributes its prose-parsed
    partial ranges when the article states bound phrases).
    was_fallback is True when an earlier matched route failed
    and a later route succeeded. Route order: Cisco CSAF,
    Juniper JSA full text, Arista CSAF, then the vendor-neutral
    CNA record."""
    cve_id = _item_cve_id(item)
    if not cve_id:
        return None
    refs = _item_references(item)
    failed_route = False
    csaf_url = _cisco_csaf_url(refs)
    if csaf_url:
        data = None  # type: Any
        try:
            data = json_fetch(csaf_url)
            text = _csaf_vendor_text(data, cve_id,
                                     "Cisco CSAF", csaf_url)
        except Exception:
            text = ""
        if text:
            return (text, csaf_url, "Cisco CSAF",
                    _csaf_traced_ranges(data, cve_id), failed_route)
        failed_route = True
    jsa_url = _juniper_jsa_url(refs)
    if jsa_url:
        try:
            fetched = text_fetch(jsa_url)
        except Exception:
            fetched = ""
        if fetched and len(fetched) >= JSA_MIN_TEXT_CHARS \
                and _jsa_is_genuine(fetched, jsa_url):
            body = ("Vendor advisory (Juniper JSA): %s\n%s"
                    % (jsa_url, fetched))[:TRACE_TEXT_CAP]
            return (body, jsa_url, "Juniper JSA",
                    _jsa_traced_ranges(fetched), failed_route)
        failed_route = True
    arista_url = _arista_csaf_url(refs)
    if arista_url:
        data = None  # type: Any
        try:
            data = json_fetch(arista_url)
            text = _csaf_vendor_text(data, cve_id,
                                     "Arista CSAF", arista_url)
        except Exception:
            text = ""
        if text:
            return (text, arista_url, "Arista CSAF",
                    _csaf_traced_ranges(data, cve_id), failed_route)
        failed_route = True
    record_url = cvelist_url(cve_id)
    if record_url:
        data = None  # type: Any
        try:
            data = json_fetch(record_url)
            text = _cna_vendor_text(data, cve_id)
        except Exception:
            text = ""
        if text:
            return (text, record_url, "CVE CNA record",
                    _cna_traced_ranges(data), failed_route)
    return None


def _fixture_trace_json_fetcher(url):
    # type: (str) -> Any
    """Mock Mode JSON stand-in for tracing: Cisco CSAF URLs read
    the bundled CSAF fixture; cvelistV5 URLs read the bundled CNA
    fixture - but only for the fixture's own CVE, so a mock trace
    of any other CVE honestly fails instead of borrowing another
    vulnerability's record."""
    if "contentjson" in url and "/csaf/" in url:
        return _load_fixture_json("cisco_csaf_fixture.json")
    if "CVEProject/cvelistV5" in url:
        data = _load_fixture_json("cve_cna_fixture.json")
        record_id = str((data.get("cveMetadata") or {}).get("cveId")
                        or "")
        if record_id and record_id in url:
            return data
        raise FetchError("no fixture CNA record for this CVE")
    raise FetchError("no fixture for this URL")


def _fixture_trace_text_fetcher(url):
    # type: (str) -> str
    """Mock Mode text stand-in for tracing: the fixtures carry no
    JSA page text, so the Juniper route fails over to the CNA
    record - the same honest fallback as a blocked portal fetch
    in Live mode."""
    raise FetchError("no fixture page text")


def trace_items(items, mock=False, fetcher=None, json_fetcher=None,
                cap=TRACE_CAP, progress=None, lang="en"):
    # type: (List[Dict[str, Any]], bool, Optional[Callable[[str], str]], Optional[Callable[[str], Any]], int, Optional[Callable[[int, int, str], None]], str) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]
    """Trace feed items to their vendor originals (see the
    section header). At most `cap` items are traced, in the given
    order; items beyond the cap and items without a CVE id pass
    through untouched. A successful trace also attaches the
    vendor document's structured affected ranges as
    "traced_ranges" (screening range-dict shape) when the
    document carries any - the feed pipeline re-screens on them.
    Returns (items, stats) with stats
    {"traced", "attempted", "by_source"} - "attempted" counts the
    in-cap items that carried a CVE id (each tries the vendor
    routes, then the CNA fallback). Input items are not mutated.
    With mock=True and no injected fetchers, bundled fixtures
    answer the fetches so the demo path works offline; `fetcher`
    fetches page text (JSA), `json_fetcher` fetches JSON
    (CSAF / CNA records). `progress`, when given, fires once per
    attempted item as progress(done, attempted_total, label)
    with the item's CVE id in the label - attempted, not just
    successful, so the count matches stats["attempted"]."""
    text_fetch = fetcher or fetch_advisory_text
    json_fetch = json_fetcher or _fetch_json
    if mock:
        if fetcher is None:
            text_fetch = _fixture_trace_text_fetcher
        if json_fetcher is None:
            json_fetch = _fixture_trace_json_fetcher
    stats = {"traced": 0, "attempted": 0, "fallbacks": 0,
             "by_source": {}}  # type: Dict[str, Any]
    items = list(items or [])
    attempted_total = sum(
        1 for item in items[:cap] if _item_cve_id(item or {}))
    trace_labels = PROGRESS_STRINGS[_normalize_lang(lang)]
    traced_items = []  # type: List[Dict[str, Any]]
    for index, item in enumerate(items):
        new_item = dict(item or {})
        if index < cap and _item_cve_id(new_item):
            stats["attempted"] += 1
            outcome = _trace_one(new_item, text_fetch, json_fetch)
            if outcome is not None:
                (vendor_text, source_url, source_label,
                 traced_ranges, was_fallback) = outcome
                if was_fallback:
                    stats["fallbacks"] += 1
                original_url = str(new_item.get("url") or "")
                if original_url and original_url != source_url:
                    vendor_text += "\nNVD: %s" % original_url
                new_item["text"] = (
                    vendor_text + "\n\n--- Feed summary ---\n"
                    + str(new_item.get("text") or ""))
                new_item["source_url"] = source_url
                new_item["source_label"] = source_label
                new_item["url"] = source_url
                if traced_ranges:
                    new_item["traced_ranges"] = traced_ranges
                stats["traced"] += 1
                by_source = stats["by_source"]
                by_source[source_label] = by_source.get(
                    source_label, 0) + 1
            _emit_progress(
                progress, stats["attempted"], attempted_total,
                trace_labels["tracing"]
                % _item_cve_id(new_item))
        traced_items.append(new_item)
    return traced_items, stats


_FEED_FIXTURE_TEXTS_CACHE = None  # type: Optional[Dict[str, List[str]]]


def bundled_feed_fixture_texts():
    # type: () -> Dict[str, List[str]]
    """Exact advisory texts a Mock Mode feed run can hand to the
    deep-triage judge, grouped by the canned-response key that
    answers them ("feed_cve_2023_20198", ...).

    Mock Mode judging serves canned Clocked responses ONLY for
    bundled demo data bound to its exact text (the sample side is
    triage.detect_sample_id). The feed fixtures are demo data
    too, but their judged texts are not files: collection
    composes them from the fixture payloads, and tracing rewrites
    them again (vendor text + feed summary). This helper
    therefore replays the deterministic mock stages -
    collect_feed_items_year and trace_items over the BUNDLED
    sample inventory - and returns every resulting item text,
    raw and traced, so the mock judge can bind to exactly the
    set the pipeline itself can produce. A text one character
    off any of these is not bundled data and earns no canned
    verdict. Cached after the first successful build: the
    fixtures are static files.
    """
    global _FEED_FIXTURE_TEXTS_CACHE
    if _FEED_FIXTURE_TEXTS_CACHE is not None:
        return _FEED_FIXTURE_TEXTS_CACHE
    texts = {}  # type: Dict[str, List[str]]
    try:
        inventory_text = (_SAMPLES_DIR / "inventory_sample.txt"
                          ).read_text(encoding="utf-8")
        devices = parse_inventory(inventory_text)
        feed = collect_feed_items_year(devices, mock=True)
        raw_items = feed["items"]
        traced_items, _trace_stats = trace_items(
            raw_items, mock=True, cap=TRACE_SCREEN_CAP)
        for raw_item, traced_item in zip(raw_items, traced_items):
            cve_id = _item_cve_id(raw_item)
            if not cve_id:
                continue
            key = "feed_" + cve_id.lower().replace("-", "_")
            bucket = texts.setdefault(key, [])
            for item in (raw_item, traced_item):
                text = str((item or {}).get("text") or "")
                if text and text not in bucket:
                    bucket.append(text)
    except Exception:
        texts = {}
    if texts:
        _FEED_FIXTURE_TEXTS_CACHE = texts
    return texts


# ---------------------------------------------------------------------------
# Batch runner
# ---------------------------------------------------------------------------

def _judge_entry(base, text, devices_text, api_key, lang, relevance,
                 mock=False):
    # type: (Dict[str, Any], str, str, Optional[str], str, Optional[Any], bool) -> Dict[str, Any]
    """Judge one already-available advisory text: relevance
    prefilter first (no Clocked calls on a miss), then run_triage.
    `base` carries the entry's identity keys (url, and label for
    pre-fetched items). `mock=True` forces Mock Mode judging in
    run_triage regardless of any configured API key."""
    entry = dict(base)
    hint = ""
    for line in (text or "").splitlines():
        if line.strip():
            hint = line.strip()[:80]
            break
    entry["text_hint"] = hint
    if relevance is not None and not relevance.search(text or ""):
        entry["status"] = "skipped"
        entry["skip_reason"] = "not_relevant"
        return entry
    try:
        triage_result = run_triage(text, devices_text,
                                   api_key=api_key, lang=lang,
                                   mock=mock)
    except Exception as exc:
        if is_credit_error(exc):
            return _credit_entry(entry, lang)
        entry["status"] = "error"
        entry["error"] = str(exc) or exc.__class__.__name__
        return entry
    if triage_result.get("credit_exhausted"):
        # run_triage translated a 402 into a verdict-less result;
        # at batch level that is an error row, not an "ok" entry
        # with no verdict - and the runners fail fast on the flag.
        return _credit_entry(entry, lang)
    entry["status"] = "ok"
    entry["triage"] = triage_result
    return entry


def _prefilter_pattern(prefilter, devices_text):
    # type: (bool, str) -> Optional[Any]
    if not prefilter:
        return None
    return _relevance_pattern(
        build_relevance_tokens(parse_inventory(devices_text)))


def run_batch(links, devices_text, api_key=None, lang="en",
              fetcher=fetch_advisory_text, progress=None,
              prefilter=False, mock=False):
    # type: (List[str], str, Optional[str], str, Callable[[str], str], Optional[Callable[[int, int, str], None]], bool, bool) -> List[Dict[str, Any]]
    """Fetch and triage every link against one inventory.

    Each link is independent: a fetch failure (or a triage error)
    is recorded in that link's entry and never aborts the batch.
    Entries: {url, status: "ok"|"fetch_failed"|"error"|"skipped",
    error?, skip_reason?, text_hint?, triage?} where "triage" is a
    run_triage result.

    With prefilter=True, each fetched text is first screened
    locally against the inventory's product space
    (build_relevance_tokens): no hit means the entry is "skipped"
    with skip_reason "not_relevant" and NO Clocked calls are spent
    on it. `progress`, when given, is called as
    progress(index, total, url) before each link is processed.

    Credit exhaustion fails the run fast: once one entry comes
    back credit_exhausted, no further Clocked calls are made and
    every remaining link gets a credit entry (see _credit_entry)
    instead of a judgment; entries already judged keep theirs.

    `mock=True` forces Mock Mode judging for every link (the
    app's Demo override), regardless of any configured API key;
    fetching still uses `fetcher` as usual.
    """
    relevance = _prefilter_pattern(prefilter, devices_text)
    results = []  # type: List[Dict[str, Any]]
    total = len(links)
    credit_dead = False
    for index, url in enumerate(links):
        if progress is not None:
            try:
                progress(index, total, url)
            except Exception:
                pass
        if credit_dead:
            results.append(_credit_entry({"url": url}, lang))
            continue
        try:
            text = fetcher(url)
        except Exception as exc:
            results.append({
                "url": url,
                "status": "fetch_failed",
                "error": str(exc) or exc.__class__.__name__,
            })
            continue
        entry = _judge_entry({"url": url}, text, devices_text,
                             api_key, lang, relevance, mock=mock)
        if entry.get("credit_exhausted"):
            credit_dead = True
        results.append(entry)
    return results


def run_batch_items(items, devices_text, api_key=None, lang="en",
                    progress=None, prefilter=False, mock=False):
    # type: (List[Dict[str, Any]], str, Optional[str], str, Optional[Callable[[int, int, str], None]], bool, bool) -> List[Dict[str, Any]]
    """Triage pre-fetched items ({"label", "url", "text"} dicts,
    as produced by the feed collectors and the upload converter)
    against one inventory - the same judging path as run_batch,
    minus the fetching. Entries additionally carry the item's
    "label". `progress`, when given, is called as
    progress(index, total, label) before each item is processed.

    Credit exhaustion fails the run fast, exactly as in run_batch:
    after the first credit entry, remaining items get credit
    entries without any further Clocked calls. `mock=True` forces
    Mock Mode judging for every item (the app's Demo override),
    regardless of any configured API key."""
    relevance = _prefilter_pattern(prefilter, devices_text)
    results = []  # type: List[Dict[str, Any]]
    total = len(items)
    credit_dead = False
    for index, item in enumerate(items):
        label = str((item or {}).get("label") or "")
        url = str((item or {}).get("url") or "")
        if progress is not None:
            try:
                progress(index, total, label or url)
            except Exception:
                pass
        base = {"url": url, "label": label}  # type: Dict[str, Any]
        # Vendor-trace provenance rides along into the result
        # entry (present even when the prefilter skips the item).
        if (item or {}).get("source_label"):
            base["source_label"] = str(item["source_label"])
        if (item or {}).get("source_url"):
            base["source_url"] = str(item["source_url"])
        item_sources = _derived_sources(item or {})
        if item_sources:
            base["sources"] = item_sources
        if credit_dead:
            results.append(_credit_entry(
                base, lang,
                text=str((item or {}).get("text") or "")))
            continue
        entry = _judge_entry(
            base, str((item or {}).get("text") or ""), devices_text,
            api_key, lang, relevance, mock=mock)
        if entry.get("credit_exhausted"):
            credit_dead = True
        results.append(entry)
    return results
