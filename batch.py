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
import io
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from triage import GENERIC_PRODUCT_WORDS, _product_core, parse_inventory, run_triage

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
    """One advisory link could not be fetched (short reason as text)."""


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


def _fetch_raw(url, timeout=FETCH_TIMEOUT):
    # type: (str, float) -> Tuple[str, str, str]
    """Download a URL once. Returns (decoded_text, content_type,
    final_url_after_redirects). Raises FetchError on any failure."""
    request = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT,
                 "Accept": "text/html, text/plain, */*"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            content_type = ""
            charset = None
            final_url = url
            try:
                content_type = response.headers.get("Content-Type") or ""
                charset = response.headers.get_content_charset()
                final_url = response.geturl() or url
            except Exception:
                pass
            raw = response.read(MAX_DOWNLOAD_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise FetchError("HTTP %d" % exc.code)
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

VENDOR_TOKENS = ["cisco", "juniper", "arista", "nokia", "extreme"]

GENERIC_NETWORK_TOKENS = [
    "switch", "router", "ios xe", "junos", "eos", "nexus",
    "catalyst", "qfx", "mx series", "ethernet", "firewall",
]


def build_relevance_tokens(devices):
    # type: (List[Dict[str, str]]) -> Set[str]
    """Match tokens for the relevance prefilter: the inventory's
    own product space (normalized model cores + significant model
    words), the five fleet vendor names, and generic network-gear
    terms. An advisory mentioning none of these is not about this
    fleet's network gear at all."""
    tokens = set(VENDOR_TOKENS) | set(GENERIC_NETWORK_TOKENS)  # type: Set[str]
    for device in devices or []:
        model = str((device or {}).get("model") or "")
        core = _product_core(model)
        if core:
            tokens.add(core)
        for word in re.findall(r"[a-z0-9]+", model.lower()):
            if len(word) >= 3 and word not in GENERIC_PRODUCT_WORDS:
                tokens.add(word)
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
# Batch runner
# ---------------------------------------------------------------------------

def run_batch(links, devices_text, api_key=None, lang="en",
              fetcher=fetch_advisory_text, progress=None,
              prefilter=False):
    # type: (List[str], str, Optional[str], str, Callable[[str], str], Optional[Callable[[int, int, str], None]], bool) -> List[Dict[str, Any]]
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
    """
    relevance = None  # type: Optional[Any]
    if prefilter:
        relevance = _relevance_pattern(
            build_relevance_tokens(parse_inventory(devices_text)))
    results = []  # type: List[Dict[str, Any]]
    total = len(links)
    for index, url in enumerate(links):
        if progress is not None:
            try:
                progress(index, total, url)
            except Exception:
                pass
        try:
            text = fetcher(url)
        except Exception as exc:
            results.append({
                "url": url,
                "status": "fetch_failed",
                "error": str(exc) or exc.__class__.__name__,
            })
            continue
        hint = ""
        for line in (text or "").splitlines():
            if line.strip():
                hint = line.strip()[:80]
                break
        if relevance is not None and not relevance.search(text or ""):
            results.append({
                "url": url,
                "status": "skipped",
                "skip_reason": "not_relevant",
                "text_hint": hint,
            })
            continue
        try:
            triage_result = run_triage(text, devices_text,
                                       api_key=api_key, lang=lang)
        except Exception as exc:
            results.append({
                "url": url,
                "status": "error",
                "error": str(exc) or exc.__class__.__name__,
                "text_hint": hint,
            })
            continue
        results.append({
            "url": url,
            "status": "ok",
            "text_hint": hint,
            "triage": triage_result,
        })
    return results
