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
import io
import json
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from pathlib import Path
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
NVD_RESULTS_PER_PAGE = 10
NVD_QUERY_CAP = 4
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
    "extreme": "ExtremeXOS",
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
    ("nokia", re.compile(r"nokia", re.IGNORECASE)),
    ("extreme", re.compile(r"extreme", re.IGNORECASE)),
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


def _fetch_json(url, timeout=FETCH_TIMEOUT):
    # type: (str, float) -> Any
    """GET a URL and parse the body as JSON. Raises FetchError."""
    text, _content_type, _final_url = _fetch_raw(url, timeout=timeout)
    try:
        return json.loads(text)
    except ValueError:
        raise FetchError("invalid JSON response")


def _cpe_unescape(field):
    # type: (str) -> str
    return re.sub(r"\\(.)", r"\1", field or "")


def _nvd_cpe_range_lines(vuln, cap=12):
    # type: (Any, int) -> List[str]
    """Deterministic affected-range lines from the NVD record's
    structured configurations: every vulnerable cpeMatch becomes
    "- product <product>: versions >= X and < Y" (only the bounds
    present are named; a boundless match falls back to its exact
    CPE version). Deduped, capped - this is the machine-readable
    half of the advisory that the prose description often omits."""
    lines = []  # type: List[str]
    seen = set()  # type: Set[str]

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
            bounds = []  # type: List[str]
            if match.get("versionStartIncluding"):
                bounds.append(">= %s" % match["versionStartIncluding"])
            if match.get("versionStartExcluding"):
                bounds.append("> %s" % match["versionStartExcluding"])
            if match.get("versionEndIncluding"):
                bounds.append("<= %s" % match["versionEndIncluding"])
            if match.get("versionEndExcluding"):
                bounds.append("< %s" % match["versionEndExcluding"])
            if bounds:
                line = "- product %s: versions %s" % (
                    product, " and ".join(bounds))
            else:
                version = _cpe_unescape(fields[5]) if len(fields) > 5 \
                    else ""
                if version in ("", "*", "-"):
                    continue
                line = "- product %s: version %s" % (product, version)
            if line in seen:
                continue
            seen.add(line)
            lines.append(line)
            if len(lines) >= cap:
                return True
        for sub in (node or {}).get("nodes") or []:
            if walk_node(sub):
                return True
        return False

    for wrap in (vuln or {}).get("configurations") or []:
        for node in (wrap or {}).get("nodes") or []:
            if walk_node(node):
                return lines
    return lines


def _nvd_item(vuln, keyword):
    # type: (Any, str) -> Optional[Dict[str, Any]]
    """Convert one NVD API vulnerability entry into a batch item,
    or None when it carries no CVE id. The English description is
    kept verbatim: it carries the affected-version prose ("EOS
    before 4.14.5...") the extraction/matching already handles.
    The item also keeps the record's full reference list (the
    vendor-trace step follows those URLs to the vendor original)
    and a deterministic "Structured affected ranges (NVD CPE)"
    section parsed from configurations[]."""
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
            "_published": published_raw}


def collect_nvd_items(devices, fetcher=None):
    # type: (List[Dict[str, str]], Optional[Callable[[str], Any]]) -> Dict[str, Any]
    """Query the NVD CVE API once per vendor present in the
    inventory (_nvd_query_terms: curated keywords for the core
    network vendors, derived "<Vendor> <product>" terms for the
    rest; at most NVD_QUERY_CAP queries) and convert the results
    into batch items, capped at FEED_ITEM_CAP, deduped by CVE id.
    The cap is shared round-robin across the per-vendor queries
    (newest first within each vendor) so a single vendor's
    publication batch cannot crowd out the others.

    Returns {"items", "status", "count", "queries", "reason"} with
    status "ok" | "empty" | "fetch_failed" | "no_vendors" - an
    honest outcome, never fabricated items. `fetcher(url) -> parsed
    JSON` is injectable for offline tests.
    """
    fetch = fetcher or _fetch_json
    queries = _nvd_query_terms(devices)
    result = {"items": [], "status": "empty", "count": 0,
              "queries": queries, "reason": ""}  # type: Dict[str, Any]
    if not queries:
        result["status"] = "no_vendors"
        return result
    per_query = []  # type: List[List[Dict[str, Any]]]
    seen = set()  # type: set
    errors = []  # type: List[str]
    # NVD keyword search returns the OLDEST matches first, which is
    # backwards for triage: restrict to the most recent 119 days
    # (the API caps a publication-date window at 120 days) so the
    # first page holds current CVEs.
    now = datetime.datetime.now(datetime.timezone.utc)
    pub_end = now.strftime("%Y-%m-%dT%H:%M:%S.000")
    pub_start = (now - datetime.timedelta(days=119)).strftime(
        "%Y-%m-%dT%H:%M:%S.000")
    for term in queries:
        url = NVD_API_URL + "?" + urllib.parse.urlencode(
            {"keywordSearch": term,
             "resultsPerPage": NVD_RESULTS_PER_PAGE,
             "pubStartDate": pub_start,
             "pubEndDate": pub_end})
        try:
            data = fetch(url)
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
            "text": text}


def collect_kev_items(devices, fetcher=None):
    # type: (List[Dict[str, str]], Optional[Callable[[str], Any]]) -> Dict[str, Any]
    """Fetch the CISA KEV catalog once and keep the entries whose
    vendorProject/product mentions an inventory vendor or a
    significant inventory model token. Returns {"items", "status",
    "count", "reason"} with status "ok" | "empty" |
    "fetch_failed". `fetcher(url) -> parsed JSON` is injectable."""
    fetch = fetcher or _fetch_json
    result = {"items": [], "status": "empty", "count": 0,
              "reason": ""}  # type: Dict[str, Any]
    try:
        data = fetch(KEV_FEED_URL)
    except Exception as exc:
        result["status"] = "fetch_failed"
        result["reason"] = str(exc) or exc.__class__.__name__
        return result
    vendors = inventory_vendors(devices)
    tokens = set(vendors) | _device_tokens(devices)
    pattern = _relevance_pattern(tokens) if tokens else None
    matched = []  # type: List[Dict[str, Any]]
    for entry in (data or {}).get("vulnerabilities") or []:
        if not isinstance(entry, dict):
            continue
        fields = "%s %s" % (entry.get("vendorProject") or "",
                            entry.get("product") or "")
        lowered = fields.lower()
        if any(vendor in lowered for vendor in vendors):
            matched.append(entry)
        elif pattern is not None and pattern.search(fields):
            matched.append(entry)
    matched.sort(key=lambda e: str(e.get("dateAdded") or ""),
                 reverse=True)
    items = [_kev_item(entry) for entry in matched[:FEED_ITEM_CAP]]
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


def collect_feed_items(devices, mock=False, nvd_fetcher=None,
                       kev_fetcher=None):
    # type: (List[Dict[str, str]], bool, Optional[Callable[[str], Any]], Optional[Callable[[str], Any]]) -> Dict[str, Any]
    """Collect batch items from both feeds. Returns {"items",
    "nvd", "kev"} where "nvd"/"kev" are the per-feed outcome dicts
    from collect_nvd_items / collect_kev_items. With mock=True and
    no injected fetchers, the bundled fixture files are read
    instead of the network, so the demo path works offline."""
    if mock:
        if nvd_fetcher is None:
            nvd_fetcher = _fixture_nvd_fetcher
        if kev_fetcher is None:
            kev_fetcher = _fixture_kev_fetcher
    nvd = collect_nvd_items(devices, fetcher=nvd_fetcher)
    kev = collect_kev_items(devices, fetcher=kev_fetcher)
    return {"items": list(nvd["items"]) + list(kev["items"]),
            "nvd": nvd, "kev": kev}


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


def _trace_one(item, text_fetch, json_fetch):
    # type: (Dict[str, Any], Callable[[str], str], Callable[[str], Any]) -> Optional[Tuple[str, str, str]]
    """Follow one item to its vendor original. Returns
    (vendor_text, source_url, source_label) or None when every
    route fails. Route order: Cisco CSAF, Juniper JSA full text,
    Arista CSAF, then the vendor-neutral CNA record."""
    cve_id = _item_cve_id(item)
    if not cve_id:
        return None
    refs = _item_references(item)
    csaf_url = _cisco_csaf_url(refs)
    if csaf_url:
        try:
            text = _csaf_vendor_text(json_fetch(csaf_url), cve_id,
                                     "Cisco CSAF", csaf_url)
        except Exception:
            text = ""
        if text:
            return text, csaf_url, "Cisco CSAF"
    jsa_url = _juniper_jsa_url(refs)
    if jsa_url:
        try:
            fetched = text_fetch(jsa_url)
        except Exception:
            fetched = ""
        if fetched and len(fetched) >= JSA_MIN_TEXT_CHARS:
            body = ("Vendor advisory (Juniper JSA): %s\n%s"
                    % (jsa_url, fetched))[:TRACE_TEXT_CAP]
            return body, jsa_url, "Juniper JSA"
    arista_url = _arista_csaf_url(refs)
    if arista_url:
        try:
            text = _csaf_vendor_text(json_fetch(arista_url), cve_id,
                                     "Arista CSAF", arista_url)
        except Exception:
            text = ""
        if text:
            return text, arista_url, "Arista CSAF"
    record_url = cvelist_url(cve_id)
    if record_url:
        try:
            text = _cna_vendor_text(json_fetch(record_url), cve_id)
        except Exception:
            text = ""
        if text:
            return text, record_url, "CVE CNA record"
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
                cap=TRACE_CAP):
    # type: (List[Dict[str, Any]], bool, Optional[Callable[[str], str]], Optional[Callable[[str], Any]], int) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]
    """Trace feed items to their vendor originals (see the
    section header). At most `cap` items are traced, in the given
    order; items beyond the cap and items without a CVE id pass
    through untouched. Returns (items, stats) with stats
    {"traced", "attempted", "by_source"} - "attempted" counts the
    in-cap items that carried a CVE id (each tries the vendor
    routes, then the CNA fallback). Input items are not mutated.
    With mock=True and no injected fetchers, bundled fixtures
    answer the fetches so the demo path works offline; `fetcher`
    fetches page text (JSA), `json_fetcher` fetches JSON
    (CSAF / CNA records)."""
    text_fetch = fetcher or fetch_advisory_text
    json_fetch = json_fetcher or _fetch_json
    if mock:
        if fetcher is None:
            text_fetch = _fixture_trace_text_fetcher
        if json_fetcher is None:
            json_fetch = _fixture_trace_json_fetcher
    stats = {"traced": 0, "attempted": 0,
             "by_source": {}}  # type: Dict[str, Any]
    traced_items = []  # type: List[Dict[str, Any]]
    for index, item in enumerate(items or []):
        new_item = dict(item or {})
        if index < cap and _item_cve_id(new_item):
            stats["attempted"] += 1
            outcome = _trace_one(new_item, text_fetch, json_fetch)
            if outcome is not None:
                vendor_text, source_url, source_label = outcome
                original_url = str(new_item.get("url") or "")
                if original_url and original_url != source_url:
                    vendor_text += "\nNVD: %s" % original_url
                new_item["text"] = (
                    vendor_text + "\n\n--- Feed summary ---\n"
                    + str(new_item.get("text") or ""))
                new_item["source_url"] = source_url
                new_item["source_label"] = source_label
                new_item["url"] = source_url
                stats["traced"] += 1
                by_source = stats["by_source"]
                by_source[source_label] = by_source.get(
                    source_label, 0) + 1
        traced_items.append(new_item)
    return traced_items, stats


# ---------------------------------------------------------------------------
# Batch runner
# ---------------------------------------------------------------------------

def _judge_entry(base, text, devices_text, api_key, lang, relevance):
    # type: (Dict[str, Any], str, str, Optional[str], str, Optional[Any]) -> Dict[str, Any]
    """Judge one already-available advisory text: relevance
    prefilter first (no Clocked calls on a miss), then run_triage.
    `base` carries the entry's identity keys (url, and label for
    pre-fetched items)."""
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
                                   api_key=api_key, lang=lang)
    except Exception as exc:
        entry["status"] = "error"
        entry["error"] = str(exc) or exc.__class__.__name__
        return entry
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
    relevance = _prefilter_pattern(prefilter, devices_text)
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
        results.append(_judge_entry({"url": url}, text, devices_text,
                                     api_key, lang, relevance))
    return results


def run_batch_items(items, devices_text, api_key=None, lang="en",
                    progress=None, prefilter=False):
    # type: (List[Dict[str, Any]], str, Optional[str], str, Optional[Callable[[int, int, str], None]], bool) -> List[Dict[str, Any]]
    """Triage pre-fetched items ({"label", "url", "text"} dicts,
    as produced by the feed collectors and the upload converter)
    against one inventory - the same judging path as run_batch,
    minus the fetching. Entries additionally carry the item's
    "label". `progress`, when given, is called as
    progress(index, total, label) before each item is processed."""
    relevance = _prefilter_pattern(prefilter, devices_text)
    results = []  # type: List[Dict[str, Any]]
    total = len(items)
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
        results.append(_judge_entry(
            base, str((item or {}).get("text") or ""), devices_text,
            api_key, lang, relevance))
    return results
