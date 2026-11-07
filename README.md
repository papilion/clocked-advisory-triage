# Advisory Triage for Network Operators

한국어 README: [README.ko.md](README.ko.md)

Give it a **list of advisory links** and your **device inventory as a
CSV upload** — it fetches every advisory itself and returns **one
defensible verdict** per advisory — **AFFECTED**, **NOT AFFECTED**,
or **CANNOT DETERMINE** — with the evidence shown, not hidden.
(Pasting a single advisory by hand is still available as the second
input mode.)

Built for the **Clocked Build Challenge** by a network operator, for
network operators. Coverage is fleet-wide, not network-only: whatever
appears in the uploaded inventory is in scope — network gear,
security appliances (firewall / IPS / WAF / DDoS), load balancers
and ADCs, and servers. The honest third verdict is the point: when an
advisory does not state affected versions, this tool says so instead of
guessing "not affected".

[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/papilion/clocked-advisory-triage)

**Live demo:** [advisory-triage.streamlit.app](https://advisory-triage.streamlit.app/)

## Languages

The UI is available in **English and Korean (한국어)** via the
language toggle at the top of the app; English is the default.
Verdicts, per-device reasons, warnings, and checklists are localized.
The bundled sample advisories remain English documents, and the
verdict claim sent to Clocked Verify stays in English.

## Demo

- Live demo: [advisory-triage.streamlit.app](https://advisory-triage.streamlit.app/)
- Demo video: [Watch on YouTube](https://youtu.be/YBKh0xRYNhk) (English narration, English/Korean subtitles) · [한국어 버전](https://youtu.be/Jj1_KyLQkEU)
- No key? The app runs in **Mock Mode** with seven bundled synthetic
  samples — see below. No sign-up needed to try the demo path.

## Run locally (under 3 minutes)

```bash
git clone <this-repo>
cd clocked-advisory-triage
python3 -m venv .venv
. .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```

The app opens in **Batch mode**: click the **Sample advisories
(GitHub)** preset, then **Run Batch** — the app collects the seven
sample advisory links from the GitHub listing itself and triages
them all. That works with no API key (Mock Mode, canned Clocked
responses). Or switch to **Paste (single advisory)**, click one of
the sample buttons (**Sample 1–7**) and **Run Triage**.

For live analysis of your own advisories, set a Clocked API key
(free account: 4,000 credits; challenge code `CLOCKEDHACKATHON` adds
16,000 more):

```bash
export CLOCKED_API_KEY=your-clocked-api-key-here   # placeholder - use your own key
streamlit run app.py
```

Or put `CLOCKED_API_KEY` in `.streamlit/secrets.toml` (git-ignored).
Never commit a real key.

## Run in GitHub Codespaces (real-time)

No local setup at all — click the **Open in GitHub Codespaces** badge
at the top of this README:

1. Create the codespace on `main`. The dev container
   (`.devcontainer/devcontainer.json`) installs `requirements.txt`
   and starts the app automatically.
2. Port **8501** is forwarded and labeled
   "Advisory Triage (Streamlit)"; a preview of the running app opens
   on its own. (If it doesn't, open the **Ports** tab and click the
   globe icon for port 8501.)
3. With no key, the app opens in **Demo (mock) mode** — all seven
   bundled samples work end to end.
4. For **LIVE mode**, add a Codespaces secret named
   `CLOCKED_API_KEY`: repo **Settings → Secrets and variables →
   Codespaces → New repository secret**. Codespaces exposes secrets
   as environment variables, and the app reads `CLOCKED_API_KEY`
   from the environment first — so create the secret *before*
   creating the codespace, or rebuild the codespace afterwards to
   pick it up. Inside a running codespace you can instead
   `export CLOCKED_API_KEY=...` in the terminal and restart the app,
   or keep the key in a local `.env` file (git-ignored, **never
   committed**) and load it into your shell before restarting:
   `set -a; . ./.env; set +a`.

The key is never stored in this repository.

한국어 사용자도 같은 순서입니다: 위 배지를 눌러 Codespace를 만들면
앱이 자동으로 실행되고, 키가 없으면 데모 모드로 열립니다.

## Batch mode — the primary workflow

The default screen is built for the real triage pile, not for
copy-pasting:

1. **Advisory source** — four ways in:
   - **Listing page (auto-collect)** — give one server-rendered
     listing/board URL (the only URL preset button is the bundled
     GitHub samples) and the app harvests the advisory links
     itself: same-domain anchors whose href or text looks
     advisory-ish (`advisory`, `cisco-sa`, `JSA…`, `/advisories/`, …),
     deduped, capped at **15**. GitHub tree pages resolve to their
     raw file URLs. The big vendors' own web listings are NOT
     offered as URL presets — Cisco PSIRT and Juniper are
     JavaScript-rendered and Arista is bot-protected, so they
     cannot be harvested; pasting one of those URLs earns a
     pointer to the vendor presets below instead of a dead run.
     When any other source cannot be harvested — a bot
     challenge page, or a JavaScript shell with no links in the
     HTML — the app says so plainly and points you at Link list
     mode; it never fakes a result.
   - **Vendor presets (structured sources)** — inside the same
     Listing source, preset buttons for **Cisco, Juniper, Arista,
     Nokia and Extreme Networks** run a vendor listing that never
     touches the vendor's web listing at all: the run collects
     that vendor's last 365 days from the structured sources —
     the NVD CVE API (the vendor's own query) and CISA KEV —
     traces the candidates to the vendor originals (CSAF / CNA)
     and screens and judges them exactly like the feeds source
     below, under a caption that names the vendor and the
     structured origin. This is the working route for precisely
     the vendors whose web listings cannot be harvested: Cisco
     PSIRT and Juniper's listing are JavaScript-rendered, and
     Arista's sits behind a bot challenge. In Mock Mode the
     presets run over the bundled fixtures for Cisco, Juniper
     and Arista; Nokia and Extreme have no bundled demo data,
     and the app says so plainly instead of showing an empty
     result — use Live mode for those two.
   - **Link list** — paste advisory URLs, one per line (the
     fallback/advanced option). The app fetches each page itself
     (HTML is reduced to readable text; plain-text advisories pass
     through) and runs the full pipeline per link. One bad link
     never aborts the batch — it shows up as a `FETCH FAILED` row
     with the reason.
   - **Vulnerability feeds (NVD / KEV)** — skip the portals
     entirely and query the official machine-readable feeds
     instead: the **NVD CVE API** (up to four keyword queries,
     vendors prioritized by device count in your inventory — the
     known network vendors use curated product keywords such as
     "Cisco IOS XE", "Juniper Junos", "Arista EOS", "Nokia SR OS",
     "Extreme EXOS"; any other
     fleet vendor present, from F5 to Microsoft, gets a derived
     "<Vendor> <top product token>" query — no API key needed) and
     CISA's **Known Exploited Vulnerabilities** catalog (filtered
     locally to your vendors and model families). Why: measured
     live, the vendor portals block automated collection (Arista
     serves a bot challenge; Cisco/Juniper listings are JavaScript
     shells), while NVD and KEV are published precisely so machines
     can read them. Each CVE becomes an advisory text (the NVD
     description carries the affected-version prose, and the NVD
     CPE configuration ranges are appended as a structured
     "affected ranges" section; KEV's due date flows into the
     Action block as the deadline) and is judged by the same
     pipeline. Per-feed counts and honest empty/failed statuses are
     shown after the run. In Mock Mode this source reads bundled
     fixture files (real public CVE/KEV data, trimmed) instead of
     the network, so the demo works offline.
   - **Vendor originals (full-text tracing)** — discovery is only
     step one. Before judging, the app follows each collected CVE
     back to the vendor's own full text (at most 10 items per run,
     known-exploited KEV items first) and judges *that*, keeping
     the feed summary appended below for reference. Routes:
     **Cisco** — the advisory's public CSAF 2.0 JSON (affected
     product names/versions composed from the product tree,
     fixed-version lists, remediation text); **Juniper** — the
     JSA article page itself, accepted only when the fetch yields
     real article text (≥ 400 chars — the portal often answers
     with a JavaScript shell instead); **Arista** — the derived
     CSAF JSON URL; and, as a fallback for **every** vendor, the
     vendor-submitted **CVE record (CNA)** from the CVEProject
     cvelistV5 mirror — structured affected products, platforms
     and version bounds (`version < lessThan`) in the vendor's own
     submission. The CNA route is vendor-generic, so it covers the
     security, load-balancer and server vendors in a fleet
     inventory too, not just the network three. The UI shows how
     many advisories were vendor-traced, and each result names its
     vendor source with a link. When every route fails, the item
     keeps its feed text and carries no vendor source — tracing
     never borrows another advisory's content and never invents
     one.
   - **Upload advisory files** — when a portal blocks the app but
     not you, save the advisory pages from your own browser and
     upload them (`.txt`, `.html`, `.htm`, `.md`, up to 10 files):
     your browser does the collecting, the app does the judging.
     Files are decoded like the inventory CSV (UTF-8 → CP949) and
     HTML is reduced to text exactly as for fetched pages.
2. **Relevance prefilter** — before any Clocked call, each fetched
   advisory is screened locally against the inventory's product
   space (model cores and words from your CSV, the fleet vendors,
   and generic network-gear terms). An advisory that mentions none
   of them is marked `SKIPPED — not related to the uploaded
   inventory` and costs **zero API calls**. A toggle ("Judge all
   advisories") turns the filter off.
3. **Inventory CSV** — upload the full device inventory once; every
   advisory is judged against every device. Column handling is
   flexible:
   - headers are matched case-insensitively in English or Korean:
     hostname ← `host|hostname|name|device|장비명|호스트명`,
     model ← `model|모델|장비모델`,
     version ← `version|os|os version|버전|펌웨어`,
     plus an optional `vendor|벤더|제조사` column that prefixes the
     model when it isn't already there;
   - extra columns (serial, IP, region, …) are ignored;
   - with no recognizable header row, columns are taken positionally
     as host, model, version;
   - encoding is decoded as UTF-8 (BOM ok) with a CP949 fallback for
     Korean Excel exports, and the delimiter may be `,`, `;`, or tab;
   - rows missing host, model, or version are skipped and counted,
     and the first parsed devices are previewed before you run.
4. **Results** — an **Action summary** first (only the advisories
   that need action, AFFECTED before CANNOT DETERMINE, one line
   each with its link), then a summary table (verdict, urgency,
   affected-device count, conditions flag per advisory; skipped
   and fetch-failed items appear as their own rows), plus one
   expandable detail per advisory. Every detail — in batch and in
   single mode — carries a deterministic **Action required** block:
   for AFFECTED, the affected hostnames, the fixed version to
   upgrade to, the deadline, and any workaround the advisory
   states (extracted by the same focused Extract pass as the
   applicability conditions); for CANNOT DETERMINE, the exact
   conditions to verify; for NOT AFFECTED, "No action required."

Caps that keep a batch sane: at most **10 links** per Link-list
run (extras are reported as skipped), **15** harvested links per
listing, **2 MB** per download, **40,000 characters** of extracted
text per advisory, 15 s fetch timeout. With no CSV uploaded, the
bundled sample inventory is used so the demo still runs in one
click. **Paste (single advisory)** mode — the original paste-text
UI — remains available in the mode switch at the top.

### One year of feed history, screened locally

The feeds source does not judge a year of CVEs one by one — most
of them are settled by the vendors' own structured data before
any model call:

1. **Collection (365 days).** NVD is queried per inventory vendor
   in consecutive publication-date windows of at most **119 days**
   (the API caps one window at 120 days) and paginated inside
   each window (500 results per page) until `totalResults` is
   exhausted — a per-vendor hard cap of 1,000 unique CVEs applies
   and is reported as truncation when hit. The KEV catalog is
   matched in full (cap 300, newest first). Entries are deduped
   by CVE id across windows and feeds — preferring the record
   that carries NVD `configurations` — and a KEV entry merges
   into the NVD item of the same CVE (known-exploited flag, due
   date), so one CVE is one item however many feeds name it.
2. **Local screening (zero API calls).** Each item's structured
   CPE ranges are evaluated against every inventoried device's
   version locally, reusing the same version comparison as the
   deterministic matcher: a version **inside** an affected range
   is a candidate-hit; a version **outside every** range for its
   product clears the device; missing ranges or an unresolvable
   comparison (e.g. a suffix-letter tie like `17.9.4` vs the
   bound `17.9.4a`) stay **uncertain**. Items whose related
   devices are *all* cleared become local **NOT AFFECTED** rows
   (basis: "local-screen"); items about no inventoried product
   are screened out and only counted; everything with a hit or an
   uncertain related device is a candidate.
3. **Deep triage (budgeted).** Candidates are traced to their
   vendor originals, then judged by the full Clocked pipeline in
   priority order — **KEV first, then CVSS severity, then
   recency** — up to **30 per run** (the "Judge all" toggle lifts
   the budget to 200). Candidates beyond the budget are not
   silently dropped: they appear as local **CANNOT DETERMINE**
   rows stating that screening was inconclusive and the item was
   beyond this run's deep-triage budget.

The captions over the results report each stage ("Collected last
365 days: NVD *n* · KEV *k*" and "Local screening: *a* not
affected by version range · *b* not in fleet · *c*
deep-triaged"). Local verdicts derive from the vendor-published
structured ranges — not from the model — and cost no Clocked
calls at all.

### Feed correctness: windows, rate limits, KEV strength, sources

- **Every NVD request carries a publication-date window**
  (`pubStartDate`/`pubEndDate`). Without one the API returns its
  oldest matches first (2015-era CVEs); both collectors — the
  recent 119-day view and the year pipeline — build their URLs
  only through the window helpers, so no code path can ask NVD
  an unwindowed question.
- **Rate budgets are honoured, and a key is optional.** NVD
  allows 5 requests / 30 s without a key and 50 / 30 s with one;
  collection spaces requests accordingly (6.1 s / 0.65 s) and
  retries 429/403 with the server's `Retry-After` when given.
  Set `NVD_API_KEY` (environment or Streamlit secrets; it is
  sent only as a request header, never in a URL) to make a
  no-key year run of minutes take well under one.
- **KEV membership is priority, not a verdict.** The KEV
  catalog publishes no version ranges, so a KEV item whose
  product matches the fleet but for which neither NVD, KEV,
  nor a traced vendor original states affected versions
  becomes a local **CANNOT DETERMINE** row ("KEV-listed product
  matches this device; confirm the installed version is not
  affected") with the KEV due date, required action and
  ransomware flag as a checklist — never AFFECTED, never NOT
  AFFECTED, and it spends no Clocked calls. When ranges do
  exist, they decide exactly as for any other item.
- **One CVE is one item, and its sources are shown.** The two
  collectors share a single merge: a CVE named by both feeds
  appears once, and every row carries a **Sources** badge —
  `NVD`, `KEV`, or `NVD + KEV` — in the summary table and the
  detail view. (The vendor document a verdict's evidence came
  from — CSAF / JSA / CNA — is still shown separately.)
- **Reachability is probed, not assumed.** Each live run
  probes NVD, KEV, Cisco CSAF, Arista CSAF, Juniper JSA and the
  CNA mirror in the deployment itself and classifies each as
  `ok`, `blocked-challenge` (HTTP 200 but an HTML challenge or
  portal shell — status codes alone lie for these vendors),
  `http-error`, `network-error` or `invalid-content`, shown as
  one caption line. Probing never blocks or alters collection.
- **Sync is a short in-process cache, KEV only.** The KEV
  catalog is cached for 15 minutes with ETag revalidation, so
  back-to-back runs do not re-download it; its
  `catalogVersion` is the freshness proof shown in the caption.
  NVD responses are deliberately *not* cached across runs:
  windows are relative to now, records are revised, and a stale
  range could manufacture a false clear.
- **Juniper JSA pages must prove they are the article.** A
  traced JSA is accepted only when the page names its JSA id
  and carries advisory markers — the support portal's
  community shell is long and plausible but is not the article,
  and it falls back to the CNA record. When a genuine JSA
  states "prior to X"-style branch bounds, they are parsed
  into *partial* ranges: a device inside a stated branch is a
  real hit, but absence from a partially parsed branch list
  never clears a device.

## How it works

```
Advisory text ──► Clocked Extract ──► structured fields
                                          │
Inventory ──────► Local deterministic ◄───┘
                  matcher (0 API calls)     per-device verdicts
                                          │
                  Clocked Decide ─────────► urgency + evidence sufficiency
                                          │
                  Clocked Verify ─────────► verdict claim checked
                  (grounding)               against advisory + inventory
                                          │
                                    Final verdict + checklist
```

1. **Extract** — Clocked `extract` pulls vendor, product(s), affected
   versions, advisory/CVE id, severity, fixed version, action
   deadline, and **applicability conditions** (statements like "only
   when TerminAttr talks to CloudVision"), verbatim. Conditions get a
   **second, focused Extract call** whose only field is
   `applicability_conditions`: measured against the real API, span
   extraction reliability drops with the number of requested fields —
   inside the full-field call the conditions came back empty even
   when the condition sentence was plainly in the text, while the
   focused single-field call returned them reliably. **Version
   constraints** are the one thing the app computes rather than
   copies: Extract is span-based, so a normalized token is not a
   span and it never emits one (the schema no longer asks) — the app
   therefore derives constraints locally and deterministically from
   the verbatim prose (prose like "versions prior to 21.4R2" becomes
   `before:21.4R2`; also `up_to:X` and `train_before:T:B`), with the
   stated fixed version as a guarded fallback. Nothing else is
   inferred.
2. **Match (local, deterministic, 0 API calls)** — each inventory line
   is compared with the extracted product and versions. Exact,
   wildcard (`17.9.x`), and range (`17.9.1-17.9.5`) version matching.
   Affected-version items as returned live may carry a vendor prefix
   ("EOS 4.30.5M", "Junos OS 21.2R1") — those are decided via their
   version token, while items with prose wording are never reduced
   to a token.
   When the explicit version list does not decide a device, the
   normalized constraints are evaluated numerically instead; when the
   numeric comparison is genuinely undecidable (e.g. EOS `4.30.5F`
   vs `4.30.5M` — suffix ordering is vendor-specific), the result is
   **CANNOT DETERMINE**, never a guess. A candidate device with an
   unparseable version, or a product match with no affected versions
   stated, is likewise **CANNOT DETERMINE** — never silently "not
   affected". And when the advisory carries applicability
   conditions, a product+version match is **gated** to
   CANNOT DETERMINE: the inventory says nothing about the condition,
   so the UI names it under "Applicability conditions to verify",
   adds a condition-check warning, and puts the concrete verification
   step at the top of the checklist.
3. **Decide** — Clocked `decide` answers three questions with
   probabilities: is action immediate, should it be planned, and is
   the advisory evidence sufficient to decide at all? Low sufficiency
   downgrades the whole verdict to CANNOT DETERMINE.
4. **Verify** — Clocked `grounding` checks the one-sentence verdict
   claim against **both source texts: the advisory and the inventory
   it was matched against**. The claim asserts inventory facts too
   (e.g. that a device is present in the inventory), so checking it
   against the advisory alone would wrongly reject correct verdicts.
   If it does not verify, the verdict is overturned to
   CANNOT DETERMINE with a visible warning.

Total: **exactly 4 Clocked calls per run.**

### Endpoints used

| Step | Clocked endpoint | SDK call | Purpose |
|------|------------------|----------|---------|
| 1 | Extract | `client.extract` | Structured fields from the advisory |
| 1b | Extract (focused) | `client.extract` | Applicability conditions only — a single-field call, because span extraction of that field proved unreliable inside the full field set |
| 3 | Decide | `client.decide` | Urgency + evidence sufficiency, with probabilities |
| 4 | Verify | `client.grounding` | Check the verdict claim against the advisory + inventory |

> **Note:** "Verify" is the challenge name for the SDK's **grounding**
> endpoint. In code and in the SDK it is `grounding`; in the challenge
> categories it is grouped under Verify / Compare / Rerank.

Award categories targeted: **Best Overall App**, **Best Use of Decide,
Extract, or Fill** (steps 1 + 3), and **Best Use of Verify, Compare,
or Rerank** (step 4).

## Samples guide

All samples are **synthetic and public-safe**: invented advisory IDs,
invented hostnames, no real IPs, no real vendor text.

| Sample | Advisory | Expected overall verdict |
|--------|----------|--------------------------|
| Sample 1 | Cisco-style: Catalyst 9300, IOS XE 17.9.x affected, High, fixed version + deadline | **AFFECTED** (CORE-SW-01 runs 17.9.4) |
| Sample 2 | Juniper-style: MX series only, version range absent from inventory | **NOT AFFECTED** |
| Sample 3 | KISA-style: product family named, **no versions, no fixed version** | **CANNOT DETERMINE** |
| Sample 4 | Arista-style: Arista 7050SX3, EOS 4.30.4M/4.30.5M affected, High, fixed version + deadline | **AFFECTED** (DC-SW-01 runs 4.30.5M; DC-SW-02 is a 7050CX3 — a different product, not affected) |
| Sample 5 | Juniper-style: QFX5110, Junos OS 21.2R1–21.2R3 affected, High, fixed version + deadline | **AFFECTED** (AGG-RTR-01 runs 21.2R3) |
| Sample 6 | Juniper-style: MX480, affected versions stated only in prose — "Junos OS versions **prior to 21.4R2**", fixed 21.4R2, High | **AFFECTED** (CORE-RTR-01 runs 21.3R3, decided by the locally derived `before:21.4R2` constraint) |
| Sample 7 | Arista-style: Arista 7050SX3, EOS 4.30.5M affected, but **only when TerminAttr is configured to talk to CloudVision (CVP)** | **CANNOT DETERMINE** (DC-SW-01 matches product + version, but the inventory cannot confirm the TerminAttr condition) |

All three vendors — Cisco, Juniper, and Arista — have an **AFFECTED**
demo case (Samples 1, 5, and 4). Samples 2 and 5 are both Juniper-style
and differ only in the product named, which shows the per-product
precision of the matcher: the MX-only advisory in Sample 2 leaves the
QFX5110 untouched, while Sample 5 hits it. Samples 6 and 7 cover the
two shapes real advisories take that a plain version list cannot:
prose version bounds (Sample 6) and configuration conditions
(Sample 7, the Arista 0201 pattern).

Sample inventory (`samples/inventory_sample.txt`): 11 invented devices
(Catalyst 9300 ×3, Nexus 3064, QFX5110, Arista 7050 ×2, ASR1002-X,
MX480, Nokia 7750 SR-12, Extreme X450a-24x), one per line as
`hostname, model, OS version`. Replace it with
your own export in the same format for live runs.

## Mock Mode

Mock Mode is a feature, not a shortcut:

- With **no** `CLOCKED_API_KEY`, the seven bundled samples run on
  canned responses in `mock_responses.json`, shaped exactly like real
  SDK responses, and the UI shows a "Demo data" banner.
- Pasting **arbitrary text** in Mock Mode does **not** produce a
  verdict — the app states plainly that a key is needed for live
  analysis. Mock Mode never fabricates a verdict.

## Project layout

```
app.py               Streamlit UI only (Batch + Paste modes, EN/KO)
triage.py            All Clocked SDK access, matcher, verdict composition
batch.py             Batch support: CSV inventory parsing, advisory fetching, listing harvester, NVD/KEV feed collectors, vendor full-text tracing (CSAF/JSA/CNA), upload conversion, batch runners
mock_responses.json  Canned Extract/Decide/Verify responses per sample
samples/             7 synthetic advisories + sample inventory + NVD/KEV/CSAF/CNA fixtures (real public data, trimmed)
tests/test_triage.py Offline pytest suite (matcher + verdict composition)
tests/test_app.py    AppTest suite (paste-mode widget state)
tests/test_batch.py  Offline pytest suite (CSV, links, fetching, batch, batch UI)
tests/test_feeds.py  Offline pytest suite (feed collectors, fleet-wide vendors, fixtures, uploads, items runner, feeds/uploads UI)
tests/test_trace.py  Offline pytest suite (vendor tracing routes, CNA fallback, caps, Mock Mode fixtures)
.devcontainer/       One-click GitHub Codespaces environment (runs the app on port 8501)
DEMO_SCRIPT.md       90-second demo video shot list
```

## Tests

```bash
pip install pytest
pytest -q
```

The suite runs fully offline on mock data: exact / range / wildcard /
unparseable / product-absent matcher cases, constraint parsing and
comparison (including the suffix-ambiguity case), the applicability
condition gate, grounding overturn, and low-sufficiency downgrade,
plus the full mock pipeline for all seven samples in English and
Korean. The batch suite covers CSV parsing (UTF-8 BOM, CP949,
semicolon/tab delimiters, Korean headers, vendor prefixing, skipped
rows, positional fallback), link-list cleaning and capping,
HTML-to-text extraction, the batch runner with an injected stub
fetcher (one fetch failure never aborts the batch), and AppTest
coverage for both input modes.

## Limitations

- **Version semantics are numeric, not vendor-aware.** Explicit
  versions match as exact strings, wildcards, or numeric ranges, and
  prose bounds ("prior to X", "X and earlier", a train bounded by a
  fixed release) are normalized into constraints and compared
  numerically. What is still not modelled: letter-suffix ordering
  when the numeric parts tie (EOS `4.30.5F` vs `4.30.5M` is
  CANNOT DETERMINE, by design), train/branch equivalence beyond the
  stated train, and bundled-image versioning.
- **Applicability conditions are surfaced, not resolved.** The
  inventory format carries model and OS version only, so a condition
  like "TerminAttr configured for CVP" cannot be confirmed from it;
  the tool gates the verdict to CANNOT DETERMINE and tells you
  exactly what to check on the device. Feeding it a configuration
  inventory would let those verdicts resolve.
- **Batch fetching is best-effort.** Batch mode downloads advisory
  pages directly; pages behind a login, a bot wall, or heavy
  JavaScript rendering may come back as `FETCH FAILED` rows or with
  partial text (which then honestly trends to CANNOT DETERMINE).
  Paste mode remains the fallback for those.
- **Listing auto-collect is best-effort too, and honest about it.**
  Server-rendered listings harvest well; portals behind a bot
  challenge (measured live: Arista) report "blocked", and
  JavaScript-rendered portals (measured live: Cisco PSIRT,
  Juniper) report "no links found" — in both cases the UI directs
  you to Link list mode rather than inventing results. The
  **vendor presets** in the same Listing source are the direct
  answer for Cisco, Juniper, Arista, Nokia and Extreme: they
  skip the web listing entirely and collect the vendor from the
  structured feeds instead. The
  **Vulnerability feeds** and **Upload advisory files** sources
  exist precisely for those portals: NVD/KEV are official
  machine-readable channels, and an upload lets the operator's own
  browser do the collecting.
- **Feed coverage is keyword-shaped and recent-first.** The NVD
  source issues at most four keyword queries (vendors prioritized
  by device count), restricted to CVEs published in the last
  119 days (the API's date-window cap; without it the API returns
  the oldest matches first), 10 results each, newest first,
  15 items max — not an exhaustive per-product CPE walk; KEV only
  lists vulnerabilities known to be exploited.
  Feeds complement vendor advisories, they do not replace them.
- **Vendor tracing is capped and best-effort.** At most 10 feed
  items per run are traced to vendor originals, known-exploited
  (KEV) items first; the rest are judged on their feed text.
  Measured live on 2026-11-07: Cisco CSAF JSON and the CNA mirror
  return full structured data, while Juniper's JSA portal answered
  a direct fetch with a 45-character shell — the ≥ 400-char
  acceptance rule rejects that, and the CNA record supplied the
  affected-version ranges instead. Arista's CSAF endpoint can
  bot-challenge automated fetches; the same CNA fallback applies.
  A failed trace is never dressed up as a traced one.
- **Cisco advisories with no CVE are a known gap.** Discovery
  is NVD keyword search plus KEV, both CVE-keyed; a Cisco
  advisory that carries no CVE cannot enter the merge/screen
  machinery. Cisco's CSAF RSS index is probed for reachability
  but is not yet a discovery source — that is deferred, not
  forgotten.
- **Arista and Juniper portals block automated fetches.** Their
  CSAF/JSA endpoints can answer HTTP 200 with a bot-challenge
  or portal-shell page; the app classifies that honestly
  (`blocked-challenge`), never ingests the shell as evidence,
  and falls back to the vendor-submitted CNA record, which
  carries the same branch ranges. No bypass is attempted.
- **The relevance prefilter is a coarse screen.** It only drops
  advisories that mention nothing in the inventory's product space
  at all; the per-device verdict logic is unchanged, and the
  filter can be switched off per run.
- **No data retention.** The app stores nothing; advisory and inventory
  text exist only for the duration of a run (and are sent to the
  Clocked API in live mode).
- The matcher is deliberately conservative: anything it cannot prove
  becomes CANNOT DETERMINE, by design.

## Deployment

The live demo at https://advisory-triage.streamlit.app/ auto-deploys
from the `main` branch of this repository (Streamlit Cloud). The
Clocked API key is provided to the deployment as a Streamlit secret
(`CLOCKED_API_KEY`); it is never committed to the repo.
