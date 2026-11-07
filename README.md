# Advisory Triage for Network Operators

Paste a vendor security advisory and your device inventory. Get **one
defensible verdict** — **AFFECTED**, **NOT AFFECTED**, or
**CANNOT DETERMINE** — with the evidence shown, not hidden.

Built for the **Clocked Build Challenge** by a network operator, for
network operators. The honest third verdict is the point: when an
advisory does not state affected versions, this tool says so instead of
guessing "not affected".

[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/papilion/clocked-advisory-triage)

## Languages

The UI is available in **English and Korean (한국어)** via the
language toggle at the top of the app; English is the default.
Verdicts, per-device reasons, warnings, and checklists are localized.
The bundled sample advisories remain English documents, and the
verdict claim sent to Clocked Verify stays in English.

## Demo

- Live demo: TBD (link to be added after deployment)
- Demo video: TBD (link to be added)
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

Then click one of the sample buttons (**Sample 1–7**) and
**Run Triage**. That works with no API key (Mock Mode, canned Clocked
responses).

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

Sample inventory (`samples/inventory_sample.txt`): 9 invented devices
(Catalyst 9300 ×3, Nexus 3064, QFX5110, Arista 7050 ×2, ASR1002-X,
MX480), one per line as `hostname, model, OS version`. Replace it with
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
app.py               Streamlit UI only
triage.py            All Clocked SDK access, matcher, verdict composition
mock_responses.json  Canned Extract/Decide/Verify responses per sample
samples/             7 synthetic advisories + sample inventory
tests/test_triage.py Offline pytest suite (matcher + verdict composition)
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
Korean.

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
- **Single advisory per run.** Paste one advisory at a time.
- **No data retention.** The app stores nothing; advisory and inventory
  text exist only for the duration of a run (and are sent to the
  Clocked API in live mode).
- The matcher is deliberately conservative: anything it cannot prove
  becomes CANNOT DETERMINE, by design.
