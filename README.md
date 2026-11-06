# Advisory Triage for Network Operators

Paste a vendor security advisory and your device inventory. Get **one
defensible verdict** — **AFFECTED**, **NOT AFFECTED**, or
**CANNOT DETERMINE** — with the evidence shown, not hidden.

Built for the **Clocked Build Challenge** by a network operator, for
network operators. The honest third verdict is the point: when an
advisory does not state affected versions, this tool says so instead of
guessing "not affected".

## Demo

- Live demo: TBD (link to be added after deployment)
- Demo video: TBD (link to be added)
- No key? The app runs in **Mock Mode** with three bundled synthetic
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

Then click **Sample 1 / 2 / 3** and **Run Triage**. That works with no
API key (Mock Mode, canned Clocked responses).

For live analysis of your own advisories, set a Clocked API key
(free account: 4,000 credits; challenge code `CLOCKEDHACKATHON` adds
16,000 more):

```bash
export CLOCKED_API_KEY=your-clocked-api-key-here   # placeholder - use your own key
streamlit run app.py
```

Or put `CLOCKED_API_KEY` in `.streamlit/secrets.toml` (git-ignored).
Never commit a real key.

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
   versions, advisory/CVE id, severity, fixed version, and action
   deadline, verbatim. Nothing is inferred.
2. **Match (local, deterministic, 0 API calls)** — each inventory line
   is compared with the extracted product and versions. Exact,
   wildcard (`17.9.x`), and range (`17.9.1-17.9.5`) version matching.
   A candidate device with an unparseable version, or a product match
   with no affected versions stated, is **CANNOT DETERMINE** — never
   silently "not affected".
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

Total: **exactly 3 Clocked calls per run.**

### Endpoints used

| Step | Clocked endpoint | SDK call | Purpose |
|------|------------------|----------|---------|
| 1 | Extract | `client.extract` | Structured fields from the advisory |
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

Sample inventory (`samples/inventory_sample.txt`): 8 invented devices
(Catalyst 9300 ×3, Nexus 3064, QFX5110, Arista 7050 ×2, ASR1002-X),
one per line as `hostname, model, OS version`. Replace it with your
own export in the same format for live runs.

## Mock Mode

Mock Mode is a feature, not a shortcut:

- With **no** `CLOCKED_API_KEY`, the three bundled samples run on
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
samples/             3 synthetic advisories + sample inventory
tests/test_triage.py Offline pytest suite (matcher + verdict composition)
DEMO_SCRIPT.md       90-second demo video shot list
```

## Tests

```bash
pip install pytest
pytest -q
```

The suite runs fully offline on mock data: exact / range / wildcard /
unparseable / product-absent matcher cases, grounding overturn, and
low-sufficiency downgrade, plus the full mock pipeline for all three
samples.

## Limitations

- **String-based version matching.** Versions are compared as exact
  strings, wildcards, or numeric ranges parsed from the advisory.
  Vendor-specific version semantics (train/branch equivalence, bundled
  images) are not modelled.
- **Single advisory per run.** Paste one advisory at a time.
- **No data retention.** The app stores nothing; advisory and inventory
  text exist only for the duration of a run (and are sent to the
  Clocked API in live mode).
- The matcher is deliberately conservative: anything it cannot prove
  becomes CANNOT DETERMINE, by design.
