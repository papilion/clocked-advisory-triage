# Demo Video Script — 8 shots (~1:45 EN / ~2:20 KO)

Goal: show the listing-first batch workflow (a vendor **listing
page** + inventory **CSV** — the app collects the advisory links
itself), the structured-source **vendor presets**, all three
verdicts, the four Clocked calls per advisory, and the one idea
that matters — an honest CANNOT DETERMINE beats a guessed
"not affected".

| Time | Shot | Narration / on-screen |
|------|------|-----------------------|
| 0:00–0:13 | **Title card.** App name and tagline over the dark slide; "Built with Clocked API · Extract / Decide / Verify". | "Advisory Triage for Network Operators. Point it at a vendor's advisory listing and your inventory CSV — it collects the advisories, filters them to your fleet, and tells you exactly what to do." |
| 0:13–0:26 | **Listing page (auto-collect)** run. The preset area shows the only URL preset left — **Sample advisories (GitHub)** — plus the **vendor preset row** (Cisco / Juniper / Arista / Nokia / Extreme Networks). Click the samples preset, **Run Batch**: the "Found 7 advisory link(s) on the listing page" caption and the **Action summary** heading are in frame, over the inventory CSV section (bundled sample inventory fallback noted). | "Nobody pastes links one by one. The app harvests the listing page itself, and advisories that mention nothing in your fleet are screened out locally — before a single API call." |
| 0:26–0:35 | **Batch summary table**: seven rows — AFFECTED, NOT AFFECTED, CANNOT DETERMINE — with urgency, affected-device counts, and a conditions flag on the Arista row, under the tail of the Action summary. | "You get one table: affected, not affected, or honestly cannot determine — with urgency and affected-device counts." |
| 0:35–0:52 | **Vendor preset (NEW).** Back in the Listing source, click the **Cisco** vendor preset, **Run Batch**. Frame holds the caption "Vendor listing — Cisco: collected from structured sources (NVD / CISA KEV + vendor original texts), last 365 days — not scraped from the vendor's web listing page.", the stage captions (collected / screened / vendor-traced), the Action summary line for the Cisco advisory with its CSAF link, and the batch table row: CVE-2023-20198 **AFFECTED**, immediate, 2 devices. | "Vendor listing pages are JavaScript-rendered or bot-walled, so presets for Cisco, Juniper, Arista, Nokia and Extreme collect from structured sources instead — NVD scoped by vendor, plus CISA KEV — and still trace every candidate to the vendor's own full text." |
| 0:52–1:05 | Expand the **Sample 1** detail. The red **AFFECTED** card, urgency IMMEDIATE, Verify (grounding) status, and the **Action required** block (affected hosts + fixed version + deadline), over the extracted fields. | "Open a row for the full evidence: the affected hosts, the version to upgrade to, the deadline — extracted fields, local per-device matching, Decide probabilities, and a checklist." |
| 1:05–1:19 | Expand the **Sample 7** detail. Show the amber **CANNOT DETERMINE** card, the "Applicability conditions to verify" section (TerminAttr → CloudVision), the extracted workaround in the Action block, and the condition check. | "This Arista notice only applies when TerminAttr talks to CloudVision. The inventory cannot confirm that — so instead of guessing, the app names the exact condition to check, plus the workaround from the advisory itself." |
| 1:19–1:33 | Switch to **Paste (single advisory)**. Click **Sample 3**, Run. Show the amber CANNOT DETERMINE card and the warnings (insufficient evidence + Verify did not verify). | "Single paste mode is still there. This notice names a product family but no versions. Most tools would guess. This one refuses — and tells you exactly what to go and get." |
| 1:33–1:45 | **End card**: the four-calls line, the live demo and source links. | "Four Clocked calls per advisory: two Extract passes, Decide, and Verify, the grounding endpoint. Built by an operator, for operators." |

## Recording notes

- The batch demo works end to end in both modes: the GitHub
  samples preset harvests the repo's own samples directory (tree
  links resolve to raw file URLs, which hit the normal sample
  detection), and **Link list** source with **Load sample link
  list** reaches the same seven files directly. With no CSV
  uploaded, the bundled sample inventory is used — say so in one
  line.
- Real vendor listings are honest about their limits (measured
  live): Cisco PSIRT and Juniper render their listings with
  JavaScript, Arista sits behind a bot challenge — so the dead
  vendor URL presets were **removed** (only the GitHub samples
  preset remains as a URL preset). The **vendor presets** in the
  Listing source (Cisco / Juniper / Arista / Nokia / Extreme
  Networks) are the supported path: they collect from structured
  sources (NVD scoped by vendor + CISA KEV) and trace candidates
  to the vendor's own full text. Pasting a vendor listing URL by
  hand earns a steering notice to the matching preset instead of
  a dead "no links found" run. The GitHub preset is the reliable
  on-stage URL path.
- If a judge asks "so how do I feed it real vendor data?": switch
  the source to **Vulnerability feeds (NVD / KEV)** and Run — the
  app queries the official NVD API and the CISA KEV catalog for
  the inventory's vendors (in Mock Mode it reads bundled real-data
  fixtures and reports "NVD: 3 CVEs collected · KEV: 3 matches").
  Before judging, each CVE is traced back to the vendor's own full
  text — Cisco CSAF, Juniper JSA, or the vendor's CNA record — and
  the caption reports how many were vendor-traced ("Vendor-traced:
  3 of 6" in the mock run).
- Or switch to **Upload advisory files**: advisories saved from
  your own browser (where the portals let you in) are judged
  exactly like fetched pages — the browser collects, the app
  judges.
- Live runs make a second, focused Extract call for applicability
  conditions and workarounds: inside the full-field call those
  fields kept coming back empty even when the sentences were
  plainly in the text, while the focused call returns them
  reliably — worth one spoken line if Sample 7 is shown live.
- A real inventory CSV also works for the upload shot: Korean or
  English headers, CP949 encoding, and extra columns are all fine —
  the preview caption shows what was understood.
- Feeds now collect a full year (NVD in ≤119-day windows plus the
  full KEV catalog), screen it locally against the vendors'
  structured version ranges at zero API cost, and deep-triage only
  the real candidates (30 per run, KEV first) — the captions above
  the results show each stage's counts.
- Samples 4–5 extend the vendor coverage (Arista EOS hits DC-SW-01,
  Juniper QFX hits AGG-RTR-01), so all three vendors have an
  AFFECTED row in the summary table. Sample 6 shows prose version
  handling: the advisory only says "versions prior to 21.4R2" — the
  app derives a `before:21.4R2` constraint locally, so CORE-RTR-01
  (21.3R3) is AFFECTED with no explicit version list at all.
- Record in Mock Mode if no live key is available on the recording
  machine; the "Demo data" banner is honest and expected — say so in
  one line rather than hiding it.
- Keep the browser at 100% zoom; the verdict card must be readable
  without pausing.
- Do not show any real advisory, real hostname, or real IP — the
  bundled samples are synthetic on purpose. The same goes for the
  CSV: use the bundled sample inventory or a synthetic export.
