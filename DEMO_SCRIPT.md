# Demo Video Script — 90 seconds

Goal: show the listing-first batch workflow (a vendor **listing
page** + inventory **CSV** — the app collects the advisory links
itself), all three verdicts, the four Clocked calls per advisory,
and the one idea that matters — an honest CANNOT DETERMINE beats a
guessed "not affected".

| Time | Shot | Narration / on-screen |
|------|------|-----------------------|
| 0:00–0:10 | Title card + app header in **Batch mode** (the default). Show the pitch line and the Mock/Live badge. | "Advisory Triage for Network Operators. Point it at a vendor's advisory listing and your inventory CSV — it collects the advisories, filters them to your fleet, and tells you what to do." |
| 0:10–0:25 | In **Listing page (auto-collect)**, click the **Sample advisories (GitHub)** preset, then **Run Batch**: the "Found 7 advisory links" caption appears. Point at the inventory CSV area: upload a CSV, show the parsed preview and row counts — or note the bundled sample inventory fallback. | "Nobody pastes links one by one: the app harvests the listing page itself. Advisories that mention nothing in your fleet are skipped locally before a single API call. The CSV preview shows exactly what was parsed — encoding, headers, skipped rows." |
| 0:25–0:40 | Show the **Action summary** at the top (only the advisories needing action, AFFECTED first, one line each with its link), then the **batch summary table**: seven rows — AFFECTED, NOT AFFECTED, CANNOT DETERMINE — with urgency, affected-device counts, and a conditions flag on the Arista row. | "First the answer to 'what do I have to do': the affected hosts, the version to upgrade to, the deadline. Then the full table for the record." |
| 0:40–0:55 | Expand the Sample 1 detail. Zoom on the red **AFFECTED** card, urgency IMMEDIATE, Verify status, and the **Action required** block (affected hosts + fixed version + deadline); scroll the per-device table, extracted fields, Decide probabilities, and the checklist. | "Open any row for the full evidence: extracted fields, per-device matching done locally with zero API calls, Decide probabilities, and a checklist that matches the verdict." |
| 0:55–1:10 | Expand the Sample 7 detail. Show the amber **CANNOT DETERMINE** card, the "Applicability conditions to verify" section (TerminAttr → CloudVision), the extracted workaround in the Action block, and the condition check at the top of the checklist. | "This Arista notice only applies when TerminAttr talks to CloudVision. The inventory can't confirm that — so instead of guessing, the app names the exact condition to check, plus the workaround the advisory itself states." |
| 1:10–1:20 | Switch the mode toggle to **Paste (single advisory)**. Click **Sample 3**, Run. Show the amber CANNOT DETERMINE card and the warnings (insufficient evidence + Verify did not verify). | "Single paste mode is still there. This notice names a product family but no versions — most tools would guess; this one refuses, and tells you exactly what to go and get." |
| 1:20–1:30 | Footer close-up: endpoints used, 4 calls per advisory, no data stored. End card with repo/demo links (TBD). | "Four Clocked calls per advisory — two Extract passes, Decide, and Verify, the grounding endpoint. Built by an operator, for operators." |

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
  JavaScript, Arista sits behind a bot challenge — the app reports
  "no links found" / "blocked" and points at Link list mode rather
  than faking a harvest. Worth one line if it comes up; the GitHub
  preset is the reliable on-stage path.
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
