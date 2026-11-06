# Demo Video Script — 90 seconds

Goal: show all three verdicts, the three Clocked calls, and the one
idea that matters — an honest CANNOT DETERMINE beats a guessed
"not affected".

| Time | Shot | Narration / on-screen |
|------|------|-----------------------|
| 0:00–0:10 | Title card + app header. Show the pitch line and the Mock/Live badge. | "Advisory Triage for Network Operators. Paste an advisory and your inventory — get one defensible verdict." |
| 0:10–0:30 | Click **Sample 1**, show advisory + inventory, click **Run Triage**. Zoom on the red **AFFECTED** card, urgency IMMEDIATE, Verify status. | "A Cisco-style advisory. CORE-SW-01 runs IOS XE 17.9.4 — listed as affected. Verdict: AFFECTED, immediate." |
| 0:30–0:45 | Scroll the per-device table, extracted-fields table, and Decide panel with probabilities. Point at the next-action checklist. | "Every step is shown: extracted fields, per-device matching done locally with zero API calls, Decide probabilities, and a checklist that matches the verdict." |
| 0:45–1:00 | Click **Sample 2**, Run. Show the grey-green **NOT AFFECTED** card. | "A Juniper-style MX advisory. No MX devices, no affected versions in inventory — NOT AFFECTED, with the evidence filed for audit." |
| 1:00–1:20 | Click **Sample 3**, Run. Show the amber **CANNOT DETERMINE** card and the warnings (insufficient evidence + Verify did not verify). | "This notice names a product family but no versions. Most tools would guess. This one refuses: CANNOT DETERMINE — and tells you exactly what to go and get." |
| 1:20–1:30 | Footer close-up: endpoints used, 3 calls, no data stored. End card with repo/demo links (TBD). | "Three Clocked calls per run — Extract, Decide, and Verify, the grounding endpoint. Built by an operator, for operators." |

## Recording notes

- Record in Mock Mode if no live key is available on the recording
  machine; the "Demo data" banner is honest and expected — say so in
  one line rather than hiding it.
- Keep the browser at 100% zoom; the verdict card must be readable
  without pausing.
- Do not show any real advisory, real hostname, or real IP — the
  bundled samples are synthetic on purpose.
