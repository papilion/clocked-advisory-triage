# Demo Video Script — 90 seconds

Goal: show all three verdicts, the four Clocked calls, and the one
idea that matters — an honest CANNOT DETERMINE beats a guessed
"not affected".

| Time | Shot | Narration / on-screen |
|------|------|-----------------------|
| 0:00–0:10 | Title card + app header. Show the pitch line and the Mock/Live badge. | "Advisory Triage for Network Operators. Paste an advisory and your inventory — get one defensible verdict." |
| 0:10–0:30 | Click **Sample 1**, show advisory + inventory, click **Run Triage**. Zoom on the red **AFFECTED** card, urgency IMMEDIATE, Verify status. | "A Cisco-style advisory. CORE-SW-01 runs IOS XE 17.9.4 — listed as affected. Verdict: AFFECTED, immediate." |
| 0:30–0:45 | Scroll the per-device table, extracted-fields table, and Decide panel with probabilities. Point at the next-action checklist. | "Every step is shown: extracted fields, per-device matching done locally with zero API calls, Decide probabilities, and a checklist that matches the verdict." |
| 0:45–1:00 | Click **Sample 2**, Run. Show the grey-green **NOT AFFECTED** card. | "A Juniper-style MX advisory. No MX devices, no affected versions in inventory — NOT AFFECTED, with the evidence filed for audit." |
| 1:00–1:20 | Click **Sample 3**, Run. Show the amber **CANNOT DETERMINE** card and the warnings (insufficient evidence + Verify did not verify). | "This notice names a product family but no versions. Most tools would guess. This one refuses: CANNOT DETERMINE — and tells you exactly what to go and get." |
| 1:20–1:30 | Footer close-up: endpoints used, 4 calls, no data stored. End card with repo/demo links (TBD). | "Four Clocked calls per run — two Extract passes, Decide, and Verify, the grounding endpoint. Built by an operator, for operators." |

## Recording notes

- Samples 4–5 extend the vendor coverage: an Arista EOS advisory that hits DC-SW-01 and a Juniper QFX advisory that hits AGG-RTR-01, so Cisco, Juniper, and Arista all have an AFFECTED demo case — swap one in if you want to show multi-vendor coverage.
- Sample 6 shows prose version handling: the Juniper advisory only says "versions prior to 21.4R2" — Extract returns that prose verbatim (it is span-based), and the app derives a `before:21.4R2` constraint from it locally, so CORE-RTR-01 (21.3R3) is AFFECTED with no explicit version list at all.
- Sample 7 shows condition gating: DC-SW-01 matches the Arista advisory's product and version, but the advisory only applies when TerminAttr talks to CloudVision — the inventory cannot confirm that, so the verdict is CANNOT DETERMINE with the condition named and its check (`show running-config | include TerminAttr`) at the top of the checklist.
- Live runs make a second, focused Extract call whose only field is applicability conditions: inside the full-field call that field kept coming back empty even when the condition was plainly in the text, while the focused call returns it reliably — worth one spoken line if Sample 7 is shown live.
- Record in Mock Mode if no live key is available on the recording
  machine; the "Demo data" banner is honest and expected — say so in
  one line rather than hiding it.
- Keep the browser at 100% zoom; the verdict card must be readable
  without pausing.
- Do not show any real advisory, real hostname, or real IP — the
  bundled samples are synthetic on purpose.
