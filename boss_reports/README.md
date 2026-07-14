# TTT-RL boss reports

This directory contains versioned, boss-ready snapshots of the TTT-RL research program. Each dated folder should contain a self-contained HTML report, a nine-slide PowerPoint milestone deck, the reusable generation sources, and a machine-readable manifest.

## Reporting cadence

- **Milestone first:** publish a new report within 24 hours of a material scientific decision boundary: formal unblinding, PASS / NO-GO / PIVOT, completion of the online-ICL comparator, N=8 confirmation, second-task transfer, or a blocker that moves the decision date by more than three working days.
- **Maximum staleness:** refresh the shareable HTML at least once every seven calendar days. If no efficacy decision has changed, say so explicitly instead of manufacturing a new claim.
- **Deck threshold:** regenerate the full 7–10 slide deck only for material progress. A no-change weekly heartbeat may update the HTML without pretending that a scientific milestone occurred.
- **Blindness rule:** never expose, summarize, infer, or plot partial efficacy from a blinded formal run. While blinded, report only liveness, pairing/integrity, sealing, and audit state.
- **Evidence labels:** every result must be labeled as `FORMAL`, `CONFIRMATORY`, `EXPLORATORY`, `AUDIT DIAGNOSTIC`, or `RUN HEALTH`.

## Naming

Use `boss_reports/YYYY-MM-DD/ttt_rl_progress_YYYY-MM-DD.{html,pptx}`. Keep report facts in `report_data.json`; use `generate_html.mjs` and `generate_pptx.mjs` to reproduce the artifacts; update `report_manifest.json` after QA.
