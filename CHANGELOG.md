# Changelog

Every code edit and every architecture change is tracked here and
committed to the project repo, so the founder can review each step
as a diff. Dates are IST. Numbers are measured runs, never estimates.

## 2026-10-25 — Architecture pass (full solution, no fake demos)

- Intent negation fix (the judge's #1 recommendation, founder's
  full-architecture order): negation now scopes to the verb's own
  clause (a whole-prefix check negated a later real verb with an
  earlier clause's don't); contracted n't fixed (no word boundary
  before the n, so "Don't delete my account." read as DELETION);
  KO/JA post-verbal scope added, including polite ません. All 15
  unit phrasings pass; 518-case census diff: ZERO flips (no main
  request uses these phrasings — the fix closes the hidden-case
  hole with no regression on known data).
- Four frozen adversarial fixtures (ADV-10 bare refusal, ADV-11
  mixed sentence + ACTIVE profile, ADV-12 Korean negation, ADV-13
  Japanese negation) via fixed-template translator entries (no free
  text from fixtures into the engine). Adversarial now 12/13 — the
  only failure remains disclosed ADV-06 (ledger flag, verdict and
  steps exact). Mutations 8/8, sample gate PASS, unchanged.
- Demo honesty: atlas corrected to 94 evidence files (103 is
  evidence plus dataset CSVs); simulator now routes empty-findings
  cases through the COMPLETE verification builder — verified live
  that simulate(case_26, []) equals adjudication (COMPLETE, 5
  steps), where it previously returned 2. Nothing on screen is
  simulated-as-real: simulations stay labeled, latency stays
  measured.
- README names the two-phase bitemporal design explicitly
  (Phase 2A lifetime ownership vs Phase 2B point-in-time state).
- Repo cleanup (approved structure): tooling scripts and run
  intermediates relocated to workspace tools/; .gitignore covers
  regenerable outputs; harness, reports, cache, and transcriptions
  stay. Post-cleanup driver re-run: identical green state.

## 2026-10-25 — Layer-1, quota saga, and repo tracking

- Layer-1 (Gemini) refresh: VLM cross-check complete (15/15 binaries);
  intent glosses in progress (cache holds 43 of 50 distinct first
  sentences at last count, agreement 35 of 43 decided); support drafts
  open (4 threads). The shipped run reads the verified cache and makes
  zero live calls.
- Key trials (transient, nothing stored): first founder-supplied key
  dead on both models (preview 1 call, fallback 0); second key alive
  on preview (21 calls in one run) but its fallback model answers 404
  (listed yet not generatable for that key's project).
- `extractor_ai.py`: 404 now raises a fail-fast model-unavailable
  abort instead of recording one failure per job (a wrong model name
  never resolves on retry).
- Repo tracking begins: new private repo created; this changelog and
  the commit history are the edit log. Cleanup to the approved
  professional structure (tooling and intermediates relocated out of
  the repo, harness and reports kept) follows as its own commit.

## 2026-10-24 — Engine, judgment, and validated output

- Shipped the deterministic audit engine (index → identity/intent →
  shape-driven rules → step builder → hash-chained ledger) with a
  bitemporal resource-to-subject linker: earlier snapshots, declared
  pointers, and subject-keyed traces link resources the audit-date
  state alone cannot.
- Sample gate: status 32/32, steps 166/193, 27 verification omissions
  disclosed by class (3 zero-occurrence, 13 bare-activity-only,
  4 global-sweep 404s, 7 identifier-free analytics) — unrecoverable
  without copying golden answers, which the rules forbid.
- Root output.csv: 518 rows validated (COMPLETE 146, INCOMPLETE 362,
  NOT_APPLICABLE 10); resignup probe 156/156 clean; live demo on the
  real engine with measured latency.
- Independent judgment (shipped system vs GHOST-CORE proposal):
  shipped system wins by a wide margin. GHOST-CORE's 190/190, O3
  sweep linkage, O4 activity-window lineage, and 100%-on-518 claims
  were refuted against participant evidence and the official docs.
  Adoptable, cheapest first: two-phase framing in docs, store_role on
  each fact, CanonicalFact as a frozen dataclass. Not adopted: O3,
  O4, the 190/190 and 100% claims, the <5ms badge, the file-merge
  goal. Full report: phase1/13_ARCHITECTURE_JUDGMENT_A_VS_GHOST_CORE.md
  (working notes; not part of the shipped package).
- Corrections recorded: evidence files are 94 (not 103 — 103 is
  evidence plus dataset CSVs); intent templates are 50 combined
  (27 main, 31 sample-distinct), not 27.
