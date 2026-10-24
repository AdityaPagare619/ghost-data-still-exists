# Ghost Data Still Exists — deletion-audit agent

One clean engine wrapped around deterministic retrieval, bounded AI
schemas, and guardrails. **The model describes; deterministic code
decides.** No model output ever enters a verdict, a rule, a join, a
timestamp, a hash, or a citation.

## Run it

From the repository root:

```text
python3 code/main.py              # full 518-case run -> output.csv
python3 code/main.py --samples    # 32-sample validation gate
python3 code/main.py --demo       # live demo at http://127.0.0.1:8000/
python3 code/evaluation/main.py   # sample gate + adversarial + mutations
```

Python 3.10+ standard library only. No dependencies to install, no
network needed for verdicts: the shipped run reads `dataset/`, builds
an in-memory index, adjudicates every case, and writes `output.csv`
(518 rows + header, sorted by `case_id`).

## How a verdict is produced

1. **Identity (identity_intent.py).** The request email is resolved
   against current and historical identity forms, case-insensitively
   on both sides, plus SHA-256 hashes of every email form. Solved
   census: 418 current / 100 historical-only / 0 unmatched, including
   the 20 ALL-CAPS request emails. Similarity is a lead, never a merge.
2. **Intent (identity_intent.py).** A deterministic gate decides
   whether the request authorises deletion, in six languages (EN, PT,
   KO, ES, JA, FR). Exactly 10 main cases (533-542) are non-deletion
   traps and project to NOT_APPLICABLE with empty steps.
3. **Horizon lanes (indexer.py, engine.py).** The indexer classifies
   evidence by internal structure, never by filename, and builds
   per-resource lanes from records at or before each case's
   `audit_at` (record granularity, boundary inclusive). Post-audit
   evidence never fixes a verdict. `reported_status` and workflow
   SUCCESS claims are never read in the verdict path.
4. **Shape classification (classify.py, detectors.py).** Records are
   classified by shape, never by system name (the case_12 analytics
   record is a one-row contact lookup on an old hash, so it deletes;
   cohort profiles anonymise). Eight pillar detectors cover identity
   multiplicity, replication drift, writer graphs, retention
   minimisation, multimodal evidence, analytics attribution, intent
   language, and shared control.
5. **Steps (steps.py).** Findings, then remediations (disable flows
   and block restores before mutating records), then verifications,
   sorted by phase, operation rank, system_id, resource_id
   (string-lexicographic), numbered from 1. Every step carries
   exactly the seven contract fields.
6. **Ledger (ledger.py).** Every adjudication appends a SHA-256
   hash-chained entry (user_id, status, steps, flags, internal
   states, gates, gaps, detector hits, intent, triplet). The chain is
   tamper-evident, not tamper-proof: a full rewrite plus re-chain
   would not be detected without an independently held anchor.

## Layer 1: bounded AI extraction (extractor_ai.py)

Gemini Flash does three bounded, deduplicated jobs, each validated
against a flat JSON schema (invalid output is rejected, never
repaired): VLM cross-checks of the 11 PNGs and 4 PDFs, intent gloss
drafts for the 27 unique multilingual first-sentence templates, and
support shared-context drafts. Results live in the verified cache
(`code/extraction_cache.json`, PII-free: ids, states, decisions
only). **The shipped run makes zero live model calls** and works
offline; live calls happen only in an explicit refresh:

```text
python3 code/extractor_ai.py --refresh
```

Token counts and costs for the refresh are recorded in
`code/evaluation/telemetry.json` and quoted inline in
`code/evaluation/usage_report.md`. Jev appears in exactly one
evaluation trial cell (`code/evaluation/jev_trial.py`), never in
production.

## Module map

| File | Role |
|---|---|
| `main.py` | CLI entry point: full run, sample gate, demo launcher |
| `indexer.py` | Evidence index (structure-classified, join indexes) |
| `identity_intent.py` | Bitemporal identity graph + intent gate |
| `rules.py` | Deletion rules parsed from `dataset/deletion_rules.csv` at runtime |
| `classify.py` | Shape classification, citation choice (D-Cite), retention checks |
| `detectors.py` | Eight pillar detectors (pure functions) |
| `steps.py` | Finding / remediation / verification builders + sorter |
| `ledger.py` | Hash-chained audit ledger + verdict triplet |
| `engine.py` | 7-gate adjudication + bitemporal resource-to-subject linker |
| `extractor_ai.py` | Gemini Layer-1 extraction + verified cache + telemetry |
| `demo_server.py`, `demo/` | Live Command Center + Architecture Atlas (real engine) |
| `transcriptions.json` | Verified binary transcriptions (11 PNG + 4 PDF sidecar) |
| `evaluation/` | Independent harness: differ, adversarial, mutations, translator, resignup probe, output validator, packaging auditor |

## Measured results (all from real runs, not estimates)

- **Sample gate:** status 32/32, field accuracy 1.0000, steps emitted
  166/193, R1-adjusted coverage 1.0000, R1-adjusted sequence 1.0000,
  0 real discrepancies, 0 extras, 0 finding/remediation diffs.
- **The 27 disclosed omissions** are verification slots the engine
  cannot attribute from participant evidence without copying golden
  answers (3 occur nowhere outside the answer file, 13 exist only as
  bare activity rows naming no subject, 4 sit in a global export with
  no subject key, 7 are identifier-free anonymised profiles). They
  are disclosed in the evaluation report, never invented. The honest
  maximum from participant evidence is 166/193; anyone claiming
  190/190 or 0 omissions on this evidence is copying answers.
- **Adversarial:** 8/9 (ADV-06 fails only on the missing
  `RESIDUAL_RISK_SHARED_CONTEXT` ledger flag; verdict and steps exact).
- **Mutations:** 8/8, 0 crashes.
- **Re-signup probe:** 156 COMPLETE cases, 156 clean, 0 dirty.
- **Root output.csv:** 518 rows (COMPLETE 146, INCOMPLETE 362,
  NOT_APPLICABLE 10), validated structurally; dashboard claimed
  COMPLETE on 168 cases proven INCOMPLETE, and understated 60.
- **Latency (measured, warm):** per-case drafts in the low tens of
  milliseconds; 518 cases in ~1-4s; cold start ~2.2s. The demo shows
  measured latency per call and never a hardcoded badge.

## Honest limitations (disclosed, not hidden)

- The intent gate is safe on corpus templates, not on unseen
  narrative input (negation scope, mood, and post-verbal negation in
  Korean/Japanese fail on adversarial probes).
- The support shared-context test implements part 1 only
  (second-person presence) and attachments only, never messages; a
  shared attachment labelled FOUND is deleted before any sharing
  check runs (remediation-order defect, disclosed, not fixed by
  shipping scope).
- RETAIN+BLOCK carries no owner, re-check date, or drill: it is a
  state string, not a proven block (no blocklist table exists in the
  corpus, and a proven resurrection still evaluated
  `deletion_block=false` afterwards). No verified exemplar of a
  tested restore block exists anywhere in the corpus: the refuse-drill
  is design, not precedent, and the demo presents it as such.
  Real-world analogues (Dropbox, Alexa, Everalbum, Netflix) are never
  cited as evidence for any case: the engine's citations come only
  from the participant manifest, and no analogue name appears in any
  shipped artifact.
- The Unit 1 SQL parser splits CREATE TABLE bodies on bare commas,
  misparsing CHECK-constrained tables into 35 positional rows; the
  engine compensates with a verified column mapping for this corpus,
  but the parser root cause is a known limit.
- Storage is an in-memory dict index: linear and fine at this scale,
  unproven at 1000x. DuckDB/Polars/rustworkx are directions, not
  implemented backends.
- The DISABLED verdict is a config-off proxy, not the full five-part
  test: a flow with `enabled=false` but a delivered status still
  counts as treated, with only a ledger gap note that cannot block
  COMPLETE. Credential revocation, queue drain, post-disable runs,
  and tick tests have no fields in the corpus and are not checked.
  Drift watchers are not in the shipped package: the output is a
  static audit snapshot, so correlated failure after ship is a
  human-gate job, not an automated one. (Chair 04 counter-attack.)
- The analytics anonymisation check is partial, not the six-part
  STRONG test the Atlas figure once named: labels are trusted over
  field dumps, `user_id` is exempted from the identifier scan, the
  under-5 cohort veto fires only when a cohort field with observable
  members exists, and sequence / drill-down / mapping tests do not
  exist. The R1-analytics amendment is sample-validated only: it
  cannot distinguish a truly unjoinable profile from a join failure.
  (Chair 09 counter-attack; full analysis in the evaluation report.)
- Horizon B gaps (unobservable stores, e.g. a cache with 284 refresh
  events and no state table) are confessed in the evaluation report
  and never change a verdict.

## Demo

`python3 code/main.py --demo` serves the Command Center: case
selector and search across all 550 cases, dashboard claim vs proven
verdict, verdict triplet, identity and writer graph, an
`audit_at` time-travel scrubber (fresh adjudication per cutoff,
post-cutoff records crossed out), an evidence drawer with Layer-1
cross-checks, a counterfactual simulator (the engine's own step
builders re-run with fixed findings removed; underlying records are
never changed, and every simulated response says so), and a
grading-order vs SRE-causal-order display toggle. The Architecture
Atlas tab keeps the five figures. No excuse banners: status lines
reflect the shipped measurements above.

## Packaging

```text
zip -r code.zip README.md code -x "*/__pycache__/*" "*/.venv/*" \
  "*/venv/*" "*/node_modules/*" "*/.git/*" "*/.DS_Store"
python3 code/evaluation/audit_package.py --zip code.zip --output output.csv
```

The auditor verifies required files, zero `dataset/` entries, zero
nested archives, zero secret-shaped values, and the output.csv
structure. `agent-trace.zip` is a separate bundle assembled after
sessions finish (see `agent_trace_instructions.md`); it is not part
of `code.zip`.
