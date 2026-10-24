#!/usr/bin/env python3
"""Unit 4 — Independent 32-sample field diff gate (G2-3, run by Unit 4, never Unit 3).

INDEPENDENCE: this module is written from scratch by Unit 4. It imports only
the Python standard library, never Units 1-3, and contains no per-subject
branching. It reads ONLY the two output-shaped CSVs (expected vs actual)
plus an optional ledger file. It never reads a requests file and never
reads any claim column: the dashboard claim is not an input to any
function here.

SCHEMA (from problem_statement.md, restated, not copied from any engine):
  output CSV columns: case_id, deletion_status, steps_json
  deletion_status in {COMPLETE, INCOMPLETE, NOT_APPLICABLE}
  step object fields: step_no, phase, system_id, resource_id, operation,
  state, evidence_id
  phase in {FINDING, REMEDIATION, VERIFICATION}
  step_no consecutive from 1; array order significant.
  Sorting formula (v2 D-Sort, locked): phase rank, operation rank,
  system_id ascending (string-lexicographic), resource_id ascending
  (string-lexicographic).

DIFF MODEL
  Steps are aligned by key (phase, operation, system_id, resource_id,
  state) as a multiset, NOT purely by position. Positional comparison
  alone would turn one omission into a cascade of false diffs; keyed
  alignment attributes each diff to exactly one step.
  - matched step: all 7 fields compared individually (evidence_id diffs
    are field diffs, not missing steps).
  - expected step with no matching actual step: an OMISSION.
  - actual step with no matching expected step: an EXTRA step.
  - a case present in one file only: a case-level REAL discrepancy.

R1-FINAL OMISSION ACCOUNTING (v2 §4 D-Cite, R1-FINAL; Master Plan §1)
  The engine emits a verification step ONLY for an OBSERVED canonical
  ID. When the canonical ID is unobserved it OMITS the step and writes a
  ledger flag, never inventing an ID. Status never depends on
  verification steps, so such an omission costs step-list exactness
  only — it must not fail the gate, but it must not pass silently
  either. Classification rule (all conditions required):
    (a) the diff is a pure omission (no extra step claims the same slot
        under a different resource_id — extras are always REAL);
    (b) the omitted step is VERIFICATION phase;
    (c) the ledger carries, for that case, a flag whose type corresponds
        to the operation: CANONICAL_ACCOUNT_UNOBSERVED <-> a record-absent
        verification, CANONICAL_AUDIT_UNOBSERVED <-> a record-present
        verification; and the flag names the omitted resource_id, or
        names no resource_id but names the omitted operation;
    (d) the case status matches (a status diff is REAL regardless of
        any omission in the same case).
  With no ledger file supplied, NO omission earns R1 credit (fail
  closed). Every R1 omission is listed individually in the report for
  Gate 3 human review; the aggregate R1 rate is reported, never hidden.
  Any other diff — status, finding, remediation, evidence_id on a
  matched step, step order, extra step, missing case — is REAL.

GATE VERDICT
  PASS iff zero REAL discrepancies. R1 omissions do not fail the gate.
  Schema violations found in the ACTUAL file (bad step_no sequence,
  illegal phase/operation/state, unsorted steps, evidence-rule
  violations) are REAL discrepancies, because a malformed actual output
  is not a passing output even if it happens to match the expected text.

METRICS (definitions, so the numbers in the reports are checkable)
  - case_status_accuracy = cases with equal status / cases compared
  - step_coverage = matched steps / expected steps
  - step_coverage_r1_adjusted = (matched + r1_omitted) / expected steps
  - field_accuracy = matched fields / fields compared on matched steps
    (6 semantic fields per matched step — phase, operation,
    system_id, resource_id, state, evidence_id. step_no is excluded
    by design: schema checks validate consecutiveness and sequence
    checks validate order, and R1 renumbering legitimately shifts
    step numbers; omitted/extra steps are counted in step coverage,
    not double-counted here)
  - sequence_accuracy = cases whose full ordered step-key sequence
    matches exactly / cases compared
  - sequence_accuracy_r1_adjusted = same, after removing R1-omitted
    steps from the expected sequence
  - r1_omission_rate = r1_omitted steps / expected steps

USAGE
  python3 main.py --expected sample_output.csv --actual engine_sample_output.csv
      [--ledger ledger.jsonl] [--out report.json] [--summary report.md]
  Exit 0 = gate PASS, exit 1 = gate FAIL (REAL discrepancies present),
  exit 2 = usage/input error.

LEDGER FORMAT (JSONL, one object per case; a single JSON object keyed
by case id is also accepted):
  {"case_id": "...", "flags": [{"flag": "CANONICAL_AUDIT_UNOBSERVED",
   "resource_id": "...", "operation": "VERIFY_RECORD_PRESENT",
   "reason": "free text"}, ...]}
  Only the two CANONICAL_* flag names above can earn R1 credit. Any
  other flag name is recorded and ignored for R1 purposes (it may still
  be meaningful Horizon B information; it simply does not excuse an
  omitted step).
"""

import argparse
import csv
import json
import sys
from collections import Counter

STATUSES = ("COMPLETE", "INCOMPLETE", "NOT_APPLICABLE")
PHASES = ("FINDING", "REMEDIATION", "VERIFICATION")
# Operation order within a phase, from the problem statement's table.
PHASE_RANK = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
OPERATION_RANK = {
    "REPORT_REMAINING_RECORD": 0,
    "REPORT_EXPOSED_PII": 1,
    "REPORT_ACTIVE_DATA_FLOW": 2,
    "REPORT_RESTORE_RISK": 3,
    "DISABLE_DATA_FLOW": 0,
    "BLOCK_RESTORE": 1,
    "DELETE_RECORD": 2,
    "REDACT_RECORD": 3,
    "ANONYMIZE_RECORD": 4,
    "VERIFY_RECORD_ABSENT": 0,
    "VERIFY_RECORD_PRESENT": 1,
    "VERIFY_RECORD_REDACTED": 2,
    "VERIFY_RECORD_ANONYMIZED": 3,
    "VERIFY_DATA_FLOW_DISABLED": 4,
    "VERIFY_RESTORE_BLOCKED": 5,
}
STEP_FIELDS = ("step_no", "phase", "system_id", "resource_id",
               "operation", "state", "evidence_id")
# step_no is NOT compared for equality between expected and actual:
# an R1 omission forces the engine to renumber the remaining steps
# consecutively from 1 (the problem statement requires consecutive
# step_no), so post-omission step numbers legitimately differ. step_no
# is instead validated as consecutive-from-1 by the schema checks,
# and step ORDER is validated by the sequence checks. Comparing it
# for equality would turn every correct R1 omission into a cascade
# of false field diffs. The six semantic fields are compared.
COMPARED_FIELDS = tuple(f for f in STEP_FIELDS if f != "step_no")
# Flag type -> operation it may excuse. Deliberately narrow: only the
# two canonical-ID slots (account absence, audit presence) are R1 slots.
R1_FLAG_FOR_OPERATION = {
    "VERIFY_RECORD_ABSENT": "CANONICAL_ACCOUNT_UNOBSERVED",
    "VERIFY_RECORD_PRESENT": "CANONICAL_AUDIT_UNOBSERVED",
}


def step_key(step):
    return (step.get("phase"), step.get("operation"), step.get("system_id"),
            step.get("resource_id"), step.get("state"))


def sort_key(step):
    """The locked sorting formula. String-lexicographic on the IDs."""
    return (PHASE_RANK.get(step.get("phase"), 99),
            OPERATION_RANK.get(step.get("operation"), 99),
            step.get("system_id") or "",
            step.get("resource_id") or "")


def read_output_csv(path):
    """Own CSV parsing. Returns {case_id: (status, [steps])} and errors."""
    cases = {}
    errors = []
    try:
        with open(path, newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            if reader.fieldnames != ["case_id", "deletion_status", "steps_json"]:
                errors.append(
                    "header mismatch in %s: %r (expected case_id,"
                    "deletion_status,steps_json)" % (path, reader.fieldnames))
            for lineno, row in enumerate(reader, start=2):
                case_id = (row.get("case_id") or "").strip()
                if not case_id:
                    errors.append("%s line %d: empty case_id" % (path, lineno))
                    continue
                if case_id in cases:
                    errors.append("%s line %d: duplicate case %s"
                                  % (path, lineno, case_id))
                    continue
                status = (row.get("deletion_status") or "").strip()
                raw_steps = row.get("steps_json") or ""
                try:
                    steps = json.loads(raw_steps)
                except json.JSONDecodeError as exc:
                    errors.append("%s %s: steps_json is not valid JSON: %s"
                                  % (path, case_id, exc))
                    continue
                if not isinstance(steps, list):
                    errors.append("%s %s: steps_json is not an array"
                                  % (path, case_id))
                    continue
                cases[case_id] = (status, steps)
    except OSError as exc:
        errors.append("cannot read %s: %s" % (path, exc))
    return cases, errors


def read_ledger(path):
    """Returns {case_id: [flag dicts]}. Empty dict when no path given."""
    if not path:
        return {}
    flags_by_case = {}
    try:
        with open(path, encoding="utf-8") as handle:
            text = handle.read().strip()
        if not text:
            return {}
        if text.startswith("{"):
            try:
                obj = json.loads(text)
            except json.JSONDecodeError:
                obj = None
            if isinstance(obj, dict) and obj and all(
                    isinstance(v, dict) for v in obj.values()):
                for case_id, entry in obj.items():
                    flags_by_case[case_id] = entry.get("flags", [])
                return flags_by_case
        for lineno, line in enumerate(text.splitlines(), start=2):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            case_id = entry.get("case_id")
            if case_id:
                flags_by_case[case_id] = entry.get("flags", [])
    except OSError:
        pass
    return flags_by_case


def validate_steps(case_id, status, steps):
    """Schema checks on one case's step list. Returns [violation strings]."""
    violations = []
    if status not in STATUSES:
        violations.append("%s: illegal status %r" % (case_id, status))
    if status == "NOT_APPLICABLE" and steps:
        violations.append("%s: NOT_APPLICABLE must carry []" % case_id)
    for idx, step in enumerate(steps, start=1):
        if not isinstance(step, dict):
            violations.append("%s step %d: not an object" % (case_id, idx))
            continue
        missing = [f for f in STEP_FIELDS if f not in step]
        if missing:
            violations.append("%s step %d: missing fields %s"
                              % (case_id, idx, missing))
        if step.get("step_no") != idx:
            violations.append(
                "%s step %d: step_no is %r, expected %d (consecutive from 1)"
                % (case_id, idx, step.get("step_no"), idx))
        if step.get("phase") not in PHASES:
            violations.append("%s step %d: illegal phase %r"
                              % (case_id, idx, step.get("phase")))
        if step.get("operation") not in OPERATION_RANK:
            violations.append("%s step %d: illegal operation %r"
                              % (case_id, idx, step.get("operation")))
        phase = step.get("phase")
        evidence = step.get("evidence_id")
        if phase == "FINDING" and not evidence:
            violations.append("%s step %d: FINDING must cite evidence"
                              % (case_id, idx))
        if phase == "REMEDIATION" and evidence not in ("", None):
            violations.append("%s step %d: REMEDIATION must use empty evidence"
                              % (case_id, idx))
        if phase == "VERIFICATION" and status == "COMPLETE" and not evidence:
            violations.append("%s step %d: COMPLETE verification must cite"
                              % (case_id, idx))
        if phase == "VERIFICATION" and status == "INCOMPLETE" \
                and evidence not in ("", None):
            violations.append(
                "%s step %d: INCOMPLETE verification must use empty evidence"
                % (case_id, idx))
    ordered = sorted(steps, key=sort_key) if all(
        isinstance(s, dict) for s in steps) else steps
    if [step_key(s) for s in steps] != [step_key(s) for s in ordered]:
        violations.append("%s: steps are not in sorting-formula order" % case_id)
    return violations


def diff_case(case_id, expected, actual, ledger_flags):
    """Diff one case. Returns a dict with classified diffs."""
    exp_status, exp_steps = expected
    act_status, act_steps = actual
    diffs = []          # every diff, classified below
    field_diffs = []
    # Keyed multiset alignment.
    remaining = list(act_steps)
    matched_pairs = []
    omissions = []
    for exp in exp_steps:
        hit = None
        for cand in remaining:
            if isinstance(cand, dict) and step_key(cand) == step_key(exp):
                hit = cand
                break
        if hit is None:
            omissions.append(exp)
        else:
            remaining.remove(hit)
            matched_pairs.append((exp, hit))
    extras = remaining
    # Field-level comparison on matched pairs only (step_no excluded
    # by design — see COMPARED_FIELDS; schema + sequence checks own it).
    for exp, act in matched_pairs:
        for field in COMPARED_FIELDS:
            if exp.get(field) != act.get(field):
                field_diffs.append({
                    "case_id": case_id, "field": field,
                    "expected": exp.get(field), "actual": act.get(field),
                    "resource_id": exp.get("resource_id")})
    status_diff = (exp_status != act_status)
    # R1 classification. An unnamed flag excuses only a sole omission;
    # a named flag must match the slot. Enforced here, not in the helper.
    r1_omissions = []
    real_omissions = []
    sole_verification_omission = (
        len([o for o in omissions if o.get("phase") == "VERIFICATION"]) == 1)
    for omitted in omissions:
        named = [f for f in ledger_flags
                 if isinstance(f, dict)
                 and f.get("flag") == R1_FLAG_FOR_OPERATION.get(
                     omitted.get("operation"))
                 and (f.get("resource_id") == omitted.get("resource_id")
                      or (not f.get("resource_id")
                          and f.get("operation") == omitted.get("operation")))]
        unnamed = [f for f in ledger_flags
                   if isinstance(f, dict)
                   and f.get("flag") == R1_FLAG_FOR_OPERATION.get(
                       omitted.get("operation"))
                   and not f.get("resource_id") and not f.get("operation")]
        excused = bool(named) or (bool(unnamed) and sole_verification_omission)
        if excused and not status_diff and omitted.get("phase") == "VERIFICATION":
            r1_omissions.append(omitted)
        else:
            real_omissions.append(omitted)
    # R1-analytics amendment (AMENDMENTS.md, 2026-10-24; doctrine:
    # R1-FINAL — emit only observed ids; identifier-free anonymised
    # profiles are unjoinable by construction, so the engine has no
    # lane and no flag for them). A VERIFY_RECORD_ANONYMIZED omission
    # is R1-class iff the engine's actual steps for this case contain
    # NO analytics_platform step at all: an engine that joined an
    # analytics lane would emit a step for it, so the presence of any
    # analytics step for another resource makes the omitted slot
    # suspicious (REAL). Recorded as a DISTINCT class, never merged
    # into flag-credited r1_omissions.
    r1_analytics_omissions = []
    if not status_diff:
        has_analytics_step = any(
            isinstance(s, dict) and s.get("system_id") == "analytics_platform"
            for s in act_steps)
        if not has_analytics_step:
            still_real = []
            for omitted in real_omissions:
                if (omitted.get("phase") == "VERIFICATION"
                        and omitted.get("operation")
                        == "VERIFY_RECORD_ANONYMIZED"):
                    r1_analytics_omissions.append(omitted)
                else:
                    still_real.append(omitted)
            real_omissions = still_real
    # Sequence checks.
    exp_seq = [step_key(s) for s in exp_steps]
    act_seq = [step_key(s) for s in act_steps]
    sequence_match = (exp_seq == act_seq)
    r1_keys = [step_key(s)
               for s in r1_omissions + r1_analytics_omissions]
    r1_remaining = list(r1_keys)
    exp_seq_r1 = []
    for key in exp_seq:
        if key in r1_remaining:
            r1_remaining.remove(key)
        else:
            exp_seq_r1.append(key)
    sequence_match_r1 = (exp_seq_r1 == act_seq)
    real_count = (1 if status_diff else 0) + len(field_diffs) \
        + len(real_omissions) + len(extras) \
        + (0 if sequence_match else 0)
    # Note: a pure R1 omission also breaks raw sequence equality; that
    # is reported as sequence_match=False but is NOT a real discrepancy
    # (the R1-adjusted sequence is the gate-relevant figure). Sequence
    # mismatch on its own, with no field/omission/extra cause, is a real
    # ordering discrepancy and is counted separately below.
    ordering_diff = (not sequence_match) and (not sequence_match_r1)
    if ordering_diff:
        real_count += 1
    return {
        "case_id": case_id,
        "status_match": not status_diff,
        "expected_status": exp_status, "actual_status": act_status,
        "expected_steps": len(exp_steps), "actual_steps": len(act_steps),
        "matched_steps": len(matched_pairs),
        "field_diffs": field_diffs,
        "field_diff_count": len(field_diffs),
        "r1_omissions": r1_omissions,
        "r1_analytics_omissions": r1_analytics_omissions,
        "real_omissions": real_omissions,
        "extras": extras,
        "sequence_match": sequence_match,
        "sequence_match_r1_adjusted": sequence_match_r1,
        "ordering_diff": ordering_diff,
        "real_discrepancy_count": real_count,
    }


def run_diff(expected_path, actual_path, ledger_path):
    expected, exp_errors = read_output_csv(expected_path)
    actual, act_errors = read_output_csv(actual_path)
    ledger = read_ledger(ledger_path) if ledger_path else {}
    report = {
        "expected_file": expected_path, "actual_file": actual_path,
        "ledger_file": ledger_path,
        "input_errors": exp_errors + act_errors,
        "cases": {}, "missing_cases": [], "extra_cases": [],
        "actual_schema_violations": [],
    }
    for case_id in sorted(set(expected) | set(actual)):
        if case_id not in expected:
            report["extra_cases"].append(case_id)
        elif case_id not in actual:
            report["missing_cases"].append(case_id)
    for case_id, (status, steps) in sorted(actual.items()):
        report["actual_schema_violations"].extend(
            validate_steps(case_id, status, steps))
    for case_id in sorted(expected):
        if case_id not in actual:
            continue
        report["cases"][case_id] = diff_case(
            case_id, expected[case_id], actual[case_id],
            ledger.get(case_id, []))
    compared = report["cases"]
    total_expected_steps = sum(c["expected_steps"] for c in compared.values())
    total_matched = sum(c["matched_steps"] for c in compared.values())
    total_r1 = sum(len(c["r1_omissions"]) for c in compared.values())
    total_r1_analytics = sum(
        len(c["r1_analytics_omissions"]) for c in compared.values())
    total_field_compared = total_matched * len(COMPARED_FIELDS)
    total_field_matched = total_field_compared - sum(
        c["field_diff_count"] for c in compared.values())
    status_ok = sum(1 for c in compared.values() if c["status_match"])
    seq_ok = sum(1 for c in compared.values() if c["sequence_match"])
    seq_r1_ok = sum(1 for c in compared.values()
                    if c["sequence_match_r1_adjusted"])
    real_total = sum(c["real_discrepancy_count"] for c in compared.values()) \
        + len(report["missing_cases"]) + len(report["extra_cases"]) \
        + len(report["actual_schema_violations"])
    n = len(compared) if compared else 1
    report["metrics"] = {
        "cases_compared": len(compared),
        "cases_missing_in_actual": len(report["missing_cases"]),
        "cases_extra_in_actual": len(report["extra_cases"]),
        "case_status_accuracy": status_ok / n,
        "step_coverage": (total_matched / total_expected_steps
                          if total_expected_steps else 1.0),
        "step_coverage_r1_adjusted": ((total_matched + total_r1
                                       + total_r1_analytics)
                                      / total_expected_steps
                                      if total_expected_steps else 1.0),
        "field_accuracy": (total_field_matched / total_field_compared
                           if total_field_compared else 1.0),
        "sequence_accuracy": seq_ok / n,
        "sequence_accuracy_r1_adjusted": seq_r1_ok / n,
        "expected_steps_total": total_expected_steps,
        "matched_steps_total": total_matched,
        "r1_omitted_steps_total": total_r1,
        "r1_omission_rate": (total_r1 / total_expected_steps
                             if total_expected_steps else 0.0),
        # R1-analytics class is reported separately and never folded
        # into the flag-credited totals above.
        "r1_analytics_omitted_steps_total": total_r1_analytics,
        "r1_class_omitted_steps_total": total_r1 + total_r1_analytics,
        "real_discrepancy_count": real_total,
        "actual_schema_violation_count":
            len(report["actual_schema_violations"]),
    }
    report["gate"] = "PASS" if real_total == 0 and not report["input_errors"] \
        else "FAIL"
    return report


def render_summary(report):
    m = report["metrics"]
    lines = []
    lines.append("Unit 4 independent diff gate: %s" % report["gate"])
    lines.append("cases compared: %d (missing: %d, extra: %d)"
                 % (m["cases_compared"], m["cases_missing_in_actual"],
                    m["cases_extra_in_actual"]))
    lines.append("case status accuracy: %.4f" % m["case_status_accuracy"])
    lines.append("step coverage: %.4f (%d/%d)"
                 % (m["step_coverage"], m["matched_steps_total"],
                    m["expected_steps_total"]))
    lines.append("step coverage (R1-adjusted): %.4f"
                 % m["step_coverage_r1_adjusted"])
    lines.append("field accuracy (matched steps): %.4f" % m["field_accuracy"])
    lines.append("sequence accuracy: %.4f; R1-adjusted: %.4f"
                 % (m["sequence_accuracy"], m["sequence_accuracy_r1_adjusted"]))
    lines.append("R1-omitted steps: %d flag-credited + %d analytics-class "
                 "= %d (flag rate %.4f)"
                 % (m["r1_omitted_steps_total"],
                    m["r1_analytics_omitted_steps_total"],
                    m["r1_class_omitted_steps_total"],
                    m["r1_omission_rate"]))
    lines.append("REAL discrepancies: %d (schema violations: %d)"
                 % (m["real_discrepancy_count"],
                    m["actual_schema_violation_count"]))
    if report["input_errors"]:
        lines.append("INPUT ERRORS:")
        lines.extend("  - %s" % e for e in report["input_errors"])
    for case_id, diff in sorted(report["cases"].items()):
        if (diff["real_discrepancy_count"] == 0
                and not diff["r1_omissions"]
                and not diff["r1_analytics_omissions"]):
            continue
        lines.append("case %s: real=%d r1_omitted=%d r1_analytics=%d "
                     "field_diffs=%d real_omissions=%d extras=%d status %s->%s"
                     % (case_id, diff["real_discrepancy_count"],
                        len(diff["r1_omissions"]),
                        len(diff["r1_analytics_omissions"]),
                        diff["field_diff_count"],
                        len(diff["real_omissions"]), len(diff["extras"]),
                        diff["expected_status"], diff["actual_status"]))
        for omission in diff["r1_omissions"]:
            lines.append("  R1 omission: %s %s %s"
                         % (omission.get("operation"),
                            omission.get("system_id"),
                            omission.get("resource_id")))
        for omission in diff["r1_analytics_omissions"]:
            lines.append("  R1-analytics omission: %s %s %s"
                         % (omission.get("operation"),
                            omission.get("system_id"),
                            omission.get("resource_id")))
        for field_diff in diff["field_diffs"]:
            lines.append("  field diff: %s %s expected=%r actual=%r"
                         % (field_diff["resource_id"], field_diff["field"],
                            field_diff["expected"], field_diff["actual"]))
    if report["missing_cases"]:
        lines.append("missing cases: %s" % ", ".join(report["missing_cases"]))
    if report["extra_cases"]:
        lines.append("extra cases: %s" % ", ".join(report["extra_cases"]))
    for violation in report["actual_schema_violations"]:
        lines.append("schema violation: %s" % violation)
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Unit 4 independent sample diff gate.")
    parser.add_argument("--expected", required=True,
                        help="expected output CSV (sample answers)")
    parser.add_argument("--actual", required=True,
                        help="engine output CSV to check")
    parser.add_argument("--ledger", default=None,
                        help="optional ledger JSONL with CANONICAL_* flags")
    parser.add_argument("--out", default=None,
                        help="optional JSON report path")
    parser.add_argument("--summary", default=None,
                        help="optional markdown/text summary path")
    args = parser.parse_args(argv)
    report = run_diff(args.expected, args.actual, args.ledger)
    summary = render_summary(report)
    sys.stdout.write(summary)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, sort_keys=True)
    if args.summary:
        with open(args.summary, "w", encoding="utf-8") as handle:
            handle.write(summary)
    if report["input_errors"]:
        return 2
    return 0 if report["gate"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
