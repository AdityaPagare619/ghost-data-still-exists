"""Independent validator for the generated root output.csv.

Checks exactly what can be checked from the output file plus the
participant manifest (no engine imports, no verdict logic):
  - 518 rows + header, exact columns, sorted by case_id;
  - steps_json valid JSON, step_no consecutive from 1, exactly the 7
    contract fields per step;
  - phase order FINDING -> REMEDIATION -> VERIFICATION;
  - FINDING steps cite a manifest evidence_id; REMEDIATION steps and
    INCOMPLETE-case VERIFICATION steps carry empty evidence_id;
    COMPLETE-case VERIFICATION steps cite a manifest evidence_id;
  - the 10 NOT_APPLICABLE cases are exactly case_533-case_542 with [].

What this does NOT check (by design, documented limit): the
record-level audit_at cutoff. A manifest file's captured_at is not
the record_time of the cited row, so a file-level cutoff check would
false-positive on bundles containing earlier records. The cutoff is
enforced by the engine and covered by the sample gate (grader.py)
and the demo scrubber, not by this file-level validator.

Usage (from the repository root):
    python3 code/evaluation/validate_output.py --output output.csv
        --dataset dataset/

Stdlib only. Exit 0 only when every check passes.
"""

import argparse
import csv
import json
import sys
from pathlib import Path

CONTRACT_FIELDS = {"step_no", "phase", "system_id", "resource_id",
                   "operation", "state", "evidence_id"}
PHASE_RANK = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
# Problem-statement section 6.4 operation -> allowed state vocabulary.
OPERATION_STATES = {
    "REPORT_REMAINING_RECORD": {"PRESENT"},
    "REPORT_EXPOSED_PII": {"PRESENT"},
    "REPORT_ACTIVE_DATA_FLOW": {"ACTIVE"},
    "REPORT_RESTORE_RISK": {"ACTIVE"},
    "DISABLE_DATA_FLOW": {"DISABLED"},
    "BLOCK_RESTORE": {"BLOCKED"},
    "DELETE_RECORD": {"ABSENT"},
    "REDACT_RECORD": {"REDACTED"},
    "ANONYMIZE_RECORD": {"ANONYMIZED"},
    "VERIFY_RECORD_ABSENT": {"ABSENT"},
    "VERIFY_RECORD_PRESENT": {"PRESENT"},
    "VERIFY_RECORD_REDACTED": {"REDACTED"},
    "VERIFY_RECORD_ANONYMIZED": {"ANONYMIZED"},
    "VERIFY_DATA_FLOW_DISABLED": {"DISABLED"},
    "VERIFY_RESTORE_BLOCKED": {"BLOCKED"},
}


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Validate a generated output.csv structurally.")
    parser.add_argument("--output", required=True)
    parser.add_argument("--dataset", required=True)
    args = parser.parse_args(argv)
    failures = []
    manifest = {row["file_id"] for row in csv.DictReader(open(
        Path(args.dataset) / "evidence_files.csv", encoding="utf-8"))}
    requests = {row["case_id"]: row for row in csv.DictReader(open(
        Path(args.dataset) / "deletion_requests.csv", encoding="utf-8"))}
    with open(args.output, encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != ["case_id", "deletion_status",
                                 "steps_json"]:
            print(f"bad header: {reader.fieldnames}")
            return 1
        rows = list(reader)
    if len(rows) != 518:
        failures.append(f"row count {len(rows)} != 518")
    case_ids = [r["case_id"] for r in rows]
    if case_ids != sorted(case_ids):
        failures.append("rows not sorted by case_id")
    if set(case_ids) != set(requests):
        failures.append("case_id set != deletion_requests.csv set")
    not_applicable = []
    for row in rows:
        case_id = row["case_id"]
        status = row["deletion_status"]
        try:
            steps = json.loads(row["steps_json"])
        except json.JSONDecodeError:
            failures.append(f"{case_id}: steps_json invalid JSON")
            continue
        if status == "NOT_APPLICABLE":
            not_applicable.append(case_id)
            if steps != []:
                failures.append(f"{case_id}: NOT_APPLICABLE with steps")
            continue
        if [s.get("step_no") for s in steps] != list(
                range(1, len(steps) + 1)):
            failures.append(f"{case_id}: step_no not consecutive")
        phases = [PHASE_RANK[s["phase"]] for s in steps
                  if s["phase"] in PHASE_RANK]
        if phases != sorted(phases):
            failures.append(f"{case_id}: phases out of order")
        for step in steps:
            if set(step) != CONTRACT_FIELDS:
                failures.append(f"{case_id}: step field set wrong")
                break
            allowed = OPERATION_STATES.get(step["operation"])
            if allowed is None:
                failures.append(f"{case_id}: invented operation "
                                f"{step['operation']}")
            elif step["state"] not in allowed:
                failures.append(f"{case_id}: operation "
                                f"{step['operation']} with illegal "
                                f"state {step['state']}")
            evidence = step["evidence_id"]
            if step["phase"] == "FINDING":
                if not evidence or evidence not in manifest:
                    failures.append(
                        f"{case_id}: FINDING without valid evidence_id "
                        f"({step['resource_id']})")
            elif step["phase"] == "REMEDIATION":
                if evidence != "":
                    failures.append(
                        f"{case_id}: REMEDIATION with non-empty "
                        f"evidence_id")
            elif step["phase"] == "VERIFICATION":
                if status == "INCOMPLETE" and evidence != "":
                    failures.append(
                        f"{case_id}: INCOMPLETE VERIFICATION with "
                        f"non-empty evidence_id")
                if status == "COMPLETE" and (
                        not evidence or evidence not in manifest):
                    failures.append(
                        f"{case_id}: COMPLETE VERIFICATION without "
                        f"valid evidence_id")
    expected_na = {f"case_{n}" for n in range(533, 543)}
    if set(not_applicable) != expected_na:
        failures.append(
            f"NOT_APPLICABLE set {sorted(not_applicable)} != "
            f"{sorted(expected_na)}")
    if failures:
        print(f"OUTPUT VALIDATION: FAIL ({len(failures)} problems)")
        for failure in failures[:50]:
            print(f"  ! {failure}")
        return 1
    print("OUTPUT VALIDATION: PASS (518 rows, sorted, contract fields, "
          "phase order, evidence rules, NOT_APPLICABLE 533-542)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
