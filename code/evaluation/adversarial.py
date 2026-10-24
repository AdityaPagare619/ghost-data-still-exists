#!/usr/bin/env python3
"""Unit 4 — Adversarial suite runner (pre-registered expectations).

INDEPENDENCE: own parsing, own diff logic, stdlib only, no Unit 1-3
imports. Expectations live in adversarial/*.json and were written
BEFORE any engine ran them. They are frozen by sha256 in
adversarial_manifest.json; changing an expectation after a failure
requires an entry in AMENDMENTS.md (reason + doctrine citation) and a
manifest refresh — the runner's --freeze-check fails loudly otherwise,
so a failing case cannot be quietly redefined into a pass.

EXPECTATION FORMAT (per file)
  adversarial_id, pillar, title, doctrine_ref, request_summary,
  bundle: synthetic input the engine is fed through its own adapter
    (fictional identifiers only; resource labels are bundle-local,
    e.g. "tombstone_synth_1" — never real competition resource ids),
  expected: {deletion_status} OR {deletion_status_not},
    steps_pattern: ordered list of {phase, operation, state} the
    engine's steps must match on those three fields (system/resource
    names are the engine's own labels, checked only against the
    bundle's allowlist — an invented id outside the bundle fails),
    requires_ledger_flags: flag names the engine's ledger must carry
    for this case, forbidden_statuses: statuses that fail outright.
  rationale: why doctrine demands this outcome, in words.

ENGINE OUTPUT FORMAT (what the runner consumes)
  JSON list of {"adversarial_id", "deletion_status", "steps": [...],
  "ledger_flags": [...]}. The runner never executes the engine; it
  grades an output the engine (or a human adjudicator) produced for
  the bundle. A missing output for a registered case is a FAIL
  (ungraded), never a skip.

USAGE
  python3 adversarial.py --dir adversarial/ [--engine-output out.json]
      [--freeze-check] [--manifest adversarial_manifest.json]
  Exit 0 = all graded cases pass (and freeze intact when checked);
  exit 1 = any fail; exit 2 = usage/input error.
  With no --engine-output, the runner only validates expectations
  (well-formed, frozen) — this is the mode runnable before Unit 3.
"""

import argparse
import hashlib
import json
import os
import sys

STATUSES = ("COMPLETE", "INCOMPLETE", "NOT_APPLICABLE")
PHASES = ("FINDING", "REMEDIATION", "VERIFICATION")
OPERATIONS = {
    "REPORT_REMAINING_RECORD", "REPORT_EXPOSED_PII",
    "REPORT_ACTIVE_DATA_FLOW", "REPORT_RESTORE_RISK",
    "DISABLE_DATA_FLOW", "BLOCK_RESTORE", "DELETE_RECORD",
    "REDACT_RECORD", "ANONYMIZE_RECORD", "VERIFY_RECORD_ABSENT",
    "VERIFY_RECORD_PRESENT", "VERIFY_RECORD_REDACTED",
    "VERIFY_RECORD_ANONYMIZED", "VERIFY_DATA_FLOW_DISABLED",
    "VERIFY_RESTORE_BLOCKED",
}


def load_expectations(directory):
    expectations = {}
    errors = []
    for name in sorted(os.listdir(directory)):
        if not name.endswith(".json"):
            continue
        path = os.path.join(directory, name)
        try:
            with open(path, encoding="utf-8") as handle:
                obj = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            errors.append("%s: unreadable: %s" % (name, exc))
            continue
        adv_id = obj.get("adversarial_id")
        if not adv_id:
            errors.append("%s: missing adversarial_id" % name)
            continue
        if adv_id in expectations:
            errors.append("duplicate adversarial_id %s" % adv_id)
        expectations[adv_id] = obj
    return expectations, errors


def validate_expectation(obj):
    """Well-formedness of one pre-registered expectation."""
    errors = []
    for field in ("adversarial_id", "pillar", "title", "doctrine_ref",
                  "request_summary", "bundle", "expected", "rationale"):
        if field not in obj:
            errors.append("%s: missing field %s" % (obj.get("adversarial_id"),
                                                    field))
    expected = obj.get("expected", {})
    has_status = "deletion_status" in expected
    has_not = "deletion_status_not" in expected
    if has_status == has_not:
        errors.append("%s: expected must carry exactly one of "
                      "deletion_status / deletion_status_not"
                      % obj.get("adversarial_id"))
    if has_status and expected["deletion_status"] not in STATUSES:
        errors.append("%s: illegal expected status" % obj.get("adversarial_id"))
    if has_not and expected["deletion_status_not"] not in STATUSES:
        errors.append("%s: illegal deletion_status_not" % obj.get("adversarial_id"))
    for step in expected.get("steps_pattern", []):
        if step.get("phase") not in PHASES:
            errors.append("%s: bad pattern phase %r"
                          % (obj.get("adversarial_id"), step.get("phase")))
        if step.get("operation") not in OPERATIONS:
            errors.append("%s: bad pattern operation %r"
                          % (obj.get("adversarial_id"), step.get("operation")))
    if expected.get("deletion_status") == "NOT_APPLICABLE" \
            and expected.get("steps_pattern"):
        errors.append("%s: NOT_APPLICABLE must carry an empty pattern"
                      % obj.get("adversarial_id"))
    return errors


def bundle_resource_labels(bundle):
    labels = set()
    for record in bundle.get("records", []):
        if record.get("resource_label"):
            labels.add(record["resource_label"])
    for flow in bundle.get("flows", []):
        if flow.get("resource_label"):
            labels.add(flow["resource_label"])
    for backup in bundle.get("backups", []):
        if backup.get("resource_label"):
            labels.add(backup["resource_label"])
    return labels


def grade_case(obj, output):
    """Grade one engine output against one expectation. Returns dict."""
    expected = obj["expected"]
    problems = []
    status = output.get("deletion_status")
    if "deletion_status" in expected and status != expected["deletion_status"]:
        problems.append("status %r, expected %r"
                        % (status, expected["deletion_status"]))
    if "deletion_status_not" in expected \
            and status == expected["deletion_status_not"]:
        problems.append("status %r is forbidden for this case" % status)
    for forbidden in expected.get("forbidden_statuses", []):
        if status == forbidden:
            problems.append("status %r is forbidden" % status)
    pattern = expected.get("steps_pattern")
    steps = output.get("steps", [])
    if pattern is not None:
        actual_pattern = [(s.get("phase"), s.get("operation"), s.get("state"))
                          for s in steps]
        wanted = [(s.get("phase"), s.get("operation"), s.get("state"))
                  for s in pattern]
        if actual_pattern != wanted:
            problems.append("step pattern mismatch: actual %r, expected %r"
                            % (actual_pattern, wanted))
    allowed = bundle_resource_labels(obj.get("bundle", {}))
    for step in steps:
        rid = step.get("resource_id")
        if rid is not None and allowed and rid not in allowed:
            problems.append("step cites resource %r outside the bundle "
                            "allowlist (invented id)" % rid)
    flags = set(output.get("ledger_flags", []))
    for required in expected.get("requires_ledger_flags", []):
        if required not in flags:
            problems.append("missing required ledger flag %s" % required)
    return {"adversarial_id": obj["adversarial_id"],
            "pass": not problems, "problems": problems}


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        digest.update(handle.read())
    return digest.hexdigest()


def freeze_check(directory, manifest_path):
    try:
        with open(manifest_path, encoding="utf-8") as handle:
            manifest = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        return ["cannot read manifest: %s" % exc]
    problems = []
    recorded = manifest.get("files", {})
    for name, digest in sorted(recorded.items()):
        path = os.path.join(directory, name)
        if not os.path.exists(path):
            problems.append("frozen file missing: %s" % name)
        elif sha256_file(path) != digest:
            problems.append("frozen file changed: %s (amend via AMENDMENTS.md)"
                            % name)
    for name in sorted(os.listdir(directory)):
        if name.endswith(".json") and name not in recorded:
            problems.append("unfrozen expectation file: %s" % name)
    return problems


def main(argv=None):
    parser = argparse.ArgumentParser(description="Unit 4 adversarial runner.")
    parser.add_argument("--dir", required=True,
                        help="directory of expectation JSON files")
    parser.add_argument("--engine-output", default=None,
                        help="JSON list of engine outputs for the bundles")
    parser.add_argument("--freeze-check", action="store_true")
    parser.add_argument("--manifest", default=None,
                        help="manifest path for --freeze-check")
    parser.add_argument("--out", default=None, help="JSON report path")
    args = parser.parse_args(argv)
    expectations, load_errors = load_expectations(args.dir)
    validation_errors = []
    for obj in expectations.values():
        validation_errors.extend(validate_expectation(obj))
    results = []
    if args.engine_output:
        try:
            with open(args.engine_output, encoding="utf-8") as handle:
                outputs = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            print("cannot read engine output: %s" % exc, file=sys.stderr)
            return 2
        by_id = {o.get("adversarial_id"): o for o in outputs
                 if isinstance(o, dict)}
        for adv_id in sorted(expectations):
            if adv_id not in by_id:
                results.append({"adversarial_id": adv_id, "pass": False,
                                "problems": ["no engine output (ungraded)"]})
            else:
                results.append(grade_case(expectations[adv_id], by_id[adv_id]))
    freeze_problems = []
    if args.freeze_check:
        if not args.manifest:
            print("--freeze-check needs --manifest", file=sys.stderr)
            return 2
        freeze_problems = freeze_check(args.dir, args.manifest)
    report = {
        "expectations": len(expectations),
        "load_errors": load_errors,
        "validation_errors": validation_errors,
        "freeze_problems": freeze_problems,
        "results": results,
        "graded_pass": sum(1 for r in results if r["pass"]),
        "graded_total": len(results),
    }
    failed = bool(load_errors or validation_errors or freeze_problems
                  or any(not r["pass"] for r in results))
    report["verdict"] = "FAIL" if failed else "PASS"
    print("adversarial suite: %s (expectations=%d, graded %d/%d pass)"
          % (report["verdict"], len(expectations), report["graded_pass"],
             report["graded_total"]))
    for error in load_errors + validation_errors + freeze_problems:
        print("  ! %s" % error)
    for result in results:
        print("  %s %s" % ("PASS" if result["pass"] else "FAIL",
                           result["adversarial_id"]))
        for problem in result["problems"]:
            print("      - %s" % problem)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, sort_keys=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
