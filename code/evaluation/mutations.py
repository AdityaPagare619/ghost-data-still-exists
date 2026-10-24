#!/usr/bin/env python3
"""Unit 4 — Mutation suite (the GENERALIZATION gate).

The 32 samples are the regression gate. This suite is the
generalization gate: it proves detectors catch FAILURE CLASSES in
cases the system has never seen. Each mutation is pre-registered in
mutations.json with its expected verdict change, written before any
engine ran it. A detector that passes the samples but fails its
mutation fails the build — that is overfitting, caught by
construction (Master Plan §3 step 5).

TWO PARTS, kept separate on purpose:
  (1) GENERATOR: pure stdlib functions that transform a synthetic base
      bundle into a mutated bundle. The generator produces INPUTS only;
      it never computes a verdict. Runnable now: it proves every
      mutated bundle is well-formed.
  (2) DELTA RUNNER: grades engine outputs for base + mutated bundles.
      Engine output format: JSON list of {"mutation_id",
      "base_status", "mutated_status", "ledger_flags": [...],
      "invalidated": bool, "crashed": bool}. A crash on any mutation
      is a FAIL of the unknown-case protocol (fail closed, never crash),
      not an edge case.

EXPECTED OUTCOME FORMS (mutations.json "expected"):
  {"status": "COMPLETE"} — mutated verdict must equal this exactly.
  {"status_change": "COMPLETE->INCOMPLETE"} — base must be COMPLETE
      and mutated must be INCOMPLETE (the delta, not just the endpoint).
  {"status": "UNCHANGED"} — mutated verdict must equal base verdict.
  {"not_complete_or_invalidated": true} — for shared-control failure:
      pass iff (invalidated is true OR mutated status is not COMPLETE)
      AND every requires_ledger_flags flag is present. A draft silently
      re-emitted as COMPLETE fails.

USAGE
  python3 mutations.py --defs mutations.json --generate-out dir/
      (writes base + mutated bundles, validates structure)
  python3 mutations.py --defs mutations.json --engine-output out.json
  Exit 0 = all pass; 1 = any fail; 2 = usage/input error.
"""

import argparse
import copy
import json
import os
import sys

STATUSES = ("COMPLETE", "INCOMPLETE", "NOT_APPLICABLE")


def base_complete_bundle():
    """A clean synthetic COMPLETE bundle (fictional identifiers)."""
    return {
        "request": {"language": "en", "intent": "deletion"},
        "subject": {"identifiers": ["synth_base@example.test"],
                    "historical": []},
        "records": [
            {"category": "USER_PROFILE", "resource_label": "account_base",
             "state": "ABSENT"},
            {"category": "ACCOUNT_TOMBSTONE",
             "resource_label": "tombstone_base",
             "fields_present": ["user_id"],
             "fields_null": ["name", "email", "phone", "email_hash"],
             "status_field": "DELETED"},
            {"category": "SECURITY_AUDIT_LOG",
             "resource_label": "audit_base", "state": "PRESENT",
             "within_retention": True,
             "fields_present": ["resource_id", "user_id", "event_code",
                                "time", "retention_until"]},
        ],
        "flows": [{"resource_label": "flow_base", "enabled": False,
                   "mode": "continuous_sync"}],
        "backups": [{"resource_label": "backup_base",
                     "restore_allowed": False, "state_snapshot": True}],
        "controls": {"restore_filter": "healthy", "signup_gate": "healthy"},
    }


def _find(bundle, label):
    for group in ("records", "flows", "backups"):
        for item in bundle.get(group, []):
            if item.get("resource_label") == label:
                return item
    return None


def mutate_casing_flip(bundle):
    out = copy.deepcopy(bundle)
    out["subject"]["identifiers"] = [
        ident.upper() for ident in out["subject"]["identifiers"]]
    return out


def mutate_flow_arming(bundle):
    out = copy.deepcopy(bundle)
    flow = _find(out, "flow_base")
    flow["enabled"] = True
    flow["last_run"] = "success"
    return out


def mutate_tombstone_dirtying(bundle):
    out = copy.deepcopy(bundle)
    tomb = _find(out, "tombstone_base")
    tomb["fields_null"] = [f for f in tomb["fields_null"]
                           if f != "email_hash"]
    tomb["fields_present"] = sorted(set(tomb["fields_present"])
                                    | {"email_hash"})
    return out


def mutate_replica_row_injection(bundle):
    out = copy.deepcopy(bundle)
    out["records"].append(
        {"category": "USER_PROFILE", "resource_label": "account_replica_new",
         "replica": "third_replica_never_seen", "state": "PRESENT"})
    return out


def mutate_language_swap(bundle):
    out = copy.deepcopy(bundle)
    out["request"] = {"language": "es", "intent": "deletion"}
    return out


def mutate_novel_field_injection(bundle):
    out = copy.deepcopy(bundle)
    tomb = _find(out, "tombstone_base")
    tomb["fields_present"] = sorted(set(tomb["fields_present"])
                                    | {"contact_hint"})
    tomb["fields_null"] = [f for f in tomb["fields_null"]
                           if f != "contact_hint"]
    tomb["novel_field_carries_identifier"] = True
    return out


def mutate_shared_control_failure(bundle):
    out = copy.deepcopy(bundle)
    out["controls"]["restore_filter"] = "disabled_globally"
    for backup in out["backups"]:
        backup["restore_allowed"] = True
    return out


def mutate_audit_expiry(bundle):
    out = copy.deepcopy(bundle)
    audit = _find(out, "audit_base")
    audit["within_retention"] = False
    audit["fields_present"] = sorted(set(audit["fields_present"])
                                     | {"email"})
    return out


GENERATORS = {
    "casing_flip": mutate_casing_flip,
    "flow_arming": mutate_flow_arming,
    "tombstone_dirtying": mutate_tombstone_dirtying,
    "replica_row_injection": mutate_replica_row_injection,
    "language_swap": mutate_language_swap,
    "novel_field_injection": mutate_novel_field_injection,
    "shared_control_failure": mutate_shared_control_failure,
    "audit_expiry": mutate_audit_expiry,
}


def validate_bundle(bundle):
    """Structure-only sanity: every record/flow/backup carries a label
    and a category/state the suite can address. NOT a verdict engine."""
    errors = []
    for group in ("records", "flows", "backups"):
        for item in bundle.get(group, []):
            if not item.get("resource_label"):
                errors.append("%s entry without resource_label: %r"
                              % (group, item))
    return errors


def load_defs(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def grade_mutation(defn, output):
    problems = []
    if output.get("crashed"):
        return {"mutation_id": defn["mutation_id"], "pass": False,
                "problems": ["engine crashed on mutated bundle "
                             "(unknown-case protocol failure)"]}
    base_status = output.get("base_status")
    mutated_status = output.get("mutated_status")
    if base_status not in STATUSES or mutated_status not in STATUSES:
        # INVALIDATED-style outputs carry invalidated=true instead of a
        # mutated status; anything else with a bad status is a fail.
        if not output.get("invalidated"):
            return {"mutation_id": defn["mutation_id"], "pass": False,
                    "problems": ["illegal status in output: base=%r "
                                 "mutated=%r" % (base_status, mutated_status)]}
    expected = defn["expected"]
    if "status" in expected and expected["status"] != "UNCHANGED":
        if mutated_status != expected["status"]:
            problems.append("mutated status %r, expected %r"
                            % (mutated_status, expected["status"]))
    if expected.get("status") == "UNCHANGED" \
            and mutated_status != base_status:
        problems.append("status changed %r -> %r, expected UNCHANGED"
                        % (base_status, mutated_status))
    if "status_change" in expected:
        want_base, want_mutated = expected["status_change"].split("->")
        if base_status != want_base or mutated_status != want_mutated:
            problems.append("delta %r -> %r, expected %s"
                            % (base_status, mutated_status,
                               expected["status_change"]))
    if expected.get("not_complete_or_invalidated"):
        if not output.get("invalidated") and mutated_status == "COMPLETE":
            problems.append("shared-control failure silently re-emitted "
                            "as COMPLETE (draft must be invalidated)")
    flags = set(output.get("ledger_flags", []))
    for required in defn.get("requires_ledger_flags", []):
        if required not in flags:
            problems.append("missing required ledger flag %s" % required)
    return {"mutation_id": defn["mutation_id"], "pass": not problems,
            "problems": problems}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Unit 4 mutation suite.")
    parser.add_argument("--defs", required=True,
                        help="mutations.json definitions file")
    parser.add_argument("--generate-out", default=None,
                        help="write base + mutated bundles here")
    parser.add_argument("--engine-output", default=None,
                        help="JSON list of engine mutation outputs")
    parser.add_argument("--out", default=None, help="JSON report path")
    args = parser.parse_args(argv)
    try:
        defs = load_defs(args.defs)
    except (OSError, json.JSONDecodeError) as exc:
        print("cannot read defs: %s" % exc, file=sys.stderr)
        return 2
    mutations = defs.get("mutations", [])
    errors = []
    for defn in mutations:
        if defn.get("generator") not in GENERATORS:
            errors.append("%s: unknown generator %r"
                          % (defn.get("mutation_id"), defn.get("generator")))
    generated = {}
    if args.generate_out and not errors:
        os.makedirs(args.generate_out, exist_ok=True)
        base = base_complete_bundle()
        errors.extend("base bundle: %s" % e for e in validate_bundle(base))
        with open(os.path.join(args.generate_out, "base.json"),
                  "w", encoding="utf-8") as handle:
            json.dump(base, handle, indent=2, sort_keys=True)
        for defn in mutations:
            mutated = GENERATORS[defn["generator"]](base)
            bundle_errors = validate_bundle(mutated)
            errors.extend("%s: %s" % (defn["mutation_id"], e)
                          for e in bundle_errors)
            generated[defn["mutation_id"]] = mutated
            with open(os.path.join(args.generate_out,
                                   defn["mutation_id"] + ".json"),
                      "w", encoding="utf-8") as handle:
                json.dump(mutated, handle, indent=2, sort_keys=True)
    results = []
    if args.engine_output:
        try:
            with open(args.engine_output, encoding="utf-8") as handle:
                outputs = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            print("cannot read engine output: %s" % exc, file=sys.stderr)
            return 2
        by_id = {o.get("mutation_id"): o for o in outputs
                 if isinstance(o, dict)}
        for defn in mutations:
            mid = defn["mutation_id"]
            if mid not in by_id:
                results.append({"mutation_id": mid, "pass": False,
                                "problems": ["no engine output (ungraded)"]})
            else:
                results.append(grade_mutation(defn, by_id[mid]))
    failed = bool(errors or any(not r["pass"] for r in results))
    print("mutation suite: %s (definitions=%d, generated=%d, graded %d/%d)"
          % ("FAIL" if failed else "PASS", len(mutations), len(generated),
             sum(1 for r in results if r["pass"]), len(results)))
    for error in errors:
        print("  ! %s" % error)
    for result in results:
        print("  %s %s" % ("PASS" if result["pass"] else "FAIL",
                           result["mutation_id"]))
        for problem in result["problems"]:
            print("      - %s" % problem)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            json.dump({"errors": errors, "results": results,
                       "verdict": "FAIL" if failed else "PASS"},
                      handle, indent=2, sort_keys=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
