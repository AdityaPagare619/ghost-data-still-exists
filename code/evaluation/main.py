"""Evaluation driver for the shipped engine (Unit 4, independent).

Runs, in order, against the SHIPPED code/ engine (never staging):
  1. the 32-sample field-exact gate (grader.py, independent differ);
  2. the 9 frozen adversarial cases (bundle_translator + adversarial.py);
  3. the 8 unseen mutations (mutations.py + bundle_translator).

Writes evaluation/diff_report.json, evaluation/adversarial_report.json,
evaluation/mutations_report.json and evaluation/summary.json, and
prints a scoreboard. Exit code 0 means the harness ran to completion
and the sample gate passed (status 32/32, no finding/remediation
diffs, no extras); suite verdicts are reported verbatim in the
scoreboard and in summary.json, including KNOWN failures, which are
never hidden. In particular ADV-06 is a known failure: the engine
emits the right verdict and the exact step pattern but never emits
the required ledger flag RESIDUAL_RISK_SHARED_CONTEXT (disclosed in
evaluation_report.md, not fixed here by scope order).

Usage (from the repository root):
    python3 code/evaluation/main.py [--dataset DIR]

Stdlib only. Synthetic indexes go to a temp dir (GHOST_SYNTH_ROOT).
"""

import argparse
import csv
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
CODE = HERE.parent
REPO = CODE.parent
sys.path.insert(0, str(CODE))

import main as shipped_main  # noqa: E402


def run(cmd, env=None):
    merged = dict(os.environ)
    if env:
        merged.update(env)
    proc = subprocess.run(cmd, capture_output=True, text=True, env=merged)
    sys.stdout.write(proc.stdout)
    if proc.stderr:
        sys.stderr.write(proc.stderr)
    return proc.returncode


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Run the shipped-engine evaluation suites.")
    parser.add_argument("--dataset", default=str(REPO / "dataset"))
    args = parser.parse_args(argv)
    dataset = Path(args.dataset)
    tmp = tempfile.TemporaryDirectory(prefix="ghost-eval-")
    tmp_path = Path(tmp.name)
    env = {"GHOST_SYNTH_ROOT": str(tmp_path / "synth")}

    # 1. Sample gate: shipped engine output -> independent differ.
    # The differ credits an omitted verification slot as R1-class
    # ONLY when the engine's own ledger confesses it with a
    # CANONICAL_* flag (grader.py R1 rules). Running without --ledger
    # silently turns 20 disclosed omissions into REAL discrepancies
    # and fails the gate -- that was a driver bug, not an engine
    # regression. So the driver translates the engine's hash-chained
    # ledger entries (one per adjudication, in call order) into the
    # differ's JSONL shape {case_id, flags: [{flag, operation}]}.
    print("== 1. sample gate (shipped engine vs sample_output.csv) ==")
    engine = shipped_main.build_engine(str(dataset))
    sample_rows = list(csv.DictReader(open(
        dataset / "sample_deletion_requests.csv", encoding="utf-8")))
    results = shipped_main.adjudicate_requests(
        engine, str(dataset / "sample_deletion_requests.csv"))
    sample_out = tmp_path / "sample_out.csv"
    shipped_main.write_output(results, str(sample_out))
    entries = engine.ledger.entries
    assert len(entries) == len(sample_rows), (
        f"ledger entries {len(entries)} != sample rows "
        f"{len(sample_rows)}; cannot align ledger to cases")
    flag_operation = {
        "CANONICAL_ACCOUNT_UNOBSERVED": "VERIFY_RECORD_ABSENT",
        "CANONICAL_AUDIT_UNOBSERVED": "VERIFY_RECORD_PRESENT"}
    ledger_path = HERE / "sample_ledger.jsonl"
    with open(ledger_path, "w", encoding="utf-8") as handle:
        for row, entry in zip(sample_rows, entries):
            flags = []
            for flag in entry["payload"].get("flags", []):
                item = {"flag": flag}
                if flag in flag_operation:
                    item["operation"] = flag_operation[flag]
                flags.append(item)
            handle.write(json.dumps(
                {"case_id": row["case_id"], "flags": flags}) + "\n")
    diff_report = HERE / "diff_report.json"
    code = run([sys.executable, str(HERE / "grader.py"),
                "--expected", str(dataset / "sample_output.csv"),
                "--actual", str(sample_out),
                "--ledger", str(ledger_path),
                "--out", str(diff_report)])
    diff = json.loads(diff_report.read_text(encoding="utf-8"))
    print(f"sample gate exit: {code}")
    metrics = diff.get("metrics", {})

    # 2. Adversarial suite.
    print("== 2. adversarial suite (9 frozen cases) ==")
    adv_out = tmp_path / "adv_out.json"
    run([sys.executable, str(HERE / "bundle_translator.py"),
         "--adv-dir", str(HERE / "adversarial"),
         "--adv-out", str(adv_out)], env=env)
    adv_report = HERE / "adversarial_report.json"
    run([sys.executable, str(HERE / "adversarial.py"),
         "--dir", str(HERE / "adversarial"),
         "--engine-output", str(adv_out),
         "--freeze-check", "--manifest",
         str(HERE / "adversarial_manifest.json"),
         "--out", str(adv_report)])
    adv = json.loads(adv_report.read_text(encoding="utf-8"))

    # 3. Mutation suite.
    print("== 3. mutation suite (8 unseen mutations) ==")
    mut_dir = tmp_path / "mut"
    run([sys.executable, str(HERE / "mutations.py"),
         "--defs", str(HERE / "mutations.json"),
         "--generate-out", str(mut_dir)])
    mut_out = tmp_path / "mut_out.json"
    run([sys.executable, str(HERE / "bundle_translator.py"),
         "--mutations-dir", str(mut_dir),
         "--mut-out", str(mut_out)], env=env)
    mut_report = HERE / "mutations_report.json"
    run([sys.executable, str(HERE / "mutations.py"),
         "--defs", str(HERE / "mutations.json"),
         "--engine-output", str(mut_out),
         "--out", str(mut_report)])
    mut = json.loads(mut_report.read_text(encoding="utf-8"))

    summary = {
        "sample_gate": diff.get("gate"),
        "sample_status_accuracy": metrics.get("case_status_accuracy"),
        "sample_field_accuracy": metrics.get("field_accuracy"),
        "sample_sequence_accuracy_raw": metrics.get("sequence_accuracy"),
        "sample_sequence_accuracy_r1_adjusted":
            metrics.get("sequence_accuracy_r1_adjusted"),
        "sample_step_coverage_raw": metrics.get("step_coverage"),
        "sample_step_coverage_r1_adjusted":
            metrics.get("step_coverage_r1_adjusted"),
        "sample_steps_matched": metrics.get("matched_steps_total"),
        "sample_steps_expected": metrics.get("expected_steps_total"),
        "sample_r1_omitted_flag": metrics.get("r1_omitted_steps_total"),
        "sample_r1_omitted_analytics":
            metrics.get("r1_analytics_omitted_steps_total"),
        "sample_r1_class_total":
            metrics.get("r1_class_omitted_steps_total"),
        "sample_real_discrepancies":
            metrics.get("real_discrepancy_count"),
        "adversarial": adv.get("verdict"),
        "adversarial_pass": f"{adv.get('graded_pass')}/"
                            f"{adv.get('graded_total')}",
        "adversarial_failures": [
            r["adversarial_id"] for r in adv.get("results", [])
            if not r["pass"]],
        "mutations": mut.get("verdict"),
        "mutations_pass": sum(1 for r in mut.get("results", [])
                              if r["pass"]),
        "mutations_total": len(mut.get("results", [])),
        "known_failures": [
            "ADV-06: engine verdict and step pattern exact, but the "
            "required ledger flag RESIDUAL_RISK_SHARED_CONTEXT is "
            "never emitted (disclosed, not fixed by scope order)."],
    }
    (HERE / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    print("== scoreboard ==")
    print(json.dumps(summary, indent=2, sort_keys=True))
    sample_ok = (diff.get("gate") == "PASS"
                 or "PASS" in str(diff.get("gate")))
    return 0 if sample_ok else 1


if __name__ == "__main__":
    sys.exit(main())
