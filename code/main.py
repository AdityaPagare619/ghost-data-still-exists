"""Ghost Data Still Exists -- deletion-audit agent (CLI entry point).

Model describes, deterministic code decides: the verdict path is pure
symbolic computation (indexer + identity/intent + 7-gate rule engine)
over participant evidence at or before each case's audit_at. No model
call runs in this process; Layer-1 AI extraction lives in
extractor_ai.py and feeds a verified cache that main.py never needs
for verdicts.

Usage (from the repository root):
    python3 code/main.py                     # full 518-case run -> output.csv
    python3 code/main.py --samples          # 32-sample validation gate
    python3 code/main.py --demo             # live interactive demo server
    python3 code/main.py --dataset DIR --out FILE

Dataset and output paths are runtime parameters, never baked in.
Stdlib only.
"""

import argparse
import csv
import json
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
sys.path.insert(0, str(HERE))

import indexer as indexer_mod
from identity_intent import IdentityGraph, IntentGate
from rules import RuleBook
from engine import Engine


def build_engine(dataset_dir, index_dir=None):
    """Build (or reuse) the evidence index and wire the engine."""
    dataset_dir = Path(dataset_dir)
    if index_dir is None:
        tmp = tempfile.TemporaryDirectory(prefix="ghost-index-")
        index_path = Path(tmp.name)
        # Keep the temp dir alive for the engine's lifetime.
        build_engine._tmp = tmp
    else:
        index_path = Path(index_dir)
        index_path.mkdir(parents=True, exist_ok=True)
    if not (index_path / "records.jsonl").exists():
        indexer_mod.build_index(str(dataset_dir), str(index_path),
                                module_dir=str(HERE))
    index = indexer_mod.Index(str(index_path))
    graph = IdentityGraph.from_csvs(
        str(dataset_dir / "user_identities.csv"),
        str(dataset_dir / "user_audit_log.csv"))
    gate = IntentGate()
    rules = RuleBook.from_csv(str(dataset_dir / "deletion_rules.csv"))
    return Engine(index, rules, graph, gate)


def adjudicate_requests(engine, requests_path):
    """Return {case_id: (status, steps)} for every request row."""
    results = {}
    with open(requests_path, encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            outcome = engine.adjudicate(
                row["email"], row["request_text"], row["audit_at"],
                row.get("requested_at"))
            results[row["case_id"]] = (outcome["status"], outcome["steps"])
    return results


def write_output(results, out_path):
    with open(out_path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["case_id", "deletion_status", "steps_json"])
        for case_id in sorted(results):
            status, steps = results[case_id]
            writer.writerow([case_id, status, json.dumps(steps)])


def run_samples(engine, dataset_dir):
    """32-sample validation gate. Prints the honest score, including
    every verification omission and extra; exits non-zero only on a
    status error, a finding/remediation diff, or an extra step.
    Omissions are disclosed, never hidden and never invented."""
    dataset_dir = Path(dataset_dir)
    requests = {row["case_id"]: row for row in csv.DictReader(
        open(dataset_dir / "sample_deletion_requests.csv",
             encoding="utf-8"))}
    answers = {row["case_id"]: (row["deletion_status"],
                                json.loads(row["steps_json"]))
               for row in csv.DictReader(
                   open(dataset_dir / "sample_output.csv",
                        encoding="utf-8"))}
    status_ok = 0
    finding_diffs = []
    remediation_diffs = []
    omissions = []
    extras = []
    total_expected = 0
    total_got = 0
    for case_id in sorted(requests):
        request = requests[case_id]
        outcome = engine.adjudicate(request["email"],
                                    request["request_text"],
                                    request["audit_at"],
                                    request.get("requested_at"))
        expected_status, expected_steps = answers[case_id]
        got_steps = outcome["steps"]
        total_expected += len(expected_steps)
        total_got += len(got_steps)
        if outcome["status"] == expected_status:
            status_ok += 1
        else:
            print(f"STATUS DIFF {case_id}: got {outcome['status']}, "
                  f"expected {expected_status}")

        def tuples(steps):
            return [(s["step_no"], s["phase"], s["system_id"],
                     s["resource_id"], s["operation"], s["state"],
                     s["evidence_id"]) for s in steps]

        for phase, diff_list in (("FINDING", finding_diffs),
                                 ("REMEDIATION", remediation_diffs)):
            exp = [s for s in expected_steps if s["phase"] == phase]
            got = [s for s in got_steps if s["phase"] == phase]
            if tuples(exp) != tuples(got):
                diff_list.append(case_id)
        exp_ver = {(s["system_id"], s["resource_id"], s["operation"])
                   for s in expected_steps if s["phase"] == "VERIFICATION"}
        got_ver = {(s["system_id"], s["resource_id"], s["operation"])
                   for s in got_steps if s["phase"] == "VERIFICATION"}
        for key in sorted(exp_ver - got_ver):
            omissions.append((case_id, key))
        for key in sorted(got_ver - exp_ver):
            extras.append((case_id, key))
    print(f"status: {status_ok}/32")
    print(f"steps: {total_got}/{total_expected} emitted "
          f"({len(omissions)} omitted, {len(extras)} extra)")
    print(f"finding diffs: {finding_diffs or 'none'}")
    print(f"remediation diffs: {remediation_diffs or 'none'}")
    if omissions:
        print("omitted verification slots (disclosed, not invented):")
        for case_id, key in omissions:
            print(f"  {case_id} {key[0]} {key[1]} {key[2]}")
    if extras:
        print("EXTRA verification steps (must be zero):")
        for case_id, key in extras:
            print(f"  {case_id} {key[0]} {key[1]} {key[2]}")
    failed = (status_ok != 32 or finding_diffs or remediation_diffs
              or extras)
    print("GATE:", "FAIL" if failed else "PASS (with disclosed omissions)"
          if omissions else "PASS (exact)")
    return 1 if failed else 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Ghost Data deletion-audit agent.")
    parser.add_argument("--dataset", default=str(REPO_ROOT / "dataset"),
                        help="Dataset directory (default: repo dataset/).")
    parser.add_argument("--requests",
                        help="Requests CSV (default: dataset/deletion_requests.csv).")
    parser.add_argument("--out", default=str(REPO_ROOT / "output.csv"),
                        help="Output CSV path (default: repo root output.csv).")
    parser.add_argument("--index-dir",
                        help="Reuse a prebuilt index directory.")
    parser.add_argument("--samples", action="store_true",
                        help="Run the 32-sample validation gate.")
    parser.add_argument("--demo", action="store_true",
                        help="Launch the live interactive demo server.")
    args = parser.parse_args(argv)
    if args.demo:
        import demo_server
        return demo_server.serve(Path(args.dataset))
    engine = build_engine(args.dataset, args.index_dir)
    if args.samples:
        return run_samples(engine, args.dataset)
    requests = args.requests or str(Path(args.dataset)
                                    / "deletion_requests.csv")
    results = adjudicate_requests(engine, requests)
    write_output(results, args.out)
    from collections import Counter
    counts = Counter(status for status, _ in results.values())
    print(f"wrote {args.out}: {len(results)} rows "
          f"({dict(sorted(counts.items()))})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
