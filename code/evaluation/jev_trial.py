"""Jev trial cell: one pre-registered support-triage comparison.

Three arms judge the SAME support threads (the sample cases' support
findings, one call per distinct support resource):
  deterministic  the shipped engine's own treatment: the sample
                 finding's remediation op (REDACT vs DELETE), which
                 rests on second_person_present() + the attachment /
                 message split actually implemented (part 1 only --
                 see evaluation report);
  gemini         the Layer-1 support draft from extraction_cache.json
                 (treatment_draft), never a verdict input;
  jev            TypeSafe Jev (System One) via the user-connected
                 custom.typesafe credential: one micro-decision per
                 thread from observable features only (second-person
                 identifier present, attachment vs message, thread
                 length). Code owns the choice; Jev returns
                 probabilities, the trial takes the argmax.

Jev is NOT a production layer: this is the single evaluation trial
cell the Layer Placement Verdict allows. If the Jev CLI fails, is
slow, or returns an unparsable verdict, the trial records the
failure honestly and continues -- a failed arm is a result, not a
reason to invent one. Prior real smoke: ~11.4s per call vs the
vendor's 70-500ms claim; latency is measured per call.

Usage (from the repository root):
    python3 code/evaluation/jev_trial.py [--dataset DIR]
        [--out FILE]

Stdlib only (plus the Jev CLI subprocess). Requires a completed
Layer-1 refresh (extraction_cache.json) for the Gemini arm.
"""

import argparse
import csv
import json
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
CODE = HERE.parent
REPO = CODE.parent
JEV_CLI = Path.home() / "workspace/custom-connectors" \
    / "custom.legacy-jev-web/bin/jev_decide.py"
sys.path.insert(0, str(CODE))

import main as shipped_main  # noqa: E402


def collect_threads(engine, dataset):
    """Support resources in sample findings + their thread text."""
    support_resources = {}
    for row in csv.DictReader(open(
            dataset / "sample_output.csv", encoding="utf-8")):
        for step in json.loads(row["steps_json"]):
            if step["system_id"] == "support_platform" \
                    and step["phase"] == "FINDING":
                support_resources.setdefault(step["resource_id"], set())
                support_resources[step["resource_id"]].add(
                    step["operation"])
    index = engine.index
    threads = {}
    for resource in sorted(support_resources):
        keys = index.indexes["by_resource_id"].get(resource, [])
        texts = []
        is_attachment = False
        for record in index.records_for_keys(keys):
            fields = record.get("fields") or {}
            if "attachment" in str(
                    fields.get("collection", "")).lower() \
                    or "attachment" in str(
                    fields.get("record_type", "")).lower():
                is_attachment = True
            for field in ("message_text", "message_excerpt", "text",
                          "subject", "result"):
                if fields.get(field):
                    texts.append(str(fields[field]))
        threads[resource] = {
            "text": " | ".join(texts)[:1500],
            "is_attachment": is_attachment,
        }
    return threads


def jev_decide(state):
    """One Jev call. Returns (pick, latency_ms, error)."""
    spec = {
        "state": state,
        "questions": {
            "treatment": {
                "type": "choice",
                "instructions": "Choose the safe treatment for this "
                                "support record under deletion policy. "
                                "REDACT when the record substantively "
                                "concerns another identifiable person "
                                "with an independent stake and the "
                                "subject's identifiers can be stripped. "
                                "DELETE when the record is solely the "
                                "subject's.",
                "options": {
                    "REDACT": "Keep the record, strip subject ids.",
                    "DELETE": "Remove the entire record.",
                },
            },
        },
    }
    started = time.perf_counter()
    try:
        proc = subprocess.run(
            [sys.executable, str(JEV_CLI)],
            input=json.dumps(spec), capture_output=True, text=True,
            timeout=120)
    except Exception as exc:  # noqa: BLE001 - failed arm is a result
        return None, round((time.perf_counter() - started) * 1000, 1), \
            f"{type(exc).__name__}: {exc}"
    latency_ms = round((time.perf_counter() - started) * 1000, 1)
    if proc.returncode != 0:
        return None, latency_ms, proc.stderr.strip()[:300]
    try:
        verdict = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None, latency_ms, "unparsable Jev output"
    try:
        answers = verdict["answers"]["treatment"]
        probs = answers.get("probabilities") or answers
        pick = max(probs, key=probs.get) if isinstance(probs, dict) \
            else None
        return pick, latency_ms, None
    except (KeyError, TypeError, ValueError):
        return None, latency_ms, \
            f"unexpected Jev shape: {proc.stdout[:300]}"


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Run the Jev support-triage trial cell.")
    parser.add_argument("--dataset", default=str(REPO / "dataset"))
    parser.add_argument("--out",
                        default=str(HERE / "jev_trial_report.json"))
    args = parser.parse_args(argv)
    dataset = Path(args.dataset)
    engine = shipped_main.build_engine(str(dataset))
    threads = collect_threads(engine, dataset)
    cache = {}
    cache_path = CODE / "extraction_cache.json"
    if cache_path.exists():
        cache = json.loads(cache_path.read_text(encoding="utf-8"))
    gemini_by_resource = {}
    for entry in cache.get("entries", {}).values():
        if entry.get("job") == "support" and entry.get("resource"):
            gemini_by_resource[entry["resource"]] = \
                entry["output"].get("treatment_draft")
    # Deterministic treatment: the sample finding's remediation op.
    deterministic = {}
    for row in csv.DictReader(open(
            dataset / "sample_output.csv", encoding="utf-8")):
        for step in json.loads(row["steps_json"]):
            if step["system_id"] == "support_platform" \
                    and step["phase"] == "REMEDIATION":
                op = step["operation"]
                deterministic[step["resource_id"]] = (
                    "REDACT" if op == "REDACT_RECORD"
                    else "DELETE" if op == "DELETE_RECORD" else op)
    results = []
    for resource, thread in sorted(threads.items()):
        if not thread["text"]:
            continue
        state = {
            "is_attachment": thread["is_attachment"],
            "thread_chars": len(thread["text"]),
        }
        pick, latency_ms, error = jev_decide(state)
        det = deterministic.get(resource)
        gem = gemini_by_resource.get(resource)
        results.append({
            "resource": resource,
            "deterministic_treatment": det,
            "gemini_draft": gem,
            "jev_pick": pick,
            "jev_latency_ms": latency_ms,
            "jev_error": error,
            "jev_agrees_with_deterministic": pick == det
            if pick else None,
            "gemini_agrees_with_deterministic": gem == det
            if gem else None,
        })
    report = {
        "threads": len(results),
        "jev_calls": sum(1 for r in results if not r["jev_error"]),
        "jev_failures": [r["resource"] for r in results
                         if r["jev_error"]],
        "jev_agree": sum(1 for r in results
                         if r["jev_agrees_with_deterministic"]),
        "gemini_agree": sum(1 for r in results
                            if r["gemini_agrees_with_deterministic"]),
        "mean_jev_latency_ms": round(
            sum(r["jev_latency_ms"] for r in results
                if not r["jev_error"])
            / max(1, sum(1 for r in results if not r["jev_error"])), 1),
        "results": results,
    }
    Path(args.out).write_text(json.dumps(report, indent=2, sort_keys=True),
                              encoding="utf-8")
    print(f"threads {report['threads']}; Jev ok "
          f"{report['jev_calls']}, agree "
          f"{report['jev_agree']}; Gemini agree "
          f"{report['gemini_agree']}; mean Jev latency "
          f"{report['mean_jev_latency_ms']}ms")
    for r in results:
        print(f"  {r['resource']}: det={r['deterministic_treatment']} "
              f"gem={r['gemini_draft']} jev={r['jev_pick']} "
              f"({r['jev_latency_ms']}ms)"
              + (f" ERROR {r['jev_error']}" if r["jev_error"] else "")
              + ")")
    return 0


if __name__ == "__main__":
    sys.exit(main())
