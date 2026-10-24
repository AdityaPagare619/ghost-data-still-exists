"""Re-signup gate probe (Chair 07 design, now observable code).

For every case the engine calls COMPLETE, this probe re-checks the
surfaces a signup flow would consult, using the engine's OWN lane
classification (never a second verdict):

  profile   account_service USER_PROFILE / SECONDARY_IDENTIFIER lanes
  search    search_service lanes
  tombstone lanes whose resource starts with tombstone_
  replica   detector hits REPLICA_ONLY_RECORD / REPLICA_DIVERGENCE

A surface is DIRTY when any of its lanes is state_kind VIOLATING --
including VIOLATING lanes whose finding_op is None, which produce no
finding and therefore cannot flip the verdict on their own. That is
the probe's real value: it catches the class of residual key the
verdict path cannot see.

INCOMPLETE and NOT_APPLICABLE cases are reported as not gated (the
gate only matters for COMPLETE). The probe never changes a verdict;
it reports, and a DIRTY surface on a COMPLETE case is a bug report,
not a silent override.

Usage (from the repository root):
    python3 code/evaluation/resignup_probe.py [--dataset DIR]
        [--cases samples|main|all] [--out FILE]

Stdlib only.
"""

import argparse
import csv
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CODE = HERE.parent
REPO = CODE.parent
sys.path.insert(0, str(CODE))

import main as shipped_main  # noqa: E402
from engine import _subject_dict  # noqa: E402


def _surface_flags(engine, row, outcome):
    """Return {surface: (dirty, [lane resources])} for one case."""
    resolution = engine.graph.resolve(row["email"])
    res = resolution if isinstance(resolution, dict) \
        else resolution.to_dict()
    if not res.get("user_id"):
        return {}
    subject = _subject_dict(engine.graph.subject(res["user_id"]))
    lanes, _, _ = engine.build_lanes(subject, row["audit_at"])
    lanes = engine._classify_lanes(lanes, subject, row["audit_at"])
    groups = {"profile": [], "search": [], "tombstone": []}
    for lane in lanes:
        verdict = lane["verdict"]
        if verdict["state_kind"] != "VIOLATING":
            continue
        resource = lane["resource"]
        system = lane["logical_system"]
        category = verdict["category"]
        if system == "account_service" and category in (
                "USER_PROFILE", "SECONDARY_IDENTIFIER"):
            groups["profile"].append(resource)
        elif system == "search_service":
            groups["search"].append(resource)
        if resource.startswith("tombstone_"):
            groups["tombstone"].append(resource)
    detectors = {h.get("signal") for h in outcome["detector_hits"]}
    replica = sorted(
        r for r in
        [h.get("resource") for h in outcome["detector_hits"]
         if h.get("signal") in ("REPLICA_ONLY_RECORD", "REPLICA_DIVERGENCE")
         and h.get("resource")] or [])
    if detectors & {"REPLICA_ONLY_RECORD", "REPLICA_DIVERGENCE"} \
            and not replica:
        replica = ["(replica signal, resource unnamed)"]
    groups["replica"] = replica
    return {name: (bool(resources), sorted(set(resources)))
            for name, resources in groups.items()}


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Probe re-signup surfaces on COMPLETE cases.")
    parser.add_argument("--dataset", default=str(REPO / "dataset"))
    parser.add_argument("--cases", default="all",
                        choices=("samples", "main", "all"))
    parser.add_argument("--out",
                        default=str(HERE / "resignup_report.json"))
    args = parser.parse_args(argv)
    dataset = Path(args.dataset)
    engine = shipped_main.build_engine(str(dataset))
    rows = {}
    if args.cases in ("samples", "all"):
        for row in csv.DictReader(open(
                dataset / "sample_deletion_requests.csv",
                encoding="utf-8")):
            rows[row["case_id"]] = row
    if args.cases in ("main", "all"):
        for row in csv.DictReader(open(
                dataset / "deletion_requests.csv", encoding="utf-8")):
            rows[row["case_id"]] = row
    report = {"cases_checked": 0, "complete_checked": 0,
              "complete_clean": 0, "complete_dirty": [],
              "non_complete": 0}
    for case_id in sorted(rows):
        row = rows[case_id]
        outcome = engine.adjudicate(
            row["email"], row["request_text"], row["audit_at"],
            row.get("requested_at"))
        report["cases_checked"] += 1
        if outcome["status"] != "COMPLETE":
            report["non_complete"] += 1
            continue
        report["complete_checked"] += 1
        surfaces = _surface_flags(engine, row, outcome)
        dirty = {name: res for name, (is_dirty, res)
                 in surfaces.items() if is_dirty}
        if dirty:
            report["complete_dirty"].append(
                {"case_id": case_id, "dirty_surfaces": dirty})
        else:
            report["complete_clean"] += 1
    Path(args.out).write_text(json.dumps(report, indent=2, sort_keys=True),
                              encoding="utf-8")
    print(f"checked {report['cases_checked']} cases; "
          f"COMPLETE {report['complete_checked']} "
          f"(clean {report['complete_clean']}, "
          f"dirty {len(report['complete_dirty'])})")
    for entry in report["complete_dirty"]:
        print(f"  DIRTY {entry['case_id']}: {entry['dirty_surfaces']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
