"""Submission packaging auditor (Chair 13 design, now observable code).

Verifies a built code.zip against the repo contract (AGENTS.md §6.9):
  - required files present (README.md, code/main.py, both evaluation
    reports);
  - banned entries absent: dataset/, __pycache__, .venv/venv/,
    node_modules/, .git/, nested archives (.zip/.tar/.gz/.7z);
  - no secret-looking values in text entries (API-key-shaped strings);
  - root output.csv structural check (518 rows + header, sorted,
    valid JSON) when --output is passed.

The auditor reads the zip, never the live tree, so it audits exactly
what would be submitted. Exit 0 only when every check passes.

Usage (from the repository root):
    python3 code/evaluation/audit_package.py --zip code.zip
        [--output output.csv]

Stdlib only.
"""

import argparse
import csv
import json
import re
import sys
import zipfile
from pathlib import Path

REQUIRED = ["README.md", "code/main.py",
            "code/evaluation/evaluation_report.md",
            "code/evaluation/usage_report.md"]
BANNED_PREFIXES = ["dataset/", ".git/"]
BANNED_SEGMENTS = ["__pycache__", ".venv", "venv", "node_modules",
                   ".DS_Store"]
BANNED_SUFFIXES = [".zip", ".tar", ".gz", ".7z", ".rar"]
SECRET_PATTERNS = [
    re.compile(r"AIza[0-9A-Za-z_-]{20,}"),
    re.compile(r"sk-[A-Za-z0-9]{16,}"),
    re.compile(r"hsurr:[A-Za-z0-9_-]+"),
    re.compile(r"(?i)api[_-]?key\s*=\s*['\"][^'\"]{8,}"),
]


def audit_zip(zip_path):
    failures = []
    with zipfile.ZipFile(zip_path) as zf:
        names = zf.namelist()
        for required in REQUIRED:
            if required not in names:
                failures.append(f"missing required file: {required}")
        for name in names:
            lowered = name.lower()
            parts = [p.lower() for p in Path(name).parts]
            if any(lowered.startswith(p) for p in BANNED_PREFIXES):
                failures.append(f"banned prefix: {name}")
            if any(seg.lower() in parts for seg in BANNED_SEGMENTS):
                failures.append(f"banned segment: {name}")
            if any(lowered.endswith(s) for s in BANNED_SUFFIXES):
                failures.append(f"nested archive: {name}")
            # Chair 13: a substring deny-list lets data copies slip
            # through (prebuilt index, cache dumps). Flag index-shaped
            # members outright; the only data members that ship are
            # the transcriptions sidecar and the verified cache.
            if lowered.endswith(".jsonl") or "index" in parts:
                failures.append(f"index-shaped member: {name}")
        if "README.md" in names and "code/README.md" in names:
            failures.append("duplicate README: root README.md is "
                            "authoritative; remove code/README.md")
        for name in names:
            if name.endswith("/"):
                continue
            try:
                text = zf.read(name).decode("utf-8", errors="ignore")
            except Exception:  # noqa: BLE001 - binary entries skipped
                continue
            for pattern in SECRET_PATTERNS:
                if pattern.search(text):
                    failures.append(
                        f"secret-shaped value in {name} "
                        f"(pattern {pattern.pattern[:24]}...)")
                    break
    return names, failures


def audit_output(output_path):
    failures = []
    with open(output_path, encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != ["case_id", "deletion_status",
                                 "steps_json"]:
            failures.append(f"bad header: {reader.fieldnames}")
            return failures
        rows = list(reader)
    if len(rows) != 518:
        failures.append(f"row count {len(rows)} != 518")
    case_ids = [r["case_id"] for r in rows]
    if case_ids != sorted(case_ids):
        failures.append("rows not sorted by case_id")
    for row in rows:
        if row["deletion_status"] not in (
                "COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"):
            failures.append(f"{row['case_id']}: bad status "
                            f"{row['deletion_status']}")
            continue
        try:
            steps = json.loads(row["steps_json"])
        except json.JSONDecodeError:
            failures.append(f"{row['case_id']}: steps_json not valid JSON")
            continue
        if row["deletion_status"] == "NOT_APPLICABLE" and steps != []:
            failures.append(f"{row['case_id']}: NOT_APPLICABLE with "
                            f"non-empty steps")
        if [s.get("step_no") for s in steps] != list(
                range(1, len(steps) + 1)):
            failures.append(f"{row['case_id']}: step_no not consecutive "
                            f"from 1")
        for step in steps:
            if set(step) != {"step_no", "phase", "system_id",
                             "resource_id", "operation", "state",
                             "evidence_id"}:
                failures.append(f"{row['case_id']}: step fields "
                                f"not exactly the contract set")
                break
    return failures


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Audit a submission code.zip (+ optional output.csv).")
    parser.add_argument("--zip", required=True)
    parser.add_argument("--output", default=None)
    args = parser.parse_args(argv)
    names, failures = audit_zip(args.zip)
    print(f"zip entries: {len(names)}")
    if args.output:
        failures.extend(audit_output(args.output))
    if failures:
        print("PACKAGING AUDIT: FAIL")
        for failure in failures:
            print(f"  ! {failure}")
        return 1
    print("PACKAGING AUDIT: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
