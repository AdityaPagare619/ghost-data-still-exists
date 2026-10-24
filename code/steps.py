"""Step builder, citation resolver, sorter, causal narrative (Unit 3).

Report Order (steps_json) follows the sorting formula: phase rank,
then operation rank, then system_id, then resource_id, all ascending
with string-lexicographic order for identifiers. Remediation steps and
post-remediation verification steps carry an empty citation by
contract (they describe future work). Finding steps and COMPLETE
verification steps cite the record the citation resolver selects.

R1-FINAL (binding): a verification step is emitted ONLY for an
OBSERVED, identifier-joined canonical id at or before the audit
cutoff. Unobserved slots are omitted and flagged, never invented --
not by time proximity, file proximity, or numbering patterns. Status
never depends on verification steps.
"""

from classify import choose_citation
from rules import (
    FINDING_TO_REMEDIATION, REMEDIATION_TO_VERIFICATION,
    ANONYMIZE_CATEGORIES, operation_rank, PHASE_RANK,
)

# Logical-system aliases: physical service names in evidence mapped to
# the logical system the output schema uses. Only aliases proven by
# the sample laboratory are listed; anything unlisted keeps its own
# name (never crash, never guess a new alias silently -- the ledger
# records the fallback).
SYSTEM_ALIASES = {
    "support_replica": "support_platform",
    "user_export_store": "export_service",
    "account_failover_replica": "account_service",
    "account_replication_cluster": "account_service",
    "search_index_service": "search_service",
    "backup_restore_service": "backup_service",
    "support_storage_service": "support_platform",
}


def logical_system(raw_system, category=None, resource=None):
    if raw_system in SYSTEM_ALIASES:
        return SYSTEM_ALIASES[raw_system]
    if raw_system:
        return raw_system
    # Empty system: infer only from an unambiguous shape signal.
    if category == "BACKUP_ARCHIVE":
        return "backup_service"
    return raw_system


def build_findings(lanes):
    """One finding per violating (system, resource), highest
    precedence wins (REMAINING over EXPOSED over ACTIVE over RISK).
    Returns (findings, finding_by_resource)."""
    by_resource = {}
    precedence = {"REPORT_REMAINING_RECORD": 0, "REPORT_EXPOSED_PII": 1,
                  "REPORT_ACTIVE_DATA_FLOW": 2, "REPORT_RESTORE_RISK": 3}
    for lane in lanes:
        verdict = lane["verdict"]
        if verdict["state_kind"] != "VIOLATING":
            continue
        finding_op = verdict["finding_op"]
        if finding_op is None:
            continue
        key = (lane["logical_system"], lane["resource"])
        candidate = {
            "phase": "FINDING",
            "system_id": lane["logical_system"],
            "resource_id": lane["resource"],
            "operation": finding_op,
            "state": "PRESENT" if finding_op in (
                "REPORT_REMAINING_RECORD", "REPORT_EXPOSED_PII") else "ACTIVE",
            "evidence_id": "",
            "category": verdict["category"],
            "remediation_op": verdict["remediation_op"],
            "verification_op": verdict["verification_op"],
            "lane": lane,
            "verdict": verdict,
        }
        citing = choose_citation(lane["records"], verdict)
        if citing is not None:
            candidate["evidence_id"] = citing.get("source_file_id") or ""
        existing = by_resource.get(key)
        if existing is None or precedence[finding_op] < precedence[
                existing["operation"]]:
            by_resource[key] = candidate
    findings = sorted(by_resource.values(),
                      key=lambda f: (precedence[f["operation"]],
                                     f["system_id"], f["resource_id"]))
    return findings, by_resource


def build_remediations(findings):
    """1:1 remediation counterparts, in causal order for the narrative
    but re-sorted into Report Order by the sorter afterwards."""
    remediations = []
    for finding in findings:
        remediation_op = finding["remediation_op"]
        if remediation_op is None:
            # Exposed-identifier findings without a category decision
            # default by category (anonymise analytics/telemetry only).
            if finding["category"] in ANONYMIZE_CATEGORIES:
                remediation_op = "ANONYMIZE_RECORD"
            else:
                remediation_op = "REDACT_RECORD"
        state = REMEDIATION_TO_VERIFICATION[remediation_op][1]
        remediations.append({
            "phase": "REMEDIATION",
            "system_id": finding["system_id"],
            "resource_id": finding["resource_id"],
            "operation": remediation_op,
            "state": state,
            "evidence_id": "",
        })
    return remediations


def build_verifications(findings, remediations, lanes, observed):
    """Verification steps under R1-FINAL.

    observed: {"account_ids": [identifier-joined account ids at/before
    cutoff], "audit_ids": [retained-valid audit ids], "account_lane_id":
    account id from a profile lane if any, else None}
    Returns (verifications, flags). Flags name every omitted slot.
    """
    verifications = []
    flags = []
    remediation_by_resource = {
        (r["system_id"], r["resource_id"]): r for r in remediations}
    # 1:1 counterparts for every remediation.
    for finding in findings:
        remediation_op = finding["remediation_op"]
        if remediation_op is None:
            remediation_op = ("ANONYMIZE_RECORD"
                              if finding["category"] in ANONYMIZE_CATEGORIES
                              else "REDACT_RECORD")
        verification_op, state = REMEDIATION_TO_VERIFICATION[remediation_op]
        verifications.append({
            "phase": "VERIFICATION",
            "system_id": finding["system_id"],
            "resource_id": finding["resource_id"],
            "operation": verification_op,
            "state": state,
            "evidence_id": "",
        })
    # Account slot: only for an observed, identifier-joined id.
    account_ids = observed.get("account_ids", [])
    if account_ids:
        account_id = observed.get("account_lane_id") or sorted(account_ids)[0]
        if ("account_service", account_id) not in remediation_by_resource \
                and not any(v["system_id"] == "account_service"
                            and v["resource_id"] == account_id
                            for v in verifications):
            verifications.append({
                "phase": "VERIFICATION",
                "system_id": "account_service",
                "resource_id": account_id,
                "operation": "VERIFY_RECORD_ABSENT",
                "state": "ABSENT",
                "evidence_id": "",
            })
    else:
        flags.append("CANONICAL_ACCOUNT_UNOBSERVED")
    # Audit slot: only for an observed, retained-valid audit id.
    audit_ids = observed.get("audit_ids", [])
    if audit_ids:
        audit_id = sorted(audit_ids)[0]
        verifications.append({
            "phase": "VERIFICATION",
            "system_id": "security_service",
            "resource_id": audit_id,
            "operation": "VERIFY_RECORD_PRESENT",
            "state": "PRESENT",
            "evidence_id": "",
        })
    else:
        flags.append("CANONICAL_AUDIT_UNOBSERVED")
    return verifications, flags


def build_complete_verifications(lanes, observed, complete_citations):
    """Verification-only steps for a COMPLETE case.

    Emitted only for observed, compliant states: account absence (with
    its absence citation), retained-valid audit (present citation),
    and treated states (redacted / anonymised / disabled / blocked,
    each with its treated-state citation). complete_citations maps
    (system, resource) -> file id for the citation; slots without a
    citation are omitted, never cited by invention.
    Returns (verifications, flags).
    """
    verifications = []
    flags = []
    account_ids = observed.get("account_ids", [])
    account_lane_id = observed.get("account_lane_id")
    # Account absence: the account lane's latest state must be absent.
    account_lanes = [lane for lane in lanes
                     if lane["logical_system"] == "account_service"
                     and lane["verdict"]["category"] in (
                         "USER_PROFILE", "SECONDARY_IDENTIFIER")]
    account_absent = any(lane["verdict"]["state_kind"] == "ABSENT"
                         for lane in account_lanes)
    if account_ids and account_absent:
        account_id = account_lane_id or sorted(account_ids)[0]
        key = ("account_service", account_id)
        verifications.append({
            "phase": "VERIFICATION",
            "system_id": "account_service",
            "resource_id": account_id,
            "operation": "VERIFY_RECORD_ABSENT",
            "state": "ABSENT",
            "evidence_id": complete_citations.get(key, ""),
        })
    elif not account_ids:
        flags.append("CANONICAL_ACCOUNT_UNOBSERVED")
    else:
        flags.append("ACCOUNT_NOT_PROVEN_ABSENT")
    audit_ids = observed.get("audit_ids", [])
    if audit_ids:
        audit_id = sorted(audit_ids)[0]
        key = ("security_service", audit_id)
        verifications.append({
            "phase": "VERIFICATION",
            "system_id": "security_service",
            "resource_id": audit_id,
            "operation": "VERIFY_RECORD_PRESENT",
            "state": "PRESENT",
            "evidence_id": complete_citations.get(key, ""),
        })
    else:
        flags.append("CANONICAL_AUDIT_UNOBSERVED")
    treated = [lane for lane in lanes
               if lane["verdict"]["state_kind"] == "COMPLIANT_TREATED"
               and lane["verdict"]["verification_op"] is not None
               and lane["logical_system"] != "account_service"]
    seen = set()
    for lane in treated:
        key = (lane["logical_system"], lane["resource"])
        if key in seen:
            continue
        seen.add(key)
        operation = lane["verdict"]["verification_op"]
        state = {"VERIFY_RECORD_REDACTED": "REDACTED",
                 "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED",
                 "VERIFY_DATA_FLOW_DISABLED": "DISABLED",
                 "VERIFY_RESTORE_BLOCKED": "BLOCKED"}.get(operation)
        if state is None:
            continue
        verifications.append({
            "phase": "VERIFICATION",
            "system_id": lane["logical_system"],
            "resource_id": lane["resource"],
            "operation": operation,
            "state": state,
            "evidence_id": complete_citations.get(key, ""),
        })
    return verifications, flags


def sort_steps(steps):
    """Report Order: phase, operation rank, system_id, resource_id
    (string-lexicographic), step_no assigned consecutively from 1."""
    ordered = sorted(
        steps,
        key=lambda s: (PHASE_RANK[s["phase"]],
                       operation_rank(s["phase"], s["operation"]),
                       s["system_id"], s["resource_id"]))
    out = []
    for index, step in enumerate(ordered, start=1):
        out.append({
            "step_no": index,
            "phase": step["phase"],
            "system_id": step["system_id"],
            "resource_id": step["resource_id"],
            "operation": step["operation"],
            "state": step["state"],
            "evidence_id": step["evidence_id"],
        })
    return out


CAUSAL_ORDER = {"DISABLE_DATA_FLOW": 0, "BLOCK_RESTORE": 1,
                "DELETE_RECORD": 2, "REDACT_RECORD": 3,
                "ANONYMIZE_RECORD": 4}
# Downstream copies purge before their source records.
_DOWNSTREAM_FIRST = {"search_service", "export_service", "marketing_platform",
                     "analytics_platform"}


def causal_narrative(remediations):
    """Causal execution order for human operators (NOT report order):
    disable/block first, drain, downstream-before-source, purge
    derivatives, mutate, verify. Returns a list of narrative lines."""
    def key(step):
        downstream = 0 if step["system_id"] in _DOWNSTREAM_FIRST else 1
        return (CAUSAL_ORDER.get(step["operation"], 9), downstream,
                step["system_id"], step["resource_id"])

    ordered = sorted(remediations, key=key)
    lines = []
    for step in ordered:
        lines.append(
            f"{step['operation']} {step['system_id']} "
            f"{step['resource_id']} -> {step['state']}")
    lines.append("VERIFY all remediated resources and processes")
    return lines
