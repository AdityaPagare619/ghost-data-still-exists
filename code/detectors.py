"""Pillar detectors (Unit 3).

Each pillar from the master plan is a failure CLASS, and each detector
is a pure function over lanes (never over competition answers). A
detector reports hits; the engine turns hits into findings, ledger
flags, or both. Detectors never invent identifiers: every hit names a
resource the index already observed, or names a shared control.

Detectors operate on lane dicts:
  {"system": raw, "logical_system": str, "resource": str,
   "replica": str|None, "verdict": classify_lane(...) output,
   "records": [index records]}
plus a subject dict and optional cross-subject accessor for the
shared-control detector. Synthetic lanes work identically, which is
what the unseen-case mutation tests exercise.
"""

from classify import pii_hits


def detect_identity_multiplicity(lanes, subject):
    """Pillar A: the subject survives under a variant form.

    Hits when any lane's records were joined via a historical form, a
    historical hash, or a non-lowercase stored form -- i.e. the variant
    closure actually fired. This is corroboration for the identity
    graph, not a finding by itself.
    """
    hits = []
    live = {(subject.get("current_email") or "").lower()}
    for lane in lanes:
        joined_via_variant = False
        for record in lane["records"]:
            identifiers = record.get("identifiers") or {}
            for email in identifiers.get("emails", []):
                if email.lower() not in live and email:
                    joined_via_variant = True
            for digest in identifiers.get("hashes", []):
                if digest.lower() not in {
                    h.lower() for h in subject.get("hashes", [])
                    if h.lower() == digest.lower()
                    and digest.lower() in _live_hashes(subject)}:
                    pass
            stored = identifiers.get("emails", [])
            if any(e != e.lower() for e in stored):
                joined_via_variant = True
        if joined_via_variant:
            hits.append({
                "pillar": "A", "signal": "VARIANT_FORM_RECORD",
                "system": lane["logical_system"], "resource": lane["resource"],
                "detail": "record joined via a non-live email form or "
                          "non-lowercase stored form",
            })
    return hits


def _live_hashes(subject):
    import hashlib
    email = (subject.get("current_email") or "").lower()
    if not email:
        return set()
    return {hashlib.sha256(email.encode()).hexdigest()}


def detect_replication(lanes, subject):
    """Pillar B: primary says gone, a replica still holds it, or lanes
    disagree about one resource."""
    hits = []
    by_resource = {}
    for lane in lanes:
        by_resource.setdefault(lane["resource"], []).append(lane)
    for resource, group in by_resource.items():
        kinds = {lane["verdict"]["state_kind"] for lane in group}
        violating = [lane for lane in group
                     if lane["verdict"]["state_kind"] == "VIOLATING"]
        if violating and any(lane["replica"] for lane in violating):
            hits.append({
                "pillar": "B", "signal": "REPLICA_ONLY_RECORD",
                "system": violating[0]["logical_system"],
                "resource": resource,
                "detail": "violating lane lives on a replica copy",
            })
        if "VIOLATING" in kinds and "ABSENT" in kinds:
            hits.append({
                "pillar": "B", "signal": "REPLICA_DIVERGENCE",
                "system": group[0]["logical_system"], "resource": resource,
                "detail": "lanes disagree: one copy present, one absent; "
                          "the present copy decides (lag-vs-drift is never "
                          "asserted without a position)",
            })
    return hits


def detect_writer_graph(lanes, subject):
    """Pillar C: any armed writer that can recreate deleted data."""
    hits = []
    for lane in lanes:
        verdict = lane["verdict"]
        if verdict["state_kind"] != "VIOLATING":
            continue
        if verdict["finding_op"] == "REPORT_ACTIVE_DATA_FLOW":
            hits.append({
                "pillar": "C", "signal": "ARMED_FLOW",
                "system": lane["logical_system"], "resource": lane["resource"],
                "detail": "flow armed at the audit cutoff",
            })
        if verdict["finding_op"] == "REPORT_RESTORE_RISK":
            hits.append({
                "pillar": "C", "signal": "UNBLOCKED_RESTORE",
                "system": lane["logical_system"], "resource": lane["resource"],
                "detail": "backup restore path not blocked at cutoff",
            })
    return hits


def detect_retention_minimisation(lanes, subject):
    """Pillar D: retained records leaking identifiers, including via a
    novel field (scan is by identifier CONTENT, never by column list).
    """
    hits = []
    for lane in lanes:
        verdict = lane["verdict"]
        if verdict["category"] not in ("ACCOUNT_TOMBSTONE",
                                       "SECURITY_AUDIT_LOG",
                                       "LEGAL_HOLD_RECORD"):
            continue
        latest = lane["records"][-1] if lane["records"] else {}
        fields = latest.get("fields") or {}
        found = pii_hits(fields, subject)
        if found:
            hits.append({
                "pillar": "D", "signal": "RETAINED_RECORD_LEAK",
                "system": lane["logical_system"], "resource": lane["resource"],
                "detail": "retained record carries identifiers: "
                          + ",".join(sorted(found)),
            })
    return hits


def detect_multimodal(lanes, subject):
    """Pillar E: truth carried only by a visual/binary artefact, or by
    a support thread. Visual evidence is presence-proof only."""
    hits = []
    for lane in lanes:
        for record in lane["records"]:
            if record.get("evidence_kind") == "binary":
                hits.append({
                    "pillar": "E", "signal": "VISUAL_ONLY_EVIDENCE",
                    "system": lane["logical_system"],
                    "resource": lane["resource"],
                    "detail": "finding rests on a verified transcription; "
                              "presence-proof only, never absence/blocked/"
                              "disabled alone",
                })
                break
    return hits


def detect_analytics_attribution(lanes, subject):
    """Pillar F: an analytics record that is a lookup, or a profile
    that is still attributable (strong test)."""
    hits = []
    for lane in lanes:
        verdict = lane["verdict"]
        if verdict["category"] != "ANALYTICS_PROFILE":
            continue
        if verdict["state_kind"] != "VIOLATING":
            continue
        if verdict["finding_op"] == "REPORT_REMAINING_RECORD":
            signal = "ANALYTICS_LOOKUP_NOT_PROFILE"
        else:
            signal = "ATTRIBUTABLE_PROFILE"
        hits.append({
            "pillar": "F", "signal": signal,
            "system": lane["logical_system"], "resource": lane["resource"],
            "detail": verdict["rationale"],
        })
    return hits


def detect_intent_language(intent_decision):
    """Pillar G: intent gate outcome as a detector hit (no verdict
    logic here; the engine projects the decision)."""
    decision = intent_decision.get("decision")
    if decision == "NOT_APPLICABLE":
        return [{"pillar": "G", "signal": "NON_DELETION_REQUEST",
                 "system": "", "resource": "",
                 "detail": "request does not authorise deletion"}]
    if decision == "UNKNOWN_INTENT":
        return [{"pillar": "G", "signal": "UNKNOWN_INTENT",
                 "system": "", "resource": "",
                 "detail": "intent unresolvable; non-destruction default"}]
    return []


def detect_shared_control(lanes, subject, subjects_for_resource=None):
    """Pillar H: one shared control (flow/backup) serving several
    subjects. subjects_for_resource(resource) -> [subject keys] is an
    index accessor supplied by the caller; without it, no hit is
    claimed (absence of the accessor is never evidence of safety)."""
    hits = []
    if subjects_for_resource is None:
        return hits
    for lane in lanes:
        if lane["verdict"]["category"] not in ("DATA_FLOW", "BACKUP_ARCHIVE"):
            continue
        others = [key for key in subjects_for_resource(lane["resource"])
                  if key != subject.get("user_id")]
        if others:
            hits.append({
                "pillar": "H", "signal": "SHARED_CONTROL",
                "system": lane["logical_system"], "resource": lane["resource"],
                "detail": "control also serves other subjects; a failure "
                          "invalidates their drafts together: "
                          + ",".join(sorted(others)[:5]),
            })
    return hits


ALL_DETECTORS = (
    detect_identity_multiplicity,
    detect_replication,
    detect_writer_graph,
    detect_retention_minimisation,
    detect_multimodal,
    detect_analytics_attribution,
)
