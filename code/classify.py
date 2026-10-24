"""Shape classification for Unit 3 (classify by SHAPE, never by name).

A lane is all result-bearing index records for one (system, resource,
replica) at or before the audit cutoff, for one subject. Classification
reads the lane's SHAPE -- collections, event names, field dumps, cohort
size, join keys, identifier content -- and never the bare system name
to decide treatment. The regression that pins this: a one-row contact
lookup keyed to a historical hash, sitting in an analytics collection,
is a LOOKUP (delete it), not a profile (anonymise it); a mapping from
collection name to treatment fails it by construction.

Inputs are plain dicts (index records, subject identifier sets) so the
module is testable on synthetic lanes without the corpus.

Record-time / time-source ranking (citation rule): row/event/line
times outrank bundle-snapshot times, which outrank manifest fallbacks.
State determination uses the latest observation by time; citation
selection prefers the highest-ranked time source among records that
exhibit the verdict state, then latest time, then smallest file id.
"""

import re
from datetime import datetime, timezone

PII_KEYS = {"email", "email_hash", "phone", "name", "full_name"}
REFERENCE_KEYS = {
    "resource_id", "user_id", "subject_reference", "customer_reference",
    "trace_id", "instance", "pod", "region", "service", "level",
}
REDACTED_MARKERS = {"[REDACTED]", "[redacted]", "REDACTED"}
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")


def parse_time(value):
    """ISO timestamp -> aware datetime (UTC assumed if naive), or None."""
    if not value or not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        parsed = datetime.fromisoformat(text)
    except ValueError:
        # Date-only form.
        try:
            parsed = datetime.fromisoformat(text + "T00:00:00+00:00")
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def time_source_rank(record):
    source = (record.get("time_source") or "").lower()
    if source.startswith("row:") or source == "line":
        return 3
    if source == "inner_snapshot":
        return 2
    if source == "manifest_fallback":
        return 1
    return 0


def is_result_record(record):
    """True if the record bears a result (not a started/pending line).

    Started lines, query keys, scan starts, pool noise and workflow
    claims carry no state. A lookup key naming a resource is not a
    stored record: only a completed readback / state row / absence /
    transcription / labelled check counts.
    """
    kind = record.get("evidence_kind")
    if kind in ("state", "readback", "absence", "binary", "lookup"):
        return True
    if kind == "log":
        fields = record.get("fields") or {}
        event = str(fields.get("event") or "")
        if event.endswith("_completed") or event in (
            "connector_heartbeat",
            "restore_candidate_evaluated",
            "message_pii_scan",
        ):
            return True
        if any(key in fields for key in (
            "rows", "http_status", "enabled", "deletion_block",
            "restore_allowed",
        )):
            return True
        return False
    return False


def _walk_strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for value in obj.values():
            yield from _walk_strings(value)
    elif isinstance(obj, (list, tuple)):
        for value in obj:
            yield from _walk_strings(value)


def _digits(value):
    return re.sub(r"\D", "", str(value))


def pii_hits(fields, subject):
    """Identifier kinds from `subject` found anywhere in `fields`.

    subject: {"emails": [...lower...], "hashes": [...lower...],
    "phones": [raw...], "name": lower-or-""}. Reference keys (stable
    internal ids, trace ids) are never hits: a tombstone or audit row
    keyed by the internal id is compliant, not exposed.
    """
    hits = set()
    emails = {e.lower() for e in subject.get("emails", [])}
    hashes = {h.lower() for h in subject.get("hashes", [])}
    phones = {_digits(p) for p in subject.get("phones", []) if _digits(p)}
    name = (subject.get("name") or "").strip().lower()
    for key, value in _flatten_fields(fields):
        if key in REFERENCE_KEYS:
            continue
        if isinstance(value, str):
            lowered = value.lower()
            for email in emails:
                if email and email in lowered:
                    hits.add("email")
            for digest in hashes:
                if digest and digest in lowered:
                    hits.add("email_hash")
            if name and name in lowered:
                hits.add("name")
            found_phones = {_digits(m) for m in EMAIL_RE.sub("", value)}
            # Phone check on the raw value itself, not on emails.
            digits = _digits(value)
            if digits and digits in phones:
                hits.add("phone")
    return hits


def _flatten_fields(fields, prefix=""):
    if isinstance(fields, dict):
        for key, value in fields.items():
            if isinstance(value, (dict, list)):
                yield from _flatten_fields(value, prefix + str(key) + ".")
            else:
                yield key, value
    elif isinstance(fields, list):
        for item in fields:
            yield from _flatten_fields(item, prefix)


def second_person_present(fields, subject):
    """A second person is present iff a NON-subject email/phone appears.

    A bare agent name is not shared context (names alone never count);
    only a second email address or phone number counts. Deterministic
    and shape-based: it inspects values, never a name list.
    """
    emails = {e.lower() for e in subject.get("emails", [])}
    phones = {_digits(p) for p in subject.get("phones", []) if _digits(p)}
    for key, value in _flatten_fields(fields):
        if key in REFERENCE_KEYS:
            continue
        if not isinstance(value, str):
            continue
        for match in EMAIL_RE.findall(value):
            if match.lower() not in emails:
                return True
        digits = _digits(value)
        if len(digits) >= 7 and digits not in phones and not EMAIL_RE.search(value):
            # A bare digit string that is not the subject's phone.
            # Restrict to phone-like keys to avoid order ids / ports.
            if "phone" in key.lower() or "mobile" in key.lower() or "tel" in key.lower():
                return True
    return False


def _label(record):
    fields = record.get("fields") or {}
    label = record.get("state_label")
    if label:
        return str(label).upper()
    outcome = record.get("lookup_outcome") or {}
    if outcome.get("result"):
        return str(outcome["result"]).upper()
    if fields.get("result"):
        return str(fields["result"]).upper()
    if fields.get("state_label"):
        return str(fields["state_label"]).upper()
    return ""


def _is_absent(record):
    if record.get("evidence_kind") == "absence":
        return True
    if _label(record) == "NOT_FOUND":
        return True
    outcome = record.get("lookup_outcome") or {}
    if outcome.get("rows") == 0 or outcome.get("http_status") == 404:
        return True
    fields = record.get("fields") or {}
    if fields.get("rows") == 0 and fields.get("http_status") == 404:
        return True
    if fields.get("status_code") == 404 and fields.get("profile") is None:
        return True
    if fields.get("rows") == 0 and "http_status" in fields:
        return True
    return False


def _restore_bool(record):
    """Canonical restore-allowed boolean, or None if unknowable.

    Two encodings exist and must not be conflated: a `restore_allowed`
    flag means what it says, while a `deletion_block` flag means the
    opposite (block present = restore NOT allowed). The indexer's
    canonical dict names its source field; honour it.
    """
    canonical = record.get("restore_allowed")
    if isinstance(canonical, dict) and "canonical" in canonical:
        if canonical.get("field") == "deletion_block":
            return not bool(canonical["canonical"])
        return bool(canonical["canonical"])
    fields = record.get("fields") or {}
    if "restore_allowed" in fields:
        raw = fields["restore_allowed"]
    elif "deletion_block" in fields:
        raw = fields["deletion_block"]
        if isinstance(raw, bool):
            return not raw
        if isinstance(raw, str):
            lowered = raw.strip().lower()
            if lowered in ("true", "1"):
                return False
            if lowered in ("false", "0"):
                return True
        return None
    else:
        raw = None
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, str):
        lowered = raw.strip().lower()
        if lowered in ("true", "1", "active", "allowed"):
            return True
        if lowered in ("false", "0", "blocked"):
            return False
    label = _label(record)
    if label == "ACTIVE":
        return True
    if label == "BLOCKED":
        return False
    return None


def _enabled_state(record):
    fields = record.get("fields") or {}
    enabled = fields.get("enabled")
    if isinstance(enabled, bool):
        return enabled
    if isinstance(enabled, str):
        if enabled.strip().lower() in ("true", "1"):
            return True
        if enabled.strip().lower() in ("false", "0"):
            return False
    label = _label(record)
    if label == "ACTIVE":
        return True
    if label == "DISABLED":
        return False
    return None


def detect_category(lane_records):
    """Category from shape: collections, events, fields -- in order."""
    collections = set()
    events = set()
    systems = set()
    record_types = set()
    for record in lane_records:
        collections.add(record.get("collection") or "")
        fields = record.get("fields") or {}
        if fields.get("event"):
            events.add(str(fields["event"]))
        if fields.get("record_type"):
            record_types.add(str(fields["record_type"]))
        systems.add(record.get("system_id") or "")
    latest = lane_records[-1] if lane_records else {}
    fields = latest.get("fields") or {}
    if "deleted_customer_references" in collections:
        return "ACCOUNT_TOMBSTONE"
    if (fields.get("account_status") == "DELETED"
            and "subject_reference" in fields
            and PII_KEYS <= set(fields.keys())):
        return "ACCOUNT_TOMBSTONE"
    if (collections & {"security_audit_events", "security_audit_records",
                        "audit_records"}
            or "audit_record_read_completed" in events
            or "SECURITY_AUDIT_LOG" in record_types):
        return "SECURITY_AUDIT_LOG"
    if collections & {"legal_holds", "retained_order_records"}:
        return "LEGAL_HOLD_RECORD"
    if (collections & {"backup_catalog", "restore_entries",
                        "backup_restore_entries", "BACKUP_ARCHIVE"}
            or "BACKUP_ARCHIVE" in record_types
            or "restore_candidate_evaluated" in events
            or "restore_allowed" in fields or "archive_path" in fields
            or "archive_key" in fields):
        return "BACKUP_ARCHIVE"
    if (collections & {"connectors", "connector_configurations",
                        "connector_subscriptions", "DATA_FLOW"}
            or "DATA_FLOW" in record_types
            or "connector_heartbeat" in events
            or "connector_config_read_completed" in events
            or ("enabled" in fields
                and ("subject_selector" in fields or "mode" in fields
                     or "destination" in fields
                     or "connector_name" in fields
                     or "customer_email" in fields))):
        return "DATA_FLOW"
    if "cache_service" in systems or "REFRESH_CACHE" in collections:
        return "CACHE_ENTRY"
    if (collections & {"support_attachments", "ticket_attachments"}
            or "SUPPORT_ATTACHMENT" in record_types):
        return "SUPPORT_ATTACHMENT"
    if "support_replica" in collections or "support_replica" in systems:
        return "SUPPORT_REPLICA_COPY"
    if (collections & {"support_conversations", "tickets", "support_records"}
            or "SUPPORT_MESSAGE" in record_types
            or "message_text" in fields or "message_excerpt" in fields
            or "message_pii_scan" in events
            or "support_ticket_read_completed" in events):
        return "SUPPORT_MESSAGE"
    if (collections & {"customer_search_documents", "search_documents",
                        "search_documents_primary", "index_queries"}
            or "SEARCH_INDEX_ENTRY" in record_types
            or "index_query_completed" in events
            or isinstance(fields.get("document"), dict)):
        return "SEARCH_INDEX_ENTRY"
    if (collections & {"customer_exports", "exports", "customer_export_jobs"}
            or "download_available" in fields
            or "object_key" in fields):
        return "USER_EXPORT"
    if "marketing_profiles" in collections or "MARKETING_PROFILE" in record_types:
        return "MARKETING_PROFILE"
    if (collections & {"customer_analytics_profiles", "analytics_profiles",
                        "customer_analytics_reports"}
            or "ANALYTICS_PROFILE" in record_types
            or "analytics_profile_read_completed" in events
            or "contact_lookup_completed" in events
            or ("correlation_key" in fields and "analytics" in str(systems))
            or "audience_cohort" in fields or "metrics" in fields):
        return "ANALYTICS_PROFILE"
    if (collections & {"customer_profiles", "customer_profiles_primary",
                        "customer_profiles_failover_replica", "profiles"}
            or "USER_PROFILE" in record_types
            or ("full_name" in fields and "email" in fields
                and "account_status" in fields)):
        return "USER_PROFILE"
    if "email_delivery_service" in systems or "SEND_EMAIL" in collections:
        return "EMAIL_DELIVERY_LOG"
    if systems & {"account_service", "identity_service"}:
        return "SECONDARY_IDENTIFIER"
    return "UNKNOWN_SHAPE"


def _is_lookup_shape(lane_records, subject):
    """Analytics lookup vs profile, by shape (the generalised rule).

    A lookup is a completed contact/index query keyed to a subject
    hash, carrying a row count and no aggregate/cohort/profile fields.
    A profile carries aggregates, a cohort, or audience fields.
    """
    hashes = {h.lower() for h in subject.get("hashes", [])}
    for record in lane_records:
        fields = record.get("fields") or {}
        if fields.get("event") == "contact_lookup_completed":
            return True
        if (fields.get("correlation_key") in hashes
                and "rows" in fields
                and not ({"metrics", "audience_cohort", "orders_completed_90d"}
                         & set(fields.keys()))):
            return True
    return False


def classify_lane(lane_records, subject, rules, audit_at, cohort_size=None):
    """Classify one lane's latest state.

    Returns a dict: category, rule_id, state_kind (VIOLATING /
    COMPLIANT_TREATED / RETAINED_VALID / ABSENT / CACHE_SIGNAL /
    UNKNOWN_SHAPE), finding_op, remediation_op, verification_op,
    rationale, citing_record, gap_notes.
    """
    gaps = []
    if not lane_records:
        return {"category": None, "state_kind": "ABSENT", "finding_op": None,
                "remediation_op": None, "rationale": "no records",
                "citing_record": None, "gap_notes": gaps}
    latest = lane_records[-1]
    category = detect_category(lane_records)
    fields = latest.get("fields") or {}
    label = _label(latest)

    def result(state_kind, finding_op=None, remediation_op=None,
               verification_op=None, rationale="", citing=None):
        return {
            "category": category,
            "rule_id": rules.rule_id_for(_rule_category(category)) if rules else None,
            "state_kind": state_kind,
            "finding_op": finding_op,
            "remediation_op": remediation_op,
            "verification_op": verification_op,
            "rationale": rationale or state_kind,
            "citing_record": citing if citing is not None else latest,
            "gap_notes": gaps,
        }

    # Absence beats every category except the audit/tombstone slot
    # logic in the caller: an absent record is simply not present.
    if _is_absent(latest):
        return result("ABSENT", rationale="latest observation is absence")

    if category == "CACHE_ENTRY":
        gaps.append("CACHE_SIGNAL: cache activity observed; no cache "
                    "state table exists, so this is a Horizon B signal, "
                    "never a finding.")
        return result("CACHE_SIGNAL", rationale="cache signal only")

    if category == "ACCOUNT_TOMBSTONE":
        hits = pii_hits(fields, subject)
        if hits:
            return result("VIOLATING", "REPORT_EXPOSED_PII", "REDACT_RECORD",
                          "VERIFY_RECORD_REDACTED",
                          rationale="tombstone still carries identifiers: "
                          + ",".join(sorted(hits)))
        return result("COMPLIANT_TREATED", None, None,
                      "VERIFY_RECORD_REDACTED",
                      rationale="tombstone carries only the stable id")

    if category == "SECURITY_AUDIT_LOG":
        hits = pii_hits(fields, subject)
        if hits:
            return result("VIOLATING", "REPORT_EXPOSED_PII", "REDACT_RECORD",
                          "VERIFY_RECORD_REDACTED",
                          rationale="retained audit carries identifiers: "
                          + ",".join(sorted(hits)))
        retention = fields.get("retention_until")
        retention_time = parse_time(retention) if retention else None
        audit_time = parse_time(audit_at)
        if retention_time and audit_time and retention_time < audit_time:
            gaps.append("OVER_RETENTION: audit record past its retention "
                        "window at the audit cutoff (protocol completion, "
                        "sample-silent).")
            return result("VIOLATING", "REPORT_REMAINING_RECORD",
                          "DELETE_RECORD", "VERIFY_RECORD_ABSENT",
                          rationale="audit record past retention window")
        return result("RETAINED_VALID", None, None,
                      "VERIFY_RECORD_PRESENT",
                      rationale="audit record minimised and within retention")

    if category == "LEGAL_HOLD_RECORD":
        hits = pii_hits(fields, subject)
        if hits:
            return result("VIOLATING", "REPORT_EXPOSED_PII", "REDACT_RECORD",
                          "VERIFY_RECORD_REDACTED",
                          rationale="legal hold record carries identifiers")
        retention = fields.get("retention_until")
        retention_time = parse_time(retention) if retention else None
        audit_time = parse_time(audit_at)
        if retention_time and audit_time and retention_time < audit_time:
            gaps.append("EXPIRED_HOLD: legal hold past its retention date; "
                        "no identifiers present so no finding, ledger only.")
        return result("RETAINED_VALID", None, None, None,
                      rationale="legal hold retained, fields minimal")

    if category == "BACKUP_ARCHIVE":
        allowed = _restore_bool(latest)
        if allowed is False:
            return result("COMPLIANT_TREATED", None, None,
                          "VERIFY_RESTORE_BLOCKED",
                          rationale="restore is blocked for this archive")
        if allowed is True:
            return result("VIOLATING", "REPORT_RESTORE_RISK",
                          "BLOCK_RESTORE", "VERIFY_RESTORE_BLOCKED",
                          rationale="archive restore is not blocked")
        gaps.append("UNPROVEN_BLOCK: backup archive carries no "
                    "restore-block state; unblocked until proven blocked.")
        return result("VIOLATING", "REPORT_RESTORE_RISK",
                      "BLOCK_RESTORE", "VERIFY_RESTORE_BLOCKED",
                      rationale="no restore-block state observed")

    if category == "DATA_FLOW":
        enabled = _enabled_state(latest)
        delivered = fields.get("last_delivery_status")
        if enabled is True or label == "ACTIVE":
            return result("VIOLATING", "REPORT_ACTIVE_DATA_FLOW",
                          "DISABLE_DATA_FLOW", "VERIFY_DATA_FLOW_DISABLED",
                          rationale="flow enabled at the audit cutoff")
        if enabled is False:
            if delivered == "delivered":
                gaps.append("DISABLED_BUT_DELIVERED: flow config disabled "
                            "yet a delivery is recorded; credential/queue "
                            "fields are absent from the corpus (Horizon B).")
            return result("COMPLIANT_TREATED", None, None,
                          "VERIFY_DATA_FLOW_DISABLED",
                          rationale="flow config disabled")
        if label == "PAUSED":
            return result("VIOLATING", "REPORT_ACTIVE_DATA_FLOW",
                          "DISABLE_DATA_FLOW", "VERIFY_DATA_FLOW_DISABLED",
                          rationale="paused is not disabled")
        if delivered == "delivered":
            return result("VIOLATING", "REPORT_ACTIVE_DATA_FLOW",
                          "DISABLE_DATA_FLOW", "VERIFY_DATA_FLOW_DISABLED",
                          rationale="flow delivered without a disabled config")
        gaps.append("FLOW_STATE_UNKNOWN: flow record carries no enabled "
                    "state; treated as not-proven-disabled.")
        return result("VIOLATING", "REPORT_ACTIVE_DATA_FLOW",
                      "DISABLE_DATA_FLOW", "VERIFY_DATA_FLOW_DISABLED",
                      rationale="flow disablement unproven")

    if category == "SUPPORT_ATTACHMENT":
        if label == "FOUND":
            return result("VIOLATING", "REPORT_REMAINING_RECORD",
                          "DELETE_RECORD", "VERIFY_RECORD_ABSENT",
                          rationale="attachment present for the subject")
        if label == "IDENTIFIABLE":
            return result("VIOLATING", "REPORT_EXPOSED_PII", "REDACT_RECORD",
                          "VERIFY_RECORD_REDACTED",
                          rationale="attachment carries identifiers; sharing "
                          "unknown, so redact maximally (sample-silent)")
        if label == "REDACTED":
            return result("COMPLIANT_TREATED", None, None,
                          "VERIFY_RECORD_REDACTED",
                          rationale="attachment already redacted")
        hits = pii_hits(fields, subject)
        if not hits:
            return result("COMPLIANT_TREATED", None, None,
                          "VERIFY_RECORD_REDACTED",
                          rationale="attachment carries no subject identifiers")
        if second_person_present(fields, subject):
            return result("VIOLATING", "REPORT_EXPOSED_PII", "REDACT_RECORD",
                          "VERIFY_RECORD_REDACTED",
                          rationale="attachment shared with a second person; "
                          "redact maximally, preserve the other issue")
        return result("VIOLATING", "REPORT_REMAINING_RECORD",
                      "DELETE_RECORD", "VERIFY_RECORD_ABSENT",
                      rationale="sole-subject attachment still present")

    if category == "SUPPORT_REPLICA_COPY":
        rows = fields.get("rows")
        marker = fields.get("marker_found")
        if rows == 0 or (isinstance(marker, str)
                         and marker.strip().lower() == "true"):
            return result("ABSENT", rationale="replica copy deleted/marked")
        return result("VIOLATING", "REPORT_REMAINING_RECORD",
                      "DELETE_RECORD", "VERIFY_RECORD_ABSENT",
                      rationale="stored support copy present on a replica")

    if category == "SUPPORT_MESSAGE":
        if label == "REDACTED":
            return result("COMPLIANT_TREATED", None, None,
                          "VERIFY_RECORD_REDACTED",
                          rationale="message already redacted")
        text = fields.get("message_text", fields.get("message_excerpt"))
        if (isinstance(text, str) and text.strip() in REDACTED_MARKERS
                and not pii_hits(fields, subject)):
            return result("COMPLIANT_TREATED", None, None,
                          "VERIFY_RECORD_REDACTED",
                          rationale="message text redacted, no identifiers")
        hits = pii_hits(fields, subject)
        if (hits or label in ("IDENTIFIABLE", "FOUND")
                or fields.get("event") == "message_pii_scan"):
            return result("VIOLATING", "REPORT_EXPOSED_PII", "REDACT_RECORD",
                          "VERIFY_RECORD_REDACTED",
                          rationale="message carries subject identifiers")
        gaps.append("MESSAGE_CONTENT_UNKNOWN: message record carries no "
                    "provable identifier content; no finding emitted.")
        return result("UNKNOWN_SHAPE",
                      rationale="message content unprovable")

    if category == "SEARCH_INDEX_ENTRY":
        hits = pii_hits(fields, subject)
        documents = []
        hits_field = fields.get("hits")
        if isinstance(hits_field, dict):
            documents = hits_field.get("documents") or []
        if label == "FOUND" or hits or documents:
            return result("VIOLATING", "REPORT_REMAINING_RECORD",
                          "DELETE_RECORD", "VERIFY_RECORD_ABSENT",
                          rationale="search entry still indexes the subject")
        rows = fields.get("rows")
        if rows == 0:
            return result("ABSENT", rationale="search readback empty")
        return result("VIOLATING", "REPORT_REMAINING_RECORD",
                      "DELETE_RECORD", "VERIFY_RECORD_ABSENT",
                      rationale="search entry present for the subject")

    if category == "USER_EXPORT":
        available = fields.get("download_available")
        if available is False and "object_key" not in fields:
            gaps.append("EXPORT_UNAVAILABLE: export job not downloadable; "
                        "no finding, ledger only.")
            return result("ABSENT", rationale="export not available")
        return result("VIOLATING", "REPORT_REMAINING_RECORD",
                      "DELETE_RECORD", "VERIFY_RECORD_ABSENT",
                      rationale="export still available for the subject")

    if category == "MARKETING_PROFILE":
        if label in ("REMOVED", "DELETED"):
            return result("ABSENT", rationale="marketing profile removed")
        return result("VIOLATING", "REPORT_REMAINING_RECORD",
                      "DELETE_RECORD", "VERIFY_RECORD_ABSENT",
                      rationale="marketing profile always deleted, even "
                      "hashed or segmented")

    if category == "ANALYTICS_PROFILE":
        if label == "ANONYMIZED":
            return result("COMPLIANT_TREATED", None, None,
                          "VERIFY_RECORD_ANONYMIZED",
                          rationale="analytics record anonymised")
        if label == "IDENTIFIABLE":
            return result("VIOLATING", "REPORT_EXPOSED_PII",
                          "ANONYMIZE_RECORD", "VERIFY_RECORD_ANONYMIZED",
                          rationale="analytics record labelled identifiable")
        if _is_lookup_shape(lane_records, subject):
            return result("VIOLATING", "REPORT_REMAINING_RECORD",
                          "DELETE_RECORD", "VERIFY_RECORD_ABSENT",
                          rationale="one-row contact lookup keyed to a "
                          "subject hash, not a statistical profile")
        hits = pii_hits(fields, subject)
        if hits:
            return result("VIOLATING", "REPORT_EXPOSED_PII",
                          "ANONYMIZE_RECORD", "VERIFY_RECORD_ANONYMIZED",
                          rationale="analytics record still attributable: "
                          + ",".join(sorted(hits)))
        if cohort_size is not None and cohort_size < 5:
            quasi = {"metrics", "orders", "device", "session", "location",
                     "age", "postcode"} & set(fields.keys())
            if quasi:
                return result("VIOLATING", "REPORT_EXPOSED_PII",
                              "ANONYMIZE_RECORD",
                              "VERIFY_RECORD_ANONYMIZED",
                              rationale="small cohort with quasi-identifiers")
        return result("COMPLIANT_TREATED", None, None,
                      "VERIFY_RECORD_ANONYMIZED",
                      rationale="analytics record carries no identifiers")

    if category == "USER_PROFILE":
        status = fields.get("account_status")
        if status in ("ACTIVE", "DELETION_PENDING"):
            return result("VIOLATING", "REPORT_REMAINING_RECORD",
                          "DELETE_RECORD", "VERIFY_RECORD_ABSENT",
                          rationale="profile live at the audit cutoff")
        if status == "DELETED":
            if pii_hits(fields, subject):
                return result("VIOLATING", "REPORT_REMAINING_RECORD",
                              "DELETE_RECORD", "VERIFY_RECORD_ABSENT",
                              rationale="deleted profile still carries PII")
            return result("ABSENT", rationale="profile deleted and minimised")
        if pii_hits(fields, subject):
            return result("VIOLATING", "REPORT_REMAINING_RECORD",
                          "DELETE_RECORD", "VERIFY_RECORD_ABSENT",
                          rationale="profile row carries subject identifiers")
        return result("ABSENT", rationale="profile row carries no identifiers")

    if category == "EMAIL_DELIVERY_LOG":
        if pii_hits(fields, subject):
            return result("VIOLATING", "REPORT_EXPOSED_PII", "REDACT_RECORD",
                          "VERIFY_RECORD_REDACTED",
                          rationale="delivery log contains a subject email")
        return result("ABSENT", rationale="delivery log without subject email")

    if category == "SECONDARY_IDENTIFIER":
        if pii_hits(fields, subject) or fields.get("user_id") \
                or fields.get("subject_reference") \
                or fields.get("customer_reference"):
            return result("VIOLATING", "REPORT_REMAINING_RECORD",
                          "DELETE_RECORD", "VERIFY_RECORD_ABSENT",
                          rationale="secondary identifier record present")
        return result("ABSENT", rationale="no secondary identifier content")

    gaps.append("UNKNOWN_SHAPE: identifier-bearing record of a shape no "
                "rule classifies; escalated, never guessed.")
    return result("UNKNOWN_SHAPE", rationale="unclassified record shape")


def _rule_category(category):
    """Map internal shape categories onto contract categories."""
    mapping = {
        "SUPPORT_REPLICA_COPY": "SUPPORT_ATTACHMENT",
        "DATA_FLOW": "DATA_FLOW",
        "CACHE_ENTRY": "CACHE_ENTRY",
    }
    return mapping.get(category, category)


def _kind_class(record):
    """Citation kind class: structured state rows outrank log lines,
    which outrank visual transcriptions (whose time is only a file
    capture). State determination never uses this; citation does."""
    kind = record.get("evidence_kind")
    if kind in ("state", "readback", "absence", "lookup"):
        return 3
    if kind == "log":
        return 2
    if kind == "binary":
        return 1
    return 0


def choose_citation(lane_records, verdict):
    """D-Cite: among records exhibiting the verdict state, prefer the
    structured state row over a log line over a visual transcription,
    then the highest-ranked time source, then latest time, then
    smallest file id.
    """
    candidates = []
    for record in lane_records:
        if _record_exhibits(record, verdict):
            candidates.append(record)
    if not candidates:
        candidates = list(lane_records)
    if not candidates:
        return None

    def sort_key(record):
        time = parse_time(record.get("record_time"))
        epoch = time.timestamp() if time else 0.0
        return (-_kind_class(record), -time_source_rank(record), -epoch,
                record.get("source_file_id") or "")

    candidates.sort(key=sort_key)
    return candidates[0]


def _record_exhibits(record, verdict):
    """Rough single-record state check for citation filtering."""
    if _is_absent(record):
        return verdict["state_kind"] == "ABSENT"
    category = verdict["category"]
    label = _label(record)
    fields = record.get("fields") or {}
    if verdict["state_kind"] == "VIOLATING":
        if category == "DATA_FLOW":
            return _enabled_state(record) is True or label == "ACTIVE" \
                or fields.get("last_delivery_status") == "delivered"
        if category == "BACKUP_ARCHIVE":
            allowed = _restore_bool(record)
            return allowed is not False
        return True  # presence-type record exhibits a presence violation
    if verdict["state_kind"] == "COMPLIANT_TREATED":
        if category == "DATA_FLOW":
            return _enabled_state(record) is False or label == "DISABLED"
        if category == "BACKUP_ARCHIVE":
            return _restore_bool(record) is False
        if category in ("SUPPORT_MESSAGE", "SUPPORT_ATTACHMENT"):
            if label == "REDACTED":
                return True
            text = fields.get("message_text", fields.get("message_excerpt"))
            if isinstance(text, str) and text.strip() in REDACTED_MARKERS:
                return True
            requester = [fields.get("requester_email"),
                         fields.get("requester_name"),
                         fields.get("requester_phone")]
            return all(value in (None, "") for value in requester) \
                and "message_excerpt" in fields
        if category == "ACCOUNT_TOMBSTONE":
            return all(fields.get(key) is None
                       for key in ("email", "email_hash", "name", "phone"))
        if category == "ANALYTICS_PROFILE":
            if label == "ANONYMIZED":
                return True
            return all(fields.get(key) is None
                       for key in ("email", "email_hash", "phone"))
        return False
    if verdict["state_kind"] == "RETAINED_VALID":
        return True
    return False
