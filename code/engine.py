"""Deterministic 7-gate rule engine (Unit 3).

Pipeline: identity resolution (Unit 2 graph) -> intent gate (Unit 2)
-> horizon lanes from the Unit 1 index (record-time <= audit cutoff,
boundary inclusive, record granularity) -> shape classification ->
pillar detectors -> findings -> 1:1 remediations -> R1-FINAL
verifications -> sorter -> hash-chained ledger entry.

The engine takes its collaborators as objects (index, graph, intent
gate, rules) so it is testable without the corpus and so no dataset
path is ever baked in. It reads no dashboard claim, no filename, and
no model output anywhere in the verdict path. Stdlib only.
"""

from classify import (
    classify_lane, detect_category, is_result_record, parse_time,
    choose_citation, _is_absent, _restore_bool, _enabled_state, _label,
)
from detectors import (
    detect_identity_multiplicity, detect_replication,
    detect_writer_graph, detect_retention_minimisation,
    detect_multimodal, detect_analytics_attribution,
    detect_intent_language, detect_shared_control,
)
from ledger import LedgerWriter, build_triplet
from rules import RuleBook
from steps import (
    build_findings, build_remediations, build_verifications,
    build_complete_verifications, sort_steps, causal_narrative,
    logical_system,
)

_EXCLUDED_KINDS = {"identity", "policy", "activity"}
_EXCLUDED_COLLECTIONS = {"user_identities", "user_audit_log"}


def _dict_of(obj):
    if isinstance(obj, dict):
        return obj
    if hasattr(obj, "to_dict"):
        return obj.to_dict()
    return {}


def _subject_dict(graph_subject):
    data = _dict_of(graph_subject)
    emails = []
    for form in data.get("email_forms", []):
        if isinstance(form, dict) and form.get("form"):
            emails.append(form["form"].lower())
    if data.get("current_email"):
        emails.append(data["current_email"].lower())
    hashes = []
    for form in data.get("hash_forms", []):
        if isinstance(form, dict) and form.get("form"):
            hashes.append(form["form"].lower())
    if data.get("current_hash"):
        hashes.append(data["current_hash"].lower())
    phones = []
    for form in data.get("phone_forms", []):
        if isinstance(form, dict) and form.get("form"):
            phones.append(form["form"])
    return {
        "user_id": data.get("user_id"),
        "name": (data.get("name") or "").lower(),
        "current_email": (data.get("current_email") or "").lower(),
        "emails": sorted(set(emails)),
        "hashes": sorted(set(hashes)),
        "phones": phones,
    }


class Engine:
    def __init__(self, index, rules, graph, intent_gate):
        self.index = index
        self.rules = rules
        self.graph = graph
        self.intent_gate = intent_gate
        self.ledger = LedgerWriter()
        self._by_resource = None
        self._cohort_sizes = {}

    # -- index helpers -------------------------------------------------
    def _resource_map(self):
        if self._by_resource is None:
            mapping = {}
            records = getattr(self.index, "records", None)
            if isinstance(records, dict):
                iterable = records.values()
            elif isinstance(records, (list, tuple)):
                iterable = records
            else:
                iterable = []
            for record in iterable:
                if record.get("resource_id"):
                    mapping.setdefault(record["resource_id"], []).append(record)
            self._by_resource = mapping
        return self._by_resource

    def _cohort_size(self, cohort_value):
        if cohort_value in self._cohort_sizes:
            return self._cohort_sizes[cohort_value]
        subjects = set()
        for record in self._resource_map_all():
            fields = record.get("fields") or {}
            if fields.get("audience_cohort") == cohort_value:
                for key in ("customer_reference", "subject_reference",
                            "user_id"):
                    if fields.get(key):
                        subjects.add(str(fields[key]).lower())
                for email in (record.get("identifiers") or {}).get("emails", []):
                    subjects.add(email.lower())
        size = len(subjects) if subjects else None
        self._cohort_sizes[cohort_value] = size
        return size

    def _resource_map_all(self):
        records = getattr(self.index, "records", None)
        if isinstance(records, dict):
            return list(records.values())
        if isinstance(records, (list, tuple)):
            return list(records)
        return []

    def _subjects_for_resource(self, resource):
        subjects = set()
        for record in self._resource_map().get(resource, []):
            identifiers = record.get("identifiers") or {}
            subjects.update(identifiers.get("user_ids", []))
            fields = record.get("fields") or {}
            for key in ("customer_reference", "subject_reference", "user_id"):
                if fields.get(key):
                    subjects.add(str(fields[key]))
        return sorted(subjects)

    # -- lane construction ---------------------------------------------
    def _normalize_positional(self, record):
        """Recover indexer-fallback rows: SQL rows the indexer stored
        with positional columns and no resource id. The row's first
        column is the resource id by table shape, and a subject
        identifier in another column is the join (stored, not guessed).
        Only the two observed fallback shapes are recovered; anything
        else passes through untouched. This compensates for an indexer
        limitation and is flagged for the indexer to own properly.
        """
        fields = record.get("fields") or {}
        if record.get("resource_id") or "col_0" not in fields:
            return record
        resource = fields.get("col_0")
        if not isinstance(resource, str) or "_" not in resource:
            return record
        collection = record.get("collection") or ""
        new_fields = dict(fields)
        row_time = None
        for key in sorted((k for k in fields if k.startswith("col_")),
                          reverse=True):
            candidate = parse_time(fields[key])
            if candidate is not None:
                row_time = fields[key]
                break
        if collection == "backup_restore_entries":
            flag = fields.get("col_4")
            allowed = flag in (1, "1", True, "true")
            new_fields["restore_allowed"] = allowed
            derived = dict(record)
            derived["resource_id"] = resource
            derived["fields"] = new_fields
            derived["restore_allowed"] = {
                "canonical": allowed, "field": "restore_allowed",
                "raw": flag}
            if row_time is not None:
                derived["record_time"] = row_time
                derived["time_source"] = "row:positional"
            return derived
        if collection == "connector_subscriptions":
            flag = fields.get("col_4")
            new_fields["enabled"] = flag in (1, "1", True, "true")
            new_fields["last_delivery_status"] = fields.get("col_5")
            derived = dict(record)
            derived["resource_id"] = resource
            derived["fields"] = new_fields
            if row_time is not None:
                derived["record_time"] = row_time
                derived["time_source"] = "row:positional"
            return derived
        return record

    def _file_trace_map(self):
        if getattr(self, "_trace_map", None) is None:
            mapping = {}
            for record in self._resource_map_all():
                fields = record.get("fields") or {}
                trace = fields.get("trace_id")
                if trace and record.get("source_file_id"):
                    mapping.setdefault(
                        (record["source_file_id"], trace), []).append(record)
            self._trace_map = mapping
        return self._trace_map

    def _trace_linked_records(self, subject, horizon_joined, audit_dt):
        """Trace linkage (documented attribution rule, not a guess):
        a POSITIVE result record inherits subject linkage from a query
        line in the SAME file with the SAME trace id whose key is a
        subject identifier. The started line IS the query and the
        completed line IS its result -- standard log correlation.
        ABSENCE linkage (founder ruling, bitemporal linker): a
        lookup-completed absence result (rows=0 / 404 / NOT_FOUND) in
        a subject-keyed trace ALSO links, flagged apart as
        _trace_linked_absence. It proves ABSENCE for the subject's
        audit sweep, never ownership of a present record: the query
        key binds the trace to the subject, the trace binds the
        result to the query. Guards (both branches): same file, same
        trace id, both lines at or before the cutoff, no foreign
        identifier anywhere in the trace, result carries a resource
        id. Linked records are flagged in the ledger, never silently
        merged.
        """
        subject_emails = {e.lower() for e in subject["emails"]}
        subject_hashes = {h.lower() for h in subject["hashes"]}
        subject_users = {subject["user_id"]} if subject.get("user_id") else set()

        def keys_of(record):
            identifiers = record.get("identifiers") or {}
            emails = {e.lower() for e in identifiers.get("emails", [])}
            emails |= {e.lower()
                       for e in identifiers.get("lookup", {}).get("emails", [])}
            hashes = {h.lower() for h in identifiers.get("hashes", [])}
            hashes |= {h.lower()
                       for h in identifiers.get("lookup", {}).get("hashes", [])}
            users = set(identifiers.get("user_ids", []))
            users |= set(identifiers.get("lookup", {}).get("user_ids", []))
            return emails, hashes, users

        traces = {}
        for record in horizon_joined:
            fields = record.get("fields") or {}
            event = str(fields.get("event") or "")
            trace = fields.get("trace_id")
            if not event.endswith("_started") or not trace:
                continue
            traces.setdefault((record.get("source_file_id"), trace), []).append(
                record)
        linked = []
        joins = []
        for (source_file, trace), query_lines in sorted(traces.items()):
            subject_hit = False
            foreign_hit = False
            for line in query_lines:
                emails, hashes, users = keys_of(line)
                if emails & subject_emails or hashes & subject_hashes \
                        or users & subject_users:
                    subject_hit = True
                if (emails - subject_emails) or (hashes - subject_hashes) \
                        or (users - subject_users):
                    foreign_hit = True
            if not subject_hit or foreign_hit:
                continue
            for record in self._file_trace_map().get((source_file, trace), []):
                fields = record.get("fields") or {}
                if record.get("evidence_kind") in _EXCLUDED_KINDS:
                    continue
                record_time = parse_time(record.get("record_time"))
                if record_time is None or record_time > audit_dt:
                    continue
                # Positive = asserts something IS present/active.
                # Row-count results and hit results are positive;
                # so is any state assertion (enabled, restore
                # allowed, FOUND/ACTIVE/IDENTIFIABLE label, an
                # active status) and any non-absence result record
                # (a state snapshot that does not itself declare
                # absence still asserts the record's existence for
                # the trace's subject). Empty/404/NOT_FOUND results
                # attribute nothing: the guard's whole job is
                # refusing to turn a failed lookup into ownership.
                positive = False
                if not _is_absent(record):
                    rows = fields.get("rows")
                    total = fields.get("total_hits")
                    if isinstance(rows, int) and rows >= 1:
                        positive = True
                    if isinstance(total, int) and total >= 1:
                        positive = True
                    if fields.get("result") == "hit":
                        positive = True
                    if _restore_bool(record) is True:
                        positive = True
                    if _enabled_state(record) is True:
                        positive = True
                    if _label(record) in ("FOUND", "ACTIVE", "IDENTIFIABLE"):
                        positive = True
                    if str(fields.get("status") or "").upper() in (
                            "ACTIVE", "DELETION_PENDING"):
                        positive = True
                    if record.get("evidence_kind") in (
                            "state", "readback", "binary", "lookup"):
                        positive = True
                is_absence = _is_absent(record) \
                    or fields.get("rows") == 0 \
                    or fields.get("http_status") == 404 \
                    or _label(record) == "NOT_FOUND"
                is_completed = str(fields.get("event") or "").endswith(
                    "_completed")
                if is_absence and is_completed \
                        and record.get("resource_id"):
                    # Absence linkage (see docstring): the subject's
                    # own lookup returned nothing under this id.
                    copy = dict(record)
                    copy["_trace_linked"] = True
                    copy["_trace_linked_absence"] = True
                    linked.append(copy)
                    joins.append({"file": source_file, "trace": trace,
                                  "resource": record["resource_id"],
                                  "kind": "absence"})
                    continue
                if not positive or not record.get("resource_id"):
                    continue
                copy = dict(record)
                copy["_trace_linked"] = True
                linked.append(copy)
                joins.append({"file": source_file, "trace": trace,
                              "resource": record["resource_id"]})
        return linked, joins

    def build_lanes(self, subject, audit_at):
        """Horizon lanes: subject-joined records, then resource
        expansion (all records for each joined resource), filtered to
        result-bearing records at or before the cutoff, grouped by
        (raw system, resource, replica), latest by time."""
        audit_dt = parse_time(audit_at)
        joined = self.index.records_for_subject(
            user_ids=[subject["user_id"]] if subject.get("user_id") else [],
            emails=subject["emails"],
            hashes=subject["hashes"],
        )
        horizon_joined = []
        for record in joined:
            if record.get("evidence_kind") in _EXCLUDED_KINDS:
                continue
            if record.get("collection") in _EXCLUDED_COLLECTIONS:
                continue
            record_time = parse_time(record.get("record_time"))
            if record_time is None or audit_dt is None:
                continue
            if record_time <= audit_dt:
                horizon_joined.append(self._normalize_positional(record))
        trace_linked, trace_joins = self._trace_linked_records(
            subject, horizon_joined, audit_dt)
        horizon_joined = horizon_joined + trace_linked
        resources = {r["resource_id"] for r in horizon_joined
                     if r.get("resource_id")}
        expanded = list(horizon_joined)
        by_resource = self._resource_map()
        for resource in sorted(resources):
            for record in by_resource.get(resource, []):
                if record.get("evidence_kind") in _EXCLUDED_KINDS:
                    continue
                if record.get("collection") in _EXCLUDED_COLLECTIONS:
                    continue
                record_time = parse_time(record.get("record_time"))
                if record_time is None or audit_dt is None:
                    continue
                if record_time <= audit_dt and is_result_record(record):
                    expanded.append(record)
        # Deduplicate by record key (joined + expanded overlap).
        seen = set()
        unique = []
        for record in expanded:
            key = record.get("record_key") or (
                record.get("source_file_id"), record.get("locator"),
                record.get("resource_id"))
            if key in seen:
                continue
            seen.add(key)
            unique.append(record)
        grouped = {}
        for record in unique:
            if not record.get("resource_id"):
                continue
            if not is_result_record(record):
                continue
            lane_key = (record.get("system_id") or "",
                        record["resource_id"],
                        record.get("replica"))
            grouped.setdefault(lane_key, []).append(record)
        lanes = []
        for (system, resource, replica), records in sorted(
                grouped.items(),
                key=lambda item: (item[0][0], item[0][1],
                                  item[0][2] or "")):
            records.sort(key=lambda r: (
                parse_time(r.get("record_time")) or parse_time("1970-01-01T00:00:00Z"),
                r.get("source_file_id") or "", r.get("locator") or ""))
            lanes.append({
                "system": system, "resource": resource, "replica": replica,
                "records": records, "logical_system": system,
            })
        return lanes, joined, trace_joins

    def _classify_lanes(self, lanes, subject, audit_at):
        for lane in lanes:
            cohort = None
            latest_fields = (lane["records"][-1].get("fields") or {})
            cohort_value = latest_fields.get("audience_cohort")
            if cohort_value:
                cohort = self._cohort_size(cohort_value)
            verdict = classify_lane(lane["records"], subject, self.rules,
                                    audit_at, cohort_size=cohort)
            lane["verdict"] = verdict
            lane["category"] = verdict["category"]
            lane["logical_system"] = logical_system(
                lane["system"], verdict["category"], lane["resource"])
        return lanes

    def _stored_linked(self, record, subject):
        """True if the record carries a subject identifier in its
        STORED identifier sets (not only in a lookup key / correlation
        key / selector). Stored content proves ownership; a query key
        alone proves only that somebody asked."""
        identifiers = record.get("identifiers") or {}
        emails = {e.lower() for e in identifiers.get("emails", [])}
        hashes = {h.lower() for h in identifiers.get("hashes", [])}
        users = set(identifiers.get("user_ids", []))
        return bool(emails & {e.lower() for e in subject["emails"]}
                    or hashes & {h.lower() for h in subject["hashes"]}
                    or (subject.get("user_id") and subject["user_id"] in users))

    def _observed_ids(self, joined, lanes, audit_at, subject,
                      requested_at=None):
        """Time-filtered, identifier-joined canonical ids.

        Account ids (the account-slot discipline): an id qualifies
        only if it is STORED-linked to the subject, or observed at/after
        the deletion request (audit-sweep observation). A stale
        pre-request lookup naming an account id is a decoy, not an
        account: it proves nothing was stored under that id for this
        subject. Audit ids: only retained-valid audit lanes (presence
        must be state-proved, not claim-proved).
        """
        audit_dt = parse_time(audit_at)
        request_dt = parse_time(requested_at) if requested_at else None
        account_ids = set()
        for record in joined:
            if record.get("evidence_kind") in _EXCLUDED_KINDS:
                continue
            fields = record.get("fields") or {}
            if str(fields.get("event") or "").endswith("_started"):
                continue
            record_time = parse_time(record.get("record_time"))
            if record_time is None or audit_dt is None:
                continue
            if record_time > audit_dt:
                continue
            logical = logical_system(record.get("system_id") or "")
            if logical == "account_service" and record.get("resource_id"):
                stored = self._stored_linked(record, subject)
                sweep = request_dt is not None and record_time >= request_dt
                if stored or sweep:
                    account_ids.add(record["resource_id"])
        audit_ids = set()
        for lane in lanes:
            if lane["verdict"]["category"] == "SECURITY_AUDIT_LOG" \
                    and lane["verdict"]["state_kind"] == "RETAINED_VALID":
                audit_ids.add(lane["resource"])
        # Trace-linked audit reads: a subject-keyed trace whose result
        # line reads an audit record with rows >= 1 proves that record
        # exists at the cutoff, even when no retained audit row is
        # stored for the subject. Positive reads only, flagged lanes.
        for lane in lanes:
            if lane["logical_system"] != "security_service":
                continue
            resource = lane["resource"] or ""
            if not resource.startswith("audit_record"):
                continue
            for record in lane["records"]:
                fields = record.get("fields") or {}
                rows = fields.get("rows")
                if record.get("_trace_linked") \
                        and isinstance(rows, int) and rows >= 1:
                    audit_ids.add(resource)
                    break
        # Pointer linkage (founder ruling, bitemporal linker): a
        # subject-stored record's declared cross-table pointer
        # (source_resource_id, the corpus's only declared pointer
        # field) links its target the way a foreign key would. Only
        # from stored-linked rows, only at or before the cutoff.
        pointer_joins = []
        for record in joined:
            if record.get("evidence_kind") in _EXCLUDED_KINDS:
                continue
            fields = record.get("fields") or {}
            target = fields.get("source_resource_id")
            if not target or not str(target).startswith("account_"):
                continue
            record_time = parse_time(record.get("record_time"))
            if record_time is None or audit_dt is None:
                continue
            if record_time > audit_dt:
                continue
            if not self._stored_linked(record, subject):
                continue
            account_ids.add(target)
            pointer_joins.append({"resource": target,
                                  "via": record.get("resource_id")})
        account_lane_id = None
        profile_lanes = [lane for lane in lanes
                         if lane["logical_system"] == "account_service"
                         and lane["verdict"]["category"] in (
                             "USER_PROFILE", "SECONDARY_IDENTIFIER")]
        qualified_lanes = []
        for lane in profile_lanes:
            stored = any(self._stored_linked(r, subject)
                         for r in lane["records"])
            latest_time = parse_time(lane["records"][-1].get("record_time"))
            sweep = request_dt is not None and latest_time is not None \
                and latest_time >= request_dt
            if stored or sweep:
                qualified_lanes.append(lane)
        # Lane-only ids count too: a subject-joined query's result
        # record (e.g. an absence readback) reaches the lane through
        # resource expansion even when the result line itself carries
        # no identifiers. The lane qualification test above is the
        # gate; the joined-records test above is not the only door.
        for lane in qualified_lanes:
            account_ids.add(lane["resource"])
        violating = sorted(lane["resource"] for lane in qualified_lanes
                           if lane["verdict"]["state_kind"] == "VIOLATING")
        absent = sorted(lane["resource"] for lane in qualified_lanes
                        if lane["verdict"]["state_kind"] == "ABSENT")
        if violating:
            account_lane_id = violating[0]
        elif absent:
            account_lane_id = absent[0]
        return {
            "account_ids": sorted(account_ids),
            "audit_ids": sorted(audit_ids),
            "account_lane_id": account_lane_id,
            "pointer_joins": pointer_joins,
        }

    # -- main entry ------------------------------------------------------
    def adjudicate(self, email, request_text, audit_at, requested_at=None):
        resolution = _dict_of(self.graph.resolve(email))
        intent = _dict_of(self.intent_gate.analyze(request_text))
        flags = []
        gaps = []
        internal_states = []
        gates = []
        subject = None
        lanes = []
        steps = []
        detector_hits = []
        user_id = resolution.get("user_id")

        if resolution.get("status") in ("ambiguous", "unresolved") \
                or not resolution.get("resolved", bool(user_id)):
            internal_states.append("UNRESOLVED_IDENTITY")
            gates.append(resolution.get("gate") or "GATE_1_UNRESOLVED")
            gaps.append("identity unresolvable: candidates=%s leads=%s"
                        % (resolution.get("candidates"),
                           resolution.get("leads")))
            status = "INCOMPLETE"
            payload = self._ledger_payload(
                user_id, status, steps, flags, internal_states, gates,
                gaps, detector_hits, intent)
            self.ledger.append(payload)
            return {"status": status, "steps": steps, "flags": flags,
                    "internal_states": internal_states, "gates": gates,
                    "gaps": gaps, "detector_hits": detector_hits,
                    "ledger_entry": payload}

        subject = _subject_dict(self.graph.subject(user_id))
        detector_hits.extend(detect_intent_language(intent))
        decision = intent.get("decision")
        if decision == "NOT_APPLICABLE":
            status = "NOT_APPLICABLE"
            payload = self._ledger_payload(
                user_id, status, steps, flags, internal_states, gates,
                gaps, detector_hits, intent)
            self.ledger.append(payload)
            return {"status": status, "steps": steps, "flags": flags,
                    "internal_states": internal_states, "gates": gates,
                    "gaps": gaps, "detector_hits": detector_hits,
                    "ledger_entry": payload}
        if decision == "UNKNOWN_INTENT":
            status = intent.get("projected_output") or "NOT_APPLICABLE"
            flags.append("FORCED_PROJECTION")
            internal_states.append("UNKNOWN_INTENT")
            internal_states.append("FORCED_PROJECTION")
            payload = self._ledger_payload(
                user_id, status, steps, flags, internal_states, gates,
                gaps, detector_hits, intent)
            self.ledger.append(payload)
            return {"status": status, "steps": steps, "flags": flags,
                    "internal_states": internal_states, "gates": gates,
                    "gaps": gaps, "detector_hits": detector_hits,
                    "ledger_entry": payload}

        lanes, joined, trace_joins = self.build_lanes(subject, audit_at)
        lanes = self._classify_lanes(lanes, subject, audit_at)
        for lane in lanes:
            gaps.extend(lane["verdict"].get("gap_notes", []))
        detector_hits.extend(detect_identity_multiplicity(lanes, subject))
        detector_hits.extend(detect_replication(lanes, subject))
        detector_hits.extend(detect_writer_graph(lanes, subject))
        detector_hits.extend(detect_retention_minimisation(lanes, subject))
        detector_hits.extend(detect_multimodal(lanes, subject))
        detector_hits.extend(detect_analytics_attribution(lanes, subject))
        detector_hits.extend(detect_shared_control(
            lanes, subject, subjects_for_resource=self._subjects_for_resource))
        for hit in detector_hits:
            if hit["signal"] == "SHARED_CONTROL":
                internal_states.append("SHARED_CONTROL_DRIFT")
            if hit["signal"] in ("REPLICA_DIVERGENCE", "REPLICA_ONLY_RECORD"):
                internal_states.append("UNVERIFIED_REPLICA")
            if hit["signal"] == "CACHE_SIGNAL":
                internal_states.append("CACHE_SIGNAL")

        limiter = intent.get("limiter") or ""
        findings, _ = build_findings(lanes)
        if limiter in ("subset_only", "keep_subset") or (
                isinstance(limiter, str) and limiter.startswith("keep_")):
            # Honour the narrowing: never widen a subset deletion into
            # a full-account deletion. Profile findings leave scope.
            findings = [f for f in findings
                        if f["category"] != "USER_PROFILE"]
            flags.append("LIMITER_HONOURED")
            gaps.append("limiter %s honoured: full-account profile scope "
                        "excluded" % limiter)
        remediations = build_remediations(findings)
        observed = self._observed_ids(joined, lanes, audit_at, subject,
                                      requested_at)
        for pointer_join in observed.get("pointer_joins", []):
            gaps.append("pointer-linked %s via %s"
                        % (pointer_join["resource"],
                           pointer_join["via"]))
        # NOTE: the limiter narrows DELETION scope (profile findings
        # are filtered above), never verification scope. A subset case
        # still verifies its account's absence (sample case_06 proves
        # it: subset request, account_006 VERIFY_RECORD_ABSENT
        # expected). Clearing account_ids here used to suppress that
        # verification; the findings filter alone implements the
        # limiter, and verification asserts a state, performs nothing.

        unknown_shapes = [lane for lane in lanes
                          if lane["verdict"]["state_kind"] == "UNKNOWN_SHAPE"]
        if unknown_shapes:
            internal_states.append("UNVERIFIED_STORE")
            gaps.append("unknown-shape lanes block COMPLETE: "
                        + ",".join(sorted(lane["resource"]
                                          for lane in unknown_shapes)))
        if not observed["audit_ids"]:
            internal_states.append("RETAINED_AUDIT_GAP")
        cache_signals = [lane for lane in lanes
                         if lane["verdict"]["state_kind"] == "CACHE_SIGNAL"]
        if cache_signals:
            internal_states.append("CACHE_SIGNAL")

        if findings:
            status = "INCOMPLETE"
            verifications, ver_flags = build_verifications(
                findings, remediations, lanes, observed)
            flags.extend(ver_flags)
            steps = sort_steps(findings + remediations + verifications)
            narrative = causal_narrative(remediations)
        elif unknown_shapes:
            status = "INCOMPLETE"
            steps = []
            narrative = []
        else:
            status = "COMPLETE"
            citations = {}
            for lane in lanes:
                citing = choose_citation(lane["records"], lane["verdict"])
                if citing is not None:
                    citations[(lane["logical_system"], lane["resource"])] = \
                        citing.get("source_file_id") or ""
                    # Audit-slot alias (validator-found bug, 4 main
                    # cases): build_complete_verifications looks the
                    # audit citation up under ("security_service",
                    # resource), but an audit lane's logical_system is
                    # its record's service (e.g. a downstream
                    # delivery readback of a SECURITY_AUDIT_LOG row).
                    # Without this alias the COMPLETE audit step
                    # emitted evidence_id "" -- uncited, against the
                    # contract's "evidence-backed verification" rule.
                    if lane["verdict"]["category"] == "SECURITY_AUDIT_LOG":
                        citations[("security_service",
                                   lane["resource"])] = \
                            citing.get("source_file_id") or ""
            verifications, ver_flags = build_complete_verifications(
                lanes, observed, citations)
            flags.extend(ver_flags)
            if any(lane["verdict"]["category"] == "BACKUP_ARCHIVE"
                   and lane["verdict"]["state_kind"] == "COMPLIANT_TREATED"
                   for lane in lanes):
                internal_states.append("RETAINED_BLOCKED_RECHECK_DUE")
            steps = sort_steps(verifications)
            narrative = []
        payload = self._ledger_payload(
            user_id, status, steps, flags, internal_states, gates, gaps,
            detector_hits, intent, narrative=narrative,
            findings=[{k: f[k] for k in ("phase", "system_id", "resource_id",
                                         "operation", "state", "evidence_id")}
                      for f in findings],
            trace_joins=trace_joins)
        self.ledger.append(payload)
        return {"status": status, "steps": steps, "flags": flags,
                "internal_states": sorted(set(internal_states)),
                "gates": gates, "gaps": gaps,
                "detector_hits": detector_hits,
                "trace_joins": trace_joins,
                "causal_narrative": narrative if findings else [],
                "ledger_entry": payload}

    def _ledger_payload(self, user_id, status, steps, flags,
                        internal_states, gates, gaps, detector_hits,
                        intent, narrative=None, findings=None,
                        trace_joins=None):
        triplet = build_triplet(status, findings or [], internal_states, gaps)
        return {
            "user_id": user_id,
            "status": status,
            "steps": steps,
            "flags": sorted(set(flags)),
            "internal_states": sorted(set(internal_states)),
            "gates": gates,
            "gaps": sorted(set(gaps)),
            "detector_hits": detector_hits,
            "trace_joins": trace_joins or [],
            "intent": {k: intent.get(k) for k in (
                "decision", "projected_output", "forced_projection",
                "language", "limiter")},
            "causal_narrative": narrative or [],
            "triplet": triplet,
        }
