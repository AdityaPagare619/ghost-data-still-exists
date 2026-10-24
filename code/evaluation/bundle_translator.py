#!/usr/bin/env python3
"""Unit 4 test harness ONLY — bundle-to-engine translator.

Converts an abstract Unit 4 bundle (adversarial fixture or mutation
bundle: records with categories/fields/states + subject identifiers)
into runnable Unit 3 engine inputs: a synthetic Unit 1 index directory
(built with Unit 1's OWN IndexBuilder record factory, so no record
field is hand-crafted), a synthetic Unit 2 identity graph (via
IdentityGraph.from_rows), and a request text.

NEVER SHIPPED ENGINE CODE. It imports Units 1-3 only as the system
under test, exactly like phase2/verification/run_unit4_on_unit3.py.

FAITHFULNESS RULES (violations are bugs, not conveniences):
- Translator inputs are BUNDLE FIELDS ONLY (records/flows/backups/
  subject/title/request_summary). Expected statuses and step patterns
  are NEVER read here; grading happens in adversarial.py /
  mutations.py, not in this file.
- Every synthetic record's resource_id is a bundle resource_label, so
  the adversarial allowlist check (no invented ids) stays meaningful.
- A bundle element with no faithful mapping raises Untranslatable
  with an exact reason. It is never approximated or hand-completed.
- System/collection/field shapes replicate the REAL corpus shapes the
  engine reads (verified against unit1/index/records.jsonl, e.g.
  tombstone state rows carry system identity_service, collection
  deleted_customer_references, fields account_status/email/email_hash/
  name/phone/resource_id/subject_reference).
- Synthetic subjects use user_9000+ ids (SUBJECT_REF_RE is user_\\d+;
  the real corpus stays below user_9000) and example.test emails, so
  no synthetic identifier can collide with a real subject.
- Request texts are canonical sentences, chosen ONLY from the bundle's
  own description: a deletion sentence, a Spanish deletion sentence
  (language_swap), or a marketing-only sentence (only when the bundle
  title/summary says marketing-only). The intent gate decides; the
  translator never forces a decision.
- Flows/backups listed in a case bundle belong to that case's subject
  by construction, so they carry subject_selector / subject_reference
  joins. A flow whose bundle says subject_selector_matches is false
  would be untranslatable (no subject join, engine could not see it).
- Ledger flags reported to the graders are the UNION of the engine
  outcome's flags and internal_states, because the engine's ledger
  entry carries both fields and the expectations phrase requirements
  as "flag names the engine's ledger must carry".
- The shared-control encoding (MUT-07): a globally-disabled restore
  filter is encoded as a second synthetic subject holding a record on
  the SAME backup resource (earlier timestamp, so the case subject's
  record stays the lane's latest). detect_shared_control fires only
  when subjects_for_resource returns other subjects; a single-subject
  index cannot express "shared" at all, so without this encoding the
  mutation would be ungradeable-by-construction, not failed.

TIMES: fixed cutoff audit_at 2026-09-15T12:00:00Z, requested_at
2026-09-01T00:00:00Z, record time 2026-09-10T00:00:00Z (all records
at/before the cutoff, at/after the request, so sweep qualification
never decides a synthetic outcome on its own).
"""

import argparse
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

PHASE2 = Path.home() / "workspace/orchestra/phase2"
REPO = Path.home() / "workspace/orchestra/repo"
DATASET = REPO / "dataset"
# The system under test is the SHIPPED engine in code/, never the
# phase2 staging copies (which predate the bitemporal linker fix).
CODE = Path(__file__).resolve().parent.parent
import os as _os
SYNTH_ROOT = Path(_os.environ.get(
    "GHOST_SYNTH_ROOT",
    str(Path(__file__).resolve().parent / "synth_indexes_tmp")))

AUDIT_AT = "2026-09-15T12:00:00Z"
REQUESTED_AT = "2026-09-01T00:00:00Z"
RECORD_TIME = "2026-09-10T00:00:00Z"
EARLIER_TIME = "2026-09-09T00:00:00Z"
RETENTION_FUTURE = "2033-12-31T00:00:00Z"
RETENTION_PAST = "2026-01-01T00:00:00Z"

EN_DELETION = "Please delete my account and all of my personal data."
ES_DELETION = "Por favor, elimina mi cuenta y todos mis datos personales."
MARKETING_ONLY = ("Please stop sending me promotional emails, but do not "
                  "delete my account or any of my data.")


class Untranslatable(Exception):
    """A bundle element has no faithful engine-input mapping."""


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def load_units():
    """Load the SHIPPED code/ modules (system under test, not harness
    logic). identity_intent.py carries both IdentityGraph and
    IntentGate (the port concatenated the two Unit 2 files)."""
    sys.path.insert(0, str(CODE))
    units = {}
    units["index_mod"] = load_module("tr_unit1_index",
                                     CODE / "indexer.py")
    units["identity_mod"] = load_module("tr_unit2_identity",
                                        CODE / "identity_intent.py")
    units["intent_mod"] = load_module("tr_unit2_intent",
                                      CODE / "identity_intent.py")
    units["rules_mod"] = load_module("tr_unit3_rules", CODE / "rules.py")
    units["engine_mod"] = load_module("tr_unit3_engine", CODE / "engine.py")
    return units


def sha256_hex(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class CaseBuilder:
    """Builds one synthetic case: index records + identity rows."""

    def __init__(self, units, case_id, subject_email, user_id,
                 historical=(), phone="5550101001"):
        self.units = units
        self.case_id = case_id
        self.email = subject_email.lower()
        self.user_id = user_id
        self.historical = [h.lower() for h in historical]
        self.phone = phone
        self.builder = units["index_mod"].IndexBuilder()
        self.counter = 0
        self.identity_rows = [{
            "user_id": user_id, "email": subject_email,
            "name": "", "phone": phone,
            "email_hash": sha256_hex(subject_email.lower()),
        }]
        self.audit_rows = []
        if self.historical:
            # One audit row per historical form, chaining old -> new
            # in event-time order (Unit 2's from_rows chain logic).
            prev = self.historical[0]
            for idx, old in enumerate(self.historical):
                new = self.historical[idx + 1] if idx + 1 < len(self.historical) else subject_email
                self.audit_rows.append({
                    "user_id": user_id,
                    "audit_id": "audit_synth_chain_%d" % (idx + 1),
                    "event_time": "2026-08-0%dT00:00:00Z" % (idx + 1),
                    "field_name": "email",
                    "old_value": old, "new_value": new,
                })
                prev = new

    def add(self, *, system_id, collection, resource_id, fields,
            evidence_kind="state", replica=None, record_time=RECORD_TIME):
        self.counter += 1
        self.builder.add(
            source_file_id="evidence_synth",
            source_path="synthetic/%s.json" % self.case_id,
            locator="record-%03d" % self.counter,
            system_id=system_id, collection=collection,
            resource_id=resource_id, record_time=record_time,
            time_source="row:observed_at", evidence_kind=evidence_kind,
            state_label="", fields=dict(fields, observed_at=record_time),
            replica=replica)

    # -- record shapes (one per bundle category) --------------------
    def profile_absent(self, label):
        self.add(system_id="account_service",
                 collection="customer_profiles", resource_id=label,
                 fields={"email": self.email, "rows": 0,
                         "http_status": 404})

    def profile_present(self, label, replica=None, system_id="account_service"):
        self.add(system_id=system_id,
                 collection="customer_profiles", resource_id=label,
                 fields={"full_name": "Synthetic Subject",
                         "email": self.email, "account_status": "ACTIVE"},
                 replica=replica)

    def tombstone(self, label, fields_present, fields_null,
                  identifier_fields=()):
        fields = {"account_status": "DELETED",
                  "subject_reference": self.user_id,
                  "resource_id": label}
        values = {
            "user_id": self.user_id,
            "email_hash": sha256_hex(self.email),
            "phone": self.phone,
            "name": None, "email": None,
        }
        # A novel field the bundle asserts carries an identifier maps
        # to the subject email itself — that IS what the bundle asserts.
        # A novel field without such an assertion is untranslatable.
        for name in identifier_fields:
            values[name] = self.email
        for name in fields_present:
            if name not in values:
                raise Untranslatable(
                    "%s: tombstone field %r has no synthetic value mapping"
                    % (label, name))
            fields[name] = values[name]
        for name in fields_null:
            if name not in values:
                raise Untranslatable(
                    "%s: tombstone null field %r has no synthetic value "
                    "mapping" % (label, name))
            fields[name] = None
        self.add(system_id="identity_service",
                 collection="deleted_customer_references",
                 resource_id=label, fields=fields)

    def analytics_lookup(self, label, join_key, rows):
        if join_key not in ("old_email_hash", "email_hash"):
            raise Untranslatable(
                "%s: analytics join_key %r is not a subject hash form"
                % (label, join_key))
        if not self.historical and join_key == "old_email_hash":
            raise Untranslatable(
                "%s: join_key old_email_hash but subject has no "
                "historical form" % label)
        key_hash = (sha256_hex(self.historical[0])
                    if join_key == "old_email_hash"
                    else sha256_hex(self.email))
        self.add(system_id="analytics_platform",
                 collection="customer_analytics_profiles",
                 resource_id=label,
                 fields={"correlation_key": key_hash, "rows": rows,
                         "email_opt_in": True,
                         "event": "contact_lookup_completed"})

    def audit_record(self, label, fields_present, within_retention):
        fields = {"user_id": self.user_id,
                  "event_code": "SUBJECT_REQUEST_AUDITED",
                  "time": RECORD_TIME,
                  "retention_until": (RETENTION_FUTURE if within_retention
                                      else RETENTION_PAST)}
        for name in fields_present:
            if name == "email":
                fields["email"] = self.email
            elif name in ("resource_id", "user_id", "event_code", "time",
                          "retention_until"):
                pass  # structural fields, already set / implicit
            else:
                raise Untranslatable(
                    "%s: audit field %r has no synthetic value mapping"
                    % (label, name))
        self.add(system_id="security_service",
                 collection="security_audit_records", resource_id=label,
                 fields=fields)

    def marketing(self, label):
        self.add(system_id="marketing_service",
                 collection="marketing_profiles", resource_id=label,
                 fields={"email": self.email, "account_status": "ACTIVE"})

    def support_message(self, label, shared_context):
        text = ("Please help with my order. My email is %s."
                % self.email)
        if shared_context:
            text += (" My friend other.person@example.test also has an "
                     "issue with her order that should be preserved.")
        self.add(system_id="support_platform",
                 collection="support_conversations", resource_id=label,
                 fields={"message_text": text})

    def unknown_shape(self, label, fields_present):
        fields = {}
        for name in fields_present:
            if name == "novel_identifier_field":
                fields[name] = self.email
            else:
                raise Untranslatable(
                    "%s: unknown-shape field %r has no synthetic value "
                    "mapping" % (label, name))
        self.add(system_id="novel_service", collection="novel_store",
                 resource_id=label, fields=fields)

    def flow(self, label, enabled, mode):
        self.add(system_id="connector_service", collection="connectors",
                 resource_id=label,
                 fields={"enabled": bool(enabled),
                         "subject_selector": self.email,
                         "mode": mode or "continuous_sync"})

    def backup(self, label, restore_allowed, record_time=RECORD_TIME):
        self.add(system_id="backup_service", collection="backup_catalog",
                 resource_id=label,
                 fields={"subject_reference": self.user_id,
                         "restore_allowed": bool(restore_allowed)},
                 record_time=record_time)

    # -- bundle translation ------------------------------------------
    def translate_record(self, record):
        label = record.get("resource_label")
        if not label:
            raise Untranslatable("record without resource_label: %r"
                                 % (record,))
        category = record.get("category")
        if category == "USER_PROFILE":
            if record.get("state") == "ABSENT":
                self.profile_absent(label)
            elif record.get("state") == "PRESENT":
                replica = record.get("replica")
                system = ("account_failover_replica"
                          if replica == "failover" else "account_service")
                self.profile_present(label, replica=replica, system_id=system)
            else:
                raise Untranslatable(
                    "%s: USER_PROFILE state %r unmapped"
                    % (label, record.get("state")))
        elif category == "ACCOUNT_TOMBSTONE":
            known = {"user_id", "email_hash", "phone", "name", "email"}
            novel = [f for f in record.get("fields_present", [])
                     if f not in known]
            if novel and not record.get("novel_field_carries_identifier"):
                raise Untranslatable(
                    "%s: novel tombstone field(s) %r with no assertion "
                    "about what they carry" % (label, novel))
            self.tombstone(label, record.get("fields_present", []),
                           record.get("fields_null", []),
                           identifier_fields=novel)
        elif category == "ANALYTICS_LOOKUP":
            self.analytics_lookup(label, record.get("join_key"),
                                  record.get("rows", 1))
        elif category == "SECURITY_AUDIT_LOG":
            self.audit_record(label, record.get("fields_present", []),
                              record.get("within_retention", True))
        elif category == "MARKETING_PROFILE":
            self.marketing(label)
        elif category == "SUPPORT_MESSAGE":
            self.support_message(label, bool(record.get("shared_context")))
        elif category == "UNKNOWN":
            if record.get("classifiable", True):
                raise Untranslatable(
                    "%s: UNKNOWN category marked classifiable — no "
                    "unknown-shape mapping applies" % label)
            self.unknown_shape(label, record.get("fields_present", []))
        else:
            raise Untranslatable(
                "%s: bundle category %r has no engine-input mapping"
                % (label, category))

    def translate_bundle(self, bundle):
        for record in bundle.get("records", []):
            self.translate_record(record)
        for flow in bundle.get("flows", []):
            label = flow.get("resource_label")
            if not label:
                raise Untranslatable("flow without resource_label: %r"
                                     % (flow,))
            if flow.get("subject_selector_matches") is False:
                raise Untranslatable(
                    "%s: flow does not match the subject selector — no "
                    "subject join exists for the engine to see it" % label)
            self.flow(label, flow.get("enabled", False),
                      flow.get("mode"))
        for backup in bundle.get("backups", []):
            label = backup.get("resource_label")
            if not label:
                raise Untranslatable("backup without resource_label: %r"
                                     % (backup,))
            self.backup(label, backup.get("restore_allowed"))
        controls = bundle.get("controls") or {}
        if controls.get("restore_filter") == "disabled_globally":
            if not bundle.get("backups"):
                raise Untranslatable(
                    "globally-disabled restore filter with no backup "
                    "record: nothing expresses the shared control")
            # Shared-control encoding (see module docstring): a second
            # subject on the same backup resource, earlier timestamp.
            self.builder.add(
                source_file_id="evidence_synth",
                source_path="synthetic/%s.json" % self.case_id,
                locator="record-shared-control",
                system_id="backup_service", collection="backup_catalog",
                resource_id=bundle["backups"][0]["resource_label"],
                record_time=EARLIER_TIME, time_source="row:observed_at",
                evidence_kind="state", state_label="",
                fields={"subject_reference": "user_9002",
                        "restore_allowed": False,
                        "observed_at": EARLIER_TIME})
            self.identity_rows.append({
                "user_id": "user_9002", "email": "other.subject@example.test",
                "name": "", "phone": "5550101002",
                "email_hash": sha256_hex("other.subject@example.test"),
            })
        elif controls and any(v not in ("healthy", None)
                              for v in controls.values()):
            raise Untranslatable(
                "unhandled non-healthy controls: %r" % (controls,))

    def write_index(self):
        out_dir = SYNTH_ROOT / self.case_id
        out_dir.mkdir(parents=True, exist_ok=True)
        records = sorted(
            self.builder.records,
            key=lambda r: (r["source_file_id"], r["source_path"],
                           r["locator"], r["resource_id"] or "",
                           r["record_key"]))
        indexes = self.units["index_mod"].build_join_indexes(records)
        rowsets = [
            {"source_file_id": fid, "system_id": system,
             "collection": collection,
             "resource_ids": sorted(resources)}
            for (fid, system, collection), resources
            in sorted(self.builder.rowsets.items())]
        version = getattr(self.units["index_mod"], "VERSION", "synthetic")
        manifest = {
            "version": version, "record_count": len(records),
            "file_count": 1,
            "files": {"synthetic/%s.json" % self.case_id: {
                "kind": "synthetic", "records": len(records),
                "skipped_lines": 0, "time_sources": {},
                "evidence_kinds": {}}},
            "rowset_count": len(rowsets),
            "index_sizes": {name: len(values)
                            for name, values in indexes.items()},
            "assumptions": ["synthetic bundle translation"],
            "sidecar_path": None,
        }
        (out_dir / "records.jsonl").write_text(
            "".join(json.dumps(r, sort_keys=True, ensure_ascii=False) + "\n"
                    for r in records), encoding="utf-8")
        (out_dir / "snapshots.jsonl").write_text(
            "".join(json.dumps(s, sort_keys=True, ensure_ascii=False) + "\n"
                    for s in rowsets), encoding="utf-8")
        (out_dir / "indexes.json").write_text(
            json.dumps(indexes, sort_keys=True, ensure_ascii=False, indent=1)
            + "\n", encoding="utf-8")
        (out_dir / "manifest.json").write_text(
            json.dumps(manifest, sort_keys=True, ensure_ascii=False, indent=1)
            + "\n", encoding="utf-8")
        return out_dir


def pick_request_text(bundle, title="", summary=""):
    """Request text from bundle description ONLY, never from expected."""
    request = bundle.get("request") or {}
    language = request.get("language", "en")
    if request.get("intent") and request["intent"] != "deletion":
        raise Untranslatable(
            "bundle request intent %r has no request-text mapping"
            % (request["intent"],))
    if language == "es":
        return ES_DELETION
    if language != "en":
        raise Untranslatable(
            "bundle request language %r has no verified request text"
            % (language,))
    blob = "%s %s" % (title, summary)
    if "marketing-only" in blob or "marketing only" in blob:
        return MARKETING_ONLY
    return EN_DELETION


def run_case(units, case_id, bundle, title="", summary=""):
    """Translate one bundle and adjudicate it. Returns (output, info).

    output matches the grader's engine-output shape. info carries the
    translation provenance (request text, synthetic user id, index
    dir) for the grading report. Raises Untranslatable, never fakes.
    """
    subject = bundle.get("subject") or {}
    identifiers = subject.get("identifiers") or []
    if not identifiers:
        raise Untranslatable("%s: subject has no identifiers" % case_id)
    email = identifiers[0]
    # Numeric user ids keep SUBJECT_REF_RE (user_\d+) joins working.
    # ADV-01 -> user_9001, MUT-01 -> user_9101, MUT-BASE -> user_9100.
    if case_id.startswith("ADV-") and case_id[4:].isdigit():
        user_id = "user_%d" % (9000 + int(case_id[4:]))
    elif case_id.startswith("MUT-") and case_id[4:].isdigit():
        user_id = "user_%d" % (9100 + int(case_id[4:]))
    else:
        user_id = "user_9999"
    builder = CaseBuilder(units, case_id, email, user_id,
                          historical=subject.get("historical", []))
    builder.translate_bundle(bundle)
    index_dir = builder.write_index()
    request_text = pick_request_text(bundle, title, summary)
    graph = units["identity_mod"].IdentityGraph.from_rows(
        builder.identity_rows, builder.audit_rows)
    gate = units["intent_mod"].IntentGate()
    rules = units["rules_mod"].RuleBook.from_csv(
        str(DATASET / "deletion_rules.csv"))
    engine = units["engine_mod"].Engine(
        units["index_mod"].Index(str(index_dir)), rules, graph, gate)
    try:
        outcome = engine.adjudicate(email, request_text, AUDIT_AT,
                                    REQUESTED_AT)
        crashed = False
        crash_reason = ""
    except Exception as exc:  # unknown-case protocol: crash is a result
        outcome = {"status": None, "steps": [], "flags": [],
                   "internal_states": []}
        crashed = True
        crash_reason = "%s: %s" % (type(exc).__name__, exc)
    ledger_flags = sorted(set(outcome.get("flags", []))
                          | set(outcome.get("internal_states", [])))
    output = {
        "deletion_status": outcome.get("status"),
        "steps": outcome.get("steps", []),
        "ledger_flags": ledger_flags,
        "crashed": crashed,
    }
    info = {
        "request_text": request_text,
        "request_email": email,
        "user_id": user_id,
        "index_dir": str(index_dir),
        "audit_at": AUDIT_AT,
        "crash_reason": crash_reason,
    }
    return output, info


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Translate bundles to engine inputs and adjudicate.")
    parser.add_argument("--adv-dir", default=None)
    parser.add_argument("--mutations-dir", default=None,
                        help="dir with base.json + MUT-*.json from "
                             "mutations.py --generate-out")
    parser.add_argument("--adv-out", default=None)
    parser.add_argument("--mut-out", default=None)
    parser.add_argument("--provenance-out", default=None)
    args = parser.parse_args(argv)
    units = load_units()
    adv_outputs, mut_outputs, provenance = [], [], {}
    if args.adv_dir:
        import os
        for name in sorted(os.listdir(args.adv_dir)):
            if not name.endswith(".json"):
                continue
            with open(os.path.join(args.adv_dir, name),
                      encoding="utf-8") as handle:
                obj = json.load(handle)
            adv_id = obj["adversarial_id"]
            try:
                output, info = run_case(
                    units, adv_id, obj["bundle"], obj.get("title", ""),
                    obj.get("request_summary", ""))
                output["adversarial_id"] = adv_id
                adv_outputs.append(output)
                provenance[adv_id] = info
            except Untranslatable as exc:
                provenance[adv_id] = {"untranslatable": str(exc)}
                print("UNTRANSLATABLE %s: %s" % (adv_id, exc))
    if args.mutations_dir:
        import os
        base_path = os.path.join(args.mutations_dir, "base.json")
        with open(base_path, encoding="utf-8") as handle:
            base = json.load(handle)
        base_out, base_info = run_case(units, "MUT-BASE", base)
        provenance["MUT-BASE"] = base_info
        for name in sorted(os.listdir(args.mutations_dir)):
            if not name.startswith("MUT-") or not name.endswith(".json"):
                continue
            mid = name[:-len(".json")]
            with open(os.path.join(args.mutations_dir, name),
                      encoding="utf-8") as handle:
                mutated = json.load(handle)
            try:
                mut_out, mut_info = run_case(units, mid, mutated)
                mut_outputs.append({
                    "mutation_id": mid,
                    "base_status": base_out["deletion_status"],
                    "mutated_status": mut_out["deletion_status"],
                    "ledger_flags": mut_out["ledger_flags"],
                    "invalidated": False,
                    "crashed": mut_out["crashed"],
                })
                provenance[mid] = mut_info
            except Untranslatable as exc:
                provenance[mid] = {"untranslatable": str(exc)}
                print("UNTRANSLATABLE %s: %s" % (mid, exc))
    if args.adv_out:
        with open(args.adv_out, "w", encoding="utf-8") as handle:
            json.dump(adv_outputs, handle, indent=2, sort_keys=True)
    if args.mut_out:
        with open(args.mut_out, "w", encoding="utf-8") as handle:
            json.dump(mut_outputs, handle, indent=2, sort_keys=True)
    if args.provenance_out:
        with open(args.provenance_out, "w", encoding="utf-8") as handle:
            json.dump(provenance, handle, indent=2, sort_keys=True)
    print("adversarial outputs: %d, mutation outputs: %d"
          % (len(adv_outputs), len(mut_outputs)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
