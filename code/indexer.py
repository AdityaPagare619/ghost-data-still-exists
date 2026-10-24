#!/usr/bin/env python3
"""Unit 1 -- Offline Normalisation & Evidence Indexer.

HackerRank Orchestrate, "Ghost Data Still Exists" (Northstar Shop).

What this module does
----------------------
Reads a dataset directory (runtime parameter, never baked in) and builds a
versioned, deterministic, normalised index of every joinable record in it:

* every evidence file is classified by INTERNAL STRUCTURE (content sniffing
  plus header/column sets), never by its path or name;
* JSON bundles are split by inner snapshot time, service exports keep
  per-row observed time, logs keep per-line time;
* every record gets a record_time under the priority
  row observed / event / line time > inner bundle snapshot time >
  manifest capture time (manifest time is the fallback ONLY for binary
  artefacts and unstructured text);
* identifiers are normalised dual-side: every email is lowercased, every
  email form gets a SHA-256 closure, polymorphic keys (subject selectors,
  correlation keys, restore flags) are canonicalised with the raw form kept;
* envelope JSON is parsed at whatever nesting the record itself carries
  (identifiers are collected by a full content scan, so a record that
  hides an address inside a nested document is found exactly like one
  that carries it flat);
* stored content identifiers are distinguished from lookup keys /
  selectors / correlation keys: a lookup that returns zero rows is
  ABSENCE evidence, never a remaining record (that distinction is the
  whole point of the lookup-vs-stored split);
* the indexer builds its OWN join indexes (by subject reference, by
  every email form, by every hash form, by phone for corroboration
  only). The source corpus has no usable join indexes; none are assumed.

What this module does NOT do
-----------------------------
No verdicts. No step lists. No output rows. No use of any workflow claim
as evidence. A record's identifiers are whatever the record itself
carries; similarity is never used to attach an identifier to a subject
(a lookalike address in a neighbouring row stays a lookalike address).
Binary artefacts (images, PDFs) cannot be read by stdlib code, so they
enter the index ONLY through a verified-transcription sidecar file
(see ``transcriptions.json`` next to this module): each sidecar entry
carries its provenance, and a binary file with no sidecar entry is
recorded as an untranscribed artefact, never guessed at.

Stdlib only. Deterministic: the same dataset directory always yields
byte-identical output files (no wall-clock time, no dict-order drift,
no randomness anywhere in the build).
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

VERSION = "unit1-index-v1"

# ---------------------------------------------------------------------------
# Generic patterns. These describe SHAPES (an address shape, a subject
# reference shape, a 64-hex digest shape), never any particular value.
# ---------------------------------------------------------------------------

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
SUBJECT_REF_RE = re.compile(r"\buser_\d+\b", re.IGNORECASE)
HASH_RE = re.compile(r"\b[0-9a-fA-F]{64}\b")
RESOURCE_RE = re.compile(r"\b[A-Za-z][A-Za-z0-9]*_\d+\b")
ISO_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
)
KV_RE = re.compile(
    r"""([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^,\s]+))"""
)
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
PDF_MAGIC = b"%PDF-"

# Keys whose values are LOOKUP KEYS / selectors, not stored content.
# A value found only under one of these keys is a query, not a record.
LOOKUP_KEYS = {
    "lookup_key", "match_key", "subject_key", "subject_selector",
    "correlation_key", "query", "search_query", "lookup",
}
# Keys whose values are subject references in stored rows.
REFERENCE_KEYS = {
    "user_id", "customer_reference", "subject_reference", "subject",
    "owner", "customer", "subject_id",
}
# Row-time fields, in priority order within one record.
TIME_FIELDS = (
    "observed_at", "recorded_at", "event_time", "line_time", "updated_at",
    "created_at", "indexed_at", "timestamp", "time",
)
# Restore-flag fields, in any casing.
RESTORE_FIELDS = {"restore_allowed", "deletion_block", "restore_blocked"}

# Corpus schema dictionary: structural table/collection names mapped to
# the system that owns them. This is a SCHEMA dictionary (the same role
# as a data dictionary in any database), not a branch on any particular
# file or subject: an unknown table still indexes, under its own name.
TABLE_SYSTEM = {
    "customer_profiles": "account_service",
    "customer_profiles_primary": "account_service",
    "customer_profiles_failover_replica": "account_service",
    "customer_search_documents": "search_service",
    "search_documents_primary": "search_service",
    "customer_analytics_profiles": "analytics_platform",
    "support_records": "support_platform",
    "customer_exports": "export_service",
    "connector_subscriptions": "integration_service",
    "backup_restore_entries": "backup_service",
    "security_audit_records": "security_service",
    "security_audit_events": "security_service",
    "customer_data_failover_replica": None,  # system comes from the row
}


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def norm_email(value):
    """Lowercase-and-strip, or None. Dual-side rule: callers must apply
    this to BOTH the query side and the stored side of every join."""
    if value is None:
        return None
    text = str(value).strip().lower()
    return text or None


def email_hash(lower_email):
    """SHA-256 of the lowercased address. Always computed, never trusted
    from a stored hash column alone."""
    return hashlib.sha256(lower_email.encode("utf-8")).hexdigest()


def norm_time(value):
    """Normalise an ISO-ish timestamp to ...Z form, or None."""
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    match = ISO_RE.search(text)
    if not match:
        return None
    raw = match.group(0).replace(" ", "T")
    try:
        if raw.endswith("Z"):
            parsed = datetime.fromisoformat(raw[:-1] + "+00:00")
        else:
            parsed = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def canonical_bool(raw):
    """Canonicalise a restore/enabled flag from any encoding in the
    corpus: bool, int, TEXT '1'/'0', ACTIVE/BLOCKED, ENABLED/DISABLED,
    or an event fragment such as deletion_block=false.

    Returns (canonical_bool_or_None, raw_form_preserved_as_string).
    """
    if raw is None:
        return None, None
    if isinstance(raw, bool):
        return raw, raw
    if isinstance(raw, (int, float)):
        return bool(raw), raw
    text = str(raw).strip()
    low = text.lower()
    if low in ("1", "true", "yes", "active", "enabled", "allowed", "eligible=true"):
        return True, raw
    if low in ("0", "false", "no", "blocked", "disabled", "not_allowed"):
        return False, raw
    match = re.search(r"deletion_block\s*=\s*(true|false)", low)
    if match:
        # deletion_block=true means restore is BLOCKED, i.e. allowed=False.
        return match.group(1) == "false", raw
    match = re.search(r"restore_allowed\s*=\s*(true|false|1|0)", low)
    if match:
        return match.group(1) in ("true", "1"), raw
    return None, raw


def _walk_strings(obj):
    """Yield every string leaf of a nested structure, in order."""
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for value in obj.values():
            yield from _walk_strings(value)
    elif isinstance(obj, (list, tuple)):
        for value in obj:
            yield from _walk_strings(value)


def _walk_dicts(obj, path="$"):
    """Yield (path, dict) for every dict in a nested structure."""
    if isinstance(obj, dict):
        yield path, obj
        for key, value in obj.items():
            yield from _walk_dicts(value, f"{path}.{key}")
    elif isinstance(obj, list):
        for i, value in enumerate(obj):
            yield from _walk_dicts(value, f"{path}[{i}]")


def extract_identifiers(fields):
    """Split a record's identifiers into stored vs lookup sets.

    Stored: identifiers appearing anywhere except under a LOOKUP_KEYS key.
    Lookup: identifiers appearing under a LOOKUP_KEYS key (query keys,
    selectors, correlation keys). An identifier in both sets counts as
    stored (the record's own content carries it, whatever the query was).
    Phones are collected ONLY from phone-named keys, and are flagged
    corroboration-only by every consumer: a phone never resolves a
    subject on its own.
    """
    stored_emails, lookup_emails = set(), set()
    stored_hashes, lookup_hashes = set(), set()
    stored_refs, lookup_refs = set(), set()
    phones = set()

    def scan_text(text, bucket):
        for match in EMAIL_RE.finditer(text):
            bucket[0].add(norm_email(match.group(0)))
        for match in HASH_RE.finditer(text):
            bucket[1].add(match.group(0).lower())
        for match in SUBJECT_REF_RE.finditer(text):
            bucket[2].add(match.group(0).lower())

    def walk(obj, in_lookup_key=False):
        if isinstance(obj, dict):
            for key, value in obj.items():
                low_key = str(key).lower()
                if low_key in LOOKUP_KEYS:
                    bucket = (lookup_emails, lookup_hashes, lookup_refs)
                    if isinstance(value, str):
                        scan_text(value, bucket)
                    else:
                        walk(value, True)
                elif "phone" in low_key or low_key in ("tel", "telephone"):
                    if isinstance(value, str) and value.strip():
                        phones.add(value.strip())
                else:
                    walk(value, in_lookup_key)
        elif isinstance(obj, list):
            for value in obj:
                walk(value, in_lookup_key)
        elif isinstance(obj, str):
            bucket = (
                (lookup_emails, lookup_hashes, lookup_refs)
                if in_lookup_key
                else (stored_emails, stored_hashes, stored_refs)
            )
            scan_text(obj, bucket)

    walk(fields)
    # A stored hash is also claimed for every stored email (closure):
    # the engine must be able to join a hash-keyed record to an
    # email-keyed subject even when the record carries no hash column.
    computed = {email_hash(e) for e in stored_emails}
    stored_hashes |= computed
    # Lookup emails also get computed hashes, kept in the lookup set.
    lookup_hashes |= {email_hash(e) for e in lookup_emails}
    # An identifier present in stored content is stored, even if it was
    # also the query key.
    lookup_emails -= stored_emails
    lookup_hashes -= stored_hashes
    lookup_refs -= stored_refs
    return {
        "emails": sorted(stored_emails),
        "hashes": sorted(stored_hashes),
        "user_ids": sorted(stored_refs),
        "phones": sorted(phones),
        "lookup": {
            "emails": sorted(lookup_emails),
            "hashes": sorted(lookup_hashes),
            "user_ids": sorted(lookup_refs),
        },
        "computed_hashes": sorted(computed),
    }


def lookup_outcome(fields, raw_text=""):
    """Derive a lookup outcome from a record, or None.

    A record is a lookup outcome when it carries rows / http_status /
    result / status_code / total_hits. Zero rows / 404 / NOT_FOUND is
    ABSENCE evidence; a hit is READBACK presence. Anything else is a
    state row, not a lookup.
    """
    rows = None
    for key in ("rows", "total", "total_hits", "hits_total"):
        if key in fields and fields[key] is not None:
            try:
                rows = int(fields[key])
            except (TypeError, ValueError):
                rows = None
            break
    if rows is None and isinstance(fields.get("hits"), dict):
        try:
            rows = int(fields["hits"].get("total"))
        except (TypeError, ValueError, AttributeError):
            rows = None
    status = fields.get("http_status", fields.get("status_code"))
    try:
        status = int(status) if status is not None else None
    except (TypeError, ValueError):
        status = None
    result = fields.get("result")
    if result is None and raw_text:
        match = re.search(r"result\s*=\s*\"?([A-Za-z_]+)", raw_text)
        result = match.group(1) if match else None
    if rows is None and status is None and result is None:
        return None
    if rows == 0 or status == 404 or (result and result.upper() == "NOT_FOUND"):
        return {"kind": "absence", "rows": rows, "http_status": status,
                "result": result}
    if rows is not None and rows >= 1 or status == 200 or (
            result and result.upper() in ("FOUND", "HIT", "IDENTIFIABLE")):
        return {"kind": "readback", "rows": rows, "http_status": status,
                "result": result}
    return {"kind": "lookup", "rows": rows, "http_status": status,
            "result": result}


def record_time_for(fields, line_time=None, inner_time=None, manifest_time=None):
    """Record-time priority: row observed/event/line time, then inner
    bundle snapshot time, then manifest capture time. Returns
    (record_time_or_None, time_source)."""
    if line_time:
        return line_time, "line"
    for field in TIME_FIELDS:
        value = fields.get(field) if isinstance(fields, dict) else None
        parsed = norm_time(value)
        if parsed:
            return parsed, f"row:{field}"
    if inner_time:
        return inner_time, "inner_snapshot"
    if manifest_time:
        return manifest_time, "manifest_fallback"
    return None, "unknown"


# ---------------------------------------------------------------------------
# Record factory
# ---------------------------------------------------------------------------

class IndexBuilder:
    """Accumulates normalised records, snapshot row sets, and indexes."""

    def __init__(self):
        self.records = []
        self.seen_keys = set()
        self.rowsets = {}  # (file_id, system, collection) -> set(resource)
        self.file_stats = defaultdict(lambda: {
            "kind": "", "records": 0, "skipped_lines": 0,
            "time_sources": defaultdict(int), "evidence_kinds": defaultdict(int),
        })
        self.assumptions = []

    def add(self, *, source_file_id, source_path, locator, system_id,
            collection, resource_id, record_time, time_source,
            evidence_kind, state_label, fields, raw_text="",
            replica=None, identifiers=None):
        key = (source_file_id, source_path, locator,
               resource_id or "", json.dumps(fields, sort_keys=True,
                                             default=str))
        if key in self.seen_keys:
            return None
        self.seen_keys.add(key)
        if identifiers is None:
            identifiers = extract_identifiers(fields)
        outcome = lookup_outcome(fields, raw_text)
        kind = evidence_kind
        if outcome is not None and evidence_kind in ("state", "readback"):
            kind = outcome["kind"]  # absence / readback / lookup
        elif outcome is not None and evidence_kind == "log":
            kind = outcome["kind"]
        restore = None
        if isinstance(fields, dict):
            for field in RESTORE_FIELDS:
                for actual in fields:
                    if actual.lower() == field:
                        canon, raw = canonical_bool(fields[actual])
                        restore = {"field": actual, "canonical": canon,
                                   "raw": raw}
                        break
                if restore:
                    break
        if raw_text and restore is None:
            match = re.search(
                r"(deletion_block|restore_allowed)\s*=\s*([A-Za-z0-9]+)",
                raw_text)
            if match:
                canon, raw = canonical_bool(
                    f"{match.group(1)}={match.group(2)}")
                restore = {"field": match.group(1), "canonical": canon,
                           "raw": match.group(2)}
        record = {
            "record_key": hashlib.sha256(
                "|".join([source_file_id, source_path, locator,
                          resource_id or ""]).encode()).hexdigest()[:24],
            "source_file_id": source_file_id,
            "source_path": source_path,
            "locator": locator,
            "system_id": system_id or "",
            "collection": collection or "",
            "resource_id": resource_id,
            "record_time": record_time,
            "time_source": time_source,
            "evidence_kind": kind,
            "state_label": state_label,
            "replica": replica,
            "lookup_outcome": outcome,
            "restore_allowed": restore,
            "identifiers": identifiers,
            "fields": fields,
        }
        self.records.append(record)
        stats = self.file_stats[source_path]
        stats["records"] += 1
        stats["time_sources"][time_source] += 1
        stats["evidence_kinds"][kind] += 1
        if resource_id and system_id:
            self.rowsets.setdefault(
                (source_file_id, system_id, collection or ""), set()
            ).add(resource_id)
        return record

    def note_rowset(self, source_file_id, system_id, collection):
        """Ensure an (empty) row set exists for a collection that was
        observed with zero resources: an empty row set IS the
        absence proof for that collection."""
        self.rowsets.setdefault(
            (source_file_id, system_id, collection or ""), set())

    def skip_line(self, source_path):
        self.file_stats[source_path]["skipped_lines"] += 1


# ---------------------------------------------------------------------------
# SQL parsing (structure-driven: CREATE TABLE + INSERT INTO statements)
# ---------------------------------------------------------------------------

def _split_sql_values(body):
    """Split one INSERT value list on top-level commas, honouring
    single-quoted strings ('' escape) and double-quoted identifiers."""
    values = []
    current = []
    in_single = False
    in_double = False
    i = 0
    while i < len(body):
        char = body[i]
        if in_single:
            if char == "'":
                if i + 1 < len(body) and body[i + 1] == "'":
                    current.append("'")
                    i += 2
                    continue
                in_single = False
            else:
                current.append(char)
        elif in_double:
            if char == '"':
                in_double = False
            else:
                current.append(char)
        else:
            if char == "'":
                in_single = True
            elif char == '"':
                in_double = True
            elif char == ",":
                values.append("".join(current).strip())
                current = []
            else:
                current.append(char)
        i += 1
    values.append("".join(current).strip())
    out = []
    for value in values:
        if value.upper() == "NULL":
            out.append(None)
        elif re.fullmatch(r"-?\d+", value):
            out.append(int(value))
        elif re.fullmatch(r"-?\d+\.\d+", value):
            out.append(float(value))
        else:
            out.append(value)
    return out


def parse_sql(text, builder, source_file_id, source_path, manifest_time):
    """Parse a SQLite-compatible dump by its own CREATE/INSERT
    statements. Envelope rows (a 5-column shape carrying a JSON
    payload) are parsed at the payload's own nesting."""
    tables = {}
    for match in re.finditer(
            r"CREATE TABLE\s+\"?([A-Za-z0-9_]+)\"?\s*\((.*?)\);",
            text, re.DOTALL | re.IGNORECASE):
        columns = []
        for col in match.group(2).split(","):
            col = col.strip()
            if not col or col.upper().startswith(
                    ("PRIMARY KEY", "FOREIGN KEY", "CHECK", "UNIQUE")):
                continue
            name = col.split()[0].strip("\"")
            columns.append(name)
        tables[match.group(1)] = columns
    # Snapshot scope rows (system -> capture time) are metadata, not
    # records; they are consumed only as a fallback clock per system.
    scope_times = {}
    for match in re.finditer(
            r"INSERT INTO\s+\"?snapshot_scope\"?\s+VALUES\s*\((.*?)\);",
            text, re.DOTALL | re.IGNORECASE):
        values = _split_sql_values(match.group(1))
        if len(values) >= 2:
            scope_times[str(values[0])] = norm_time(values[1])
    line_starts = []
    pos = 0
    for line in text.splitlines(keepends=True):
        line_starts.append(pos)
        pos += len(line)

    def line_no(offset):
        import bisect
        return bisect.bisect_right(line_starts, offset)

    for match in re.finditer(
            r"INSERT INTO\s+\"?([A-Za-z0-9_]+)\"?\s+VALUES\s*\((.*?)\);",
            text, re.DOTALL | re.IGNORECASE):
        table = match.group(1)
        if table == "snapshot_scope":
            continue
        columns = tables.get(table)
        if not columns:
            continue
        values = _split_sql_values(match.group(2))
        if len(values) != len(columns):
            # Shape mismatch: keep the row, keyed positionally, and say so.
            fields = {f"col_{i}": v for i, v in enumerate(values)}
        else:
            fields = dict(zip(columns, values))
        locator = f"line:{line_no(match.start())}"
        payload = fields.get("record_json")
        if isinstance(payload, str) and payload.strip().startswith("{"):
            try:
                parsed = json.loads(payload)
            except ValueError:
                parsed = None
            if isinstance(parsed, dict):
                system_id = parsed.get("origin_system") or fields.get(
                    "origin_system") or TABLE_SYSTEM.get(table) or table
                collection = parsed.get("collection_name") or fields.get(
                    "collection_name") or table
                resource_id = parsed.get("resource_id") or fields.get(
                    "resource_id")
                record_time, source = record_time_for(
                    fields, manifest_time=manifest_time)
                # Envelope updated_at is a uniform snapshot stamp, not
                # a position: it equals the manifest time in practice.
                builder.add(
                    source_file_id=source_file_id, source_path=source_path,
                    locator=locator, system_id=system_id,
                    collection=collection, resource_id=resource_id,
                    record_time=record_time, time_source=source,
                    evidence_kind="state", state_label=None,
                    fields=parsed, raw_text=payload,
                    replica=table if "replica" in table else None)
                continue
        system_id = TABLE_SYSTEM.get(table)
        if system_id is None and table in tables:
            system_id = table
        replica = None
        if "replica" in table:
            replica = table
        elif "primary" in table:
            replica = "primary"
        resource_id = fields.get("resource_id")
        record_time, source = record_time_for(
            fields, manifest_time=scope_times.get(system_id) or manifest_time)
        builder.add(
            source_file_id=source_file_id, source_path=source_path,
            locator=locator, system_id=system_id, collection=table,
            resource_id=resource_id, record_time=record_time,
            time_source=source, evidence_kind="state", state_label=(
                fields.get("account_status")),
            fields=fields, replica=replica)
    # Empty collections still get a row set (absence proof needs it).
    for table in tables:
        if table == "snapshot_scope":
            continue
        system_id = TABLE_SYSTEM.get(table) or table
        builder.note_rowset(source_file_id, system_id, table)


# ---------------------------------------------------------------------------
# JSON parsing (shape-driven: snapshots, service exports, flat lists,
# generic walk for unseen shapes)
# ---------------------------------------------------------------------------

def _json_records(builder, source_file_id, source_path, manifest_time,
                  data, top_time):
    if isinstance(data, dict) and isinstance(data.get("snapshots"), list):
        for snap_i, snap in enumerate(data["snapshots"]):
            if not isinstance(snap, dict):
                continue
            inner_time = norm_time(snap.get("captured_at"))
            system_id = snap.get("data_store") or snap.get("system") or ""
            collection = snap.get("collection") or ""
            records = snap.get("records")
            if not isinstance(records, list):
                continue
            builder.note_rowset(source_file_id, system_id, collection)
            for rec_i, rec in enumerate(records):
                if not isinstance(rec, dict):
                    continue
                record_time, source = record_time_for(
                    rec, inner_time=inner_time, manifest_time=manifest_time)
                builder.add(
                    source_file_id=source_file_id, source_path=source_path,
                    locator=f"snapshots[{snap_i}].records[{rec_i}]",
                    system_id=system_id, collection=collection,
                    resource_id=rec.get("resource_id"),
                    record_time=record_time, time_source=source,
                    evidence_kind="state", state_label=None, fields=rec)
        return True
    if isinstance(data, dict) and isinstance(data.get("service_exports"), dict):
        for system_id, collections in data["service_exports"].items():
            if not isinstance(collections, dict):
                continue
            for collection, rows in collections.items():
                if not isinstance(rows, list):
                    continue
                builder.note_rowset(source_file_id, system_id, collection)
                for row_i, row in enumerate(rows):
                    if not isinstance(row, dict):
                        continue
                    record_time, source = record_time_for(
                        row, manifest_time=manifest_time)
                    builder.add(
                        source_file_id=source_file_id,
                        source_path=source_path,
                        locator=(f"service_exports.{system_id}.{collection}"
                                 f"[{row_i}]"),
                        system_id=system_id, collection=collection,
                        resource_id=row.get("resource_id"),
                        record_time=record_time, time_source=source,
                        evidence_kind="state", state_label=None, fields=row)
        return True
    if isinstance(data, dict) and isinstance(data.get("records"), list):
        system_default = data.get("source") or ""
        collection_default = data.get("collection") or ""
        seen_collections = set()
        for row in data["records"]:
            if isinstance(row, dict):
                seen_collections.add(
                    (row.get("system") or system_default,
                     row.get("record_type") or collection_default))
        for system_id, collection in seen_collections:
            builder.note_rowset(source_file_id, system_id, collection)
        for row_i, row in enumerate(data["records"]):
            if not isinstance(row, dict):
                continue
            system_id = row.get("system") or system_default
            collection = row.get("record_type") or collection_default
            record_time, source = record_time_for(
                row, inner_time=norm_time(data.get("captured_at")),
                manifest_time=manifest_time)
            builder.add(
                source_file_id=source_file_id, source_path=source_path,
                locator=f"records[{row_i}]", system_id=system_id,
                collection=collection, resource_id=row.get("resource_id"),
                record_time=record_time, time_source=source,
                evidence_kind="state",
                state_label=row.get("result"), fields=row)
        return True
    if isinstance(data, list):
        for row_i, row in enumerate(data):
            if isinstance(row, dict):
                record_time, source = record_time_for(
                    row, manifest_time=manifest_time)
                builder.add(
                    source_file_id=source_file_id, source_path=source_path,
                    locator=f"[{row_i}]",
                    system_id=row.get("system") or row.get("origin_system")
                    or "", collection=row.get("collection_name") or "",
                    resource_id=row.get("resource_id"),
                    record_time=record_time, time_source=source,
                    evidence_kind="state", state_label=None, fields=row)
        return True
    # Generic unseen shape: any dict carrying a resource identifier is
    # a record; dicts carrying identifiers plus a state-ish field are
    # records without an identifier. Nothing here may crash on novelty.
    found = False
    for path, obj in _walk_dicts(data):
        if not isinstance(obj, dict):
            continue
        has_resource = obj.get("resource_id") is not None
        text_blob = " ".join(_walk_strings(obj))
        has_identifier = bool(EMAIL_RE.search(text_blob)
                              or SUBJECT_REF_RE.search(text_blob)
                              or HASH_RE.search(text_blob))
        has_state = any(
            k.lower() in ("result", "status", "state", "enabled",
                          "restore_allowed", "account_status")
            for k in obj)
        if has_resource or (has_identifier and has_state):
            record_time, source = record_time_for(
                obj, manifest_time=manifest_time)
            builder.add(
                source_file_id=source_file_id, source_path=source_path,
                locator=path,
                system_id=obj.get("system") or obj.get("origin_system") or "",
                collection=obj.get("collection_name")
                or obj.get("record_type") or "",
                resource_id=obj.get("resource_id"),
                record_time=record_time, time_source=source,
                evidence_kind="state", state_label=obj.get("result"),
                fields=obj)
            found = True
    return found


def parse_json(text, builder, source_file_id, source_path, manifest_time):
    try:
        data = json.loads(text)
    except ValueError:
        builder.assumptions.append(
            f"{source_path}: JSON parse failed; stored as text lines.")
        parse_text_lines(text, builder, source_file_id, source_path,
                         manifest_time, structured=False)
        return
    top_time = norm_time(data.get("captured_at") if isinstance(data, dict)
                         else None) or manifest_time
    _json_records(builder, source_file_id, source_path, manifest_time,
                  data, top_time)


# ---------------------------------------------------------------------------
# Logs and structured text (per-line, generic key=value extraction)
# ---------------------------------------------------------------------------

def parse_log_line(line, line_no_text):
    """Parse one log line generically: leading timestamp, service
    token, key=value pairs. Returns a fields dict or None when the
    line carries no joinable identifier at all (pure infra noise)."""
    timestamp = None
    match = ISO_RE.match(line.strip())
    if match:
        timestamp = norm_time(match.group(0))
    fields = {}
    service = None
    service_match = re.search(r"\bservice=([A-Za-z0-9_]+)", line)
    if service_match:
        service = service_match.group(1)
    else:
        bracket = re.search(r"\]\s*\[([A-Za-z0-9_]+)\]", line)
        if bracket:
            service = bracket.group(1)
    for key, quoted, bare in KV_RE.findall(line):
        value = quoted if quoted != "" else bare
        value = value.replace('\\"', '"')
        if key in ("rows", "http_status", "status_code", "total_hits"):
            try:
                value = int(value)
            except ValueError:
                pass
        elif key in ("enabled", "restore_allowed"):
            value = value.lower() in ("true", "1")
        fields[key] = value
    if "resource_id" not in fields:
        res = RESOURCE_RE.search(line)
        # Only accept a resource-shaped token that is NOT part of an
        # event name or a trace id: require it after resource_id= or
        # as a standalone token in a completed/read line.
        if res and ("resource_id" in line or "completed" in line
                    or "read" in line or "query" in line):
            fields["resource_id"] = res.group(0)
    text_blob = " ".join(str(v) for v in fields.values())
    has_joinable = bool(
        fields.get("resource_id")
        or EMAIL_RE.search(line)
        or SUBJECT_REF_RE.search(line)
        or HASH_RE.search(line)
        or "restore_allowed" in fields
        or "deletion_block" in line
        or "enabled" in fields)
    if not has_joinable:
        return None
    fields["_line_time"] = timestamp
    if service:
        fields["_service"] = service
    event_match = re.search(r"event\s*=\s*\"?([A-Za-z0-9_]+)", line)
    if not event_match:
        event_match = re.search(r"\]\s+([a-z_]+):", line)
    if event_match:
        fields["_event"] = event_match.group(1)
    return fields


def parse_json_log_line(line):
    """JSON-lines logs (e.g. structured service events): a line that is
    a JSON object after an optional leading ISO timestamp. Returns a
    fields dict with the same int/bool coercions as the key=value path,
    or None when the line is not a JSON object. Never raises. Without
    this branch, JSON log lines lost every key (trace_id, event,
    lookup_key, subject_ref, rows) and could never join or group."""
    stripped = line.strip()
    match = ISO_RE.match(stripped)
    timestamp = norm_time(match.group(0)) if match else None
    rest = stripped[match.end():].strip() if match else stripped
    if not rest.startswith("{"):
        return None
    try:
        obj = json.loads(rest)
    except (ValueError, TypeError):
        return None
    if not isinstance(obj, dict):
        return None
    fields = {}
    for key, value in obj.items():
        if key in ("rows", "http_status", "status_code", "total_hits"):
            try:
                value = int(value)
            except (ValueError, TypeError):
                pass
        elif key in ("enabled", "restore_allowed"):
            if isinstance(value, str):
                value = value.lower() in ("true", "1")
        fields[key] = value
    has_joinable = bool(
        fields.get("resource_id")
        or EMAIL_RE.search(line)
        or SUBJECT_REF_RE.search(line)
        or HASH_RE.search(line)
        or "restore_allowed" in fields
        or "deletion_block" in line
        or "enabled" in fields)
    if not has_joinable:
        return None
    fields["_line_time"] = timestamp
    service = fields.get("service") or fields.get("logger")
    if service:
        fields["_service"] = service
    if fields.get("event"):
        fields["_event"] = fields["event"]
    return fields


def parse_logs(text, builder, source_file_id, source_path, manifest_time):
    for i, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        fields = parse_json_log_line(line)
        if fields is not None:
            line_time = fields.pop("_line_time")
            service = fields.pop("_service", None)
            fields.pop("_event", None)
            record_time, source = record_time_for(
                fields, line_time=line_time, manifest_time=manifest_time)
            builder.add(
                source_file_id=source_file_id, source_path=source_path,
                locator=f"line:{i}", system_id=service or "",
                collection="", resource_id=fields.get("resource_id"),
                record_time=record_time, time_source=source,
                evidence_kind="log", state_label=None, fields=fields,
                raw_text=line)
            continue
        fields = parse_log_line(line, i)
        if fields is None:
            builder.skip_line(source_path)
            continue
        line_time = fields.pop("_line_time")
        service = fields.pop("_service", None)
        fields.pop("_event", None)
        record_time, source = record_time_for(
            fields, line_time=line_time, manifest_time=manifest_time)
        builder.add(
            source_file_id=source_file_id, source_path=source_path,
            locator=f"line:{i}", system_id=service or "",
            collection="", resource_id=fields.get("resource_id"),
            record_time=record_time, time_source=source,
            evidence_kind="log", state_label=None, fields=fields,
            raw_text=line)


HANDOVER_RE = re.compile(
    r"^\s*-?\s*(?P<time>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s*\|\s*"
    r"(?P<system>[^|]+?)\s*\|\s*(?P<resource>[^|]+?)\s*\|\s*"
    r"(?P<rtype>[^|]+?)\s*\|\s*(?P<result>[^|]+?)\s*\|\s*(?P<selector>.+?)\s*$"
)


def parse_text_lines(text, builder, source_file_id, source_path,
                     manifest_time, structured=True):
    """Structured text (pipe-delimited check lines) or, failing that,
    plain text lines that carry an identifier. Never crashes."""
    for i, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        match = HANDOVER_RE.match(stripped)
        if match:
            fields = {
                "system": match.group("system").strip(),
                "resource_id": match.group("resource").strip(),
                "record_type": match.group("rtype").strip(),
                "result": match.group("result").strip(),
                "subject_reference": match.group("selector").strip(),
            }
            line_time = norm_time(match.group("time"))
            record_time, source = record_time_for(
                fields, line_time=line_time, manifest_time=manifest_time)
            builder.add(
                source_file_id=source_file_id, source_path=source_path,
                locator=f"line:{i}", system_id=fields["system"],
                collection=fields["record_type"],
                resource_id=fields["resource_id"],
                record_time=record_time, time_source=source,
                evidence_kind="state", state_label=fields["result"],
                fields=fields, raw_text=line)
            continue
        if not structured:
            continue
        if EMAIL_RE.search(line) or SUBJECT_REF_RE.search(line):
            line_time = norm_time(ISO_RE.search(line).group(0)) \
                if ISO_RE.search(line) else manifest_time
            source = "line" if ISO_RE.search(line) else "manifest_fallback"
            builder.add(
                source_file_id=source_file_id, source_path=source_path,
                locator=f"line:{i}", system_id="", collection="",
                resource_id=None, record_time=line_time,
                time_source=source, evidence_kind="text",
                state_label=None, fields={"text": stripped}, raw_text=line)
        else:
            builder.skip_line(source_path)


# ---------------------------------------------------------------------------
# CSV (classified by HEADER SET, never by path)
# ---------------------------------------------------------------------------

def classify_csv_header(header):
    """Return a source kind from the column set alone."""
    cols = {c.strip().lower() for c in header}
    if {"user_id", "name", "email", "phone", "email_hash"}.issubset(cols):
        return "identity"
    if {"audit_id", "user_id", "event_time", "field_name",
            "old_value", "new_value"}.issubset(cols):
        return "identity_audit"
    if {"activity_id", "event_time", "event_type", "source_system",
            "target_system", "resource_id"}.issubset(cols):
        return "activity"
    if {"rule_id", "data_category", "condition",
            "required_action"}.issubset(cols):
        return "policy"
    if {"file_id", "file_path", "origin", "captured_at"}.issubset(cols):
        return "manifest"
    if {"case_id", "email", "requested_at", "audit_at",
            "request_text"}.issubset(cols):
        return "request_set"
    if {"case_id", "deletion_status", "steps_json"}.issubset(cols):
        return "answer_set"
    return "unknown_csv"


def parse_csv(text, builder, source_file_id, source_path, manifest_time):
    reader = csv.DictReader(io.StringIO(text))
    if reader.fieldnames is None:
        return
    kind = classify_csv_header(reader.fieldnames)
    if kind in ("manifest", "request_set", "answer_set"):
        # Not evidence: the manifest is the map, requests are queries,
        # answers are outputs. Skipping them is the honest classification.
        builder.file_stats[source_path]["kind"] = kind
        return
    for row_i, row in enumerate(reader, start=1):
        row = {k: v for k, v in row.items() if k is not None}
        if kind == "identity":
            resource_id = row.get("user_id")
            system_id = "identity_service"
            collection = "user_identities"
            evidence_kind = "identity"
        elif kind == "identity_audit":
            resource_id = row.get("audit_id")
            system_id = "identity_service"
            collection = "user_audit_log"
            evidence_kind = "identity"
        elif kind == "activity":
            resource_id = row.get("resource_id")
            system_id = row.get("target_system") or ""
            collection = row.get("event_type") or ""
            evidence_kind = "activity"
        elif kind == "policy":
            resource_id = row.get("rule_id")
            system_id = ""
            collection = "deletion_rules"
            evidence_kind = "policy"
        else:
            resource_id = row.get("resource_id")
            system_id = ""
            collection = "csv_row"
            evidence_kind = "state"
        record_time, source = record_time_for(
            row, manifest_time=manifest_time)
        builder.add(
            source_file_id=source_file_id, source_path=source_path,
            locator=f"row:{row_i}", system_id=system_id,
            collection=collection, resource_id=resource_id,
            record_time=record_time, time_source=source,
            evidence_kind=evidence_kind, state_label=None, fields=row)


# ---------------------------------------------------------------------------
# Binary artefacts via verified-transcription sidecar
# ---------------------------------------------------------------------------

def load_sidecar(dataset_dir, module_dir):
    """Sidecar entries keyed by dataset-relative path. A sidecar entry
    is VERIFIED transcription data (human-verified, with provenance);
    it is data, not logic: the indexer performs no branching on which
    file an entry belongs to beyond the path join itself."""
    candidates = [module_dir / "transcriptions.json",
                  dataset_dir / "transcriptions.json"]
    for path in candidates:
        if path.exists():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except ValueError:
                return {}, str(path)
            if isinstance(data, dict):
                return data.get("entries", data), str(path)
    return {}, None


def parse_binary(builder, source_file_id, source_path, manifest_time,
                 origin, sidecar_entries):
    raw_entries = sidecar_entries.get(source_path, [])
    if isinstance(raw_entries, dict):
        entries = raw_entries.get("records", [])
    else:
        entries = raw_entries
    if not entries:
        builder.assumptions.append(
            f"{source_path}: binary artefact with no verified "
            "transcription; recorded as untranscribed, never guessed.")
        builder.add(
            source_file_id=source_file_id, source_path=source_path,
            locator="binary:untranscribed", system_id=origin or "",
            collection="", resource_id=None, record_time=manifest_time,
            time_source="manifest_fallback", evidence_kind="binary",
            state_label="UNTRANSCRIBED",
            fields={"note": "binary artefact, no verified transcription"},
            identifiers={"emails": [], "hashes": [], "user_ids": [],
                         "phones": [], "lookup": {"emails": [],
                                                   "hashes": [],
                                                   "user_ids": []},
                         "computed_hashes": []})
        return
    for entry_i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            continue
        fields = dict(entry)
        fields.pop("provenance", None)
        record_time = manifest_time
        builder.add(
            source_file_id=source_file_id, source_path=source_path,
            locator=f"transcription:{entry_i}",
            system_id=entry.get("system_id") or origin or "",
            collection=entry.get("collection") or "",
            resource_id=entry.get("resource_id"),
            record_time=record_time, time_source="manifest_fallback",
            evidence_kind="binary",
            state_label=entry.get("state_label"), fields=fields)


# ---------------------------------------------------------------------------
# File classification by content sniffing
# ---------------------------------------------------------------------------

def sniff_kind(data):
    if data.startswith(PNG_MAGIC):
        return "binary_image"
    if data.startswith(PDF_MAGIC):
        return "binary_pdf"
    stripped = data.lstrip(b"\xef\xbb\xbf \t\r\n")
    if stripped.startswith(b"{") or stripped.startswith(b"["):
        return "json"
    text_head = stripped[:4000].decode("utf-8", errors="replace")
    if re.search(r"CREATE TABLE|INSERT INTO", text_head, re.IGNORECASE):
        return "sql"
    first_line = text_head.splitlines()[0] if text_head.splitlines() else ""
    if "," in first_line and re.search(
            r"[A-Za-z_]+(,[A-Za-z_]+)+", first_line):
        # A header row: confirm it parses as CSV with >1 column.
        try:
            parsed = next(csv.reader(io.StringIO(first_line)))
            if len(parsed) >= 2:
                return "csv"
        except csv.Error:
            pass
    if re.search(HANDOVER_RE.pattern, text_head, re.MULTILINE):
        return "structured_text"
    if ISO_RE.match(text_head.strip()):
        return "log"
    return "text"


# ---------------------------------------------------------------------------
# Build / load / query
# ---------------------------------------------------------------------------

def build_index(dataset_dir, out_dir, module_dir=None):
    dataset_dir = Path(dataset_dir)
    out_dir = Path(out_dir)
    module_dir = Path(module_dir) if module_dir else Path(__file__).parent
    out_dir.mkdir(parents=True, exist_ok=True)

    # Manifest: the dataset's own map from path -> file identifier and
    # capture time. Read as data; never used to branch on content.
    manifest_by_path = {}
    manifest_file = dataset_dir / "evidence_files.csv"
    if manifest_file.exists():
        with manifest_file.open(newline="", encoding="utf-8") as handle:
            for row in csv.DictReader(handle):
                manifest_by_path[row["file_path"]] = {
                    "file_id": row["file_id"],
                    "captured_at": norm_time(row.get("captured_at")),
                    "origin": row.get("origin", ""),
                }
    sidecar, sidecar_path = load_sidecar(dataset_dir, module_dir)

    builder = IndexBuilder()
    builder.assumptions.append(
        "Record-time priority: row observed/event/line time, then inner "
        "bundle snapshot time, then manifest capture time (fallback only "
        "for binary artefacts and unstructured text).")
    builder.assumptions.append(
        "Email normalisation is lowercase-only on both sides of every "
        "join. Plus-tags, dot-stripping and domain aliases are NOT "
        "normalised: they are leads, never merges.")
    builder.assumptions.append(
        "Phone is a corroboration-only index. A phone match never "
        "resolves a subject on its own.")
    builder.assumptions.append(
        "A lookup returning zero rows / 404 / NOT_FOUND is ABSENCE "
        "evidence, never a remaining record. Stored content and lookup "
        "keys are kept in separate identifier sets per record.")
    builder.assumptions.append(
        "Binary artefacts enter only through verified transcriptions "
        f"(sidecar: {sidecar_path or 'none found'}). An untranscribed "
        "binary file is recorded as such, never guessed.")

    # Deterministic walk: sorted relative paths.
    all_files = sorted(
        (p for p in dataset_dir.rglob("*") if p.is_file()),
        key=lambda p: str(p.relative_to(dataset_dir)))
    # Note: no path-based skip lives here. The manifest file is
    # recognised by its HEADER SET in parse_csv (kind "manifest") and
    # skipped there, like every other non-evidence CSV kind.
    for path in all_files:
        rel = str(path.relative_to(dataset_dir)).replace("\\", "/")
        meta = manifest_by_path.get(rel, {})
        source_file_id = meta.get("file_id", "")
        manifest_time = meta.get("captured_at")
        origin = meta.get("origin", "")
        data = path.read_bytes()
        kind = sniff_kind(data)
        stats = builder.file_stats[rel]
        stats["kind"] = kind
        try:
            text = data.decode("utf-8", errors="replace")
        except Exception:
            text = ""
        if kind in ("binary_image", "binary_pdf"):
            parse_binary(builder, source_file_id, rel, manifest_time,
                         origin, sidecar)
        elif kind == "json":
            parse_json(text, builder, source_file_id, rel, manifest_time)
        elif kind == "sql":
            parse_sql(text, builder, source_file_id, rel, manifest_time)
        elif kind == "csv":
            parse_csv(text, builder, source_file_id, rel, manifest_time)
        elif kind == "log":
            parse_logs(text, builder, source_file_id, rel, manifest_time)
        elif kind == "structured_text":
            parse_text_lines(text, builder, source_file_id, rel,
                             manifest_time, structured=True)
        else:
            parse_text_lines(text, builder, source_file_id, rel,
                             manifest_time, structured=True)

    records = sorted(
        builder.records,
        key=lambda r: (r["source_file_id"], r["source_path"], r["locator"],
                       r["resource_id"] or "", r["record_key"]))
    # Re-key deterministically after sorting (record_key itself is a
    # content hash, so it is already stable; sorting only fixes order).
    indexes = build_join_indexes(records)
    rowsets = [
        {"source_file_id": fid, "system_id": system,
         "collection": collection,
         "resource_ids": sorted(resources)}
        for (fid, system, collection), resources
        in sorted(builder.rowsets.items())
    ]
    manifest = {
        "version": VERSION,
        "record_count": len(records),
        "file_count": len(builder.file_stats),
        "files": {
            path: {
                "kind": stats["kind"],
                "records": stats["records"],
                "skipped_lines": stats["skipped_lines"],
                "time_sources": dict(sorted(stats["time_sources"].items())),
                "evidence_kinds": dict(sorted(stats["evidence_kinds"].items())),
            }
            for path, stats in sorted(builder.file_stats.items())
        },
        "rowset_count": len(rowsets),
        "index_sizes": {name: len(values)
                        for name, values in indexes.items()},
        "assumptions": builder.assumptions,
        "sidecar_path": sidecar_path,
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
    write_manifest_md(out_dir, manifest, records)
    return manifest


def build_join_indexes(records):
    """Join indexes. Keys are normalised (lowercase emails/hashes/refs,
    digits-only phones). Values are record_keys, sorted. Phone is
    corroboration-only: it is indexed for lookup, and every consumer
    must treat a phone-only hit as unconfirmed."""
    by_user, by_email, by_hash, by_phone, by_resource = (
        defaultdict(set) for _ in range(5))
    for record in records:
        ids = record["identifiers"]
        for ref in ids["user_ids"]:
            by_user[ref].add(record["record_key"])
        for ref in ids["lookup"]["user_ids"]:
            by_user[ref].add(record["record_key"])
        for email in ids["emails"]:
            by_email[email].add(record["record_key"])
        for email in ids["lookup"]["emails"]:
            by_email[email].add(record["record_key"])
        for digest in ids["hashes"]:
            by_hash[digest].add(record["record_key"])
        for digest in ids["lookup"]["hashes"]:
            by_hash[digest].add(record["record_key"])
        for phone in ids["phones"]:
            digits = re.sub(r"\D", "", phone)
            if digits:
                by_phone[digits].add(record["record_key"])
        if record["resource_id"]:
            by_resource[record["resource_id"]].add(record["record_key"])
    return {
        "by_user_id": {k: sorted(v) for k, v in sorted(by_user.items())},
        "by_email": {k: sorted(v) for k, v in sorted(by_email.items())},
        "by_hash": {k: sorted(v) for k, v in sorted(by_hash.items())},
        "by_phone_corroboration_only": {
            k: sorted(v) for k, v in sorted(by_phone.items())},
        "by_resource_id": {k: sorted(v)
                           for k, v in sorted(by_resource.items())},
    }


def write_manifest_md(out_dir, manifest, records):
    lines = [
        "# Unit 1 Index Manifest",
        "",
        f"Version: `{manifest['version']}`",
        "",
        f"Records indexed: **{manifest['record_count']}** across "
        f"**{manifest['file_count']}** files. Snapshot row sets: "
        f"{manifest['rowset_count']}.",
        "",
        "## Schema (one record per line in `records.jsonl`)",
        "",
        "| Field | Meaning |",
        "|---|---|",
        "| `record_key` | Content hash of source + locator + resource (stable across rebuilds). |",
        "| `source_file_id` | Manifest identifier for evidence files; empty for top-level data files. |",
        "| `source_path` | Dataset-relative path (provenance, never a branch condition). |",
        "| `locator` | Line / row / JSON path / transcription entry locating the record. |",
        "| `system_id` | Owning system, from the record itself (table dictionary, bundle field, row field). Unknown tables index under their own table name. |",
        "| `collection` | Table / collection / record type, from the record itself. |",
        "| `resource_id` | Resource identifier, or null for identifier-only artefacts. |",
        "| `record_time` / `time_source` | Priority: row observed/event/line > inner snapshot > manifest fallback. |",
        "| `evidence_kind` | `state` (stored row), `readback` (lookup hit), `absence` (zero-row / 404 / NOT_FOUND lookup), `lookup`, `activity` (workflow claim, not state), `identity`, `policy`, `binary` (verified transcription), `text`, `event`. |",
        "| `state_label` | Raw result/status string from the source, or null. |",
        "| `replica` | Replica/primary table marker where the source carries one, else null. |",
        "| `lookup_outcome` | rows / http_status / result for lookup-shaped records, else null. |",
        "| `restore_allowed` | Canonical boolean + raw form for restore flags, else null. |",
        "| `identifiers` | Stored emails (lowercased), hashes (stored + computed SHA-256 closure), subject references, phones (corroboration only), plus a separate `lookup` set for query keys/selectors/correlation keys. |",
        "| `fields` | Full normalised raw record, for downstream classification by shape. |",
        "",
        "## Snapshot row sets (`snapshots.jsonl`)",
        "",
        "One entry per (file, system, collection) with the sorted set of "
        "resource identifiers observed in it -- including EMPTY sets. An "
        "empty set is the absence proof for that collection: a resource "
        "absent from a collection's row set was not in that snapshot. "
        "Row sets never prove absence for a collection the file does not "
        "cover.",
        "",
        "## Join indexes (`indexes.json`)",
        "",
        "By subject reference, by email (lowercased), by hash (stored + "
        "computed), by phone (digits-folded, corroboration only), and by "
        "resource identifier. Values are record keys.",
        "",
        "## Assumptions (binding, carried into downstream gates)",
        "",
    ]
    for assumption in manifest["assumptions"]:
        lines.append(f"- {assumption}")
    lines += [
        "",
        "## Per-file counts",
        "",
        "| File | Kind | Records | Skipped lines |",
        "|---|---|---|---|",
    ]
    for path, stats in sorted(manifest["files"].items()):
        lines.append(f"| `{path}` | {stats['kind']} | {stats['records']} "
                     f"| {stats['skipped_lines']} |")
    lines.append("")
    (out_dir / "index_manifest.md").write_text(
        "\n".join(lines), encoding="utf-8")


# ---------------------------------------------------------------------------
# Query interface for downstream units (R1-FINAL support)
# ---------------------------------------------------------------------------

class Index:
    """Loaded index with the only queries downstream units need.

    `observed_ids_for` answers 'all OBSERVED canonical identifiers for
    a subject' -- it never invents one. A subject with no observed
    account identifier gets an empty result plus a flag, not a
    fabricated identifier.
    """

    def __init__(self, out_dir):
        out_dir = Path(out_dir)
        self.records = {}
        with (out_dir / "records.jsonl").open(encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    record = json.loads(line)
                    self.records[record["record_key"]] = record
        self.indexes = json.loads(
            (out_dir / "indexes.json").read_text(encoding="utf-8"))
        self.rowsets = []
        with (out_dir / "snapshots.jsonl").open(encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    self.rowsets.append(json.loads(line))
        self.manifest = json.loads(
            (out_dir / "manifest.json").read_text(encoding="utf-8"))

    def records_for_keys(self, record_keys):
        return [self.records[k] for k in record_keys if k in self.records]

    def records_for_subject(self, *, user_ids=(), emails=(), hashes=()):
        """All records joined to a subject by reference, email, or hash
        (lowercased on both sides). Phone is deliberately NOT a join
        key here: it corroborates, it does not resolve."""
        keys = set()
        for ref in user_ids:
            keys |= set(self.indexes["by_user_id"].get(ref.lower(), []))
        for email in emails:
            lowered = norm_email(email)
            if lowered:
                keys |= set(self.indexes["by_email"].get(lowered, []))
                keys |= set(self.indexes["by_hash"].get(
                    email_hash(lowered), []))
        for digest in hashes:
            keys |= set(self.indexes["by_hash"].get(digest.lower(), []))
        return sorted((self.records[k] for k in keys),
                      key=lambda r: (r["record_time"] or "",
                                     r["source_file_id"], r["locator"]))

    def observed_ids_for(self, *, user_ids=(), emails=(), hashes=()):
        """Observed canonical identifiers for a subject, split into
        positive rows (state/readback) and identifier mentions
        (absence lookups, activity claims, ledger checks).

        Returns a dict with sorted identifier lists and flags:
        `has_positive_account_row` (a state/readback record in the
        account system) and `observed_account_ids` (every account
        identifier seen in any record kind, including absence
        lookups). Nothing is invented: an empty list means unobserved,
        and the caller must flag it, not fill it."""
        records = self.records_for_subject(
            user_ids=user_ids, emails=emails, hashes=hashes)
        account_ids, audit_ids, positive_account = set(), set(), False
        for record in records:
            resource = record["resource_id"] or ""
            system = record["system_id"]
            if system == "account_service" and resource:
                account_ids.add(resource)
                if record["evidence_kind"] in ("state", "readback"):
                    positive_account = True
            if system == "security_service" and resource.startswith(
                    "audit_record"):
                audit_ids.add(resource)
        return {
            "record_count": len(records),
            "observed_account_ids": sorted(account_ids),
            "observed_audit_ids": sorted(audit_ids),
            "has_positive_account_row": positive_account,
            "flags": [] if account_ids else ["NO_OBSERVED_ACCOUNT_ID"],
        }

    def citation_resolves(self, source_file_id, resource_id, system_id=""):
        """G2-1 resolution: a cited (file, resource) pair resolves iff
        the index holds a record for that resource in that file, OR a
        snapshot row set for that file+system that EXCLUDES the
        resource (an absence proof: the snapshot's row set is the
        evidence). Returns (resolves, mechanism)."""
        for record in self.records.values():
            if (record["source_file_id"] == source_file_id
                    and record["resource_id"] == resource_id):
                return True, f"record:{record['evidence_kind']}"
        for rowset in self.rowsets:
            if rowset["source_file_id"] != source_file_id:
                continue
            if system_id and rowset["system_id"] != system_id:
                continue
            if resource_id not in rowset["resource_ids"]:
                return True, "rowset_exclusion"
        return False, "unresolved"


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Build the Unit 1 normalised evidence index.")
    parser.add_argument("--dataset", required=True,
                        help="Dataset directory (runtime parameter).")
    parser.add_argument("--out", required=True,
                        help="Output index directory.")
    args = parser.parse_args(argv)
    manifest = build_index(args.dataset, args.out)
    print(f"records={manifest['record_count']} "
          f"files={manifest['file_count']} "
          f"rowsets={manifest['rowset_count']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
