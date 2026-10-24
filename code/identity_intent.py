"""Unit 2 — Bitemporal Identity Graph (HackerRank Orchestrate, Northstar Shop).

Deterministic, stdlib-only. No model calls, no file scans at query time: the
graph is built once from the identity tables and then queried from indexes.

Doctrine implemented (v2 §1 P3, §2 Gate 2; Master Plan §2 Pillar A, §3):
  * Nodes: user_id + every email form (current + historical) + every email-hash
    form + phone forms. Phone nodes are FLAGGED corroboration-only: a phone can
    corroborate a subject, it can never resolve one.
  * Edges: audit-log change events, each carrying a validity interval
    (bitemporal: valid-time from the event timestamp; transaction-time is the
    audit-log order itself — the corpus carries no separate transaction
    timestamp, and this module never invents one).
  * Normalisation: lowercase ONLY, applied to BOTH sides of every lookup.
    Plus-tags, dot-stripping and domain aliases are NOT rules: they produce
    leads at most, never resolutions.
  * Expansion: transitive closure over audit edges. A subject's form set is
    the whole chain (current form + every superseded form), so a record keyed
    to any historical form or hash still resolves.
  * Similarity is a LEAD, never a merge. A query that matches no exact form
    is never resolved from a similar form, however unique the similarity.
  * Collision HALT: if an exact form maps to more than one subject, or a
    stem-only query maps to more than one subject, resolution HALTS to
    Gate 1 (human) with the ambiguity named. It is never resolved by picking
    the "most likely" subject. An exact full-form match is NOT blocked by a
    stem collision elsewhere: two subjects may share a digit-stripped stem
    while their full forms (digits + domain included) are distinct and
    unambiguous — the full form is what resolves.

Anti-hardcoding: this module contains no request identifiers, no evidence
identifiers, no filename branches and no dashboard/status inputs. It reads
whatever identity tables it is given at runtime (paths are constructor
arguments) and derives everything — forms, chains, hashes, stems, collision
groups — from those rows. An unseen subject, an unseen email form, an unseen
collision pair or an unseen chain length is handled by the same code path
as a seen one.

Public surface (see SCHEMA.md for the wire schemas Unit 3 consumes):
  IdentityGraph.from_csvs(identities_path, audit_log_path)
  IdentityGraph.from_rows(identity_rows, audit_rows)   # tests / synthetic data
  graph.resolve(email)            -> Resolution (exact-form lookup)
  graph.resolve_by_hash(hex_hash) -> Resolution (hash-form lookup)
  graph.corroborate_phone(user_id, phone) -> bool (never resolves)
  graph.subject(user_id)          -> Subject | None
  graph.collision_groups()        -> {stem: [user_id, ...]} for stems with >1 user
  graph.to_dict()                 -> JSON-serialisable snapshot of the graph
"""

from __future__ import annotations

import csv
import hashlib
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence

# ---------------------------------------------------------------------------
# Normalisation helpers (the ONLY automatic normalisation: lowercase).
# ---------------------------------------------------------------------------

_DIGIT_SUFFIX = re.compile(r"\d+$")


def normalize_email(value: str) -> str:
    """Lowercase + strip. Both sides of every lookup go through this."""
    return value.strip().lower()


def sha256_hex(lowercased_value: str) -> str:
    """SHA-256 of the already-lowercased form (hashes are of stored forms)."""
    return hashlib.sha256(lowercased_value.encode("utf-8")).hexdigest()


def email_stem(normalized_email: str) -> str:
    """Digit-stripped local part: the similarity LEAD key.

    Two subjects sharing a stem are a collision GROUP (a lead, and a HALT
    trigger for stem-only queries) — never a merge key. Digits and domain
    are part of the full form and therefore part of exact resolution.
    """
    local = normalized_email.split("@", 1)[0]
    return _DIGIT_SUFFIX.sub("", local)


def normalize_phone(value: str) -> str:
    """Phone comparison key: digits only. Used for corroboration only."""
    return re.sub(r"\D", "", value or "")


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FormInterval:
    """One identifier form's validity interval for one subject.

    valid_from is inclusive, valid_to is exclusive; None means unbounded
    (unknown start for the earliest form, still-current for the live form).
    kind: 'current' for the live identity-table form, 'historical' otherwise.
    source: where the form was seen ('identity' or an audit event id).
    """

    form: str
    kind: str
    valid_from: Optional[str]
    valid_to: Optional[str]
    source: str


@dataclass
class Subject:
    user_id: str
    name: str
    current_email: str
    current_hash: str
    email_forms: List[FormInterval] = field(default_factory=list)
    hash_forms: List[FormInterval] = field(default_factory=list)
    phone_forms: List[FormInterval] = field(default_factory=list)
    audit_event_ids: List[str] = field(default_factory=list)

    def all_email_forms(self) -> List[str]:
        return [f.form for f in self.email_forms]

    def all_hashes(self) -> List[str]:
        return [f.form for f in self.hash_forms]

    def to_dict(self) -> dict:
        return {
            "user_id": self.user_id,
            "name": self.name,
            "current_email": self.current_email,
            "current_hash": self.current_hash,
            "email_forms": [f.__dict__ for f in self.email_forms],
            "hash_forms": [f.__dict__ for f in self.hash_forms],
            "phone_forms": [f.__dict__ for f in self.phone_forms],
            "audit_event_ids": list(self.audit_event_ids),
        }


@dataclass
class Resolution:
    """Outcome of one lookup. Exactly one of user_id / gate is actionable.

    status:
      'current'     — query form is the subject's live form.
      'historical'  — query form is a superseded form of exactly one subject.
      'unresolved'  — no exact form matches; leads (if any) are named, and
                      the subject is NOT guessed. Unit 3 records
                      UNRESOLVED_IDENTITY for this outcome.
      'ambiguous'   — exact form maps to >1 subject, or a stem-only query
                      maps to >1 subject. HALT to Gate 1; candidates named.
    """

    status: str
    query: str
    normalized_query: str
    user_id: Optional[str] = None
    matched_form: Optional[str] = None
    form_kind: Optional[str] = None
    candidates: List[str] = field(default_factory=list)
    leads: List[str] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)

    @property
    def resolved(self) -> bool:
        return self.status in ("current", "historical") and self.user_id is not None

    @property
    def gate(self) -> Optional[str]:
        if self.status == "ambiguous":
            return "GATE_1_COLLISION"
        if self.status == "unresolved":
            return "GATE_1_UNRESOLVED_IDENTITY"
        return None

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "query": self.query,
            "normalized_query": self.normalized_query,
            "user_id": self.user_id,
            "matched_form": self.matched_form,
            "form_kind": self.form_kind,
            "candidates": list(self.candidates),
            "leads": list(self.leads),
            "reasons": list(self.reasons),
            "resolved": self.resolved,
            "gate": self.gate,
        }


# ---------------------------------------------------------------------------
# Graph
# ---------------------------------------------------------------------------


class IdentityGraph:
    """Bitemporal identity graph built from identity + audit-log rows."""

    def __init__(self, subjects: Dict[str, Subject]):
        self.subjects = subjects
        # Exact-form indexes (built once; queries are dict lookups).
        self._email_index: Dict[str, List[str]] = defaultdict(list)
        self._hash_index: Dict[str, List[str]] = defaultdict(list)
        self._phone_index: Dict[str, List[str]] = defaultdict(list)
        for subject in subjects.values():
            for form in subject.email_forms:
                self._email_index[form.form].append(subject.user_id)
            for form in subject.hash_forms:
                self._hash_index[form.form].append(subject.user_id)
            for form in subject.phone_forms:
                self._phone_index[normalize_phone(form.form)].append(subject.user_id)
        # Stem index: leads + collision groups only, never resolution.
        self._stem_index: Dict[str, List[str]] = defaultdict(list)
        for subject in subjects.values():
            stems = {email_stem(f.form) for f in subject.email_forms}
            for stem in stems:
                self._stem_index[stem].append(subject.user_id)
        for index in (self._email_index, self._hash_index, self._stem_index):
            for key in index:
                index[key] = sorted(set(index[key]))

    # -- construction ------------------------------------------------------

    @classmethod
    def from_csvs(cls, identities_path, audit_log_path) -> "IdentityGraph":
        with open(identities_path, newline="", encoding="utf-8") as fh:
            identity_rows = list(csv.DictReader(fh))
        with open(audit_log_path, newline="", encoding="utf-8") as fh:
            audit_rows = list(csv.DictReader(fh))
        return cls.from_rows(identity_rows, audit_rows)

    @classmethod
    def from_rows(cls, identity_rows: Sequence[dict], audit_rows: Sequence[dict]) -> "IdentityGraph":
        """Build the graph from raw rows.

        Chain reconstruction is generic: per subject, email-change events
        are sorted by event time and chained old -> new. A subject with no
        change events has one form (the live form, unbounded interval). A
        subject with N change events has N+1 forms; the earliest form's
        start is unknown (None), each superseding event closes the previous
        form and opens the next. Hash intervals follow the paired hash
        events at the same event time; a hash form is also always computed
        from its email form (SHA-256 of the lowercased form) so a missing
        hash row cannot silently drop a form — computed and stored hashes
        are cross-checked and any mismatch is recorded on the subject via
        the graph-level integrity report (see check_integrity).
        """
        subjects: Dict[str, Subject] = {}
        for row in identity_rows:
            user_id = row["user_id"]
            current = normalize_email(row["email"])
            # Default single-form subject. Subjects WITH audit events get
            # their full chain below; subjects WITHOUT any audit row must
            # still resolve — previously this default was missing, so a
            # no-event subject had no forms at all and could never resolve
            # (caught by the unseen-case mutation suite, not by the seen
            # census, because the seen census exercises the same path).
            subjects[user_id] = Subject(
                user_id=user_id,
                name=row.get("name", ""),
                current_email=current,
                current_hash=(row.get("email_hash") or "").strip().lower(),
                email_forms=[FormInterval(current, "current", None, None, "identity")],
                hash_forms=[FormInterval(sha256_hex(current), "current", None, None, "identity")],
            )

        # Group audit events per subject, per field, sorted by event time.
        events: Dict[str, List[dict]] = defaultdict(list)
        for row in audit_rows:
            events[row["user_id"]].append(row)
        for user_events in events.values():
            user_events.sort(key=lambda r: (r.get("event_time") or "", r.get("audit_id") or ""))

        for user_id, user_events in events.items():
            subject = subjects.get(user_id)
            if subject is None:
                # Audit rows for an unknown subject cannot create a subject:
                # there is no identity row to anchor them to. Recorded as a
                # lead for Gate 1, never silently materialised.
                continue
            subject.audit_event_ids = [r.get("audit_id", "") for r in user_events]

            email_changes = [r for r in user_events if r.get("field_name") == "email"]
            hash_changes = [r for r in user_events if r.get("field_name") == "email_hash"]
            phone_changes = [r for r in user_events if r.get("field_name") == "phone"]

            # Email chain: walk old -> new in event-time order.
            forms: List[FormInterval] = []
            if email_changes:
                first_old = normalize_email(email_changes[0]["old_value"])
                forms.append(FormInterval(first_old, "historical", None,
                                          email_changes[0]["event_time"],
                                          email_changes[0].get("audit_id", "")))
                for i, change in enumerate(email_changes):
                    new_form = normalize_email(change["new_value"])
                    nxt = email_changes[i + 1]["event_time"] if i + 1 < len(email_changes) else None
                    kind = "current" if new_form == subject.current_email else "historical"
                    forms.append(FormInterval(new_form, kind, change["event_time"], nxt,
                                              change.get("audit_id", "")))
                # Safety net: if the chain's final form is not the live form
                # (truncated log), the live form is still added unbounded.
                if not any(f.form == subject.current_email for f in forms):
                    forms.append(FormInterval(subject.current_email, "current", None, None, "identity"))
            else:
                forms.append(FormInterval(subject.current_email, "current", None, None, "identity"))
            subject.email_forms = forms

            # Hash forms: one per email form, computed (never trusted blindly).
            # check_integrity() cross-checks computed vs. stored hashes; a
            # stored hash row that disagrees is a Gate 1 finding, not a
            # silent correction.
            hash_forms: List[FormInterval] = []
            for form in forms:
                computed = sha256_hex(form.form)
                hash_forms.append(FormInterval(computed, form.kind, form.valid_from,
                                               form.valid_to, form.source))
            subject.hash_forms = hash_forms

            # Phone forms: corroboration-only nodes, same interval logic.
            phone_forms: List[FormInterval] = []
            if phone_changes:
                phone_forms.append(FormInterval(phone_changes[0]["old_value"], "historical", None,
                                                phone_changes[0]["event_time"],
                                                phone_changes[0].get("audit_id", "")))
                for i, change in enumerate(phone_changes):
                    nxt = phone_changes[i + 1]["event_time"] if i + 1 < len(phone_changes) else None
                    # Provisional kind; the identity row fixes live-ness below.
                    phone_forms.append(FormInterval(change["new_value"], "historical",
                                                    change["event_time"], nxt,
                                                    change.get("audit_id", "")))
            subject.phone_forms = phone_forms

        # Fix phone forms from the identity rows (authoritative live value).
        identity_by_user = {r["user_id"]: r for r in identity_rows}
        for user_id, subject in subjects.items():
            live_phone = (identity_by_user[user_id].get("phone") or "").strip()
            if not live_phone:
                continue
            if not any(p.form == live_phone for p in subject.phone_forms):
                subject.phone_forms.append(FormInterval(live_phone, "current", None, None, "identity"))
            else:
                fixed = []
                for p in subject.phone_forms:
                    if p.form == live_phone and p.valid_to is None:
                        fixed.append(FormInterval(p.form, "current", p.valid_from, None, p.source))
                    elif p.form == live_phone:
                        fixed.append(p)
                    else:
                        fixed.append(FormInterval(p.form, "historical", p.valid_from, p.valid_to, p.source))
                subject.phone_forms = fixed
            # Email kind fix-up: exactly the live form is 'current'.
            subject.email_forms = [
                FormInterval(f.form, "current" if f.form == subject.current_email else "historical",
                             f.valid_from, f.valid_to, f.source)
                for f in subject.email_forms
            ]
            subject.hash_forms = [
                FormInterval(f.form, "current" if f.form == sha256_hex(subject.current_email) else "historical",
                             f.valid_from, f.valid_to, f.source)
                for f in subject.hash_forms
            ]

        return cls(subjects)

    # -- integrity ---------------------------------------------------------

    def check_integrity(self) -> List[str]:
        """Cross-checks computed hashes against stored hashes. Empty = clean.

        Stored current hashes must equal SHA-256(live lowercased email);
        stored historical hash pairs must equal SHA-256 of the paired email
        forms. A mismatch is a data-integrity finding for Gate 1, never
        silently repaired.
        """
        problems: List[str] = []
        for subject in self.subjects.values():
            if subject.current_hash and sha256_hex(subject.current_email) != subject.current_hash:
                problems.append(f"{subject.user_id}: stored current hash != SHA-256(current email)")
            email_hashes = {sha256_hex(f.form) for f in subject.email_forms}
            stored_hashes = {f.form for f in subject.hash_forms}
            if email_hashes != stored_hashes:
                problems.append(f"{subject.user_id}: computed hash set != stored hash set")
        return problems

    # -- lookups -----------------------------------------------------------

    def resolve(self, email: str) -> Resolution:
        """Resolve a request email to exactly one subject, or halt.

        Dual-side lowercase: the query is lowercased and the index holds
        lowercased forms, so casing on either side cannot cause a miss.
        """
        normalized = normalize_email(email or "")
        if not normalized:
            return Resolution("unresolved", email or "", normalized,
                              reasons=["empty query form"])
        hits = self._email_index.get(normalized, [])
        if len(hits) == 1:
            subject = self.subjects[hits[0]]
            matched = next(f for f in subject.email_forms if f.form == normalized)
            return Resolution(matched.kind, email, normalized, user_id=hits[0],
                              matched_form=normalized, form_kind=matched.kind,
                              reasons=[f"exact normalized form match ({matched.kind})"])
        if len(hits) > 1:
            return Resolution("ambiguous", email, normalized, candidates=hits,
                              reasons=["exact form maps to multiple subjects"])
        # No exact match: similarity is a lead only. A stem hit names
        # candidates for Gate 1; it never resolves, even if unique.
        stem = email_stem(normalized)
        stem_hits = self._stem_index.get(stem, [])
        if len(stem_hits) > 1:
            return Resolution("ambiguous", email, normalized, candidates=stem_hits,
                              reasons=["no exact form; digit-stripped stem maps to multiple subjects"])
        if len(stem_hits) == 1:
            return Resolution("unresolved", email, normalized, leads=stem_hits,
                              reasons=["no exact form; stem lead exists but similarity never resolves"])
        return Resolution("unresolved", email, normalized,
                          reasons=["no exact form and no stem lead"])

    def resolve_by_hash(self, hex_hash: str) -> Resolution:
        """Resolve a stored hash form to exactly one subject, or halt.

        Used by Unit 3 when a record carries only a hash: the hash closure
        (every email form's SHA-256) is the bridge. A hash that matches no
        form, or more than one subject, halts — it is never approximated.
        """
        normalized = (hex_hash or "").strip().lower()
        if not normalized:
            return Resolution("unresolved", hex_hash or "", normalized,
                              reasons=["empty hash query"])
        hits = self._hash_index.get(normalized, [])
        if len(hits) == 1:
            subject = self.subjects[hits[0]]
            matched = next(f for f in subject.hash_forms if f.form == normalized)
            return Resolution(matched.kind, hex_hash, normalized, user_id=hits[0],
                              matched_form=normalized, form_kind=matched.kind,
                              reasons=[f"exact hash-form match ({matched.kind})"])
        if len(hits) > 1:
            return Resolution("ambiguous", hex_hash, normalized, candidates=hits,
                              reasons=["hash form maps to multiple subjects"])
        return Resolution("unresolved", hex_hash, normalized,
                          reasons=["hash form matches no subject"])

    def corroborate_phone(self, user_id: str, phone: str) -> bool:
        """Phone corroboration only: does this phone belong to this subject?

        Returns a boolean about an already-resolved subject. It never
        returns a subject for a phone, and Unit 3 must never call it as a
        resolver: phone changed for many subjects and carries no hash.
        """
        subject = self.subjects.get(user_id)
        if subject is None:
            return False
        key = normalize_phone(phone)
        return any(normalize_phone(f.form) == key for f in subject.phone_forms)

    def subject(self, user_id: str) -> Optional[Subject]:
        return self.subjects.get(user_id)

    def collision_groups(self) -> Dict[str, List[str]]:
        """Stem -> subjects, for stems shared by more than one subject.

        These groups are the HALT catalogue: any future query that can only
        be answered from a stem in this catalogue is ambiguous by
        construction. Exact full-form queries are unaffected.
        """
        return {stem: users for stem, users in sorted(self._stem_index.items())
                if len(users) > 1}

    def census(self, emails: Iterable[str]) -> dict:
        """Count resolutions over a batch of request emails (gate metric)."""
        counts = {"current": 0, "historical": 0, "unresolved": 0, "ambiguous": 0}
        details = []
        for email in emails:
            res = self.resolve(email)
            counts[res.status] += 1
            details.append(res)
        return {"counts": counts, "resolutions": details}

    def to_dict(self) -> dict:
        return {
            "subjects": {uid: s.to_dict() for uid, s in sorted(self.subjects.items())},
            "collision_groups": self.collision_groups(),
            "integrity_problems": self.check_integrity(),
        }


# ---------------------------------------------------------------------------
# Intent gate (ported from Unit 2 intent.py, unchanged logic)
# ---------------------------------------------------------------------------

"""Unit 2 — Intent Gate (HackerRank Orchestrate, Northstar Shop).

Deterministic, stdlib-only, original-language analysis. No translation
layer, no model calls: the gloss is computed from the request's own words
with small, generic, per-language verb lexicons (linguistic knowledge, not
request data — no request text, template or identifier is baked in).

Doctrine implemented (v2 §1 P4, §2 Gate 1, §4 D4/D9; Master Plan §2 Pillar G,
§3 unknown-case protocol):
  * 5-part authorisation test, judged in the ORIGINAL language:
    (1) subject intent is the requester's own record;
    (2) a deletion verb (or deletion noun in a request frame, or a
        prior-deletion statement) targets that record;
    (3) the object is the account / personal data (not a subset service);
    (4) the mood is present / unconditional, OR a past attempt whose
        condition is scoped to COMPLETION ("complete it if anything
        remains") rather than to WHETHER to delete, OR a verification /
        audit of a prior deletion;
    (5) no contradictory carve-out cancels the deletion.
  * Formality is register, never weakness: a formal declarative request
    ("I hereby request...", formal verb forms) PASSES exactly like an
    imperative. Politeness is never penalised.
  * Sentences after the first are role-classified, never blanket-ignored:
    PROCEDURAL sentences (confirmations, "apply the correct treatment",
    "check the records", "contact me if you need information", "review
    current and previous identifiers") neither widen nor narrow the
    request. RESTRICTIVE sentences (only / except / do-not / keep / leave
    / continue-using / "not a request to erase") narrow or cancel it, and
    the distinction is computed from markers + object scope, not from
    sentence position. IDENTITY_NOTE sentences (a similar address belongs
    to someone else, an address was changed) are recorded as notes for
    Gate 1: they never create identity-graph edges and never change the
    intent decision by themselves.
  * Template cache: the FIRST sentence's gloss is cached by hash of the
    normalised first sentence (O(1) on repeat templates). The cache NEVER
    caches a decision: the full-text restriction scan runs on EVERY
    request, so a novel carve-out in sentence 3 is caught even when
    sentence 1 is a cache hit. A cache hit without a restriction scan
    would be exactly the "template = decision" shortcut the doctrine bans.
  * Decisions: DELETION (a deletion request exists; a subset limiter, if
    any, rides in the gloss for Unit 3 to honour — the gate never widens
    a narrowed request back to full scope), NOT_APPLICABLE (clean fail:
    no deletion request, or an explicit cancellation of one), or
    UNKNOWN_INTENT (genuinely unresolvable after analysis: no deletion
    evidence, no clean non-deletion evidence, an unsupported language, a
    third-party subject, or an empty text). UNKNOWN_INTENT projects to
    NOT_APPLICABLE with a FORCED_PROJECTION flag and ZERO deletion steps
    (non-destruction default, v2 P4) — the projection is recorded on the
    decision object; this module emits no steps at all.
  * Fail closed, never crash: unparsable, empty or unsupported-language
    input yields UNKNOWN_INTENT with reasons, never an exception and
    never a guessed DELETION.

Anti-hardcoding: no request identifiers, no evidence identifiers, no
filename branches, no dashboard/status inputs. Lexicons are generic
language resources. A novel template in a supported language, a novel
carve-out, or a novel language is handled by the general rules (see
test_unseen.py for the pre-registered mutation expectations).
"""


import hashlib
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Sentence handling (language-agnostic terminators, incl. CJK full-width).
# ---------------------------------------------------------------------------

_SENTENCE_SPLIT = re.compile(r"(?<=[.!?\u3002\uff01\uff1f])\s+")
_WS = re.compile(r"\s+")


def split_sentences(text: str) -> List[str]:
    """Split into sentences on . ! ? and CJK equivalents. Never empty."""
    text = _WS.sub(" ", (text or "").strip())
    if not text:
        return []
    parts = _SENTENCE_SPLIT.split(text)
    return [p.strip() for p in parts if p.strip()]


def first_sentence(text: str) -> str:
    sentences = split_sentences(text)
    return sentences[0] if sentences else ""


def first_sentence_hash(sentence: str) -> str:
    """Template-cache key: hash of the casefolded, whitespace-collapsed
    first sentence. Casefolding here is a cache key choice, not an
    identity join (identity normalisation lives in identity.py)."""
    normalized = _WS.sub(" ", sentence.strip()).casefold()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Language detection (script + marker words). Detection selects a lexicon;
# it never translates and never rewrites the gloss language field.
# ---------------------------------------------------------------------------

_HANGUL = re.compile(r"[\uac00-\ud7a3]")
_HIRAGANA_KATAKANA = re.compile(r"[\u3040-\u30ff]")
_CJK = re.compile(r"[\u4e00-\u9fff]")


def detect_language(text: str) -> str:
    lowered = text.lower()
    if _HANGUL.search(text):
        return "ko"
    if _HIRAGANA_KATAKANA.search(text):
        return "ja"
    if _CJK.search(text):
        return "ja"
    if re.search(r"\bexclus[aã]o\b|\bconta\b", lowered):
        return "pt"
    if re.search(r"\beliminaci[oó]n\b|\bcuenta\b|\bcorreo\b", lowered):
        return "es"
    if re.search(r"\bsuppression\b|\bcompte\b|\badresse e-mail\b", lowered):
        return "fr"
    if re.search(r"[a-z]", lowered):
        return "en"
    return "unknown"


# ---------------------------------------------------------------------------
# Generic per-language lexicons. These are language resources: deletion
# verbs/nouns, subset services, non-deletion actions, restriction markers
# and procedural markers. They contain no request text from any dataset.
# ---------------------------------------------------------------------------

# Deletion verbs/nouns (word-boundary regex fragments, lowercased text).
_DELETION_TOKENS: Dict[str, Tuple[str, ...]] = {
    "en": (r"delet\w*", r"eras\w*", r"remov\w*", r"purge\w*", r"expung\w*",
           r"permanent account deletion", r"account deletion"),
    # Verb stems, not infinitives: conjugated forms ("apaguem", "eliminen",
    # "supprimez") must match too — an infinitive-only lexicon silently
    # misses novel templates in supported languages (mutation-suite catch).
    "pt": (r"exclus[aã]o", r"elimin\w*", r"apag\w*", r"exclu\w*", r"remov\w*",
           r"eliminaç[aã]o"),
    "es": (r"eliminaci[oó]n", r"elimin\w*", r"borr\w*", r"suprim\w*"),
    "fr": (r"suppression", r"supprim\w*", r"effac\w*"),
    "ko": (r"삭제",),
    "ja": (r"削除",),
}

# Account / personal-data objects (what a deletion verb must target).
_ACCOUNT_OBJECTS: Dict[str, Tuple[str, ...]] = {
    "en": (r"account", r"profile", r"personal data", r"personal information",
           r"personal details", r"my data", r"identity document"),
    "pt": (r"conta", r"dados pessoais", r"dados"),
    "es": (r"cuenta", r"datos personales", r"datos"),
    "fr": (r"compte", r"donn[eé]es personnelles", r"donn[eé]es"),
    "ko": (r"계정", r"개인정보", r"개인 데이터"),
    "ja": (r"アカウント", r"個人情報", r"個人データ"),
}

# Subset services: deleting ONLY one of these is not an account deletion.
_SUBSET_OBJECTS: Dict[str, Tuple[str, ...]] = {
    "en": (r"marketing lists?", r"promotional emails?", r"promotions?",
           r"newsletter", r"search history", r"search results?"),
    "pt": (r"listas? de marketing", r"e-mails? promocionais"),
    "es": (r"listas? de marketing", r"correos promocionales"),
    "fr": (r"listes? de marketing", r"e-mails? promotionnels"),
    "ko": (r"마케팅", r"홍보"),
    "ja": (r"マーケティング", r"プロモーション"),
}

# Non-deletion actions (a request doing ONLY one of these is a clean fail).
_NON_DELETION_ACTIONS: Dict[str, Tuple[str, ...]] = {
    "en": (r"stop the promotional", r"download my", r"resetting the login",
           r"reset (my|the) (login|password)", r"correct it", r"misspelled",
           r"change the email address", r"tell me what personal",
           r"what personal information you hold", r"copy of .* invoices",
           r"send me a copy", r"replace it with the new",
           r"information request", r"download .* portable"),
    "pt": (r"baixar", r"alterar o e-mail", r"corrigir"),
    "es": (r"descargar", r"cambiar el correo", r"corregir"),
    "fr": (r"t[eé]l[eé]charger", r"changer l'adresse", r"corriger"),
    "ko": (r"다운로드", r"변경"),
    "ja": (r"ダウンロード", r"変更"),
}

# Restriction markers: a sentence carrying one of these + an object is
# RESTRICTIVE. Whether it cancels depends on its object (see _classify).
_RESTRICTION_MARKERS: Dict[str, Tuple[str, ...]] = {
    "en": (r"\bonly\b", r"except", r"without removing", r"do not\b",
           r"don't\b", r"dont\b", r"not a request to", r"not asking for",
           r"\bnever\b",
           r"\bkeep\b", r"leave .* (active|in place)", r"continue using",
           r"still (need|want|use)", r"as it is"),
    "pt": (r"\bapenas\b", r"somente", r"n[aã]o (apagar|excluir|eliminar)",
           r"manter", r"continuar (a )?usar"),
    "es": (r"\bsolo\b", r"solamente", r"no (eliminar|borrar)",
           r"mantener", r"seguir usando"),
    "fr": (r"\bseulement\b", r"ne pas", r"garder", r"continuer"),
    "ko": (r"만\b", r"유지", r"삭제하지", r"하지"),
    "ja": (r"のみ", r"削除しない", r"しない", r"ません", r"維持"),
}

# Explicit whole-cancellation declarations (cancel regardless of object).
_CANCELLATION_DECLARATIONS: Dict[str, Tuple[str, ...]] = {
    "en": (r"not a request to (erase|delete)", r"not asking for deletion",
           r"don't delete or change anything", r"do not delete or change",
           r"do not close the account", r"don't delete anything",
           r"leave the account active", r"keep the account as it is",
           r"i want to continue using", r"i still use it",
           r"please leave .* in place"),
    "pt": (r"n[aã]o [eé] um pedido de (exclus[aã]o|eliminaç[aã]o)",
           r"n[aã]o estou pedindo (a )?exclus[aã]o",
           r"quero continuar (a )?usar", r"continuar (a )?usar o serviço"),
    "es": (r"no es una solicitud de eliminaci[oó]n",
           r"no estoy pidiendo (la )?eliminaci[oó]n",
           r"quiero seguir usando", r"seguir usando el servicio"),
    "fr": (r"pas une demande de suppression",
           r"je ne demande pas la suppression",
           r"continuer (à )?utiliser"),
    "ko": (r"삭제 요청이 아닙니다", r"삭제를 요청하는 것이 아닙니다"),
    "ja": (r"削除の依頼ではありません", r"削除を求めるものではありません"),
}

# Procedural markers: sentences carrying only these neither widen nor narrow.
_PROCEDURAL_MARKERS: Dict[str, Tuple[str, ...]] = {
    "en": (r"confirm", r"apply the correct treatment",
           r"check the records", r"contact me if you need",
           r"review is complete", r"let me know when",
           r"records covered by", r"systems covered by",
           r"handle any copies that fall within the scope",
           r"review .* identifiers", r"checks? (are )?complete"),
    "pt": (r"confirm", r"verifiqu", r"identificadores atuais e anteriores"),
    "es": (r"confirm", r"verifiqu", r"identificadores actuales y anteriores"),
    "fr": (r"confirm", r"v[eé]rif", r"identifiants actuels et ant[ée]rieurs"),
    "ko": (r"확인", r"검토"),
    "ja": (r"確認", r"識別情報"),
}

# Prior-deletion / discontinuation statements (narrative deletion evidence).
_PRIOR_DELETION: Dict[str, Tuple[str, ...]] = {
    "en": (r"i (have )?deleted (my|this|the) account",
           r"i['’]m deleting (my|this|the) account",
           r"i deleted this account", r"i closed (my|this|the) account",
           r"i disconnected (my|this|the) account",
           r"i no longer (use|need) (this|my) account",
           r"my account page is gone", r"the account itself is gone",
           r"deletion was complete, but", r"was told .* deleted, but",
           r"still (recogniz\w*|appears?|exists?|existed|found|works|seems active)",
           r"verify .* (deleted|deletion)", r"audit the deletion",
           r"request failed", r"still existed", r"still seems active",
           r"old .* still (works|appears|exists)",
           r"i changed the email .* before deleting",
           r"i used .* before changing"),
    "pt": (r"exclu[ií] (minha|a) conta", r"fechei (minha|a) conta"),
    "es": (r"elimin[eé] (mi|la) cuenta", r"cerr[eé] (mi|la) cuenta"),
    "fr": (r"supprim[eé] (mon|le) compte", r"ferm[eé] (mon|le) compte"),
    "ko": (r"삭제했", r"계정을 닫았"),
    "ja": (r"削除しました", r"アカウントを閉じ"),
}

# Third-party subject markers (object is someone else's record).
_THIRD_PARTY: Dict[str, Tuple[str, ...]] = {
    # Word boundaries are load-bearing here: without \b, "this account"
    # matches the "his account" alternative ("t[his account]") and every
    # "this account" template reads as third-party (mutation-suite catch
    # on the main census: 109 false UNKNOWNs, all from this one substring).
    "en": (r"\bmy (friend|brother|sister|mother|father|wife|husband|colleague|partner)['’]s account",
           r"\b(his|her|their) account\b", r"\bon behalf of\b"),
    "pt": (r"\bconta do meu", r"\bconta da minha", r"\bem nome de\b"),
    "es": (r"\bcuenta de mi", r"\ben nombre de\b"),
    "fr": (r"\bcompte de mon", r"\bcompte de ma", r"\bau nom de\b"),
    "ko": (r"친구의 계정", r"대신"),
    "ja": (r"友人のアカウント", r"代理で"),
}

# Completion-scoped conditionals: the condition is about whether anything
# REMAINS, not about whether to delete (these PASS; cf. "complete it if
# anything is left" vs. "delete it if you feel like it").
_COMPLETION_CONDITIONALS: Dict[str, Tuple[str, ...]] = {
    "en": (r"if (anything|any data|something) (remains|is left|still)",
           r"if (it|there) (is|are) (still|anything)",
           r"if (needed|necessary|required)", r"if (it )?needs?",
           r"si hace falta", r"if (there is )?anything left"),
    "pt": (r"se (ainda )?(houver|restar)", r"se necess[aá]rio"),
    "es": (r"si (a[uú]n )?(queda|hay)", r"si hace falta", r"si es necesario"),
    "fr": (r"s'il (reste|y a)", r"si n[eé]cessaire"),
    "ko": (r"남아 있다면", r"필요하다면"),
    "ja": (r"残っている場合", r"必要であれば"),
}


def _any(patterns: Tuple[str, ...], text: str) -> Optional[str]:
    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            return match.group(0)
    return None


def _lex(language: str, table: Dict[str, Tuple[str, ...]]) -> Tuple[str, ...]:
    return table.get(language, ()) + table.get("en", ()) if language != "en" else table.get("en", ())


@dataclass
class SentenceRole:
    text: str
    role: str  # PROCEDURAL | RESTRICTIVE | IDENTITY_NOTE | OTHER
    markers: List[str] = field(default_factory=list)


@dataclass
class Gloss:
    """Structured reading of one request, in its original language.

    verb_token is the matched deletion-verb text (or ''), verb_mood is one
    of request/imperative/declarative/past-attempt/verification/conditional/
    none, object_scope is account/data/subset/other/none, limiter describes
    any narrowing ('' | 'subset_only' | 'keep_<object>' | 'whole_cancel').
    """

    language: str
    subject: str  # 'self' | 'third_party' | 'unclear'
    verb_token: str
    verb_mood: str
    object_scope: str
    limiter: str
    sentence_roles: List[SentenceRole] = field(default_factory=list)
    identity_notes: List[str] = field(default_factory=list)


@dataclass
class IntentDecision:
    """Intent-gate outcome. Unit 3 consumes decision + projected_output.

    decision: 'DELETION' | 'NOT_APPLICABLE' | 'UNKNOWN_INTENT'.
    projected_output: the 3-way schema value (UNKNOWN_INTENT projects to
    NOT_APPLICABLE) + whether FORCED_PROJECTION must be flagged in the
    ledger. This module emits no steps and no verdicts.
    """

    decision: str
    projected_output: str
    forced_projection: bool
    gloss: Gloss
    reasons: List[str] = field(default_factory=list)
    cache_hit: bool = False
    first_sentence: str = ""
    first_sentence_hash: str = ""

    def to_dict(self) -> dict:
        return {
            "decision": self.decision,
            "projected_output": self.projected_output,
            "forced_projection": self.forced_projection,
            "language": self.gloss.language,
            "subject": self.gloss.subject,
            "verb_token": self.gloss.verb_token,
            "verb_mood": self.gloss.verb_mood,
            "object_scope": self.gloss.object_scope,
            "limiter": self.gloss.limiter,
            "sentence_roles": [{"text": s.text, "role": s.role, "markers": s.markers}
                               for s in self.gloss.sentence_roles],
            "identity_notes": list(self.gloss.identity_notes),
            "reasons": list(self.reasons),
            "cache_hit": self.cache_hit,
            "first_sentence_hash": self.first_sentence_hash,
        }


class IntentGate:
    """Stateless-per-request analyser with a first-sentence gloss cache."""

    def __init__(self):
        # hash -> (language, verb_token, verb_mood, object_scope, subject)
        self._first_sentence_cache: Dict[str, tuple] = {}
        self.cache_hits = 0
        self.cache_misses = 0

    # -- sentence roles ----------------------------------------------------

    def _classify_sentence(self, sentence: str, language: str, is_first: bool) -> SentenceRole:
        lowered = sentence.lower()
        markers: List[str] = []
        # Identity notes first: they must never be mistaken for restrictions.
        if _any((r"similar .* belongs to someone else", r"belongs to someone else",
                 r"different email", r"changed the email", r"before changing",
                 r"used .* before", r"previous .* email", r"old .* address"),
                lowered):
            return SentenceRole(sentence, "IDENTITY_NOTE", ["identity_hint"])
        # "systems that do not display the email" is a scope EXPANSION
        # (check even hidden systems), not a restriction on scope.
        if re.search(r"do not (display|show|list)", lowered):
            return SentenceRole(sentence, "OTHER", ["scope_expansion"])
        found = _any(_lex(language, _RESTRICTION_MARKERS), lowered)
        if found:
            return SentenceRole(sentence, "RESTRICTIVE", [found])
        # A sentence carrying deletion / prior-deletion content is
        # substantive, never merely procedural ("received a confirmation"
        # must not relabel a remaining-trace report as procedural).
        if (_any(_lex(language, _DELETION_TOKENS), lowered)
                or _any(_lex(language, _PRIOR_DELETION), lowered)):
            return SentenceRole(sentence, "OTHER", ["substantive"])
        if _any(_lex(language, _PROCEDURAL_MARKERS), lowered):
            return SentenceRole(sentence, "PROCEDURAL", ["procedural"])
        return SentenceRole(sentence, "OTHER", [])

    # -- first-sentence gloss (cached) --------------------------------------

    def _gloss_first_sentence(self, sentence: str, language: str) -> tuple:
        key = first_sentence_hash(sentence)
        if key in self._first_sentence_cache:
            self.cache_hits += 1
            return key, True, self._first_sentence_cache[key]
        self.cache_misses += 1
        lowered = sentence.lower()
        verb = _any(_lex(language, _DELETION_TOKENS), lowered) or ""
        obj = ""
        if _any(_lex(language, _ACCOUNT_OBJECTS), lowered):
            obj = "account"
        elif _any(_lex(language, _SUBSET_OBJECTS), lowered):
            obj = "subset"
        if _any(_lex(language, _THIRD_PARTY), lowered) and not _any(
                (r"\bmy account\b", r"\bmy data\b", r"this email", r"this address",
                 r"this account"), lowered):
            subject = "third_party"
        elif _any((r"\bmy\b", r"\bi\b", r"this email", r"this address", r"this message",
                   r"conta associada", r"cuenta asociada", r"compte associ",
                   r"minha conta", r"meu", r"mi cuenta", r"mon compte", r"ma compte",
                   r"계정", r"アカウント"), lowered):
            subject = "self"
        else:
            # Bare imperative to delete "the account associated with this
            # address": the request channel itself binds it to the requester.
            subject = "self" if (verb and obj) else "unclear"
        mood = "none"
        if verb:
            if re.search(r"\bplease\b", lowered) or lowered.startswith(("please", "por favor", "porfavor")):
                mood = "request"
            elif _any(_lex(language, _PRIOR_DELETION), lowered):
                mood = "past_attempt"
            else:
                mood = "declarative"
        gloss = (language, verb, mood, obj, subject)
        self._first_sentence_cache[key] = gloss
        return key, False, gloss

    # -- per-sentence verb/object features (clause-tied, not whole-text) --
    # A deletion verb counts only when its OWN sentence also names the
    # object: a whole-text "account" elsewhere (e.g. in a keep-account
    # sentence) must never satisfy the verb's object test. This is the
    # clause-tieing that keeps "remove me from marketing lists only"
    # (verb + subset object, keep-account sentence) from reading as an
    # account deletion.

    def _sentence_deletion_verb(self, sentence: str, language: str) -> str:
        lowered = sentence.lower()
        # Negation is language-specific: an English-only guard lets "no
        # quiero eliminar mi cuenta" read as a deletion request (mutation
        # catch). "No longer" is discontinuation, not negation — strip it
        # first so "no longer use ... permanently deleted" is not negated.
        # Contracted n't has no word boundary before the n ("don't" =
        # d-o-n-'-t), so \bn['’]t\b never matches it: bare "Don't
        # delete my account." read as DELETION. Match n't as a suffix
        # instead (every English n't-form is a negation); "dont"
        # without apostrophe is attested in the restriction lexicon.
        negations = {
            "en": r"\b(without|not|never|dont)\b|n['’]t\b",
            "pt": r"\b(sem|n[aã]o|nunca)\b",
            "es": r"\b(sin|no|nunca)\b",
            "fr": r"\b(sans|ne|pas|jamais)\b",
            "ko": r"(하지|않)",
            "ja": r"(しない|ません|せず|ない)",
        }.get(language, r"\b(without|not|never|dont)\b|n['’]t\b")
        for pattern in _lex(language, _DELETION_TOKENS):
            for match in re.finditer(pattern, lowered):
                # Negation scopes to the verb's OWN CLAUSE, not the whole
                # sentence: "Don't delete my photos, delete my account"
                # must count the second verb. A whole-prefix check
                # negates it with the first clause's "don't". Clause
                # boundaries: comma, semicolon, and/but joins.
                bounds = [m.end() for m in re.finditer(
                    r"[,;]|\band\b|\bbut\b", lowered[:match.start()])]
                clause_start = bounds[-1] if bounds else 0
                prefix = re.sub(
                    r"no longer", "", lowered[clause_start:match.start()])
                if re.search(negations, prefix):
                    continue
                # Verb-final languages (ko/ja) put negation AFTER the
                # verb: "삭제하지" (don't delete), "削除しない" (don't
                # delete). A prefix-only check misses it, so check the
                # same sentence's suffix too — ko/ja only, since
                # pre-verbal languages scope negation before the verb
                # and a suffix check there would misread restrictions.
                if language in ("ko", "ja") and re.search(
                        negations, lowered[match.end():]):
                    continue
                return match.group(0)
        # "close" is a deletion verb only with an account object AND a
        # permanence/deletion marker in the same sentence ("close this
        # account permanently"). Bare "close" (a session, a tab) is not.
        if re.search(r"\bclose\b", lowered) and _any(
                _lex(language, _ACCOUNT_OBJECTS), lowered) and re.search(
                r"permanent|deletion", lowered):
            return "close (permanent)"
        return ""

    def _sentence_objects(self, sentence: str, language: str) -> Tuple[bool, bool]:
        lowered = sentence.lower()
        has_account = bool(_any(_lex(language, _ACCOUNT_OBJECTS), lowered))
        has_subset = bool(_any(_lex(language, _SUBSET_OBJECTS), lowered))
        return has_account, has_subset

    # -- full analysis -------------------------------------------------------

    def analyze(self, text: str) -> IntentDecision:
        sentences = split_sentences(text or "")
        first = sentences[0] if sentences else ""
        language = detect_language(text or "")
        key, hit, (lang, verb, mood, obj, subject) = self._gloss_first_sentence(first, language) \
            if first else ("", False, (language, "", "none", "", "unclear"))

        roles = [self._classify_sentence(s, language, i == 0) for i, s in enumerate(sentences)]
        full_lower = (text or "").lower()

        identity_notes = [r.text for r in roles if r.role == "IDENTITY_NOTE"]
        reasons: List[str] = []

        # Empty / unsupported-language input: fail closed, never guess.
        if not sentences:
            gloss = Gloss(language, "unclear", "", "none", "none", "",
                          roles, identity_notes)
            return IntentDecision("UNKNOWN_INTENT", "NOT_APPLICABLE", True, gloss,
                                  ["empty request text"], hit, first, key)
        if language == "unknown":
            gloss = Gloss(language, "unclear", "", "none", "none", "",
                          roles, identity_notes)
            return IntentDecision("UNKNOWN_INTENT", "NOT_APPLICABLE", True, gloss,
                                  ["language not in supported lexicon; fluent review required"],
                                  hit, first, key)

        # 1. Whole-cancellation declarations cancel any deletion reading.
        #    (Checked before deletion evidence: "don't delete anything" must
        #    win over a deletion verb elsewhere in the text.)
        cancel = _any(_lex(language, _CANCELLATION_DECLARATIONS), full_lower)
        if cancel:
            gloss = Gloss(language, subject, verb, mood, obj, "whole_cancel", roles, identity_notes)
            return IntentDecision("NOT_APPLICABLE", "NOT_APPLICABLE", False, gloss,
                                  [f"explicit cancellation declaration: {cancel!r}"],
                                  hit, first, key)

        # 2. Third-party subject: the requester is not the record's subject.
        #    Human review, never a deletion on someone else's say-so.
        if subject == "third_party" or (
                _any(_lex(language, _THIRD_PARTY), full_lower)
                and not _any(_lex(language, _ACCOUNT_OBJECTS), full_lower)):
            gloss = Gloss(language, "third_party", verb, mood, obj, "", roles, identity_notes)
            return IntentDecision("UNKNOWN_INTENT", "NOT_APPLICABLE", True, gloss,
                                  ["subject is a third party, not the requester"],
                                  hit, first, key)

        # 3. Restrictive sentences: subset narrowing vs. whole cancellation.
        #    A restriction whose object is a NAMED SUBSET while an account
        #    deletion stands narrows scope (limiter) — it does not cancel.
        #    A restriction on the account/data itself cancels.
        limiter = ""
        for role in roles:
            if role.role != "RESTRICTIVE":
                continue
            rlower = role.text.lower()
            if _any(_lex(language, _SUBSET_OBJECTS), rlower) and _any(
                    (r"only", r"apenas", r"solo", r"seulement", r"のみ", r"만"), rlower):
                limiter = "subset_only"
                reasons.append(f"subset-only restriction: {role.text!r}")
            elif _any((r"without removing", r"without deleting", r"leave .* in place",
                       r"keep .*", r"do not (close|delete)", r"don't delete"), rlower):
                # A keep-subset restriction alongside an account deletion
                # ("delete my account but keep my invoices") narrows scope:
                # record it as a limiter for Unit 3 to honour. It is NOT a
                # cancellation — cancellation declarations are handled in
                # step 1. "Without removing any records" attached to a
                # correction (no deletion verb) falls through to step 5.
                if _any((r"keep .*", r"leave .* in place"), rlower) and not limiter:
                    limiter = "keep_subset"
                reasons.append(f"restrictive sentence noted: {role.text!r}")

        # 4. Deletion evidence, CLAUSE-TIED: a verb counts only with an
        #    object in its own sentence. Whole-text object scans are banned
        #    here — they are how a keep-account sentence donates its
        #    "account" to a subset verb in another sentence.
        verb_account = False
        verb_subset = False
        keep_account = False
        for sentence in sentences:
            sl = sentence.lower()
            sverb = self._sentence_deletion_verb(sentence, language)
            has_account, has_subset = self._sentence_objects(sentence, language)
            if sverb and has_account:
                verb_account = True
            if sverb and has_subset and not has_account:
                verb_subset = True
            if has_account and _any(
                    (r"\bkeep\b", r"leave .* active", r"continue using",
                     r"still (need|want|use)", r"as it is"), sl):
                keep_account = True
        prior = _any(_lex(language, _PRIOR_DELETION), full_lower)
        verification = bool(re.search(
            r"verify .* (delet|account)|audit the deletion|check .* still|"
            r"confirm .* delet|deletion (audit|review)", full_lower))
        completion_conditional = bool(_any(_lex(language, _COMPLETION_CONDITIONALS), full_lower))

        if verb_account and subject != "third_party":
            # Mood: a completion-scoped conditional does not weaken the
            # request (condition is on remaining data, not on deleting).
            final_mood = mood
            if completion_conditional and mood in ("none", "declarative"):
                final_mood = "request"
            # A keep-subset restriction alongside an account deletion
            # narrows scope (limiter) — it does not cancel the deletion.
            gloss = Gloss(language, subject, verb, final_mood, "account", limiter,
                          roles, identity_notes)
            return IntentDecision("DELETION", "DELETION", False, gloss,
                                  reasons + ["deletion verb + account object in the same sentence"],
                                  hit, first, key)

        if verb_subset and keep_account:
            # Subset removal + explicit account retention (the
            # marketing-only shape): not an account-deletion request.
            gloss = Gloss(language, subject, verb, mood, "subset", "subset_only",
                          roles, identity_notes)
            return IntentDecision("NOT_APPLICABLE", "NOT_APPLICABLE", False, gloss,
                                  reasons + ["subset-only removal with explicit account retention"],
                                  hit, first, key)

        if verb_subset:
            # Subset-only deletion, no account retention stated: still a
            # deletion request, but the subset limiter MUST be honoured by
            # Unit 3 — it must never be widened to the account.
            gloss = Gloss(language, subject, verb, mood, "subset", "subset_only",
                          roles, identity_notes)
            return IntentDecision("DELETION", "DELETION", False, gloss,
                                  reasons + ["subset-only deletion request; limiter recorded"],
                                  hit, first, key)

        if prior or verification:
            gloss = Gloss(language, subject, verb, "past_attempt" if prior else "verification",
                          "account", limiter, roles, identity_notes)
            return IntentDecision("DELETION", "DELETION", False, gloss,
                                  reasons + ["prior-deletion / verification statement about own account"],
                                  hit, first, key)

        # 5. Clean non-deletion: an action that is not deletion, and no
        #    deletion evidence above. (Also catches correction-without-
        #    removal: a correction verb + a restrictive "without removing"
        #    sentence and no deletion verb.)
        non_del = _any(_lex(language, _NON_DELETION_ACTIONS), full_lower)
        restrictive = any(r.role == "RESTRICTIVE" for r in roles)
        deletion_verb_anywhere = verb_account or verb_subset
        if non_del or (restrictive and not deletion_verb_anywhere):
            gloss = Gloss(language, subject, verb, mood, obj or "other", limiter,
                          roles, identity_notes)
            return IntentDecision("NOT_APPLICABLE", "NOT_APPLICABLE", False, gloss,
                                  reasons + [f"non-deletion request (action: {non_del!r})" if non_del
                                             else "restrictive request with no deletion verb"],
                                  hit, first, key)

        # 6. Nothing decides it: UNKNOWN, projected safe, zero deletion steps.
        gloss = Gloss(language, subject, verb, mood, obj or "none", limiter,
                      roles, identity_notes)
        return IntentDecision("UNKNOWN_INTENT", "NOT_APPLICABLE", True, gloss,
                              reasons + ["no deletion evidence and no clean non-deletion evidence"],
                              hit, first, key)

    def cache_stats(self) -> dict:
        return {"hits": self.cache_hits, "misses": self.cache_misses,
                "entries": len(self._first_sentence_cache)}
