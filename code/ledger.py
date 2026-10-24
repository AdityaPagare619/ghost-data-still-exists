"""Hash-chained ledger writer (Unit 3).

Every adjudication appends one canonical entry: verdict, steps,
citations, internal states, gates, projections, Horizon B gaps, and
the triplet (why + constraint + counterfactual). Entries chain by
SHA-256 over the previous entry hash, so rewriting history is
DETECTABLE (tamper-evident, honestly not tamper-proof). Canonical
JSON (sorted keys, tight separators) makes the chain deterministic:
the same inputs always produce the same chain.
"""

import hashlib
import json

GENESIS_HASH = "0" * 64


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def entry_hash(previous_hash, payload):
    digest = hashlib.sha256()
    digest.update(previous_hash.encode("utf-8"))
    digest.update(canonical_json(payload).encode("utf-8"))
    return digest.hexdigest()


class LedgerWriter:
    def __init__(self):
        self.previous_hash = GENESIS_HASH
        self.entries = []

    def append(self, payload):
        digest = entry_hash(self.previous_hash, payload)
        entry = {"previous_hash": self.previous_hash,
                 "entry_hash": digest, "payload": payload}
        self.entries.append(entry)
        self.previous_hash = digest
        return entry

    def verify_chain(self):
        previous = GENESIS_HASH
        for entry in self.entries:
            if entry["previous_hash"] != previous:
                return False
            if entry_hash(previous, entry["payload"]) != entry["entry_hash"]:
                return False
            previous = entry["entry_hash"]
        return True

    def write_jsonl(self, path):
        with open(path, "w", encoding="utf-8") as handle:
            for entry in self.entries:
                handle.write(canonical_json(entry) + "\n")


def build_triplet(status, findings, internal_states, gaps):
    """why + constraint + counterfactual, from proven parts only."""
    if findings:
        why = "; ".join(
            f"{f['system_id']}/{f['resource_id']} {f['operation']}"
            for f in findings)
        constraint = "deletion complete only when every relevant copy " \
            "has its required treatment and no armed path can recreate it"
        counterfactual = ("if every finding above were remediated and "
                          "verified, the status would become COMPLETE")
    elif status == "COMPLETE":
        why = "no rule violation observed in the horizon; retained " \
            "records minimised and within retention; no armed path"
        constraint = "same completeness invariant as above"
        counterfactual = ("if any retained record regained an identifier "
                          "or any flow armed, the status would flip to "
                          "INCOMPLETE")
    elif status == "NOT_APPLICABLE":
        why = "request does not authorise deletion"
        constraint = "non-destruction on non-authorisation"
        counterfactual = ("if the request had authorised deletion, the "
                          "engine would adjudicate the subject's records")
    else:
        why = "adjudication blocked by an open gate: " \
            + ",".join(sorted(internal_states))
        constraint = "fail closed: no COMPLETE while a gate is open"
        counterfactual = ("if the gate resolved with no violations, the "
                          "status would become COMPLETE")
    return {"why": why, "constraint": constraint,
            "counterfactual": counterfactual,
            "gaps_noted": sorted(gaps)}
