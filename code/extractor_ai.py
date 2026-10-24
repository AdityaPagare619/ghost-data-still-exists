"""Layer-1 AI extraction (Gemini) + verified cache + telemetry.

Model describes, deterministic code decides. This module NEVER returns
a verdict, a rule, or an identifier for the verdict path: it returns
DRAFTS and CROSS-CHECKS that the deterministic engine compares against
its own decisions. A schema-invalid model output is REJECTED, never
repaired. A model output creating or removing a finding without second
corroboration is BLOCKED by design (nothing here feeds steps_json).

The shipped run reads the verified cache and makes ZERO live calls.
Live calls happen only in an explicit refresh run:

    python3 code/extractor_ai.py --refresh [--dataset DIR]

Refresh writes code/extraction_cache.json (PII-free: resource ids,
states, decisions and limiters only -- no names, emails or thread
text) and code/evaluation/telemetry.json (per-call tokens/latency,
no URLs, no credentials). The .md reports quote those numbers inline.

Credential rules (connector custom.gemini): the key travels only as a
surrogate query parameter via dynamic_credentials, only to
generativelanguage.googleapis.com. Raw credentials are never printed,
logged or persisted. Model names are verified against the live model
list at refresh time; the default falls back to gemini-2.5-flash when
the preview is not listed.

Pricing used for cost estimates (Google list rates, stated in
usage_report.md): gemini-3-flash-preview $0.50 / $3.00 per million
input / output tokens. Costs are estimates; token counts are exact
(from usageMetadata).
"""

import argparse
import base64
import csv
import hashlib
import json
import os
import sys
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, "/opt/muse/skills/custom-connector-setup/bin")

from dynamic_credentials import (  # noqa: E402
    url_with_surrogate_query_param, read_json_response)

ALLOWED_HOSTS = ["generativelanguage.googleapis.com"]
API_BASE = "https://generativelanguage.googleapis.com/v1beta"
MODEL_DEFAULT = "gemini-3-flash-preview"
MODEL_FALLBACK = "gemini-2.5-flash"
PRICING_PER_MTOK = {MODEL_DEFAULT: (0.50, 3.00),
                    MODEL_FALLBACK: (0.30, 2.50)}

CACHE_PATH = HERE / "extraction_cache.json"
TELEMETRY_PATH = HERE / "evaluation" / "telemetry.json"
TELEMETRY_CALLS_PATH = HERE / "evaluation" / "telemetry_calls.jsonl"


def _append_call_telemetry(telemetry):
    """Durable per-call record: a later crash must never lose the
    token evidence of calls that already succeeded."""
    try:
        TELEMETRY_CALLS_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(TELEMETRY_CALLS_PATH, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(telemetry) + "\n")
    except OSError as exc:  # noqa: BLE001 - never fail extraction
        print(f"  [telemetry] call record not written: {exc}", flush=True)

VLM_SCHEMA = {
    "type": "OBJECT",
    "properties": {
        "resource_ids": {"type": "ARRAY", "items": {"type": "STRING"}},
        "states": {"type": "ARRAY", "items": {"type": "STRING"}},
    },
    "required": ["resource_ids", "states"],
}
INTENT_SCHEMA = {
    "type": "OBJECT",
    "properties": {
        "decision": {"type": "STRING",
                     "enum": ["DELETION", "NOT_APPLICABLE", "UNKNOWN"]},
        "limiter": {"type": "STRING"},
        "rationale": {"type": "STRING"},
    },
    "required": ["decision", "limiter", "rationale"],
}
SUPPORT_SCHEMA = {
    "type": "OBJECT",
    "properties": {
        "shared_context": {"type": "BOOLEAN"},
        "treatment_draft": {"type": "STRING",
                            "enum": ["REDACT", "DELETE"]},
        "rationale": {"type": "STRING"},
    },
    "required": ["shared_context", "treatment_draft", "rationale"],
}


def validate_schema(obj, schema):
    """Flat stdlib schema gate: required keys present, types match.
    Returns an error string, or None when valid."""
    if not isinstance(obj, dict):
        return "output is not a JSON object"
    for key in schema.get("required", []):
        if key not in obj:
            return f"missing required key: {key}"
    for key, spec in schema.get("properties", {}).items():
        if key not in obj:
            continue
        value = obj[key]
        kind = spec.get("type")
        if kind == "STRING" and not isinstance(value, str):
            return f"key {key} is not a string"
        if kind == "BOOLEAN" and not isinstance(value, bool):
            return f"key {key} is not a boolean"
        if kind == "ARRAY" and not isinstance(value, list):
            return f"key {key} is not an array"
        if kind == "ARRAY" and not all(isinstance(v, str) for v in value):
            return f"key {key} has non-string items"
        if "enum" in spec and value not in spec["enum"]:
            return f"key {key} value {value!r} not in {spec['enum']}"
    return None


class GeminiClient:
    """Minimal generateContent client with telemetry, no retries
    beyond one schema/API retry, and no credential exposure."""

    def __init__(self, model=MODEL_DEFAULT):
        # Env override exists for one reason: when the default model's
        # quota is exhausted, the documented fallback can take over
        # without a code change. The model actually used is recorded
        # in telemetry and cache["model"] either way.
        model = os.environ.get("GHOST_GEMINI_MODEL", model)
        self.model = self._verify_model(model)
        self.calls = []

    def _verify_model(self, model):
        url = url_with_surrogate_query_param(
            f"{API_BASE}/models", "custom.gemini",
            allowed_hosts=ALLOWED_HOSTS)
        req = urllib.request.Request(
            url, headers={"User-Agent": "ghost-data-extractor/1.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = read_json_response(resp)
        names = {m.get("name", "").replace("models/", "")
                 for m in data.get("models", [])}
        if model in names:
            return model
        if MODEL_FALLBACK in names:
            return MODEL_FALLBACK
        raise RuntimeError(f"neither {model} nor {MODEL_FALLBACK} listed")

    def generate(self, job, key, prompt, schema, media=None,
                 media_mime=None, pacing=12):
        """One bounded call with one schema retry and 429 backoff.
        Returns (parsed, telemetry). Raises on repeated failure; the
        caller records it in cache["failures"] and continues (never
        to a guessed output). A 429 on every attempt raises
        QuotaExhausted instead, so the run aborts cleanly. Output
        tokens include thinking tokens: Gemini bills thoughts as
        output, so output = candidates + thoughts."""
        import os
        if self.calls:
            time.sleep(float(os.environ.get("GEMINI_PACING", pacing)))
        parts = [{"text": prompt}]
        if media is not None:
            parts.append({"inline_data": {
                "mime_type": media_mime,
                "data": base64.b64encode(media).decode()}})
        body = {
            "contents": [{"parts": parts}],
            "generationConfig": {
                "responseMimeType": "application/json",
                "responseSchema": schema,
                "temperature": 0,
                # Thinking tokens count against this budget (~980 per
                # call observed); 1024 truncated JSON mid-string twice
                # (finishReason MAX_TOKENS). 8192 leaves real headroom;
                # we pay for tokens used, not for budget.
                "maxOutputTokens": 8192,
            },
        }
        url = url_with_surrogate_query_param(
            f"{API_BASE}/models/{self.model}:generateContent",
            "custom.gemini", allowed_hosts=ALLOWED_HOSTS)
        last_error = None
        attempts = 0
        for attempt in (1, 2):
            attempts = attempt
            started = time.time()
            req = urllib.request.Request(
                url, data=json.dumps(body).encode(),
                headers={"Content-Type": "application/json",
                         "User-Agent": "ghost-data-extractor/1.0"},
                method="POST")
            try:
                with urllib.request.urlopen(req, timeout=180) as resp:
                    data = read_json_response(resp)
            except Exception as exc:  # noqa: BLE001 - telemetry + retry
                code = getattr(exc, "code", None)
                if code == 404:
                    # Listed but not generatable (proven 2026-10-25:
                    # gemini-2.5-flash lists yet 404s on generateContent
                    # for this key's project). A wrong model name never
                    # resolves on retry: fail fast, do not burn jobs.
                    raise ModelUnavailable(
                        f"model {self.model} not generatable (404)")
                if code == 429:
                    retry_after = None
                    try:
                        retry_after = exc.headers.get("Retry-After")
                    except Exception:  # noqa: BLE001
                        pass
                    wait = int(retry_after) + 1 if retry_after \
                        and str(retry_after).isdigit() else 30
                    print(f"  [429] backing off {wait}s", flush=True)
                    time.sleep(wait)
                    # 429 does not consume the schema retry budget,
                    # but it is recorded: a 429 on every attempt is a
                    # quota exhaustion, not a per-file failure.
                    last_error = "429 quota exhausted"
                    continue
                last_error = f"{type(exc).__name__}: {exc}"
                continue
            latency_ms = int((time.time() - started) * 1000)
            finish_reason = data.get("candidates", [{}])[0].get(
                "finishReason")
            if finish_reason == "MAX_TOKENS":
                # Output was cut by budget, not finished: never accept
                # it, even if the fragment happens to parse.
                last_error = "finishReason MAX_TOKENS (truncated output)"
                continue
            try:
                raw_parts = data["candidates"][0]["content"]["parts"]
                text = "".join(
                    p.get("text", "") for p in raw_parts
                    if not p.get("thought"))
                if text.strip().startswith("```"):
                    text = text.strip().strip("`")
                    if text.startswith("json"):
                        text = text[4:]
                parsed = json.loads(text)
            except (KeyError, IndexError, TypeError, ValueError) as exc:
                last_error = f"unparsable response: {exc}"
                continue
            error = validate_schema(parsed, schema)
            if error is not None:
                last_error = f"schema-invalid: {error}"
                continue
            usage = data.get("usageMetadata", {}) or {}
            telemetry = {
                "job": job, "key": key, "model": self.model,
                "input_tokens": usage.get("promptTokenCount", 0),
                "output_tokens": usage.get("candidatesTokenCount", 0)
                + usage.get("thoughtsTokenCount", 0),
                "candidates_tokens": usage.get("candidatesTokenCount", 0),
                "thoughts_tokens": usage.get("thoughtsTokenCount", 0),
                "latency_ms": latency_ms, "attempts": attempt,
                "status": "ok",
            }
            self.calls.append(telemetry)
            _append_call_telemetry(telemetry)
            print(f"  [{job}] {key} ok: in={telemetry['input_tokens']} "
                  f"out={telemetry['output_tokens']} "
                  f"({telemetry['latency_ms']}ms)", flush=True)
            return parsed, telemetry
        telemetry = {"job": job, "key": key, "model": self.model,
                     "input_tokens": 0, "output_tokens": 0,
                     "latency_ms": 0, "attempts": attempts,
                     "status": f"failed: {last_error}"}
        self.calls.append(telemetry)
        _append_call_telemetry(telemetry)
        if last_error and last_error.startswith("429"):
            raise QuotaExhausted(
                f"Gemini quota exhausted ({job}/{key}): {last_error}")
        raise RuntimeError(f"Gemini call failed ({job}/{key}): {last_error}")


class QuotaExhausted(RuntimeError):
    """Raised when Gemini answers 429 on every attempt: the run must
    stop cleanly (cache saved, partial telemetry written) instead of
    burning the remaining jobs against a dead quota."""


class ModelUnavailable(Exception):
    """Raised when Gemini answers 404 for the model: listed but not
    generatable for this key's project. Not a RuntimeError on purpose:
    job loops catch RuntimeError per file, but a wrong model name must
    abort the run fast instead of recording one failure per job."""


def load_cache():
    if CACHE_PATH.exists():
        return json.loads(CACHE_PATH.read_text(encoding="utf-8"))
    return {"version": 1, "model": None, "entries": {}}


def save_cache(cache):
    CACHE_PATH.write_text(json.dumps(cache, indent=2, sort_keys=True),
                          encoding="utf-8")


def sha_key(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def job_vlm(dataset_dir, client, cache):
    """Cross-check the verified binary transcriptions with one VLM
    read per binary. Comparison only; never a finding source."""
    dataset_dir = Path(dataset_dir)
    manifest = list(csv.DictReader(
        open(dataset_dir / "evidence_files.csv", encoding="utf-8")))
    sidecar = json.loads((HERE / "transcriptions.json").read_text(
        encoding="utf-8"))
    # Sidecar is keyed by dataset-relative file path; each entry's
    # records carry the verified resource ids (null when the binary
    # carries no rule-category resource identifier).
    verified_by_path = sidecar.get("entries", {})
    results = []
    for row in manifest:
        path = row.get("file_path", "")
        if not (path.endswith(".png") or path.endswith(".pdf")):
            continue
        data = (dataset_dir / path).read_bytes()
        key = f"vlm:{hashlib.sha256(data).hexdigest()[:16]}"
        verified = verified_by_path.get(path, {})
        verified_ids = {r.get("resource_id")
                        for r in verified.get("records", [])
                        if r.get("resource_id")}
        if key in cache["entries"]:
            parsed = cache["entries"][key]["output"]
        else:
            mime = "image/png" if path.endswith(".png") \
                else "application/pdf"
            prompt = ("Transcribe the structured facts visible in this "
                      "business artifact as JSON: every resource "
                      "identifier (account_*, search_*, support_*, "
                      "analytics_*, audit_record_*, backup_*, data_flow_*, "
                      "tombstone_*, export_*, marketing_*) and every "
                      "status/state word attached to one (ACTIVE, "
                      "DELETED, FOUND, NOT_FOUND, ANONYMIZED, REDACTED, "
                      "BLOCKED, DISABLED, Live, Healthy). Do not infer "
                      "identifiers that are not visible.")
            try:
                parsed, _ = client.generate("vlm", key, prompt,
                                            VLM_SCHEMA, media=data,
                                            media_mime=mime)
            except QuotaExhausted:
                save_cache(cache)
                raise
            except RuntimeError as exc:
                # One bad binary must not kill the refresh, and a
                # missing cross-check is recorded, never invented.
                cache.setdefault("failures", {})[key] = {
                    "job": "vlm", "file_id": row.get("file_id"),
                    "error": str(exc)}
                save_cache(cache)
                results.append({
                    "file_id": row.get("file_id"),
                    "verified_resource_id": sorted(verified_ids),
                    "vlm_resource_ids": [],
                    "verified_in_vlm": [],
                    "verified_missing_in_vlm": [],
                    "failed": True, "error": str(exc)})
                continue
            cache["entries"][key] = {
                "job": "vlm", "file_id": row.get("file_id"),
                "output": parsed}
            save_cache(cache)
        vlm_ids = set(parsed.get("resource_ids", []))
        results.append({
            "file_id": row.get("file_id"),
            "verified_resource_id": sorted(verified_ids),
            "vlm_resource_ids": sorted(vlm_ids),
            "verified_in_vlm": sorted(verified_ids & vlm_ids),
            "verified_missing_in_vlm": sorted(verified_ids - vlm_ids),
            "vlm_extra_ids": sorted(vlm_ids - verified_ids),
        })
    return results


def job_intent(dataset_dir, client, cache):
    """Gloss drafts for the deduplicated multilingual first-sentence
    templates. Compared against the deterministic intent gate."""
    from identity_intent import IntentGate, first_sentence, detect_language
    dataset_dir = Path(dataset_dir)
    sentences = {}
    for name in ("deletion_requests.csv", "sample_deletion_requests.csv"):
        path = dataset_dir / name
        if not path.exists():
            continue
        for row in csv.DictReader(open(path, encoding="utf-8")):
            sent = first_sentence(row["request_text"] or "")
            norm = " ".join(sent.split()).lower()
            sentences.setdefault(sha_key(norm), sent)
    gate = IntentGate()
    results = []
    for key_hash, sent in sorted(sentences.items()):
        key = f"intent:{key_hash}"
        if key in cache["entries"]:
            parsed = cache["entries"][key]["output"]
        else:
            prompt = ("Classify this customer request sentence as JSON. "
                      "decision: DELETION if it asks to delete/erase/"
                      "remove their account or personal data, "
                      "NOT_APPLICABLE if it asks for something else "
                      "(access, correction, export, marketing opt-out, "
                      "update, reset), UNKNOWN if it cannot be decided. "
                      "limiter: subset_only if only part of the data is "
                      "in scope, keep_subset if something must be kept, "
                      "else empty string. rationale: one sentence.\n\n"
                      f"Sentence: {sent}")
            try:
                parsed, _ = client.generate("intent", key, prompt,
                                            INTENT_SCHEMA)
            except QuotaExhausted:
                save_cache(cache)
                raise
            except RuntimeError as exc:
                cache.setdefault("failures", {})[key] = {
                    "job": "intent", "error": str(exc)}
                save_cache(cache)
                det = gate.analyze(sent).to_dict()
                results.append({
                    "sentence": sent,
                    "language": detect_language(sent),
                    "gemini_decision": None,
                    "gemini_limiter": None,
                    "deterministic_decision": det.get("decision"),
                    "deterministic_limiter": det.get("limiter"),
                    "agree": None,
                    "failed": True, "error": str(exc)})
                continue
            cache["entries"][key] = {"job": "intent", "output": parsed}
            save_cache(cache)
        # IntentDecision is an object, not a dict (engine.py uses the
        # same to_dict() conversion). The engine's UNKNOWN_INTENT
        # means the same as the schema's UNKNOWN (undecided); agree
        # is computed on that basis, raw value kept in the row.
        deterministic = gate.analyze(sent).to_dict()
        det_decision = deterministic.get("decision")
        agree = parsed.get("decision") == (
            "UNKNOWN" if det_decision == "UNKNOWN_INTENT" else det_decision)
        results.append({
            "sentence": sent,
            "language": detect_language(sent),
            "gemini_decision": parsed.get("decision"),
            "gemini_limiter": parsed.get("limiter"),
            "deterministic_decision": det_decision,
            "deterministic_limiter": deterministic.get("limiter"),
            "agree": agree,
        })
    return results


def job_support(dataset_dir, client, cache):
    """Shared-context drafts for the sample cases' support findings,
    plus the deterministic comparison. Bounded: one call per distinct
    support resource in the 32 sample findings."""
    sys.path.insert(0, str(HERE))
    import indexer as indexer_mod
    from identity_intent import IdentityGraph
    dataset_dir = Path(dataset_dir)
    # Sample support findings (system + resource) from sample answers.
    support_resources = set()
    for row in csv.DictReader(open(
            dataset_dir / "sample_output.csv", encoding="utf-8")):
        for step in json.loads(row["steps_json"]):
            if step["system_id"] == "support_platform" \
                    and step["phase"] == "FINDING":
                support_resources.add(step["resource_id"])
    # Thread text: indexed records for those resources (fields only).
    import tempfile
    tmp = tempfile.TemporaryDirectory(prefix="ghost-support-")
    indexer_mod.build_index(str(dataset_dir), tmp.name,
                            module_dir=str(HERE))
    index = indexer_mod.Index(tmp.name)
    threads = {}
    for resource in sorted(support_resources):
        keys = index.indexes["by_resource_id"].get(resource, [])
        texts = []
        for record in index.records_for_keys(keys):
            fields = record.get("fields") or {}
            for field in ("message_text", "message_excerpt", "text",
                          "subject", "result"):
                if fields.get(field):
                    texts.append(str(fields[field]))
        threads[resource] = " | ".join(texts)[:1500]
    tmp.cleanup()
    results = []
    for resource, text in sorted(threads.items()):
        if not text:
            continue
        key = f"support:{sha_key(resource + text)}"
        if key in cache["entries"]:
            parsed = cache["entries"][key]["output"]
        else:
            prompt = ("Judge this support record as JSON. "
                      "shared_context: true only if the record "
                      "substantively concerns another identifiable "
                      "person with an independent stake (not a staff "
                      "name, not a passing carrier, not a bare order "
                      "number). treatment_draft: REDACT if the subject's "
                      "identifiers can be stripped leaving the other "
                      "person's issue intelligible, DELETE if the "
                      "record is solely the subject's. rationale: one "
                      "sentence.\n\nRecord: " + text)
            try:
                parsed, _ = client.generate("support", key, prompt,
                                            SUPPORT_SCHEMA)
            except QuotaExhausted:
                save_cache(cache)
                raise
            except RuntimeError as exc:
                cache.setdefault("failures", {})[key] = {
                    "job": "support", "resource": resource,
                    "error": str(exc)}
                save_cache(cache)
                results.append({"resource": resource,
                                "gemini_shared_context": None,
                                "gemini_treatment": None,
                                "failed": True, "error": str(exc)})
                continue
            cache["entries"][key] = {"job": "support",
                                     "resource": resource,
                                     "output": parsed}
            save_cache(cache)
        results.append({"resource": resource,
                        "gemini_shared_context":
                            parsed.get("shared_context"),
                        "gemini_treatment": parsed.get("treatment_draft")})
    return results


def refresh(dataset_dir):
    """Run all Layer-1 jobs live, fill the cache, write telemetry.

    Telemetry is written in every outcome. Per-file failures are
    recorded and counted, never hidden; a quota exhaustion aborts
    cleanly with status partial and complete=False. Returns
    (telemetry, results, complete).
    """
    client = GeminiClient()
    cache = load_cache()
    cache["model"] = client.model
    vlm, intent, support = [], [], []
    status = "complete"
    try:
        vlm = job_vlm(dataset_dir, client, cache)
        intent = job_intent(dataset_dir, client, cache)
        support = job_support(dataset_dir, client, cache)
    except QuotaExhausted:
        status = "partial: quota_exhausted"
    except ModelUnavailable:
        status = "partial: model_unavailable"
    save_cache(cache)
    failed = (sum(1 for r in vlm if r.get("failed"))
              + sum(1 for r in intent if r.get("failed"))
              + sum(1 for r in support if r.get("failed")))
    if status == "complete" and failed:
        status = f"partial: {failed} job failures"
    calls = client.calls
    in_tok = sum(c["input_tokens"] for c in calls)
    out_tok = sum(c["output_tokens"] for c in calls)
    in_rate, out_rate = PRICING_PER_MTOK.get(
        client.model, PRICING_PER_MTOK[MODEL_DEFAULT])
    cost = in_tok / 1_000_000 * in_rate + out_tok / 1_000_000 * out_rate
    telemetry = {
        "model": client.model,
        "status": status,
        "calls": calls,
        "totals": {
            "calls": len(calls),
            "input_tokens": in_tok,
            "output_tokens": out_tok,
            "total_tokens": in_tok + out_tok,
            "estimated_cost_usd": round(cost, 4),
            "per_request_cost_usd": round(cost / 518, 6),
            "per_request_tokens": round((in_tok + out_tok) / 518, 2),
            "avg_latency_ms": round(
                sum(c["latency_ms"] for c in calls) / max(len(calls), 1)),
        },
        "jobs": {
            "vlm": {"binaries": len(vlm),
                    "failed": sum(1 for r in vlm if r.get("failed")),
                    "verified_ids_in_vlm": sum(
                        1 for r in vlm if r["verified_in_vlm"]),
                    "verified_ids_missing": sum(
                        1 for r in vlm if r["verified_missing_in_vlm"])},
            "intent": {"templates": len(intent),
                       "agree": sum(1 for r in intent if r.get("agree")),
                       "failed": sum(1 for r in intent if r.get("failed"))},
            "support": {"threads": len(support),
                        "failed": sum(1 for r in support
                                      if r.get("failed"))},
        },
    }
    TELEMETRY_PATH.parent.mkdir(parents=True, exist_ok=True)
    TELEMETRY_PATH.write_text(json.dumps(telemetry, indent=2),
                              encoding="utf-8")
    return telemetry, {"vlm": vlm, "intent": intent, "support": support}, \
        status == "complete"


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Gemini Layer-1 extraction refresh (live calls).")
    parser.add_argument("--dataset", default=str(REPO_ROOT / "dataset"))
    parser.add_argument("--refresh", action="store_true",
                        help="Run live calls and fill the verified cache.")
    args = parser.parse_args(argv)
    if not args.refresh:
        cache = load_cache()
        print(f"cache entries: {len(cache.get('entries', {}))} "
              f"(model: {cache.get('model')}); pass --refresh for live "
              f"calls. The shipped run uses the cache only.")
        return 0
    telemetry, _, complete = refresh(args.dataset)
    print(json.dumps(telemetry["totals"], indent=2))
    print(json.dumps(telemetry["jobs"], indent=2))
    print(f"status: {telemetry['status']}")
    return 0 if complete else 2


if __name__ == "__main__":
    sys.exit(main())
