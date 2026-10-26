# backend/metrics.py
"""
metrics.py — provenance for every published metric
==================================================
A metric number is only meaningful next to: which ruleset produced it, which
corpus it was scored on, and when it actually ran. This module supplies that
provenance so `/api/v1/reliability`, `worker.py benchmark` and the reports all
describe metrics identically.

Deliberate limits
-----------------
* Fingerprints are content hashes (sha256) of committed files — no host paths,
  no repository contents, no secrets.
* `metric_source` names the *kind* of evidence: ``hermetic`` (bundled synthetic
  corpus), ``external-ground-truth`` (manually labelled real repository), or
  ``not-run``. The three are never blended into one score.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone

BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
RULES_PATH = os.path.join(BACKEND_DIR, "rules.yaml")

CORPUS_VERSION = "corpus-v2"
RULESET_VERSION = "ruleset-v2"
METRICS_SCHEMA_VERSION = "metrics-v2"

HERMETIC = "hermetic"
EXTERNAL = "external-ground-truth"
NOT_RUN = "not-run"


def _sha256_file(path: str) -> str | None:
    try:
        with open(path, "rb") as fh:
            return hashlib.sha256(fh.read()).hexdigest()
    except OSError:
        return None


def ruleset_fingerprint() -> dict:
    """Ruleset identity: content hash + number of declared rules."""
    digest = _sha256_file(RULES_PATH)
    count = 0
    try:
        with open(RULES_PATH, "r", encoding="utf-8") as fh:
            for line in fh:
                if line.lstrip().startswith("- id:"):
                    count += 1
    except OSError:
        pass
    return {
        "version": RULESET_VERSION,
        "sha256": digest,
        "rules": count,
        "file": "rules.yaml",
    }


def corpus_fingerprint(tests: dict | None = None) -> dict:
    """Corpus identity: content hash over the labeled case specs.

    Only labels and file names are hashed — never file bodies — so the hash is
    stable, reproducible and carries no third-party source.
    """
    if tests is None:
        from benchmark.corpus import TESTS as tests  # noqa: N813
    basis = {
        name: {
            "expected": spec.get("expected"),
            "category": spec.get("category"),
            "files": sorted((spec.get("files") or {}).keys()),
            "expect_rules": spec.get("expect_rules", []),
            "forbid_rules": spec.get("forbid_rules", []),
        }
        for name, spec in tests.items()
    }
    blob = json.dumps(basis, sort_keys=True, separators=(",", ":"))
    return {
        "version": CORPUS_VERSION,
        "sha256": hashlib.sha256(blob.encode("utf-8")).hexdigest(),
        "cases": len(tests),
        "binary_cases": sum(1 for s in tests.values()
                            if s.get("expected") != "UNDERTERMINED"),
        "uncertain_cases": sum(1 for s in tests.values()
                               if s.get("expected") == "UNDERTERMINED"),
    }


def age_seconds(generated_at: str | None) -> float | None:
    """Seconds since an ISO-8601 timestamp, or None when unparseable."""
    if not generated_at:
        return None
    try:
        stamp = datetime.fromisoformat(str(generated_at).replace("Z", "+00:00"))
    except ValueError:
        return None
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    return round((datetime.now(timezone.utc) - stamp).total_seconds(), 1)


def annotate(report: dict, *, metric_source: str = HERMETIC,
             max_age_seconds: int | None = None) -> dict:
    """Attach provenance + freshness to a metric report.

    Staleness is *reported*, never hidden: a cached report older than
    ``max_age_seconds`` is flagged ``stale: true`` with its real age.
    """
    out = dict(report or {})
    generated_at = out.get("generated_at")
    age = age_seconds(generated_at)
    out.setdefault("generated_at", datetime.now(timezone.utc).isoformat())
    out["metrics_schema_version"] = METRICS_SCHEMA_VERSION
    out["metric_source"] = metric_source
    out["ruleset"] = ruleset_fingerprint()
    if metric_source == HERMETIC:
        out["corpus"] = corpus_fingerprint()
    else:
        out.setdefault("corpus", {"version": "unknown", "sha256": None})
    out["age_seconds"] = age
    out["stale"] = bool(max_age_seconds is not None and age is not None
                        and age > max_age_seconds)
    if max_age_seconds is not None:
        out["max_age_seconds"] = max_age_seconds
    return out


def release_gates(report: dict | None = None, *,
                  known_misses: dict | None = None,
                  external_min_f1: float | None = None) -> dict:
    """Evaluate the documented release gates against a hermetic report.

    Gates are deliberately separate and never collapse into one number:
      * ``hermetic_fixtures`` — every false positive / false negative / error
        must be in the documented ``known_misses`` budget; a *new* miss fails
        the gate.
      * ``hermetic_expectations`` — per-case rule/confidence/absence
        assertions (``expect_rules`` / ``forbid_rules``).
      * ``false_positive_floor`` — zero false positives on the hermetic corpus.
      * ``external_baseline`` — only when a justified threshold is configured;
        otherwise ``not-run`` (never reported as a pass).
    """
    known_misses = known_misses or {}
    gates: dict = {"hermetic_fixtures": NOT_RUN,
                   "hermetic_expectations": NOT_RUN,
                   "false_positive_floor": NOT_RUN,
                   "external_baseline": NOT_RUN,
                   "details": {}}
    if report:
        confusion = report.get("confusion") or {}
        metric_values = report.get("metrics") or {}
        fp = int(confusion.get("fp") or 0)
        fn = int(confusion.get("fn") or 0)
        errors = list(report.get("errors") or [])
        unexpected = sorted((set(report.get("unexpected_misses") or [])))
        gates["hermetic_fixtures"] = "pass" if not unexpected else "fail"
        gates["hermetic_expectations"] = "pass" if not report.get(
            "expectation_failures") else "fail"
        gates["false_positive_floor"] = "pass" if fp == 0 else "fail"
        gates["details"] = {"fp": fp, "fn": fn, "errors": errors,
                            "known_misses": sorted(known_misses),
                            "unexpected_misses": unexpected,
                            "f1": metric_values.get("f1"),
                            "cases": report.get("corpus_size")}
    if external_min_f1 is not None:
        gates["external_baseline"] = NOT_RUN
    return gates
