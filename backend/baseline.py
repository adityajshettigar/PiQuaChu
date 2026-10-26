# backend/baseline.py
"""
baseline.py — versioned scan baselines, delta classification and CI gate policy
===============================================================================
Turns a committed baseline into deterministic CI semantics:

    scan -> compare against baseline -> new / persistent / resolved / changed
         -> gate on *new actionable* findings by policy (not on score deltas)

Design rules
------------
* **No source, no secrets, no host paths.** A baseline stores only identity
  fields: fingerprint, rule id, normalized relative path, category, severity,
  confidence tier, an optional site-signature hash (for move/rename best-effort
  matching) and suppression rationales. Nothing else survives serialization.
* **Strict import.** Anything malformed, absolute-pathed, wildcarded or
  suspiciously broad raises ``BaselineError`` — the caller must fail safely
  (exit 2), never "assume no new issues".
* **Honest identity.** Primary match is the stable Phase 2 fingerprint
  (line-shift immune). Renames/moves fall back to a unique rule+site-signature
  match and are labelled ``moved``; ambiguity marks the comparison uncertain
  instead of declaring a clean result.
* **Deterministic gate.** Policy is ``<scope>-<severity>`` (scope: new,
  changed, any | none). Low-confidence (inconclusive/informational) findings
  are annotations by default and only gate when explicitly configured.

Exit-code contract used by the CLI (and documented in the Phase 3 report):
    0 = pass, 1 = gate policy triggered, 2 = baseline/usage error (fail safe).
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import re

KIND = "piquachu-baseline"
SCHEMA_VERSION = 1

SEVERITIES = ("INFO", "WARNING", "ERROR")
_SEVERITY_RANK = {"INFO": 0, "WARNING": 1, "ERROR": 2}
_CONFIDENCE_TIERS = ("high", "medium", "low", "inconclusive")

# Level aliases so `--fail-on new-high` works alongside rule severities.
LEVEL_ALIASES = {
    "info": "INFO", "note": "INFO", "low": "INFO",
    "warning": "WARNING", "medium": "WARNING", "warn": "WARNING",
    "error": "ERROR", "high": "ERROR", "critical": "ERROR", "crit": "ERROR",
}
SCOPES = ("new", "changed", "any")

_FINGERPRINT_RE = re.compile(r"^pqc1-[0-9a-f]{24}$")
_RULE_ID_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._/-]{0,119}$")
_SAFE_PATH_RE = re.compile(r"^[^\0*\[\]{}<>|&$`\\]{1,400}$")
_SITE_RE = re.compile(r"^(?:pattern:[^|]{1,200}|call:.{1,200}|h=[0-9a-f]{6,64})$")
_MAX_SUPPRESSION_YEARS_DAYS = 365
_MIN_RATIONALE = 10
_MAX_ENTRIES = 50_000


class BaselineError(Exception):
    """Malformed / suspicious baseline. Callers must fail safely (exit 2)."""


# ---------------------------------------------------------------------------
# Strict field validation
# ---------------------------------------------------------------------------

def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise BaselineError(msg)


def _validate_rel_path(path, *, what: str) -> str:
    _require(isinstance(path, str) and path, f"{what}: path must be a non-empty string")
    p = path.replace("\\", "/")
    _require(not p.startswith("/"), f"{what}: absolute path is not allowed: {path!r}")
    _require(not re.match(r"^[A-Za-z]:/", p), f"{what}: drive-letter path is not allowed: {path!r}")
    _require(".." not in p.split("/"), f"{what}: path traversal ('..') is not allowed: {path!r}")
    # A suppression must name ONE exact file: directory/prefix scopes are the
    # usual way a waiver silently covers a whole tree, so they are rejected.
    _require(not p.endswith("/") and p.rsplit("/", 1)[-1] not in ("", "."),
             f"{what}: expected one exact file, not a directory or prefix: {path!r}")
    _require(_SAFE_PATH_RE.match(p) is not None,
             f"{what}: suspicious path characters: {path!r}")
    _require(not any(ch in p for ch in "*?"),
             f"{what}: wildcard paths are not allowed (too broad): {path!r}")
    return p


def _validate_entry(entry, *, index: int) -> dict:
    what = f"findings[{index}]"
    _require(isinstance(entry, dict), f"{what}: must be an object")
    allowed = {"fingerprint", "rule_id", "path", "category", "severity",
               "confidence", "site", "nist_standard", "engine"}
    extra = set(entry) - allowed
    _require(not extra, f"{what}: unknown field(s) {sorted(extra)}")
    fp = entry.get("fingerprint")
    _require(isinstance(fp, str) and _FINGERPRINT_RE.match(fp or ""),
             f"{what}: bad fingerprint {fp!r} (expected pqc1-<24 hex>)")
    rule = entry.get("rule_id")
    _require(isinstance(rule, str) and _RULE_ID_RE.match(rule or ""),
             f"{what}: bad rule_id {rule!r}")
    _require(rule not in {"*", "all"}, f"{what}: rule_id may not be a wildcard")
    rel = _validate_rel_path(entry.get("path"), what=what)
    severity = entry.get("severity")
    _require(severity in SEVERITIES, f"{what}: severity {severity!r} not in {SEVERITIES}")
    confidence = entry.get("confidence")
    _require(confidence in _CONFIDENCE_TIERS,
             f"{what}: confidence {confidence!r} not in {_CONFIDENCE_TIERS}")
    site = entry.get("site")
    if site is not None:
        _require(isinstance(site, str) and _SITE_RE.match(site),
                 f"{what}: site signature must be a hash, not source text: {site!r}")
    out = {
        "fingerprint": fp,
        "rule_id": rule,
        "path": rel,
        "category": str(entry.get("category") or ""),
        "severity": severity,
        "confidence": confidence,
    }
    if site:
        out["site"] = site
    if entry.get("nist_standard"):
        out["nist_standard"] = str(entry["nist_standard"])
    if entry.get("engine"):
        out["engine"] = str(entry["engine"])
    return out


def _validate_suppression(sup, *, index: int, today: _dt.date) -> dict:
    what = f"suppressions[{index}]"
    _require(isinstance(sup, dict), f"{what}: must be an object")
    allowed = {"kind", "fingerprint", "rule_id", "path", "rationale", "expires"}
    extra = set(sup) - allowed
    _require(not extra, f"{what}: unknown field(s) {sorted(extra)}")

    kind = sup.get("kind", "fingerprint")
    _require(kind in {"fingerprint", "rule-file"},
             f"{what}: kind must be 'fingerprint' or 'rule-file', got {kind!r}")

    fp = sup.get("fingerprint")
    rule = sup.get("rule_id")
    path = sup.get("path")
    if kind == "fingerprint":
        _require(isinstance(fp, str) and _FINGERPRINT_RE.match(fp or ""),
                 f"{what}: fingerprint-scoped suppression needs a valid fingerprint")
        _require(not rule and not path,
                 f"{what}: fingerprint suppression must not carry rule/path")
    else:  # rule-file: narrowest non-fingerprint scope — exact file + exact rule
        _require(isinstance(rule, str) and _RULE_ID_RE.match(rule or ""),
                 f"{what}: rule-file suppression needs an exact rule_id")
        _require(rule not in {"*", "all"}, f"{what}: rule may not be a wildcard")
        _require(path is not None,
                 f"{what}: rule-file suppression must name one exact file "
                 f"(directory/wildcard suppressions are rejected as too broad)")
        _require(fp is None,
                 f"{what}: use kind 'fingerprint' when a fingerprint is given")

    rationale = sup.get("rationale")
    _require(isinstance(rationale, str) and rationale.strip().__len__() >= _MIN_RATIONALE,
             f"{what}: rationale must be at least {_MIN_RATIONALE} characters "
             f"(suppressions must justify themselves)")

    expires = sup.get("expires")
    _require(isinstance(expires, str) and re.match(r"^\d{4}-\d{2}-\d{2}$", expires or ""),
             f"{what}: expires must be an ISO date (YYYY-MM-DD)")
    try:
        exp_date = _dt.date.fromisoformat(expires)
    except ValueError as exc:
        raise BaselineError(f"{what}: invalid expiry date {expires!r}") from exc
    horizon = (exp_date - today).days
    # Past-dated expiries are NOT an error here: validate_baseline() partitions
    # them into expired_suppressions (inactive + reported) so an old waiver
    # re-surfaces its finding instead of breaking the whole pipeline.
    _require(horizon <= _MAX_SUPPRESSION_YEARS_DAYS,
             f"{what}: expiry {expires} is more than {_MAX_SUPPRESSION_YEARS_DAYS} "
             f"days out (suspiciously long for a narrow suppression)")

    out = {
        "kind": kind,
        "rationale": rationale.strip(),
        "expires": expires,
    }
    if kind == "fingerprint":
        out["fingerprint"] = fp
    else:
        out["rule_id"] = rule
        out["path"] = _validate_rel_path(path, what=what)
    return out


# ---------------------------------------------------------------------------
# Load / build / save
# ---------------------------------------------------------------------------

def validate_baseline(data, *, source: str = "baseline") -> dict:
    """Strictly validate a decoded baseline document. Returns a normalized copy."""
    _require(isinstance(data, dict), f"{source}: root must be a JSON object")
    _require(data.get("kind") in (None, KIND),
             f"{source}: kind must be {KIND!r}, got {data.get('kind')!r}")
    extra = set(data) - {"kind", "schema_version", "generated_at", "scanner_version",
                         "engine_version", "model_version", "ruleset", "findings",
                         "suppressions", "expired_suppressions"}
    _require(not extra, f"{source}: unknown top-level field(s) {sorted(extra)}")
    ver = data.get("schema_version")
    _require(ver == SCHEMA_VERSION,
             f"{source}: unsupported schema_version {ver!r} (this build supports {SCHEMA_VERSION})")

    ruleset = data.get("ruleset")
    _require(ruleset is None or isinstance(ruleset, dict),
             f"{source}: ruleset must be an object")
    if ruleset:
        sha = ruleset.get("sha256")
        _require(sha is None or (isinstance(sha, str) and re.match(r"^[0-9a-f]{64}$", sha)),
                 f"{source}: ruleset.sha256 must be a sha256 hex digest")
        ver = ruleset.get("version")
        _require(ver is None or (isinstance(ver, str) and len(ver) <= 64),
                 f"{source}: ruleset.version must be a short string")
        extra_r = set(ruleset) - {"sha256", "rule_count", "version"}
        _require(not extra_r, f"{source}: unknown ruleset field(s) {sorted(extra_r)}")

    findings = data.get("findings")
    _require(isinstance(findings, list), f"{source}: findings must be a list")
    _require(len(findings) <= _MAX_ENTRIES,
             f"{source}: {len(findings)} entries exceeds {_MAX_ENTRIES}")
    seen_fps: set[str] = set()
    entries = []
    for i, entry in enumerate(findings):
        norm = _validate_entry(entry, index=i)
        _require(norm["fingerprint"] not in seen_fps,
                 f"{source}: duplicate fingerprint {norm['fingerprint']}")
        seen_fps.add(norm["fingerprint"])
        entries.append(norm)
    entries.sort(key=lambda e: (e["path"], e["rule_id"], e["fingerprint"]))

    today = _dt.date.today()
    suppressions = data.get("suppressions") or []
    _require(isinstance(suppressions, list), f"{source}: suppressions must be a list")
    expired_in = data.get("expired_suppressions") or []
    _require(isinstance(expired_in, list),
             f"{source}: expired_suppressions must be a list")
    all_sups = [_validate_suppression(s, index=i, today=today)
                for i, s in enumerate(suppressions)]
    all_sups += [_validate_suppression(s, index=f"expired[{i}]", today=today)
                 for i, s in enumerate(expired_in)]
    active, expired = [], []
    for s in all_sups:
        if _dt.date.fromisoformat(s["expires"]) < today:
            expired.append(s)
        else:
            active.append(s)
    active.sort(key=lambda s: (s.get("fingerprint") or "", s.get("rule_id") or "",
                               s.get("path") or ""))
    expired.sort(key=lambda s: s["expires"])

    return {
        "kind": KIND,
        "schema_version": SCHEMA_VERSION,
        "generated_at": data.get("generated_at"),
        "scanner_version": data.get("scanner_version"),
        "engine_version": data.get("engine_version"),
        "model_version": data.get("model_version"),
        "ruleset": dict(ruleset or {}),
        "findings": entries,
        "suppressions": active,
        "expired_suppressions": expired,
    }


def load_baseline(path: str) -> dict:
    """Read + strictly validate a baseline file. Raises BaselineError on any
    problem (missing file, invalid JSON, schema violation, broad suppression)."""
    _require(isinstance(path, str) and path, "baseline path must be a non-empty string")
    if not os.path.isfile(path):
        raise BaselineError(f"baseline file not found: {path}")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, UnicodeDecodeError) as exc:
        raise BaselineError(f"baseline unreadable: {path} ({exc})") from exc
    except json.JSONDecodeError as exc:
        raise BaselineError(
            f"baseline is not valid JSON: {path} (line {exc.lineno}, col {exc.colno}) — "
            f"refusing to treat the scan as baseline-clean") from exc
    return validate_baseline(data, source=path)


def _finding_site(finding: dict) -> str | None:
    """Hash-only site signature for move/rename matching (never source text).

    `evidence.annotate` records `site_signature = h=<sha1(sig)[:24]>` so the
    baseline stores a digest of the call-site signature, never the text.
    """
    import hashlib as _hashlib
    sig = finding.get("site_signature")
    if isinstance(sig, str) and _SITE_RE.match(sig):
        return sig
    raw = finding.get("evidence_signature")
    if isinstance(raw, str) and raw:
        return "h=" + _hashlib.sha1(raw.encode("utf-8", errors="replace")).hexdigest()[:24]
    return None


def _entry_from_finding(finding: dict) -> dict:
    fp = finding.get("fingerprint")
    if not isinstance(fp, str) or not _FINGERPRINT_RE.match(fp):
        raise BaselineError(
            f"finding without a stable fingerprint cannot be baselined: "
            f"{finding.get('rule_id') or finding.get('vulnerability')} "
            f"in {finding.get('file')!r}")
    path = _validate_rel_path(finding.get("file"), what="finding path")
    severity = finding.get("severity")
    _require(severity in SEVERITIES,
             f"finding severity {severity!r} not in {SEVERITIES} (rule {finding.get('rule_id')!r})")
    confidence = finding.get("confidence_tier")
    _require(confidence in _CONFIDENCE_TIERS,
             f"finding confidence {confidence!r} not in {_CONFIDENCE_TIERS}")
    entry = {
        "fingerprint": fp,
        "rule_id": str(finding.get("rule_id") or finding.get("vulnerability")),
        "path": path,
        "category": str(finding.get("category") or ""),
        "severity": severity,
        "confidence": confidence,
    }
    site = _finding_site(finding)
    if site:
        entry["site"] = site
    if finding.get("nist_standard"):
        entry["nist_standard"] = str(finding["nist_standard"])
    if finding.get("engine"):
        entry["engine"] = str(finding["engine"])
    return entry


def build_baseline(findings: list, *, ruleset: dict | None = None,
                   scanner_version: str | None = None,
                   engine_version: str | None = None,
                   model_version: str | None = None,
                   suppressions: list | None = None,
                   generated_at: str | None = None) -> dict:
    """Build a baseline document from normalized findings (sorted, deduped)."""
    entries: dict[str, dict] = {}
    for finding in findings or []:
        if finding.get("pqc_compliant"):
            continue  # PASS evidence is not a defect to remember
        entry = _entry_from_finding(finding)
        entries[entry["fingerprint"]] = entry
    data = {
        "kind": KIND,
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at or _dt.datetime.now(_dt.timezone.utc)
                        .replace(microsecond=0).isoformat(),
        "scanner_version": scanner_version,
        "engine_version": engine_version,
        "model_version": model_version,
        "ruleset": dict(ruleset or {}),
        "findings": sorted(entries.values(),
                           key=lambda e: (e["path"], e["rule_id"], e["fingerprint"])),
        "suppressions": suppressions or [],
    }
    return validate_baseline(data, source="new baseline")


def diff_baselines(old: dict | None, new: dict) -> dict:
    """What would change if `new` replaced `old`? Used by --update-baseline so
    the operator always sees added/removed/changed entries before any write."""
    old_by_fp = {e["fingerprint"]: e for e in (old or {}).get("findings", [])}
    new_by_fp = {e["fingerprint"]: e for e in new.get("findings", [])}
    added = [new_by_fp[fp] for fp in sorted(set(new_by_fp) - set(old_by_fp))]
    removed = [old_by_fp[fp] for fp in sorted(set(old_by_fp) - set(new_by_fp))]
    changed = []
    for fp in sorted(set(new_by_fp) & set(old_by_fp)):
        deltas = {k: {"from": old_by_fp[fp].get(k), "to": new_by_fp[fp].get(k)}
                  for k in ("path", "severity", "confidence", "category", "rule_id")
                  if old_by_fp[fp].get(k) != new_by_fp[fp].get(k)}
        if deltas:
            changed.append({"fingerprint": fp, "fields": deltas})
    old_sup = {(s.get("fingerprint"), s.get("rule_id"), s.get("path"))
               for s in (old or {}).get("suppressions", [])}
    old_sup |= {(s.get("fingerprint"), s.get("rule_id"), s.get("path"))
                for s in (old or {}).get("expired_suppressions", [])}
    new_sup = {(s.get("fingerprint"), s.get("rule_id"), s.get("path"))
               for s in new.get("suppressions", [])}
    return {
        "added": added,
        "removed": removed,
        "changed": changed,
        "suppressions_added": sorted(new_sup - old_sup, key=str),
        "suppressions_removed": sorted(old_sup - new_sup, key=str),
        "total_before": len(old_by_fp) if old else 0,
        "total_after": len(new_by_fp),
    }


def baseline_changes_summary(diff: dict) -> str:
    """Human-readable change block printed by --update-baseline."""
    lines = [
        f"Baseline changes: {diff['total_before']} -> {diff['total_after']} entries "
        f"(+{len(diff['added'])} added, -{len(diff['removed'])} removed, "
        f"~{len(diff['changed'])} changed)"
    ]
    for e in diff["added"][:50]:
        lines.append(f"  + {e['path']}:{e['rule_id']} [{e['severity']}] {e['fingerprint']}")
    for e in diff["removed"][:50]:
        lines.append(f"  - {e['path']}:{e['rule_id']} [{e['severity']}] {e['fingerprint']}")
    for c in diff["changed"][:50]:
        fields = ", ".join(f"{k}: {v['from']!r}->{v['to']!r}"
                           for k, v in c["fields"].items())
        lines.append(f"  ~ {c['fingerprint']} ({fields})")
    for sup in diff["suppressions_added"][:50]:
        lines.append(f"  + suppression {sup}")
    for sup in diff["suppressions_removed"][:50]:
        lines.append(f"  - suppression {sup}")
    more = (len(diff["added"]) + len(diff["removed"]) + len(diff["changed"])
            + len(diff["suppressions_added"]) + len(diff["suppressions_removed"]))
    if more > 150:
        lines.append(f"  … {more - 150} more change(s) omitted")
    return "\n".join(lines)


def save_baseline(baseline: dict, path: str, *, force: bool = False,
                  allow_in_ci: bool = False) -> dict:
    """Atomically write a baseline. Refuses to overwrite without force=True and
    refuses CI runs unless allow_in_ci=True — updates are never the default
    action anywhere, least of all in CI. Returns the diff vs the previous file.
    """
    data = validate_baseline(baseline, source="baseline to write")
    ci_env = any(os.environ.get(k) for k in ("CI", "GITHUB_ACTIONS", "GITLAB_CI"))
    if ci_env and not allow_in_ci:
        raise BaselineError(
            "refusing to write a baseline in a CI environment (CI/GITHUB_ACTIONS/"
            "GITLAB_CI is set) — baseline updates must be an explicit local "
            "action; pass --allow-in-ci only if you really mean it")
    exists = os.path.exists(path)
    if exists and not force:
        raise BaselineError(
            f"baseline already exists: {path} — --update-baseline never "
            f"silently overwrites; re-run with --force after reviewing the changes")

    old = None
    if exists:
        old = load_baseline(path)  # strict: a corrupt existing file also blocks
    diff = diff_baselines(old, data)

    tmp = f"{path}.tmp.{os.getpid()}"
    text = json.dumps(data, indent=2, sort_keys=False, ensure_ascii=False) + "\n"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        if exists:
            # preserve permissions of the file we replace
            os.chmod(tmp, os.stat(path).st_mode & 0o7777)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass
    return diff


# ---------------------------------------------------------------------------
# Delta classification
# ---------------------------------------------------------------------------

_CHANGED_FIELDS = ("severity", "category", "confidence", "nist_standard")


def _current_value(finding: dict, field: str):
    """Baseline field -> the *current* finding's matching value. `confidence`
    is the evidence tier (confidence_tier) — findings may also carry an
    unrelated `confidence` enrichment field that must not be compared."""
    if field == "confidence":
        val = finding.get("confidence_tier")
    elif field == "severity":
        val = finding.get("severity")
        return str(val).upper() if val else None
    else:
        val = finding.get(field)
    return val if val not in (None, "") else None


def compare(findings: list, baseline: dict | None, *, baseline_path: str | None = None,
            ruleset_sha256: str | None = None) -> dict:
    """Classify current findings against a baseline.

    Statuses: new / persistent / moved (best-effort) / changed / suppressed /
    resolved. `uncertain.reasons` lists anything that makes "clean" unprovable.
    """
    current = {}
    for finding in findings or []:
        if finding.get("pqc_compliant"):
            continue
        fp = finding.get("fingerprint")
        if isinstance(fp, str) and fp:
            current[fp] = finding

    reasons: list[str] = []
    counts = {"new": 0, "persistent": 0, "moved": 0, "changed": 0,
              "suppressed": 0, "resolved": 0}
    new_items: list[dict] = []
    persistent_items: list[dict] = []
    moved_items: list[dict] = []
    changed_items: list[dict] = []
    suppressed_items: list[dict] = []
    resolved_items: list[dict] = []

    if baseline is None:
        # Explicit no-baseline mode: everything actionable counts as new.
        for fp in sorted(current):
            f = dict(current[fp])
            f["gate_excluded"] = _is_annotation(f)
            new_items.append(f)
        counts["new"] = len(new_items)
        return {
            "mode": "no-baseline",
            "baseline": {"path": baseline_path, "present": False},
            "counts": counts,
            "new": new_items, "persistent": [], "moved": [], "changed": [],
            "suppressed": [], "resolved": [],
            "annotations": _annotation_counts(new_items),
            "uncertain": {"is_uncertain": True,
                          "reasons": ["no baseline supplied — every actionable "
                                      f"finding is treated as new ({len(new_items)})"]},
        }

    base_by_fp = {e["fingerprint"]: e for e in baseline.get("findings", [])}
    if ruleset_sha256 and baseline.get("ruleset", {}).get("sha256") \
            and baseline["ruleset"]["sha256"] != ruleset_sha256:
        reasons.append(
            "ruleset hash differs from the baseline (rules were added/changed "
            "since the baseline was written) — classification is uncertain")

    # Suppression matching (fingerprint-exact, or rule+file for kind rule-file).
    sups_fp = {s["fingerprint"]: s for s in baseline.get("suppressions", [])
               if s.get("kind") == "fingerprint"}
    sups_rf = [s for s in baseline.get("suppressions", []) if s.get("kind") == "rule-file"]

    def _match_suppression(finding) -> dict | None:
        fp = finding.get("fingerprint")
        if fp in sups_fp:
            return sups_fp[fp]
        path = str(finding.get("file") or "").replace("\\", "/")
        rule = finding.get("rule_id") or finding.get("vulnerability")
        for s in sups_rf:
            if s["rule_id"] == rule and s["path"] == path:
                return s
        return None

    # Move/rename best-effort index: rule + site signature hash -> entries.
    site_index: dict[tuple, list[dict]] = {}
    for entry in baseline.get("findings", []):
        if entry.get("site"):
            site_index.setdefault((entry["rule_id"], entry["site"]), []).append(entry)

    matched_base: set[str] = set()
    for fp in sorted(current):
        finding = current[fp]
        sup = _match_suppression(finding)
        if sup is not None:
            if fp in base_by_fp:
                matched_base.add(fp)  # waived, not resolved
            item = {"fingerprint": fp,
                    "rule_id": finding.get("rule_id"),
                    "file": finding.get("file"),
                    "line": finding.get("line") or finding.get("line_start"),
                    "severity": finding.get("severity"),
                    "suppression": {"kind": sup["kind"],
                                    "rationale": sup["rationale"],
                                    "expires": sup["expires"]}}
            suppressed_items.append(item)
            counts["suppressed"] += 1
            continue

        entry = base_by_fp.get(fp)
        if entry is not None:
            matched_base.add(fp)
            diffs = {k: {"baseline": entry.get(k), "current": cur}
                     for k in _CHANGED_FIELDS
                     for cur in [_current_value(finding, k)]
                     if entry.get(k) and cur and entry.get(k) != cur}
            if diffs:
                changed_items.append({
                    "fingerprint": fp,
                    "rule_id": finding.get("rule_id"),
                    "file": finding.get("file"),
                    "line": finding.get("line") or finding.get("line_start"),
                    "differences": diffs,
                    "baseline": {k: entry.get(k) for k in
                                 ("severity", "confidence", "category", "path")},
                    "current_severity": finding.get("severity"),
                })
                counts["changed"] += 1
            else:
                item = dict(finding)
                item["gate_excluded"] = _is_annotation(finding)
                item["baseline_status"] = "persistent"
                persistent_items.append(item)
                counts["persistent"] += 1
            continue

        # Best-effort move/rename match: unique (rule, site hash) pair.
        site = _finding_site(finding)
        candidates = site_index.get((finding.get("rule_id"), site), []) if site else []
        candidates = [c for c in candidates if c["fingerprint"] not in matched_base]
        if len(candidates) == 1:
            matched_base.add(candidates[0]["fingerprint"])
            item = dict(finding)
            item["baseline_status"] = "moved"
            item["moved_from"] = candidates[0]["path"]
            item["gate_excluded"] = _is_annotation(finding)
            moved_items.append(item)
            counts["moved"] += 1
        elif len(candidates) > 1:
            item = dict(finding)
            item["baseline_status"] = "new"
            item["uncertain_identity"] = True
            item["gate_excluded"] = _is_annotation(finding)
            new_items.append(item)
            counts["new"] += 1
        else:
            item = dict(finding)
            item["baseline_status"] = "new"
            item["gate_excluded"] = _is_annotation(finding)
            new_items.append(item)
            counts["new"] += 1

    if moved_items:
        reasons.append(
            f"{len(moved_items)} finding(s) matched the baseline only via "
            "best-effort rule+site-signature identity (file rename or moved "
            "code) — identity could not be proven from the fingerprint alone")

    for fp in sorted(set(base_by_fp) - matched_base):
        entry = base_by_fp[fp]
        if any(s.get("kind") == "fingerprint" and s["fingerprint"] == fp
               for s in baseline.get("suppressions", [])):
            continue  # suppressed entries are not "resolved" — they are waived
        resolved_items.append(entry)
        counts["resolved"] += 1

    all_new_uncertain = any(i.get("uncertain_identity") for i in new_items)
    if all_new_uncertain:
        reasons.append("some new findings could not be matched to baseline "
                       "entries unambiguously (multiple rename candidates)")

    return {
        "mode": "baseline",
        "baseline": {
            "path": baseline_path,
            "present": True,
            "schema_version": baseline.get("schema_version"),
            "generated_at": baseline.get("generated_at"),
            "ruleset": baseline.get("ruleset"),
            "entry_count": len(base_by_fp),
            "suppression_count": len(baseline.get("suppressions", [])),
            "expired_suppression_count": len(baseline.get("expired_suppressions", [])),
            "expired_suppressions": [
                {"expires": s.get("expires"),
                 "scope": s.get("fingerprint") or
                          f"{s.get('rule_id')}@{s.get('path')}"}
                for s in baseline.get("expired_suppressions", [])],
        },
        "ruleset": {"sha256": ruleset_sha256,
                    "matches_baseline": bool(
                        ruleset_sha256 and baseline.get("ruleset", {}).get("sha256")
                        and ruleset_sha256 == baseline["ruleset"].get("sha256"))},
        "counts": counts,
        "new": new_items,
        "persistent": persistent_items,
        "moved": moved_items,
        "changed": changed_items,
        "suppressed": suppressed_items,
        "resolved": resolved_items,
        "annotations": _annotation_counts(new_items + persistent_items + moved_items),
        "uncertain": {"is_uncertain": bool(reasons), "reasons": reasons},
    }


def _is_annotation(finding: dict) -> bool:
    """Low-confidence / draft findings annotate; they do not gate by default."""
    return (finding.get("confidence_tier") == "inconclusive"
            or bool(finding.get("informational"))
            or bool(finding.get("inconclusive")))


def _annotation_counts(items: list) -> dict:
    excluded = [i for i in items if i.get("gate_excluded")]
    return {"count": len(excluded),
            "by_rule": sorted({str(i.get("rule_id") or i.get("vulnerability"))
                               for i in excluded})}


# ---------------------------------------------------------------------------
# Gate policy
# ---------------------------------------------------------------------------

def parse_policy(policy: str | None) -> dict:
    """Parse `<scope>-<level>` (or `none`) into {scope, severity, raw}.

    scope : new | changed | any   (plus the special policy `none`)
    level : info|warning|error with aliases low/medium/high/critical/note.
    """
    raw = (policy or "").strip().lower()
    if not raw:
        raise BaselineError("empty --fail-on policy")
    if raw == "none":
        return {"raw": policy, "scope": "none", "severity": None}
    if "-" in raw:
        scope, _, level = raw.partition("-")
    else:
        scope, level = raw, "error"
    if scope == "none" and not level:
        return {"raw": policy, "scope": "none", "severity": None}
    if scope not in SCOPES:
        raise BaselineError(
            f"unknown --fail-on scope {scope!r} (expected one of "
            f"{', '.join(SCOPES)}, 'none', or e.g. new-high)")
    if level not in LEVEL_ALIASES:
        raise BaselineError(
            f"unknown --fail-on level {level!r} (expected one of "
            f"info, warning, error or aliases low/medium/high/critical)")
    return {"raw": policy, "scope": scope, "severity": LEVEL_ALIASES[level]}


def evaluate_gate(delta: dict, policy: dict, *, gate_inconclusive: bool = False) -> dict:
    """Deterministically evaluate the gate. Returns:

        {policy, triggered, exit_code, failures, counts, annotations}

    failures list every finding that caused a trigger (id + location only).
    """
    severity = policy.get("severity")
    scope = policy.get("scope")
    result = {
        "policy": policy.get("raw"),
        "scope": scope,
        "min_severity": severity,
        "gate_inconclusive": gate_inconclusive,
        "triggered": False,
        "exit_code": 0,
        "failures": [],
        "counts": {"new": 0, "changed": 0, "any": 0},
        "annotation_only": [],
    }
    if scope == "none":
        return result
    if severity is None:
        raise BaselineError("policy has no severity level")

    threshold = _SEVERITY_RANK[severity]

    def _sev_of(item: dict) -> str:
        return str(item.get("severity") or item.get("current_severity") or "").upper()

    def _eligible(item: dict) -> bool:
        if item.get("gate_excluded") and not gate_inconclusive:
            return False
        return _SEVERITY_RANK.get(_sev_of(item), -1) >= threshold

    def _annotation(item: dict) -> bool:
        return item.get("gate_excluded") and not gate_inconclusive

    if scope in ("new", "any"):
        pool = delta.get("new", []) if scope == "new" else (
            delta.get("new", []) + delta.get("persistent", [])
            + delta.get("moved", []) + delta.get("changed", []))
        for item in pool:
            if _eligible(item):
                result["failures"].append({
                    "status": "new" if scope == "new" else
                              (item.get("baseline_status") or "present"),
                    "rule_id": item.get("rule_id") or item.get("vulnerability"),
                    "file": item.get("file"),
                    "line": item.get("line") or item.get("line_start"),
                    "severity": _sev_of(item),
                    "fingerprint": item.get("fingerprint"),
                    "uncertain_identity": bool(item.get("uncertain_identity")),
                })
                result["counts"]["new" if scope == "new" else "any"] += 1
            elif _annotation(item):
                result["annotation_only"].append(
                    item.get("fingerprint") or item.get("rule_id"))
    elif scope == "changed":
        for item in delta.get("changed", []):
            current_sev = str(item.get("current_severity") or "").upper()
            if _SEVERITY_RANK.get(current_sev, -1) >= threshold:
                result["failures"].append({
                    "status": "changed",
                    "rule_id": item.get("rule_id"),
                    "file": item.get("file"),
                    "line": item.get("line"),
                    "severity": item.get("current_severity"),
                    "fingerprint": item.get("fingerprint"),
                    "differences": item.get("differences"),
                })
                result["counts"]["changed"] += 1

    result["triggered"] = bool(result["failures"])
    result["exit_code"] = 1 if result["triggered"] else 0
    return result


def print_delta(delta: dict, gate: dict | None = None, *, out=print) -> None:
    """Human-readable delta + gate report for the CLI."""
    counts = delta.get("counts", {})
    mode = delta.get("mode")
    out("=" * 72)
    out("BASELINE COMPARISON")
    out("=" * 72)
    if mode == "no-baseline":
        out("Baseline: none (explicit --no-baseline) — every actionable "
            f"finding counts as new.")
    else:
        b = delta.get("baseline", {})
        out(f"Baseline: {b.get('path')} (schema v{b.get('schema_version')}, "
            f"{b.get('entry_count')} entries, generated {b.get('generated_at')})")
        rs = delta.get("ruleset", {})
        out(f"Ruleset  : {'matches baseline' if rs.get('matches_baseline') else 'DIFFERS from baseline'}")
    out(f"  new={counts.get('new', 0)}  persistent={counts.get('persistent', 0)}  "
        f"moved={counts.get('moved', 0)}  changed={counts.get('changed', 0)}  "
        f"suppressed={counts.get('suppressed', 0)}  resolved={counts.get('resolved', 0)}")
    for item in delta.get("new", [])[:40]:
        flag = " [identity uncertain]" if item.get("uncertain_identity") else ""
        ann = " (annotation only)" if item.get("gate_excluded") else ""
        out(f"  NEW  {item.get('file')}:{item.get('line') or item.get('line_start')} "
            f"{item.get('rule_id') or item.get('vulnerability')} "
            f"[{item.get('severity')}]{flag}{ann}")
    for item in delta.get("changed", [])[:40]:
        diffs = ", ".join(f"{k}: {v['baseline']}->{v['current']}"
                          for k, v in (item.get("differences") or {}).items())
        out(f"  CHANGED {item.get('file')} {item.get('rule_id')} ({diffs})")
    for item in delta.get("suppressed", [])[:40]:
        sup = item.get("suppression", {})
        out(f"  SUPPRESSED {item.get('file')} {item.get('rule_id')} "
            f"until {sup.get('expires')} — {sup.get('rationale', '')[:60]}")
    for entry in delta.get("resolved", [])[:40]:
        out(f"  RESOLVED {entry.get('path')} {entry.get('rule_id')} "
            f"[{entry.get('severity')}]")
    expired_count = delta.get("baseline", {}).get("expired_suppression_count", 0)
    if expired_count:
        out(f"  ⚠ {expired_count} expired suppression(s) are INACTIVE — their "
            f"findings count normally again (refresh or remove the waiver)")
        for s in delta.get("baseline", {}).get("expired_suppressions", [])[:20]:
            out(f"    · {s.get('scope')} expired {s.get('expires')}")
    for reason in delta.get("uncertain", {}).get("reasons", []):
        out(f"  ⚠ UNCERTAIN: {reason}")
    if gate is not None:
        out("-" * 72)
        if gate["scope"] == "none":
            out(f"Gate: --fail-on none (never fails) — {len(delta.get('new', []))} new finding(s)")
        elif gate["triggered"]:
            out(f"Gate: FAIL — policy {gate['policy']}: {len(gate['failures'])} "
                f"finding(s) at or above {gate['min_severity']}")
            for f in gate["failures"][:40]:
                extra = " [identity uncertain]" if f.get("uncertain_identity") else ""
                out(f"  ✗ {f.get('file')}:{f.get('line')} {f.get('rule_id')} "
                    f"[{f.get('severity')}] ({f.get('status')}){extra}")
        else:
            out(f"Gate: PASS — policy {gate['policy']}: no finding at or above "
                f"{gate['min_severity']} in scope '{gate['scope']}'")
        if gate.get("annotation_only"):
            out(f"  (annotation-only, not gating: {len(gate['annotation_only'])} "
                f"low-confidence finding(s))")
