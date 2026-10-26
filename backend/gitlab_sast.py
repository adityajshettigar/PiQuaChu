# backend/gitlab_sast.py
"""
gitlab_sast.py — native GitLab SAST report export (gl-sast-report.json)
=======================================================================
PiQuaChu findings are *cryptographic discovery evidence*, not generic memory
safety bugs. This exporter therefore publishes only the subset that is
defensible as a GitLab SAST vulnerability and leaves the rest in the PiQuaChu
artifact:

* included: actionable code findings (ERROR/WARNING severity) with a
  repository-relative file + line, excluding PASS evidence (`pqc_compliant`),
  informational notes, and inconclusive findings. Inconclusive/informational
  results are annotation-only in the gate policy too, so promoting them to
  vulnerabilities here would contradict the product's own semantics.
* excluded, and counted in `scan.messages` (never silently dropped): PASS
  evidence, informational findings, inconclusive findings, unlocated findings
  and unknown severities.

Guarantees
----------
* Schema-valid against the pinned official GitLab schema
  `schemas/gitlab-sast-report-format-v15.2.5.json` (tag v15.2.5, commit
  94999aa479bd7607fb28e28701754021fe3a6723). Refresh policy: re-download the
  tagged file from
  https://gitlab.com/gitlab-org/security-products/security-report-schemas
  and re-run test_phase3.py.
* Stable vulnerability `id`: UUIDv5 derived from the Phase 2 finding
  fingerprint, so re-runs and line shifts do not create new vulnerabilities.
* No source lines, no `raw_source_code_extract`, no secrets, no absolute host
  paths — only normalized evidence metadata.
* Single severity mapping shared with SARIF semantics (ERROR→High,
  WARNING→Medium); it is never recomputed per exporter.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import uuid

import evidence

REPORT_VERSION = "15.2.5"
SCHEMA_FILE = "gitlab-sast-report-format-v15.2.5.json"
INFORMATION_URI = "https://github.com/adityajshettigar/cipher-sentinel"
SCANNER_ID = "piquachu-sast"
ANALYZER_ID = "piquachu-cli"

# Severity mapping is intentionally *only* this table: SARIF maps the same
# tiers to error/warning. Unknown severities are excluded and counted instead
# of being guessed into "Medium".
_SEVERITY_MAP = {"ERROR": "High", "WARNING": "Medium"}

_ID_NAMESPACE = uuid.UUID("6f0d1f9c-3d2b-5f8e-9a41-7c6b5d4e3f21")


def _schema_path() -> str:
    return os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "schemas", SCHEMA_FILE)


def _iso_now() -> str:
    """GitLab schema format: yyyy-mm-ddThh:mm:ss (no timezone suffix)."""
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def _tool_block(tool_id: str, name: str, version: str) -> dict:
    return {
        "id": tool_id,
        "name": name,
        "version": version,
        "vendor": {"name": "PiQuaChu"},
        "url": INFORMATION_URI,
    }


def _is_secret_bearing(finding: dict) -> bool:
    """Key/secret findings must never carry a value into the report."""
    category = str(finding.get("category") or "").lower()
    evidence_type = str(finding.get("evidence_type") or "").lower()
    return category in ("secrets", "key_material") or evidence_type == "key_material"


def _description(finding: dict, rule_id: str, meta: dict) -> str:
    """Markdown description built only from static metadata (no source text)."""
    lines = []
    rationale = finding.get("message") or meta.get("message")
    vuln = finding.get("vulnerability") or rule_id
    lines.append(f"**{vuln}**")
    if rationale:
        lines.append(str(rationale).strip())
    lines.append("")
    lines.append(f"- Rule: `{rule_id}`")
    category = finding.get("category") or meta.get("category")
    if category:
        lines.append(f"- Category: {category}")
    standard = finding.get("nist_standard") or meta.get("nist_standard")
    if standard:
        lines.append(f"- Target standard: {standard}")
    tier = finding.get("confidence_tier")
    if tier:
        lines.append(f"- Evidence confidence: {tier}")
    etype = finding.get("evidence_type")
    if etype:
        lines.append(f"- Evidence type: {etype}")
    engine = finding.get("engine")
    if engine:
        lines.append(f"- Detected by: {engine} "
                     f"{finding.get('engine_version') or ''}".strip())
    lines.append("")
    lines.append("PiQuaChu reports static-discovery evidence for post-quantum "
                 "migration. A finding is not a compliance certification and a "
                 "clean report is not proof of cryptographic compliance.")
    return "\n".join(lines)


def _vulnerability(finding: dict, registry: dict) -> dict | None:
    rule_id = str(finding.get("rule_id") or finding.get("vulnerability") or "")
    if not rule_id:
        return None
    meta = registry.get(rule_id) or {}
    severity = _SEVERITY_MAP.get(str(finding.get("severity") or "").upper())
    if severity is None:
        return None
    rel = evidence.relativize(finding.get("file"))
    line = finding.get("line_start") or finding.get("line")
    if not rel or not isinstance(line, int) or line < 1:
        return None

    fp = finding.get("fingerprint") or \
        evidence.fingerprint(rule_id, rel, f"call:{rule_id}")
    vuln_id = str(uuid.uuid5(_ID_NAMESPACE, f"piquachu:{fp}"))

    name = str(finding.get("vulnerability") or rule_id)
    item = {
        "id": vuln_id,
        "name": name[:200],
        "description": _description(finding, rule_id, meta),
        "severity": severity,
        "identifiers": [{
            "type": "piquachu_rule",
            "name": rule_id,
            "value": rule_id,
        }],
        "location": {"file": rel, "start_line": int(line)},
    }
    end = finding.get("line_end")
    if isinstance(end, int) and end >= line:
        item["location"]["end_line"] = int(end)

    solution = []
    target = finding.get("target_algorithm") or meta.get("target_algorithm")
    if target:
        solution.append(f"Migrate to {target}.")
    recommendation = finding.get("recommendation") or meta.get("recommendation")
    if recommendation:
        solution.append(str(recommendation))
    if solution:
        item["solution"] = " ".join(solution)[:4000]

    # A secret-bearing finding keeps its location but never echoes a value.
    if _is_secret_bearing(finding):
        item["description"] += ("\n\nKey/secret material is intentionally not "
                                "rendered in this report.")
    return item


def build_report(report: dict, *, tool_version: str | None = None,
                 start_time: str | None = None, end_time: str | None = None,
                 status: str | None = None,
                 registry: dict | None = None) -> tuple[dict, dict]:
    """Build a GitLab SAST report from a PiQuaChu scan result.

    Returns ``(document, stats)`` where ``stats`` records every exclusion
    reason so nothing disappears unaccounted for.
    """
    if registry is None:
        try:
            import compliance
            registry = compliance.load_rule_metadata()
        except Exception:  # registry unavailable — unknown rules still export
            registry = {}

    version = tool_version or evidence.ENGINE_VERSION
    findings = list(report.get("findings") or [])

    stats = {
        "findings_total": len(findings),
        "included": 0,
        "excluded": {"pass_evidence": 0, "informational": 0,
                     "inconclusive": 0, "unlocated": 0,
                     "unknown_severity": 0},
    }
    vulnerabilities: list[dict] = []
    seen: set[str] = set()

    for finding in findings:
        if finding.get("pqc_compliant"):
            stats["excluded"]["pass_evidence"] += 1
            continue
        if finding.get("informational"):
            stats["excluded"]["informational"] += 1
            continue
        if str(finding.get("confidence_tier") or "") == "inconclusive":
            stats["excluded"]["inconclusive"] += 1
            continue
        item = _vulnerability(finding, registry)
        severity = str(finding.get("severity") or "").upper()
        if item is None:
            if severity not in _SEVERITY_MAP:
                stats["excluded"]["unknown_severity"] += 1
            else:
                stats["excluded"]["unlocated"] += 1
            continue
        if item["id"] in seen:
            continue  # same fingerprint + rule already reported
        seen.add(item["id"])
        vulnerabilities.append(item)

    vulnerabilities.sort(key=lambda v: (v["location"]["file"],
                                        v["location"]["start_line"],
                                        v["id"]))
    stats["included"] = len(vulnerabilities)

    messages = [{
        "level": "info",
        "value": ("PiQuaChu static PQC discovery: findings describe "
                  "post-quantum migration evidence, not a compliance "
                  "certification."),
    }]
    excluded_total = sum(stats["excluded"].values())
    if excluded_total:
        detail = ", ".join(f"{k}={v}" for k, v in sorted(stats["excluded"].items())
                           if v)
        messages.append({
            "level": "info",
            "value": (f"{excluded_total} finding(s) not exported as GitLab "
                      f"vulnerabilities ({detail}). They remain in the "
                      f"PiQuaChu JSON/SARIF artifact."),
        })

    doc = {
        "version": REPORT_VERSION,
        "scan": {
            "type": "sast",
            "status": status or "success",
            "start_time": start_time or _iso_now(),
            "end_time": end_time or _iso_now(),
            "scanner": _tool_block(SCANNER_ID, "PiQuaChu",
                                   str(report.get("engine_version") or version)),
            "analyzer": _tool_block(ANALYZER_ID, "PiQuaChu CLI", str(version)),
            "messages": messages,
        },
        "vulnerabilities": vulnerabilities,
    }
    return doc, stats


def validate_report(doc: dict) -> list[str]:
    """Validate against the pinned official GitLab SAST schema.

    Returns a list of error strings (empty = valid).
    """
    try:
        import jsonschema
    except ImportError:
        return ["jsonschema is not installed — official validation unavailable"]
    path = _schema_path()
    if not os.path.isfile(path):
        return [f"official GitLab SAST schema missing: {path}"]
    try:
        with open(path, "r", encoding="utf-8") as fh:
            schema = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        return [f"official GitLab SAST schema unreadable: {exc}"]
    validator = jsonschema.Draft7Validator(schema)
    errors = sorted(validator.iter_errors(doc), key=lambda e: list(e.path))
    return [f"{'/'.join(str(p) for p in e.path) or '<root>'}: {e.message}"
            for e in errors]


def write_report(doc: dict, path: str) -> None:
    """Atomically write the report (a truncated CI artifact is worse than none)."""
    text = json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
    tmp = f"{path}.tmp.{os.getpid()}"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass
