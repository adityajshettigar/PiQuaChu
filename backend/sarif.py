# backend/sarif.py
"""
sarif.py — SARIF 2.1.0 output for CLI, CI and (optionally) code scanning
========================================================================
Produces a schema-valid SARIF 2.1.0 log from the normalized Phase 2 scan
result. Guarantees:

* **Stable partial fingerprints** — `partialFingerprints["pquFingerprint/v1"]`
  carries the Phase 2 finding fingerprint, so identical issues survive line
  shifts and tool re-runs (SARIF consumers de-duplicate on it).
* **Safe URIs** — repository-relative paths only, percent-encoded per RFC 3986
  (spaces, `#`, `%`, non-ASCII/Unicode and Windows-style separators all
  round-trip), `uriBaseId: SRCROOT`, never an absolute host path.
* **No content leaks** — no source snippets by default; snippets exist only
  when the caller explicitly passes `snippet_provider` (local opt-in, never
  used by CI workflows), no secrets, no env values, no repo metadata beyond
  the public tool identity.
* **Consistent severity mapping** — ERROR→error, WARNING→warning, INFO→note;
  unknown severities fall back to warning and say so in properties.
* **Parse failures are notifications, not results** — engine diagnostics land
  in `invocations[0].toolExecutionNotifications`, never as fake findings.

Validated against the official OASIS schema
`schemas/sarif-schema-2.1.0.json` (draft-04) in test_phase3.py.
"""

from __future__ import annotations

import datetime as _dt
import os
import urllib.parse

import evidence

SCHEMA_URL = ("https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/"
              "schemas/sarif-schema-2.1.0.json")
SCHEMA_VERSION = "2.1.0"
INFORMATION_URI = "https://github.com/adityajshettigar/cipher-sentinel"
TOOL_NAME = "PiQuaChu"

_LEVEL_MAP = {"ERROR": "error", "WARNING": "warning", "INFO": "note"}
_FP_PROPERTY = "pquFingerprint/v1"


def _rel_uri(path) -> str | None:
    """Percent-encoded, repository-relative, host-path-free artifact URI."""
    if not path:
        return None
    rel = evidence.relativize(str(path)) or None
    if not rel:
        return None
    # quote() percent-encodes spaces, '#', '%', non-ASCII and backslashes.
    return urllib.parse.quote(rel.replace("\\", "/"), safe="/~")


def _region(finding: dict) -> dict | None:
    start = finding.get("line_start") or finding.get("line")
    if not isinstance(start, int) or start < 1:
        return None
    region: dict = {"startLine": start}
    col = finding.get("column_start")
    if isinstance(col, int) and col > 0:
        region["startColumn"] = col
    end = finding.get("line_end")
    if isinstance(end, int) and end >= start:
        region["endLine"] = end
    return region


def _message(finding: dict, registry: dict) -> str:
    """Actionable message: what is wrong, where to move, what evidence backs it."""
    rule_id = str(finding.get("rule_id") or finding.get("vulnerability") or "unknown-rule")
    meta = registry.get(rule_id) or {}
    target = finding.get("target_algorithm") or meta.get("target_algorithm")
    vuln = finding.get("vulnerability") or rule_id
    parts = [f"{vuln}"]
    rationale = finding.get("message") or meta.get("message")
    if rationale:
        parts.append(str(rationale).strip())
    if target:
        parts.append(f"Recommended migration: {target}.")
    confidence = finding.get("confidence_tier")
    if confidence:
        parts.append(f"Evidence confidence: {confidence}"
                     + (" (inconclusive — annotation only by default)."
                        if confidence == "inconclusive" else "."))
    return " ".join(parts)


def _rule_descriptor(rule_id: str, meta: dict | None, *, unknown: bool) -> dict:
    meta = meta or {}
    severity = str(meta.get("severity") or "WARNING").upper()
    desc = {
        "id": rule_id,
        "name": rule_id.replace("_", "-"),
        "shortDescription": {
            "text": str(meta.get("message") or
                        f"PiQuaChu rule {rule_id} (severity {severity})")[:500]},
        "fullDescription": {
            "text": str(meta.get("message") or
                        f"Detected by PiQuaChu rule {rule_id}.")[:2000]},
        "defaultConfiguration": {
            "level": _LEVEL_MAP.get(severity, "warning")},
        "helpUri": f"{INFORMATION_URI}/blob/main/backend/rules.yaml",
        "properties": {
            "tags": ["security", "post-quantum-crypto",
                     str(meta.get("category") or "crypto"),
                     str(meta.get("nist_standard") or "").strip()],
            "nistStandard": meta.get("nist_standard"),
            "category": meta.get("category"),
            "pqcCompliant": meta.get("pqc_compliant"),
            "precision": {0.9: "high", 0.6: "medium", 0.3: "low"}.get(
                {"high": 0.9, "medium": 0.6, "low": 0.3,
                 "inconclusive": 0.1}.get(
                    str(meta.get("confidence") or "medium"), 0.6), "medium"),
        },
    }
    # Drop nulls so the document stays lean and schema-clean.
    desc["properties"] = {k: v for k, v in desc["properties"].items()
                          if v is not None and v != ""}
    desc["properties"]["tags"] = [t for t in desc["properties"]["tags"] if t]
    if unknown:
        desc["properties"]["unknownRule"] = True
        desc["shortDescription"]["text"] = (
            f"{rule_id}: rule not present in the loaded ruleset registry "
            f"(finding still reported — unknown rules are never dropped)")
    return desc


def build_sarif(report: dict, *, tool_version: str | None = None,
                baseline_delta: dict | None = None, gate: dict | None = None,
                snippet_provider=None, registry: dict | None = None) -> dict:
    """Build a SARIF 2.1.0 log from a scan report (or a subset dict).

    snippet_provider: optional callable(path, start_line, end_line) -> str.
    Only pass one for *local, opt-in* artifacts; CI must never enable it.
    """
    if registry is None:
        try:
            import compliance
            registry = compliance.load_rule_metadata()
        except Exception:  # registry unavailable — unknown-rule path still works
            registry = {}

    findings = list(report.get("findings") or [])
    findings.sort(key=lambda f: (str(f.get("file") or ""),
                                 int(f.get("line_start") or f.get("line") or 0),
                                 str(f.get("fingerprint") or "")))

    # Deterministic de-duplication: same fingerprint + rule = one result.
    seen: set[tuple] = set()
    results: list[dict] = []
    rule_order: list[str] = []

    delta_by_fp: dict[str, dict] = {}
    if baseline_delta:
        for status in ("new", "persistent", "moved"):
            for item in baseline_delta.get(status, []) or []:
                if item.get("fingerprint"):
                    delta_by_fp[item["fingerprint"]] = item
        for item in baseline_delta.get("changed", []) or []:
            if item.get("fingerprint"):
                delta_by_fp[item["fingerprint"]] = item
        for item in baseline_delta.get("suppressed", []) or []:
            if item.get("fingerprint"):
                delta_by_fp[item["fingerprint"]] = item

    for finding in findings:
        if finding.get("pqc_compliant"):
            continue  # PASS evidence is not a SARIF result
        rule_id = str(finding.get("rule_id") or finding.get("vulnerability")
                      or "unknown-rule")
        fp = finding.get("fingerprint")
        key = (rule_id, fp)
        if key in seen:
            continue
        seen.add(key)
        if rule_id not in rule_order:
            rule_order.append(rule_id)

        meta = registry.get(rule_id)
        severity = str(finding.get("severity") or "").upper()
        level = _LEVEL_MAP.get(severity)
        properties = {
            "severity": severity or None,
            "mappedLevel": level or "warning",
            "unknownSeverity": level is None,
            "confidenceTier": finding.get("confidence_tier"),
            "confidenceScore": finding.get("confidence_score"),
            "category": finding.get("category"),
            "nistStandard": finding.get("nist_standard"),
            "engine": finding.get("engine"),
            "evidenceType": finding.get("evidence_type"),
            "fingerprint": fp,
            "siteSignature": finding.get("site_signature"),
            "pqcCompliant": bool(finding.get("pqc_compliant")),
        }
        if finding.get("cross_engine_confirmed"):
            properties["crossEngineConfirmed"] = True
        delta_item = delta_by_fp.get(fp) if fp else None
        if delta_item is not None:
            status = (delta_item.get("baseline_status")
                      or ("suppressed" if delta_item.get("suppression")
                          else "changed" if delta_item.get("differences") else None))
            if fp and baseline_delta:
                for status_key in ("new", "persistent", "moved"):
                    if any(i.get("fingerprint") == fp
                           for i in baseline_delta.get(status_key, []) or []):
                        status = status_key
            properties["baselineStatus"] = status
            if delta_item.get("uncertain_identity"):
                properties["uncertainIdentity"] = True
            if delta_item.get("suppression"):
                properties["suppressionRationale"] = \
                    delta_item["suppression"].get("rationale")
                properties["suppressionExpires"] = \
                    delta_item["suppression"].get("expires")
            if delta_item.get("moved_from"):
                properties["movedFrom"] = evidence.relativize(
                    delta_item["moved_from"])
            if delta_item.get("differences"):
                properties["baselineDifferences"] = {
                    k: {"baseline": v.get("baseline"), "current": v.get("current")}
                    for k, v in delta_item["differences"].items()}
        properties = {k: v for k, v in properties.items() if v is not None}

        result: dict = {
            "ruleId": rule_id,
            "ruleIndex": rule_order.index(rule_id),
            "level": level or "warning",
            "kind": "fail",
            "message": {"text": _message(finding, registry)},
            "partialFingerprints": {_FP_PROPERTY: fp} if fp else {},
            "properties": properties,
        }
        uri = _rel_uri(finding.get("file"))
        region = _region(finding)
        if uri:
            location: dict = {"artifactLocation": {"uri": uri,
                                                   "uriBaseId": "SRCROOT"}}
            if region:
                location["region"] = region
            result["locations"] = [ {"physicalLocation": location} ]
            if region and snippet_provider is not None:
                try:
                    text = snippet_provider(finding.get("file"),
                                            region.get("startLine", 1),
                                            region.get("endLine",
                                                       region.get("startLine", 1)))
                except Exception:
                    text = None
                if text:
                    location["region"]["snippet"] = {"text": str(text)[:2000]}
        else:
            result["properties"]["unlocated"] = True

        if delta_item is not None and delta_item.get("suppression"):
            result["suppressions"] = [{
                "kind": "external",
                "status": "accepted",
                "justification": (
                    f"Baselined suppression until "
                    f"{delta_item['suppression'].get('expires')}: "
                    f"{delta_item['suppression'].get('rationale')}"),
            }]
        if finding.get("confidence_tier") == "inconclusive" or finding.get("informational"):
            result["properties"]["annotationOnly"] = True
        results.append(result)

    rules = []
    for rule_id in rule_order:
        meta = registry.get(rule_id)
        rules.append(_rule_descriptor(rule_id, meta, unknown=meta is None))

    # Engine diagnostics (dict from evidence.summarize_diagnostics, or a plain
    # list) become toolExecutionNotifications — parse failures are never
    # invented into results.
    notifications = []
    diags = report.get("diagnostics") or report.get("parser_failures") or []
    diag_texts: list[tuple[str, dict | None]] = []
    if isinstance(diags, dict):
        failures = diags.get("parser_failures") or {}
        if isinstance(failures, dict):
            for lang, count in sorted(failures.items()):
                diag_texts.append((f"{lang} parser failed on {count} file(s) — "
                                   f"those files were refused, not guessed", None))
        for fname in sorted(diags.get("parser_failure_files") or [])[:20]:
            diag_texts.append((f"parser failure: {fname}", {"file": fname}))
        for key in ("unresolved_values",):
            vals = diags.get(key) or {}
            if isinstance(vals, dict) and sum(vals.values()) > 0:
                diag_texts.append((f"unresolved value(s): " + ", ".join(
                    f"{k}={v}" for k, v in sorted(vals.items())), None))
    elif isinstance(diags, list):
        for diag in diags:
            if isinstance(diag, str):
                diag_texts.append((diag, None))
            elif isinstance(diag, dict):
                diag_texts.append((diag.get("message") or diag.get("detail")
                                   or str(diag),
                                   {"file": diag.get("file")}
                                   if diag.get("file") else None))
    elif isinstance(diags, str):
        diag_texts.append((diags, None))

    for text, loc in diag_texts:
        note = {"descriptor": {"id": "parser-failure"
                               if "parser failure" in text or "parser failed" in text
                               else "engine-diagnostic"},
                "message": {"text": str(text)[:1000]},
                "level": "warning"}
        if loc and loc.get("file"):
            note["locations"] = [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": _rel_uri(loc.get("file")) or "unknown",
                        "uriBaseId": "SRCROOT"}}}]
        notifications.append(note)

    run_properties: dict = {
        "scanner": report.get("engine"),
        "modelVersion": evidence.MODEL_VERSION,
        "engineVersion": report.get("engine_version") or evidence.ENGINE_VERSION,
        "generatedAt": _dt.datetime.now(_dt.timezone.utc)
                        .replace(microsecond=0).isoformat(),
        "ruleset": report.get("ruleset"),
        "note": ("Discovery evidence, not a compliance certificate. "
                 "Results are static-analysis findings."),
    }
    if baseline_delta:
        run_properties["baseline"] = {
            "present": bool(baseline_delta.get("baseline", {}).get("present")),
            "mode": baseline_delta.get("mode"),
            "schemaVersion": baseline_delta.get("baseline", {}).get("schema_version"),
            "generatedAt": baseline_delta.get("baseline", {}).get("generated_at"),
            "counts": baseline_delta.get("counts"),
            "uncertain": baseline_delta.get("uncertain"),
        }
    if gate:
        run_properties["gate"] = {
            "policy": gate.get("policy"),
            "triggered": gate.get("triggered"),
            "failureCount": len(gate.get("failures") or []),
        }
    run_properties = {k: v for k, v in run_properties.items() if v is not None}

    run = {
        "tool": {"driver": {
            "name": TOOL_NAME,
            "version": tool_version or evidence.ENGINE_VERSION,
            "semanticVersion": tool_version or evidence.ENGINE_VERSION,
            "informationUri": INFORMATION_URI,
            "rules": rules,
        }},
        "invocations": [{
            "executionSuccessful": True,
            "toolExecutionNotifications": notifications,
        }],
        "columnKind": "utf16CodeUnits",
        # Host-independent base: a *relative* uri (".") so no absolute host
        # path ever appears, while uriBaseId: SRCROOT keeps consumers happy.
        "originalUriBaseIds": {"SRCROOT": {"uri": "."}},
        "results": results,
        "properties": run_properties,
    }
    return {
        "$schema": SCHEMA_URL,
        "version": SCHEMA_VERSION,
        "runs": [run],
    }


def validate_sarif(doc: dict) -> list[str]:
    """Validate against the official OASIS SARIF 2.1.0 schema.

    Returns a list of error strings (empty = valid). Uses the vendored schema
    file `schemas/sarif-schema-2.1.0.json` (draft-04).
    """
    try:
        import jsonschema
    except ImportError:
        return ["jsonschema is not installed — official validation unavailable"]
    schema_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "schemas", "sarif-schema-2.1.0.json")
    if not os.path.isfile(schema_path):
        return [f"official SARIF schema missing: {schema_path}"]
    import json
    try:
        with open(schema_path, "r", encoding="utf-8") as fh:
            schema = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        return [f"official SARIF schema unreadable: {exc}"]
    validator = jsonschema.Draft4Validator(schema)
    errors = sorted(validator.iter_errors(doc), key=lambda e: list(e.path))
    return [f"{'/'.join(str(p) for p in e.path) or '<root>'}: {e.message}"
            for e in errors]


def write_sarif(doc: dict, path: str) -> None:
    """Atomically write the SARIF document."""
    import json
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
