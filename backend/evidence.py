# backend/evidence.py
"""
evidence.py — normalized evidence model shared by every PiQuaChu engine
=======================================================================
Every engine (semgrep, Python AST, Python data-flow, Java AST/data-flow,
transport/config, dependency, key-material) annotates its raw finding with the
same evidence fields *before* enrichment, so downstream consumers (compliance,
CBOM, CLI, API, CI baselines) see one shape.

Design rules
------------
* No absolute host paths, no source snippets and no secrets in identity fields.
* Identity is a **stable fingerprint** — rule id + normalized file identity +
  evidence signature (+ an optional scope guard) — so line shifts after an edit
  do not create a new finding, while two different call sites in the same file
  stay distinct.
* Line/column are display evidence only.
* Findings are deduplicated only when the evidence identity justifies it; when
  two engines emit different rules for the same call site we keep both and
  report the disagreement instead of silently merging contradictory evidence.
"""

from __future__ import annotations

import hashlib
import os
import re

MODEL_VERSION = "evidence-v2"
ENGINE_VERSION = "2.3.0"

# Documented confidence tiers. A tier is a *claim about evidence strength*, not
# about the security impact of the finding.
CONFIDENCE_TIERS = {
    "high": 0.9,     # literal/constant value observed at the call site
    "medium": 0.6,   # API pattern matched (semgrep/AST) without value proof
    "low": 0.3,      # bounded data-flow inference or unresolved value
    "inconclusive": 0.1,  # value came from config/env/dynamic source
}

EVIDENCE_TYPES = {
    "literal",               # algorithm string literal at the call site
    "constant_propagated",   # resolved through local assignments/aliases
    "data_flow",             # bounded source->sink inference
    "ast_api_pattern",       # AST/API pattern match (semgrep / AST engine)
    "dependency_advisory",   # manifest/lockfile advisory match
    "key_material",          # key/secret file presence (no key bytes)
    "transport_config",      # TLS/SSH configuration evidence
    "inconclusive",          # observed sink, value not statically resolvable
}

_TMP_PREFIX_RE = re.compile(r"^(?:[A-Za-z]:)?/.*?/piquachu-[^/]+/(.+)$")
_DRIVE_RE = re.compile(r"^[A-Za-z]:/")


def relativize(path: str | None, root: str | None = None) -> str | None:
    """Normalize a path to a relative, host-path-free identity.

    When the scan root is known the path is made relative to it, which keeps
    ``pkg/a.py`` and ``pkg2/a.py`` distinct (import identity must not collapse
    across directories). Without a root, a ``/tmp/piquachu-…/`` prefix is
    stripped; any other absolute path is reduced to its basename so the host
    layout is never leaked.
    """
    if not path:
        return None
    p = str(path).replace("\\", "/").strip()
    if not p:
        return None
    if root:
        root_norm = str(root).replace("\\", "/").rstrip("/")
        if root_norm and (p == root_norm or p.startswith(root_norm + "/")):
            p = p[len(root_norm):].lstrip("/")
            p = p or "."
    if p.startswith("/") or _DRIVE_RE.match(p):
        match = _TMP_PREFIX_RE.match(p)
        if match:
            p = match.group(1)
        else:
            p = os.path.basename(p)
    p = p.lstrip("./")
    segments = [seg for seg in p.split("/") if seg and seg not in (".", "..")]
    return "/".join(segments) or None


def file_identity(path: str | None, root: str | None = None) -> str:
    """Cross-file-collision-safe file component of a fingerprint.

    The normalized root-relative path is used as-is, so identical call sites in
    ``a/Utils.java`` and ``b/Utils.java`` can never share a fingerprint.
    """
    rel = relativize(path, root) or ""
    return rel or "<unknown>"


def fingerprint(rule_id: str, file_id: str, evidence_signature: str,
                scope: str | None = None) -> str:
    """Stable identity for baseline/CI use.

    Contains the normalized file identity, so the same call site in two files
    can never collide; ``scope`` (module/function) further separates identical
    call signatures inside one file.
    """
    basis = "\x1f".join([rule_id or "", file_id or "", evidence_signature or "",
                         scope or ""])
    digest = hashlib.sha1(basis.encode("utf-8")).hexdigest()[:24]
    return f"pqc1-{digest}"


def text_signature(rule_id: str, text: str | None) -> str:
    """Call-site signature for pattern engines that only have a source line.

    The line text is normalized and hashed — the snippet itself is never stored
    in the fingerprint, and the identity survives a line-number shift as long as
    the code at the call site is unchanged.
    """
    norm = " ".join((text or "").split())
    digest = hashlib.sha1(norm.encode("utf-8", errors="replace")).hexdigest()[:12]
    return f"pattern:{rule_id}|h={digest}"


def safe_observed_value(value, *, is_secret_source: bool = False) -> str | None:
    """Redact values that may be secrets. Environment/config-origin values are
    never rendered — only their source name is recorded."""
    if value is None:
        return None
    if is_secret_source:
        return None
    text = str(value)
    # Never echo long binary-ish or key-like strings.
    if len(text) > 120:
        return text[:117] + "..."
    if re.fullmatch(r"[A-Za-z0-9+/=_-]{40,}", text) and not re.fullmatch(
            r"[A-Za-z0-9._-]+", text):
        return "<redacted>"
    return text


def annotate(finding: dict, *, engine: str, evidence_type: str,
             confidence: str, language: str | None = None,
             evidence_signature: str | None = None,
             source_description: str | None = None,
             sink_description: str | None = None,
             observed_value: str | None = None,
             scope: str | None = None,
             rationale: str | None = None,
             limitations: str | None = None,
             inconclusive: bool = False,
             informational: bool = False,
             metadata: dict | None = None,
             root: str | None = None) -> dict:
    """Return a copy of ``finding`` with normalized evidence fields attached."""
    if confidence not in CONFIDENCE_TIERS:
        raise ValueError(f"unknown confidence tier: {confidence!r}")
    out = dict(finding)
    rel = relativize(out.get("file"), root) or out.get("file") or ""
    rule_id = out.get("vulnerability") or out.get("rule") or ""
    sig = evidence_signature or f"call:{sink_description or rule_id}"
    out["rule_id"] = rule_id
    # Static vs runtime evidence are separate sources; they share the finding
    # shape but are never conflated into one "complete" inventory.
    out["evidence_source"] = "static"
    out["engine"] = engine
    out["engine_version"] = ENGINE_VERSION
    out["model_version"] = MODEL_VERSION
    if language:
        out["language"] = language
    out["file"] = rel
    out["line_start"] = out.get("line")
    if out.get("end_line"):
        out["line_end"] = out["end_line"]
    else:
        out["line_end"] = out.get("line")
    if out.get("column") is not None:
        out["column_start"] = out["column"]
    out["evidence_type"] = evidence_type
    out["confidence_tier"] = confidence
    out["confidence_score"] = CONFIDENCE_TIERS[confidence]
    if source_description:
        out["source_description"] = source_description
    if sink_description:
        out["sink_description"] = sink_description
    if observed_value is not None:
        out["observed_value"] = observed_value
    if rationale:
        out["evidence_rationale"] = rationale
    if limitations:
        out["evidence_limitations"] = limitations
    if inconclusive:
        out["inconclusive"] = True
    if informational:
        out["informational"] = True
    out["evidence_scope"] = scope or ""
    # Hash-only call-site signature for baseline move/rename matching.
    # The raw signature (which may embed call text) is never persisted.
    out["site_signature"] = "h=" + hashlib.sha1(
        sig.encode("utf-8", errors="replace")).hexdigest()[:24]
    out["fingerprint"] = fingerprint(rule_id, file_identity(rel), sig, scope)
    if metadata:
        meta = metadata.get(rule_id)
        if meta:
            out.setdefault("category", meta.get("category"))
            out.setdefault("nist_standard", meta.get("nist_standard"))
            out.setdefault("target_algorithm", meta.get("target_algorithm"))
    return out


def _provenance(finding: dict) -> dict:
    return {
        "engine": finding.get("engine"),
        "rule_id": finding.get("rule_id") or finding.get("vulnerability"),
        "evidence_type": finding.get("evidence_type"),
        "confidence_tier": finding.get("confidence_tier"),
        "fingerprint": finding.get("fingerprint"),
    }


def _merge_into(current: dict, incoming: dict) -> dict:
    """Fold ``incoming`` into ``current``, keeping every engine as provenance."""
    prov = current.setdefault("provenance", [_provenance(current)])
    for item in [_provenance(incoming)]:
        if item not in prov:
            prov.append(item)
    engines = {p.get("engine") for p in prov if p.get("engine")}
    current["engine_count"] = len(engines)
    if len(engines) > 1:
        current["cross_engine_confirmed"] = True
    # Highest-confidence evidence describes the finding; weaker engines are
    # still listed in provenance rather than discarded.
    if incoming.get("confidence_score", 0) > current.get("confidence_score", 0):
        prov = current["provenance"]
        merged = dict(incoming)
        merged["provenance"] = prov
        merged["engine_count"] = current.get("engine_count")
        if current.get("cross_engine_confirmed"):
            merged["cross_engine_confirmed"] = True
        return merged
    return current


def reconcile(findings: list) -> tuple[list, list]:
    """Deduplicate by evidence identity while retaining provenance.

    Returns ``(deduped, disagreements)``.

    Two collapse passes, in order:
    1. Same ``fingerprint`` (same rule + file identity + call signature) — one
       finding, provenance lists every engine.
    2. Same rule on the same file + line — the pattern engines can only offer a
       source-line signature while the data-flow engines know the sink, so the
       identical rule fired on the same line is the same evidence. It is merged
       (not double-counted) and every engine is retained in provenance.

    Different *rules* on the same call site are never merged: both are kept and
    reported in ``disagreements`` so contradictory/overlapping evidence stays
    visible.
    """
    by_fingerprint: dict[str, dict] = {}
    order: list[str] = []

    for finding in findings:
        fp = finding.get("fingerprint")
        if fp is None:
            fp = fingerprint(str(finding.get("vulnerability") or ""),
                             file_identity(finding.get("file")),
                             "call:unknown")
            finding = dict(finding, fingerprint=fp)
        if fp not in by_fingerprint:
            by_fingerprint[fp] = finding
            order.append(fp)
        else:
            by_fingerprint[fp] = _merge_into(by_fingerprint[fp], finding)

    # Pass 2: same rule + file + line across engines.
    by_site_key: dict[tuple, str] = {}
    for fp in order:
        finding = by_fingerprint[fp]
        site = (finding.get("rule_id") or finding.get("vulnerability"),
                finding.get("file"), finding.get("line_start"))
        if site not in by_site_key:
            by_site_key[site] = fp
            continue
        keeper = by_site_key[site]
        merged = _merge_into(by_fingerprint[keeper], finding)
        by_fingerprint[keeper] = merged
        by_fingerprint[fp] = merged

    deduped: list[dict] = []
    seen: set[int] = set()
    for fp in order:
        finding = by_fingerprint[fp]
        if id(finding) in seen:
            continue
        seen.add(id(finding))
        deduped.append(finding)

    # Disagreement reporting over the collapsed set: distinct rules for the
    # same file + line are overlapping/contradictory evidence worth surfacing.
    by_site: dict[tuple, set] = {}
    for finding in deduped:
        site_key = (finding.get("file"), finding.get("line_start"))
        by_site.setdefault(site_key, set()).add(
            finding.get("rule_id") or finding.get("vulnerability"))

    disagreements = []
    for (file, line), rules in by_site.items():
        rules = {r for r in rules if r}
        if len(rules) > 1:
            disagreements.append({
                "file": file, "line": line,
                "rules": sorted(rules),
                "note": "multiple rules matched the same line; provenance "
                        "retained, evidence not merged",
            })

    return deduped, disagreements


def summarize_diagnostics(diagnostics: dict | None = None) -> dict:
    """Normalize per-engine diagnostics for scan results and reports."""
    diagnostics = diagnostics or {}
    return {
        "parser_failures": diagnostics.get("parser_failures", {}),
        "files_analyzed": diagnostics.get("files_analyzed", {}),
        "unresolved_values": diagnostics.get("unresolved_values", {}),
        "engines": diagnostics.get("engines", {}),
    }
