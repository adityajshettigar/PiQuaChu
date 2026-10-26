# backend/compliance.py
"""
compliance.py — cryptographic discovery / migration-readiness decision engine
==============================================================================
Classifies scan findings against the authoritative standards registry
(``standards.py``) and produces a discovery / migration-readiness matrix:

    FIPS 203  ML-KEM (CRYSTALS-Kyber)      Key Encapsulation — FINAL (2024-08-13)
    FIPS 204  ML-DSA (CRYSTALS-Dilithium)  Digital Signatures — FINAL (2024-08-13)
    FIPS 205  SLH-DSA (SPHINCS+)           Digital Signatures — FINAL (2024-08-13)
    FIPS 206  FN-DSA (FALCON)              Digital Signatures — IN DEVELOPMENT

A rule match is *evidence of a code pattern*.  It is not proof that a
cryptographic module is FIPS 140 validated, that the application is compliant,
or that an algorithm is implemented correctly.  Do not treat a scan as a
compliance certificate.

Verdict semantics
-----------------
    PASS  – a recognized PQC usage pattern was detected
    WARN  – legacy/ambiguous pattern that can still be migrated
    FAIL  – broken / quantum-insecure / unsupported algorithm (e.g. RSA-1024, SHA-1)

Per-standard status semantics (public, backward compatible)
-----------------------------------------------------------
    compliant               – PQC evidence for a FINAL standard, no legacy evidence
    partial                 – PQC + legacy evidence for the same category
    non_compliant           – only legacy evidence for that category
    detected_in_development – PQC evidence for a standard still in development
                              (currently FIPS 206 / FN-DSA); NOT a finalized pass
    transitional            – hybrid classical+PQC key establishment evidence
    not_detected            – no qualifying evidence observed (unknown, NOT a pass)

The additive ``evidence_status`` field carries the discovery-oriented enum:
    detected | legacy_detected | mixed | not_detected | unsupported_or_inconclusive
"""

import os

import standards

RULES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules.yaml")

# Derived from the authoritative registry — never duplicate lifecycle claims here.
STANDARDS = standards.as_compliance_table()

# Versioned metric definitions.  These are product heuristics, not NIST scores.
SCORE_FORMULA_VERSION = "readiness-v1"
RISK_FORMULA_VERSION = "risk-v1"
SEMANTICS_VERSION = "evidence-v1"

EVIDENCE_STATUSES = ("detected", "legacy_detected", "mixed", "not_detected",
                     "unsupported_or_inconclusive")

# Non-standard advisory buckets (hashing / symmetric / TLS / secrets / deps /
# KDF salts / randomness).
ADVISORY_BUCKETS = ("hashing", "symmetric", "tls", "secrets", "dependencies",
                    "kdf", "randomness")

# ---------------------------------------------------------------------------
# Weighted risk model
# ---------------------------------------------------------------------------

# Per-category weight applied to every legacy finding when computing the
# weighted risk score (higher = more dangerous if left unmigrated).
CATEGORY_RISK_WEIGHT = {
    "key-encapsulation": 1.0,   # RSA/ECDH — broken by Shor's algorithm
    "signatures": 1.0,          # ECDSA/RSA/DSA — broken by Shor's algorithm
    "symmetric": 0.8,           # DES/3DES/RC4/ECB/static-IV
    "secrets": 0.7,             # hardcoded secrets / secret-in-weak-algo
    "randomness": 0.7,          # predictable key/IV material
    "hashing": 0.6,             # MD5/SHA-1
    "kdf": 0.5,                 # static salts
    "tls": 0.5,                 # TLS 1.0/1.1, classical cipher suites
    "dependencies": 0.4,        # manifest/lockfile risks
    "hybrid": 0.1,              # transitional hybrid (already migrating)
    "unknown": 0.3,
}

_SEVERITY_FACTOR = {"ERROR": 1.0, "WARNING": 0.5, "INFO": 0.0}

# A single max-weight critical finding contributes 20 points, so five such
# findings saturate the risk score at 100 (a codebase with 5+ Shor-broken
# algorithm uses is unambiguously critical).
_RISK_NORMALIZER = 5.0


def compute_risk_score(findings: list) -> int:
    """Weighted risk score 0..100. Legacy findings contribute
    category_weight * severity_factor; PQC-compliant usage contributes nothing.
    Unlike pqc_score (a readiness score that *starts* at 100), this measures
    how much dangerous legacy cryptography is actually present — so SHA-1
    (hashing, 0.6) scores lower than RSA (key-encapsulation, 1.0)."""
    total = 0.0
    for f in findings:
        if f.get("pqc_compliant"):
            continue
        severity = str(f.get("severity", "WARNING")).upper()
        category = f.get("category", "unknown")
        weight = CATEGORY_RISK_WEIGHT.get(category, CATEGORY_RISK_WEIGHT["unknown"])
        total += weight * _SEVERITY_FACTOR.get(severity, 0.5)
    return max(0, min(100, round(total * 100 / _RISK_NORMALIZER)))


def risk_level(score: int) -> str:
    """Human-readable risk band for the weighted risk score."""
    if score >= 80:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 20:
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
# Rule metadata loading
# ---------------------------------------------------------------------------

_rule_metadata_cache = None


def load_rule_metadata(rules_path: str = RULES_PATH) -> dict:
    """Parse rules.yaml and return {rule_id: metadata}. Tries ruamel.yaml,
    then PyYAML, then a built-in zero-dependency parser — the engine always
    stays importable even with no third-party packages installed."""
    global _rule_metadata_cache
    if _rule_metadata_cache is not None:
        return _rule_metadata_cache

    metadata = {}
    for loader in (_load_ruamel, _load_pyyaml, _load_fallback):
        try:
            metadata = loader(rules_path)
            if metadata:
                break
        except Exception as exc:  # pragma: no cover - env-dependent
            print(f"[compliance] Warning: {loader.__name__} failed: {exc}")
    _rule_metadata_cache = metadata
    return metadata


def _load_ruamel(rules_path: str) -> dict:
    from ruamel.yaml import YAML

    yaml = YAML(typ="safe")
    with open(rules_path, "r", encoding="utf-8") as fh:
        doc = yaml.load(fh)
    return _extract_metadata(doc)


def _load_pyyaml(rules_path: str) -> dict:
    import yaml

    with open(rules_path, "r", encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    return _extract_metadata(doc)


def _extract_metadata(doc: dict) -> dict:
    metadata = {}
    for rule in doc.get("rules", []) or []:
        rule_id = rule.get("id")
        if not rule_id:
            continue
        meta = dict(rule.get("metadata", {}) or {})
        meta.setdefault("nist_standard", "Unspecified")
        meta.setdefault("category", "unknown")
        meta.setdefault("pqc_compliant", False)
        meta.setdefault("target_algorithm", "")
        meta.setdefault("severity", rule.get("severity", "WARNING"))
        metadata[rule_id] = meta
    return metadata


def _load_fallback(rules_path: str) -> dict:
    """Tiny deterministic parser for our specific rules.yaml layout.
    Extracts rule ids plus the metadata block and severity line."""
    import re

    metadata = {}
    current_id = None
    in_metadata = False
    meta = {}
    sev_re = re.compile(r"^\s*severity:\s*(\w+)\s*$")
    key_re = re.compile(r"^\s{6}(\w+):\s*(.*?)\s*$")
    with open(rules_path, "r", encoding="utf-8") as fh:
        for line in fh:
            id_match = re.match(r"^\s*-\s*id:\s*([\w-]+)\s*$", line)
            if id_match:
                if current_id and meta:
                    metadata[current_id] = _normalize_meta(meta)
                current_id = id_match.group(1)
                meta = {}
                in_metadata = False
                continue
            if current_id is None:
                continue
            if re.match(r"^\s*metadata:\s*$", line):
                in_metadata = True
                continue
            if in_metadata:
                m = key_re.match(line)
                if m:
                    meta[m.group(1)] = m.group(2)
                elif line.strip() and not line.strip().startswith("#"):
                    in_metadata = False  # left the metadata block
                continue
            m = sev_re.match(line)
            if m and "severity" not in meta:
                meta["severity"] = m.group(1)
    if current_id and meta:
        metadata[current_id] = _normalize_meta(meta)
    return metadata


def _normalize_meta(meta: dict) -> dict:
    return {
        "nist_standard": meta.get("nist_standard", "Unspecified"),
        "category": meta.get("category", "unknown"),
        "pqc_compliant": str(meta.get("pqc_compliant", "false")).lower() == "true",
        "target_algorithm": meta.get("target_algorithm", ""),
        "severity": meta.get("severity", "WARNING"),
    }


def enrich_finding(finding: dict, metadata: dict) -> dict:
    """Attach standards metadata + verdict + evidence provenance to a finding."""
    rule_id = finding.get("vulnerability") or finding.get("rule") or ""
    meta = metadata.get(rule_id, {})
    finding["nist_standard"] = meta.get("nist_standard", "Unspecified")
    finding["category"] = meta.get("category", "unknown")
    finding["pqc_compliant"] = bool(meta.get("pqc_compliant", False))
    finding["target_algorithm"] = meta.get("target_algorithm", "")
    finding["verdict"] = verdict_for(finding.get("severity", "WARNING"),
                                     finding["pqc_compliant"])

    std = standards.get_standard(finding["nist_standard"])
    finding["standard_lifecycle"] = std["lifecycle"] if std else "unknown"
    finding["evidence_kind"] = "pqc_usage" if finding["pqc_compliant"] else "legacy_usage"
    has_location = bool(finding.get("file")) and finding.get("line") is not None
    finding["confidence"] = "high" if has_location else "medium"
    finding["rationale"] = (
        f"Rule '{rule_id}' matched {finding['nist_standard']} "
        f"{finding['category']} evidence; static pattern only."
    )
    finding["limitations"] = (
        "Static source-pattern evidence. Does not prove runtime behaviour, "
        "library internals, parameter correctness, FIPS 140 validation, or "
        "organisation-wide compliance."
    )
    return finding


def verdict_for(severity: str, pqc_compliant: bool) -> str:
    """Map (severity, compliance) to PASS / WARN / FAIL."""
    if pqc_compliant:
        return "PASS"
    return "FAIL" if severity.upper() == "ERROR" else "WARN"


# ---------------------------------------------------------------------------
# Per-standard compliance status
# ---------------------------------------------------------------------------

def status_for(compliant_hits: int, legacy_hits: int,
               lifecycle: str = standards.LIFECYCLE_FINAL) -> str:
    """Public per-standard status for a single NIST standard.

    A positive hit for a standard that is still in development is reported as
    ``detected_in_development`` — never as a finalized ``compliant`` pass.
    """
    if compliant_hits and legacy_hits:
        return "partial"
    if compliant_hits:
        if lifecycle == standards.LIFECYCLE_FINAL:
            return "compliant"
        return "detected_in_development"
    if legacy_hits:
        return "non_compliant"
    return "not_detected"


def evidence_status_for(compliant_hits: int, legacy_hits: int,
                        inconclusive: bool = False) -> str:
    """Discovery-oriented evidence state, independent of standard lifecycle."""
    if inconclusive:
        return "unsupported_or_inconclusive"
    if compliant_hits and legacy_hits:
        return "mixed"
    if compliant_hits:
        return "detected"
    if legacy_hits:
        return "legacy_detected"
    return "not_detected"


def compute_score(findings: list) -> int:
    """PQC readiness score 0..100.

    Starts at 100. Legacy findings deduct (ERROR=-20, WARNING=-10). Each
    PQC-compliant usage adds +5 (capped). Floor at 0, ceiling at 100.
    """
    score = 100
    for f in findings:
        if f.get("pqc_compliant"):
            score += 5
        else:
            severity = str(f.get("severity", "WARNING")).upper()
            score -= 20 if severity == "ERROR" else 10
    return max(0, min(100, score))


def overall_verdict(score: int, standards_matrix: dict,
                    findings_count: int = 1, advisory_total: int = 0,
                    legacy_total: int = 0) -> str:
    """Project-level discovery verdict used by dashboards / reports.

    ``not_assessed`` is deliberately distinct from ``compliant``: no matching
    evidence means the scanner observed nothing, not that the project is safe.
    """
    if findings_count == 0:
        return "not_assessed"

    statuses = {
        std: standards_matrix.get(std, {}).get("status", "not_detected")
        for std in STANDARDS
    }
    if any(s == "non_compliant" for s in statuses.values()):
        return "non_compliant"
    if any(s == "partial" for s in statuses.values()):
        return "at_risk"
    if any(s == "transitional" for s in statuses.values()):
        return "transitional"
    if advisory_total > 0:
        return "at_risk"

    # Project-level "compliant" requires positive PQC evidence for every final
    # standard and no legacy evidence anywhere.  ``not_detected`` is not a pass.
    final_ids = [s["id"] for s in standards.STANDARDS
                 if s["lifecycle"] == standards.LIFECYCLE_FINAL]
    if all(statuses.get(std) == "compliant" for std in final_ids):
        return "compliant"
    if any(s in ("compliant", "detected_in_development") for s in statuses.values()):
        return "incomplete"
    # No standard evidence: do not call legacy-only or unknown evidence a pass.
    if legacy_total > 0:
        return "at_risk"
    return "incomplete"


# ---------------------------------------------------------------------------
# Main entry points
# ---------------------------------------------------------------------------

def analyze_compliance(findings: list, metadata: dict | None = None) -> dict:
    """Compute the full NIST compliance matrix for a list of findings.

    Findings are dicts with at least 'severity' and either 'vulnerability'
    (rule id) or 'rule'. Metadata is attached automatically.
    """
    metadata = metadata if metadata is not None else load_rule_metadata()
    findings = [enrich_finding(dict(f), metadata) for f in findings]
    # Inconclusive data-flow evidence (unresolved env/config values) is surfaced
    # to the user but must not silently drive statuses/scores.
    informational = [f for f in findings if f.get("informational")]
    findings = [f for f in findings if not f.get("informational")]

    standards_matrix = {}
    for std, info in STANDARDS.items():
        std_findings = [f for f in findings if f.get("nist_standard") == std]
        compliant = [f for f in std_findings if f.get("pqc_compliant")]
        legacy = [f for f in std_findings if not f.get("pqc_compliant")]
        inconclusive = any(f.get("standard_evidence") == "inconclusive"
                           for f in std_findings)
        lifecycle = info.get("lifecycle", standards.lifecycle_of(std))
        status = status_for(len(compliant), len(legacy), lifecycle=lifecycle)
        severity = "ok"
        if status == "non_compliant":
            severity = "critical" if any(f["severity"].upper() == "ERROR"
                                          for f in legacy) else "warning"
        elif status in ("partial", "detected_in_development", "transitional"):
            severity = "warning" if status == "partial" else "info"

        located = [f for f in (compliant + legacy) if f.get("file") and f.get("line")]
        if not std_findings:
            confidence = "none"
        elif len(located) == len(std_findings):
            confidence = "high"
        else:
            confidence = "medium"

        standards_matrix[std] = {
            "algorithm": info["algorithm"],
            "former": info["former"],
            "role": info["role"],
            "primitive": info.get("primitive", "unknown"),
            "category": info.get("category", "unknown"),
            "status": status,
            "evidence_status": evidence_status_for(
                len(compliant), len(legacy), inconclusive=inconclusive
            ),
            "standard_lifecycle": lifecycle,
            "lifecycle_label": (
                "Finalized NIST standard" if lifecycle == standards.LIFECYCLE_FINAL
                else "Selected algorithm; standard in development"
            ),
            "source": info.get("source", ""),
            "reviewed": info.get("reviewed", standards.REGISTRY_REVIEWED),
            "confidence": confidence,
            "evidence_coverage": "static source-pattern evidence only",
            "rationale": _standard_rationale(std, info, status, len(compliant),
                                              len(legacy), lifecycle),
            "compliant_count": len(compliant),
            "legacy_count": len(legacy),
            "severity": severity,
        }

    advisory = {bucket: 0 for bucket in ADVISORY_BUCKETS}
    advisory["total"] = 0
    for f in findings:
        cat = f.get("category", "unknown")
        if cat in ADVISORY_BUCKETS and not f.get("pqc_compliant"):
            advisory[cat] += 1
            advisory["total"] += 1

    # Hybrid / transitional classification: X25519+ML-KEM (or a documented
    # X25519Kyber768Draft00 TLS group) counts as compliant migration evidence
    # but is NOT fully-compliant — it is a transitional state.
    hybrid = any(f.get("category") == "hybrid" and f.get("pqc_compliant") for f in findings)
    if hybrid:
        std203 = standards_matrix.get("FIPS 203")
        if std203 and std203["status"] in ("compliant", "partial"):
            std203["status"] = "transitional"
            std203["evidence_status"] = "mixed" if std203["legacy_count"] else "detected"
            std203["severity"] = "warning" if std203.get("legacy_count") else "info"

    score = compute_score(findings)
    risk = compute_risk_score(findings)
    level = risk_level(risk)
    legacy_total = sum(1 for f in findings if not f.get("pqc_compliant"))
    verdict = overall_verdict(score, standards_matrix, findings_count=len(findings),
                              advisory_total=advisory["total"],
                              legacy_total=legacy_total)
    coverage = "no matching evidence observed" if not findings else \
        "static source-pattern evidence only"
    summary = build_summary(standards_matrix, advisory, score, risk=risk,
                            risk_level=level, coverage=coverage)

    return {
        "pqc_score": score,
        "risk_score": risk,
        "risk_level": level,
        "verdict": verdict,
        "standards": standards_matrix,
        "advisory": advisory,
        "summary": summary,
        "findings_count": len(findings),
        "informational_count": len(informational),
        "hybrid": hybrid,
        "assessment": {
            "status": "not_assessed" if not findings else "static_discovery",
            "evidence_coverage": coverage,
            "standards_registry_reviewed": standards.REGISTRY_REVIEWED,
            "semantics_version": SEMANTICS_VERSION,
            "score_formula_version": SCORE_FORMULA_VERSION,
            "risk_formula_version": RISK_FORMULA_VERSION,
            "limitations": (
                "Discovery only: source-pattern matches do not prove runtime "
                "behaviour, FIPS 140 module validation, or compliance. "
                "Inconclusive (unresolved dynamic value) evidence is reported "
                "separately and excluded from statuses and scores."
            ),
        },
    }


def _standard_rationale(std: str, info: dict, status: str, compliant: int,
                        legacy: int, lifecycle: str) -> str:
    """Explain *why* a status was produced, without overclaiming."""
    if status == "not_detected":
        return (f"No {info['algorithm']} ({std}) evidence observed. This means "
                f"unknown/not observed — not compliant.")
    if status == "non_compliant":
        return (f"{legacy} legacy {info['category']} finding(s) and no "
                f"{info['algorithm']} evidence.")
    if status == "partial":
        return (f"{compliant} {info['algorithm']} evidence finding(s) alongside "
                f"{legacy} legacy finding(s) in the same category.")
    if status == "detected_in_development":
        return (f"{compliant} {info['algorithm']} evidence finding(s); {std} is "
                f"still in development, so this is algorithm evidence, not a "
                f"finalized-standard pass.")
    if status == "transitional":
        return (f"Hybrid classical+PQC evidence for {info['algorithm']} ({std}); "
                f"migration is in progress, not complete.")
    return (f"{compliant} {info['algorithm']} evidence finding(s) and no legacy "
            f"finding(s) in this category (static pattern evidence only).")


def build_summary(standards: dict, advisory: dict, score: int,
                  risk: int = 0, risk_level: str = "low",
                  coverage: str = "static source-pattern evidence only") -> str:
    """Human-readable one-paragraph summary for reports and the chat assistant."""
    parts = []
    for std, info in STANDARDS.items():
        data = standards.get(std, {})
        status = data.get("status", "not_detected")
        if status == "compliant":
            parts.append(f"{info['algorithm']} ({std}) evidence detected")
        elif status == "detected_in_development":
            parts.append(f"{info['algorithm']} ({std}) algorithm evidence detected, "
                         f"but the standard is still in development "
                         f"(not a finalized pass)")
        elif status == "transitional":
            parts.append(f"{info['algorithm']} ({std}) is in transitional hybrid state "
                         f"(classical + PQC key exchange combined)")
        elif status == "partial":
            parts.append(f"{info['algorithm']} ({std}) is partially migrated "
                         f"({data.get('legacy_count', 0)} legacy use(s) remain)")
        elif status == "non_compliant":
            parts.append(f"{info['algorithm']} ({std}) migration required — "
                         f"{data.get('legacy_count', 0)} legacy use(s) detected")
        else:
            parts.append(f"no {info['algorithm']} ({std}) evidence observed "
                         f"(not assessed)")

    if advisory.get("total"):
        parts.append(f"{advisory['total']} advisory issue(s) in "
                     f"hashing/symmetric/TLS/secrets layers")

    return (f"PQC readiness score {score}/100 (weighted risk {risk}/100, {risk_level}). "
            + "; ".join(parts) +
            f". Evidence coverage: {coverage}. Findings are not proof of FIPS 140 "
            f"module validation or organisation-wide compliance.")


# ---------------------------------------------------------------------------
# Anonymized telemetry (zero-trust local analysis)
# ---------------------------------------------------------------------------

def build_telemetry(findings: list, metadata: dict | None = None) -> dict:
    """Strip source code / variable names; keep only algorithm-level telemetry.

    This is the ONLY payload permitted to leave the local machine when the
    cloud/AI engine is used. No source code, file paths or identifiers.
    """
    metadata = metadata if metadata is not None else load_rule_metadata()
    seen = {}
    for f in findings:
        enriched = enrich_finding(dict(f), metadata)
        key = (enriched.get("nist_standard"), enriched.get("category"),
               enriched.get("severity", "WARNING"), enriched.get("verdict"),
               enriched.get("standard_lifecycle", "unknown"))
        if key not in seen:
            seen[key] = 0
        seen[key] += 1
    return {
        "engine": "piquachu-pqc",
        "algorithm_telemetry": [
            {
                "nist_standard": std,
                "category": cat,
                "severity": sev,
                "verdict": vd,
                "standard_lifecycle": lifecycle,
                "count": count,
            }
            for (std, cat, sev, vd, lifecycle), count in seen.items()
        ],
    }
