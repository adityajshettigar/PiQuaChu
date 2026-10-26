# backend/cbom.py
"""
cbom.py — CycloneDX 1.7 Cryptographic Bill of Materials generator
==================================================================
Serializes the cryptographic assets that PiQuaChu *observed statically* into a
native CycloneDX 1.7 CBOM:

  * components[].type = "cryptographic-asset"
      - algorithm assets with cryptoProperties.algorithmProperties
      - related cryptographic material (keys/secrets) with **no key bytes**
      - protocol assets for TLS/SSH configuration evidence
  * evidence.occurrences — normalized source path + line for each observation
  * vulnerabilities — ONLY genuine advisories (e.g. a matched CVE).  Policy
    findings such as "AES/ECB detected" are not CVEs and stay in PiQuaChu's
    native findings report.
  * metadata — tool, timestamp, registry review date, assessment status.

The official CycloneDX 1.7 JSON schema is bundled under ``schemas/`` (pinned
to specification tag 1.7.2, commit 349314a9d7671d7d2ca5b711a725f49a73979da6).
Use ``validate_cbom()`` to validate serialized artifacts — application unit
tests are not a substitute for schema validation.

Usage:  cipher_cli.py cbom <target> --output cbom.json
        GET /api/v1/scans/<scan_id>/cbom
"""

from __future__ import annotations

import json
import os
import re
import uuid
from datetime import datetime, timezone

import standards

TOOL_NAME = "PiQuaChu"
TOOL_VERSION = "2.4.0"
CBOM_SPEC_VERSION = "1.7"
SCHEMA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "schemas")
SCHEMA_PATH = os.path.join(SCHEMA_DIR, "bom-1.7.schema.json")


class CbomValidationUnavailable(RuntimeError):
    """The official schema validator could not run in this environment."""


class CbomValidationError(ValueError):
    """The generated CBOM failed the official CycloneDX schema."""


# ---------------------------------------------------------------------------
# Identity helpers
# ---------------------------------------------------------------------------

_TMP_PREFIX_RE = re.compile(r"^(?:[A-Za-z]:)?/.*?/piquachu-[^/]+/(.+)$")
_DRIVE_RE = re.compile(r"^[A-Za-z]:/")


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9._-]+", "-", (value or "").lower()).strip("-")
    return slug[:64] or "asset"


def _safe_path(path: str | None) -> str | None:
    """Return a normalized, relative source path.  Never leak host paths."""
    if not path:
        return None
    p = str(path).replace("\\", "/").strip()
    if not p:
        return None
    match = _TMP_PREFIX_RE.match(p)
    if match:
        p = match.group(1)
    elif p.startswith("/") or _DRIVE_RE.match(p):
        # Unknown absolute root: keep only the basename rather than the host path.
        p = os.path.basename(p)
    p = p.lstrip("./")
    # Drop traversal / empty segments.
    segments = [seg for seg in p.split("/") if seg and seg not in (".", "..")]
    return "/".join(segments) or None


def _unique_ref(base: str, used: set[str]) -> str:
    ref = base
    n = 2
    while ref in used:
        ref = f"{base}-{n}"
        n += 1
    used.add(ref)
    return ref


# ---------------------------------------------------------------------------
# Asset derivation (conservative: rule-id evidence only)
# ---------------------------------------------------------------------------
# Each tuple: (compiled matcher, asset descriptor).  An asset is only emitted
# when the rule id carries a recognizable primitive; otherwise the finding stays
# in PiQuaChu's native report and is not fabricated into the CBOM.
# CycloneDX 1.7 cryptoProperties.algorithmProperties.algorithmFamily enum.
# Only emit a family value when the official schema accepts it; FN-DSA and
# generic RSA have no family identifier in 1.7, so the component name carries it.
_FAMILY_ENUM = {
    "3DES", "AES", "DES", "DSA", "ECDH", "ECDSA", "EdDSA", "MD5",
    "ML-DSA", "ML-KEM", "RC4", "SHA-1", "SLH-DSA",
}

_ASSET_RULES: list[tuple[re.Pattern, dict]] = [
    # Key-material rules must win over generic algorithm matchers (e.g. "rsa").
    (re.compile(r"key[-_]file[-_]rsa|openssh.*rsa", re.I),
     {"name": "RSA key material", "assetType": "related-crypto-material",
      "rcmType": "private-key"}),
    (re.compile(r"key[-_]file[-_]ec", re.I),
     {"name": "EC key material", "assetType": "related-crypto-material",
      "rcmType": "private-key"}),
    (re.compile(r"hardcoded[-_]secret|taint[-_]secret|credential", re.I),
     {"name": "Hardcoded cryptographic secret", "assetType": "related-crypto-material",
      "rcmType": "credential"}),
    (re.compile(r"ml[-_]?kem|kyber", re.I),
     {"name": "ML-KEM", "primitive": "kem", "algorithmFamily": "ML-KEM",
      "nist_standard": "FIPS 203"}),
    (re.compile(r"ml[-_]?dsa|dilithium", re.I),
     {"name": "ML-DSA", "primitive": "signature", "algorithmFamily": "ML-DSA",
      "nist_standard": "FIPS 204"}),
    (re.compile(r"slh[-_]?dsa|sphincs", re.I),
     {"name": "SLH-DSA", "primitive": "signature", "algorithmFamily": "SLH-DSA",
      "nist_standard": "FIPS 205"}),
    (re.compile(r"fn[-_]?dsa|falcon", re.I),
     {"name": "FN-DSA", "primitive": "signature",
      "nist_standard": "FIPS 206"}),
    (re.compile(r"hybrid", re.I),
     {"name": "Hybrid classical+PQC key exchange", "primitive": "combiner"}),
    (re.compile(r"rsa.*sign|sign.*rsa", re.I),
     {"name": "RSA signature", "primitive": "signature"}),
    (re.compile(r"rsa", re.I),
     {"name": "RSA", "primitive": "pke"}),
    (re.compile(r"ecdsa|eddsa|ed25519|ed448", re.I),
     {"name": "ECDSA/EdDSA", "primitive": "signature"}),
    (re.compile(r"ecdh|x25519|x448", re.I),
     {"name": "ECDH/X25519", "primitive": "key-agree",
      "algorithmFamily": "ECDH"}),
    (re.compile(r"(^|[-_])dsa([-_]|$)", re.I),
     {"name": "DSA", "primitive": "signature", "algorithmFamily": "DSA"}),
    (re.compile(r"md5", re.I),
     {"name": "MD5", "primitive": "hash", "algorithmFamily": "MD5"}),
    (re.compile(r"sha[-_]?1", re.I),
     {"name": "SHA-1", "primitive": "hash", "algorithmFamily": "SHA-1"}),
    (re.compile(r"aes[-_]?128", re.I),
     {"name": "AES-128", "primitive": "block-cipher",
      "algorithmFamily": "AES", "classicalSecurityLevel": 128}),
    (re.compile(r"3des|desede|(^|[-_])des([-_]|$)", re.I),
     {"name": "DES/3DES", "primitive": "block-cipher",
      "algorithmFamily": "3DES"}),
    (re.compile(r"rc4", re.I),
     {"name": "RC4", "primitive": "stream-cipher", "algorithmFamily": "RC4"}),
    (re.compile(r"pkcs1v15", re.I),
     {"name": "RSA PKCS#1 v1.5", "primitive": "pke", "padding": "pkcs1v15"}),
    (re.compile(r"ecb", re.I),
     {"name": "ECB mode", "primitive": "block-cipher", "mode": "ecb"}),
    (re.compile(r"cbc.*static|static.*iv", re.I),
     {"name": "CBC mode with static IV", "primitive": "block-cipher", "mode": "cbc"}),
    (re.compile(r"static[-_]salt|kdf", re.I),
     {"name": "KDF with static salt", "primitive": "kdf"}),
    (re.compile(r"random", re.I),
     {"name": "Insecure PRNG", "primitive": "drbg"}),
    (re.compile(r"(^|[-_])ssh([-_]|$)", re.I),
     {"name": "SSH transport configuration", "assetType": "protocol",
      "protocolType": "ssh"}),
    (re.compile(r"(^|[-_])tls([-_]|$)", re.I),
     {"name": "TLS transport configuration", "assetType": "protocol",
      "protocolType": "tls"}),
]


def _parameter_set(text: str) -> tuple[str | None, int | None]:
    """Extract an exact standardized parameter set from observed source text.

    Only returns a value when the literal parameter set appears in evidence.
    Family-level names (e.g. "ML-KEM") deliberately return no NIST level.
    """
    blob = (text or "").casefold()
    found: list[tuple[str, int]] = []
    seen = set()
    for entry in standards.STANDARDS:
        for name, level in entry["nist_quantum_security_levels"].items():
            if name.casefold() in blob and name.casefold() not in seen:
                seen.add(name.casefold())
                found.append((name, level))
    if len({level for _, level in found}) == 1 and found:
        return found[0]
    return None, None


def _asset_from_finding(finding: dict) -> dict | None:
    """Derive one cryptographic asset descriptor from a finding, or None."""
    rule_id = str(finding.get("vulnerability") or finding.get("rule") or "")
    if not rule_id:
        return None
    # Dependency findings describe libraries, not the crypto asset itself.
    if rule_id.startswith("dependency-"):
        return None

    for matcher, descriptor in _ASSET_RULES:
        if not matcher.search(rule_id):
            continue
        asset = dict(descriptor)
        asset.setdefault("assetType", "algorithm")
        text = " ".join(str(finding.get(k) or "")
                        for k in ("line_text", "recommendation"))
        if asset["assetType"] == "algorithm":
            param, level = _parameter_set(text)
            if param:
                asset["parameterSetIdentifier"] = param
                asset["nistQuantumSecurityLevel"] = level
        if asset["assetType"] == "protocol" and asset.get("protocolType") == "tls":
            version = re.search(r"TLS\s*(1\.[0-3])", text, re.I)
            if version:
                asset["protocolVersion"] = version.group(1)
        asset["rule_id"] = rule_id
        return asset
    return None


def _asset_key(asset: dict) -> tuple:
    return (
        asset.get("assetType", "algorithm"),
        asset.get("name"),
        asset.get("primitive"),
        asset.get("mode"),
        asset.get("padding"),
        asset.get("parameterSetIdentifier"),
        asset.get("protocolType"),
        asset.get("protocolVersion"),
    )


def _crypto_properties(asset: dict) -> dict:
    asset_type = asset.get("assetType", "algorithm")
    props: dict = {"assetType": asset_type}
    if asset_type == "algorithm":
        algorithm = {"primitive": asset.get("primitive", "unknown")}
        if asset.get("algorithmFamily") in _FAMILY_ENUM:
            algorithm["algorithmFamily"] = asset["algorithmFamily"]
        if asset.get("parameterSetIdentifier"):
            algorithm["parameterSetIdentifier"] = asset["parameterSetIdentifier"]
        if asset.get("nistQuantumSecurityLevel") is not None:
            # Only present when the exact parameter set was observed.
            algorithm["nistQuantumSecurityLevel"] = asset["nistQuantumSecurityLevel"]
        if asset.get("mode"):
            algorithm["mode"] = asset["mode"]
        if asset.get("padding"):
            algorithm["padding"] = asset["padding"]
        if asset.get("classicalSecurityLevel"):
            algorithm["classicalSecurityLevel"] = asset["classicalSecurityLevel"]
        props["algorithmProperties"] = algorithm
    elif asset_type == "related-crypto-material":
        props["relatedCryptoMaterialProperties"] = {
            "type": asset.get("rcmType", "other")
        }
    elif asset_type == "protocol":
        protocol = {"type": asset.get("protocolType", "other")}
        if asset.get("protocolVersion"):
            protocol["version"] = asset["protocolVersion"]
        props["protocolProperties"] = protocol
    return props


# ---------------------------------------------------------------------------
# CBOM construction
# ---------------------------------------------------------------------------

def build_cbom(compliance_matrix: dict, findings: list, scan_id: int | None = None,
               filename: str | None = None) -> dict:
    """Build a CycloneDX 1.7 CBOM from a compliance matrix + findings list."""
    standards_matrix = (compliance_matrix or {}).get("standards", {}) or {}
    findings = findings or []

    assets: dict[tuple, dict] = {}
    used_refs: set[str] = set()

    def _add_asset(asset: dict, finding: dict | None) -> None:
        key = _asset_key(asset)
        entry = assets.get(key)
        if entry is None:
            entry = {
                "asset": asset,
                "rules": set(),
                "occurrences": {},
                "standards": set(),
                "lifecycles": set(),
                "evidence_statuses": set(),
            }
            assets[key] = entry
        if finding:
            entry["rules"].add(asset.get("rule_id", ""))
            location = _safe_path(finding.get("file"))
            line = finding.get("line")
            if location:
                occ_key = (location, line)
                entry["occurrences"][occ_key] = {"location": location, "line": line}
        std_id = asset.get("nist_standard")
        if std_id:
            entry["standards"].add(std_id)
            std = standards.get_standard(std_id)
            if std:
                entry["lifecycles"].add(std["lifecycle"])
            info = standards_matrix.get(std_id, {})
            if info.get("evidence_status"):
                entry["evidence_statuses"].add(info["evidence_status"])

    # 1) Assets from individual findings (legacy + PQC + config/key evidence).
    for finding in findings:
        asset = _asset_from_finding(finding)
        if asset:
            _add_asset(asset, finding)

    # 2) Family-level standard assets only when no finding-level asset for that
    #    standard already exists.  This avoids double-counting the same asset.
    represented = {std for entry in assets.values() for std in entry["standards"]}
    for std_id, info in standards_matrix.items():
        if not info.get("compliant_count") or std_id in represented:
            continue
        std = standards.get_standard(std_id)
        if not std:
            continue
        _add_asset({
            "name": std["algorithm"],
            "assetType": "algorithm",
            "primitive": std["primitive"],
            "nist_standard": std_id,
            "rule_id": "",
        }, None)

    components = []
    for key, entry in assets.items():
        asset = entry["asset"]
        ref = _unique_ref(f"crypto-{_slug(asset['name'])}", used_refs)
        occurrences = sorted(entry["occurrences"].values(),
                             key=lambda o: (o["location"], o.get("line") or 0))
        properties = [
            {"name": "piquachu:evidence_source", "value": "static-source-pattern"},
            {"name": "piquachu:limitations", "value":
             "Pattern evidence only; not proof of runtime use, correct "
             "parameters, FIPS 140 validation, or organisation-wide compliance."},
        ]
        if entry["rules"]:
            properties.append({"name": "piquachu:rule_ids",
                               "value": ", ".join(sorted(r for r in entry["rules"] if r))})
        for std_id in sorted(entry["standards"]):
            properties.append({"name": "piquachu:nist_standard", "value": std_id})
        for lifecycle in sorted(entry["lifecycles"]):
            properties.append({"name": "piquachu:standard_lifecycle", "value": lifecycle})
        for status in sorted(entry["evidence_statuses"]):
            properties.append({"name": "piquachu:evidence_status", "value": status})
        properties.append({"name": "piquachu:occurrence_count",
                           "value": str(len(occurrences))})

        component = {
            "type": "cryptographic-asset",
            "bom-ref": ref,
            "name": asset["name"],
            "description": (
                "Cryptographic asset observed by PiQuaChu static analysis. "
                "Discovery evidence, not a compliance certification."
            ),
            "cryptoProperties": _crypto_properties(asset),
            "properties": properties,
        }
        if occurrences:
            component["evidence"] = {
                "identity": [{"field": "name", "confidence": 0.6}],
                "occurrences": occurrences,
            }
        components.append(component)

    # 3) Vulnerabilities: genuine CVE advisories only (dependency matches).
    vulnerabilities = []
    policy_count = 0
    seen_cves: set[str] = set()
    for finding in findings:
        rule_id = str(finding.get("vulnerability") or "")
        recommendation = str(finding.get("recommendation") or "")
        cve_match = re.search(r"CVE-\d{4}-\d{4,}", recommendation)
        if not (rule_id == "dependency-vulnerable-version" and cve_match):
            policy_count += 1
            continue
        cve_id = cve_match.group(0)
        if cve_id in seen_cves:
            continue
        seen_cves.add(cve_id)
        severity = {"ERROR": "high", "CRITICAL": "critical",
                    "WARNING": "medium", "INFO": "info"}.get(
            str(finding.get("severity", "WARNING")).upper(), "medium")
        vulnerabilities.append({
            "id": cve_id,
            "source": {"name": "NVD",
                       "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"},
            "description": recommendation,
            "recommendation": "Upgrade the affected dependency to a patched version.",
            "ratings": [{"severity": severity, "method": "other"}],
            "properties": [
                {"name": "piquachu:rule_id", "value": rule_id},
                {"name": "piquachu:file", "value": _safe_path(finding.get("file")) or ""},
                {"name": "piquachu:line", "value": str(finding.get("line", ""))},
            ],
        })

    covered_refs = [c["bom-ref"] for c in components]
    metadata_properties = [
        {"name": "piquachu:pqc_score", "value": str((compliance_matrix or {}).get("pqc_score", 0))},
        {"name": "piquachu:risk_score", "value": str((compliance_matrix or {}).get("risk_score", 0))},
        {"name": "piquachu:verdict", "value": str((compliance_matrix or {}).get("verdict", "unknown"))},
        {"name": "piquachu:findings_count", "value": str(len(findings))},
        {"name": "piquachu:assessment_status", "value": str(
            ((compliance_matrix or {}).get("assessment") or {}).get("status", "unknown"))},
        {"name": "piquachu:standards_registry_reviewed", "value": standards.REGISTRY_REVIEWED},
        {"name": "piquachu:policy_findings_not_in_vulnerabilities", "value": str(policy_count)},
        {"name": "piquachu:cbom_spec_version", "value": CBOM_SPEC_VERSION},
    ]
    if scan_id is not None:
        metadata_properties.append({"name": "piquachu:scan_id", "value": str(scan_id)})
    if covered_refs:
        metadata_properties.append({
            "name": "piquachu:assets_within_scope",
            "value": ", ".join(covered_refs),
        })

    metadata = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tools": {
            "components": [{
                "type": "application",
                "name": TOOL_NAME,
                "version": TOOL_VERSION,
                "supplier": {"name": "PiQuaChu"},
            }]
        },
        "component": {
            "type": "application",
            "name": _safe_path(filename) or "unknown-project",
            "bom-ref": "piquachu-project",
        },
        "properties": metadata_properties,
    }

    return {
        "bomFormat": "CycloneDX",
        "specVersion": CBOM_SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": metadata,
        "components": components,
        "vulnerabilities": vulnerabilities,
    }


# ---------------------------------------------------------------------------
# Official schema validation
# ---------------------------------------------------------------------------

def _load_json(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def validate_cbom(bom: dict, schema_path: str = SCHEMA_PATH) -> None:
    """Validate a BOM against the bundled official CycloneDX 1.7 JSON schema.

    Raises CbomValidationUnavailable when the jsonschema dependency is missing
    (callers must report BLOCKED, never a fake pass) and CbomValidationError on
    schema violations.
    """
    try:
        from jsonschema import Draft7Validator
        from referencing import Registry, Resource
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise CbomValidationUnavailable(
            "jsonschema/referencing not installed; run "
            "`pip install jsonschema` and re-run CBOM validation"
        ) from exc

    if not os.path.exists(schema_path):
        raise CbomValidationUnavailable(f"official schema not found: {schema_path}")

    schema = _load_json(schema_path)
    base = "http://cyclonedx.org/schema/"
    resources = {}
    for name in ("cryptography-defs.schema.json", "spdx.schema.json",
                 "jsf-0.82.schema.json"):
        path = os.path.join(os.path.dirname(schema_path), name)
        if os.path.exists(path):
            resources[base + name] = Resource.from_contents(_load_json(path))
    registry = Registry().with_resources(resources.items())
    validator = Draft7Validator(schema, registry=registry)
    errors = sorted(validator.iter_errors(bom), key=lambda e: list(e.absolute_path))
    if errors:
        detail = []
        for err in errors[:10]:
            location = "/".join(str(p) for p in err.absolute_path) or "<root>"
            detail.append(f"{location}: {err.message}")
        raise CbomValidationError(
            f"{len(errors)} CycloneDX 1.7 schema violation(s): " + "; ".join(detail)
        )
