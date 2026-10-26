# backend/standards.py
"""
standards.py — authoritative algorithm / standards registry
============================================================
Single source of truth for what PiQuaChu claims about post-quantum standards.

Every other module (compliance matrix, CBOM, CLI, docs tests) reads from this
registry.  A standard entry records *standardisation lifecycle* only — it says
nothing about implementation assurance, FIPS 140 module validation, runtime
behaviour or organisation-wide compliance.

Status provenance (reviewed 2026-10-18):
  * FIPS 203, 204 and 205 were published by NIST on 2024-08-13.
  * FIPS 206 (FN-DSA / FALCON) is still **in development** on NIST's PQC
    project pages; FALCON is listed as a selected algorithm with "FIPS coming
    soon".  It must never be reported as a finalized-standard pass until the
    authoritative source below changes and this registry is re-reviewed.

Keep this file data-driven: correcting a lifecycle status is a one-line edit
(plus a fresh review date), never a repository-wide string replacement.
"""

from __future__ import annotations

import datetime as _dt

REGISTRY_REVIEWED = "2026-10-18"

LIFECYCLE_FINAL = "final"
LIFECYCLE_IN_DEVELOPMENT = "in_development"

# CycloneDX 1.7 algorithmProperties.primitive enum
CYCLONEDX_PRIMITIVES = {
    "drbg", "mac", "block-cipher", "stream-cipher", "signature", "hash",
    "pke", "xof", "kdf", "key-agree", "kem", "ae", "combiner", "key-wrap",
    "other", "unknown",
}

# Internal finding categories (rules.yaml metadata.category)
CATEGORIES = {
    "key-encapsulation", "signatures", "hashing", "symmetric", "tls",
    "provider", "secrets", "dependencies", "kdf", "randomness", "hybrid",
    "unknown",
}

STANDARDS: list[dict] = [
    {
        "id": "FIPS 203",
        "algorithm": "ML-KEM",
        "former": "CRYSTALS-Kyber",
        "role": "Key Encapsulation — general encryption",
        "primitive": "kem",
        "category": "key-encapsulation",
        "lifecycle": LIFECYCLE_FINAL,
        "publication_date": "2024-08-13",
        "source": "https://csrc.nist.gov/pubs/fips/203/final",
        "reviewed": REGISTRY_REVIEWED,
        "aliases": ["ML-KEM", "MLKEM", "CRYSTALS-Kyber", "Kyber"],
        "migration_note": (
            "Use ML-KEM for key establishment (KEM), ideally as a hybrid such as "
            "X25519MLKEM768 during transition. Do not describe ML-KEM as a "
            "signature replacement."
        ),
        "nist_quantum_security_levels": {
            "ML-KEM-512": 1,
            "ML-KEM-768": 3,
            "ML-KEM-1024": 5,
        },
    },
    {
        "id": "FIPS 204",
        "algorithm": "ML-DSA",
        "former": "CRYSTALS-Dilithium",
        "role": "Digital Signatures — primary",
        "primitive": "signature",
        "category": "signatures",
        "lifecycle": LIFECYCLE_FINAL,
        "publication_date": "2024-08-13",
        "source": "https://csrc.nist.gov/pubs/fips/204/final",
        "reviewed": REGISTRY_REVIEWED,
        "aliases": ["ML-DSA", "MLDSA", "CRYSTALS-Dilithium", "Dilithium"],
        "migration_note": (
            "Use ML-DSA for digital signatures. Signature migration requires "
            "key, certificate and protocol changes; it is not a drop-in digest swap."
        ),
        "nist_quantum_security_levels": {
            "ML-DSA-44": 2,
            "ML-DSA-65": 3,
            "ML-DSA-87": 5,
        },
    },
    {
        "id": "FIPS 205",
        "algorithm": "SLH-DSA",
        "former": "SPHINCS+",
        "role": "Digital Signatures — hash-based backup",
        "primitive": "signature",
        "category": "signatures",
        "lifecycle": LIFECYCLE_FINAL,
        "publication_date": "2024-08-13",
        "source": "https://csrc.nist.gov/pubs/fips/205/final",
        "reviewed": REGISTRY_REVIEWED,
        "aliases": ["SLH-DSA", "SLHDSA", "SPHINCS+", "SPHINCS"],
        "migration_note": (
            "Use SLH-DSA where hash-based signature assumptions are preferred. "
            "It has larger signatures and different performance trade-offs."
        ),
        "nist_quantum_security_levels": {
            "SLH-DSA-SHA2-128s": 1,
            "SLH-DSA-SHA2-128f": 1,
            "SLH-DSA-SHA2-192s": 3,
            "SLH-DSA-SHA2-192f": 3,
            "SLH-DSA-SHA2-256s": 5,
            "SLH-DSA-SHA2-256f": 5,
            "SLH-DSA-SHAKE-128s": 1,
            "SLH-DSA-SHAKE-128f": 1,
            "SLH-DSA-SHAKE-192s": 3,
            "SLH-DSA-SHAKE-192f": 3,
            "SLH-DSA-SHAKE-256s": 5,
            "SLH-DSA-SHAKE-256f": 5,
        },
    },
    {
        "id": "FIPS 206",
        "algorithm": "FN-DSA",
        "former": "FALCON",
        "role": "Digital Signatures — lattice (NTRU), hash-and-sign",
        "primitive": "signature",
        "category": "signatures",
        # NIST lists FALCON as selected; FIPS 206 has NOT been published.
        "lifecycle": LIFECYCLE_IN_DEVELOPMENT,
        "publication_date": None,
        "source": "https://csrc.nist.gov/projects/post-quantum-cryptography",
        "reviewed": REGISTRY_REVIEWED,
        "aliases": ["FN-DSA", "FNDSA", "FALCON", "Falcon"],
        "migration_note": (
            "FN-DSA/FALCON is a selected algorithm whose standard is still in "
            "development. Treat detected usage as algorithm evidence, not as a "
            "finalized FIPS 206 compliance pass."
        ),
        "nist_quantum_security_levels": {
            "Falcon-512": 1,
            "Falcon-1024": 5,
            "FN-DSA-512": 1,
            "FN-DSA-1024": 5,
        },
    },
]

# Category-aware migration guidance.  A weak primitive does not universally map
# to a PQC algorithm: hashes, symmetric ciphers, RNGs, KDFs, TLS versions and
# secrets hygiene each need their own reasoning.
MIGRATION_GUIDANCE = {
    "key-encapsulation": (
        "Key establishment: migrate to ML-KEM (FIPS 203), preferably hybrid "
        "(X25519MLKEM768) during transition. Requires protocol/key-format changes."
    ),
    "signatures": (
        "Signatures: migrate to ML-DSA (FIPS 204) or SLH-DSA (FIPS 205); FN-DSA "
        "(FIPS 206) is still in development. Requires key, certificate and "
        "protocol changes — never a mechanical text substitution."
    ),
    "hashing": (
        "Hashing/integrity: MD5/SHA-1 → SHA-256/SHA-3. This is a legacy-integrity "
        "remediation, not a post-quantum signature migration."
    ),
    "symmetric": (
        "Symmetric crypto: AES is not broken by Shor's algorithm. Prefer "
        "AES-256-GCM and remove ECB/static-IV modes. Grover's algorithm only "
        "reduces the nominal security margin."
    ),
    "tls": (
        "Transport: move to TLS 1.3 with a hybrid PQC group where supported; "
        "observe actual negotiation separately."
    ),
    "secrets": (
        "Secrets hygiene: move credentials/keys to a secrets manager and rotate "
        "them. This is not an algorithm migration."
    ),
    "kdf": (
        "KDF: use a modern KDF with a fresh random salt per credential; a static "
        "salt is a hygiene defect, not a PQC primitive."
    ),
    "randomness": (
        "Randomness: use a cryptographically secure RNG for key/IV/nonce material; "
        "PRNG choice is orthogonal to PQC algorithm selection."
    ),
    "dependencies": (
        "Dependency risk: update or replace the library and re-scan. A vulnerable "
        "dependency does not prove the application calls the affected primitive."
    ),
    "hybrid": (
        "Hybrid/transitional: classical + PQC is evidence of migration in progress; "
        "it is not a finalized PQC-only state."
    ),
    "provider": (
        "Provider evidence: a PQC-capable provider/library is not proof that the "
        "application uses an approved algorithm correctly."
    ),
    "unknown": (
        "Unclassified evidence: review manually; the scanner cannot determine a "
        "safe migration target."
    ),
}


class RegistryError(ValueError):
    """Raised when the authoritative standards registry is internally invalid."""


def standard_ids() -> list[str]:
    return [s["id"] for s in STANDARDS]


def get_standard(standard_id: str) -> dict | None:
    for s in STANDARDS:
        if s["id"] == standard_id:
            return s
    return None


def lifecycle_of(standard_id: str) -> str:
    s = get_standard(standard_id)
    return s["lifecycle"] if s else "unknown"


def is_final(standard_id: str) -> bool:
    return lifecycle_of(standard_id) == LIFECYCLE_FINAL


def as_compliance_table() -> dict:
    """Backward-compatible mapping used by compliance.STANDARDS and clients."""
    return {
        s["id"]: {
            "algorithm": s["algorithm"],
            "former": s["former"],
            "role": s["role"],
            "primitive": s["primitive"],
            "category": s["category"],
            "lifecycle": s["lifecycle"],
            "source": s["source"],
            "reviewed": s["reviewed"],
        }
        for s in STANDARDS
    }


def by_alias(name: str) -> dict | None:
    """Resolve an algorithm name/alias to its standard entry (alias ≠ proof of
    correct API or parameter use)."""
    needle = (name or "").strip().casefold()
    if not needle:
        return None
    for s in STANDARDS:
        if needle == s["algorithm"].casefold():
            return s
        if needle in {a.casefold() for a in s["aliases"]}:
            return s
    return None


def nist_quantum_security_level(parameter_set: str) -> int | None:
    """Exact parameter-set → NIST category mapping, or None when unknown.

    Never guess.  A family-level name (e.g. "ML-KEM") has no single level.
    """
    needle = (parameter_set or "").strip().casefold()
    if not needle:
        return None
    for s in STANDARDS:
        for name, level in s["nist_quantum_security_levels"].items():
            if name.casefold() == needle:
                return level
    return None


def migration_guidance(category: str) -> str:
    return MIGRATION_GUIDANCE.get(category, MIGRATION_GUIDANCE["unknown"])


def _is_iso_date(value: str) -> bool:
    try:
        _dt.date.fromisoformat(value)
        return True
    except (TypeError, ValueError):
        return False


def validate_registry(registry: list[dict] | None = None) -> None:
    """Fail loudly on lifecycle/provenance/alias mistakes.

    Raises RegistryError; call from self-check and tests.
    """
    registry = STANDARDS if registry is None else registry
    errors: list[str] = []
    if not registry:
        raise RegistryError("standards registry is empty")

    seen_ids: set[str] = set()
    seen_algorithms: set[str] = set()
    alias_owner: dict[str, str] = {}

    for entry in registry:
        sid = entry.get("id") or "<missing id>"
        required = ("id", "algorithm", "former", "role", "primitive", "category",
                    "lifecycle", "source", "reviewed", "aliases", "migration_note")
        missing = [k for k in required if not entry.get(k)]
        if missing:
            errors.append(f"{sid}: missing required fields {missing}")
            continue

        if sid in seen_ids:
            errors.append(f"{sid}: duplicate canonical standard id")
        seen_ids.add(sid)

        alg = entry["algorithm"].casefold()
        if alg in seen_algorithms:
            errors.append(f"{sid}: duplicate canonical algorithm '{entry['algorithm']}'")
        seen_algorithms.add(alg)

        if entry["lifecycle"] not in (LIFECYCLE_FINAL, LIFECYCLE_IN_DEVELOPMENT):
            errors.append(f"{sid}: invalid lifecycle '{entry['lifecycle']}'")

        if entry["primitive"] not in CYCLONEDX_PRIMITIVES:
            errors.append(f"{sid}: invalid primitive '{entry['primitive']}'")

        if entry["category"] not in CATEGORIES:
            errors.append(f"{sid}: invalid category '{entry['category']}'")

        if not str(entry["source"]).startswith("https://"):
            errors.append(f"{sid}: official source must be an https URL")

        if not _is_iso_date(entry["reviewed"]):
            errors.append(f"{sid}: reviewed date must be ISO-8601 (YYYY-MM-DD)")

        # Lifecycle integrity: a final standard needs a publication date; an
        # in-development standard must NOT claim one.
        if entry["lifecycle"] == LIFECYCLE_FINAL:
            if not entry.get("publication_date"):
                errors.append(f"{sid}: final standard requires publication_date")
            elif not _is_iso_date(entry["publication_date"]):
                errors.append(f"{sid}: publication_date must be ISO-8601")
        else:
            if entry.get("publication_date"):
                errors.append(
                    f"{sid}: in-development standard must not claim a publication date"
                )

        levels = entry.get("nist_quantum_security_levels")
        if not isinstance(levels, dict) or not levels:
            errors.append(f"{sid}: nist_quantum_security_levels must be a non-empty map")
        else:
            for name, level in levels.items():
                if level not in (1, 2, 3, 4, 5, 6):
                    errors.append(f"{sid}: invalid NIST level {level} for {name}")

        aliases = entry.get("aliases") or []
        if not aliases:
            errors.append(f"{sid}: at least one alias is required")
        for alias in aliases:
            key = str(alias).strip().casefold()
            if not key:
                errors.append(f"{sid}: empty alias")
                continue
            if key == sid.casefold():
                errors.append(f"{sid}: alias duplicates the standard id")
            owner = alias_owner.get(key)
            if owner and owner != sid:
                errors.append(f"alias collision: '{alias}' in {owner} and {sid}")
            alias_owner[key] = sid

    if errors:
        raise RegistryError("; ".join(errors))


def registry_metadata() -> dict:
    return {
        "reviewed": REGISTRY_REVIEWED,
        "standards": standard_ids(),
        "lifecycle": {s["id"]: s["lifecycle"] for s in STANDARDS},
    }


# Validate on import: a broken registry must never silently drive verdicts.
validate_registry()
