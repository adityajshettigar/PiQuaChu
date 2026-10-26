# backend/deps.py
"""
deps.py — Dependency Manifest Scanner (Cryptographic Bill of Materials input)
==============================================================================
Parses package manifests (requirements.txt, package.json, go.mod, Cargo.toml,
pom.xml, composer.json, Gemfile) AND lockfiles (package-lock.json, Pipfile.lock,
poetry.lock, Cargo.lock, go.sum, yarn.lock) and classifies the declared
cryptography libraries into:

  * LEGACY crypto libs      -> `dependency-legacy-crypto-lib`        (WARNING advisory)
  * Post-quantum crypto libs -> `dependency-pqc-lib`                 (INFO positive)
  * Known-vulnerable version -> `dependency-vulnerable-version`      (severity per CVE)
  * Lockfile-only (possibly transitive) legacy libs
                             -> `dependency-transitive-legacy-crypto-lib` (WARNING)

Version-aware checking matches the declared version against a bundled, curated
advisory database (CVEs for well-known crypto libraries). It is offline-first —
no network calls — so the zero-trust scan pipeline stays hermetic. The advisory
table is a plain dict and can be extended or later fed from OSV/NVD feeds.

Findings share the standard PiQuaChu shape so `compliance.enrich_finding`
and the UI pipeline handle them transparently.
"""

import json
import os
import re

# Rule ids defined in rules.yaml (metadata-only entries).
LEGACY_RULE = "dependency-legacy-crypto-lib"
PQC_RULE = "dependency-pqc-lib"
VULN_RULE = "dependency-vulnerable-version"
TRANSITIVE_RULE = "dependency-transitive-legacy-crypto-lib"

# name (normalized) -> description. Names are matched lower-cased, exact match
# on the package key (e.g. "@noble/post-quantum", "bcpqc-jdk18on").
LEGACY_CRYPTO_LIBS = {
    "cryptography": "Python cryptography (RSA/ECC/MD5/SHA-1 capable)",
    "pycryptodome": "PyCryptodome (DES/3DES/RC4/AES capable)",
    "pycryptodomex": "PyCryptodomeX (DES/3DES/RC4/AES capable)",
    "pycrypto": "PyCrypto (unmaintained; DES/3DES/RC4 capable)",
    "node-forge": "node-forge (RSA/3DES capable)",
    "forge": "forge (RSA capable)",
    "crypto-js": "crypto-js (MD5/SHA-1/DES/RC4 capable)",
    "sjcl": "SJCL (RSA/ECC capable)",
    "crypto-browserify": "crypto-browserify (legacy algorithms available)",
    "bcprov-jdk18on": "BouncyCastle core provider (RSA/EC/DES capable; PQC lives in bcpqc)",
    "bcprov-jdk15on": "BouncyCastle core provider (legacy algorithms)",
    "openssl": "OpenSSL toolkit",
    "libgcrypt": "GnuPG libgcrypt",
    "nettle": "GNU Nettle low-level crypto",
    "botan": "Botan C++ crypto library",
    "ring": "ring (RSA/ECDSA capable)",
    "openssl-sys": "OpenSSL FFI bindings (Rust)",
}

PQC_CRYPTO_LIBS = {
    "liboqs-python": "liboqs Python bindings (ML-KEM / ML-DSA / SLH-DSA)",
    "oqs": "liboqs Python bindings",
    "pqcrypto": "pqcrypto Python bindings (NIST PQC algorithms)",
    "crystals-kyber": "crystals-kyber (ML-KEM/Kyber)",
    "@noble/post-quantum": "@noble/post-quantum (ML-KEM / ML-DSA / SLH-DSA)",
    "ml-kem": "ml-kem (ML-KEM)",
    "pqcrypto-dilithium": "pqcrypto-dilithium (ML-DSA/Dilithium)",
    "pqcrypto-kyber": "pqcrypto-kyber (ML-KEM/Kyber)",
    "pqcrypto-sphincsplus": "pqcrypto-sphincsplus (SLH-DSA/SPHINCS+)",
    "pqcrypto-traits": "pqcrypto-traits (PQC abstraction)",
    "pqcrypto-falcon": "pqcrypto-falcon (FN-DSA/FALCON signatures)",
    "mlkem-native": "mlkem-native (ML-KEM, PQClean successor)",
    "mldsa-native": "mldsa-native (ML-DSA, PQClean successor)",
    "slhdsa-c": "slhdsa-c (SLH-DSA, PQClean successor)",
    "circl": "Cloudflare circl (Go: ML-KEM / ML-DSA / SLH-DSA)",
    "bcpqc-jdk18on": "BouncyCastle PQC provider (Java)",
    "bcpqc-jdk15on": "BouncyCastle PQC provider (Java)",
    "liboqs": "liboqs C library",
    "oqs-go": "liboqs Go bindings",
}

# ---------------------------------------------------------------------------
# Bundled advisory database (curated, offline). Constraints are AND-ed; each
# constraint is {"op": "<|<=|>|>=|==|!=", "version": "x.y.z"}. Add entries from
# OSV/NVD feeds here — no code change needed beyond this dict.
# ---------------------------------------------------------------------------
ADVISORIES = {
    "node-forge": [
        {"id": "CVE-2022-24771", "severity": "ERROR",
         "constraints": [{"op": "<", "version": "1.3.0"}],
         "description": "RSA signature verification bypass in node-forge (CVE-2022-24771)."},
        {"id": "CVE-2020-7720", "severity": "WARNING",
         "constraints": [{"op": "<", "version": "0.10.0"}],
         "description": "Prototype pollution in node-forge (CVE-2020-7720)."},
    ],
    "cryptography": [
        {"id": "CVE-2023-49083", "severity": "WARNING",
         "constraints": [{"op": "<", "version": "42.0.2"}],
         "description": "Denial of service via crafted input in pyca/cryptography (CVE-2023-49083)."},
    ],
    "openssl": [
        {"id": "CVE-2022-3602", "severity": "WARNING",
         "constraints": [{"op": "<", "version": "3.0.7"}],
         "description": "X.509 email-address 4-byte buffer overflow in OpenSSL (CVE-2022-3602)."},
    ],
}

_VERSION_RE = re.compile(r"(\d+)(?:\.\d+)*")


def _extract_version(spec: str) -> str | None:
    """Pull the first concrete dotted version out of a spec string
    ('==1.2.3', '^1.3.1', '~> 1.2', 'v1.0.0', '>=1.2,<2' …) or None."""
    if not spec:
        return None
    m = _VERSION_RE.search(spec)
    return m.group(0) if m else None


def _parse_version(version: str) -> tuple:
    parts = []
    for chunk in version.split("."):
        m = re.match(r"\d+", chunk)
        parts.append(int(m.group(0)) if m else 0)
    return tuple(parts)


def _version_satisfies(version: str, constraints: list) -> bool:
    """True if `version` satisfies ALL constraints (AND semantics)."""
    v = _parse_version(version)
    for con in constraints:
        op, target = con.get("op"), con.get("version")
        if not op or not target:
            continue
        t = _parse_version(target)
        if op == "<" and not v < t:
            return False
        if op == "<=" and not v <= t:
            return False
        if op == ">" and not v > t:
            return False
        if op == ">=" and not v >= t:
            return False
        if op == "==" and not v == t:
            return False
        if op == "!=" and not v != t:
            return False
    return True


# ---------------------------------------------------------------------------
# Manifest parsers — each returns an ordered list of (package_name, version_spec, line)
# ---------------------------------------------------------------------------

_PIP_RE = re.compile(r"^\s*([A-Za-z0-9_.\-\[\]]+)\s*(==|>=|<=|~=|!=|<|>)?\s*([^\s#;]+)?")


def _parse_pip(content: str):
    out = []
    for i, raw in enumerate(content.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith(("#", "-r", "--", "git+")):
            continue
        m = _PIP_RE.match(line)
        if m:
            out.append((m.group(1).lower(), m.group(3) or None, i))
    return out


def _parse_json_deps(content: str):
    """package.json / composer.json style: name keys under dependencies/devDependencies."""
    out = []
    try:
        doc = json.loads(content)
    except Exception:
        return []
    for section in ("dependencies", "devDependencies", "require", "require-dev"):
        deps = doc.get(section) or {}
        if isinstance(deps, dict):
            for name, spec in deps.items():
                out.append((name.lower(), str(spec) if spec is not None else None, 1))
    return out


_GO_RE = re.compile(r"^\s*require\s+\(?([\w.\-/]+)(\s+v[\w.+-]+)?\)?\s*$")


def _parse_go_mod(content: str):
    out = []
    for i, raw in enumerate(content.splitlines(), 1):
        line = raw.strip()
        if line.startswith("require"):
            m = _GO_RE.match(line)
            if m:
                out.append((m.group(1).lower(), m.group(2) or None, i))
        elif line and not line.startswith(("module", "go ", "//", ")")) and " " in line:
            parts = line.split()
            if parts and not parts[0].startswith("("):
                out.append((parts[0].lower(), parts[1] if len(parts) > 1 else None, i))
    return out


_CARGO_RE = re.compile(r"^\s*([A-Za-z0-9_\-]+)\s*=\s*[\"\{]")
_CARGO_GIT_RE = re.compile(r"^\s*([A-Za-z0-9_\-]+)\s*=\s*\{")


def _parse_cargo(content: str):
    out = []
    for i, raw in enumerate(content.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith(("[", "#")):
            continue
        m = _CARGO_RE.match(line) or _CARGO_GIT_RE.match(line)
        if m:
            spec = None
            em = re.search(r'=\s*"([^"]+)"', line)
            if em:
                spec = em.group(1)
            out.append((m.group(1).lower().replace("_", "-"), spec, i))
    return out


def _parse_pom(content: str):
    out = []
    try:
        import xml.etree.ElementTree as ET
        root = ET.fromstring(content)
    except Exception:
        return []
    ns = {"m": "http://maven.apache.org/POM/4.0.0"}
    for dep in root.findall(".//m:dependency", ns):
        aid = dep.findtext("m:artifactId", default="", namespaces=ns)
        ver = dep.findtext("m:version", default="", namespaces=ns)
        if aid:
            out.append((aid.lower(), ver or None, 1))
    return out


_GEM_RE = re.compile(r"^\s*gem\s+['\"]([^'\"]+)['\"]")


def _parse_gemfile(content: str):
    out = []
    for i, raw in enumerate(content.splitlines(), 1):
        m = _GEM_RE.match(raw)
        if m:
            spec = None
            em = re.search(r",\s*['\"]([^'\"]+)['\"]", raw)
            if em:
                spec = em.group(1)
            out.append((m.group(1).lower(), spec, i))
    return out


# ---------------------------------------------------------------------------
# Lockfile parsers — capture *transitive* dependencies with pinned versions
# ---------------------------------------------------------------------------

def _parse_package_lock(content: str):
    """npm package-lock.json — packages dict includes transitive deps."""
    out = []
    try:
        doc = json.loads(content)
    except Exception:
        return []
    packages = doc.get("packages") if isinstance(doc, dict) else None
    if isinstance(packages, dict):
        for key, info in packages.items():
            if not isinstance(info, dict):
                continue
            name = info.get("name") or key.rsplit("/", 1)[-1]
            out.append((name.lower(), str(info.get("version") or ""), 1))
    return out


def _parse_pipfile_lock(content: str):
    out = []
    try:
        doc = json.loads(content)
    except Exception:
        return []
    for section in ("default", "develop"):
        deps = doc.get(section) or {}
        if isinstance(deps, dict):
            for name, info in deps.items():
                version = info.get("version", "") if isinstance(info, dict) else ""
                out.append((name.lower(), str(version), 1))
    return out


_PKG_LOCK_RE = re.compile(r'^name\s*=\s*"([^"]+)"')
_PKG_VER_RE = re.compile(r'^version\s*=\s*"([^"]+)"')


def _parse_toml_lock(content: str):
    """Cargo.lock / poetry.lock — [[package]] blocks include transitive deps."""
    out = []
    name = None
    for i, raw in enumerate(content.splitlines(), 1):
        if raw.strip().startswith("[[package]]"):
            name = None
            continue
        m = _PKG_LOCK_RE.match(raw.strip())
        if m:
            name = m.group(1).lower().replace("_", "-")
            continue
        mv = _PKG_VER_RE.match(raw.strip())
        if mv and name:
            out.append((name, mv.group(1), i))
    return out


_GO_SUM_RE = re.compile(r"^([\w.\-/]+)\s+(v[\w.+-]+)\s")


def _parse_go_sum(content: str):
    out = []
    for i, raw in enumerate(content.splitlines(), 1):
        m = _GO_SUM_RE.match(raw)
        if m:
            out.append((m.group(1).lower(), m.group(2), i))
    return out


_YARN_RE = re.compile(r'^"?([^"@][^"@]*)@[^":]*:')


def _parse_yarn_lock(content: str):
    out = []
    for i, raw in enumerate(content.splitlines(), 1):
        m = _YARN_RE.match(raw.strip())
        if m:
            out.append((m.group(1).lower(), None, i))
    return out


# (matcher, parser, is_lockfile)
_MANIFEST_HANDLERS = [
    (lambda name: name.startswith("requirements") and name.endswith(".txt"), _parse_pip, False),
    (lambda name: name == "package.json", _parse_json_deps, False),
    (lambda name: name == "composer.json", _parse_json_deps, False),
    (lambda name: name == "go.mod", _parse_go_mod, False),
    (lambda name: name == "Cargo.toml", _parse_cargo, False),
    (lambda name: name == "pom.xml", _parse_pom, False),
    (lambda name: name == "Gemfile", _parse_gemfile, False),
    # Lockfiles (transitive evidence + pinned versions)
    (lambda name: name == "package-lock.json", _parse_package_lock, True),
    (lambda name: name == "Pipfile.lock", _parse_pipfile_lock, True),
    (lambda name: name == "poetry.lock", _parse_toml_lock, True),
    (lambda name: name == "Cargo.lock", _parse_toml_lock, True),
    (lambda name: name == "go.sum", _parse_go_sum, True),
    (lambda name: name == "yarn.lock", _parse_yarn_lock, True),
]

# Same exclusion policy as the code scanners (vendor code is not the target).
_EXCLUDED_DIRS = {"venv", ".venv", "node_modules", ".git", "dist", "build",
                  "__pycache__", "site-packages", "target",
                  ".piquachu-backups", ".piquachu-patches"}


def scan_manifests(target_directory: str) -> list:
    """Scan a directory tree for dependency manifests + lockfiles and return
    findings shaped for compliance.enrich_finding()."""
    findings = []
    for root, dirs, files in os.walk(target_directory):
        dirs[:] = [d for d in dirs if d not in _EXCLUDED_DIRS]
        for name in files:
            handler = None
            is_lockfile = False
            for match, parser, lock in _MANIFEST_HANDLERS:
                if match(name):
                    handler = parser
                    is_lockfile = lock
                    break
            if handler is None:
                continue
            path = os.path.join(root, name)
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    content = fh.read()
            except OSError:
                continue
            deps = handler(content)
            _emit(deps, path, findings, is_lockfile=is_lockfile)
    return findings


def _emit(deps: list, path: str, findings: list, is_lockfile: bool = False) -> None:
    """Attach findings for one manifest/lockfile. One finding per rule per file;
    the message enumerates every matching library so the audit trail is complete."""
    legacy_hits, pqc_hits = [], []
    for name, spec, _line in deps:
        if name in LEGACY_CRYPTO_LIBS:
            legacy_hits.append(name)
        elif name in PQC_CRYPTO_LIBS:
            pqc_hits.append(name)
        # Version-aware advisory check (only when a concrete version is known).
        version = _extract_version(spec)
        for adv in ADVISORIES.get(name, []):
            if version and _version_satisfies(version, adv["constraints"]):
                findings.append({
                    "file": path,
                    "line": 1,
                    "vulnerability": VULN_RULE,
                    "recommendation": (f"{adv['id']}: {adv['description']} "
                                       f"Declared {name} {spec or version} — upgrade to a patched version."),
                    "severity": adv["severity"],
                })
    if legacy_hits:
        if is_lockfile:
            findings.append({
                "file": path,
                "line": 1,
                "vulnerability": TRANSITIVE_RULE,
                "recommendation": (f"Legacy crypto library(ies) present in lockfile "
                                   f"(direct or transitive): {', '.join(legacy_hits)}. "
                                   f"Review whether they are reachable before the PQC migration freeze."),
                "severity": "WARNING",
            })
        else:
            findings.append({
                "file": path,
                "line": 1,
                "vulnerability": LEGACY_RULE,
                "recommendation": (f"Classical-crypto library(ies) declared: "
                                   f"{', '.join(legacy_hits)}. Review usage before the "
                                   f"PQC migration freeze."),
                "severity": "WARNING",
            })
    if pqc_hits:
        findings.append({
            "file": path,
            "line": 1,
            "vulnerability": PQC_RULE,
            "recommendation": (f"Post-quantum crypto library(ies) declared: "
                               f"{', '.join(pqc_hits)} — positive PQC adoption signal."),
            "severity": "INFO",
        })


def scan_target(target_directory: str) -> list:
    """Public entry point used by scanner.scan_directory()."""
    return scan_manifests(target_directory)
