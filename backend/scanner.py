# backend/scanner.py
"""
scanner.py — PQC Analysis Engine
=================================
Six engines produce findings — never regex-on-raw-source-text:

  1. Semgrep        — parses the AST of Python / Java / JS / TS / Go / C / C++
                      / Rust / PHP and matches against `rules.yaml`.
  2. Python AST     — zero-dependency walker that parses `.py`/`.pyx`/`.pyi`
                      with the built-in `ast` module. Adds *semantic* detection
                      that pattern rules can't express: import-alias resolution,
                      hardcoded secrets, key-length-aware AES-128, textbook/toy
                      RSA (modular exponentiation), and pqcrypto module usage.
  3. Python flow    — bounded intraprocedural constant propagation
                      (dataflow_python.py): local assignment chains, alias
                      imports, constant string expressions, agreeing if/else
                      joins, depth-1 wrappers and env/config values tracked as
                      *unresolved* evidence — never as a pass and never echoed.
  4. Java flow      — bounded javalang pass (dataflow_java.py) over static
                      fields, local chains, concatenation and wrappers into JCA
                      getInstance sinks; parameters stay unresolved. Absence of
                      javalang is reported, not silently assumed supported.
  5. Auxiliary      — semgrep with an explicit `--lang` for unusual extensions
                      (`.java.bak`, `.pyx`, …) plus config-evidence scanning
                      (hybrid X25519Kyber768Draft00 TLS groups, classical
                      ECDHE-RSA cipher suites) for infra configs.
  6. Dependency /   — manifest parsing (deps.py) for crypto-library declarations
     Key-material     and PEM header + OID sniffing (keyfiles.py).

Every finding is normalized into the shared evidence model (evidence.py: stable
fingerprints, confidence tiers, provenance) and then enriched with NIST metadata
(FIPS 203/204/205/206) and a code snippet (±N lines) by scan_directory(), which
also computes the compliance matrix via compliance.py.

Returns: {"findings": [...], "compliance": {...},
          "engine": "semgrep+ast+dataflow-py+dataflow-java+aux+deps+keyfiles",
          "diagnostics": {parser failures, files analyzed, unresolved values},
          "engine_disagreements": [...]}
"""

import ast
import json
import logging
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading

import compliance
import dataflow_java
import dataflow_python
import deps
import evidence
import keyfiles

RULES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules.yaml")

# ---------------------------------------------------------------------------
# Semgrep engine
# ---------------------------------------------------------------------------


def find_semgrep_binary() -> str | None:
    """Locate the semgrep executable. Checks PATH first, then the directory of
    the running interpreter, so `venv/bin/python cipher_cli.py ...` uses the
    AST-based semgrep engine even when the virtualenv is not activated."""
    found = shutil.which("semgrep")
    if found:
        return found
    bindir = os.path.dirname(sys.executable)
    for candidate in (os.path.join(bindir, "semgrep"),
                      os.path.join(bindir, "semgrep.exe")):
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


_SEMGREP_PREFIX_CACHE: list[str] | None = None
_SEMGREP_CHECKED = False
_SEMGREP_LAUNCHER_PATH: str | None = None
_SEMGREP_LOCK = threading.Lock()


def _probe_semgrep(prefix: list[str]) -> bool:
    """Return True if the given argv prefix actually runs semgrep."""
    try:
        probe = subprocess.run(prefix + ["--version"],
                               capture_output=True, text=True, timeout=90)
        return probe.returncode == 0 and bool(probe.stdout.strip())
    except Exception:
        return False


def _self_healing_launcher() -> str | None:
    """Generate a private semgrep launcher script.

    Copied virtualenvs ship console scripts whose shebang points at the OLD
    python path ("no such file"). The package itself imports fine, so we write
    a tiny launcher that calls pysemgrep's main() in-process. mkstemp gives a
    unique, not-yet-existing path (no shared-file race / symlink-replacement
    window in the world-writable temp dir); chmod 700 keeps it private.
    Returns the launcher path, or None if writing it failed.
    """
    global _SEMGREP_LAUNCHER_PATH
    if _SEMGREP_LAUNCHER_PATH:
        return _SEMGREP_LAUNCHER_PATH
    try:
        fd, launcher = tempfile.mkstemp(prefix="piquachu-semgrep-", suffix=".py")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(
                "import sys\n"
                "from semgrep.console_scripts.pysemgrep import main\n"
                "if __name__ == '__main__':\n"
                "    sys.argv[0] = 'semgrep'\n"
                "    sys.exit(main())\n"
            )
        os.chmod(launcher, 0o700)
        _SEMGREP_LAUNCHER_PATH = launcher
        return launcher
    except Exception as exc:
        logging.warning(f"could not create semgrep launcher: {exc}")
        return None


def semgrep_prefix() -> list[str] | None:
    """Return the argv prefix that *actually executes* semgrep, or None.

    Verifies the candidate with `--version` so a stale venv console script
    (e.g. a copied venv whose shebang points at a deleted path) never silently
    degrades a scan to the Python-only fallback engine. The self-healing
    launcher is only generated if the installed console script is broken.

    Thread-safe: the probe can take ~2s, and background scan jobs run
    concurrently with API requests, so the cache is only marked populated
    *after* the result is stored (a previous version set the flag first, which
    made concurrent callers observe a None cache mid-probe).
    """
    global _SEMGREP_PREFIX_CACHE, _SEMGREP_CHECKED
    with _SEMGREP_LOCK:
        if _SEMGREP_CHECKED:
            return _SEMGREP_PREFIX_CACHE

        binary = find_semgrep_binary()
        if binary and _probe_semgrep([binary]):
            _SEMGREP_PREFIX_CACHE = [binary]
        else:
            launcher = _self_healing_launcher()
            if launcher and _probe_semgrep([sys.executable, launcher]):
                _SEMGREP_PREFIX_CACHE = [sys.executable, launcher]
        _SEMGREP_CHECKED = True
        return _SEMGREP_PREFIX_CACHE


def _run_semgrep(command: list[str], timeout: int = 90) -> dict:
    """Execute a semgrep invocation and parse JSON results into raw findings.

    Rule ids are canonicalized here: semgrep namespaces `check_id` with the
    dot-joined path of the config file whenever the config lives outside the
    process CWD (e.g. scanning an external repo). Without this, the same site
    was reported twice — once under the namespaced id (semgrep) and once under
    the canonical id (native AST engine) — inflating counts and gate failures.
    """
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        semgrep_output = json.loads(result.stdout)
        findings = []
        metadata = compliance.load_rule_metadata()
        for match in semgrep_output.get("results", []):
            findings.append({
                "file": match.get("path", ""),
                "line": match.get("start", {}).get("line", 0),
                "vulnerability": _resolve_rule_id(match.get("check_id", ""), metadata),
                "recommendation": match.get("extra", {}).get("message", ""),
                "severity": match.get("extra", {}).get("severity", "WARNING"),
            })
        return {"findings": findings}
    except Exception as exc:
        logging.error(f"Semgrep execution failed: {exc}")
        return {"error": f"Scan failed to execute properly: {exc}"}


def run_semgrep_scan(target_directory: str) -> dict:
    """Run Semgrep (AST-based) against a directory. Returns raw findings."""
    prefix = semgrep_prefix()
    if not prefix:
        return {"findings": []}

    command = prefix + [
        "--config", RULES_PATH,
        target_directory,
        "--json",
        "--metrics", "off",
        "--timeout", "30",
    ] + [item for d in _EXCLUDED_DIRS for item in ("--exclude", d)]
    return _run_semgrep(command)


def _resolve_rule_id(check_id: str, metadata: dict) -> str:
    """Map a namespaced check id back to its canonical rule id.

    Semgrep prefixes ids with the config path (dot-joined, e.g.
    ``home.user.repo.backend.weak-crypto-python-md5`` or ``rules.<id>``) when
    the rule file is outside the working directory. Try every dot-suffix,
    longest first, so a rule id that itself contains a dot still resolves;
    unknown ids pass through unchanged (default: never guess).
    """
    if not check_id or check_id in metadata:
        return check_id
    if not metadata:
        return check_id
    parts = check_id.split(".")
    for start in range(1, len(parts)):
        candidate = ".".join(parts[start:])
        if candidate in metadata:
            return candidate
    return check_id


# ---------------------------------------------------------------------------
# Native Python AST engine (zero-dependency semantic layer)
# ---------------------------------------------------------------------------

_PYTHON_EXTS = {".py", ".pyx", ".pxd", ".pyi"}


def _match_aes128(call, aliases) -> bool:
    """AES.new(...) with a statically-known 16-byte key ⇒ AES-128 (Grover-weakened)."""
    if not (_func(call, aliases) == "new" and _in_modules(call, {"Crypto.Cipher.AES", "aes"}, aliases)):
        return False
    for arg in call.args:
        if isinstance(arg, ast.Constant):
            if isinstance(arg.value, bytes) and len(arg.value) == 16:
                return True
            if isinstance(arg.value, str):
                if len(arg.value) == 16:
                    return True
                if len(arg.value) == 32 and re.fullmatch(r"[0-9a-fA-F]{32}", arg.value):
                    return True
    return False


def _pqcrypto_matcher(prefix: str, token: str):
    """pqcrypto.kem.kyber768.keypair(...) / pqcrypto.sign.dilithium3.sign(...)."""
    def matcher(call, aliases) -> bool:
        module = _module(call, aliases)
        if not module.startswith("pqcrypto." + prefix):
            return False
        if token not in module:
            return False
        func = _func(call, aliases)
        return func in {"keypair", "encapsulate", "decapsulate", "sign", "verify"}
    return matcher


# ---------------------------------------------------------------------------
# Classical-misuse matchers (ECB, static IV, static salt, weak RNG, taint)
# ---------------------------------------------------------------------------

# PyCryptodome-style symmetric modules (Crypto.Cipher.AES / DES / DES3 / ARC4).
_SYMMETRIC_MODULES = {"Crypto.Cipher.AES", "Crypto.Cipher.DES", "Crypto.Cipher.DES3",
                      "Crypto.Cipher.ARC4", "aes", "des", "des3", "arc4"}
_MODE_NAMES = {"ECB", "CBC", "CFB", "OFB", "CTR", "GCM", "EAX", "SIV", "OPENPGP"}


def _mode_of(call, aliases: dict | None = None) -> str:
    """Return the cipher mode for `X.new(key, mode, ...)` calls ("ECB", "CBC", …)
    from either a positional Attribute (AES.MODE_CBC), a string ("CBC") or a
    keyword argument (mode=/operation=)."""
    for arg in call.args:
        if isinstance(arg, ast.Attribute) and arg.attr.startswith("MODE_"):
            return arg.attr[5:]
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            if arg.value.upper() in _MODE_NAMES:
                return arg.value.upper()
    for kw in call.keywords or []:
        if kw.arg in ("mode", "operation"):
            v = kw.value
            if isinstance(v, ast.Attribute) and v.attr.startswith("MODE_"):
                return v.attr[5:]
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                return v.value.upper()
    return ""


def _new_in_symmetric_module(call, aliases) -> bool:
    return _func(call, aliases) == "new" and _in_modules(call, _SYMMETRIC_MODULES, aliases)


def _match_ecb(call, aliases) -> bool:
    """AES/DES/DES3.new(..., MODE_ECB) — ECB leaks plaintext structure."""
    return _new_in_symmetric_module(call, aliases) and _mode_of(call, aliases) == "ECB"


def _match_cbc_static_iv(call, aliases) -> bool:
    """CBC mode with a statically-known IV (string/bytes literal) — IV reuse
    and known-plaintext attacks become possible."""
    if not (_new_in_symmetric_module(call, aliases) and _mode_of(call, aliases) == "CBC"):
        return False
    for kw in call.keywords or []:
        if kw.arg in ("iv", "nonce") and isinstance(kw.value, ast.Constant) \
                and isinstance(kw.value.value, (str, bytes)):
            return True
    for arg in call.args[1:]:  # args[0] is the key; the mode string is filtered out
        if isinstance(arg, ast.Constant) and isinstance(arg.value, (str, bytes)):
            if isinstance(arg.value, str) and arg.value.upper() in _MODE_NAMES:
                continue
            return True
    return False


def _match_static_salt(call, aliases) -> bool:
    """KDF called with a constant salt: hashlib.pbkdf2_hmac / hashlib.scrypt /
    cryptography PBKDF2HMAC — weakens password derivation."""
    func = _func(call, aliases)
    module = _module(call, aliases)
    if func in ("pbkdf2_hmac", "scrypt") and _in_modules(call, {"hashlib"}, aliases):
        salt_args = list(call.args[2:])  # (name, password, salt, ...)
        for kw in call.keywords or []:
            if kw.arg == "salt":
                salt_args.append(kw.value)
        return any(isinstance(a, ast.Constant) and isinstance(a.value, (str, bytes))
                   for a in salt_args)
    if func == "PBKDF2HMAC" and "kdf" in module.lower():
        for kw in call.keywords or []:
            if kw.arg == "salt" and isinstance(kw.value, ast.Constant) \
                    and isinstance(kw.value.value, (str, bytes)):
                return True
    return False


_RANDOM_FUNCS = {"random", "randint", "randrange", "choice", "choices", "sample",
                 "uniform", "seed", "getrandbits", "randbytes"}


def _is_random_call(call, aliases) -> bool:
    """True for calls into the stdlib `random` module (crypto-insecure RNG)."""
    return _module(call, aliases) == "random" and _func(call, aliases) in _RANDOM_FUNCS


# rule_id -> matcher. Matchers receive (ast.Call node, alias map) and return bool.
_PYTHON_RULES = [
    ("weak-crypto-python-md5",
     lambda c, a: (_func(c, a) == "md5" and _in_modules(c, {"hashlib"}, a))
                  or (_func(c, a) == "MD5" and _in_modules(c, {"hashes"}, a))),
    ("weak-crypto-python-sha1",
     lambda c, a: (_func(c, a) == "sha1" and _in_modules(c, {"hashlib"}, a))
                  or (_func(c, a) == "SHA1" and _in_modules(c, {"hashes"}, a))),
    ("deprecated-rsa-python-cryptography",
     lambda c, a: _func(c, a) == "generate_private_key" and _in_modules(c, {"rsa"}, a)),
    ("deprecated-ecdh-python-cryptography",
     lambda c, a: (_func(c, a) == "generate_private_key" and _in_modules(c, {"ec", "x25519"}, a))
                  or _func(c, a) == "ECDH"
                  or (_func(c, a) in {"generate", "exchange"}
                      and "x25519" in _module(c, a).lower())
                  or "x25519privatekey" in "".join(_parts(c, a)).lower()),
    ("deprecated-ecdsa-python-cryptography",
     lambda c, a: _func(c, a) == "ECDSA" or _func(c, a) in {"Ed25519PrivateKey", "Ed448PrivateKey"}),
    ("deprecated-des-python",
     lambda c, a: _func(c, a) == "new" and _in_modules(c, {"Crypto.Cipher.DES", "Crypto.Cipher.DES3",
                                                           "des", "des3"}, a)),
    ("deprecated-rc4-python",
     lambda c, a: _func(c, a) == "new" and _in_modules(c, {"Crypto.Cipher.ARC4", "ARC4"}, a)),
    ("deprecated-tlsv1-python",
     lambda c, a: any("TLSv1" in i or "SSLv3" in i for i in _arg_identifiers(c))),
    ("deprecated-aes128-python", _match_aes128),
    ("pqc-mlkem-python",
     lambda c, a: _func(c, a) == "KeyEncapsulation" and _in_modules(c, {"oqs"}, a)
                  and _string_contains(c, ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
                                           "Kyber512", "Kyber768", "Kyber1024"])),
    ("pqc-mldsa-python",
     lambda c, a: _func(c, a) == "Signature" and _in_modules(c, {"oqs"}, a)
                  and _string_contains(c, ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
                                           "Dilithium2", "Dilithium3", "Dilithium5"])),
    ("pqc-slhdsa-python",
     lambda c, a: _func(c, a) == "Signature" and _in_modules(c, {"oqs"}, a)
                  and _string_contains(c, ["SLH-DSA", "Sphincs", "SPHINCS"])),
    ("pqc-mlkem-python-cryptography",
     lambda c, a: _func(c, a) in {"MLKEM768", "MLKEM1024", "X25519MLKEM768"}),
    ("pqc-mlkem-python-pqcrypto", _pqcrypto_matcher("kem", "kyber")),
    ("pqc-mldsa-python-pqcrypto", _pqcrypto_matcher("sign", "dilithium")),
    ("pqc-slhdsa-python-pqcrypto", _pqcrypto_matcher("sign", "sphincs")),
    ("pqc-fndsa-python",
     lambda c, a: _func(c, a) == "Signature" and _in_modules(c, {"oqs"}, a)
                  and _string_contains(c, ["FN-DSA-512", "FN-DSA-1024",
                                           "Falcon-512", "Falcon-1024",
                                           "Falcon512", "Falcon1024"])),
    ("pqc-fndsa-python-pqcrypto", _pqcrypto_matcher("sign", "falcon")),
    ("deprecated-ecb-python", _match_ecb),
    ("deprecated-cbc-static-iv-python", _match_cbc_static_iv),
    ("deprecated-static-salt-python", _match_static_salt),
    ("weak-randomness-python",
     lambda c, a: _func(c, a) == "seed" and _module(c, a) == "random"),
]


# Messages mirrored from rules.yaml for the AST engine.
_PYTHON_MESSAGES = {
    "weak-crypto-python-md5": "PQC compliance (FIPS 202): MD5 is broken for collision resistance. Migrate to SHA-256 (FIPS 180-4) or SHA-3 (FIPS 202).",
    "weak-crypto-python-sha1": "PQC compliance (FIPS 202): SHA-1 is broken and not quantum-resistant. Migrate to SHA-256 or SHA-3 (FIPS 202).",
    "deprecated-rsa-python-cryptography": "PQC compliance (FIPS 203): RSA key generation will be broken by Shor's algorithm. Migrate to ML-KEM (Kyber).",
    "deprecated-ecdh-python-cryptography": "PQC compliance (FIPS 203): ECDH/X25519 key agreement broken by Shor's algorithm. Migrate to ML-KEM (hybrid X25519MLKEM768).",
    "deprecated-ecdsa-python-cryptography": "PQC compliance (FIPS 204): ECDSA/EdDSA signatures broken by Shor's algorithm. Migrate to ML-DSA or SLH-DSA.",
    "deprecated-des-python": "PQC compliance (Advisory): DES/3DES is broken. Migrate to AES-256-GCM.",
    "deprecated-rc4-python": "PQC compliance (Advisory): RC4 is broken. Migrate to AES-256-GCM.",
    "deprecated-tlsv1-python": "PQC compliance (Advisory): TLS 1.0/1.1 deprecated. Upgrade to TLS 1.3 with ML-KEM hybrid key exchange.",
    "deprecated-aes128-python": "PQC compliance (Advisory): AES-128 is weakened by Grover's algorithm (64-bit effective quantum security). Migrate to AES-256-GCM.",
    "hardcoded-secret-python": "PQC compliance (Secrets hygiene): hardcoded cryptographic secret/credential detected. Move to a secrets manager / environment variables.",
    "semantic-naive-rsa-python": "PQC compliance (FIPS 203): textbook/toy RSA implementation detected (modular exponentiation key scheme). Migrate to a vetted ML-KEM implementation.",
    "pqc-mlkem-python": "PQC algorithm evidence (FIPS 203): ML-KEM (Kyber) key encapsulation detected.",
    "pqc-mldsa-python": "PQC algorithm evidence (FIPS 204): ML-DSA (Dilithium) digital signatures detected.",
    "pqc-slhdsa-python": "PQC algorithm evidence (FIPS 205): SLH-DSA (SPHINCS+) signatures detected.",
    "pqc-mlkem-python-cryptography": "PQC algorithm evidence (FIPS 203): ML-KEM usage detected (incl. X25519MLKEM768 hybrid).",
    "pqc-mlkem-python-pqcrypto": "PQC algorithm evidence (FIPS 203): ML-KEM (Kyber) detected via the pqcrypto package.",
    "pqc-mldsa-python-pqcrypto": "PQC algorithm evidence (FIPS 204): ML-DSA (Dilithium) detected via the pqcrypto package.",
    "pqc-slhdsa-python-pqcrypto": "PQC algorithm evidence (FIPS 205): SLH-DSA (SPHINCS+) detected via the pqcrypto package.",
    "pqc-fndsa-python": "FN-DSA (FALCON) algorithm evidence detected via liboqs (FIPS 206 is still in development — not a finalized pass).",
    "pqc-fndsa-python-pqcrypto": "FN-DSA (FALCON) algorithm evidence detected via the pqcrypto package (FIPS 206 is still in development — not a finalized pass).",
    "deprecated-ecb-python": "PQC compliance (Advisory): ECB mode leaks plaintext structure (identical blocks encrypt identically). Use AES-256-GCM authenticated encryption.",
    "deprecated-cbc-static-iv-python": "PQC compliance (Advisory): CBC mode with a static/predictable IV enables IV-reuse and known-plaintext attacks. Use AES-256-GCM with a fresh random nonce per message.",
    "deprecated-static-salt-python": "PQC compliance (Advisory): KDF called with a static salt weakens password derivation. Use a fresh random salt per credential (secrets.token_bytes(16)).",
    "weak-randomness-python": "PQC compliance (Advisory): insecure randomness (random module) used for cryptographic key/IV material — predictable keys. Use secrets.token_bytes / os.urandom.",
    "taint-secret-weak-algorithm-python": "PQC compliance (Secrets hygiene): a secret/private-key value flows into a weak algorithm call. Fix the algorithm AND rotate the affected secret.",
}

_SEVERITY_MAP = {
    "weak-crypto-python-md5": "WARNING", "weak-crypto-python-sha1": "WARNING",
    "deprecated-rsa-python-cryptography": "ERROR", "deprecated-ecdh-python-cryptography": "ERROR",
    "deprecated-ecdsa-python-cryptography": "ERROR", "deprecated-des-python": "ERROR",
    "deprecated-rc4-python": "ERROR", "deprecated-tlsv1-python": "WARNING",
    "deprecated-aes128-python": "WARNING", "hardcoded-secret-python": "WARNING",
    "semantic-naive-rsa-python": "ERROR",
    "pqc-mlkem-python": "INFO", "pqc-mldsa-python": "INFO",
    "pqc-slhdsa-python": "INFO", "pqc-mlkem-python-cryptography": "INFO",
    "pqc-mlkem-python-pqcrypto": "INFO", "pqc-mldsa-python-pqcrypto": "INFO",
    "pqc-slhdsa-python-pqcrypto": "INFO", "pqc-fndsa-python": "INFO",
    "pqc-fndsa-python-pqcrypto": "INFO",
    "deprecated-ecb-python": "ERROR", "deprecated-cbc-static-iv-python": "ERROR",
    "deprecated-static-salt-python": "WARNING", "weak-randomness-python": "ERROR",
    "taint-secret-weak-algorithm-python": "ERROR",
}

# Function names that identify a modular-exponentiation implementation (toy RSA).
_MODEXP_NAMES = {"modexp", "mod_pow", "pow_mod", "modular_pow", "modpow",
                 "modular_exponentiation", "fast_pow", "modexp_mod"}

# Assignment targets that look like cryptographic secrets.
_SECRET_NAMES = {"key", "secret", "password", "passwd", "pwd", "api_key",
                 "apikey", "token", "auth_token", "access_token", "private_key",
                 "psk", "pre_shared_key", "nonce", "master_key", "signing_key",
                 "secret_key", "client_secret", "iv"}


def _parts(call, aliases: dict | None = None) -> list:
    """Dotted chain of the call target, outermost first, with import aliases
    resolved to their canonical module path.
    hashlib.md5(...) -> ['hashlib', 'md5']
    pq_rsa.generate_private_key(...) with `import rsa as pq_rsa` -> ['rsa', 'generate_private_key']"""
    parts = []
    node = call.func
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    parts = list(reversed(parts))
    if aliases and parts:
        head = parts[0]
        if head in aliases:
            return aliases[head].split(".") + parts[1:]
    return parts


def _func(call, aliases: dict | None = None) -> str:
    parts = _parts(call, aliases)
    return parts[-1] if parts else ""


def _module(call, aliases: dict | None = None) -> str:
    parts = _parts(call, aliases)
    return ".".join(parts[:-1]) if len(parts) > 1 else ""


def _in_modules(call, modules, aliases: dict | None = None) -> bool:
    """True if the call's dotted module path matches any module (exact or
    trailing, so fully-qualified imports are caught too)."""
    module = _module(call, aliases)
    return module in modules or any(module.endswith("." + m) for m in modules)


def _arg_identifiers(call) -> list:
    ids = []
    for arg in call.args:
        if isinstance(arg, ast.Attribute):
            ids.append(arg.attr)
        elif isinstance(arg, ast.Name):
            ids.append(arg.id)
        elif isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            ids.append(arg.value)
    return ids


def _string_contains(call, needles) -> bool:
    for arg in call.args:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            if any(n in arg.value for n in needles):
                return True
    return False


class _CryptoVisitor(ast.NodeVisitor):
    """Walks the Python AST and records cryptographic call sites + semantic
    patterns (hardcoded secrets, toy RSA, AES-128 key length)."""

    def __init__(self, file_path):
        self.file_path = file_path
        self.findings = []
        self._seen = set()
        self.aliases: dict[str, str] = {}
        self._func_stack: list[str] = []
        self._tainted: set[str] = set()
        self._static_consts: set[str] = set()

    def collect_aliases(self, tree) -> None:
        """Resolve `import x as y` / `from m import n as y` bindings so rules
        match through aliasing (a common detection-evasion pattern)."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.name
                    if alias.asname:
                        self.aliases[alias.asname] = name
                    else:
                        self.aliases[name.split(".")[0]] = name
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    canonical = f"{mod}.{alias.name}" if mod else alias.name
                    if alias.asname:
                        self.aliases[alias.asname] = canonical
                    else:
                        self.aliases[alias.name] = canonical

    def _add(self, rule_id: str, line: int) -> None:
        key = (rule_id, line)
        if key in self._seen:
            return
        self._seen.add(key)
        self.findings.append({
            "file": self.file_path,
            "line": line,
            "vulnerability": rule_id,
            "recommendation": _PYTHON_MESSAGES.get(rule_id, rule_id),
            "severity": _SEVERITY_MAP.get(rule_id, "WARNING"),
        })

    def visit_FunctionDef(self, node):
        self._func_stack.append(node.name)
        # Secret-typed parameters taint the function body (scope-restored on exit).
        saved = set(self._tainted)
        for arg in node.args.posonlyargs + node.args.args + node.args.kwonlyargs:
            if arg.arg.lower() in _SECRET_NAMES:
                self._tainted.add(arg.arg)
        self.generic_visit(node)
        self._tainted = saved
        self._func_stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def _check_taint(self, node: ast.Call) -> None:
        """Flag when a secret value flows into a weak-algorithm call.
        KDF/CBC/randomness findings are exempt: the algorithm itself is not
        quantum-broken (the misuse is the salt/IV/RNG choice)."""
        for arg in list(node.args) + [kw.value for kw in (node.keywords or [])]:
            if isinstance(arg, ast.Name) and arg.id in self._tainted:
                self._add("taint-secret-weak-algorithm-python", getattr(node, "lineno", 0))
                return

    def visit_Assign(self, node):
        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue
            name = target.id.lower()
            if name not in _SECRET_NAMES:
                continue
            value = node.value
            # Hardcoded secret literal.
            if isinstance(value, ast.Constant) and isinstance(value.value, (str, bytes)):
                if len(value.value) >= 8 and not (isinstance(value.value, str) and value.value.startswith("env:")):
                    self._add("hardcoded-secret-python", getattr(node, "lineno", 0))
                    break
            # Crypto key/IV material drawn from the insecure `random` module.
            if isinstance(value, ast.Call) and _is_random_call(value, self.aliases):
                self._add("weak-randomness-python", getattr(node, "lineno", 0))
            # Taint propagation: secret names + copies of tainted values.
            self._tainted.add(target.id)
            if isinstance(value, ast.Name) and value.id in self._tainted:
                self._tainted.add(target.id)
        # Track statically-assigned constants (e.g. `iv = b"..."`) so CBC calls
        # that pass a constant IV *by variable* are still caught.
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, (str, bytes)):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self._static_consts.add(target.id)
        self.generic_visit(node)

    def visit_While(self, node):
        # Textbook RSA modexp loop: `while exp > 0: ... result = (result * base) % mod`
        if self._func_stack and self._func_stack[-1].lower() in _MODEXP_NAMES:
            if self._has_modulo(node.body):
                self._add("semantic-naive-rsa-python", getattr(node, "lineno", 0))
        self.generic_visit(node)

    @staticmethod
    def _has_modulo(stmts) -> bool:
        for stmt in stmts:
            for sub in ast.walk(stmt):
                if isinstance(sub, ast.BinOp) and isinstance(sub.op, ast.Mod):
                    return True
        return False

    def visit_Call(self, node):
        # toy-RSA keygen: d = pow(e, -1, phi)
        if _func(node, self.aliases) == "pow" and len(node.args) == 3:
            second = node.args[1]
            third = node.args[2]
            if (isinstance(second, ast.UnaryOp) and isinstance(second.op, ast.USub)
                    and isinstance(second.operand, ast.Constant) and second.operand.value == 1
                    and isinstance(third, ast.Name) and third.id.lower() in
                    {"phi", "totient", "phin", "n", "lambda_n"}):
                self._add("semantic-naive-rsa-python", getattr(node, "lineno", 0))

        # CBC mode with an IV assigned from a constant (stored in a variable).
        if (_new_in_symmetric_module(node, self.aliases)
                and _mode_of(node, self.aliases) == "CBC"):
            args = list(node.args) + [kw.value for kw in (node.keywords or [])]
            if any(isinstance(a, ast.Name) and a.id in self._static_consts for a in args):
                self._add("deprecated-cbc-static-iv-python", getattr(node, "lineno", 0))

        matched = None
        for rule_id, matcher in _PYTHON_RULES:
            try:
                if matcher(node, self.aliases):
                    self._add(rule_id, getattr(node, "lineno", 0))
                    matched = rule_id
                    break
            except Exception:
                continue
        # Secret value reaching a legacy (non-compliant) crypto call → taint finding.
        # Exempt misuse rules whose algorithm is not itself quantum-broken.
        _TAINT_EXEMPT = {"deprecated-static-salt-python", "deprecated-cbc-static-iv-python",
                         "weak-randomness-python", "deprecated-aes128-python",
                         "deprecated-tlsv1-python", "hardcoded-secret-python"}
        if matched and matched not in _TAINT_EXEMPT \
                and not _PYTHON_MESSAGES.get(matched, "").startswith("PQC compliant"):
            self._check_taint(node)
        self.generic_visit(node)


# Dependency / build directories never scanned (vendor code is not the target).
_EXCLUDED_DIRS = {"venv", ".venv", "node_modules", ".git", "dist", "build",
                  "__pycache__", "site-packages", "target",
                  ".piquachu-backups", ".piquachu-patches"}


def run_python_ast_scan(target_directory: str) -> list:
    """Walk all Python-family files (.py/.pyx/.pxd/.pyi) with the built-in ast
    module and return raw findings (semantic layer)."""
    findings = []
    for root, dirs, files in os.walk(target_directory):
        dirs[:] = [d for d in dirs if d not in _EXCLUDED_DIRS]
        for name in files:
            if os.path.splitext(name)[1].lower() not in _PYTHON_EXTS:
                continue
            path = os.path.join(root, name)
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    tree = ast.parse(fh.read(), filename=path)
                visitor = _CryptoVisitor(path)
                visitor.collect_aliases(tree)
                visitor.visit(tree)
                findings.extend(visitor.findings)
            except (SyntaxError, UnicodeDecodeError, OSError):
                continue
    return findings


# ---------------------------------------------------------------------------
# Auxiliary scanner — unusual extensions + infra config evidence
# ---------------------------------------------------------------------------

# Unusual extensions that semgrep won't auto-detect → explicit --lang passthrough.
_UNUSUAL_LANG_MAP = {
    ".java.bak": "java", ".java.old": "java", ".java.orig": "java",
    ".js.bak": "javascript", ".ts.bak": "typescript",
    ".go.bak": "go", ".c.bak": "c", ".cpp.bak": "cpp", ".cc.bak": "cpp",
    ".rs.bak": "rust", ".php.bak": "php",
}

# Minified bundles: semgrep silently skips `*.min.js` files during directory
# discovery, so they are scanned here with explicit file args (--lang passthrough).
_MINIFIED_LANG_MAP = {
    ".min.js": "javascript", ".min.jsx": "javascript", ".min.mjs": "javascript",
    ".min.cjs": "javascript", ".min.ts": "typescript",
}
# Size cap for minified bundles (huge generated files are not the target).
_MAX_MINIFIED_BYTES = 2 * 1024 * 1024

# Infra config files worth scanning for transport-level PQC evidence.
_CONFIG_NAMES = {"nginx.conf", "ssl.conf", "haproxy.cfg", "openssl.cnf", "httpd.conf",
                 "sshd_config", "ssh_config"}
_CONFIG_EXTS = {".conf", ".yaml", ".yml", ".ini", ".cfg", ".toml", ".properties"}

# TLS hybrid groups (NIST / Chrome / Cloudflare drafts) — same surface as
# network flow analyzers (e.g. CipherIQ/pqc-flow) but from config evidence.
_TLS_HYBRID_TOKENS = ("X25519Kyber768Draft00", "X25519MLKEM768", "X25519MLKEM1024",
                      "X25519Kyber768", "X25519Kyber1024", "P-256+ML-KEM-768")
# OpenSSH hybrid key-exchange algorithms (OpenSSH 9.0+, RFC drafts).
_SSH_HYBRID_TOKENS = ("sntrup761x25519-sha512@openssh.com", "mlkem768x25519-sha256",
                      "mlkem1024x25519-sha512", "sntrup761x25519")
_CLASSICAL_CIPHER_RE = re.compile(r"(ECDHE-RSA|DHE-RSA|ECDH-RSA|kEECDH|kEDH)", re.I)


def run_aux_scan(target_directory: str) -> list:
    """Scan unusual-extension code files (explicit --lang semgrep) and infra
    configs (hybrid TLS group + classical cipher-suite evidence)."""
    findings = []

    # 1) Unusual-extension / minified code files, grouped by inferred language.
    prefix = semgrep_prefix()
    groups: dict[str, list[str]] = {}
    for root, dirs, files in os.walk(target_directory):
        dirs[:] = [d for d in dirs if d not in _EXCLUDED_DIRS]
        for name in files:
            lower = name.lower()
            matched = False
            for suffix, lang in _UNUSUAL_LANG_MAP.items():
                if lower.endswith(suffix):
                    groups.setdefault(lang, []).append(os.path.join(root, name))
                    matched = True
                    break
            if matched:
                continue
            for suffix, lang in _MINIFIED_LANG_MAP.items():
                if lower.endswith(suffix):
                    path = os.path.join(root, name)
                    try:
                        if os.path.getsize(path) > _MAX_MINIFIED_BYTES:
                            continue
                    except OSError:
                        continue
                    groups.setdefault(lang, []).append(path)
                    break

    if prefix and groups:
        for lang, files in groups.items():
            command = prefix + [
                "--config", RULES_PATH,
                "--lang", lang,
                "--json", "--metrics", "off", "--timeout", "30",
            ] + files
            res = _run_semgrep(command, timeout=180)
            findings.extend(res.get("findings", []))

    # 2) Config evidence.
    for root, dirs, files in os.walk(target_directory):
        dirs[:] = [d for d in dirs if d not in _EXCLUDED_DIRS]
        for name in files:
            if name not in _CONFIG_NAMES and os.path.splitext(name)[1].lower() not in _CONFIG_EXTS:
                continue
            path = os.path.join(root, name)
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    for lineno, line in enumerate(fh, 1):
                        if any(tok in line for tok in _TLS_HYBRID_TOKENS):
                            findings.append({
                                "file": path, "line": lineno,
                                "vulnerability": "pqc-hybrid-tls-config",
                                "recommendation": "PQC hybrid (FIPS 203): hybrid TLS group "
                                                  "(X25519+ML-KEM/Kyber) detected — transitional "
                                                  "PQC key exchange in transport config.",
                                "severity": "INFO",
                            })
                        if any(tok in line for tok in _SSH_HYBRID_TOKENS):
                            findings.append({
                                "file": path, "line": lineno,
                                "vulnerability": "pqc-hybrid-ssh-kex-config",
                                "recommendation": "PQC hybrid (FIPS 203): OpenSSH hybrid KEX "
                                                  "(sntrup761x25519 / mlkem768x25519) detected — "
                                                  "transitional PQC key exchange in SSH config.",
                                "severity": "INFO",
                            })
                        if ("kexalgorithms" in line.lower()
                                and "curve25519-sha256" in line
                                and not any(tok in line for tok in _SSH_HYBRID_TOKENS)):
                            findings.append({
                                "file": path, "line": lineno,
                                "vulnerability": "deprecated-ssh-kex-config",
                                "recommendation": "PQC compliance (Advisory): SSH config advertises "
                                                  "classical-only key exchange. Enable OpenSSH hybrid "
                                                  "KEX (sntrup761x25519 / mlkem768x25519).",
                                "severity": "WARNING",
                            })
                        if ("ssl-ciphers" in line.lower() or "ssl_ciphers" in line.lower()) \
                                and _CLASSICAL_CIPHER_RE.search(line):
                            findings.append({
                                "file": path, "line": lineno,
                                "vulnerability": "deprecated-tls-ciphers-config",
                                "recommendation": "PQC compliance (Advisory): TLS config advertises "
                                                  "classical ECDHE-RSA/DHE-RSA cipher suites. Enable "
                                                  "TLS 1.3 with X25519MLKEM768 hybrid groups.",
                                "severity": "WARNING",
                            })
                        if ("ssl_protocols" in line.lower() or "ssl-protocols" in line.lower()
                                or "tls_versions" in line.lower()) \
                                and re.search(r"(TLSv1\b|TLSv1\.1|SSLv3)", line):
                            findings.append({
                                "file": path, "line": lineno,
                                "vulnerability": "deprecated-tls-protocols-config",
                                "recommendation": "PQC compliance (Advisory): TLS config enables deprecated "
                                                  "protocols (TLS 1.0/1.1/SSLv3). Restrict to TLS 1.2+ and prefer "
                                                  "TLS 1.3 with X25519MLKEM768 hybrid groups.",
                                "severity": "WARNING",
                            })
            except OSError:
                continue
    return findings


# ---------------------------------------------------------------------------
# Archive extraction hardening (zip-slip / symlink / bomb defenses)
# ---------------------------------------------------------------------------

class ZipExtractionError(Exception):
    """Raised when an archive violates extraction safety policies."""


# Per-file / ratio defaults for the API. A single highly compressible source
# file under 1 MiB is exempt from the ratio check so legitimate generated code
# is not rejected while a 10 MiB->20 KiB bomb still is.
MAX_FILE_BYTES = 25 * 1024 * 1024
MAX_COMPRESSION_RATIO = 200
_RATIO_MIN_BYTES = 1024 * 1024

# Archives inside the archive are extracted as opaque files and never expanded.
NESTED_ARCHIVE_SUFFIXES = (".zip", ".jar", ".war", ".ear", ".tar", ".gz",
                           ".tgz", ".bz2", ".xz", ".7z", ".rar")


def _safe_entry_name(name: str) -> str:
    """Normalize + validate one archive member name; returns the normalized path.

    Rejects: NUL/control characters, absolute paths, drive letters, Windows
    alternate data streams, traversal segments and empty names. Backslashes are
    normalized first so `..\\x` cannot slip through as a POSIX filename.
    """
    if not name:
        raise ZipExtractionError("Archive contains an entry with an empty name.")
    if "\x00" in name:
        raise ZipExtractionError(f"NUL byte in archive entry name: {name!r}")
    if any(ord(ch) < 32 for ch in name):
        raise ZipExtractionError(f"Control character in archive entry name: {name!r}")
    forward = name.replace("\\", "/")
    if forward.startswith("/"):
        raise ZipExtractionError(f"Absolute path in archive not allowed: {name}")
    if len(forward) > 1 and forward[1] == ":" and forward[0].isalpha():
        raise ZipExtractionError(f"Drive-letter path in archive not allowed: {name}")
    if ":" in forward:
        raise ZipExtractionError(f"Alternate-data-stream path not allowed: {name}")
    segments = forward.split("/")
    if ".." in segments:
        raise ZipExtractionError(f"Path traversal in archive not allowed: {name}")
    normalized = "/".join(seg for seg in segments if seg not in ("", "."))
    if not normalized:
        raise ZipExtractionError(f"Archive entry resolves to an empty path: {name}")
    return normalized


def validate_zip_entries(zip_ref, max_entries: int | None = None,
                         max_bytes: int | None = None, dest_dir: str | None = None,
                         max_file_bytes: int | None = None,
                         max_compression_ratio: int | None = None) -> None:
    """Validate every archive entry against extraction-safety policy WITHOUT
    writing anything (used by the API's synchronous pre-checks):

      * NUL/control characters, absolute paths, drive letters, '..' segments,
        Windows alternate-data-stream names
      * duplicate normalized names and case-fold collisions
      * symlink / device / fifo / socket entries (can escape the root)
      * encrypted entries (no password prompt path)
      * entry-count, total-size, per-file and compression-ratio budgets

    Raises ZipExtractionError on the first offending entry. Nested archives are
    allowed as opaque files but never expanded (see NESTED_ARCHIVE_SUFFIXES).
    """
    entries = zip_ref.infolist()
    if max_entries is not None and len(entries) > max_entries:
        raise ZipExtractionError(f"Archive has {len(entries)} entries (limit {max_entries}).")

    dest_root = os.path.realpath(dest_dir) if dest_dir else None
    total_bytes = 0
    total_compressed = 0
    seen: dict[str, str] = {}
    for info in entries:
        name = info.filename or ""
        normalized = _safe_entry_name(name)
        key = normalized.casefold()
        if key in seen:
            raise ZipExtractionError(
                f"Duplicate normalized archive entry: {name!r} collides with "
                f"{seen[key]!r} (case-insensitive)")
        seen[key] = normalized

        if info.flag_bits & 0x1:
            raise ZipExtractionError(f"Encrypted archive entries are not supported: {name}")

        size = int(info.file_size or 0)
        compressed = int(info.compress_size or 0)
        if size < 0 or compressed < 0:
            raise ZipExtractionError(f"Invalid entry size in archive: {name}")
        if max_file_bytes is not None and size > max_file_bytes:
            raise ZipExtractionError(
                f"Archive entry exceeds per-file budget: {name} "
                f"({size} bytes, limit {max_file_bytes}).")
        if max_compression_ratio is not None and size >= _RATIO_MIN_BYTES:
            ratio = size / compressed if compressed > 0 else float("inf")
            if ratio > max_compression_ratio:
                raise ZipExtractionError(
                    f"Suspicious compression ratio for {name} "
                    f"({ratio:.0f}:1, limit {max_compression_ratio}:1).")

        total_bytes += size
        total_compressed += compressed
        if max_bytes is not None and total_bytes > max_bytes:
            raise ZipExtractionError("Archive exceeds decompressed-size budget.")

        mode = (info.external_attr >> 16) & 0xFFFF
        if (stat.S_ISLNK(mode) or stat.S_ISCHR(mode) or stat.S_ISBLK(mode)
                or stat.S_ISFIFO(mode) or stat.S_ISSOCK(mode)):
            raise ZipExtractionError(f"Special file entry in archive not allowed: {name}")

        if dest_root is not None:
            target = os.path.realpath(os.path.join(dest_root, normalized))
            if target != dest_root and not target.startswith(dest_root + os.sep):
                raise ZipExtractionError(f"Entry escapes extraction root: {name}")

    if (max_compression_ratio is not None and total_bytes >= _RATIO_MIN_BYTES
            and total_compressed > 0
            and (total_bytes / total_compressed) > max_compression_ratio * 2):
        raise ZipExtractionError("Archive total compression ratio exceeds the allowed budget.")


def archive_diagnostics(zip_ref) -> dict:
    """Non-fatal facts about an accepted archive (shown in job logs)."""
    names = [info.filename or "" for info in zip_ref.infolist()]
    nested = [n for n in names
              if n.lower().endswith(NESTED_ARCHIVE_SUFFIXES)][:20]
    return {
        "entries": len(names),
        "nested_archives": nested,
        "nested_archive_count": sum(
            1 for n in names if n.lower().endswith(NESTED_ARCHIVE_SUFFIXES)),
        "note": "Nested archives are stored as opaque files and never expanded.",
    }


def safe_extract_zip(zip_ref, dest_dir: str, max_entries: int | None = None,
                     max_bytes: int | None = None,
                     max_file_bytes: int | None = None,
                     max_compression_ratio: int | None = None) -> None:
    """Validate then extract; nothing is written before validation passes.

    A post-extraction containment check is still performed: it catches a
    platform/library mismatch (e.g. a path resolved differently by the OS) and
    refuses symlinks that appeared after extraction.
    """
    validate_zip_entries(zip_ref, max_entries=max_entries, max_bytes=max_bytes,
                         dest_dir=dest_dir, max_file_bytes=max_file_bytes,
                         max_compression_ratio=max_compression_ratio)
    root = os.path.realpath(dest_dir)
    zip_ref.extractall(dest_dir, members=zip_ref.infolist())
    for current, dirs, files in os.walk(root):
        for name in list(dirs):
            if os.path.islink(os.path.join(current, name)):
                raise ZipExtractionError(f"Symlink created during extraction: {name}")
        for name in files:
            path = os.path.join(current, name)
            if os.path.islink(path):
                raise ZipExtractionError(f"Symlink created during extraction: {name}")
            real = os.path.realpath(path)
            if real != root and not real.startswith(root + os.sep):
                raise ZipExtractionError(f"Extracted file escaped the root: {name}")


def cleanup_stale_upload_dirs(max_age_seconds: int | None = None,
                              prefix: str = "piquachu-upload-") -> list[str]:
    """Remove leftover extraction dirs from crashes/restarts.

    Only directories owned by the current user, matching the API prefix, and
    older than the grace period are touched — never a shared temp entry we do
    not own.
    """
    import time

    age = 6 * 3600 if max_age_seconds is None else max(0, int(max_age_seconds))
    root = tempfile.gettempdir()
    removed: list[str] = []
    try:
        entries = os.listdir(root)
    except OSError:
        return removed
    now = time.time()
    uid = os.getuid() if hasattr(os, "getuid") else None
    for name in entries:
        if not name.startswith(prefix):
            continue
        path = os.path.join(root, name)
        try:
            info = os.lstat(path)
            if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
                continue
            if uid is not None and info.st_uid != uid:
                continue
            if now - info.st_mtime < age:
                continue
            shutil.rmtree(path, ignore_errors=True)
            removed.append(path)
        except OSError:
            continue
    return removed


# ---------------------------------------------------------------------------
# Snippet capture
# ---------------------------------------------------------------------------

# Findings whose source line may BE the secret. Their evidence stays
# metadata-only: a snippet would copy key material / credentials into the DB,
# the API response, the dashboard and any export.
SENSITIVE_SNIPPET_RULES = {
    "hardcoded-secret-python",
    "taint-secret-weak-algorithm-python",
}


def is_sensitive_finding(finding: dict) -> bool:
    rule = str(finding.get("vulnerability") or finding.get("rule_id") or "")
    short = rule.rsplit(".", 1)[-1]
    return (rule.startswith("key-file") or short.startswith("key-file")
            or rule in SENSITIVE_SNIPPET_RULES
            or short in SENSITIVE_SNIPPET_RULES)


# Belt-and-braces for lines the secret rule did not fire on (short values, an
# unusual variable name): a snippet never carries an obvious credential.
_SECRET_LINE_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|apikey|token|private[_-]?key|"
    r"client[_-]?secret|access[_-]?key)\b\s*[:=]\s*['\"][^'\"]{2,}['\"]")


def redact_snippet_line(text: str) -> str:
    if text and _SECRET_LINE_RE.search(text):
        return "<redacted: secret-like assignment>"
    return text


def attach_snippets(findings: list, target_directory: str, context: int = 3) -> None:
    """Attach `snippet` (list of {line, text}) and `line_text` to every finding
    so the dashboard can render expandable, line-pinpointed code cards.

    Key-material and hardcoded-secret findings are deliberately excluded: their
    line text is the secret itself. Those findings keep rule/severity/evidence
    metadata only (no snippet, no value).
    """
    # A file that contains a secret/key finding must not export *any* snippet:
    # a neighbouring finding's 3-line context can contain the secret line.
    sensitive_files = {f.get("file") for f in findings if is_sensitive_finding(f)}
    cache: dict[str, list[str] | None] = {}
    for f in findings:
        path = f.get("file", "")
        if is_sensitive_finding(f) or path in sensitive_files:
            f.pop("snippet", None)
            f.pop("line_text", None)
            continue
        if not path:
            continue
        if path not in cache:
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    cache[path] = fh.read().splitlines()
            except OSError:
                cache[path] = None
        lines = cache[path]
        if not lines:
            continue
        line = f.get("line") or 1
        start = max(0, line - 1 - context)
        end = min(len(lines), line + context)
        f["snippet"] = [{"line": i + 1, "text": redact_snippet_line(lines[i])}
                        for i in range(start, end)]
        if 0 < line <= len(lines):
            f["line_text"] = redact_snippet_line(lines[line - 1])


def _dedupe(findings: list) -> list:
    """Legacy (rule, file, line) dedupe — retained for callers/tests."""
    seen, out = set(), []
    for f in findings:
        key = (f.get("vulnerability"), f.get("file"), f.get("line"))
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


_ENGINE_EVIDENCE = {
    "semgrep": ("ast_api_pattern", "medium"),
    "ast": ("ast_api_pattern", "medium"),
    "aux": ("transport_config", "medium"),
    "deps": ("dependency_advisory", "medium"),
    "keyfiles": ("key_material", "high"),
}


def annotate_engine_findings(findings: list, engine: str,
                            root: str | None = None) -> list:
    """Normalize pattern-engine findings into the shared evidence model.

    Identity uses a hash of the normalized source line (never the snippet), so
    a line shift does not create a new finding; findings without a captured
    line fall back to a line-qualified signature. ``root`` makes the stored
    path root-relative, preserving directory identity across the archive.
    """
    evidence_type, confidence = _ENGINE_EVIDENCE.get(
        engine, ("ast_api_pattern", "medium"))
    out = []
    for f in findings or []:
        if f.get("fingerprint"):  # already annotated by a data-flow engine
            out.append(f)
            continue
        rule_id = f.get("vulnerability") or f.get("rule") or ""
        text = f.get("line_text")
        signature = evidence.text_signature(rule_id, text) if text else \
            f"pattern:{rule_id}|L{f.get('line')}"
        out.append(evidence.annotate(
            f, engine=engine, evidence_type=evidence_type,
            confidence=confidence, evidence_signature=signature,
            sink_description=f"rule:{rule_id}", root=root,
        ))
    return out


# ---------------------------------------------------------------------------
# Entry point shared by app.py / cipher_cli.py
# ---------------------------------------------------------------------------

def scan_directory(target_directory: str, logger=None) -> dict:
    """Full multi-engine scan. `logger` (optional callable(level, message))
    receives human-readable stage events for the live scan console."""
    def _log(level: str, message: str) -> None:
        if logger:
            try:
                logger(level, message)
            except Exception:
                pass

    metadata = compliance.load_rule_metadata()
    _log("info", f"Rules loaded: {len(metadata)} PQC rules (registry-mapped)")

    engine_parts: list[str] = []
    groups: list[tuple[str, list]] = []
    diagnostics: dict = {"parser_failures": {}, "files_analyzed": {},
                         "unresolved_values": {}, "parser_failure_files": [],
                         "engines": {}}
    prefix = semgrep_prefix()

    if prefix:
        _log("info", "Engine 1/6 — semgrep AST scan (all languages)…")
        res = run_semgrep_scan(target_directory)
        if "error" in res:
            _log("warning", f"semgrep failed: {res['error']}")
        else:
            engine_parts.append("semgrep")
            groups.append(("semgrep", res.get("findings", [])))
    else:
        _log("info", "semgrep unavailable — semantic layer will run standalone")

    _log("info", "Engine 2/6 — Python AST semantic scan (aliases, secrets, AES-128, toy-RSA)…")
    ast_findings = run_python_ast_scan(target_directory)
    if ast_findings:
        engine_parts.append("ast")
        groups.append(("ast", ast_findings))
        _log("info", f"AST semantic layer: {len(ast_findings)} finding(s)")

    _log("info", "Engine 3/6 — Python bounded data-flow (constant propagation)…")
    pyflow = dataflow_python.analyze_directory(target_directory, metadata=metadata)
    if pyflow["findings"]:
        engine_parts.append("dataflow-py")
        groups.append(("dataflow-py", pyflow["findings"]))
    _merge_diagnostics(diagnostics, pyflow["diagnostics"])
    _log("info", f"Python data-flow: {len(pyflow['findings'])} finding(s)")

    _log("info", "Engine 4/6 — Java AST/data-flow (javalang, bounded)…")
    javaflow = dataflow_java.analyze_directory(target_directory, metadata=metadata)
    if javaflow["findings"]:
        engine_parts.append("dataflow-java")
        groups.append(("dataflow-java", javaflow["findings"]))
    if javaflow["diagnostics"].get("javalang_available"):
        _merge_diagnostics(diagnostics, javaflow["diagnostics"])
    _log("info", f"Java data-flow: {len(javaflow['findings'])} finding(s)")

    _log("info", "Engine 5/6 — auxiliary scan (unusual extensions + TLS config evidence)…")
    aux_findings = run_aux_scan(target_directory)
    if aux_findings:
        engine_parts.append("aux")
        groups.append(("aux", aux_findings))

    _log("info", "Engine 6/6 — dependency manifests + key-material files…")
    dep_findings = deps.scan_target(target_directory)
    key_findings = keyfiles.scan_target(target_directory)
    if dep_findings:
        engine_parts.append("deps")
        groups.append(("deps", dep_findings))
    if key_findings:
        engine_parts.append("keyfiles")
        groups.append(("keyfiles", key_findings))

    flat = [f for _eng, items in groups for f in items]
    attach_snippets(flat, target_directory)

    annotated: list = []
    for eng, items in groups:
        if eng in ("dataflow-py", "dataflow-java"):
            annotated.extend(items)
        else:
            annotated.extend(annotate_engine_findings(items, eng,
                                                      root=target_directory))

    deduped, disagreements = evidence.reconcile(annotated)
    enriched = [compliance.enrich_finding(dict(f), metadata) for f in deduped]
    matrix = compliance.analyze_compliance(enriched, metadata=metadata)
    engine = "+".join(engine_parts) if engine_parts else "ast"

    _log("info", f"Analysis complete: {len(enriched)} finding(s), score "
                 f"{matrix['pqc_score']}/100, verdict {matrix['verdict']} (engine {engine})")
    return {
        "findings": enriched,
        "compliance": matrix,
        "engine": engine,
        "diagnostics": evidence.summarize_diagnostics(diagnostics),
        "engine_disagreements": disagreements,
    }


def _merge_diagnostics(target: dict, incoming: dict) -> None:
    for key in ("parser_failures", "files_analyzed", "unresolved_values"):
        for lang, count in (incoming.get(key) or {}).items():
            target[key][lang] = target[key].get(lang, 0) + int(count)
    target.setdefault("parser_failure_files", []).extend(
        incoming.get("parser_failure_files", []))
    for name, info in (incoming.get("engines") or {}).items():
        target["engines"][name] = info


def finalize_scan(findings: list, engine: str) -> dict:
    """Compatibility helper: attach NIST metadata + compliance matrix."""
    metadata = compliance.load_rule_metadata()
    for f in findings:
        f["vulnerability"] = _resolve_rule_id(f.get("vulnerability", "") or "", metadata)
    enriched = [compliance.enrich_finding(f, metadata) for f in findings]
    matrix = compliance.analyze_compliance(enriched, metadata=metadata)
    return {"findings": enriched, "compliance": matrix, "engine": engine}
