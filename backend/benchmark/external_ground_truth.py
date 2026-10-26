# backend/benchmark/external_ground_truth.py
"""
external_ground_truth.py — pinned targets + manually reviewed call-site labels
=============================================================================
This module is the *human* half of external validation. Every entry below was
read in the actual source at the pinned commit and classified against the
rubric in ``LABELING_RUBRIC``. It contains only identifiers, locations and
short descriptions — never third-party source, never a checkout path.

Reproduce a target locally (the raw clone stays outside this repository)::

    git clone --depth 1 --branch <ref> <url> /tmp/pqc-ext/<name>
    git -C /tmp/pqc-ext/<name> rev-parse HEAD     # must equal ``commit``

Then::

    cd backend && python -m benchmark.external_eval --target paramiko

Scope discipline
----------------
* Only the directories listed in ``scope`` are scanned; everything else is
  excluded and named in the report.
* Ground truth covers **crypto API call sites and explicit algorithm-selection
  strings**. Pure-Python big-integer DH group implementations
  (``kex_group1/14/16/gex``) and key-material files are *out of the measured
  scope* and are recorded under ``known_blind_spots`` so recall is never
  inflated by an incomplete denominator.
"""

LABELING_RUBRIC = {
    "risk": (
        "Quantum-vulnerable or deprecated cryptography actually selected in "
        "code at this site: RSA/DSA/ECDSA/EdDSA/DH/ECDH/X25519 key generation, "
        "signing or verification; MD5/SHA-1 as a digest for signatures, MACs, "
        "KDFs or fingerprints; DES/3DES/RC4/Blowfish; AES-128; ECB mode; "
        "non-cryptographic randomness used for a secret."
    ),
    "benign": (
        "Cryptography at this site that must NOT be reported as legacy risk: "
        "SHA-256 or stronger digests, HMAC-SHA-256, AES-256 with a "
        "salt/random-derived IV, a CSPRNG (os.urandom / crypto.randomBytes), "
        "a generic helper that does not itself pick an algorithm, or an "
        "algorithm name appearing in a non-crypto string/query."
    ),
    "uncertain": (
        "The algorithm is chosen dynamically from a table the reviewer could "
        "not statically pin down at this site (for example a cipher class "
        "looked up from parsed key-file metadata). Recorded separately; never "
        "scored as TP/FP/FN/TN."
    ),
}

# A finding line may point at any line of a multi-line call expression, so a
# reviewed site matches findings within +/- this many lines on the same file.
# Reviewing a mismatch is still required: the tolerance is documented, not a
# way to hide disagreement (see MATCH_TOLERANCE_NOTE in the report).
MATCH_TOLERANCE_LINES = 2
REVIEWER = "PiQuaChu maintainer review (single reviewer, documented rubric)"
REVIEW_DATE = "2026-10-19"

# ---------------------------------------------------------------------------
# Target A — OWASP Juice Shop (integration target; small crypto surface)
# ---------------------------------------------------------------------------
JUICE_SHOP = {
    "name": "owasp-juice-shop",
    "url": "https://github.com/juice-shop/juice-shop.git",
    "ref": "v17.1.1",
    "commit": "39b46860612990ae18d499a20472172839fe8c77",
    "license": "MIT",
    "languages": ["TypeScript", "JavaScript"],
    "scope": ["."],
    "exclusions": [
        "node_modules", "dist", "build", "coverage", "vendor",
        ".git", "__pycache__", "venv", ".venv", "target", "out",
    ],
    "note": (
        "Integration target with a deliberately small crypto surface; it "
        "exercises discovery on a real Node/TypeScript application. It does "
        "not contain enough crypto for a meaningful PQC recall measurement, "
        "which is exactly why a crypto-dense second target is included."
    ),
    "known_blind_spots": [
        "JWT key material files (encryptionkeys/*) are covered by the "
        "key-material engine, not measured here.",
        "Third-party frontend bundles under node_modules are excluded by the "
        "scanner's default skip list.",
    ],
    "sites": [
        # risk
        {"id": "JS-001", "file": "lib/insecurity.ts", "line": 43,
         "category": "hashing", "observed": "crypto.createHash('md5')",
         "label": "risk", "rationale": "MD5 digest used for password hashes."},
        {"id": "JS-002", "file": "lib/insecurity.ts", "line": 55,
         "category": "randomness", "observed": "Math.random() as a JWT secret",
         "label": "risk",
         "rationale": "Non-cryptographic RNG used to produce a secret; "
                      "predictable."},
        {"id": "JS-003", "file": "lib/insecurity.ts", "line": 56,
         "category": "signature", "observed": "jwt.sign(..., algorithm 'RS256')",
         "label": "risk", "rationale": "RSA signature (quantum-vulnerable)."},
        {"id": "JS-004", "file": "lib/insecurity.ts", "line": 57,
         "category": "signature", "observed": "jws.verify(token, publicKey)",
         "label": "risk", "rationale": "RSA verification with a public key."},
        {"id": "JS-005", "file": "lib/insecurity.ts", "line": 191,
         "category": "signature", "observed": "jwt.verify(token, publicKey)",
         "label": "risk", "rationale": "RSA verification (RS256 token)."},
        {"id": "JS-006", "file": "routes/verify.ts", "line": 115,
         "category": "signature", "observed": "jwt.verify(token, publicKey)",
         "label": "risk", "rationale": "RSA verification (RS256 token)."},
        {"id": "JS-007", "file": "routes/chatbot.ts", "line": 240,
         "category": "signature", "observed": "jwt.verify(token, publicKey)",
         "label": "risk", "rationale": "RSA verification (RS256 token)."},
        {"id": "JS-013", "file": "Gruntfile.js", "line": 77,
         "category": "hashing", "observed": "crypto.createHash('md5')",
         "label": "risk",
         "rationale": "MD5 checksum generation (added during review after the "
                      "first run flagged this line)."},
        # benign
        {"id": "JS-008", "file": "lib/utils.ts", "line": 146,
         "category": "randomness", "observed": "crypto.randomBytes()",
         "label": "benign", "rationale": "CSPRNG."},
        {"id": "JS-009", "file": "lib/insecurity.ts", "line": 44,
         "category": "hashing", "observed": "createHmac('sha256', ...)",
         "label": "benign", "rationale": "HMAC-SHA-256."},
        {"id": "JS-010", "file": "lib/insecurity.ts", "line": 152,
         "category": "hashing", "observed": "createHmac('sha256', ...)",
         "label": "benign", "rationale": "HMAC-SHA-256."},
        {"id": "JS-011", "file": "routes/verify.ts", "line": 89,
         "category": "configuration", "observed": "challenge algorithm 'HS256'",
         "label": "benign",
         "rationale": "Algorithm name in a CTF challenge description, not a "
                      "crypto call site."},
        {"id": "JS-012", "file": "routes/verify.ts", "line": 275,
         "category": "non-crypto", "observed": "'%md5%' SQL LIKE filter",
         "label": "benign",
         "rationale": "The string 'md5' inside a database query — classic "
                      "false-positive bait."},
    ],
}

# ---------------------------------------------------------------------------
# Target B — paramiko (crypto-dense Python library)
# ---------------------------------------------------------------------------
PARAMIKO = {
    "name": "paramiko",
    "url": "https://github.com/paramiko/paramiko.git",
    "ref": "3.5.1",
    "commit": "ed8b09751ff20340332d4b1bb2b10e32aedc57ff",
    "license": "LGPL-2.1",
    "languages": ["Python"],
    "scope": ["paramiko"],
    "exclusions": ["tests/**", "demos/**", "sites/**", "build/**"],
    "note": (
        "Crypto-dense SSH library: classical key exchange, host keys, "
        "signatures, private-key envelope crypto and MAC negotiation."
    ),
    "known_blind_spots": [
        "kex_group1/14/16/gex: custom big-integer Diffie-Hellman and "
        "modular-exponentiation code with no library call site (name/constant "
        "heuristics only).",
        "primes.py group constants (data, not a call site).",
    ],
    "sites": [
        # --- risk ---
        {"id": "PAR-001", "file": "dsskey.py", "line": 121,
         "category": "signature", "observed": "DSA sign with hashes.SHA1()",
         "label": "risk", "rationale": "SHA-1 signature digest + DSA key."},
        {"id": "PAR-002", "file": "dsskey.py", "line": 159,
         "category": "signature", "observed": "DSA verify with hashes.SHA1()",
         "label": "risk", "rationale": "SHA-1 signature digest; ssh-dss."},
        {"id": "PAR-003", "file": "dsskey.py", "line": 211,
         "category": "key-generation",
         "observed": "dsa.generate_private_key(...)",
         "label": "risk", "rationale": "Classical DSA key generation."},
        {"id": "PAR-004", "file": "ecdsakey.py", "line": 222,
         "category": "signature", "observed": "EC private key sign (ECDSA)",
         "label": "risk", "rationale": "ECDSA signature (quantum-vulnerable)."},
        {"id": "PAR-005", "file": "ecdsakey.py", "line": 238,
         "category": "signature", "observed": "EC public key verify (ECDSA)",
         "label": "risk", "rationale": "ECDSA verification."},
        {"id": "PAR-006", "file": "ecdsakey.py", "line": 277,
         "category": "key-generation",
         "observed": "ec.generate_private_key(curve, ...)",
         "label": "risk", "rationale": "NIST-curve key generation."},
        {"id": "PAR-007", "file": "ed25519key.py", "line": 153,
         "category": "signature", "observed": "nacl.signing.SigningKey(...)",
         "label": "risk", "rationale": "Ed25519 signature key."},
        {"id": "PAR-008", "file": "kex_curve25519.py", "line": 30,
         "category": "key-exchange", "observed": "X25519PrivateKey.generate()",
         "label": "risk", "rationale": "Classical ECDH key exchange."},
        {"id": "PAR-009", "file": "kex_curve25519.py", "line": 45,
         "category": "key-exchange", "observed": "X25519PrivateKey.generate()",
         "label": "risk", "rationale": "Classical ECDH key exchange."},
        {"id": "PAR-010", "file": "kex_ecdh_nist.py", "line": 59,
         "category": "key-exchange", "observed": "ec.generate_private_key(...)",
         "label": "risk", "rationale": "NIST-curve ECDH key generation."},
        {"id": "PAR-042", "file": "kex_ecdh_nist.py", "line": 71,
         "category": "key-exchange",
         "observed": "self.P.exchange(ec.ECDH(), self.Q_C)",
         "label": "risk",
         "rationale": "ECDH shared-secret computation (added during review "
                      "after the first run flagged this line)."},
        {"id": "PAR-043", "file": "kex_ecdh_nist.py", "line": 117,
         "category": "key-exchange",
         "observed": "self.P.exchange(ec.ECDH(), self.Q_S)",
         "label": "risk",
         "rationale": "ECDH shared-secret computation (added during review "
                      "after the first run flagged this line)."},
        {"id": "PAR-011", "file": "kex_gss.py", "line": 230,
         "category": "hashing", "observed": "sha1(...).digest()",
         "label": "risk", "rationale": "SHA-1 as the group-exchange hash."},
        {"id": "PAR-012", "file": "kex_gss.py", "line": 269,
         "category": "hashing", "observed": "sha1(...).digest()",
         "label": "risk", "rationale": "SHA-1 as the group-exchange hash."},
        {"id": "PAR-013", "file": "kex_gss.py", "line": 532,
         "category": "hashing", "observed": "sha1(...).digest()",
         "label": "risk", "rationale": "SHA-1 as the group-exchange hash."},
        {"id": "PAR-014", "file": "kex_gss.py", "line": 634,
         "category": "hashing", "observed": "sha1(...).digest()",
         "label": "risk", "rationale": "SHA-1 as the group-exchange hash."},
        {"id": "PAR-015", "file": "pkey.py", "line": 105,
         "category": "symmetric", "observed": "AES-128-CBC envelope entry",
         "label": "risk", "rationale": "AES-128 key envelope (deprecated rule)."},
        {"id": "PAR-016", "file": "pkey.py", "line": 117,
         "category": "symmetric", "observed": "TripleDES (DES-EDE3-CBC) entry",
         "label": "risk", "rationale": "3DES key envelope."},
        {"id": "PAR-017", "file": "pkey.py", "line": 358,
         "category": "hashing", "observed": "md5(self.asbytes()).digest()",
         "label": "risk", "rationale": "MD5 public-key fingerprint."},
        {"id": "PAR-018", "file": "pkey.py", "line": 594,
         "category": "key-derivation",
         "observed": "util.generate_key_bytes(md5, salt, password, keysize)",
         "label": "risk", "rationale": "MD5-based OpenSSH KDF."},
        {"id": "PAR-019", "file": "rsakey.py", "line": 41,
         "category": "signature",
         "observed": "\"ssh-rsa\": hashes.SHA1 (algorithm map)",
         "label": "risk", "rationale": "SHA-1 RSA signature algorithm."},
        {"id": "PAR-020", "file": "rsakey.py", "line": 125,
         "category": "signature",
         "observed": "RSA sign with padding.PKCS1v15()",
         "label": "risk", "rationale": "RSA signature (quantum-vulnerable)."},
        {"id": "PAR-021", "file": "rsakey.py", "line": 154,
         "category": "signature",
         "observed": "RSA verify with padding.PKCS1v15()",
         "label": "risk", "rationale": "RSA verification."},
        {"id": "PAR-022", "file": "rsakey.py", "line": 188,
         "category": "key-generation",
         "observed": "rsa.generate_private_key(public_exponent=65537, ...)",
         "label": "risk", "rationale": "RSA key generation."},
        {"id": "PAR-023", "file": "transport.py", "line": 195,
         "category": "configuration",
         "observed": "preferred MAC list including hmac-sha1 / hmac-md5",
         "label": "risk", "rationale": "SHA-1/MD5 MACs offered."},
        {"id": "PAR-024", "file": "transport.py", "line": 229,
         "category": "key-exchange",
         "observed": "preferred KEX list including diffie-hellman-*-sha1",
         "label": "risk",
         "rationale": "SHAl-based DH group exchange offered by default."},
        {"id": "PAR-025", "file": "transport.py", "line": 236,
         "category": "key-exchange",
         "observed": "GSS key-exchange list including gss-*-sha1",
         "label": "risk", "rationale": "SHA-1 GSS key exchange offered."},
        {"id": "PAR-026", "file": "transport.py", "line": 263,
         "category": "symmetric",
         "observed": "aes128-ctr/cbc entries in _cipher_info",
         "label": "risk", "rationale": "AES-128 session cipher offered."},
        {"id": "PAR-027", "file": "transport.py", "line": 269,
         "category": "symmetric",
         "observed": "aes192 entry in _cipher_info",
         "label": "risk", "rationale": "AES-192 session cipher offered."},
        {"id": "PAR-028", "file": "transport.py", "line": 275,
         "category": "symmetric",
         "observed": "aes256-cbc entry in _cipher_info",
         "label": "risk", "rationale": "CBC-mode session cipher offered."},
        {"id": "PAR-029", "file": "transport.py", "line": 281,
         "category": "symmetric",
         "observed": "3des-cbc entry in _cipher_info (TripleDES)",
         "label": "risk", "rationale": "3DES session cipher offered."},
        # --- benign ---
        {"id": "PAR-030", "file": "pkey.py", "line": 111,
         "category": "symmetric",
         "observed": "AES-256-CBC entry with salt-derived IV",
         "label": "benign",
         "rationale": "AES-256 with a random IV is not a legacy-algorithm "
                      "finding."},
        {"id": "PAR-031", "file": "pkey.py", "line": 369,
         "category": "hashing", "observed": "sha256(bytes(self))",
         "label": "benign", "rationale": "Modern fingerprint digest."},
        {"id": "PAR-032", "file": "pkey.py", "line": 633,
         "category": "symmetric",
         "observed": "modes.CBC for aes256-cbc private key",
         "label": "benign",
         "rationale": "IV is derived from the bcrypt salt, not static."},
        {"id": "PAR-033", "file": "pkey.py", "line": 667,
         "category": "symmetric",
         "observed": "Cipher(algorithms.AES(key), mode(iv)) with bcrypt key",
         "label": "benign",
         "rationale": "AES-256 + bcrypt-derived key/IV envelope."},
        {"id": "PAR-034", "file": "pkey.py", "line": 654,
         "category": "key-derivation", "observed": "bcrypt.kdf(...)",
         "label": "benign", "rationale": "Modern password KDF."},
        {"id": "PAR-035", "file": "util.py", "line": 142,
         "category": "key-derivation",
         "observed": "def generate_key_bytes(hash_alg, salt, key, nbytes)",
         "label": "benign",
         "rationale": "Generic helper; the algorithm is chosen by the caller "
                      "(the MD5 caller is PAR-018)."},
        {"id": "PAR-036", "file": "config.py", "line": 449,
         "category": "non-crypto",
         "observed": "sha1(tohash.encode()).hexdigest() for the '%C' token",
         "label": "benign",
         "rationale": "Config-string token expansion, not a security digest."},
        {"id": "PAR-037", "file": "hostkeys.py", "line": 296,
         "category": "non-crypto",
         "observed": "os.urandom(sha1().digest_size) (size only)",
         "label": "benign",
         "rationale": "SHA-1 used only for its digest size; the bytes come "
                      "from a CSPRNG."},
        {"id": "PAR-038", "file": "transport.py", "line": 1232,
         "category": "randomness", "observed": "os.urandom(...) padding",
         "label": "benign", "rationale": "CSPRNG."},
        {"id": "PAR-039", "file": "transport.py", "line": 2059,
         "category": "symmetric",
         "observed": "Cipher(algorithm=info['class'](key), mode=info['mode'](iv))",
         "label": "benign",
         "rationale": "Algorithm chosen from the negotiated table at runtime; "
                      "no static weak algorithm at this call site."},
        # --- uncertain (excluded from the confusion matrix) ---
        {"id": "PAR-040", "file": "ed25519key.py", "line": 131,
         "category": "symmetric",
         "observed": "Cipher(cipher['class'](...), cipher['mode'](...))",
         "label": "uncertain",
         "rationale": "Cipher class read from parsed OpenSSH key metadata; a "
                      "bounded static pass cannot pin the algorithm down."},
        {"id": "PAR-041", "file": "pkey.py", "line": 595,
         "category": "symmetric",
         "observed": "Cipher(cipher(key), mode(salt)) from _CIPHER_TABLE",
         "label": "uncertain",
         "rationale": "The table entry can be AES or 3DES depending on the "
                      "key file; reviewer could not fix one label."},
    ],
}

TARGETS = {
    JUICE_SHOP["name"]: JUICE_SHOP,
    PARAMIKO["name"]: PARAMIKO,
}


def sites(target: dict, label: str | None = None) -> list:
    return [s for s in target["sites"] if label is None or s["label"] == label]


def counts(target: dict) -> dict:
    return {label: len(sites(target, label))
            for label in ("risk", "benign", "uncertain")}
