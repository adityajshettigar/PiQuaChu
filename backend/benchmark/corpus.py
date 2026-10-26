# backend/benchmark/corpus.py
"""
corpus.py — Labeled PQC benchmark corpus
========================================
Hermetic, self-contained copy of the PiQuaChu reliability corpus. Each
case carries an `expected` label used by runner.py to compute detection
metrics (Accuracy / Precision / Recall / F1). Counts are never hard-coded in
documentation; `report_counts.py` derives them.

Phase 2 cases additionally carry `rationale`, `label_source`, `kind`,
`expect_rules`, `forbid_rules`, `expect_confidence` and
`expect_parser_failures`, so a case cannot pass merely because *some* rule
fired. These are synthetic unit fixtures (kind=synthetic-corpus), not
externally sourced ground truth — external validation lives in
`benchmark/external_ground_truth.py` and is reported separately.

Labels:
  COMPLIANT                   — PQC usage only (no risk expected)
  COMPLIANT_SYMMETRIC_ONLY    — safe symmetric crypto only (no risk expected)
  NO_CRYPTO_DETECTED          — no crypto at all (no risk expected)
  NO_FILES_ERROR_HANDLING     — empty archive (no risk expected)
  NON_COMPLIANT               — classical/weak crypto (risk expected)
  NON_COMPLIANT_UNREACHABLE   — legacy code behind a dead flag (risk expected)
  NON_COMPLIANT_SEMANTIC      — textbook RSA, no imports (risk expected)
  MIXED                       — PQC + legacy coexisting (risk expected)
  TRANSITIONAL_COMPLIANT      — hybrid classical+PQC (risk expected)
  NO_CODE_USAGE_DEPENDENCY_RISK — manifest-only crypto libs (risk expected)
  UNDERTERMINED               — evidence is genuinely unresolved (env/config/
                                dynamic value); reported separately and never
                                forced into TP/FP/FN/TN
"""

# ---------------------------------------------------------------------------
# Build a large "haystack" file with one classical RSA call buried in the middle
# ---------------------------------------------------------------------------
filler_funcs = [f"def helper_function_{i}(x):\n    return x * {i} + 1\n" for i in range(70)]
large_content = "# Large utility module - assorted, unrelated helper functions.\n\n"
large_content += "\n".join(filler_funcs[:35])
large_content += "\n\n# --- classical crypto buried here (not near top or bottom) ---\n"
large_content += "from cryptography.hazmat.primitives.asymmetric import rsa\n\n"
large_content += "def _internal_bootstrap_key():\n    # Legacy bootstrap key, still RSA-2048.\n"
large_content += "    return rsa.generate_private_key(public_exponent=65537, key_size=2048)\n\n"
large_content += "\n".join(filler_funcs[35:])

TESTS = {}

TESTS["01_py_kyber_kem"] = {
    "category": "PQC-Compliant (KEM)",
    "expected": "COMPLIANT",
    "desc": "Python ML-KEM-768 (Kyber) key encapsulation via liboqs-python.",
    "files": {
        "kem_demo.py": (
            "# Post-Quantum KEM demo using ML-KEM-768 (Kyber) via liboqs-python.\n"
            "# Fully PQC-compliant key encapsulation mechanism per NIST FIPS 203.\n"
            "import oqs\n\n"
            "def generate_and_exchange():\n"
            '    kem_alg = "ML-KEM-768"\n'
            "    with oqs.KeyEncapsulation(kem_alg) as client:\n"
            "        public_key = client.generate_keypair()\n"
            "        with oqs.KeyEncapsulation(kem_alg) as server:\n"
            "            ciphertext, shared_secret_server = server.encap_secret(public_key)\n"
            "        shared_secret_client = client.decap_secret(ciphertext)\n"
            "        assert shared_secret_client == shared_secret_server\n"
            "        return shared_secret_client\n"
        ),
        "requirements.txt": "liboqs-python>=0.10.0\n",
    },
}

TESTS["02_py_dilithium_sign"] = {
    "category": "PQC-Compliant (Signature)",
    "expected": "COMPLIANT",
    "desc": "Python ML-DSA-65 (Dilithium3) digital signature via liboqs-python.",
    "files": {
        "sign_demo.py": (
            "# Digital signature demo using ML-DSA-65 (Dilithium3) via liboqs-python.\n"
            "# Fully PQC-compliant signature scheme per NIST FIPS 204.\n"
            "import oqs\n\n"
            'message = b"Firmware update package v2.3.1"\n\n'
            "def sign_and_verify():\n"
            '    sig_alg = "Dilithium3"\n'
            "    with oqs.Signature(sig_alg) as signer:\n"
            "        public_key = signer.generate_keypair()\n"
            "        signature = signer.sign(message)\n"
            "    with oqs.Signature(sig_alg) as verifier:\n"
            "        is_valid = verifier.verify(message, signature, public_key)\n"
            "    return is_valid\n"
        ),
        "requirements.txt": "liboqs-python>=0.10.0\n",
    },
}

TESTS["03_py_sphincs_sign"] = {
    "category": "PQC-Compliant (Signature)",
    "expected": "COMPLIANT",
    "desc": "Python SLH-DSA (SPHINCS+) stateless hash-based signature via pqcrypto.",
    "files": {
        "sign_demo.py": (
            "# Stateless hash-based signature demo using SLH-DSA (SPHINCS+) via pqcrypto.\n"
            "# Fully PQC-compliant per NIST FIPS 205.\n"
            "from pqcrypto.sign.sphincs_sha2_128f_simple import generate_keypair, sign, verify\n\n"
            "def demo():\n"
            "    public_key, secret_key = generate_keypair()\n"
            '    message = b"contract-hash-9f8a2b"\n'
            "    signature = sign(secret_key, message)\n"
            "    ok = verify(message, signature, public_key)\n"
            "    return ok\n"
        ),
        "requirements.txt": "pqcrypto>=0.3.0\n",
    },
}

TESTS["04_js_kyber_kem"] = {
    "category": "PQC-Compliant (KEM)",
    "expected": "COMPLIANT",
    "desc": "JavaScript Kyber768 KEM via crystals-kyber npm package.",
    "files": {
        "kem.js": (
            "// Post-quantum KEM demo using Kyber768 via the crystals-kyber package.\n"
            "// Fully PQC-compliant per NIST FIPS 203 (ML-KEM).\n"
            "const kyber = require('crystals-kyber');\n\n"
            "async function exchange() {\n"
            "  const { publicKey, privateKey } = kyber.keyPair();\n"
            "  const { cyphertext, secret: serverSecret } = kyber.encrypt(publicKey);\n"
            "  const clientSecret = kyber.decrypt(cyphertext, privateKey);\n"
            "  console.log('Shared secret match:', Buffer.compare(clientSecret, serverSecret) === 0);\n"
            "}\n"
        ),
        "package.json": (
            '{\n  "name": "kyber-kem-demo",\n  "version": "1.0.0",\n'
            '  "dependencies": {\n    "crystals-kyber": "^1.0.0"\n  }\n}\n'
        ),
    },
}

TESTS["05_java_bc_dilithium"] = {
    "category": "PQC-Compliant (Signature)",
    "expected": "COMPLIANT",
    "desc": "Java Dilithium signature via BouncyCastle PQC provider.",
    "files": {
        "DilithiumSign.java": (
            "// PQC digital signature demo using Dilithium via BouncyCastle PQC provider.\n"
            "// Fully compliant with NIST FIPS 204 (ML-DSA).\n"
            "import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;\n"
            "import java.security.*;\n\n"
            "public class DilithiumSign {\n"
            "    public static void main(String[] args) throws Exception {\n"
            "        Security.addProvider(new BouncyCastlePQCProvider());\n"
            '        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DILITHIUM", "BCPQC");\n'
            "        KeyPair kp = kpg.generateKeyPair();\n\n"
            '        Signature signer = Signature.getInstance("DILITHIUM", "BCPQC");\n'
            "        signer.initSign(kp.getPrivate());\n"
            '        signer.update("release-manifest-v4".getBytes());\n'
            "        byte[] signature = signer.sign();\n\n"
            '        Signature verifier = Signature.getInstance("DILITHIUM", "BCPQC");\n'
            "        verifier.initVerify(kp.getPublic());\n"
            '        verifier.update("release-manifest-v4".getBytes());\n'
            '        System.out.println("Valid: " + verifier.verify(signature));\n'
            "    }\n"
            "}\n"
        ),
    },
}

TESTS["06_go_circl_kyber"] = {
    "category": "PQC-Compliant (KEM)",
    "expected": "COMPLIANT",
    "desc": "Go Kyber768 KEM via Cloudflare's circl library.",
    "files": {
        "kyber_demo.go": (
            "// Post-quantum KEM demo using Kyber768 via Cloudflare's circl library.\n"
            "// Fully PQC-compliant per NIST FIPS 203.\n"
            "package main\n\n"
            "import (\n"
            '\t"fmt"\n'
            '\t"github.com/cloudflare/circl/kem/kyber/kyber768"\n'
            ")\n\n"
            "func main() {\n"
            "\tpk, sk, _ := kyber768.GenerateKeyPair(nil)\n"
            "\tct, ssSender, _ := kyber768.Encapsulate(pk, nil)\n"
            "\tssReceiver, _ := kyber768.Decapsulate(sk, ct)\n"
            '\tfmt.Println("secrets match:", string(ssSender) == string(ssReceiver))\n'
            "}\n"
        ),
        "go.mod": "module kyberdemo\n\ngo 1.21\n\nrequire github.com/cloudflare/circl v1.3.7\n",
    },
}

TESTS["07_c_liboqs_kyber"] = {
    "category": "PQC-Compliant (KEM)",
    "expected": "COMPLIANT",
    "desc": "C Kyber768 KEM via liboqs C API (legacy constant name).",
    "files": {
        "kyber_kem.c": (
            "/* Post-quantum KEM demo using Kyber768 via liboqs C API. */\n"
            "/* Fully PQC-compliant per NIST FIPS 203. */\n"
            "#include <oqs/oqs.h>\n#include <stdio.h>\n#include <stdlib.h>\n\n"
            "int main(void) {\n"
            "    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);\n"
            "    uint8_t *public_key = malloc(kem->length_public_key);\n"
            "    uint8_t *secret_key = malloc(kem->length_secret_key);\n"
            "    uint8_t *ciphertext = malloc(kem->length_ciphertext);\n"
            "    uint8_t *shared_secret_e = malloc(kem->length_shared_secret);\n"
            "    uint8_t *shared_secret_d = malloc(kem->length_shared_secret);\n\n"
            "    OQS_KEM_keypair(kem, public_key, secret_key);\n"
            "    OQS_KEM_encaps(kem, ciphertext, shared_secret_e, public_key);\n"
            "    OQS_KEM_decaps(kem, shared_secret_d, ciphertext, secret_key);\n\n"
            '    printf("KEM: %s\\n", kem->method_name);\n'
            "    OQS_KEM_free(kem);\n"
            "    return 0;\n"
            "}\n"
        ),
    },
}

TESTS["08_rust_pqcrypto_dilithium"] = {
    "category": "PQC-Compliant (Signature)",
    "expected": "COMPLIANT",
    "desc": "Rust Dilithium3 signature via pqcrypto crate.",
    "files": {
        "main.rs": (
            "// Post-quantum signature demo using Dilithium3 via the pqcrypto crate.\n"
            "// Fully compliant with NIST FIPS 204 (ML-DSA).\n"
            "use pqcrypto_dilithium::dilithium3::*;\n"
            "use pqcrypto_traits::sign::{DetachedSignature, PublicKey, SecretKey};\n\n"
            "fn main() {\n"
            "    let (pk, sk) = keypair();\n"
            '    let message = b"config-checksum-77a1";\n'
            "    let sig = detached_sign(message, &sk);\n"
            "    let ok = verify_detached_signature(&sig, message, &pk).is_ok();\n"
            '    println!("Dilithium3 signature valid: {}", ok);\n'
            "}\n"
        ),
        "Cargo.toml": (
            "[package]\nname = \"dilithium-demo\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n"
            "[dependencies]\npqcrypto-dilithium = \"0.5\"\npqcrypto-traits = \"0.3\"\n"
        ),
    },
}

TESTS["09_py_rsa_keygen"] = {
    "category": "Non-Compliant (Classical Asymmetric)",
    "expected": "NON_COMPLIANT",
    "desc": "Python RSA-2048 key generation via the cryptography library.",
    "files": {
        "rsa_demo.py": (
            "# Classical asymmetric key generation using RSA-2048.\n"
            "# NOT post-quantum safe - vulnerable to Shor's algorithm.\n"
            "from cryptography.hazmat.primitives.asymmetric import rsa\n\n"
            "def generate_rsa_keypair():\n"
            "    private_key = rsa.generate_private_key(\n"
            "        public_exponent=65537,\n"
            "        key_size=2048,\n"
            "    )\n"
            "    return private_key\n"
        ),
    },
}

TESTS["10_py_ecdsa_sign"] = {
    "category": "Non-Compliant (Classical Asymmetric)",
    "expected": "NON_COMPLIANT",
    "desc": "Python ECDSA over SECP256R1 via the cryptography library.",
    "files": {
        "ecdsa_demo.py": (
            "# Classical elliptic-curve signature using ECDSA over SECP256R1.\n"
            "# NOT post-quantum safe - vulnerable to Shor's algorithm.\n"
            "from cryptography.hazmat.primitives.asymmetric import ec\n"
            "from cryptography.hazmat.primitives import hashes\n\n"
            "def sign_message(message: bytes):\n"
            "    private_key = ec.generate_private_key(ec.SECP256R1())\n"
            "    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))\n"
            "    return signature\n"
        ),
    },
}

TESTS["11_java_rsa_keypair"] = {
    "category": "Non-Compliant (Classical Asymmetric)",
    "expected": "NON_COMPLIANT",
    "desc": "Java RSA-2048 keypair generation.",
    "files": {
        "RsaKeyGen.java": (
            "// Classical RSA-2048 keypair generation.\n"
            "// NOT post-quantum safe.\n"
            "import java.security.*;\n\n"
            "public class RsaKeyGen {\n"
            "    public static void main(String[] args) throws Exception {\n"
            '        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");\n'
            "        kpg.initialize(2048);\n"
            "        KeyPair kp = kpg.generateKeyPair();\n"
            '        System.out.println("RSA key generated: " + kp.getPublic().getAlgorithm());\n'
            "    }\n"
            "}\n"
        ),
    },
}

TESTS["12_java_ecdh"] = {
    "category": "Non-Compliant (Classical Asymmetric)",
    "expected": "NON_COMPLIANT",
    "desc": "Java Elliptic-Curve Diffie-Hellman key agreement.",
    "files": {
        "EcdhDemo.java": (
            "// Classical Elliptic-Curve Diffie-Hellman key agreement.\n"
            "// NOT post-quantum safe.\n"
            "import java.security.*;\n"
            "import javax.crypto.KeyAgreement;\n\n"
            "public class EcdhDemo {\n"
            "    public static void main(String[] args) throws Exception {\n"
            '        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");\n'
            "        kpg.initialize(256);\n"
            "        KeyPair aliceKp = kpg.generateKeyPair();\n"
            "        KeyPair bobKp = kpg.generateKeyPair();\n\n"
            '        KeyAgreement ka = KeyAgreement.getInstance("ECDH");\n'
            "        ka.init(aliceKp.getPrivate());\n"
            "        ka.doPhase(bobKp.getPublic(), true);\n"
            "        byte[] shared = ka.generateSecret();\n"
            '        System.out.println("Shared secret bytes: " + shared.length);\n'
            "    }\n"
            "}\n"
        ),
    },
}

TESTS["13_go_crypto_rsa"] = {
    "category": "Non-Compliant (Classical Asymmetric)",
    "expected": "NON_COMPLIANT",
    "desc": "Go RSA-2048 key generation using the standard library.",
    "files": {
        "rsa_demo.go": (
            "// Classical RSA-2048 key generation using Go standard library.\n"
            "// NOT post-quantum safe.\n"
            "package main\n\n"
            "import (\n"
            '\t"crypto/rand"\n'
            '\t"crypto/rsa"\n'
            '\t"fmt"\n'
            ")\n\n"
            "func main() {\n"
            "\tkey, err := rsa.GenerateKey(rand.Reader, 2048)\n"
            "\tif err != nil {\n"
            "\t\tpanic(err)\n"
            "\t}\n"
            '\tfmt.Println("RSA key size:", key.N.BitLen())\n'
            "}\n"
        ),
    },
}

TESTS["14_js_node_rsa"] = {
    "category": "Non-Compliant (Classical Asymmetric)",
    "expected": "NON_COMPLIANT",
    "desc": "Node.js RSA-2048 keypair generation via built-in crypto module.",
    "files": {
        "rsa.js": (
            "// Classical RSA-2048 keypair generation using Node's built-in crypto module.\n"
            "// NOT post-quantum safe.\n"
            "const crypto = require('crypto');\n\n"
            "const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {\n"
            "  modulusLength: 2048,\n"
            "  publicKeyEncoding: { type: 'spki', format: 'pem' },\n"
            "  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },\n"
            "});\n"
        ),
    },
}

TESTS["15_c_openssl_rsa"] = {
    "category": "Non-Compliant (Classical Asymmetric)",
    "expected": "NON_COMPLIANT",
    "desc": "C RSA-2048 key generation using OpenSSL.",
    "files": {
        "rsa_demo.c": (
            "/* Classical RSA-2048 key generation using OpenSSL. */\n"
            "/* NOT post-quantum safe. */\n"
            "#include <openssl/rsa.h>\n"
            "#include <openssl/bn.h>\n"
            "#include <stdio.h>\n\n"
            "int main(void) {\n"
            "    RSA *rsa = RSA_new();\n"
            "    BIGNUM *e = BN_new();\n"
            "    BN_set_word(e, RSA_F4);\n"
            "    RSA_generate_key_ex(rsa, 2048, e, NULL);\n"
            '    printf("RSA-2048 key generated\\n");\n'
            "    RSA_free(rsa);\n"
            "    BN_free(e);\n"
            "    return 0;\n"
            "}\n"
        ),
    },
}

TESTS["16_cpp_openssl_ec"] = {
    "category": "Non-Compliant (Classical Asymmetric)",
    "expected": "NON_COMPLIANT",
    "desc": "C++ elliptic-curve (P-256) key generation using OpenSSL.",
    "files": {
        "ec_demo.cpp": (
            "// Classical elliptic-curve key generation using OpenSSL (P-256).\n"
            "// NOT post-quantum safe.\n"
            "#include <openssl/ec.h>\n"
            "#include <openssl/obj_mac.h>\n"
            "#include <iostream>\n\n"
            "int main() {\n"
            "    EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);\n"
            "    EC_KEY_generate_key(key);\n"
            '    std::cout << "EC P-256 key generated" << std::endl;\n'
            "    EC_KEY_free(key);\n"
            "    return 0;\n"
            "}\n"
        ),
    },
}

TESTS["17_py_md5_hash"] = {
    "category": "Deprecated/Weak",
    "expected": "NON_COMPLIANT",
    "desc": "Python MD5 hashing - collision-broken since 2004.",
    "files": {
        "hash_demo.py": (
            "# Deprecated cryptographic hash function MD5 - collision-broken since 2004.\n"
            "import hashlib\n\n"
            "def hash_password(password: str) -> str:\n"
            "    return hashlib.md5(password.encode()).hexdigest()\n"
        ),
    },
}

TESTS["18_py_sha1_sign"] = {
    "category": "Deprecated/Weak",
    "expected": "NON_COMPLIANT",
    "desc": "RSA signature using deprecated SHA-1 digest.",
    "files": {
        "sign_demo.py": (
            "# RSA signature using deprecated SHA-1 digest.\n"
            "# SHA-1 is cryptographically broken (SHAttered, 2017).\n"
            "from cryptography.hazmat.primitives.asymmetric import rsa, padding\n"
            "from cryptography.hazmat.primitives import hashes\n\n"
            "def sign(private_key, message: bytes):\n"
            "    return private_key.sign(message, padding.PKCS1v15(), hashes.SHA1())\n"
        ),
    },
}

TESTS["19_php_des_mcrypt"] = {
    "category": "Deprecated/Weak",
    "expected": "NON_COMPLIANT",
    "desc": "PHP DES encryption via the removed mcrypt extension.",
    "files": {
        "des_demo.php": (
            "<?php\n"
            "// Deprecated DES encryption via the removed mcrypt extension.\n"
            "// DES has a 56-bit key space and is trivially brute-forceable today.\n"
            '$key = "8bytekey";\n'
            "$iv = mcrypt_create_iv(mcrypt_get_iv_size(MCRYPT_DES, MCRYPT_MODE_CBC), MCRYPT_RAND);\n"
            '$ciphertext = mcrypt_encrypt(MCRYPT_DES, $key, "sensitive-data", MCRYPT_MODE_CBC, $iv);\n'
            "echo bin2hex($ciphertext);\n"
            "?>\n"
        ),
    },
}

TESTS["20_js_crypto_des"] = {
    "category": "Deprecated/Weak",
    "expected": "NON_COMPLIANT",
    "desc": "JavaScript Triple-DES (3DES) symmetric cipher.",
    "files": {
        "des.js": (
            "// Deprecated Triple-DES (3DES/EDE3) symmetric cipher.\n"
            "// Deprecated by NIST since 2023; weak 112-bit effective security.\n"
            "const crypto = require('crypto');\n\n"
            "const key = crypto.randomBytes(24);\n"
            "const iv = crypto.randomBytes(8);\n"
            "const cipher = crypto.createCipheriv('des-ede3-cbc', key, iv);\n"
            "let encrypted = cipher.update('sensitive-payload', 'utf8', 'hex');\n"
            "encrypted += cipher.final('hex');\n"
        ),
    },
}

TESTS["21_java_des_cipher"] = {
    "category": "Deprecated/Weak",
    "expected": "NON_COMPLIANT",
    "desc": "Java DES symmetric cipher.",
    "files": {
        "DesCipher.java": (
            "// Deprecated DES symmetric cipher.\n"
            "import javax.crypto.*;\n"
            "import javax.crypto.spec.*;\n\n"
            "public class DesCipher {\n"
            "    public static void main(String[] args) throws Exception {\n"
            '        KeyGenerator kg = KeyGenerator.getInstance("DES");\n'
            "        SecretKey key = kg.generateKey();\n"
            '        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");\n'
            "        cipher.init(Cipher.ENCRYPT_MODE, key);\n"
            '        byte[] ct = cipher.doFinal("legacy-record".getBytes());\n'
            '        System.out.println("Encrypted length: " + ct.length);\n'
            "    }\n"
            "}\n"
        ),
    },
}

TESTS["22_c_rc4"] = {
    "category": "Deprecated/Weak",
    "expected": "NON_COMPLIANT",
    "desc": "C hand-rolled RC4 stream cipher (no library import).",
    "files": {
        "rc4_demo.c": (
            "/* Deprecated RC4 stream cipher - biased keystream, banned in TLS since 2015. */\n"
            "#include <stdio.h>\n#include <string.h>\n\n"
            "void rc4_ksa(unsigned char *key, int keylen, unsigned char *S) {\n"
            "    int j = 0;\n"
            "    for (int i = 0; i < 256; i++) S[i] = i;\n"
            "    for (int i = 0; i < 256; i++) {\n"
            "        j = (j + S[i] + key[i % keylen]) % 256;\n"
            "        unsigned char tmp = S[i]; S[i] = S[j]; S[j] = tmp;\n"
            "    }\n"
            "}\n\n"
            "int main(void) {\n"
            '    unsigned char key[] = "weakkey1";\n'
            "    unsigned char S[256];\n"
            '    unsigned char data[] = "top-secret-memo";\n'
            "    rc4_ksa(key, 8, S);\n"
            "    printf(\"RC4 keystream applied\\n\");\n"
            "    return 0;\n"
            "}\n"
        ),
    },
}

TESTS["23_py_hybrid_x25519_kyber"] = {
    "category": "Hybrid/Transitional",
    "expected": "TRANSITIONAL_COMPLIANT",
    "desc": "Python hybrid X25519 + ML-KEM-768 key exchange.",
    "files": {
        "hybrid_kem.py": (
            "# Hybrid key exchange combining classical X25519 with post-quantum ML-KEM-768.\n"
            "# Transitional / defense-in-depth scheme recommended during PQC migration.\n"
            "from cryptography.hazmat.primitives.asymmetric import x25519\n"
            "from cryptography.hazmat.primitives.kdf.hkdf import HKDF\n"
            "from cryptography.hazmat.primitives import hashes\n"
            "import oqs\n\n"
            "def hybrid_exchange():\n"
            "    alice_x = x25519.X25519PrivateKey.generate()\n"
            "    bob_x = x25519.X25519PrivateKey.generate()\n"
            "    classical_secret = alice_x.exchange(bob_x.public_key())\n\n"
            '    with oqs.KeyEncapsulation("ML-KEM-768") as kem:\n'
            "        pk = kem.generate_keypair()\n"
            "        ct, pqc_secret = kem.encap_secret(pk)\n\n"
            "    combined = HKDF(algorithm=hashes.SHA384(), length=32, salt=None, info=b'hybrid-kex').derive(\n"
            "        classical_secret + pqc_secret\n"
            "    )\n"
            "    return combined\n"
        ),
    },
}

TESTS["24_nginx_tls_hybrid_group"] = {
    "category": "Hybrid/Transitional (Config Only)",
    "expected": "TRANSITIONAL_COMPLIANT",
    "desc": "nginx.conf enabling X25519Kyber768Draft00 hybrid TLS group.",
    "files": {
        "nginx.conf": (
            "# TLS 1.3 configuration enabling hybrid post-quantum key exchange group.\n"
            "# X25519Kyber768Draft00 combines classical X25519 with ML-KEM-768.\n"
            "server {\n"
            "    listen 443 ssl;\n"
            "    server_name example.com;\n\n"
            "    ssl_protocols TLSv1.3;\n"
            "    ssl_ecdh_curve X25519Kyber768Draft00:X25519:prime256v1;\n"
            "    ssl_certificate /etc/ssl/certs/example.com.crt;\n"
            "    ssl_certificate_key /etc/ssl/private/example.com.key;\n"
            "}\n"
        ),
    },
}

TESTS["25_go_hybrid_tls_circl"] = {
    "category": "Hybrid/Transitional",
    "expected": "TRANSITIONAL_COMPLIANT",
    "desc": "Go TLS 1.3 client with hybrid X25519+Kyber768 curve preference.",
    "files": {
        "hybrid_tls.go": (
            "// TLS 1.3 client configured with hybrid X25519+Kyber768 key exchange\n"
            "// using Cloudflare's circl/tls hybrid group support.\n"
            "package main\n\n"
            "import (\n"
            '\t"crypto/tls"\n'
            '\t"fmt"\n'
            ")\n\n"
            "func main() {\n"
            "\tcfg := &tls.Config{\n"
            "\t\tMinVersion: tls.VersionTLS13,\n"
            "\t\tCurvePreferences: []tls.CurveID{\n"
            "\t\t\ttls.X25519Kyber768Draft00,\n"
            "\t\t\ttls.X25519,\n"
            "\t\t},\n"
            "\t}\n"
            '\tfmt.Println("Hybrid curve preferences configured:", len(cfg.CurvePreferences))\n'
            "}\n"
        ),
    },
}

TESTS["26_comment_only_mention"] = {
    "category": "Edge Case (False-Positive Bait)",
    "expected": "NO_CRYPTO_DETECTED",
    "desc": "RSA/Kyber only mentioned in a TODO comment; actual code does no key generation at all.",
    "files": {
        "util.py": (
            "# TODO: migrate our key exchange from RSA to a PQC KEM such as Kyber\n"
            "# once the compliance team finalizes the algorithm choice.\n"
            "# Ticket: SEC-4471\n\n"
            "import os\n\n"
            "def generate_session_token():\n"
            "    # Not cryptographic key generation - just a random session id.\n"
            "    return os.urandom(16).hex()\n"
        ),
    },
}

TESTS["27_string_literal_mention"] = {
    "category": "Edge Case (False-Positive Bait)",
    "expected": "COMPLIANT_SYMMETRIC_ONLY",
    "desc": "'RSA' and 'Kyber' appear only inside a log string; actual crypto call is AES-GCM.",
    "files": {
        "logger.js": (
            "// Structured logging around a key-rotation job.\n"
            "// Note: the string below is log text only, not an actual RSA call.\n"
            "const crypto = require('crypto');\n\n"
            "function rotateKey() {\n"
            "  console.log('Migrating from RSA to Kyber for the next key rotation cycle');\n"
            "  const key = crypto.randomBytes(32); // AES-256 key material\n"
            "  const iv = crypto.randomBytes(12);\n"
            "  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);\n"
            "  return cipher;\n"
            "}\n"
        ),
    },
}

TESTS["28_misleading_naming"] = {
    "category": "Edge Case (False-Positive Bait)",
    "expected": "COMPLIANT_SYMMETRIC_ONLY",
    "desc": "Function/variable named 'rsa' but implementation actually returns AES key material.",
    "files": {
        "keymgr.py": (
            "# Function and variable names reference \"rsa\" for historical reasons,\n"
            "# but the implementation actually generates symmetric AES key material.\n"
            "import os\n\n"
            "def generate_rsa_key():\n"
            "    rsa_key = os.urandom(32)  # actually an AES-256 key, not RSA\n"
            "    return rsa_key\n"
        ),
    },
}

TESTS["29_aliased_import"] = {
    "category": "Edge Case (Detection Evasion)",
    "expected": "NON_COMPLIANT",
    "desc": "RSA imported under a 'pq_' alias - tests whether scanner resolves import aliasing.",
    "files": {
        "keygen.py": (
            "# Import aliasing obscures the underlying algorithm name.\n"
            "from cryptography.hazmat.primitives.asymmetric import rsa as pq_rsa\n\n"
            "def generate_keypair():\n"
            "    # Despite the \"pq_\" alias, this generates a classical RSA-3072 key.\n"
            "    return pq_rsa.generate_private_key(public_exponent=65537, key_size=3072)\n"
        ),
    },
}

TESTS["30_dead_code_unreachable"] = {
    "category": "Edge Case (Reachability)",
    "expected": "NON_COMPLIANT_UNREACHABLE",
    "desc": "RSA call sits behind a permanently-False feature flag.",
    "files": {
        "legacy.py": (
            "# Legacy RSA code path kept for reference but never executed.\n"
            "from cryptography.hazmat.primitives.asymmetric import rsa\n\n"
            "FEATURE_FLAG_LEGACY_CRYPTO = False\n\n"
            "def get_keypair():\n"
            "    if FEATURE_FLAG_LEGACY_CRYPTO:\n"
            "        return rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
            "    else:\n"
            "        raise NotImplementedError(\"PQC key generation not yet wired up\")\n"
        ),
    },
}

TESTS["31_manifest_only_requirements"] = {
    "category": "Edge Case (Dependency-Only Signal)",
    "expected": "NO_CODE_USAGE_DEPENDENCY_RISK",
    "desc": "requirements.txt lists RSA-capable libraries but no .py file actually calls them.",
    "files": {
        "requirements.txt": "pycryptodome==3.20.0\ncryptography==42.0.5\nflask==3.0.3\n",
        "README.md": (
            "# Service Skeleton\n\n"
            "This repository only contains dependency manifests at this stage.\n"
            "No cryptographic code has been implemented yet - `pycryptodome` and\n"
            "`cryptography` are listed as anticipated dependencies for an upcoming\n"
            "authentication module.\n"
        ),
    },
}

TESTS["32_manifest_only_package_json"] = {
    "category": "Edge Case (Dependency-Only Signal)",
    "expected": "NO_CODE_USAGE_DEPENDENCY_RISK",
    "desc": "package.json lists node-forge (RSA-capable) but no .js file imports it.",
    "files": {
        "package.json": (
            '{\n  "name": "auth-service-skeleton",\n  "version": "0.1.0",\n'
            '  "dependencies": {\n    "node-forge": "^1.3.1",\n    "express": "^4.19.2"\n  }\n}\n'
        ),
        "index.html": "<!doctype html>\n<html>\n  <head><title>Placeholder</title></head>\n"
                      "  <body>Service under construction.</body>\n</html>\n",
    },
}

TESTS["33_mixed_lang_repo"] = {
    "category": "Edge Case (Mixed Verdict)",
    "expected": "MIXED",
    "desc": "Python backend uses ML-KEM-768 (compliant); JS frontend still uses RSA-OAEP (non-compliant).",
    "files": {
        "backend/kyber_server.py": (
            "# Backend key exchange endpoint using ML-KEM-768 (Kyber).\n"
            "# Fully PQC-compliant per NIST FIPS 203.\n"
            "import oqs\n\n"
            "def handle_kem_request():\n"
            '    with oqs.KeyEncapsulation("ML-KEM-768") as kem:\n'
            "        pk = kem.generate_keypair()\n"
            "        return pk\n"
        ),
        "frontend/legacy_rsa.js": (
            "// Legacy frontend crypto helper still using RSA-OAEP for a payments\n"
            "// widget that has not yet been migrated to the new PQC backend.\n"
            "const forge = require('node-forge');\n\n"
            "function encryptWithRsa(publicKeyPem, data) {\n"
            "  const publicKey = forge.pki.publicKeyFromPem(publicKeyPem);\n"
            "  return publicKey.encrypt(data, 'RSA-OAEP');\n"
            "}\n"
        ),
    },
}

TESTS["34_minified_js_rsa"] = {
    "category": "Edge Case (Obfuscation)",
    "expected": "NON_COMPLIANT",
    "desc": "RSA keygen call buried in a single-line minified JS bundle.",
    "files": {
        "bundle.min.js": (
            '!function(){"use strict";var a=require("crypto"),b=a.generateKeyPairSync("rsa",'
            '{modulusLength:2048,publicKeyEncoding:{type:"spki",format:"pem"},'
            'privateKeyEncoding:{type:"pkcs8",format:"pem"}});console.log("k",b.publicKey.length)}();\n'
        ),
    },
}

TESTS["35_empty_zip"] = {
    "category": "Edge Case (Malformed Input)",
    "expected": "NO_FILES_ERROR_HANDLING",
    "desc": "Archive containing zero files - tests graceful handling of empty input.",
    "files": {},
}

TESTS["36_noncode_only"] = {
    "category": "Edge Case (No Code)",
    "expected": "NO_CRYPTO_DETECTED",
    "desc": "Zip contains only README/LICENSE/asset placeholder - no source code at all.",
    "files": {
        "README.md": (
            "# Marketing Landing Page Assets\n\n"
            "This archive contains only static marketing assets - no source code\n"
            "and no cryptographic operations of any kind.\n"
        ),
        "LICENSE": (
            "MIT License\n\nCopyright (c) 2026 Example Corp\n\n"
            "Permission is hereby granted, free of charge, to any person obtaining a copy...\n"
        ),
        "assets/logo_placeholder.txt": "[binary image placeholder]\n",
    },
}

TESTS["37_deep_nested_folder"] = {
    "category": "Edge Case (Recursive Scanning)",
    "expected": "COMPLIANT",
    "desc": "PQC KEM usage buried five directories deep.",
    "files": {
        "a/b/c/d/e/kyber_deep.py": (
            "# PQC KEM usage buried five directories deep - tests recursive scanning.\n"
            "# Fully PQC-compliant per NIST FIPS 203.\n"
            "import oqs\n\n"
            "def deep_kem():\n"
            '    with oqs.KeyEncapsulation("ML-KEM-1024") as kem:\n'
            "        pk = kem.generate_keypair()\n"
            "        return pk\n"
        ),
    },
}

TESTS["38_large_file_buried_rsa"] = {
    "category": "Edge Case (Scan Depth)",
    "expected": "NON_COMPLIANT",
    "desc": "~700-line file with one RSA call buried in the middle.",
    "files": {"big_module.py": large_content},
}

TESTS["39_unusual_extensions"] = {
    "category": "Edge Case (File Type Coverage)",
    "expected": "NON_COMPLIANT",
    "desc": "Crypto code in non-standard extensions: .java.bak (archived) and .pyx (Cython).",
    "files": {
        "OldService.java.bak": (
            "// Archived service class (renamed with .bak so it is excluded from the\n"
            "// build) that still performs classical RSA signing.\n"
            "import java.security.*;\n\n"
            "public class OldService {\n"
            "    public static byte[] sign(PrivateKey key, byte[] data) throws Exception {\n"
            '        Signature sig = Signature.getInstance("SHA256withRSA");\n'
            "        sig.initSign(key);\n"
            "        sig.update(data);\n"
            "        return sig.sign();\n"
            "    }\n"
            "}\n"
        ),
        "legacy.pyx": (
            "# Cython extension module performing ECDSA verification.\n"
            "# NOT post-quantum safe.\n"
            "from cryptography.hazmat.primitives.asymmetric import ec\n"
            "from cryptography.hazmat.primitives import hashes\n\n"
            "def verify_ecdsa(public_key, signature, message):\n"
            "    public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))\n"
            "    return True\n"
        ),
    },
}

TESTS["40_toy_rsa_naive"] = {
    "category": "Edge Case (Semantic Detection)",
    "expected": "NON_COMPLIANT_SEMANTIC",
    "desc": "Textbook RSA implemented from scratch with modular exponentiation, no library imports.",
    "files": {
        "naive_rsa.py": (
            "# Textbook/toy RSA implementation written from scratch without importing\n"
            "# any crypto library. Tests semantic detection (recognizing modular\n"
            "# exponentiation + public/private exponents as RSA).\n\n"
            "def modexp(base, exp, mod):\n"
            "    result = 1\n"
            "    base %= mod\n"
            "    while exp > 0:\n"
            "        if exp & 1:\n"
            "            result = (result * base) % mod\n"
            "        exp >>= 1\n"
            "        base = (base * base) % mod\n"
            "    return result\n\n"
            "def toy_keygen(p, q, e=65537):\n"
            "    n = p * q\n"
            "    phi = (p - 1) * (q - 1)\n"
            "    d = pow(e, -1, phi)\n"
            "    return (e, n), (d, n)\n"
        ),
    },
}

TESTS["41_pem_key_files"] = {
    "category": "Non-Compliant (Key Material)",
    "expected": "NON_COMPLIANT",
    "desc": "RSA-2048 and EC P-256 PEM key files, no source code - tests key-file header detection.",
    "files": {
        "id_rsa.pem": (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA7E5vKqvhQ1x7P9ZjDmQa6x8bLx0yUw5n0eU4TqgH2fL9mJdO\n"
            "-----END RSA PRIVATE KEY-----\n"
        ),
        "ec_private.pem": (
            "-----BEGIN EC PRIVATE KEY-----\n"
            "MHcCAQEEIB8M3p7z3vL2pB0X3wU5rV0kHnYq2mJcO6jR4vG9WxGgAoGCCqGSM49\n"
            "-----END EC PRIVATE KEY-----\n"
        ),
        "README.md": (
            "# Key Material Only\n\n"
            "This archive contains (disposable) RSA-2048 and EC P-256 key files\n"
            "with no accompanying source code.\n"
        ),
    },
}

TESTS["42_yaml_cipher_suite_config"] = {
    "category": "Edge Case (Infra Config, Not Code)",
    "expected": "NON_COMPLIANT",
    "desc": "Kubernetes ingress YAML specifying classical ECDHE-RSA TLS cipher suites.",
    "files": {
        "ingress-tls.yaml": (
            "apiVersion: networking.k8s.io/v1\n"
            "kind: Ingress\n"
            "metadata:\n"
            "  name: payments-api\n"
            "  annotations:\n"
            '    nginx.ingress.kubernetes.io/ssl-ciphers: "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256"\n'
            '    nginx.ingress.kubernetes.io/ssl-protocols: "TLSv1.2 TLSv1.3"\n'
            "spec:\n"
            "  tls:\n"
            '    - hosts: ["api.example.com"]\n'
            "      secretName: payments-tls\n"
        ),
    },
}

TESTS["43_multi_algo_single_file"] = {
    "category": "Edge Case (Mixed Verdict, Single File)",
    "expected": "MIXED",
    "desc": "Single file with both a legacy RSA path and a new ML-KEM path, branched by API version.",
    "files": {
        "migration_inprogress.py": (
            "# Partial PQC migration: legacy RSA path retained for backward\n"
            "# compatibility while new traffic is routed through ML-KEM.\n"
            "from cryptography.hazmat.primitives.asymmetric import rsa\n"
            "import oqs\n\n"
            "def legacy_encrypt_setup():\n"
            "    # Old code path, still reachable for clients on API v1.\n"
            "    return rsa.generate_private_key(public_exponent=65537, key_size=2048)\n\n"
            "def pq_encrypt_setup():\n"
            "    # New code path for clients on API v2+.\n"
            '    with oqs.KeyEncapsulation("ML-KEM-768") as kem:\n'
            "        return kem.generate_keypair()\n\n"
            "def get_keypair(api_version: int):\n"
            "    if api_version >= 2:\n"
            "        return pq_encrypt_setup()\n"
            "    return legacy_encrypt_setup()\n"
        ),
    },
}

TESTS["44_wrapper_around_stdlib"] = {
    "category": "Edge Case (Wrapper Functions)",
    "expected": "NON_COMPLIANT",
    "desc": "Custom wrapper function around the standard hashlib.md5 call.",
    "files": {
        "wrapper.py": (
            "# Custom wrapper around the standard library - the scanner must see\n"
            "# through the indirection to the underlying crypto call.\n"
            "import hashlib\n\n"
            "def digest(data):\n"
            "    h = hashlib.md5()\n"
            "    h.update(data)\n"
            "    return h.hexdigest()\n"
        ),
    },
}

TESTS["45_py_falcon_fndsa_sign"] = {
    "category": "PQC-Compliant (Signature)",
    "expected": "COMPLIANT",
    "desc": "Python FN-DSA (FALCON-512) signature via liboqs-python — FIPS 206 is in development; positive detection is algorithm evidence, not a finalized pass.",
    "files": {
        "fndsa_sign.py": (
            "# Post-quantum signature demo using FN-DSA (FALCON-512) via liboqs-python.\n"
            "# FN-DSA (FALCON-512) via liboqs. NIST selected FALCON, but FIPS 206\n"
            "# was still in development at the registry review date.\n"
            "import oqs\n\n"
            'message = b"Signed release artifact v4.2.0"\n\n'
            "def sign_and_verify():\n"
            "    with oqs.Signature(\"Falcon-512\") as signer:\n"
            "        public_key = signer.generate_keypair()\n"
            "        signature = signer.sign(message)\n"
            "    with oqs.Signature(\"Falcon-512\") as verifier:\n"
            "        is_valid = verifier.verify(message, signature, public_key)\n"
            "    return is_valid\n"
        ),
        "requirements.txt": "liboqs-python>=0.10.0\n",
    },
}

TESTS["46_java_bc_falcon"] = {
    "category": "PQC-Compliant (Signature)",
    "expected": "COMPLIANT",
    "desc": "Java FN-DSA (FALCON-1024) signing via Bouncy Castle PQC (bcpqc).",
    "files": {
        "FnDsaDemo.java": (
            "// Post-quantum signature demo using FN-DSA (FALCON-1024) via Bouncy Castle PQC.\n"
            "// FN-DSA (FALCON-1024) via Bouncy Castle. FIPS 206 is still in\n"
            "// development at the registry review date.\n"
            "import org.bouncycastle.pqc.crypto.falcon.FalconKeyGenerationParameters;\n"
            "import org.bouncycastle.pqc.crypto.falcon.FalconKeyPairGenerator;\n"
            "import org.bouncycastle.pqc.crypto.falcon.FalconParameters;\n"
            "import org.bouncycastle.pqc.crypto.falcon.FalconSigner;\n"
            "import org.bouncycastle.crypto.AsymmetricCipherKeyPair;\n"
            "import java.security.SecureRandom;\n\n"
            "public class FnDsaDemo {\n"
            "    public static AsymmetricCipherKeyPair keypair() {\n"
            "        FalconKeyPairGenerator gen = new FalconKeyPairGenerator();\n"
            "        gen.init(new FalconKeyGenerationParameters(new SecureRandom(), FalconParameters.falcon1024));\n"
            "        return gen.generateKeyPair();\n"
            "    }\n\n"
            "    public static byte[] sign(AsymmetricCipherKeyPair kp, byte[] msg) {\n"
            "        FalconSigner signer = new FalconSigner();\n"
            "        signer.init(true, kp.getPrivate());\n"
            "        signer.update(msg, 0, msg.length);\n"
            "        return signer.generateSignature();\n"
            "    }\n"
            "}"
        ),
        "pom.xml": (
            "<project><dependencies><dependency>"
            "<groupId>org.bouncycastle</groupId><artifactId>bcpqc-jdk18on</artifactId>"
            "<version>1.78</version></dependency></dependencies></project>\n"
        ),
    },
}

TESTS["47_ssh_hybrid_kex_config"] = {
    "category": "PQC-Compliant (Hybrid / Transitional)",
    "expected": "TRANSITIONAL_COMPLIANT",
    "desc": "OpenSSH config enabling hybrid key exchange (mlkem768x25519) — mirrors pqc-flow's SSH KEX detection surface.",
    "files": {
        "sshd_config": (
            "# OpenSSH server configuration\n"
            "Port 22\n"
            "KexAlgorithms sntrup761x25519-sha512@openssh.com,mlkem768x25519-sha256,curve25519-sha256\n"
            "PasswordAuthentication no\n"
        ),
    },
}

# ---------------------------------------------------------------------------
# CVE-derived regression cases (G4 + external-validation roadmap).
# Ground truth is the bundled advisory in deps.py: the declared dependency
# version falls inside the CVE's constraint range, so risk is expected.
# ---------------------------------------------------------------------------
TESTS["48_cve_2022_24771_node_forge"] = {
    "category": "Dependency Risk (CVE-derived)",
    "expected": "NO_CODE_USAGE_DEPENDENCY_RISK",
    "desc": "node-forge < 1.3.0 — RSA signature verification bypass (CVE-2022-24771); manifest-only, no code usage.",
    "files": {
        "package.json": (
            "{\n"
            "  \"name\": \"legacy-signing-service\",\n"
            "  \"version\": \"1.0.0\",\n"
            "  \"dependencies\": {\n"
            "    \"node-forge\": \"0.9.1\"\n"
            "  }\n"
            "}\n"
        ),
    },
}

TESTS["49_cve_2023_49083_cryptography"] = {
    "category": "Dependency Risk (CVE-derived)",
    "expected": "NO_CODE_USAGE_DEPENDENCY_RISK",
    "desc": "pyca/cryptography < 42.0.2 — DoS via crafted input (CVE-2023-49083); manifest-only, no code usage.",
    "files": {
        "requirements.txt": "cryptography==41.0.7\n",
    },
}

# ---------------------------------------------------------------------------
# Phase 2 — bounded data-flow / constant-propagation cases.
#
# Every case carries: unique id, language + category, minimal fixture, expected
# risk label, the rule that must fire (expect_rules), rules that must NOT fire
# (forbid_rules), expected confidence tier, and a rationale + label provenance.
# UNDERTERMINED means the honest outcome is "a human must review the runtime
# value" — such cases are reported separately and never forced into TP/FP.
# ---------------------------------------------------------------------------
TESTS["50_py_dataflow_md5_alias_chain"] = {
    "category": "Data-Flow (Python)",
    "expected": "NON_COMPLIANT",
    "desc": "MD5 selected through an assignment chain and passed by variable to hashlib.new.",
    "rationale": "Two-hop constant propagation reaches a weak-hash sink; literal "
                 "rules alone cannot see this because no literal sits at the call.",
    "label_source": "manual review, Phase 2 corpus authoring (2026-10-18)",
    "kind": "synthetic-corpus",
    "expect_rules": ["weak-crypto-python-md5"],
    "forbid_rules": ["weak-crypto-python-sha1", "deprecated-rsa-python-cryptography"],
    "expect_confidence": ["high"],
    "files": {
        "digest.py": (
            "# Bait: the docstring mentions MD5 only to say it is retired.\n"
            '"""Historical note: MD5 and SHA-1 were removed in 2019.\n'
            '"""\n'
            "import hashlib\n\n"
            'ALGORITHM = "md5"\n\n\n'
            "def fingerprint(payload: bytes) -> str:\n"
            "    algo = ALGORITHM\n"
            "    selected = algo\n"
            "    return hashlib.new(selected, payload).hexdigest()\n"
        ),
        "NOTES.md": "# Notes\n\nWe no longer use md5 or sha1 anywhere in this service.\n",
    },
}

TESTS["51_py_dataflow_sha1_string_expression"] = {
    "category": "Data-Flow (Python)",
    "expected": "NON_COMPLIANT",
    "desc": "SHA-1 assembled from statically resolvable string concatenation and f-string format.",
    "rationale": "Concatenation and f-string formatting resolve to 'sha1' at the "
                 "sink, so the weak hash is real and provable.",
    "label_source": "manual review, Phase 2 corpus authoring (2026-10-18)",
    "kind": "synthetic-corpus",
    "expect_rules": ["weak-crypto-python-sha1"],
    "forbid_rules": ["weak-crypto-python-md5"],
    "expect_confidence": ["high"],
    "files": {
        "legacy.py": (
            "import hashlib\n\n"
            'PREFIX = "sh"\n\n\n'
            "def digest_concat(data: bytes) -> bytes:\n"
            '    name = PREFIX + "a1"\n'
            "    return hashlib.new(name, data).digest()\n\n\n"
            "def digest_fstring(data: bytes) -> bytes:\n"
            '    name = f"sh{\'a\'}1"\n'
            "    return hashlib.new(name, data).digest()\n"
        ),
    },
}

TESTS["52_py_dataflow_wrapper_forwarding"] = {
    "category": "Data-Flow (Python)",
    "expected": "NON_COMPLIANT",
    "desc": "Single-return wrapper forwards its algorithm argument (with an MD5 default) into hashlib.new.",
    "rationale": "The wrapper default is a constant, so the call site is provably MD5; "
                 "confidence is medium because the value crosses a function boundary.",
    "label_source": "manual review, Phase 2 corpus authoring (2026-10-18)",
    "kind": "synthetic-corpus",
    "expect_rules": ["weak-crypto-python-md5"],
    "expect_confidence": ["medium"],
    "files": {
        "hashing.py": (
            "import hashlib\n\n\n"
            'def make_hash(algo="md5"):\n'
            "    return hashlib.new(algo)\n\n\n"
            "def checksum(payload: bytes) -> str:\n"
            "    h = make_hash()\n"
            "    h.update(payload)\n"
            "    return h.hexdigest()\n"
        ),
    },
}

TESTS["53_py_dataflow_env_value_unresolved"] = {
    "category": "Data-Flow (Uncertain)",
    "expected": "UNDERTERMINED",
    "desc": "Digest algorithm comes from an environment variable — not statically resolvable.",
    "rationale": "An environment value is not a constant. Reporting a pass would be a "
                 "false negative; reporting non-compliance would be a guess. The honest "
                 "outcome is inconclusive evidence for a human to resolve.",
    "label_source": "manual review, Phase 2 corpus authoring (2026-10-18)",
    "kind": "synthetic-corpus",
    "expect_rules": ["dataflow-unresolved-algorithm-python"],
    "forbid_rules": ["weak-crypto-python-md5", "weak-crypto-python-sha1"],
    "expect_confidence": ["inconclusive"],
    "files": {
        "service.py": (
            "import hashlib\n"
            "import os\n\n\n"
            "def digest(payload: bytes) -> bytes:\n"
            '    algo = os.environ.get("DIGEST_ALGORITHM")\n'
            "    return hashlib.new(algo, payload).digest()\n"
        ),
    },
}

TESTS["54_py_dataflow_ecb_mode_object"] = {
    "category": "Data-Flow (Python)",
    "expected": "NON_COMPLIANT",
    "desc": "ECB mode selected through the mode object API in a cryptography Cipher.",
    "rationale": "ECB is deterministic and structurally unsafe for the payload sizes "
                 "involved; the mode object is an explicit API choice, not a string "
                 "that a literal rule could miss.",
    "label_source": "manual review, Phase 2 corpus authoring (2026-10-18)",
    "kind": "synthetic-corpus",
    "expect_rules": ["deprecated-ecb-python"],
    "files": {
        "encrypt.py": (
            "from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\n\n\n"
            "def encrypt_block(key: bytes, data: bytes) -> bytes:\n"
            "    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()\n"
            "    return encryptor.update(data) + encryptor.finalize()\n"
        ),
    },
}

TESTS["55_py_dataflow_join_same_value"] = {
    "category": "Data-Flow (Python)",
    "expected": "NON_COMPLIANT",
    "desc": "Both branches of an if/else assign the same constant, so the join resolves.",
    "rationale": "A join where every reachable branch agrees is provable; the rule "
                 "should fire with high confidence.",
    "label_source": "manual review, Phase 2 corpus authoring (2026-10-18)",
    "kind": "synthetic-corpus",
    "expect_rules": ["weak-crypto-python-md5"],
    "expect_confidence": ["high"],
    "files": {
        "policy.py": (
            "import hashlib\n\n\n"
            "def choose(legacy: bool) -> bytes:\n"
            "    if legacy:\n"
            '        algo = "md5"\n'
            "    else:\n"
            '        algo = "md5"\n'
            "    return hashlib.new(algo).digest()\n"
        ),
    },
}

TESTS["56_py_dataflow_join_divergent"] = {
    "category": "Data-Flow (Uncertain)",
    "expected": "UNDERTERMINED",
    "desc": "One branch selects MD5, the other SHA-256 — the join is genuinely ambiguous.",
    "rationale": "The bounded analysis cannot prove which branch runs, so it reports "
                 "unresolved evidence instead of guessing or silently dropping the MD5 "
                 "branch. A human/WAF decision is required.",
    "label_source": "manual review, Phase 2 corpus authoring (2026-10-18)",
    "kind": "synthetic-corpus",
    "expect_rules": ["dataflow-unresolved-algorithm-python"],
    "forbid_rules": ["weak-crypto-python-md5"],
    "expect_confidence": ["inconclusive"],
    "files": {
        "selector.py": (
            "import hashlib\n\n\n"
            "def choose(legacy: bool) -> bytes:\n"
            "    if legacy:\n"
            '        algo = "md5"\n'
            "    else:\n"
            '        algo = "sha256"\n'
            "    return hashlib.new(algo).digest()\n"
        ),
    },
}

TESTS["57_java_dataflow_md5_alias_chain"] = {
    "category": "Data-Flow (Java)",
    "expected": "NON_COMPLIANT",
    "desc": "Java MessageDigest.getInstance receives MD5 through a local variable chain and string concatenation.",
    "rationale": "Local Java constant propagation reaches the JCA sink; the literal is "
                 "not at the call site, so pattern-only engines can miss it.",
    "label_source": "manual review, Phase 2 corpus authoring (2026-10-18)",
    "kind": "synthetic-corpus",
    "expect_rules": ["weak-crypto-java-md5"],
    "expect_confidence": ["high"],
    "files": {
        "Digest.java": (
            "// Note: SHA-256 is the approved digest; MD5 is retained below.\n"
            "import java.security.MessageDigest;\n\n"
            "public class Digest {\n"
            "    private static final String ALG = \"MD\" + \"5\";\n\n"
            "    public byte[] legacyDigest(byte[] data) throws Exception {\n"
            "        String algo = ALG;\n"
            "        MessageDigest md = MessageDigest.getInstance(algo);\n"
            "        return md.digest(data);\n"
            "    }\n"
            "}\n"
        ),
    },
}

TESTS["58_java_dataflow_cipher_ecb_transformation"] = {
    "category": "Data-Flow (Java)",
    "expected": "NON_COMPLIANT",
    "desc": "Cipher transformation string built locally and resolved to AES/ECB/PKCS5Padding.",
    "rationale": "ECB mode is unsafe regardless of key size; the transformation is "
                 "assembled from constants and is therefore provable.",
    "label_source": "manual review, Phase 2 corpus authoring (2026-10-18)",
    "kind": "synthetic-corpus",
    "expect_rules": ["deprecated-ecb-java"],
    "expect_confidence": ["high"],
    "files": {
        "BlockCipher.java": (
            "import javax.crypto.Cipher;\n\n"
            "public class BlockCipher {\n"
            "    public Cipher build() throws Exception {\n"
            "        String mode = \"ECB\";\n"
            "        String transformation = \"AES/\" + mode + \"/PKCS5Padding\";\n"
            "        return Cipher.getInstance(transformation);\n"
            "    }\n"
            "}\n"
        ),
    },
}

TESTS["59_java_dataflow_parameter_unresolved"] = {
    "category": "Data-Flow (Uncertain)",
    "expected": "UNDERTERMINED",
    "desc": "JCA algorithm arrives as a method parameter — not statically resolvable.",
    "rationale": "The caller is outside the bounded scope, so the engine must not "
                 "claim the call is safe and must not accuse it either.",
    "label_source": "manual review, Phase 2 corpus authoring (2026-10-18)",
    "kind": "synthetic-corpus",
    "expect_rules": ["dataflow-unresolved-algorithm-java"],
    "forbid_rules": ["weak-crypto-java-md5"],
    "expect_confidence": ["inconclusive"],
    "files": {
        "Configurable.java": (
            "import java.security.MessageDigest;\n\n"
            "public class Configurable {\n"
            "    public MessageDigest digestOf(String algorithm) throws Exception {\n"
            "        MessageDigest md = MessageDigest.getInstance(algorithm);\n"
            "        return md;\n"
            "    }\n"
            "}\n"
        ),
    },
}

TESTS["60_dataflow_false_positive_bait"] = {
    "category": "Edge Case (False-Positive Bait)",
    "expected": "NO_CRYPTO_DETECTED",
    "desc": "Algorithm names appear in comments, docs, dead constants and config data with no crypto sink.",
    "rationale": "Unused strings and documentation are not evidence of crypto usage; "
                 "the data-flow pass must only fire when a value reaches a sink.",
    "label_source": "manual review, Phase 2 corpus authoring (2026-10-18)",
    "kind": "synthetic-corpus",
    "forbid_rules": [
        "weak-crypto-python-md5", "weak-crypto-python-sha1",
        "dataflow-unresolved-algorithm-python", "deprecated-ecb-python",
    ],
    "files": {
        "labels.py": (
            '"""Allowed algorithm labels for the migration tracker.\n\n'
            'Removed: md5, sha1, DES, RSA-1024.\n'
            '"""\n'
            "# md5 and sha1 are tracked here but never used for hashing.\n"
            "RETIRED = {\"md5\": \"retired\", \"sha1\": \"retired\"}\n"
            "ECB_WARNING = \"ECB mode is not allowed\"\n"
        ),
        "ui_text.json": '{\n  "warning": "md5 is retired",\n  "mode": "ECB"\n}\n',
        "docs/security.md": "# Security\n\nWe do not use md5, sha1 or RSA-1024.\n",
    },
}

TESTS["61_py_parser_failure_isolation"] = {
    "category": "Data-Flow (Parser Robustness)",
    "expected": "NON_COMPLIANT",
    "desc": "A file that fails to parse must not discard findings from files that parse.",
    "rationale": "Parser failure is recorded as a diagnostic; the valid file still "
                 "contains a literal MD5 sink that must be reported.",
    "label_source": "manual review, Phase 2 corpus authoring (2026-10-18)",
    "kind": "synthetic-corpus",
    "expect_rules": ["weak-crypto-python-md5"],
    "expect_parser_failures": 1,
    "files": {
        "good.py": "import hashlib\n\nh = hashlib.new(\"md5\")\n",
        "broken.py": "def broken(:\n    return 1\n",
    },
}

TESTS["62_java_parser_failure_isolation"] = {
    "category": "Data-Flow (Parser Robustness)",
    "expected": "NON_COMPLIANT",
    "desc": "A Java file outside javalang's grammar must not suppress findings in valid files.",
    "rationale": "Grammar coverage is limited (records/sealed types may fail); the "
                 "failure is counted and the valid MD5 sink is still reported.",
    "label_source": "manual review, Phase 2 corpus authoring (2026-10-18)",
    "kind": "synthetic-corpus",
    "expect_rules": ["weak-crypto-java-md5"],
    "expect_parser_failures": 1,
    "files": {
        "Valid.java": (
            "import java.security.MessageDigest;\n\n"
            "public class Valid {\n"
            "    public MessageDigest md() throws Exception {\n"
            "        return MessageDigest.getInstance(\"MD5\");\n"
            "    }\n"
            "}\n"
        ),
        "Broken.java": "public class Broken { void f( { }\n",
    },
}

# NOTE (design limit, verified 2026-09): a "patched version" control case is not
# possible for CVEs in legacy crypto libraries. deps.py flags any declared
# legacy-capable library (node-forge, cryptography, ...) as
# dependency-legacy-crypto-lib regardless of version — correct behavior, since
# the library remains quantum-vulnerable-capable even when its CVE is patched.
# The CVE-specific finding (dependency-vulnerable-version) fires only inside the
# constraint range; the generic legacy advisory always fires. See CHANGELOG.md.


def build_case_dir(case_name: str, spec: dict, dest_root: str) -> str:
    """Materialize one corpus case into dest_root/<case_name> and return the path."""
    import os
    case_dir = os.path.join(dest_root, case_name)
    os.makedirs(case_dir, exist_ok=True)
    for relpath, content in spec.get("files", {}).items():
        fpath = os.path.join(case_dir, relpath)
        os.makedirs(os.path.dirname(fpath), exist_ok=True)
        with open(fpath, "w", encoding="utf-8") as fh:
            fh.write(content)
    return case_dir
