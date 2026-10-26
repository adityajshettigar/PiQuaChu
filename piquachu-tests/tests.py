import os, zipfile, shutil, csv, subprocess

BASE = "/home/claude/pqc_tests"
OUT = "/home/claude/pqc_tests_zips"
os.makedirs(BASE, exist_ok=True)
os.makedirs(OUT, exist_ok=True)

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
        "kem_demo.py": '''# Post-Quantum KEM demo using ML-KEM-768 (Kyber) via liboqs-python.
# Fully PQC-compliant key encapsulation mechanism per NIST FIPS 203.
import oqs

def generate_and_exchange():
    kem_alg = "ML-KEM-768"
    with oqs.KeyEncapsulation(kem_alg) as client:
        public_key = client.generate_keypair()
        with oqs.KeyEncapsulation(kem_alg) as server:
            ciphertext, shared_secret_server = server.encap_secret(public_key)
        shared_secret_client = client.decap_secret(ciphertext)
        assert shared_secret_client == shared_secret_server
        return shared_secret_client

if __name__ == "__main__":
    secret = generate_and_exchange()
    print("Shared secret established via ML-KEM-768:", secret.hex()[:16])
''',
        "requirements.txt": "liboqs-python>=0.10.0\n",
    },
}

TESTS["02_py_dilithium_sign"] = {
    "category": "PQC-Compliant (Signature)",
    "expected": "COMPLIANT",
    "desc": "Python ML-DSA-65 (Dilithium3) digital signature via liboqs-python.",
    "files": {
        "sign_demo.py": '''# Digital signature demo using ML-DSA-65 (Dilithium3) via liboqs-python.
# Fully PQC-compliant signature scheme per NIST FIPS 204.
import oqs

message = b"Firmware update package v2.3.1"

def sign_and_verify():
    sig_alg = "Dilithium3"
    with oqs.Signature(sig_alg) as signer:
        public_key = signer.generate_keypair()
        signature = signer.sign(message)
    with oqs.Signature(sig_alg) as verifier:
        is_valid = verifier.verify(message, signature, public_key)
    return is_valid

if __name__ == "__main__":
    print("Signature valid:", sign_and_verify())
''',
        "requirements.txt": "liboqs-python>=0.10.0\n",
    },
}

TESTS["03_py_sphincs_sign"] = {
    "category": "PQC-Compliant (Signature)",
    "expected": "COMPLIANT",
    "desc": "Python SLH-DSA (SPHINCS+) stateless hash-based signature via pqcrypto.",
    "files": {
        "sign_demo.py": '''# Stateless hash-based signature demo using SLH-DSA (SPHINCS+) via pqcrypto.
# Fully PQC-compliant per NIST FIPS 205.
from pqcrypto.sign.sphincs_sha2_128f_simple import generate_keypair, sign, verify

def demo():
    public_key, secret_key = generate_keypair()
    message = b"contract-hash-9f8a2b"
    signature = sign(secret_key, message)
    ok = verify(message, signature, public_key)
    return ok

if __name__ == "__main__":
    print("SPHINCS+ signature valid:", demo())
''',
        "requirements.txt": "pqcrypto>=0.3.0\n",
    },
}

TESTS["04_js_kyber_kem"] = {
    "category": "PQC-Compliant (KEM)",
    "expected": "COMPLIANT",
    "desc": "JavaScript Kyber768 KEM via crystals-kyber npm package.",
    "files": {
        "kem.js": '''// Post-quantum KEM demo using Kyber768 via the crystals-kyber package.
// Fully PQC-compliant per NIST FIPS 203 (ML-KEM).
const kyber = require('crystals-kyber');

async function exchange() {
  const { publicKey, privateKey } = kyber.keyPair();
  const { cyphertext, secret: serverSecret } = kyber.encrypt(publicKey);
  const clientSecret = kyber.decrypt(cyphertext, privateKey);
  console.log('Shared secret match:', Buffer.compare(clientSecret, serverSecret) === 0);
}

exchange();
''',
        "package.json": '''{
  "name": "kyber-kem-demo",
  "version": "1.0.0",
  "dependencies": {
    "crystals-kyber": "^1.0.0"
  }
}
''',
    },
}

TESTS["05_java_bc_dilithium"] = {
    "category": "PQC-Compliant (Signature)",
    "expected": "COMPLIANT",
    "desc": "Java Dilithium signature via BouncyCastle PQC provider.",
    "files": {
        "DilithiumSign.java": '''// PQC digital signature demo using Dilithium via BouncyCastle PQC provider.
// Fully compliant with NIST FIPS 204 (ML-DSA).
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import java.security.*;

public class DilithiumSign {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastlePQCProvider());
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DILITHIUM", "BCPQC");
        KeyPair kp = kpg.generateKeyPair();

        Signature signer = Signature.getInstance("DILITHIUM", "BCPQC");
        signer.initSign(kp.getPrivate());
        signer.update("release-manifest-v4".getBytes());
        byte[] signature = signer.sign();

        Signature verifier = Signature.getInstance("DILITHIUM", "BCPQC");
        verifier.initVerify(kp.getPublic());
        verifier.update("release-manifest-v4".getBytes());
        System.out.println("Valid: " + verifier.verify(signature));
    }
}
''',
    },
}

TESTS["06_go_circl_kyber"] = {
    "category": "PQC-Compliant (KEM)",
    "expected": "COMPLIANT",
    "desc": "Go Kyber768 KEM via Cloudflare's circl library.",
    "files": {
        "kyber_demo.go": '''// Post-quantum KEM demo using Kyber768 via Cloudflare's circl library.
// Fully PQC-compliant per NIST FIPS 203.
package main

import (
	"fmt"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
)

func main() {
	pk, sk, _ := kyber768.GenerateKeyPair(nil)
	ct, ssSender, _ := kyber768.Encapsulate(pk, nil)
	ssReceiver, _ := kyber768.Decapsulate(sk, ct)
	fmt.Println("secrets match:", string(ssSender) == string(ssReceiver))
}
''',
        "go.mod": '''module kyberdemo

go 1.21

require github.com/cloudflare/circl v1.3.7
''',
    },
}

TESTS["07_c_liboqs_kyber"] = {
    "category": "PQC-Compliant (KEM)",
    "expected": "COMPLIANT",
    "desc": "C Kyber768 KEM via liboqs C API.",
    "files": {
        "kyber_kem.c": '''/* Post-quantum KEM demo using Kyber768 via liboqs C API. */
/* Fully PQC-compliant per NIST FIPS 203. */
#include <oqs/oqs.h>
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
    uint8_t *public_key = malloc(kem->length_public_key);
    uint8_t *secret_key = malloc(kem->length_secret_key);
    uint8_t *ciphertext = malloc(kem->length_ciphertext);
    uint8_t *shared_secret_e = malloc(kem->length_shared_secret);
    uint8_t *shared_secret_d = malloc(kem->length_shared_secret);

    OQS_KEM_keypair(kem, public_key, secret_key);
    OQS_KEM_encaps(kem, ciphertext, shared_secret_e, public_key);
    OQS_KEM_decaps(kem, shared_secret_d, ciphertext, secret_key);

    printf("KEM: %s\\n", kem->method_name);
    OQS_KEM_free(kem);
    return 0;
}
''',
    },
}

TESTS["08_rust_pqcrypto_dilithium"] = {
    "category": "PQC-Compliant (Signature)",
    "expected": "COMPLIANT",
    "desc": "Rust Dilithium3 signature via pqcrypto crate.",
    "files": {
        "main.rs": '''// Post-quantum signature demo using Dilithium3 via the pqcrypto crate.
// Fully compliant with NIST FIPS 204 (ML-DSA).
use pqcrypto_dilithium::dilithium3::*;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey, SecretKey};

fn main() {
    let (pk, sk) = keypair();
    let message = b"config-checksum-77a1";
    let sig = detached_sign(message, &sk);
    let ok = verify_detached_signature(&sig, message, &pk).is_ok();
    println!("Dilithium3 signature valid: {}", ok);
}
''',
        "Cargo.toml": '''[package]
name = "dilithium-demo"
version = "0.1.0"
edition = "2021"

[dependencies]
pqcrypto-dilithium = "0.5"
pqcrypto-traits = "0.3"
''',
    },
}

TESTS["09_py_rsa_keygen"] = {
    "category": "Non-Compliant (Classical Asymmetric)",
    "expected": "NON_COMPLIANT",
    "desc": "Python RSA-2048 key generation via the cryptography library.",
    "files": {
        "rsa_demo.py": '''# Classical asymmetric key generation using RSA-2048.
# NOT post-quantum safe - vulnerable to Shor's algorithm.
from cryptography.hazmat.primitives.asymmetric import rsa

def generate_rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    return private_key

if __name__ == "__main__":
    key = generate_rsa_keypair()
    print("Generated RSA-2048 key:", key.key_size)
''',
    },
}

TESTS["10_py_ecdsa_sign"] = {
    "category": "Non-Compliant (Classical Asymmetric)",
    "expected": "NON_COMPLIANT",
    "desc": "Python ECDSA over SECP256R1 via the cryptography library.",
    "files": {
        "ecdsa_demo.py": '''# Classical elliptic-curve signature using ECDSA over SECP256R1.
# NOT post-quantum safe - vulnerable to Shor's algorithm.
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

def sign_message(message: bytes):
    private_key = ec.generate_private_key(ec.SECP256R1())
    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    return signature

if __name__ == "__main__":
    sig = sign_message(b"invoice-4471")
    print("ECDSA signature length:", len(sig))
''',
    },
}

TESTS["11_java_rsa_keypair"] = {
    "category": "Non-Compliant (Classical Asymmetric)",
    "expected": "NON_COMPLIANT",
    "desc": "Java RSA-2048 keypair generation.",
    "files": {
        "RsaKeyGen.java": '''// Classical RSA-2048 keypair generation.
// NOT post-quantum safe.
import java.security.*;

public class RsaKeyGen {
    public static void main(String[] args) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        System.out.println("RSA key generated: " + kp.getPublic().getAlgorithm());
    }
}
''',
    },
}

TESTS["12_java_ecdh"] = {
    "category": "Non-Compliant (Classical Asymmetric)",
    "expected": "NON_COMPLIANT",
    "desc": "Java Elliptic-Curve Diffie-Hellman key agreement.",
    "files": {
        "EcdhDemo.java": '''// Classical Elliptic-Curve Diffie-Hellman key agreement.
// NOT post-quantum safe.
import java.security.*;
import javax.crypto.KeyAgreement;

public class EcdhDemo {
    public static void main(String[] args) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        KeyPair aliceKp = kpg.generateKeyPair();
        KeyPair bobKp = kpg.generateKeyPair();

        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(aliceKp.getPrivate());
        ka.doPhase(bobKp.getPublic(), true);
        byte[] shared = ka.generateSecret();
        System.out.println("Shared secret bytes: " + shared.length);
    }
}
''',
    },
}

TESTS["13_go_crypto_rsa"] = {
    "category": "Non-Compliant (Classical Asymmetric)",
    "expected": "NON_COMPLIANT",
    "desc": "Go RSA-2048 key generation using the standard library.",
    "files": {
        "rsa_demo.go": '''// Classical RSA-2048 key generation using Go standard library.
// NOT post-quantum safe.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

func main() {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	fmt.Println("RSA key size:", key.N.BitLen())
}
''',
    },
}

TESTS["14_js_node_rsa"] = {
    "category": "Non-Compliant (Classical Asymmetric)",
    "expected": "NON_COMPLIANT",
    "desc": "Node.js RSA-2048 keypair generation via built-in crypto module.",
    "files": {
        "rsa.js": '''// Classical RSA-2048 keypair generation using Node's built-in crypto module.
// NOT post-quantum safe.
const crypto = require('crypto');

const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

console.log('RSA keypair generated');
''',
    },
}

TESTS["15_c_openssl_rsa"] = {
    "category": "Non-Compliant (Classical Asymmetric)",
    "expected": "NON_COMPLIANT",
    "desc": "C RSA-2048 key generation using OpenSSL.",
    "files": {
        "rsa_demo.c": '''/* Classical RSA-2048 key generation using OpenSSL. */
/* NOT post-quantum safe. */
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <stdio.h>

int main(void) {
    RSA *rsa = RSA_new();
    BIGNUM *e = BN_new();
    BN_set_word(e, RSA_F4);
    RSA_generate_key_ex(rsa, 2048, e, NULL);
    printf("RSA-2048 key generated\\n");
    RSA_free(rsa);
    BN_free(e);
    return 0;
}
''',
    },
}

TESTS["16_cpp_openssl_ec"] = {
    "category": "Non-Compliant (Classical Asymmetric)",
    "expected": "NON_COMPLIANT",
    "desc": "C++ elliptic-curve (P-256) key generation using OpenSSL.",
    "files": {
        "ec_demo.cpp": '''// Classical elliptic-curve key generation using OpenSSL (P-256).
// NOT post-quantum safe.
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <iostream>

int main() {
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_generate_key(key);
    std::cout << "EC P-256 key generated" << std::endl;
    EC_KEY_free(key);
    return 0;
}
''',
    },
}

TESTS["17_py_md5_hash"] = {
    "category": "Deprecated/Weak",
    "expected": "NON_COMPLIANT",
    "desc": "Python MD5 hashing - collision-broken since 2004.",
    "files": {
        "hash_demo.py": '''# Deprecated cryptographic hash function MD5 - collision-broken since 2004.
import hashlib

def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()

if __name__ == "__main__":
    print(hash_password("hunter2"))
''',
    },
}

TESTS["18_py_sha1_sign"] = {
    "category": "Deprecated/Weak",
    "expected": "NON_COMPLIANT",
    "desc": "RSA signature using deprecated SHA-1 digest.",
    "files": {
        "sign_demo.py": '''# RSA signature using deprecated SHA-1 digest.
# SHA-1 is cryptographically broken (SHAttered, 2017).
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

def sign(private_key, message: bytes):
    return private_key.sign(message, padding.PKCS1v15(), hashes.SHA1())

if __name__ == "__main__":
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    sig = sign(key, b"legacy-doc")
    print("Signed with RSA+SHA1:", len(sig))
''',
    },
}

TESTS["19_php_des_mcrypt"] = {
    "category": "Deprecated/Weak",
    "expected": "NON_COMPLIANT",
    "desc": "PHP DES encryption via the removed mcrypt extension.",
    "files": {
        "des_demo.php": '''<?php
// Deprecated DES encryption via the removed mcrypt extension.
// DES has a 56-bit key space and is trivially brute-forceable today.
$key = "8bytekey";
$iv = mcrypt_create_iv(mcrypt_get_iv_size(MCRYPT_DES, MCRYPT_MODE_CBC), MCRYPT_RAND);
$ciphertext = mcrypt_encrypt(MCRYPT_DES, $key, "sensitive-data", MCRYPT_MODE_CBC, $iv);
echo bin2hex($ciphertext);
?>
''',
    },
}

TESTS["20_js_crypto_des"] = {
    "category": "Deprecated/Weak",
    "expected": "NON_COMPLIANT",
    "desc": "JavaScript Triple-DES (3DES) symmetric cipher.",
    "files": {
        "des.js": '''// Deprecated Triple-DES (3DES/EDE3) symmetric cipher.
// Deprecated by NIST since 2023; weak 112-bit effective security.
const crypto = require('crypto');

const key = crypto.randomBytes(24);
const iv = crypto.randomBytes(8);
const cipher = crypto.createCipheriv('des-ede3-cbc', key, iv);
let encrypted = cipher.update('sensitive-payload', 'utf8', 'hex');
encrypted += cipher.final('hex');
console.log(encrypted);
''',
    },
}

TESTS["21_java_des_cipher"] = {
    "category": "Deprecated/Weak",
    "expected": "NON_COMPLIANT",
    "desc": "Java DES symmetric cipher.",
    "files": {
        "DesCipher.java": '''// Deprecated DES symmetric cipher.
import javax.crypto.*;
import javax.crypto.spec.*;

public class DesCipher {
    public static void main(String[] args) throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("DES");
        SecretKey key = kg.generateKey();
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] ct = cipher.doFinal("legacy-record".getBytes());
        System.out.println("Encrypted length: " + ct.length);
    }
}
''',
    },
}

TESTS["22_c_rc4"] = {
    "category": "Deprecated/Weak",
    "expected": "NON_COMPLIANT",
    "desc": "C hand-rolled RC4 stream cipher (no library import).",
    "files": {
        "rc4_demo.c": '''/* Deprecated RC4 stream cipher - biased keystream, banned in TLS since 2015. */
#include <stdio.h>
#include <string.h>

void rc4_ksa(unsigned char *key, int keylen, unsigned char *S) {
    int j = 0;
    for (int i = 0; i < 256; i++) S[i] = i;
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % keylen]) % 256;
        unsigned char tmp = S[i]; S[i] = S[j]; S[j] = tmp;
    }
}

void rc4_prga(unsigned char *S, unsigned char *data, int len) {
    int i = 0, j = 0;
    for (int n = 0; n < len; n++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        unsigned char tmp = S[i]; S[i] = S[j]; S[j] = tmp;
        data[n] ^= S[(S[i] + S[j]) % 256];
    }
}

int main(void) {
    unsigned char key[] = "weakkey1";
    unsigned char S[256];
    unsigned char data[] = "top-secret-memo";
    rc4_ksa(key, 8, S);
    rc4_prga(S, data, strlen((char*)data));
    printf("RC4 keystream applied\\n");
    return 0;
}
''',
    },
}

TESTS["23_py_hybrid_x25519_kyber"] = {
    "category": "Hybrid/Transitional",
    "expected": "TRANSITIONAL_COMPLIANT",
    "desc": "Python hybrid X25519 + ML-KEM-768 key exchange.",
    "files": {
        "hybrid_kem.py": '''# Hybrid key exchange combining classical X25519 with post-quantum ML-KEM-768.
# Transitional / defense-in-depth scheme recommended during PQC migration.
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import oqs

def hybrid_exchange():
    alice_x = x25519.X25519PrivateKey.generate()
    bob_x = x25519.X25519PrivateKey.generate()
    classical_secret = alice_x.exchange(bob_x.public_key())

    with oqs.KeyEncapsulation("ML-KEM-768") as kem:
        pk = kem.generate_keypair()
        ct, pqc_secret = kem.encap_secret(pk)

    combined = HKDF(algorithm=hashes.SHA384(), length=32, salt=None, info=b"hybrid-kex").derive(
        classical_secret + pqc_secret
    )
    return combined

if __name__ == "__main__":
    print("Hybrid shared secret bytes:", len(hybrid_exchange()))
''',
    },
}

TESTS["24_nginx_tls_hybrid_group"] = {
    "category": "Hybrid/Transitional (Config Only)",
    "expected": "TRANSITIONAL_COMPLIANT",
    "desc": "nginx.conf enabling X25519Kyber768Draft00 hybrid TLS group (no source code, config file only).",
    "files": {
        "nginx.conf": '''# TLS 1.3 configuration enabling hybrid post-quantum key exchange group.
# X25519Kyber768Draft00 combines classical X25519 with ML-KEM-768.
server {
    listen 443 ssl;
    server_name example.com;

    ssl_protocols TLSv1.3;
    ssl_ecdh_curve X25519Kyber768Draft00:X25519:prime256v1;
    ssl_certificate /etc/ssl/certs/example.com.crt;
    ssl_certificate_key /etc/ssl/private/example.com.key;
}
''',
    },
}

TESTS["25_go_hybrid_tls_circl"] = {
    "category": "Hybrid/Transitional",
    "expected": "TRANSITIONAL_COMPLIANT",
    "desc": "Go TLS 1.3 client with hybrid X25519+Kyber768 curve preference.",
    "files": {
        "hybrid_tls.go": '''// TLS 1.3 client configured with hybrid X25519+Kyber768 key exchange
// using Cloudflare's circl/tls hybrid group support.
package main

import (
	"crypto/tls"
	"fmt"
)

func main() {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{
			tls.X25519Kyber768Draft00,
			tls.X25519,
		},
	}
	fmt.Println("Hybrid curve preferences configured:", len(cfg.CurvePreferences))
}
''',
    },
}

TESTS["26_comment_only_mention"] = {
    "category": "Edge Case (False-Positive Bait)",
    "expected": "NO_CRYPTO_DETECTED",
    "desc": "RSA/Kyber only mentioned in a TODO comment; actual code does no key generation at all.",
    "files": {
        "util.py": '''# TODO: migrate our key exchange from RSA to a PQC KEM such as Kyber
# once the compliance team finalizes the algorithm choice.
# Ticket: SEC-4471

import os

def generate_session_token():
    # Not cryptographic key generation - just a random session id.
    return os.urandom(16).hex()
''',
    },
}

TESTS["27_string_literal_mention"] = {
    "category": "Edge Case (False-Positive Bait)",
    "expected": "COMPLIANT_SYMMETRIC_ONLY",
    "desc": "'RSA' and 'Kyber' appear only inside a log string; actual crypto call is AES-GCM.",
    "files": {
        "logger.js": '''// Structured logging around a key-rotation job.
// Note: the string below is log text only, not an actual RSA call.
const crypto = require('crypto');

function rotateKey() {
  console.log('Migrating from RSA to Kyber for the next key rotation cycle');
  const key = crypto.randomBytes(32); // AES-256 key material
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  return cipher;
}

rotateKey();
''',
    },
}

TESTS["28_misleading_naming"] = {
    "category": "Edge Case (False-Positive Bait)",
    "expected": "COMPLIANT_SYMMETRIC_ONLY",
    "desc": "Function/variable named 'rsa' but implementation actually returns AES key material - tests naming vs. semantics.",
    "files": {
        "keymgr.py": '''# Function and variable names reference "rsa" for historical reasons,
# but the implementation actually generates symmetric AES key material.
# Naming left unchanged to avoid breaking downstream callers.
import os

def generate_rsa_key():
    rsa_key = os.urandom(32)  # actually an AES-256 key, not RSA
    return rsa_key

if __name__ == "__main__":
    print(len(generate_rsa_key()))
''',
    },
}

TESTS["29_aliased_import"] = {
    "category": "Edge Case (Detection Evasion)",
    "expected": "NON_COMPLIANT",
    "desc": "RSA imported under a 'pq_' alias - tests whether scanner resolves import aliasing.",
    "files": {
        "keygen.py": '''# Import aliasing obscures the underlying algorithm name.
from cryptography.hazmat.primitives.asymmetric import rsa as pq_rsa

def generate_keypair():
    # Despite the "pq_" alias, this generates a classical RSA-3072 key.
    return pq_rsa.generate_private_key(public_exponent=65537, key_size=3072)

if __name__ == "__main__":
    key = generate_keypair()
    print(key.key_size)
''',
    },
}

TESTS["30_dead_code_unreachable"] = {
    "category": "Edge Case (Reachability)",
    "expected": "NON_COMPLIANT_UNREACHABLE",
    "desc": "RSA call sits behind a permanently-False feature flag - tests reachability analysis vs. naive text matching.",
    "files": {
        "legacy.py": '''# Legacy RSA code path kept for reference but never executed.
from cryptography.hazmat.primitives.asymmetric import rsa

FEATURE_FLAG_LEGACY_CRYPTO = False

def get_keypair():
    if FEATURE_FLAG_LEGACY_CRYPTO:
        # Unreachable in current build: FEATURE_FLAG_LEGACY_CRYPTO is always False.
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    else:
        raise NotImplementedError("PQC key generation not yet wired up")
''',
    },
}

TESTS["31_manifest_only_requirements"] = {
    "category": "Edge Case (Dependency-Only Signal)",
    "expected": "NO_CODE_USAGE_DEPENDENCY_RISK",
    "desc": "requirements.txt lists RSA-capable libraries but no .py file actually calls them.",
    "files": {
        "requirements.txt": "pycryptodome==3.20.0\ncryptography==42.0.5\nflask==3.0.3\n",
        "README.md": '''# Service Skeleton

This repository only contains dependency manifests at this stage.
No cryptographic code has been implemented yet - `pycryptodome` and
`cryptography` are listed as anticipated dependencies for an upcoming
authentication module.
''',
    },
}

TESTS["32_manifest_only_package_json"] = {
    "category": "Edge Case (Dependency-Only Signal)",
    "expected": "NO_CODE_USAGE_DEPENDENCY_RISK",
    "desc": "package.json lists node-forge (RSA-capable) but no .js file imports it.",
    "files": {
        "package.json": '''{
  "name": "auth-service-skeleton",
  "version": "0.1.0",
  "dependencies": {
    "node-forge": "^1.3.1",
    "express": "^4.19.2"
  }
}
''',
        "index.html": '''<!doctype html>
<html>
  <head><title>Placeholder</title></head>
  <body>Service under construction.</body>
</html>
''',
    },
}

TESTS["33_mixed_lang_repo"] = {
    "category": "Edge Case (Mixed Verdict)",
    "expected": "MIXED",
    "desc": "Python backend uses ML-KEM-768 (compliant); JS frontend still uses RSA-OAEP (non-compliant).",
    "files": {
        "backend/kyber_server.py": '''# Backend key exchange endpoint using ML-KEM-768 (Kyber).
# Fully PQC-compliant per NIST FIPS 203.
import oqs

def handle_kem_request():
    with oqs.KeyEncapsulation("ML-KEM-768") as kem:
        pk = kem.generate_keypair()
        return pk
''',
        "frontend/legacy_rsa.js": '''// Legacy frontend crypto helper still using RSA-OAEP for a payments
// widget that has not yet been migrated to the new PQC backend.
const forge = require('node-forge');

function encryptWithRsa(publicKeyPem, data) {
  const publicKey = forge.pki.publicKeyFromPem(publicKeyPem);
  return publicKey.encrypt(data, 'RSA-OAEP');
}

module.exports = { encryptWithRsa };
''',
    },
}

TESTS["34_minified_js_rsa"] = {
    "category": "Edge Case (Obfuscation)",
    "expected": "NON_COMPLIANT",
    "desc": "RSA keygen call buried in a single-line minified JS bundle.",
    "files": {
        "bundle.min.js": '''!function(){"use strict";var a=require("crypto"),b=a.generateKeyPairSync("rsa",{modulusLength:2048,publicKeyEncoding:{type:"spki",format:"pem"},privateKeyEncoding:{type:"pkcs8",format:"pem"}});console.log("k",b.publicKey.length)}();
''',
    },
}

TESTS["36_noncode_only"] = {
    "category": "Edge Case (No Code)",
    "expected": "NO_CRYPTO_DETECTED",
    "desc": "Zip contains only README/LICENSE/asset placeholder - no source code at all.",
    "files": {
        "README.md": '''# Marketing Landing Page Assets

This archive contains only static marketing assets - no source code
and no cryptographic operations of any kind.
''',
        "LICENSE": '''MIT License

Copyright (c) 2026 Example Corp

Permission is hereby granted, free of charge, to any person obtaining a copy...
''',
        "assets/logo_placeholder.txt": "[binary image placeholder - not a real image, for zip-structure testing only]\n",
    },
}

TESTS["37_deep_nested_folder"] = {
    "category": "Edge Case (Recursive Scanning)",
    "expected": "COMPLIANT",
    "desc": "PQC KEM usage buried five directories deep.",
    "files": {
        "a/b/c/d/e/kyber_deep.py": '''# PQC KEM usage buried five directories deep - tests recursive scanning.
# Fully PQC-compliant per NIST FIPS 203.
import oqs

def deep_kem():
    with oqs.KeyEncapsulation("ML-KEM-1024") as kem:
        pk = kem.generate_keypair()
        return pk
''',
    },
}

TESTS["38_large_file_buried_rsa"] = {
    "category": "Edge Case (Scan Depth)",
    "expected": "NON_COMPLIANT",
    "desc": "~700-line file with one RSA call buried in the middle - tests full-file scanning vs. truncated reads.",
    "files": {
        "big_module.py": large_content,
    },
}

TESTS["39_unusual_extensions"] = {
    "category": "Edge Case (File Type Coverage)",
    "expected": "NON_COMPLIANT",
    "desc": "Crypto code in non-standard extensions: .java.bak (archived) and .pyx (Cython).",
    "files": {
        "OldService.java.bak": '''// Archived service class (renamed with .bak so it is excluded from the
// build) that still performs classical RSA signing.
import java.security.*;

public class OldService {
    public static byte[] sign(PrivateKey key, byte[] data) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(key);
        sig.update(data);
        return sig.sign();
    }
}
''',
        "legacy.pyx": '''# Cython extension module performing ECDSA verification.
# NOT post-quantum safe.
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

def verify_ecdsa(public_key, signature, message):
    public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
    return True
''',
    },
}

TESTS["40_toy_rsa_naive"] = {
    "category": "Edge Case (Semantic Detection)",
    "expected": "NON_COMPLIANT_SEMANTIC",
    "desc": "Textbook RSA implemented from scratch with modular exponentiation, no library imports at all.",
    "files": {
        "naive_rsa.py": '''# Textbook/toy RSA implementation written from scratch without importing
# any crypto library. Tests whether a scanner does semantic detection
# (recognizing modular exponentiation + public/private exponents as RSA)
# rather than relying solely on import-statement pattern matching.

def modexp(base, exp, mod):
    result = 1
    base %= mod
    while exp > 0:
        if exp & 1:
            result = (result * base) % mod
        exp >>= 1
        base = (base * base) % mod
    return result

def toy_keygen(p, q, e=65537):
    n = p * q
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    return (e, n), (d, n)

def encrypt(m, pubkey):
    e, n = pubkey
    return modexp(m, e, n)

def decrypt(c, privkey):
    d, n = privkey
    return modexp(c, d, n)

if __name__ == "__main__":
    pub, priv = toy_keygen(61, 53)
    ct = encrypt(42, pub)
    pt = decrypt(ct, priv)
    print("Recovered:", pt)
''',
    },
}

TESTS["42_yaml_cipher_suite_config"] = {
    "category": "Edge Case (Infra Config, Not Code)",
    "expected": "NON_COMPLIANT",
    "desc": "Kubernetes ingress YAML specifying classical ECDHE-RSA TLS cipher suites.",
    "files": {
        "ingress-tls.yaml": '''apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: payments-api
  annotations:
    nginx.ingress.kubernetes.io/ssl-ciphers: "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256"
    nginx.ingress.kubernetes.io/ssl-protocols: "TLSv1.2 TLSv1.3"
spec:
  tls:
    - hosts: ["api.example.com"]
      secretName: payments-tls
''',
    },
}

TESTS["43_multi_algo_single_file"] = {
    "category": "Edge Case (Mixed Verdict, Single File)",
    "expected": "MIXED",
    "desc": "Single file with both a legacy RSA path and a new ML-KEM path, branched by API version.",
    "files": {
        "migration_inprogress.py": '''# Partial PQC migration: legacy RSA path retained for backward
# compatibility while new traffic is routed through ML-KEM.
# Expected verdict: mixed / transitional.
from cryptography.hazmat.primitives.asymmetric import rsa
import oqs

def legacy_encrypt_setup():
    # Old code path, still reachable for clients on API v1.
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

def pq_encrypt_setup():
    # New code path for clients on API v2+.
    with oqs.KeyEncapsulation("ML-KEM-768") as kem:
        return kem.generate_keypair()

def get_keypair(api_version: int):
    if api_version >= 2:
        return pq_encrypt_setup()
    return legacy_encrypt_setup()
''',
    },
}

# ---------------------------------------------------------------------------
# Write out every test-case directory and zip it
# ---------------------------------------------------------------------------
manifest_rows = []

for name, spec in sorted(TESTS.items()):
    tdir = os.path.join(BASE, name)
    if os.path.exists(tdir):
        shutil.rmtree(tdir)
    os.makedirs(tdir)
    for relpath, content in spec["files"].items():
        fpath = os.path.join(tdir, relpath)
        os.makedirs(os.path.dirname(fpath), exist_ok=True) if os.path.dirname(fpath) else None
        with open(fpath, "w") as f:
            f.write(content)
    zpath = os.path.join(OUT, f"{name}.zip")
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(tdir):
            for fn in files:
                full = os.path.join(root, fn)
                arc = os.path.relpath(full, tdir)
                zf.write(full, arc)
    manifest_rows.append([f"{name}.zip", spec["category"], spec["expected"], spec["desc"]])

# ---------------------------------------------------------------------------
# 35: empty zip (zero files) - special case
# ---------------------------------------------------------------------------
with zipfile.ZipFile(os.path.join(OUT, "35_empty_zip.zip"), "w") as zf:
    pass
manifest_rows.append(["35_empty_zip.zip", "Edge Case (Malformed Input)", "NO_FILES_ERROR_HANDLING",
                       "Zip archive containing zero files - tests graceful handling of empty input."])

# ---------------------------------------------------------------------------
# 41: real PEM key material, no source code at all
# ---------------------------------------------------------------------------
pem_dir = os.path.join(BASE, "41_pem_key_files")
os.makedirs(pem_dir, exist_ok=True)
subprocess.run(["openssl", "genrsa", "-out", os.path.join(pem_dir, "id_rsa.pem"), "2048"],
               check=True, capture_output=True)
subprocess.run(["openssl", "rsa", "-in", os.path.join(pem_dir, "id_rsa.pem"),
                 "-pubout", "-out", os.path.join(pem_dir, "id_rsa_pub.pem")],
               check=True, capture_output=True)
subprocess.run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout",
                 "-out", os.path.join(pem_dir, "ec_private.pem")],
               check=True, capture_output=True)
with open(os.path.join(pem_dir, "README.md"), "w") as f:
    f.write("# Key Material Only\n\nThis archive contains real (but disposable, meaningless) "
            "RSA-2048 and EC P-256 key files with no accompanying source code. Tests whether "
            "the scanner inspects key/cert file headers directly, not just source code.\n")

zpath = os.path.join(OUT, "41_pem_key_files.zip")
with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as zf:
    for root, dirs, files in os.walk(pem_dir):
        for fn in files:
            full = os.path.join(root, fn)
            arc = os.path.relpath(full, pem_dir)
            zf.write(full, arc)
manifest_rows.append(["41_pem_key_files.zip", "Non-Compliant (Key Material)", "NON_COMPLIANT",
                       "Real RSA-2048 and EC P-256 PEM key files, no source code - tests key-file header detection."])

# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------
manifest_rows.sort(key=lambda r: r[0])
with open(os.path.join(BASE, "MANIFEST.csv"), "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["zip_file", "category", "expected_verdict", "description"])
    for row in manifest_rows:
        w.writerow(row)

print(f"Generated {len(manifest_rows)} test-case zip files in {OUT}")
