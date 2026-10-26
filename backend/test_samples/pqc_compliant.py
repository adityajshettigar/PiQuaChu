"""PQC-compliant sample — should trigger the positive FIPS 203/204/205/206 rules."""
import oqs


def ml_kem_key_exchange():
    """FIPS 203 — ML-KEM (Kyber) key encapsulation."""
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    public_key, secret_key = kem.generate_keypair()
    ciphertext, shared_secret = kem.encap_secret(public_key)
    peer_secret = kem.decap_secret(ciphertext)
    assert peer_secret == shared_secret
    return public_key, ciphertext


def ml_dsa_sign(message: bytes):
    """FIPS 204 — ML-DSA (Dilithium) digital signature."""
    sig = oqs.Signature("ML-DSA-65")
    public_key, secret_key = sig.generate_keypair()
    signature = sig.sign(message)
    assert sig.verify(message, signature, public_key)
    return signature


def slh_dsa_backup_sign(message: bytes):
    """FIPS 205 — SLH-DSA (SPHINCS+) hash-based backup signature."""
    sig = oqs.Signature("SLH-DSA-SHA2-128s")
    public_key, secret_key = sig.generate_keypair()
    return sig.sign(message)
