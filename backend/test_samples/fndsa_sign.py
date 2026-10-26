"""FN-DSA (FALCON-512) algorithm-evidence sample — should trigger the positive
FIPS 206 rule (pqc-fndsa-python). FALCON is a selected NIST algorithm, but
FIPS 206 was still in development at the registry review date; this is not a
finalized-standard pass.
"""
import oqs


def sign_and_verify() -> bool:
    """Sign and verify with FN-DSA-512 (Falcon-512) via liboqs-python."""
    message = b"firmware-update-v5.3.0"

    with oqs.Signature("Falcon-512") as signer:
        public_key = signer.generate_keypair()
        signature = signer.sign(message)

    with oqs.Signature("Falcon-512") as verifier:
        return verifier.verify(message, signature, public_key)
