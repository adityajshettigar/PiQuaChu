// PQC-compliant C sample — should trigger positive C rules via liboqs.
#include <oqs/oqs.h>

void ml_kem_keygen(void) {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768); // pqc-mlkem-c
    OQS_KEM_alg_is_supported(OQS_KEM_alg_ml_kem_768);
}

void ml_dsa_sign(void) {
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65); // pqc-mldsa-c
    OQS_SIG_alg_is_supported(OQS_SIG_alg_ml_dsa_65);
}

void slh_dsa_backup(void) {
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_slh_dsa_sha2_128s); // pqc-slhdsa-c
}
