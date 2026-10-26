// Insecure C sample — should trigger C/C++ negative rules.
#include <openssl/evp.h>
#include <openssl/rsa.h>

void legacy_md5(void) {
    MD5_Init(NULL);          // deprecated-c-openssl-md5
    EVP_md5();               // deprecated-c-openssl-md5
}

void legacy_rsa(void) {
    RSA_generate_key(1024, RSA_F4, NULL, NULL); // deprecated-c-openssl-rsa
    EVP_PKEY_RSA;            // deprecated-c-openssl-rsa
}

void legacy_des(void) {
    EVP_des_ecb();           // deprecated-c-openssl-symmetric
    EVP_des_ede3_cbc();      // deprecated-c-openssl-symmetric
}
