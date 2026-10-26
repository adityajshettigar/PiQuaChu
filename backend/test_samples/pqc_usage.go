// PQC-compliant Go sample — should trigger positive Go rules.
package main

import (
	"crypto/rand"
	"fmt"

	"github.com/cloudflare/circl/kem/mlkem"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/sphincs"
)

func main() {
	// FIPS 203 — ML-KEM
	seed := make([]byte, mlkem.SeedSize)
	rand.Read(seed)
	pk, sk, err := mlkem.NewMLKEM768().GenerateKeyPair(rand.Reader)
	fmt.Println(err, pk, sk)

	// FIPS 204 — ML-DSA
	pk2, sk2, _ := mldsa65.GenerateKey(rand.Reader)
	fmt.Println(pk2, sk2)

	// FIPS 205 — SLH-DSA
	pk3, sk3, _ := sphincs.GenerateKey(rand.Reader)
	fmt.Println(pk3, sk3)
}
