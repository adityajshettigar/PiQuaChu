// Insecure Go sample — should trigger Go negative rules.
package main

import (
	"crypto/ecdsa"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
)

func legacyRSA() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048) // deprecated-go-rsa
}

func legacyECDSA() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(ecdsa.P256(), rand.Reader) // deprecated-go-ecdsa
}

func legacyHash(data []byte) [16]byte {
	h := md5.Sum(data) // deprecated-go-hash
	return h
}

func legacyTLS() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS10} // deprecated-go-tlsv1
}

func unused() [20]byte {
	return sha1.Sum([]byte("x")) // deprecated-go-hash
}
