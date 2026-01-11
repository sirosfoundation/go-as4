package auth

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
)

// verifyRS256 verifies an RS256 (RSA-SHA256) signature
func verifyRS256(key *rsa.PublicKey, message, sig []byte) error {
	return verifyRSA(key, message, sig, crypto.SHA256, sha256.New())
}

// verifyRS384 verifies an RS384 (RSA-SHA384) signature
func verifyRS384(key *rsa.PublicKey, message, sig []byte) error {
	return verifyRSA(key, message, sig, crypto.SHA384, sha512.New384())
}

// verifyRS512 verifies an RS512 (RSA-SHA512) signature
func verifyRS512(key *rsa.PublicKey, message, sig []byte) error {
	return verifyRSA(key, message, sig, crypto.SHA512, sha512.New())
}

func verifyRSA(key *rsa.PublicKey, message, sig []byte, hash crypto.Hash, h hash.Hash) error {
	h.Write(message)
	digest := h.Sum(nil)
	return rsa.VerifyPKCS1v15(key, hash, digest, sig)
}
