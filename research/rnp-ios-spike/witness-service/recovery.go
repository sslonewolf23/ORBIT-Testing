package main

import (
	"crypto/hmac"
	"crypto/sha256"
)

// The enrollment verifier is HMAC(serverPepper, domain || recoverySecret).
// For recoverability without storing the secret, proof uses a second domain
// keyed by that verifier. The client derives the same verifier only if it has
// the recovery secret and server pepper? It cannot know server pepper; instead
// this function is intentionally replaced by a client-verifiable construction
// in the protocol design before production. See README limitations.
func recoveryProofFromVerifier(verifier, challenge []byte, oldKeyID, newKeyID string) []byte {
	mac := hmac.New(sha256.New, verifier)
	mac.Write([]byte("ORBIT-RECOVERY-AUTH-V1\\x00"))
	mac.Write(challenge)
	mac.Write([]byte{0})
	mac.Write([]byte(oldKeyID))
	mac.Write([]byte{0})
	mac.Write([]byte(newKeyID))
	return mac.Sum(nil)
}
