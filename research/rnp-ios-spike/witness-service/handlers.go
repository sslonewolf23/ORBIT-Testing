package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

func (s *service) challenge(w http.ResponseWriter, r *http.Request) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil { jsonError(w, 503, "unavailable"); return }
	digest := sha256.Sum256(value)
	expires := s.now().Add(5*time.Minute).Unix()
	_, _ = s.db.Exec("DELETE FROM challenges WHERE expires_at<? OR consumed=1", s.now().Unix())
	if _, err := s.db.Exec("INSERT INTO challenges(digest,expires_at,consumed) VALUES(?,?,0)", digest[:], expires); err != nil {
		jsonError(w, 503, "unavailable"); return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"challenge":base64.StdEncoding.EncodeToString(value)})
}

func (s *service) register(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := decodeJSON(w, r, &req); err != nil { jsonError(w, 400, "invalid request"); return }
	if len(req.KeyID) == 0 || len(req.KeyID) > 128 {
		jsonError(w, 400, "invalid request")
		return
	}
	if _, err := decodeAppAttestKeyID(req.KeyID); err != nil {
		jsonError(w, 400, "invalid request")
		return
	}
	challenge, err := decodeB64(req.Challenge, 32, 32)
	if err != nil { jsonError(w, 400, "invalid request"); return }
	credential, credErr := decodeB64(req.RecoveryCredential, 32, 32)
	if credErr != nil { jsonError(w, 400, "invalid recovery credential"); return }
	verifier, verifierErr := s.recoveryVerifier(credential)
	if verifierErr != nil { jsonError(w, 503, "recovery unavailable"); return }
	attestation, err := decodeB64(req.Attestation, 1, 512<<10)
	if err != nil { jsonError(w, 400, "invalid request"); return }
	attDigest := sha256.Sum256(attestation)
	// Lost-response retry: the exact same proof is idempotent, while any
	// different proof for an already registered key is permanently rejected.
	var prior, priorVerifier []byte
	err = s.db.QueryRow("SELECT attestation_digest,recovery_verifier FROM installations WHERE key_id=?", req.KeyID).Scan(&prior, &priorVerifier)
	if err == nil {
		if equalBytes(prior, attDigest[:]) && equalBytes(priorVerifier, verifier) { w.WriteHeader(http.StatusNoContent); return }
		jsonError(w, 409, "registration conflict"); return
	}
	if err != sql.ErrNoRows { jsonError(w, 503, "unavailable"); return }

	challengeDigest := sha256.Sum256(challenge)
	var challengeValid int
	if err := s.db.QueryRow(
		"SELECT 1 FROM challenges WHERE digest=? AND consumed=0 AND expires_at>=?",
		challengeDigest[:], s.now().Unix()).Scan(&challengeValid); err != nil {
		jsonError(w, 409, "challenge expired or consumed")
		return
	}

	publicDER, err := s.verifyAttestation(req.KeyID, challenge, attestation)
	if err != nil { jsonError(w, 403, "attestation rejected"); return }

	tx, err := s.db.Begin()
	if err != nil { jsonError(w, 503, "unavailable"); return }
	defer tx.Rollback()
	res, err := tx.Exec("UPDATE challenges SET consumed=1 WHERE digest=? AND consumed=0 AND expires_at>=?",
		challengeDigest[:], s.now().Unix())
	if err != nil { jsonError(w, 503, "unavailable"); return }
	changed, err := res.RowsAffected()
	if err != nil || changed != 1 { jsonError(w, 409, "challenge expired or consumed"); return }
	zero := make([]byte, 32)
	rev := make([]byte, 8)
	if _, err = tx.Exec("INSERT INTO installations(key_id,public_key,attestation_digest,assertion_counter,revision,head_digest,tombstone,created_at,recovery_verifier) VALUES(?,?,?,0,?,?,1,?,?)",
		req.KeyID, publicDER, attDigest[:], rev, zero, s.now().Unix(), verifier); err != nil {
		jsonError(w, 409, "registration conflict"); return
	}
	if err = tx.Commit(); err != nil { jsonError(w, 503, "unavailable"); return }
	w.WriteHeader(http.StatusNoContent)
}

func (s *service) head(w http.ResponseWriter, r *http.Request) {
	req, raw, assertion, ok := s.readSigned(w, r)
	if !ok { return }
	if parseHeadRequest(raw, req.KeyID) != nil { jsonError(w, 400, "invalid request"); return }
	tx, err := s.db.Begin()
	if err != nil { jsonError(w, 503, "unavailable"); return }
	defer tx.Rollback()
	stored, counter, err := s.authenticateAssertion(tx, req.KeyID, raw, assertion)
	if err != nil { jsonError(w, 403, "request rejected"); return }
	if err = updateCounter(tx, req.KeyID, counter); err != nil { jsonError(w, 409, "assertion replay"); return }
	if err = tx.Commit(); err != nil { jsonError(w, 503, "unavailable"); return }
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"revision": binary.BigEndian.Uint64(stored.Revision[:]),
		"digest": base64.StdEncoding.EncodeToString(stored.Digest[:]),
		"tombstone": stored.Tombstone,
	})
}

func (s *service) compareAndSwap(w http.ResponseWriter, r *http.Request) {
	req, raw, assertion, ok := s.readSigned(w, r)
	if !ok { return }
	old, next, err := parseCASRequest(raw, req.KeyID)
	if err != nil || !validTransition(old, next) { jsonError(w, 400, "invalid transition"); return }
	tx, err := s.db.Begin()
	if err != nil { jsonError(w, 503, "unavailable"); return }
	defer tx.Rollback()
	stored, counter, err := s.authenticateAssertion(tx, req.KeyID, raw, assertion)
	if err != nil { jsonError(w, 403, "request rejected"); return }
	current := stored.Head
	if current != old {
		// Idempotent retry after the server committed but the response was lost.
		if current == next {
			if err = updateCounter(tx, req.KeyID, counter); err != nil { jsonError(w, 409, "assertion replay"); return }
			if err = tx.Commit(); err != nil { jsonError(w, 503, "unavailable"); return }
			w.WriteHeader(http.StatusNoContent); return
		}
		jsonError(w, 409, "head conflict"); return
	}
	if err = updateCounter(tx, req.KeyID, counter); err != nil { jsonError(w, 409, "assertion replay"); return }
	res, err := tx.Exec("UPDATE installations SET revision=?,head_digest=?,tombstone=? WHERE key_id=? AND revision=? AND head_digest=? AND tombstone=?",
		u64Bytes(next.Revision), next.Digest[:], boolInt(next.Tombstone), req.KeyID,
		u64Bytes(old.Revision), old.Digest[:], boolInt(old.Tombstone))
	if err != nil { jsonError(w, 503, "unavailable"); return }
	changed, err := res.RowsAffected()
	if err != nil || changed != 1 { jsonError(w, 409, "head conflict"); return }
	if err = tx.Commit(); err != nil { jsonError(w, 503, "unavailable"); return }
	w.WriteHeader(http.StatusNoContent)
}

type storedInstallation struct {
	PublicKey []byte
	Counter uint32
	Revision []byte
	Digest [32]byte
	Tombstone bool
	Head witnessHead
}

func (s *service) readSigned(w http.ResponseWriter, r *http.Request) (signedRequest, []byte, []byte, bool) {
	var req signedRequest
	if err := decodeJSON(w, r, &req); err != nil { jsonError(w, 400, "invalid request"); return req,nil,nil,false }
	raw, err := decodeB64(req.Request, 1, 4096)
	if err != nil { jsonError(w, 400, "invalid request"); return req,nil,nil,false }
	assertion, err := decodeB64(req.Assertion, 1, 64<<10)
	if err != nil { jsonError(w, 400, "invalid request"); return req,nil,nil,false }
	if req.KeyID == "" || len(req.KeyID) > 128 { jsonError(w, 400, "invalid request"); return req,nil,nil,false }
	return req, raw, assertion, true
}

func (s *service) authenticateAssertion(tx *sql.Tx, keyID string, request, assertion []byte) (storedInstallation, uint32, error) {
	var result storedInstallation
	var counter uint32
	var tomb int
	var digest []byte
	err := tx.QueryRow("SELECT public_key,assertion_counter,revision,head_digest,tombstone FROM installations WHERE key_id=?", keyID).
		Scan(&result.PublicKey, &result.Counter, &result.Revision, &digest, &tomb)
	if err != nil { return result,0,err }
	if len(result.Revision) != 8 || len(digest) != 32 || (tomb != 0 && tomb != 1) {
		return result,0,errors.New("corrupt witness row")
	}
	copy(result.Digest[:], digest)
	result.Tombstone = tomb == 1
	result.Head.Revision = binary.BigEndian.Uint64(result.Revision)
	result.Head.Digest = result.Digest
	result.Head.Tombstone = result.Tombstone
	counter, err = s.verifyAssertion(result.PublicKey, request, assertion)
	if err != nil || counter <= result.Counter { return result,0,errors.New("assertion counter replay") }
	return result,counter,nil
}

func updateCounter(tx *sql.Tx, keyID string, counter uint32) error {
	res, err := tx.Exec("UPDATE installations SET assertion_counter=? WHERE key_id=? AND assertion_counter<?",
		counter, keyID, counter)
	if err != nil { return err }
	n, err := res.RowsAffected()
	if err != nil || n != 1 { return errors.New("assertion counter conflict") }
	return nil
}

func u64Bytes(v uint64) []byte { b:=make([]byte,8); binary.BigEndian.PutUint64(b,v); return b }
func boolInt(v bool) int { if v { return 1 }; return 0 }
func equalBytes(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}


func (s *service) recoveryChallenge(w http.ResponseWriter, r *http.Request) {
	var req recoveryChallengeRequest
	if err := decodeJSON(w, r, &req); err != nil || req.NewKeyID == "" || len(req.NewKeyID) > 128 {
		jsonError(w, 400, "invalid recovery request"); return
	}
	if _, err := decodeAppAttestKeyID(req.NewKeyID); err != nil { jsonError(w, 400, "invalid replacement key"); return }
	credential, err := decodeB64(req.RecoveryCredential, 32, 32)
	if err != nil { jsonError(w, 400, "recovery unavailable"); return }
	verifier, err := s.recoveryVerifier(credential)
	if err != nil { jsonError(w, 503, "unavailable"); return }
	var oldKeyID string
	if err := s.db.QueryRow("SELECT key_id FROM installations WHERE recovery_verifier=?", verifier).Scan(&oldKeyID); err != nil {
		// Do not reveal whether an installation or credential exists.
		jsonError(w, 403, "recovery unavailable"); return
	}
	var replacementExists int
	if err := s.db.QueryRow("SELECT 1 FROM installations WHERE key_id=?", req.NewKeyID).Scan(&replacementExists); err == nil {
		jsonError(w, 409, "replacement key already registered"); return
	} else if err != sql.ErrNoRows { jsonError(w, 503, "unavailable"); return }
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil { jsonError(w, 503, "unavailable"); return }
	digest := sha256.Sum256(challenge)
	_, _ = s.db.Exec("DELETE FROM recovery_challenges WHERE expires_at<? OR consumed=1", s.now().Unix())
	if _, err := s.db.Exec("INSERT INTO recovery_challenges(digest,old_key_id,new_key_id,expires_at,consumed) VALUES(?,?,?,?,0)", digest[:], oldKeyID, req.NewKeyID, s.now().Add(5*time.Minute).Unix()); err != nil {
		jsonError(w, 503, "unavailable"); return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"challenge": base64.StdEncoding.EncodeToString(challenge)})
}

func (s *service) recoverKey(w http.ResponseWriter, r *http.Request) {
	var req recoveryRequest
	if err := decodeJSON(w, r, &req); err != nil || req.NewKeyID == "" {
		jsonError(w, 400, "invalid recovery request"); return
	}
	if _, err := decodeAppAttestKeyID(req.NewKeyID); err != nil { jsonError(w, 400, "invalid replacement key"); return }
	challenge, err := decodeB64(req.Challenge, 32, 32); if err != nil { jsonError(w, 400, "invalid recovery request"); return }
	credential, err := decodeB64(req.RecoveryCredential, 32, 32); if err != nil { jsonError(w, 400, "invalid recovery request"); return }
	attestation, err := decodeB64(req.Attestation, 1, 512<<10); if err != nil { jsonError(w, 400, "invalid recovery request"); return }
	verifier, err := s.recoveryVerifier(credential)
	if err != nil { jsonError(w, 403, "recovery rejected"); return }
	challengeDigest := sha256.Sum256(challenge)
	var oldKeyID, storedNew string
	var expires int64
	var consumed int
	err = s.db.QueryRow("SELECT c.old_key_id,c.new_key_id,c.expires_at,c.consumed FROM recovery_challenges c JOIN installations i ON i.key_id=c.old_key_id WHERE c.digest=? AND i.recovery_verifier=?", challengeDigest[:], verifier).Scan(&oldKeyID,&storedNew,&expires,&consumed)
	if err != nil || consumed != 0 || expires < s.now().Unix() || storedNew != req.NewKeyID {
		jsonError(w, 403, "recovery rejected"); return
	}
	publicDER, err := s.verifyAttestation(req.NewKeyID, challenge, attestation)
	if err != nil { jsonError(w, 403, "replacement attestation rejected"); return }
	tx, err := s.db.Begin(); if err != nil { jsonError(w, 503, "unavailable"); return }; defer tx.Rollback()
	var revision, headDigest []byte
	var tombstone int
	if err = tx.QueryRow("SELECT revision,head_digest,tombstone FROM installations WHERE key_id=? AND recovery_verifier=?", oldKeyID, verifier).Scan(&revision,&headDigest,&tombstone); err != nil || len(revision)!=8 || len(headDigest)!=32 {
		jsonError(w, 403, "recovery rejected"); return
	}
	res, err := tx.Exec("UPDATE recovery_challenges SET consumed=1 WHERE digest=? AND consumed=0 AND expires_at>=?", challengeDigest[:], s.now().Unix())
	if err != nil { jsonError(w,503,"unavailable"); return }
	n,_ := res.RowsAffected()
	if n!=1 { jsonError(w,409,"recovery challenge consumed"); return }
	if _, err = tx.Exec("INSERT INTO key_recovery_history(old_key_id,new_key_id,recovered_at,prior_revision,prior_head_digest,prior_tombstone) VALUES(?,?,?,?,?,?)", oldKeyID,req.NewKeyID,s.now().Unix(),revision,headDigest,tombstone); err != nil {
		jsonError(w,409,"recovery conflict"); return
	}
	attDigest := sha256.Sum256(attestation)
	if _, err = tx.Exec("UPDATE installations SET key_id=?,public_key=?,attestation_digest=?,assertion_counter=0 WHERE key_id=? AND recovery_verifier=?", req.NewKeyID,publicDER,attDigest[:],oldKeyID,verifier); err != nil {
		jsonError(w,409,"recovery conflict"); return
	}
	if err = tx.Commit(); err != nil { jsonError(w,503,"unavailable"); return }
	w.WriteHeader(http.StatusNoContent)
}
