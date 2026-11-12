package main

import (
	"bytes"
	"path/filepath"
	"testing"
)

func TestKeyRecoveryPreservesJournalHeadAndConsumesChallenge(t *testing.T) {
	db, err := openDatabase(filepath.Join(t.TempDir(), "witness.sqlite"))
	if err != nil { t.Fatal(err) }
	defer db.Close()

	oldKeyID := "old-attested-key"
	newKeyID := "new-attested-key"
	verifier := bytes.Repeat([]byte{0x11}, 32)
	revision := u64Bytes(17)
	headDigest := bytes.Repeat([]byte{0x22}, 32)
	challengeDigest := bytes.Repeat([]byte{0x33}, 32)
	publicDER := []byte("replacement-public-key")
	attestationDigest := bytes.Repeat([]byte{0x44}, 32)
	if _, err := db.Exec(`INSERT INTO installations
		(key_id,public_key,attestation_digest,assertion_counter,revision,head_digest,tombstone,created_at,recovery_verifier)
		VALUES(?,?,?,12,?,?,0,1,?)`,
		oldKeyID, []byte("old-public-key"), []byte("old-attestation"),
		revision, headDigest, verifier); err != nil { t.Fatal(err) }
	if _, err := db.Exec(`INSERT INTO recovery_challenges
		(digest,old_key_id,new_key_id,expires_at,consumed) VALUES(?,?,?,?,0)`,
		challengeDigest, oldKeyID, newKeyID, int64(9999999999)); err != nil { t.Fatal(err) }

	tx, err := db.Begin()
	if err != nil { t.Fatal(err) }
	if err := commitKeyRecovery(tx, oldKeyID, newKeyID, verifier,
		challengeDigest, publicDER, attestationDigest, 100); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil { t.Fatal(err) }

	var gotPublic, gotAttestation, gotRevision, gotDigest, gotVerifier []byte
	var counter, tombstone int
	if err := db.QueryRow(`SELECT public_key,attestation_digest,assertion_counter,
		revision,head_digest,tombstone,recovery_verifier
		FROM installations WHERE key_id=?`, newKeyID).Scan(
		&gotPublic,&gotAttestation,&counter,&gotRevision,&gotDigest,&tombstone,&gotVerifier); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotPublic, publicDER) || !bytes.Equal(gotAttestation, attestationDigest) {
		t.Fatal("replacement App Attest material not stored")
	}
	if counter != 0 { t.Fatalf("replacement assertion counter = %d, want 0", counter) }
	if !bytes.Equal(gotRevision, revision) || !bytes.Equal(gotDigest, headDigest) ||
		tombstone != 0 || !bytes.Equal(gotVerifier, verifier) {
		t.Fatal("recovery changed the existing journal head or credential binding")
	}
	var historyCount, consumed int
	if err := db.QueryRow("SELECT COUNT(*) FROM key_recovery_history WHERE old_key_id=? AND new_key_id=?",
		oldKeyID,newKeyID).Scan(&historyCount); err != nil { t.Fatal(err) }
	if historyCount != 1 { t.Fatalf("recovery history rows = %d, want 1", historyCount) }
	if err := db.QueryRow("SELECT consumed FROM recovery_challenges WHERE digest=?",
		challengeDigest).Scan(&consumed); err != nil { t.Fatal(err) }
	if consumed != 1 { t.Fatal("recovery challenge was not consumed") }

	retry, err := db.Begin()
	if err != nil { t.Fatal(err) }
	if err := commitKeyRecovery(retry, oldKeyID, newKeyID, verifier,
		challengeDigest, publicDER, attestationDigest, 101); err == nil {
		_ = retry.Rollback()
		t.Fatal("replayed recovery challenge accepted")
	}
	_ = retry.Rollback()
}
