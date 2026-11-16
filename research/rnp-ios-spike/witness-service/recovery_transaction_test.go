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

func TestAnchoredKeyRecoveryRetryFinalizesAfterSQLiteRollback(t *testing.T) {
	db,err:=openDatabase(filepath.Join(t.TempDir(),"witness.sqlite"))
	if err!=nil { t.Fatal(err) }
	defer db.Close()
	verifier:=bytes.Repeat([]byte{0x51},32)
	oldKey,newKey:="old-key","new-key"
	oldPublic,newPublic:=[]byte("old-public"),[]byte("new-public")
	oldHead:=witnessHead{Revision:12,Tombstone:false}; oldHead.Digest[0]=0x61
	attDigest:=bytes.Repeat([]byte{0x72},32)
	challenge:=bytes.Repeat([]byte{0x83},32)
	id:=installationAnchorID(verifier)
	prior:=anchorCheckpoint{InstallationID:id,Sequence:1,KeyID:oldKey,PublicKey:oldPublic,Counter:9,Head:oldHead}
	prior.Hash=checkpointHash(prior)
	anchor:=newMemoryAnchor(); anchor.items[id]=prior
	if _,err=db.Exec(`INSERT INTO installations
		(key_id,public_key,attestation_digest,assertion_counter,revision,head_digest,tombstone,created_at,recovery_verifier,anchor_sequence)
		VALUES(?,?,?,9,?,?,0,1,?,1)`,oldKey,oldPublic,[]byte("old-att"),u64Bytes(oldHead.Revision),oldHead.Digest[:],verifier); err!=nil { t.Fatal(err) }
	if _,err=db.Exec(`INSERT INTO recovery_challenges(digest,old_key_id,new_key_id,expires_at,consumed)
		VALUES(?,?,?,?,0)`,challenge,oldKey,newKey,int64(9999999999)); err!=nil { t.Fatal(err) }

	// Simulate the first request: SQLite changes are staged, but the anchor
	// accepts the new-key checkpoint before the local transaction rolls back.
	firstTx,err:=db.Begin(); if err!=nil { t.Fatal(err) }
	if err=commitKeyRecovery(firstTx,oldKey,newKey,verifier,challenge,newPublic,attDigest,100); err!=nil { _=firstTx.Rollback(); t.Fatal(err) }
	next:=anchorCheckpoint{InstallationID:id,Sequence:2,KeyID:newKey,PublicKey:newPublic,Counter:0,Head:oldHead,PreviousHash:prior.Hash}
	next.Hash=checkpointHash(next)
	if _,err=(&service{db:db,anchor:anchor}).appendAnchoredState(context.Background(),firstTx,verifier,prior,newKey,newPublic,0,oldHead); err!=nil { _=firstTx.Rollback(); t.Fatal(err) }
	if anchor.items[id].Hash!=next.Hash { _=firstTx.Rollback(); t.Fatal("anchor did not accept replacement checkpoint") }
	if err=firstTx.Rollback(); err!=nil { t.Fatal(err) }

	// The retry reconciles the local row from the anchor and completes the
	// still-unconsumed challenge and immutable recovery-history record.
	retryTx,err:=db.Begin(); if err!=nil { t.Fatal(err) }
	s:=&service{db:db,anchor:anchor,now:time.Now}
	checkpoint,err:=s.reconcileAnchoredInstallation(context.Background(),retryTx,verifier)
	if err!=nil { _=retryTx.Rollback(); t.Fatal(err) }
	if err=finalizeAnchoredRecoveryRetry(retryTx,oldKey,newKey,verifier,challenge,newPublic,attDigest,checkpoint,101); err!=nil { _=retryTx.Rollback(); t.Fatal(err) }
	if err=retryTx.Commit(); err!=nil { t.Fatal(err) }

	var keyID string
	var storedAtt []byte
	var sequence int64
	var consumed,history int
	if err=db.QueryRow("SELECT key_id,attestation_digest,anchor_sequence FROM installations WHERE recovery_verifier=?",verifier).Scan(&keyID,&storedAtt,&sequence); err!=nil { t.Fatal(err) }
	if keyID!=newKey || !bytes.Equal(storedAtt,attDigest) || sequence!=2 { t.Fatal("retry did not finalize the anchored replacement") }
	if err=db.QueryRow("SELECT consumed FROM recovery_challenges WHERE digest=?",challenge).Scan(&consumed); err!=nil { t.Fatal(err) }
	if consumed!=1 { t.Fatal("retry did not consume recovery challenge") }
	if err=db.QueryRow("SELECT COUNT(*) FROM key_recovery_history WHERE old_key_id=? AND new_key_id=?",oldKey,newKey).Scan(&history); err!=nil { t.Fatal(err) }
	if history!=1 { t.Fatal("retry did not create exactly one recovery history record") }
}

