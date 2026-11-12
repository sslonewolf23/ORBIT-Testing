package main

import (
	"context"
	"database/sql"
	"errors"
)

func sameCheckpointState(c anchorCheckpoint, keyID string, publicKey []byte,
	counter uint32, head witnessHead) bool {
	return c.KeyID == keyID && equalBytes(c.PublicKey, publicKey) &&
		c.Counter == counter && c.Head == head
}

// reconcileAnchoredInstallation repairs a SQLite snapshot that is behind the
// independent append-only anchor. It never moves the anchor backward and fails
// closed if SQLite claims a state newer than the external checkpoint.
func (s *service) reconcileAnchoredInstallation(ctx context.Context, tx *sql.Tx,
	verifier []byte) (anchorCheckpoint, error) {
	var checkpoint anchorCheckpoint
	installationID := installationAnchorID(verifier)
	remote, found, err := s.anchor.Latest(ctx, installationID)
	if err != nil { return checkpoint, err }
	if !found { return checkpoint, errors.New("independent monotonic anchor missing") }
	if err := validateCheckpoint(remote); err != nil { return checkpoint, err }

	var keyID string
	var publicKey, revision, digest, storedVerifier []byte
	var counter uint32
	var tombstone int
	var sequence int64
	err = tx.QueryRow(`SELECT key_id,public_key,assertion_counter,revision,
		head_digest,tombstone,anchor_sequence,recovery_verifier FROM installations
		WHERE recovery_verifier=?`, verifier).Scan(
		&keyID,&publicKey,&counter,&revision,&digest,&tombstone,&sequence,&storedVerifier)
	if err == sql.ErrNoRows {
		// A full SQLite restore may predate this installation. The client-held
		// recovery credential selects the independent anchor; rebuild the cache
		// row from that authenticated checkpoint rather than resetting it.
		var existingVerifier []byte
		err = tx.QueryRow("SELECT recovery_verifier FROM installations WHERE key_id=?",remote.KeyID).Scan(&existingVerifier)
		if err == nil && len(existingVerifier) != 0 && !equalBytes(existingVerifier,verifier) {
			return checkpoint, errors.New("anchor key is bound to a different local installation")
		}
		if err != nil && err != sql.ErrNoRows { return checkpoint, err }
		if err == sql.ErrNoRows {
			_, err = tx.Exec(`INSERT INTO installations
				(key_id,public_key,attestation_digest,assertion_counter,revision,head_digest,
				tombstone,created_at,recovery_verifier,anchor_sequence)
				VALUES(?,?,?, ?,?,?, ?,?,?,?)`, remote.KeyID,remote.PublicKey,
				make([]byte,32),remote.Counter,u64Bytes(remote.Head.Revision),
				remote.Head.Digest[:],boolInt(remote.Head.Tombstone),s.now().Unix(),
				verifier,int64(remote.Sequence))
		} else {
			_, err = tx.Exec("UPDATE installations SET recovery_verifier=? WHERE key_id=? AND (recovery_verifier IS NULL OR recovery_verifier=?)",
				verifier,remote.KeyID,verifier)
		}
		if err != nil { return checkpoint, err }
		return remote,nil
	}
	if err != nil { return checkpoint, err }
	if !equalBytes(storedVerifier,verifier) { return checkpoint, errors.New("local installation credential mismatch") }
	if sequence < 0 || len(revision)!=8 || len(digest)!=32 ||
		(tombstone!=0 && tombstone!=1) {
		return checkpoint, errors.New("invalid local witness state")
	}
	var localHead witnessHead
	localHead.Revision = binaryRevision(revision)
	copy(localHead.Digest[:], digest)
	localHead.Tombstone = tombstone == 1

	installationID := installationAnchorID(verifier)
	remote, found, err := s.anchor.Latest(ctx, installationID)
	if err != nil { return checkpoint, err }
	if !found { return checkpoint, errors.New("independent monotonic anchor missing") }
	if err := validateCheckpoint(remote); err != nil { return checkpoint, err }
	if uint64(sequence) > remote.Sequence {
		return checkpoint, errors.New("local witness state is ahead of independent anchor")
	}
	if uint64(sequence) == remote.Sequence {
		if !sameCheckpointState(remote,keyID,publicKey,counter,localHead) {
			return checkpoint, errors.New("local and independent witness states disagree")
		}
		return remote,nil
	}
	if remote.Sequence > uint64(^uint64(0)>>1) {
		return checkpoint, errors.New("anchor sequence exceeds local storage range")
	}
	// The anchor is authoritative. A stale DB backup is advanced to its exact
	// immutable checkpoint before any assertion is accepted.
	res, err := tx.Exec(`UPDATE installations SET key_id=?,public_key=?,
		assertion_counter=?,revision=?,head_digest=?,tombstone=?,anchor_sequence=?
		WHERE recovery_verifier=?`, remote.KeyID,remote.PublicKey,remote.Counter,
		u64Bytes(remote.Head.Revision),remote.Head.Digest[:],boolInt(remote.Head.Tombstone),
		int64(remote.Sequence),verifier)
	if err != nil { return checkpoint, err }
	changed, err := res.RowsAffected()
	if err != nil || changed != 1 { return checkpoint, errors.New("failed to reconcile local witness state") }
	return remote,nil
}

func (s *service) appendAnchoredState(ctx context.Context, tx *sql.Tx,
	verifier []byte, previous anchorCheckpoint, keyID string, publicKey []byte,
	counter uint32, head witnessHead) (anchorCheckpoint,error) {
	if previous.Sequence == ^uint64(0) || previous.Sequence >= uint64(^uint64(0)>>1) {
		return anchorCheckpoint{}, errors.New("monotonic anchor sequence exhausted")
	}
	next := anchorCheckpoint{
		Sequence: previous.Sequence+1,
		KeyID: keyID,
		PublicKey: append([]byte(nil),publicKey...),
		Counter: counter,
		Head: head,
		PreviousHash: previous.Hash,
	}
	next.Hash = checkpointHash(next)
	installationID := installationAnchorID(verifier)
	if err := s.anchor.Append(ctx,installationID,next); err != nil {
		if errors.Is(err,errAnchorConflict) {
			latest,found,readErr := s.anchor.Latest(ctx,installationID)
			if readErr == nil && found && latest.Hash == next.Hash {
				// A retry after the anchor accepted the write is idempotent.
			} else {
				return anchorCheckpoint{},errAnchorConflict
			}
		} else { return anchorCheckpoint{},err }
	}
	res,err := tx.Exec("UPDATE installations SET anchor_sequence=? WHERE recovery_verifier=? AND key_id=?",
		int64(next.Sequence),verifier,keyID)
	if err != nil { return anchorCheckpoint{},err }
	changed,err := res.RowsAffected()
	if err != nil || changed != 1 { return anchorCheckpoint{},errors.New("failed to persist local anchor sequence") }
	return next,nil
}

func binaryRevision(b []byte) uint64 {
	var v uint64
	for _, x := range b { v = (v << 8) | uint64(x) }
	return v
}
