package main

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

type memoryAnchor struct { items map[string]anchorCheckpoint }

func newMemoryAnchor() *memoryAnchor { return &memoryAnchor{items: make(map[string]anchorCheckpoint)} }
func (m *memoryAnchor) Latest(_ context.Context,id string)(anchorCheckpoint,bool,error) {
	c,ok:=m.items[id]; return c,ok,nil
}
func (m *memoryAnchor) Append(_ context.Context,id string,c anchorCheckpoint) error {
	if err:=validateCheckpoint(c); err!=nil { return err }
	prior,ok:=m.items[id]
	if !ok {
		if c.Sequence!=1 || c.PreviousHash!=([32]byte{}) { return errAnchorConflict }
	} else {
		if c.Sequence==prior.Sequence && c.Hash==prior.Hash { return nil }
		if c.Sequence!=prior.Sequence+1 || c.PreviousHash!=prior.Hash { return errAnchorConflict }
	}
	m.items[id]=c
	return nil
}

func TestCheckpointHashDetectsMutation(t *testing.T) {
	c:=anchorCheckpoint{InstallationID:installationAnchorID([]byte{1}),Sequence:1,KeyID:"test-key",PublicKey:[]byte{1,2,3},
		Counter:0,Head:witnessHead{Revision:0,Tombstone:true}}
	c.Hash=checkpointHash(c)
	if err:=validateCheckpoint(c); err!=nil { t.Fatal(err) }
	c.Counter++
	if err:=validateCheckpoint(c); err==nil { t.Fatal("mutated checkpoint accepted") }
}

func TestMemoryAnchorRequiresContiguousAppend(t *testing.T) {
	a:=newMemoryAnchor()
	c:=anchorCheckpoint{InstallationID:"",Sequence:1,KeyID:"key",PublicKey:[]byte{1},Head:witnessHead{Tombstone:true}}
	c.Hash=checkpointHash(c)
	if err:=c.InstallationID=installationAnchorID([]byte{2}); c.Hash=checkpointHash(c)
	if err:=a.Append(context.Background(),c.InstallationID,c); err!=nil { t.Fatal(err) }
	next:=c
	next.Sequence=3
	next.PreviousHash=c.Hash
	next.Hash=checkpointHash(next)
	if err:=a.Append(context.Background(),c.InstallationID,next); !errors.Is(err,errAnchorConflict) {
		t.Fatal("skipped checkpoint sequence accepted")
	}
}

func TestReconcileRepairsRolledBackSQLiteStateFromExternalAnchor(t *testing.T) {
	db,err:=openDatabase(filepath.Join(t.TempDir(),"witness.sqlite"))
	if err!=nil { t.Fatal(err) }
	defer db.Close()
	verifier:=make([]byte,32); verifier[0]=0xA1
	oldHead:=witnessHead{Revision:1,Tombstone:false}; oldHead.Digest[0]=0x11
	newHead:=witnessHead{Revision:2,Tombstone:false}; newHead.Digest[0]=0x22
	oldKey,newKey:="old-key","current-key"
	oldPublic,newPublic:=[]byte("old-public"),[]byte("current-public")
	if _,err:=db.Exec(`INSERT INTO installations
		(key_id,public_key,attestation_digest,assertion_counter,revision,head_digest,tombstone,created_at,recovery_verifier,anchor_sequence)
		VALUES(?,?,?,4,?,?,0,1,?,1)`,
		oldKey,oldPublic,[]byte("att"),u64Bytes(oldHead.Revision),oldHead.Digest[:],verifier); err!=nil { t.Fatal(err) }
	anchor:=newMemoryAnchor()
	first:=anchorCheckpoint{InstallationID:installationAnchorID(verifier),Sequence:1,KeyID:oldKey,PublicKey:oldPublic,Counter:4,Head:oldHead}
	first.Hash=checkpointHash(first)
	second:=anchorCheckpoint{InstallationID:installationAnchorID(verifier),Sequence:2,KeyID:newKey,PublicKey:newPublic,Counter:2,Head:newHead,PreviousHash:first.Hash}
	second.Hash=checkpointHash(second)
	id:=installationAnchorID(verifier)
	anchor.items[id]=second
	s:=&service{db:db,anchor:anchor}
	tx,err:=db.Begin(); if err!=nil { t.Fatal(err) }
	got,err:=s.reconcileAnchoredInstallation(context.Background(),tx,verifier)
	if err!=nil { _=tx.Rollback(); t.Fatal(err) }
	if got.Hash!=second.Hash { _=tx.Rollback(); t.Fatal("wrong external checkpoint returned") }
	if err:=tx.Commit(); err!=nil { t.Fatal(err) }
	var keyID string
	var seq int64
	var counter uint32
	var revision,digest []byte
	if err:=db.QueryRow("SELECT key_id,anchor_sequence,assertion_counter,revision,head_digest FROM installations WHERE recovery_verifier=?",verifier).
		Scan(&keyID,&seq,&counter,&revision,&digest); err!=nil { t.Fatal(err) }
	if keyID!=newKey || seq!=2 || counter!=2 || binaryRevision(revision)!=2 || digest[0]!=0x22 {
		t.Fatal("local database was not repaired to external checkpoint")
	}
}

func TestReconcileRejectsLocalStateAheadOfAnchor(t *testing.T) {
	db,err:=openDatabase(filepath.Join(t.TempDir(),"witness.sqlite"))
	if err!=nil { t.Fatal(err) }
	defer db.Close()
	verifier:=make([]byte,32); verifier[0]=0xB2
	head:=witnessHead{Revision:1,Tombstone:false}; head.Digest[0]=7
	if _,err:=db.Exec(`INSERT INTO installations
		(key_id,public_key,attestation_digest,assertion_counter,revision,head_digest,tombstone,created_at,recovery_verifier,anchor_sequence)
		VALUES('key',?,?,1,?,?,0,1,?,2)`,[]byte("pub"),[]byte("att"),u64Bytes(1),head.Digest[:],verifier); err!=nil { t.Fatal(err) }
	anchor:=newMemoryAnchor()
	c:=anchorCheckpoint{Sequence:1,KeyID:"key",PublicKey:[]byte("pub"),Counter:1,Head:head}
	c.Hash=checkpointHash(c); anchor.items[installationAnchorID(verifier)]=c
	s:=&service{db:db,anchor:anchor}
	tx,err:=db.Begin(); if err!=nil { t.Fatal(err) }
	_,err=s.reconcileAnchoredInstallation(context.Background(),tx,verifier)
	_ = tx.Rollback()
	if err==nil { t.Fatal("local state ahead of external anchor accepted") }
}


func TestReconcileRebuildsCompletelyMissingSQLiteInstallation(t *testing.T) {
	db,err:=openDatabase(filepath.Join(t.TempDir(),"witness.sqlite"))
	if err!=nil { t.Fatal(err) }
	defer db.Close()
	verifier:=make([]byte,32); verifier[0]=0xC3
	head:=witnessHead{Revision:9,Tombstone:false}; head.Digest[0]=0x91
	anchor:=newMemoryAnchor()
	c:=anchorCheckpoint{InstallationID:installationAnchorID(verifier),Sequence:7,KeyID:"restored-key",PublicKey:[]byte("attested-public"),
		Counter:19,Head:head}
	c.Hash=checkpointHash(c)
	anchor.items[installationAnchorID(verifier)]=c
	s:=&service{db:db,anchor:anchor}
	tx,err:=db.Begin(); if err!=nil { t.Fatal(err) }
	got,err:=s.reconcileAnchoredInstallation(context.Background(),tx,verifier)
	if err!=nil { _=tx.Rollback(); t.Fatal(err) }
	if got.Hash!=c.Hash { _=tx.Rollback(); t.Fatal("wrong checkpoint reconstructed") }
	if err:=tx.Commit(); err!=nil { t.Fatal(err) }
	var keyID string
	var sequence int64
	var counter uint32
	var revision,digest,storedVerifier []byte
	var tombstone int
	if err:=db.QueryRow(`SELECT key_id,anchor_sequence,assertion_counter,revision,
		head_digest,tombstone,recovery_verifier FROM installations WHERE recovery_verifier=?`,
		verifier).Scan(&keyID,&sequence,&counter,&revision,&digest,&tombstone,&storedVerifier); err!=nil {
		t.Fatal(err)
	}
	if keyID!="restored-key" || sequence!=7 || counter!=19 ||
		binaryRevision(revision)!=9 || digest[0]!=0x91 || tombstone!=0 ||
		!equalBytes(storedVerifier,verifier) {
		t.Fatal("missing local installation was not reconstructed from anchor")
	}
}
