package main

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestHeadWireFormat(t *testing.T) {
	h := witnessHead{Revision: 0x0102030405060708, Tombstone: true}
	h.Digest[0] = 0xA5
	encoded := encodeHead(h)
	if len(encoded) != 41 { t.Fatalf("encoded length = %d", len(encoded)) }
	if binary.BigEndian.Uint64(encoded[:8]) != h.Revision { t.Fatal("revision encoding mismatch") }
	got, err := parseHead(encoded)
	if err != nil || got != h { t.Fatalf("round trip: %#v, %v", got, err) }
	encoded[8] = 2
	if _, err := parseHead(encoded); err == nil { t.Fatal("invalid tombstone flag accepted") }
}

func TestSignedRequestBinding(t *testing.T) {
	keyID := "attested-key"
	head := []byte("ORBIT-JOURNAL-HEAD-V1\x00" + keyID)
	if err := parseHeadRequest(head, keyID); err != nil { t.Fatal(err) }
	if parseHeadRequest(head, "other-key") == nil { t.Fatal("wrong key binding accepted") }

	old := witnessHead{Revision: 7}
	next := witnessHead{Revision: 8}
	old.Digest[0] = 1
	next.Digest[0] = 2
	raw := append([]byte("ORBIT-JOURNAL-CAS-V1\x00"+keyID), encodeHead(old)...)
	raw = append(raw, encodeHead(next)...)
	gotOld, gotNext, err := parseCASRequest(raw, keyID)
	if err != nil || gotOld != old || gotNext != next { t.Fatalf("CAS parse failed: %v", err) }
	raw = append(raw, 0)
	if _, _, err := parseCASRequest(raw, keyID); err == nil { t.Fatal("trailing bytes accepted") }
}

func TestAllowedHeadTransitions(t *testing.T) {
	var zero witnessHead
	zero.Tombstone = true
	active1 := witnessHead{Revision: 1}
	active1.Digest[0] = 1
	if !validTransition(zero, active1) { t.Fatal("initial activation rejected") }

	active2 := witnessHead{Revision: 2}
	active2.Digest[0] = 2
	if !validTransition(active1, active2) { t.Fatal("active revision increment rejected") }

	tombstone2 := witnessHead{Revision: 2, Tombstone: true}
	tombstone2.Digest[0] = 3
	if !validTransition(active2, tombstone2) { t.Fatal("active-to-tombstone rejected") }
	active3 := witnessHead{Revision: 3}
	active3.Digest[0] = 4
	if !validTransition(tombstone2, active3) { t.Fatal("tombstone-to-active rejected") }

	if validTransition(active1, witnessHead{Revision: 3, Digest: active2.Digest}) {
		t.Fatal("skipped revision accepted")
	}
	if validTransition(active1, witnessHead{Revision: 1, Digest: active2.Digest}) {
		t.Fatal("same-revision digest replacement accepted")
	}
	if validTransition(tombstone2, tombstone2) { t.Fatal("tombstone rewrite accepted") }
	if validTransition(active2, witnessHead{Revision: 3, Tombstone: true, Digest: active3.Digest}) {
		t.Fatal("tombstone revision increment accepted")
	}
}

func TestCASRequestExactLength(t *testing.T) {
	keyID := "id"
	raw := append([]byte("ORBIT-JOURNAL-CAS-V1\x00"+keyID), make([]byte, 82)...)
	if _, _, err := parseCASRequest(raw, keyID); err != nil { t.Fatal(err) }
	if bytes.Equal(raw, nil) { t.Fatal("unexpected empty request") }
}
