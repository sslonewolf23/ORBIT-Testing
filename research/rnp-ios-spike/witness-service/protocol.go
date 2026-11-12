package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const maxRequestBytes = 1 << 20

type signedRequest struct {
	KeyID     string `json:"keyID"`
	Request   string `json:"request"`
	Assertion string `json:"assertion"`
	RecoveryCredential string `json:"recoveryCredential"`
}

type registerRequest struct {
	KeyID      string `json:"keyID"`
	Challenge  string `json:"challenge"`
	Attestation string `json:"attestation"`
	RecoveryCredential string `json:"recoveryCredential"`
}

type recoveryChallengeRequest struct { NewKeyID string `json:"newKeyID"`; RecoveryCredential string `json:"recoveryCredential"` }
type recoveryRequest struct { NewKeyID string `json:"newKeyID"`; Challenge string `json:"challenge"`; RecoveryCredential string `json:"recoveryCredential"`; Attestation string `json:"attestation"` }

type witnessHead struct {
	Revision  uint64
	Digest    [32]byte
	Tombstone bool
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
	data, err := io.ReadAll(r.Body)
	if err != nil { return err }
	if err := rejectDuplicateJSONKeys(data); err != nil { return err }
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil { return err }
	if err := dec.Decode(new(any)); err != io.EOF { return errors.New("trailing JSON data") }
	return nil
}

// rejectDuplicateJSONKeys rejects ambiguous object encodings before the
// request is decoded into a protocol struct. encoding/json otherwise accepts
// duplicate names and silently keeps the last value.
func rejectDuplicateJSONKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := consumeJSONValue(dec); err != nil { return err }
	if _, err := dec.Token(); err != io.EOF {
		if err == nil { return errors.New("trailing JSON data") }
		return err
	}
	return nil
}

func consumeJSONValue(dec *json.Decoder) error {
	token, err := dec.Token()
	if err != nil { return err }
	delim, isDelim := token.(json.Delim)
	if !isDelim { return nil }
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for dec.More() {
			keyToken, err := dec.Token()
			if err != nil { return err }
			key, ok := keyToken.(string)
			if !ok { return errors.New("invalid JSON object key") }
			if _, exists := seen[key]; exists {
				return errors.New("duplicate JSON object key")
			}
			seen[key] = struct{}{}
			if err := consumeJSONValue(dec); err != nil { return err }
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim('}') { return errors.New("malformed JSON object") }
	case '[':
		for dec.More() {
			if err := consumeJSONValue(dec); err != nil { return err }
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim(']') { return errors.New("malformed JSON array") }
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}

func decodeB64(value string, min, max int) ([]byte, error) {
	if strings.TrimSpace(value) != value { return nil, errors.New("invalid base64 whitespace") }
	b, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(b) < min || len(b) > max { return nil, errors.New("invalid base64 field") }
	return b, nil
}

func parseHead(data []byte) (witnessHead, error) {
	var h witnessHead
	if len(data) != 41 { return h, errors.New("invalid encoded head length") }
	h.Revision = binary.BigEndian.Uint64(data[:8])
	if data[8] > 1 { return h, errors.New("invalid tombstone flag") }
	h.Tombstone = data[8] == 1
	copy(h.Digest[:], data[9:41])
	return h, nil
}

func encodeHead(h witnessHead) []byte {
	out := make([]byte, 41)
	binary.BigEndian.PutUint64(out[:8], h.Revision)
	if h.Tombstone { out[8] = 1 }
	copy(out[9:], h.Digest[:])
	return out
}

func parseHeadRequest(raw []byte, keyID string) error {
	prefix := append([]byte("ORBIT-JOURNAL-HEAD-V1\x00"), []byte(keyID)...)
	if !bytes.Equal(raw, prefix) { return errors.New("head request binding mismatch") }
	return nil
}

func parseCASRequest(raw []byte, keyID string) (witnessHead, witnessHead, error) {
	var zero witnessHead
	prefix := append([]byte("ORBIT-JOURNAL-CAS-V1\x00"), []byte(keyID)...)
	if len(raw) != len(prefix)+82 || !bytes.Equal(raw[:len(prefix)], prefix) {
		return zero, zero, errors.New("CAS request binding mismatch")
	}
	old, err := parseHead(raw[len(prefix):len(prefix)+41])
	if err != nil { return zero, zero, err }
	next, err := parseHead(raw[len(prefix)+41:])
	return old, next, err
}

func validTransition(old, next witnessHead) bool {
	if old.Digest == ([32]byte{}) && old.Revision == 0 && old.Tombstone {
		return next.Revision == 1 && !next.Tombstone && next.Digest != ([32]byte{})
	}
	if old.Tombstone {
		return next.Revision == old.Revision+1 && old.Revision != ^uint64(0) &&
			!next.Tombstone && next.Digest != ([32]byte{})
	}
	if next.Tombstone {
		return next.Revision == old.Revision && next.Digest != ([32]byte{})
	}
	return old.Revision != ^uint64(0) && next.Revision == old.Revision+1 &&
		next.Digest != ([32]byte{})
}

func decodeAppAttestKeyID(keyID string) ([]byte, error) {
	encodings := []*base64.Encoding{
		base64.StdEncoding.Strict(),
		base64.RawStdEncoding.Strict(),
		base64.URLEncoding.Strict(),
		base64.RawURLEncoding.Strict(),
	}
	for _, encoding := range encodings {
		if decoded, err := encoding.DecodeString(keyID); err == nil && len(decoded) == 32 {
			return decoded, nil
		}
	}
	return nil, errors.New("invalid App Attest key identifier")
}

func appAttestKeyIDMatches(keyID string, publicKey []byte) bool {
	got, err := decodeAppAttestKeyID(keyID)
	if err != nil { return false }
	sum := sha256.Sum256(publicKey)
	return bytes.Equal(got, sum[:])
}

func jsonError(w http.ResponseWriter, status int, message string) {
	http.Error(w, fmt.Sprintf("{\"error\":%q}", message), status)
}
