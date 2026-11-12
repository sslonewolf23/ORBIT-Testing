package main

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func TestAppAttestKeyIDEncodings(t *testing.T) {
	key := make([]byte, 65)
	key[0] = 4
	sum := sha256.Sum256(key)
	for _, encoded := range []string{
		base64.StdEncoding.EncodeToString(sum[:]),
		base64.RawStdEncoding.EncodeToString(sum[:]),
		base64.URLEncoding.EncodeToString(sum[:]),
		base64.RawURLEncoding.EncodeToString(sum[:]),
	} {
		got, err := decodeAppAttestKeyID(encoded)
		if err != nil || len(got) != 32 { t.Fatalf("decode key ID %q: %v", encoded, err) }
		if !appAttestKeyIDMatches(encoded, key) { t.Fatalf("key ID %q did not match public key", encoded) }
	}
	if _, err := decodeAppAttestKeyID("not-a-key-id"); err == nil {
		t.Fatal("malformed key identifier accepted")
	}
}

func TestStrictCBORRejectsDuplicateKeysAndIndefiniteMaps(t *testing.T) {
	var decoded map[string]any
	duplicate := []byte{0xa2, 0x61, 0x61, 0x01, 0x61, 0x61, 0x02}
	if err := decodeCBOR(duplicate, &decoded); err == nil {
		t.Fatal("duplicate CBOR map key accepted")
	}
	indefinite := []byte{0xbf, 0xff}
	if err := decodeCBOR(indefinite, &decoded); err == nil {
		t.Fatal("indefinite CBOR map accepted")
	}
}

func TestCOSECredentialKeyAndAttestationExtensions(t *testing.T) {
	x, y, err := elliptic.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil { t.Fatal(err) }
	pubX, pubY := elliptic.P256().ScalarBaseMult(x)
	_ = y
	xBytes := pubX.FillBytes(make([]byte, 32))
	yBytes := pubY.FillBytes(make([]byte, 32))
	coseKey, err := cbor.Marshal(map[int64]any{
		1: uint64(2), 3: int64(-7), -1: uint64(1),
		-2: xBytes, -3: yBytes,
	})
	if err != nil { t.Fatal(err) }
	parsed, _, err := parseCOSEPublicKey(coseKey)
	if err != nil { t.Fatal(err) }
	if parsed.X.Cmp(pubX) != 0 || parsed.Y.Cmp(pubY) != 0 {
		t.Fatal("COSE key coordinates changed")
	}

	extensions, err := cbor.Marshal(map[string]any{
		"apple_validation_category_01": uint64(3),
		"apple_bundle_version_01": "1.0",
	})
	if err != nil { t.Fatal(err) }
	authData := make([]byte, 37)
	authData[32] = 0x80
	authData = append(authData, coseKey...)
	authData = append(authData, extensions...)
	embedded, err := verifyAppAttestExtensions(authData, 37, true)
	if err != nil { t.Fatal(err) }
	if embedded == nil || embedded.X.Cmp(pubX) != 0 || embedded.Y.Cmp(pubY) != 0 {
		t.Fatal("embedded COSE key not returned")
	}
}

func TestCOSERejectsWrongCurveAndAlgorithm(t *testing.T) {
	x, y, err := elliptic.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil { t.Fatal(err) }
	pubX, pubY := elliptic.P256().ScalarBaseMult(x)
	_ = y
	for _, test := range []map[int64]any{
		{1:uint64(2), 3:int64(-7), -1:uint64(2), -2:pubX.FillBytes(make([]byte,32)), -3:pubY.FillBytes(make([]byte,32))},
		{1:uint64(2), 3:int64(-257), -1:uint64(1), -2:pubX.FillBytes(make([]byte,32)), -3:pubY.FillBytes(make([]byte,32))},
	} {
		encoded, err := cbor.Marshal(test)
		if err != nil { t.Fatal(err) }
		if _, _, err := parseCOSEPublicKey(encoded); err == nil {
			t.Fatal("unsupported COSE credential key accepted")
		}
	}
	_ = big.NewInt(0)
}
