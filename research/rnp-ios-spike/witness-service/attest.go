package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/fxamacker/cbor/v2"
)

var (
	nonceOID = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 2}
)

type service struct {
	db          *sql.DB
	appID       string
	environment string
	roots       *x509.CertPool
	now         func() time.Time
}

type cborAttestation struct {
	Format string `cbor:"fmt"`
	Statement map[string]any `cbor:"attStmt"`
	AuthData []byte `cbor:"authData"`
}

func decodeCBOR(data []byte, target any) error {
	var opts cbor.DecOptions
	mode, err := opts.DecMode()
	if err != nil { return err }
	return mode.Unmarshal(data, target)
}

func cborBytes(value any) ([]byte, bool) {
	b, ok := value.([]byte)
	return b, ok
}

func verifyAppAttestExtensions(authData []byte, extensionOffset int,
	hasCredentialPublicKey bool) error {
	if len(authData) < 37 || authData[32]&0x80 == 0 ||
		extensionOffset < 37 || extensionOffset >= len(authData) {
		return errors.New("missing App Attest authenticator extensions")
	}
	extensionBytes := authData[extensionOffset:]
	if hasCredentialPublicKey {
		var credentialPublicKey any
		remaining, err := cbor.UnmarshalFirst(extensionBytes, &credentialPublicKey)
		if err != nil || len(remaining) == 0 {
			return errors.New("malformed authenticator credential key")
		}
		extensionBytes = remaining
	}
	var extensions map[string]any
	if err := cbor.Unmarshal(extensionBytes, &extensions); err != nil {
		return errors.New("malformed App Attest extension map")
	}
	category, ok := extensions["apple_validation_category_01"].(uint64)
	if !ok || !(category >= 1 && category <= 6 || category == 10) {
		return errors.New("invalid App Attest validation category")
	}
	bundleVersion, ok := extensions["apple_bundle_version_01"].(string)
	if !ok || bundleVersion == "" || len(bundleVersion) > 128 {
		return errors.New("invalid App Attest bundle version")
	}
	return nil
}

func parseAuthData(data []byte, requireAttested bool) (rpHash [32]byte, counter uint32, credentialID []byte, err error) {
	if len(data) < 37 { err = errors.New("short authenticator data"); return }
	copy(rpHash[:], data[:32])
	counter = binary.BigEndian.Uint32(data[33:37])
	if requireAttested {
		if data[32]&0x40 == 0 || len(data) < 55 { err = errors.New("missing attested credential data"); return }
		n := int(binary.BigEndian.Uint16(data[53:55]))
		if n == 0 || len(data) < 55+n { err = errors.New("invalid credential ID length"); return }
		credentialID = append([]byte(nil), data[55:55+n]...)
	}
	return
}

func (s *service) verifyAttestation(keyID string, challenge, object []byte) ([]byte, error) {
	var envelope cborAttestation
	if err := decodeCBOR(object, &envelope); err != nil { return nil, fmt.Errorf("attestation CBOR: %w", err) }
	if envelope.Format != "apple-appattest" { return nil, errors.New("unexpected attestation format") }
	x5cRaw, ok := envelope.Statement["x5c"].([]any)
	if !ok || len(x5cRaw) < 2 || len(x5cRaw) > 4 { return nil, errors.New("invalid certificate chain") }
	certs := make([]*x509.Certificate, 0, len(x5cRaw))
	for _, raw := range x5cRaw {
		der, ok := cborBytes(raw); if !ok { return nil, errors.New("invalid x5c item") }
		cert, err := x509.ParseCertificate(der); if err != nil { return nil, err }
		certs = append(certs, cert)
	}
	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] { intermediates.AddCert(cert) }
	if _, err := certs[0].Verify(x509.VerifyOptions{Roots:s.roots, Intermediates:intermediates,
		CurrentTime:s.now(), KeyUsages:[]x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return nil, fmt.Errorf("App Attest certificate chain: %w", err)
	}
	pub, ok := certs[0].PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() { return nil, errors.New("attested key is not P-256") }
	uncompressed := elliptic.Marshal(elliptic.P256(), pub.X, pub.Y)
	if !appAttestKeyIDMatches(keyID, uncompressed) { return nil, errors.New("key identifier mismatch") }

	clientHash := sha256.Sum256(challenge)
	nonceInput := append(append([]byte(nil), envelope.AuthData...), clientHash[:]...)
	nonce := sha256.Sum256(nonceInput)
	var extension []byte
	for _, ext := range certs[0].Extensions {
		if ext.Id.Equal(nonceOID) { extension = ext.Value; break }
	}
	var sequence struct { Value []byte }
	rest, err := asn1.Unmarshal(extension, &sequence)
	if err != nil || len(rest) != 0 || !bytes.Equal(sequence.Value, nonce[:]) {
		return nil, errors.New("attestation nonce extension mismatch")
	}
	rpHash, counter, credentialID, err := parseAuthData(envelope.AuthData, true)
	if err != nil { return nil, err }
	appHash := sha256.Sum256([]byte(s.appID))
	if rpHash != appHash { return nil, errors.New("App ID hash mismatch") }
	if counter != 0 { return nil, errors.New("attestation counter is not zero") }
	if !bytes.Equal(credentialID, mustDecodeKeyID(keyID)) { return nil, errors.New("credential ID mismatch") }
	if len(envelope.AuthData) < 55+len(credentialID)+1 { return nil, errors.New("truncated authenticator data") }
	aaguid := envelope.AuthData[37:53]
	expected := []byte("appattest")
	if s.environment == "development" { expected = []byte("appattestdevelop") }
	expectedAAGUID := make([]byte, 16); copy(expectedAAGUID, expected)
	if !bytes.Equal(aaguid, expectedAAGUID) { return nil, errors.New("App Attest environment mismatch") }
	if err := verifyAppAttestExtensions(envelope.AuthData, 55+len(credentialID), true); err != nil {
		return nil, err
	}
	return x509.MarshalPKIXPublicKey(pub)
}

func mustDecodeKeyID(keyID string) []byte {
	b, _ := decodeB64(keyID, 32, 32)
	return b
}

func (s *service) verifyAssertion(publicDER, clientData, assertion []byte) (uint32, error) {
	var obj map[string]any
	if err := decodeCBOR(assertion, &obj); err != nil { return 0, err }
	authData, ok1 := cborBytes(obj["authenticatorData"])
	signature, ok2 := cborBytes(obj["signature"])
	if !ok1 || !ok2 || len(signature) == 0 { return 0, errors.New("malformed assertion object") }
	rpHash, counter, _, err := parseAuthData(authData, false)
	if err != nil { return 0, err }
	appHash := sha256.Sum256([]byte(s.appID))
	if rpHash != appHash { return 0, errors.New("assertion App ID hash mismatch") }
	if err := verifyAppAttestExtensions(authData, 37, false); err != nil {
		return 0, err
	}
	pubAny, err := x509.ParsePKIXPublicKey(publicDER)
	if err != nil { return 0, err }
	pub, ok := pubAny.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() { return 0, errors.New("stored key is invalid") }
	clientHash := sha256.Sum256(clientData)
	nonceInput := append(append([]byte(nil), authData...), clientHash[:]...)
	nonce := sha256.Sum256(nonceInput)
	var parsed struct { R, S *big.Int }
	rest, err := asn1.Unmarshal(signature, &parsed)
	if err != nil || len(rest) != 0 || parsed.R == nil || parsed.S == nil ||
		!ecdsa.Verify(pub, nonce[:], parsed.R, parsed.S) {
		return 0, errors.New("assertion signature invalid")
	}
	return counter, nil
}
