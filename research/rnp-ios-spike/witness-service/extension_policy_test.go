package main

import "testing"

func TestAllowedValidationCategoryParsing(t *testing.T) {
	got, err := parseAllowedValidationCategories("1,3,255")
	if err != nil { t.Fatal(err) }
	for _, value := range []uint64{1,3,255} {
		if _, ok := got[value]; !ok { t.Fatalf("category %d missing", value) }
	}
	for _, raw := range []string{"", "0", "256", "1,1", "1, 3", " 1", "1,"} {
		if _, err := parseAllowedValidationCategories(raw); err == nil {
			t.Fatalf("invalid category allowlist %q accepted", raw)
		}
	}
}

func TestAllowedBundleVersionParsing(t *testing.T) {
	got, err := parseAllowedBundleVersions("2.4.1")
	if err != nil { t.Fatal(err) }
	if len(got) != 1 {
		t.Fatalf("expected exactly one active bundle version, got %d", len(got))
	}
	if _, ok := got["2.4.1"]; !ok {
		t.Fatal("active bundle version missing")
	}
	for _, raw := range []string{"", "1.0,,2.0", "1.0, 2.0", "1.0,1.0", "1.0,2.0", "../1", "version;bad"} {
		if _, err := parseAllowedBundleVersions(raw); err == nil {
			t.Fatalf("invalid bundle-version allowlist %q accepted", raw)
		}
	}
}

func TestAppAttestExtensionPolicyRequiresBothAllowlists(t *testing.T) {
	s := &service{
		allowedValidationCategories: map[uint64]struct{}{3:{}},
		allowedBundleVersions: map[string]struct{}{"2.4.1":{}},
	}
	if err := s.validateAppAttestExtensionPolicy(appAttestExtensionInfo{
		ValidationCategory:3, BundleVersion:"2.4.1",
	}); err != nil { t.Fatal(err) }
	for _, info := range []appAttestExtensionInfo{
		{ValidationCategory:4, BundleVersion:"2.4.1"},
		{ValidationCategory:3, BundleVersion:"2.4.2"},
	} {
		if err := s.validateAppAttestExtensionPolicy(info); err == nil {
			t.Fatalf("unapproved extension values accepted: %+v", info)
		}
	}
}
