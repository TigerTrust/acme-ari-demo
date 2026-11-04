package ari

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func genCert(t *testing.T, aki []byte) *x509.Certificate {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(0x1234567890abcdef),
		Subject:        pkix.Name{CommonName: "example.com"},
		Issuer:         pkix.Name{CommonName: "Test CA"},
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       time.Now().Add(47 * 24 * time.Hour),
		AuthorityKeyId: aki,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	c, _ := x509.ParseCertificate(der)
	return c
}

func TestCertID_Format(t *testing.T) {
	aki := []byte{0xde, 0xad, 0xbe, 0xef}
	c := genCert(t, aki)
	id, err := CertID(c)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(id, ".") {
		t.Fatalf("cert id should be base64url(aki).base64url(serial), got %q", id)
	}
	left, right, _ := strings.Cut(id, ".")
	if left == "" || right == "" {
		t.Fatalf("empty halves in %q", id)
	}
	if strings.ContainsAny(id, "+/=") {
		t.Fatalf("expected base64url (no +, /, =): %q", id)
	}
}

func TestCertID_RequiresAKI(t *testing.T) {
	c := genCert(t, nil)
	if _, err := CertID(c); err == nil {
		t.Fatal("expected error when AKI missing")
	}
}

func TestRenewalInfo_Describe(t *testing.T) {
	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	ri := &RenewalInfo{SuggestedWindow: SuggestedWindow{
		Start: now.Add(24 * time.Hour),
		End:   now.Add(72 * time.Hour),
	}}
	if ri.InWindow(now) {
		t.Error("InWindow(now) should be false before start")
	}
	if !ri.InWindow(now.Add(36 * time.Hour)) {
		t.Error("InWindow should be true inside window")
	}
	if ri.InWindow(now.Add(100 * time.Hour)) {
		t.Error("InWindow should be false after end")
	}
	if !strings.Contains(ri.Describe(now), "opens in") {
		t.Errorf("Describe before: %s", ri.Describe(now))
	}
}

func TestFetch_ParsesJSON(t *testing.T) {
	aki := []byte{0xde, 0xad, 0xbe, 0xef}
	c := genCert(t, aki)

	expectedID, _ := CertID(c)
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(RenewalInfo{
			SuggestedWindow: SuggestedWindow{
				Start: time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC),
				End:   time.Date(2026, 12, 3, 0, 0, 0, 0, time.UTC),
			},
			ExplanationURL: "https://ca.example/why",
		})
	}))
	defer srv.Close()

	ri, err := Fetch(srv.Client(), srv.URL, c)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(gotPath, "/"+expectedID) {
		t.Errorf("path = %q, want suffix /%s", gotPath, expectedID)
	}
	if ri.ExplanationURL != "https://ca.example/why" {
		t.Errorf("explanation URL = %q", ri.ExplanationURL)
	}
}

func TestFetchDirectory(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(Directory{
			NewNonce:    "https://ca.example/nonce",
			NewAccount:  "https://ca.example/acct",
			NewOrder:    "https://ca.example/order",
			RenewalInfo: "https://ca.example/renewal-info",
		})
	}))
	defer srv.Close()
	d, err := FetchDirectory(srv.Client(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if d.RenewalInfo == "" {
		t.Fatal("empty renewalInfo")
	}
}
