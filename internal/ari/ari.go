// Package ari is a minimal client for ACME Renewal Information
// (draft-ietf-acme-ari / RFC 9773). It is intentionally scoped to the
// "given a cert, tell me when to renew" use case — the whole point of
// 47-day certificate lifetimes.
package ari

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// SuggestedWindow is the renewal window returned by the CA.
type SuggestedWindow struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// RenewalInfo is the JSON body of GET /renewalInfo/{id}.
type RenewalInfo struct {
	SuggestedWindow SuggestedWindow `json:"suggestedWindow"`
	ExplanationURL  string          `json:"explanationURL,omitempty"`
}

// InWindow reports whether `now` is inside the suggested renewal window.
func (r *RenewalInfo) InWindow(now time.Time) bool {
	return !now.Before(r.SuggestedWindow.Start) && now.Before(r.SuggestedWindow.End)
}

// Describe returns a human sentence about the window.
func (r *RenewalInfo) Describe(now time.Time) string {
	switch {
	case now.Before(r.SuggestedWindow.Start):
		d := time.Until(r.SuggestedWindow.Start).Round(time.Minute)
		return fmt.Sprintf("Renewal window opens in %s (at %s UTC).", d, r.SuggestedWindow.Start.UTC().Format(time.RFC3339))
	case now.Before(r.SuggestedWindow.End):
		d := time.Until(r.SuggestedWindow.End).Round(time.Minute)
		return fmt.Sprintf("Inside renewal window — renew now. Window closes in %s.", d)
	default:
		return fmt.Sprintf("Renewal window has closed (ended %s UTC). Renew immediately.", r.SuggestedWindow.End.UTC().Format(time.RFC3339))
	}
}

// CertID builds the ARI cert identifier `base64url(AKI) . base64url(serial)`
// per draft-ietf-acme-ari §4.1.
func CertID(cert *x509.Certificate) (string, error) {
	if cert == nil {
		return "", fmt.Errorf("ari: nil cert")
	}
	if len(cert.AuthorityKeyId) == 0 {
		return "", fmt.Errorf("ari: cert has no AuthorityKeyIdentifier extension")
	}
	aki := base64.RawURLEncoding.EncodeToString(cert.AuthorityKeyId)
	// Encode the serial as its minimal big-endian bytes.
	serialBytes := cert.SerialNumber.Bytes()
	if len(serialBytes) == 0 {
		serialBytes = []byte{0}
	}
	serial := base64.RawURLEncoding.EncodeToString(serialBytes)
	return aki + "." + serial, nil
}

// Directory is the subset of the ACME directory JSON we care about.
type Directory struct {
	NewNonce   string `json:"newNonce"`
	NewAccount string `json:"newAccount"`
	NewOrder   string `json:"newOrder"`
	// RenewalInfo is the ARI endpoint (LE calls it `renewalInfo`).
	RenewalInfo string `json:"renewalInfo"`
}

// FetchDirectory GETs the ACME directory JSON.
func FetchDirectory(client *http.Client, url string) (*Directory, error) {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "tigertrust/acme-ari-demo")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return nil, fmt.Errorf("directory %s: %d %s", url, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var d Directory
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return nil, fmt.Errorf("directory decode: %w", err)
	}
	if d.RenewalInfo == "" {
		return nil, fmt.Errorf("directory %s: no renewalInfo endpoint (CA may not implement ARI)", url)
	}
	return &d, nil
}

// Fetch retrieves RenewalInfo for an existing cert.
func Fetch(client *http.Client, renewalInfoBase string, cert *x509.Certificate) (*RenewalInfo, error) {
	id, err := CertID(cert)
	if err != nil {
		return nil, err
	}
	u := strings.TrimRight(renewalInfoBase, "/") + "/" + id
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "tigertrust/acme-ari-demo")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return nil, fmt.Errorf("ARI %s: %d %s", u, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var ri RenewalInfo
	if err := json.NewDecoder(resp.Body).Decode(&ri); err != nil {
		return nil, fmt.Errorf("ARI decode: %w", err)
	}
	return &ri, nil
}

// Thumbprint is a convenience for pretty-printing a cert's SHA-256 fingerprint.
func Thumbprint(cert *x509.Certificate) string {
	h := sha256.Sum256(cert.Raw)
	return strings.ToUpper(hexColons(h[:]))
}

func hexColons(b []byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, 0, len(b)*3)
	for i, v := range b {
		if i > 0 {
			out = append(out, ':')
		}
		out = append(out, hex[v>>4], hex[v&0x0f])
	}
	return string(out)
}
