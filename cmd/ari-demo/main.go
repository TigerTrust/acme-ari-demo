// Command ari-demo is an educational ACME + Renewal Information (ARI) demo.
//
// It defaults to Let's Encrypt STAGING. Do NOT point it at production LE
// unless you know what you are doing — this repo is a teaching tool, not a
// certificate lifecycle manager.
//
// Subcommands:
//
//	ari-demo issue     — register account, issue a cert with manual DNS-01, print ARI
//	ari-demo ari-check — fetch ARI only for an existing PEM
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/acme"

	"github.com/tigertrust/acme-ari-demo/internal/ari"
)

// Let's Encrypt staging directory — the default so this tool can't accidentally
// hammer prod LE while we're teaching ARI.
const defaultDirectoryURL = "https://acme-staging-v02.api.letsencrypt.org/directory"

func main() {
	if len(os.Args) < 2 {
		printTopUsage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "issue":
		runIssue(os.Args[2:])
	case "ari-check":
		runARICheck(os.Args[2:])
	case "-h", "--help", "help":
		printTopUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", os.Args[1])
		printTopUsage()
		os.Exit(2)
	}
}

func printTopUsage() {
	fmt.Fprint(os.Stderr, `ari-demo — TigerTrust ACME + Renewal Information (ARI) teaching demo

Subcommands:
  issue      Register an ACME account and issue a cert with manual DNS-01,
             then print the Renewal Information (ARI) window.
  ari-check  Fetch ARI only, for an existing PEM.

The default directory is Let's Encrypt STAGING. Do NOT point this at
production — this is an educational tool.

Examples:
  ari-demo issue --domain demo.example.com --email you@example.com
  ari-demo ari-check --cert ./_acme/cert.pem
  ari-demo ari-check --cert ./_acme/cert.pem --json

Run "ari-demo <subcommand> --help" for subcommand flags.
`)
}

// -------- issue ----------------------------------------------------------

func runIssue(args []string) {
	fs := flag.NewFlagSet("issue", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `ari-demo issue — register ACME account + issue a cert with manual DNS-01

Flags:
`)
		fs.PrintDefaults()
	}
	directoryURL := fs.String("directory-url", defaultDirectoryURL, "ACME directory URL (default: Let's Encrypt STAGING)")
	domain := fs.String("domain", "", "domain name to issue for")
	email := fs.String("email", "", "contact email for the ACME account")
	datadir := fs.String("datadir", "./_acme", "directory for account key, cert, and private key")
	jsonOut := fs.Bool("json", false, "emit JSON for the final ARI report")
	timeout := fs.Duration("timeout", 10*time.Minute, "overall timeout for issuance")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if *domain == "" || *email == "" {
		fs.Usage()
		os.Exit(2)
	}

	if strings.Contains(*directoryURL, "acme-v02.api.letsencrypt.org") {
		fmt.Fprintln(os.Stderr, "⚠ WARNING: pointed at Let's Encrypt PRODUCTION. Ctrl-C now unless intentional.")
		time.Sleep(3 * time.Second)
	}

	if err := os.MkdirAll(*datadir, 0o700); err != nil {
		die("mkdir datadir: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	// 1. Load/create account key.
	accountKey, err := loadOrCreateKey(filepath.Join(*datadir, "account.key"))
	if err != nil {
		die("account key: %v", err)
	}

	client := &acme.Client{
		DirectoryURL: *directoryURL,
		Key:          accountKey,
		UserAgent:    "tigertrust/acme-ari-demo",
	}

	// 2. Discover the directory (for account registration).
	if _, err := client.Discover(ctx); err != nil {
		die("directory: %v", err)
	}
	// Separately, fetch the raw directory JSON so we can read the ARI endpoint,
	// which older x/crypto/acme versions don't expose on acme.Directory.
	rawDir, err := ari.FetchDirectory(nil, *directoryURL)
	if err != nil {
		die("ari directory: %v", err)
	}
	fmt.Fprintf(os.Stderr, "✓ ACME directory loaded: %s\n", *directoryURL)

	// 3. Register / confirm account.
	_, err = client.Register(ctx, &acme.Account{Contact: []string{"mailto:" + *email}}, acme.AcceptTOS)
	if err != nil && !isAlreadyRegistered(err) {
		die("register: %v", err)
	}
	fmt.Fprintln(os.Stderr, "✓ ACME account ready")

	// 4. Create an order.
	order, err := client.AuthorizeOrder(ctx, []acme.AuthzID{{Type: "dns", Value: *domain}})
	if err != nil {
		die("order: %v", err)
	}

	// 5. Pick the DNS-01 challenge and prompt the user to publish it.
	for _, authzURL := range order.AuthzURLs {
		authz, err := client.GetAuthorization(ctx, authzURL)
		if err != nil {
			die("authorization: %v", err)
		}
		if authz.Status == acme.StatusValid {
			continue
		}
		var dns01 *acme.Challenge
		for _, c := range authz.Challenges {
			if c.Type == "dns-01" {
				dns01 = c
				break
			}
		}
		if dns01 == nil {
			die("no dns-01 challenge offered for %s (this demo requires DNS-01)", authz.Identifier.Value)
		}
		token, err := client.DNS01ChallengeRecord(dns01.Token)
		if err != nil {
			die("dns01 record: %v", err)
		}
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "===== MANUAL DNS-01 =====")
		fmt.Fprintf(os.Stderr, "Publish this DNS TXT record and wait for propagation:\n\n")
		fmt.Fprintf(os.Stderr, "    _acme-challenge.%s.  TXT  %q\n\n", authz.Identifier.Value, token)
		fmt.Fprint(os.Stderr, "Press Enter when the record is in place... ")
		fmt.Scanln()

		if _, err := client.Accept(ctx, dns01); err != nil {
			die("accept: %v", err)
		}
		if _, err := client.WaitAuthorization(ctx, authz.URI); err != nil {
			die("wait authz: %v", err)
		}
		fmt.Fprintln(os.Stderr, "✓ Authorization valid")
	}

	// 6. Generate cert key + CSR, finalize.
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		die("cert key: %v", err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: *domain},
		DNSNames: []string{*domain},
	}, certKey)
	if err != nil {
		die("csr: %v", err)
	}
	der, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		die("finalize: %v", err)
	}

	certPath := filepath.Join(*datadir, "cert.pem")
	if err := writeChain(certPath, der); err != nil {
		die("write cert: %v", err)
	}
	keyPath := filepath.Join(*datadir, "cert.key")
	if err := writeECKey(keyPath, certKey); err != nil {
		die("write key: %v", err)
	}
	fmt.Fprintf(os.Stderr, "✓ Cert saved to %s\n", certPath)

	// 7. Fetch ARI.
	leaf, err := x509.ParseCertificate(der[0])
	if err != nil {
		die("parse leaf: %v", err)
	}
	printARI(rawDir.RenewalInfo, leaf, *jsonOut)
}

// -------- ari-check ------------------------------------------------------

func runARICheck(args []string) {
	fs := flag.NewFlagSet("ari-check", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `ari-demo ari-check — fetch ARI for an existing certificate

Flags:
`)
		fs.PrintDefaults()
	}
	certPath := fs.String("cert", "", "path to leaf certificate PEM")
	directoryURL := fs.String("directory-url", defaultDirectoryURL, "ACME directory URL (default: Let's Encrypt STAGING)")
	renewalInfoURL := fs.String("renewal-info-url", "", "ARI endpoint base URL (skips directory discovery if set)")
	jsonOut := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if *certPath == "" {
		fs.Usage()
		os.Exit(2)
	}

	data, err := os.ReadFile(*certPath)
	if err != nil {
		die("read cert: %v", err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		die("no CERTIFICATE PEM block in %s", *certPath)
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		die("parse cert: %v", err)
	}

	base := *renewalInfoURL
	if base == "" {
		d, err := ari.FetchDirectory(nil, *directoryURL)
		if err != nil {
			die("directory: %v", err)
		}
		base = d.RenewalInfo
	}
	printARI(base, leaf, *jsonOut)
}

// -------- helpers --------------------------------------------------------

func printARI(renewalBase string, leaf *x509.Certificate, jsonOut bool) {
	if renewalBase == "" {
		die("ARI endpoint unknown; pass --renewal-info-url or point at a directory that advertises one")
	}
	ri, err := ari.Fetch(nil, renewalBase, leaf)
	if err != nil {
		die("ari: %v", err)
	}
	now := time.Now()
	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(struct {
			Cert   string          `json:"cert"`
			Window ari.RenewalInfo `json:"renewalInfo"`
			InWindow bool          `json:"inWindow"`
			Note   string          `json:"note"`
		}{Cert: ari.Thumbprint(leaf), Window: *ri, InWindow: ri.InWindow(now), Note: ri.Describe(now)})
		return
	}
	fmt.Println("Cert thumbprint (SHA-256):", ari.Thumbprint(leaf))
	fmt.Println("NotAfter:                 ", leaf.NotAfter.UTC().Format(time.RFC3339))
	fmt.Println("Suggested window start:   ", ri.SuggestedWindow.Start.UTC().Format(time.RFC3339))
	fmt.Println("Suggested window end:     ", ri.SuggestedWindow.End.UTC().Format(time.RFC3339))
	if ri.ExplanationURL != "" {
		fmt.Println("Explanation:              ", ri.ExplanationURL)
	}
	fmt.Println("")
	fmt.Println(ri.Describe(now))
	fmt.Println("")
	fmt.Println("With 47-day certs, renew in the ARI window — not on a fixed calendar day.")
}

func loadOrCreateKey(path string) (*ecdsa.PrivateKey, error) {
	if data, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("no PEM in %s", path)
		}
		return x509.ParseECPrivateKey(block.Bytes)
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := writeECKey(path, k); err != nil {
		return nil, err
	}
	return k, nil
}

func writeECKey(path string, k *ecdsa.PrivateKey) error {
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

func writeChain(path string, ders [][]byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, der := range ders {
		if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
			return err
		}
	}
	return nil
}

func isAlreadyRegistered(err error) bool {
	if err == nil {
		return false
	}
	// x/crypto/acme returns an error containing "account already exists" or a
	// 409 from the server.
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "already") || strings.Contains(msg, "conflict")
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}

