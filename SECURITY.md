# Security policy

## Supported versions

The `main` branch and the latest tagged release receive security fixes.

## Reporting a vulnerability

Please email **security@tigertrust.io** with a description of the issue, steps
to reproduce, and any proof-of-concept. We acknowledge reports within 3
business days and aim to ship fixes within 30 days for critical findings.

Do **not** file public GitHub issues for vulnerabilities.

## Scope and warnings

**This repository is an educational demo, not a certificate lifecycle
manager.** It defaults to Let's Encrypt STAGING. Do not use it to manage
production certificates.

- ACME account keys are written to `./_acme/account.key` with mode `0600`.
  Rotate or delete them when you're done.
- The tool stores leaf private keys in the same directory. Treat `_acme/` as
  a secrets directory; it is in `.gitignore` by default.
- No data is transmitted to TigerTrust.
