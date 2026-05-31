# Security Policy

## Supported Versions

Only the latest release of go-secretbox is supported with security updates.

## Reporting a Vulnerability

If you discover a security vulnerability in go-secretbox, please report it responsibly. **Do not open a public issue.**

Email us at [us@floatpane.com](mailto:us@floatpane.com) with:

- A description of the vulnerability
- Steps to reproduce the issue
- The potential impact
- Any suggested fixes (optional)

We will acknowledge your report within 48 hours and aim to provide a fix or mitigation plan within 7 days, depending on severity.

## Scope

This policy covers the go-secretbox codebase and its official releases.

Of particular interest, since this is a cryptographic library:

- **Nonce reuse** — any code path where a fixed or predictable nonce could be fed to an AEAD, breaking confidentiality/integrity.
- **Sentinel oracle** — `Vault.Unlock` leaking timing or error detail that distinguishes "wrong password" from "corrupt metadata" beyond what is intended.
- **Weak defaults** — `DefaultArgon2id` parameters that are too low for the stated interactive-login threat model.
- **Key-zeroing failures** — derived keys surviving `Lock`/`Rekey`/`zero` longer than documented, or being copied where they cannot be wiped.
- **Rekey corruption** — a partial `Rekey` (crash, disk-full, decrypt failure) leaving files unreadable under both old and new passwords.
- **Format confusion** — a crafted `Seal` blob or metadata file that triggers panics, runaway allocations, or decrypts under an unintended algorithm.

Note the explicit non-goals (see the docs): go-secretbox does not protect keys in memory against a privileged local attacker, and offers no protection once the password is known.

Third-party dependencies (notably `golang.org/x/crypto`) are outside our direct control, but we will work to address reported issues in them as quickly as possible.

## Disclosure

We ask that you give us reasonable time to address the issue before disclosing it publicly. We are committed to crediting reporters in release notes (unless you prefer to remain anonymous).
