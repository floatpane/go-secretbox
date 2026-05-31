<div align="center">

# go-secretbox

**Password-based encryption for data at rest, in Go. Argon2id + AES-256-GCM, done right.**

[![Go Version](https://img.shields.io/github/go-mod/go-version/floatpane/go-secretbox)](https://golang.org)
[![Go Reference](https://pkg.go.dev/badge/github.com/floatpane/go-secretbox.svg)](https://pkg.go.dev/github.com/floatpane/go-secretbox)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/floatpane/go-secretbox)](https://github.com/floatpane/go-secretbox/releases)
[![CI](https://github.com/floatpane/go-secretbox/actions/workflows/ci.yml/badge.svg)](https://github.com/floatpane/go-secretbox/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

</div>

`go-secretbox` is the boring, correct version of the encryption code everyone ends up writing once: stretch a password with a slow KDF, encrypt with an authenticated cipher, prepend the nonce, store a salt, verify the password without storing it. It gets the parts that are easy to get wrong — nonce generation, constant-time checks, key zeroing, self-describing formats — out of your codebase.

It was extracted from [matcha](https://github.com/floatpane/matcha)'s "secure mode," which encrypts a mail client's config and caches behind a master password.

## Features

- **Two layers, one set of primitives.**
  - `Seal` / `Unseal` — one-shot, self-describing blobs. The salt and KDF parameters travel *inside* the ciphertext, so a blob is decryptable years later with only the password.
  - `Vault` — the long-lived "secure mode" pattern: a metadata file with a salt + encrypted sentinel, an in-memory session key, transparent file encryption, password change, and key rotation.
- **Sentinel password verification.** No password, and no hash of it, is ever stored. `Unlock` decrypts a known sentinel and compares in constant time.
- **Pluggable KDF and cipher.** Argon2id + AES-256-GCM by default; swap in XChaCha20-Poly1305 (or your own `KDF`/`Cipher`) via options. The choice is recorded in metadata, so `Unlock`/`Unseal` always reconstruct the right algorithm.
- **Key hygiene.** Derived keys are zeroed after use and on `Lock`. `Rekey` decrypts-all-then-rotates so a failure can't leave files stranded.
- **Small surface, single dependency.** Just `golang.org/x/crypto`.

## Install

```bash
go get github.com/floatpane/go-secretbox
```

Requires Go 1.26+.

## Usage

### One-shot: encrypt a blob with a password

```go
package main

import (
    "fmt"
    "log"

    "github.com/floatpane/go-secretbox"
)

func main() {
    blob, err := secretbox.Seal([]byte("attack at dawn"), "correct horse battery staple")
    if err != nil {
        log.Fatal(err)
    }
    // blob is safe to write to disk — it carries its own salt + KDF params.

    plain, err := secretbox.Unseal(blob, "correct horse battery staple")
    if err != nil {
        log.Fatal(err) // ErrDecrypt on wrong password or tampering
    }
    fmt.Println(string(plain)) // attack at dawn
}
```

### Vault: "secure mode" with a master password

```go
v := secretbox.NewVault("/home/me/.config/app/secure.meta")

// First run — turn secure mode on.
if !v.Initialized() {
    if err := v.Init(masterPassword); err != nil {
        log.Fatal(err)
    }
}

// Later runs — unlock with the master password.
if err := v.Unlock(masterPassword); err != nil {
    log.Fatal(err) // ErrWrongPassword
}
defer v.Lock() // zeroes the session key

// Transparent file encryption while unlocked.
v.WriteFile("/home/me/.config/app/config.json", configBytes, 0o600)
data, _ := v.ReadFile("/home/me/.config/app/config.json")
```

### Rotate the master password (and migrate files)

```go
// Decrypts every file with the old key, rotates the vault, re-encrypts with
// the new key. Phase-ordered so a crash can't strand your data.
err := v.Rekey(newPassword, []string{
    "/home/me/.config/app/config.json",
    "/home/me/.config/app/cache.db",
})
```

### Choose a different cipher

```go
v := secretbox.NewVault(metaPath,
    secretbox.WithCipher(secretbox.ChaCha20Poly1305{}),
    secretbox.WithKDF(secretbox.NewArgon2id(secretbox.Argon2idParams{
        Time: 4, Memory: 128 * 1024, Threads: 4,
    })),
)
```

## Defaults

| Knob | Default | Notes |
|------|---------|-------|
| KDF | Argon2id | `Time=3, Memory=64 MiB, Threads=4` (interactive-login baseline) |
| Cipher | AES-256-GCM | 32-byte key, 12-byte random nonce, prepended to ciphertext |
| Salt | 16 random bytes | fresh per `Init`/`Seal`/`Rekey` |
| Sentinel | `secretbox-verified` | encrypted under the key, compared constant-time on `Unlock` |

## What this is not

- **Not key management.** It protects data *with a password*. If the password leaks, so does the data.
- **Not memory-hardened against root.** While unlocked, the key lives in process memory. A privileged local attacker (or a core dump) can read it. `Lock` shortens that window; it does not close it against an attacker with `ptrace`.
- **Not a replacement for an OS keyring.** It's complementary — matcha uses the keyring when secure mode is off and a `Vault` when it's on.

## Documentation

Full API reference: [pkg.go.dev/github.com/floatpane/go-secretbox](https://pkg.go.dev/github.com/floatpane/go-secretbox)

Guides and diagrams: see [`docs/`](docs/).

## Sister projects

| Project | Role |
|---------|------|
| [floatpane/matcha](https://github.com/floatpane/matcha) | Reference consumer — uses this library for its config/cache "secure mode." |
| [floatpane/go-uds-jsonrpc](https://github.com/floatpane/go-uds-jsonrpc) | Sibling extraction — local daemon JSON-RPC over Unix sockets. |

## Contributing

PRs welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

Report vulnerabilities privately via [SECURITY.md](SECURITY.md).

## License

MIT. See [LICENSE](LICENSE).
