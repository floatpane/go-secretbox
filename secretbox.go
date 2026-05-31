// Package secretbox encrypts data at rest with a password.
//
// It pairs a key-derivation function (Argon2id by default) with an
// authenticated cipher (AES-256-GCM by default) behind two layers:
//
//   - One-shot functions Seal and Unseal produce a self-describing blob that
//     carries its own salt and KDF parameters — decryptable years later with
//     only the password.
//   - A Vault manages the long-lived "secure mode" pattern: a metadata file
//     with a salt and an encrypted sentinel, an in-memory session key, and
//     transparent file encryption, plus password change and key rotation.
//
// Both layers default to the same primitives matcha uses, and both accept
// custom KDF/Cipher implementations via options.
package secretbox

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
)

// Sentinel errors. Compare with errors.Is.
var (
	// ErrDecrypt is returned for any decryption failure: wrong key, truncated
	// input, or authentication-tag mismatch. It deliberately does not say
	// which, to avoid leaking information to an attacker.
	ErrDecrypt = errors.New("secretbox: decryption failed")
	// ErrWrongPassword is returned by Vault.Unlock when the password fails the
	// sentinel check.
	ErrWrongPassword = errors.New("secretbox: incorrect password")
	// ErrLocked is returned by Vault operations that need the session key while
	// the vault is locked.
	ErrLocked = errors.New("secretbox: vault is locked")
	// ErrNotInitialized is returned when a vault's metadata file is absent.
	ErrNotInitialized = errors.New("secretbox: vault not initialized")
	// ErrUnsupported is returned when metadata names a KDF or cipher this build
	// does not know how to construct.
	ErrUnsupported = errors.New("secretbox: unsupported algorithm")
)

const (
	saltLen = 16

	sealMagic    = "SBX1"
	kdfArgon2id  = 1
	cipherAES    = 1
	cipherChaCha = 2
)

// Seal encrypts plaintext with password using the default primitives
// (Argon2id + AES-256-GCM) and returns a self-describing blob.
//
// The blob embeds a fresh random salt and the KDF parameters, so Unseal needs
// only the password. Use SealWith to choose different primitives.
func Seal(plaintext []byte, password string) ([]byte, error) {
	return SealWith(plaintext, password, NewArgon2id(DefaultArgon2id), AESGCM{})
}

// SealWith is Seal with an explicit KDF and cipher.
func SealWith(plaintext []byte, password string, kdf KDF, c Cipher) ([]byte, error) {
	kid, cid, err := algoIDs(kdf, c)
	if err != nil {
		return nil, err
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("secretbox: salt: %w", err)
	}
	key := kdf.DeriveKey(password, salt, uint32(c.KeySize()))
	defer zero(key)

	body, err := c.Encrypt(plaintext, key)
	if err != nil {
		return nil, err
	}

	p := kdf.Params()
	// Header: magic | kdfID | cipherID | time | memory | threads | saltLen | salt
	out := make([]byte, 0, 4+1+1+4+4+1+1+len(salt)+len(body))
	out = append(out, sealMagic...)
	out = append(out, kid, cid)
	out = binary.BigEndian.AppendUint32(out, p["time"])
	out = binary.BigEndian.AppendUint32(out, p["memory"])
	out = append(out, byte(p["threads"]), byte(len(salt)))
	out = append(out, salt...)
	out = append(out, body...)
	return out, nil
}

// Unseal reverses Seal/SealWith. It reads the embedded header to reconstruct
// the KDF and cipher, so the caller supplies only the password.
func Unseal(blob []byte, password string) ([]byte, error) {
	const headFixed = 4 + 1 + 1 + 4 + 4 + 1 + 1
	if len(blob) < headFixed || string(blob[:4]) != sealMagic {
		return nil, ErrDecrypt
	}
	kid, cid := blob[4], blob[5]
	params := map[string]uint32{
		"time":    binary.BigEndian.Uint32(blob[6:10]),
		"memory":  binary.BigEndian.Uint32(blob[10:14]),
		"threads": uint32(blob[14]),
	}
	sl := int(blob[15])
	if len(blob) < headFixed+sl {
		return nil, ErrDecrypt
	}
	salt := blob[headFixed : headFixed+sl]
	body := blob[headFixed+sl:]

	kdf, err := kdfByName(kid, params)
	if err != nil {
		return nil, err
	}
	c, err := cipherByCode(cid)
	if err != nil {
		return nil, err
	}
	key := kdf.DeriveKey(password, salt, uint32(c.KeySize()))
	defer zero(key)
	return c.Decrypt(body, key)
}

func algoIDs(kdf KDF, c Cipher) (kid, cid byte, err error) {
	switch kdf.ID() {
	case "argon2id":
		kid = kdfArgon2id
	default:
		return 0, 0, fmt.Errorf("%w: kdf %q not supported by Seal", ErrUnsupported, kdf.ID())
	}
	switch c.ID() {
	case "aes-256-gcm":
		cid = cipherAES
	case "xchacha20-poly1305":
		cid = cipherChaCha
	default:
		return 0, 0, fmt.Errorf("%w: cipher %q not supported by Seal", ErrUnsupported, c.ID())
	}
	return kid, cid, nil
}

func kdfByName(code byte, params map[string]uint32) (KDF, error) {
	switch code {
	case kdfArgon2id:
		return argon2idFromParams(params), nil
	default:
		return nil, fmt.Errorf("%w: kdf code %d", ErrUnsupported, code)
	}
}

func cipherByCode(code byte) (Cipher, error) {
	switch code {
	case cipherAES:
		return AESGCM{}, nil
	case cipherChaCha:
		return ChaCha20Poly1305{}, nil
	default:
		return nil, fmt.Errorf("%w: cipher code %d", ErrUnsupported, code)
	}
}

// zero overwrites key material in place. Best-effort; the compiler may still
// keep copies, but it shortens the window for obvious leaks.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
