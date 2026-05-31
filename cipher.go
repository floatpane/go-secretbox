package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// Cipher is an authenticated encryption scheme keyed by a KDF-derived key.
//
// Encrypt must generate a fresh random nonce per call and prepend it to the
// returned ciphertext; Decrypt reverses that framing. Implementations are
// stateless and safe for concurrent use.
type Cipher interface {
	// Encrypt seals plaintext under key, returning nonce-prefixed ciphertext.
	Encrypt(plaintext, key []byte) ([]byte, error)
	// Decrypt opens ciphertext produced by Encrypt. It returns ErrDecrypt on
	// any authentication or format failure.
	Decrypt(ciphertext, key []byte) ([]byte, error)
	// ID is the stable identifier persisted in vault metadata.
	ID() string
	// KeySize is the required key length in bytes.
	KeySize() int
}

// sealAEAD is the shared nonce-prepend framing used by every AEAD cipher here.
func sealAEAD(aead cipher.AEAD, plaintext []byte) ([]byte, error) {
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("secretbox: nonce: %w", err)
	}
	return aead.Seal(nonce, nonce, plaintext, nil), nil
}

// openAEAD reverses sealAEAD.
func openAEAD(aead cipher.AEAD, ciphertext []byte) ([]byte, error) {
	ns := aead.NonceSize()
	if len(ciphertext) < ns {
		return nil, ErrDecrypt
	}
	nonce, enc := ciphertext[:ns], ciphertext[ns:]
	plaintext, err := aead.Open(nil, nonce, enc, nil)
	if err != nil {
		return nil, ErrDecrypt
	}
	return plaintext, nil
}

// AESGCM is the default cipher: AES-256 in Galois/Counter Mode. The key must
// be exactly 32 bytes. This matches matcha's on-disk format.
type AESGCM struct{}

// Encrypt implements Cipher.
func (AESGCM) Encrypt(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("secretbox: aes: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("secretbox: gcm: %w", err)
	}
	return sealAEAD(aead, plaintext)
}

// Decrypt implements Cipher.
func (AESGCM) Decrypt(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("secretbox: aes: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("secretbox: gcm: %w", err)
	}
	return openAEAD(aead, ciphertext)
}

// ID implements Cipher.
func (AESGCM) ID() string { return "aes-256-gcm" }

// KeySize implements Cipher.
func (AESGCM) KeySize() int { return 32 }

// ChaCha20Poly1305 is an alternative cipher using the XChaCha20-Poly1305 AEAD,
// which has a 24-byte nonce (safe to generate randomly without a counter). The
// key must be exactly 32 bytes. Prefer this on platforms without AES hardware
// acceleration.
type ChaCha20Poly1305 struct{}

// Encrypt implements Cipher.
func (ChaCha20Poly1305) Encrypt(plaintext, key []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("secretbox: chacha20: %w", err)
	}
	return sealAEAD(aead, plaintext)
}

// Decrypt implements Cipher.
func (ChaCha20Poly1305) Decrypt(ciphertext, key []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("secretbox: chacha20: %w", err)
	}
	return openAEAD(aead, ciphertext)
}

// ID implements Cipher.
func (ChaCha20Poly1305) ID() string { return "xchacha20-poly1305" }

// KeySize implements Cipher.
func (ChaCha20Poly1305) KeySize() int { return chacha20poly1305.KeySize }

// cipherByID resolves a persisted cipher identifier back to an implementation.
func cipherByID(id string) (Cipher, error) {
	switch id {
	case "aes-256-gcm":
		return AESGCM{}, nil
	case "xchacha20-poly1305":
		return ChaCha20Poly1305{}, nil
	default:
		return nil, fmt.Errorf("%w: cipher %q", ErrUnsupported, id)
	}
}

// kdfByID resolves a persisted KDF identifier + params back to an implementation.
func kdfByID(id string, params map[string]uint32) (KDF, error) {
	switch id {
	case "argon2id":
		return argon2idFromParams(params), nil
	default:
		return nil, fmt.Errorf("%w: kdf %q", ErrUnsupported, id)
	}
}
