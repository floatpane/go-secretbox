package secretbox

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// sentinelPlaintext is encrypted under the derived key and stored in the
// metadata file. Unlock decrypts it and compares: a match proves the password
// without ever storing the password or a hash of it.
const sentinelPlaintext = "secretbox-verified"

// Meta is the JSON document written to the vault's metadata file. It holds
// everything needed to re-derive the key from a password — except the password
// itself. It is safe to store in plaintext.
type Meta struct {
	Version  int               `json:"version"`
	KDF      string            `json:"kdf"`
	Cipher   string            `json:"cipher"`
	Salt     string            `json:"salt"`     // base64
	Sentinel string            `json:"sentinel"` // base64 ciphertext of sentinelPlaintext
	Params   map[string]uint32 `json:"params"`   // KDF parameters
}

// Vault implements the "secure mode" pattern: a metadata file with a salt and
// an encrypted sentinel, an in-memory session key derived on Unlock, and
// transparent file encryption while unlocked.
//
// A Vault is safe for concurrent use once unlocked. Lock zeroes the key.
type Vault struct {
	metaPath string
	kdf      KDF
	cipher   Cipher

	mu  sync.RWMutex
	key []byte // nil when locked
}

// Option configures a Vault.
type Option func(*Vault)

// WithKDF sets the key-derivation function used for new vaults and one-shot
// sealing. On Unlock the KDF is reconstructed from metadata instead, so this
// only affects Init. Defaults to Argon2id with DefaultArgon2id parameters.
func WithKDF(kdf KDF) Option { return func(v *Vault) { v.kdf = kdf } }

// WithCipher sets the cipher used for new vaults. On Unlock the cipher is
// reconstructed from metadata. Defaults to AES-256-GCM.
func WithCipher(c Cipher) Option { return func(v *Vault) { v.cipher = c } }

// NewVault returns a vault backed by the metadata file at metaPath. It does not
// touch the filesystem; call Init to create a new vault or Unlock to open an
// existing one.
func NewVault(metaPath string, opts ...Option) *Vault {
	v := &Vault{
		metaPath: metaPath,
		kdf:      NewArgon2id(DefaultArgon2id),
		cipher:   AESGCM{},
	}
	for _, o := range opts {
		o(v)
	}
	return v
}

// Initialized reports whether the metadata file exists, i.e. whether secure
// mode has been enabled for this vault.
func (v *Vault) Initialized() bool {
	_, err := os.Stat(v.metaPath)
	return err == nil
}

// Init creates a new vault: it generates a random salt, derives the key from
// password, encrypts the sentinel, writes the metadata file, and leaves the
// vault unlocked with the session key set.
//
// It fails if the vault is already initialized.
func (v *Vault) Init(password string) error {
	if v.Initialized() {
		return fmt.Errorf("secretbox: already initialized at %s", v.metaPath)
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("secretbox: salt: %w", err)
	}
	key := v.kdf.DeriveKey(password, salt, uint32(v.cipher.KeySize()))

	sentinel, err := v.cipher.Encrypt([]byte(sentinelPlaintext), key)
	if err != nil {
		zero(key)
		return err
	}
	meta := Meta{
		Version:  1,
		KDF:      v.kdf.ID(),
		Cipher:   v.cipher.ID(),
		Salt:     base64.StdEncoding.EncodeToString(salt),
		Sentinel: base64.StdEncoding.EncodeToString(sentinel),
		Params:   v.kdf.Params(),
	}
	if err := v.writeMeta(meta); err != nil {
		zero(key)
		return err
	}
	v.mu.Lock()
	v.key = key
	v.mu.Unlock()
	return nil
}

// Unlock derives the key from password, verifies it against the stored
// sentinel, and on success stores the session key. It reconstructs the KDF and
// cipher from metadata, so a vault created with non-default primitives unlocks
// correctly regardless of the options passed to NewVault.
//
// It returns ErrWrongPassword on mismatch and ErrNotInitialized if no metadata
// file exists.
func (v *Vault) Unlock(password string) error {
	meta, err := v.readMeta()
	if err != nil {
		return err
	}
	salt, err := base64.StdEncoding.DecodeString(meta.Salt)
	if err != nil {
		return fmt.Errorf("secretbox: corrupt salt: %w", err)
	}
	sentinel, err := base64.StdEncoding.DecodeString(meta.Sentinel)
	if err != nil {
		return fmt.Errorf("secretbox: corrupt sentinel: %w", err)
	}
	kdf, err := kdfByID(meta.KDF, meta.Params)
	if err != nil {
		return err
	}
	c, err := cipherByID(meta.Cipher)
	if err != nil {
		return err
	}
	key := kdf.DeriveKey(password, salt, uint32(c.KeySize()))

	plain, err := c.Decrypt(sentinel, key)
	if err != nil || subtle.ConstantTimeCompare(plain, []byte(sentinelPlaintext)) != 1 {
		zero(key)
		return ErrWrongPassword
	}
	v.mu.Lock()
	v.kdf, v.cipher = kdf, c
	v.key = key
	v.mu.Unlock()
	return nil
}

// Lock zeroes and discards the session key. After Lock, Encrypt/Decrypt/
// ReadFile/WriteFile return ErrLocked until the next Unlock.
func (v *Vault) Lock() {
	v.mu.Lock()
	zero(v.key)
	v.key = nil
	v.mu.Unlock()
}

// Key returns a copy of the current session key, or nil if the vault is
// locked.
//
// The returned slice is an independent copy — mutating it does not affect the
// key stored inside the vault, and the vault's Lock method will not zero the
// copy. Callers that hold the key beyond the immediate call should zero it
// explicitly (e.g. with a deferred loop) once it is no longer needed, to
// shorten the window during which key material sits in memory.
//
// The primary use case is bridging to an API that stores or passes around a
// raw key (as opposed to driving all encryption through the vault itself). For
// normal encrypt/decrypt operations, prefer Encrypt, Decrypt, ReadFile, and
// WriteFile, which never expose the key.
func (v *Vault) Key() []byte {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.key == nil {
		return nil
	}
	out := make([]byte, len(v.key))
	copy(out, v.key)
	return out
}

// Locked reports whether the session key is absent.
func (v *Vault) Locked() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.key == nil
}

// Encrypt seals plaintext with the session key. Returns ErrLocked if locked.
func (v *Vault) Encrypt(plaintext []byte) ([]byte, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.key == nil {
		return nil, ErrLocked
	}
	return v.cipher.Encrypt(plaintext, v.key)
}

// Decrypt opens ciphertext with the session key. Returns ErrLocked if locked.
func (v *Vault) Decrypt(ciphertext []byte) ([]byte, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.key == nil {
		return nil, ErrLocked
	}
	return v.cipher.Decrypt(ciphertext, v.key)
}

// WriteFile encrypts data and writes it to path with the given permissions.
// Returns ErrLocked if locked.
func (v *Vault) WriteFile(path string, data []byte, perm os.FileMode) error {
	enc, err := v.Encrypt(data)
	if err != nil {
		return err
	}
	return os.WriteFile(path, enc, perm)
}

// ReadFile reads path and decrypts it with the session key. Returns ErrLocked
// if locked.
func (v *Vault) ReadFile(path string) ([]byte, error) {
	enc, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return v.Decrypt(enc)
}

// ChangePassword re-keys the vault to newPassword. The vault must be unlocked
// (newer code can Unlock with the old password first). It generates a fresh
// salt, derives a new key, re-encrypts the sentinel, and rewrites metadata.
//
// Existing files encrypted with the old key are NOT touched — pass them to
// Rekey instead, which migrates files and rotates the password atomically from
// the caller's perspective.
func (v *Vault) ChangePassword(newPassword string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.key == nil {
		return ErrLocked
	}
	return v.rekeyMetaLocked(newPassword)
}

// Rekey migrates files to a new password: it decrypts each path with the
// current key, rotates the vault to newPassword, then re-encrypts each path
// with the new key. The vault must be unlocked.
//
// Files that do not exist are skipped. If a file fails to decrypt with the
// current key it is left untouched and an error is returned before any
// metadata change, so a wrong assumption cannot corrupt data.
func (v *Vault) Rekey(newPassword string, files []string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.key == nil {
		return ErrLocked
	}

	// Phase 1: decrypt everything with the old key (no writes yet).
	type pending struct {
		path string
		perm os.FileMode
		data []byte
	}
	var work []pending
	for _, f := range files {
		info, err := os.Stat(f)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		enc, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		plain, err := v.cipher.Decrypt(enc, v.key)
		if err != nil {
			return fmt.Errorf("secretbox: decrypt %s: %w", f, err)
		}
		work = append(work, pending{f, info.Mode().Perm(), plain})
	}

	// Phase 2: rotate the key + metadata.
	if err := v.rekeyMetaLocked(newPassword); err != nil {
		return err
	}

	// Phase 3: re-encrypt each file with the new key.
	for _, w := range work {
		enc, err := v.cipher.Encrypt(w.data, v.key)
		if err != nil {
			return err
		}
		if err := os.WriteFile(w.path, enc, w.perm); err != nil {
			return err
		}
		zero(w.data)
	}
	return nil
}

// rekeyMetaLocked derives a new key from newPassword under a fresh salt,
// rewrites the metadata, and swaps the session key. Caller must hold v.mu.
func (v *Vault) rekeyMetaLocked(newPassword string) error {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("secretbox: salt: %w", err)
	}
	newKey := v.kdf.DeriveKey(newPassword, salt, uint32(v.cipher.KeySize()))
	sentinel, err := v.cipher.Encrypt([]byte(sentinelPlaintext), newKey)
	if err != nil {
		zero(newKey)
		return err
	}
	meta := Meta{
		Version:  1,
		KDF:      v.kdf.ID(),
		Cipher:   v.cipher.ID(),
		Salt:     base64.StdEncoding.EncodeToString(salt),
		Sentinel: base64.StdEncoding.EncodeToString(sentinel),
		Params:   v.kdf.Params(),
	}
	if err := v.writeMeta(meta); err != nil {
		zero(newKey)
		return err
	}
	zero(v.key)
	v.key = newKey
	return nil
}

func (v *Vault) writeMeta(m Meta) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(v.metaPath), 0o700); err != nil {
		return err
	}
	return os.WriteFile(v.metaPath, data, 0o600)
}

func (v *Vault) readMeta() (Meta, error) {
	var m Meta
	data, err := os.ReadFile(v.metaPath)
	if os.IsNotExist(err) {
		return m, ErrNotInitialized
	}
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return m, fmt.Errorf("secretbox: corrupt metadata: %w", err)
	}
	return m, nil
}
