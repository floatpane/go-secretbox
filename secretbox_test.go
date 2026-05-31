package secretbox

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// fastArgon keeps tests quick — production should use DefaultArgon2id.
var fastArgon = NewArgon2id(Argon2idParams{Time: 1, Memory: 8 * 1024, Threads: 1})

func TestSealUnsealRoundTrip(t *testing.T) {
	plaintext := []byte("attack at dawn")
	blob, err := SealWith(plaintext, "hunter2", fastArgon, AESGCM{})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, plaintext) {
		t.Fatal("plaintext leaked into ciphertext")
	}
	got, err := Unseal(blob, "hunter2")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("got %q want %q", got, plaintext)
	}
}

func TestUnsealWrongPassword(t *testing.T) {
	blob, err := SealWith([]byte("x"), "right", fastArgon, AESGCM{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Unseal(blob, "wrong"); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("got %v want ErrDecrypt", err)
	}
}

func TestUnsealTampered(t *testing.T) {
	blob, _ := SealWith([]byte("payload"), "pw", fastArgon, AESGCM{})
	blob[len(blob)-1] ^= 0xff // flip a tag byte
	if _, err := Unseal(blob, "pw"); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("got %v want ErrDecrypt", err)
	}
}

func TestSealChaChaSelfDescribing(t *testing.T) {
	blob, err := SealWith([]byte("msg"), "pw", fastArgon, ChaCha20Poly1305{})
	if err != nil {
		t.Fatal(err)
	}
	// Unseal must pick the cipher from the header, not a default.
	got, err := Unseal(blob, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "msg" {
		t.Fatalf("got %q", got)
	}
}

func TestUnsealGarbage(t *testing.T) {
	if _, err := Unseal([]byte("not a real blob"), "pw"); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("got %v want ErrDecrypt", err)
	}
}

func newTestVault(t *testing.T) *Vault {
	t.Helper()
	dir := t.TempDir()
	return NewVault(filepath.Join(dir, "secure.meta"), WithKDF(fastArgon))
}

func TestVaultInitUnlockLock(t *testing.T) {
	v := newTestVault(t)
	if v.Initialized() {
		t.Fatal("fresh vault reports initialized")
	}
	if err := v.Init("pw"); err != nil {
		t.Fatal(err)
	}
	if !v.Initialized() || v.Locked() {
		t.Fatal("post-Init should be initialized + unlocked")
	}

	enc, err := v.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}

	v.Lock()
	if !v.Locked() {
		t.Fatal("expected locked")
	}
	if _, err := v.Decrypt(enc); !errors.Is(err, ErrLocked) {
		t.Fatalf("got %v want ErrLocked", err)
	}

	v2 := NewVault(v.metaPath, WithKDF(fastArgon))
	if err := v2.Unlock("pw"); err != nil {
		t.Fatal(err)
	}
	got, err := v2.Decrypt(enc)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "secret" {
		t.Fatalf("got %q", got)
	}
}

func TestVaultUnlockWrongPassword(t *testing.T) {
	v := newTestVault(t)
	if err := v.Init("correct"); err != nil {
		t.Fatal(err)
	}
	v.Lock()
	if err := v.Unlock("nope"); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("got %v want ErrWrongPassword", err)
	}
}

func TestVaultUnlockNotInitialized(t *testing.T) {
	v := newTestVault(t)
	if err := v.Unlock("pw"); !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("got %v want ErrNotInitialized", err)
	}
}

func TestVaultFileRoundTrip(t *testing.T) {
	v := newTestVault(t)
	if err := v.Init("pw"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "data.bin")
	if err := v.WriteFile(path, []byte("on disk"), 0o600); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	if bytes.Contains(raw, []byte("on disk")) {
		t.Fatal("file written in plaintext")
	}
	got, err := v.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "on disk" {
		t.Fatalf("got %q", got)
	}
}

func TestVaultRekeyMigratesFiles(t *testing.T) {
	v := newTestVault(t)
	if err := v.Init("old"); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	f1 := filepath.Join(dir, "a")
	f2 := filepath.Join(dir, "b")
	if err := v.WriteFile(f1, []byte("alpha"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := v.WriteFile(f2, []byte("beta"), 0o600); err != nil {
		t.Fatal(err)
	}

	missing := filepath.Join(dir, "ghost") // should be skipped, not error
	if err := v.Rekey("new", []string{f1, f2, missing}); err != nil {
		t.Fatal(err)
	}

	// Old password must no longer unlock.
	v.Lock()
	if err := v.Unlock("old"); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("old password still works: %v", err)
	}
	if err := v.Unlock("new"); err != nil {
		t.Fatal(err)
	}
	got1, err := v.ReadFile(f1)
	if err != nil {
		t.Fatal(err)
	}
	got2, err := v.ReadFile(f2)
	if err != nil {
		t.Fatal(err)
	}
	if string(got1) != "alpha" || string(got2) != "beta" {
		t.Fatalf("got %q,%q", got1, got2)
	}
}

func TestVaultChangePassword(t *testing.T) {
	v := newTestVault(t)
	if err := v.Init("old"); err != nil {
		t.Fatal(err)
	}
	if err := v.ChangePassword("new"); err != nil {
		t.Fatal(err)
	}
	v.Lock()
	if err := v.Unlock("new"); err != nil {
		t.Fatalf("new password rejected: %v", err)
	}
}

func TestVaultChangePasswordLocked(t *testing.T) {
	v := newTestVault(t)
	if err := v.Init("pw"); err != nil {
		t.Fatal(err)
	}
	v.Lock()
	if err := v.ChangePassword("x"); !errors.Is(err, ErrLocked) {
		t.Fatalf("got %v want ErrLocked", err)
	}
}

func TestVaultDefaultCipherIsAESGCM(t *testing.T) {
	v := NewVault(filepath.Join(t.TempDir(), "m"), WithKDF(fastArgon))
	if v.cipher.ID() != "aes-256-gcm" {
		t.Fatalf("default cipher %q", v.cipher.ID())
	}
}
