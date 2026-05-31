package secretbox

import "golang.org/x/crypto/argon2"

// KDF derives a symmetric key from a low-entropy password and a random salt.
//
// Implementations must be deterministic: the same password, salt, and
// parameters always produce the same key. The returned key length must equal
// the cipher's KeySize.
type KDF interface {
	// DeriveKey stretches password+salt into a key of keyLen bytes.
	DeriveKey(password string, salt []byte, keyLen uint32) []byte
	// ID is the stable identifier persisted in vault metadata (e.g. "argon2id").
	ID() string
	// Params returns the tunable parameters so they can be stored alongside the
	// salt and reproduced on unlock.
	Params() map[string]uint32
}

// Argon2idParams configures the Argon2id key-derivation function.
//
// The zero value is not usable; start from DefaultArgon2id and adjust. Higher
// Time/Memory raise the cost of a brute-force attack at the expense of latency
// on the legitimate path.
type Argon2idParams struct {
	Time    uint32 // number of passes over memory
	Memory  uint32 // memory in KiB
	Threads uint8  // parallelism
}

// DefaultArgon2id is a sensible interactive-login baseline: 3 passes over
// 64 MiB across 4 lanes. It matches the parameters matcha ships with.
var DefaultArgon2id = Argon2idParams{Time: 3, Memory: 64 * 1024, Threads: 4}

// Argon2id is the default KDF. It implements KDF using the Argon2id variant,
// which resists both GPU and side-channel attacks.
type Argon2id struct {
	params Argon2idParams
}

// NewArgon2id returns an Argon2id KDF with the given parameters. Passing the
// zero value falls back to DefaultArgon2id.
func NewArgon2id(p Argon2idParams) Argon2id {
	if p == (Argon2idParams{}) {
		p = DefaultArgon2id
	}
	return Argon2id{params: p}
}

// DeriveKey implements KDF.
func (a Argon2id) DeriveKey(password string, salt []byte, keyLen uint32) []byte {
	p := a.params
	if p == (Argon2idParams{}) {
		p = DefaultArgon2id
	}
	return argon2.IDKey([]byte(password), salt, p.Time, p.Memory, p.Threads, keyLen)
}

// ID implements KDF.
func (Argon2id) ID() string { return "argon2id" }

// Params implements KDF.
func (a Argon2id) Params() map[string]uint32 {
	p := a.params
	if p == (Argon2idParams{}) {
		p = DefaultArgon2id
	}
	return map[string]uint32{
		"time":    p.Time,
		"memory":  p.Memory,
		"threads": uint32(p.Threads),
	}
}

// argon2idFromParams rebuilds an Argon2id KDF from persisted metadata params.
func argon2idFromParams(m map[string]uint32) Argon2id {
	return Argon2id{params: Argon2idParams{
		Time:    m["time"],
		Memory:  m["memory"],
		Threads: uint8(m["threads"]),
	}}
}
