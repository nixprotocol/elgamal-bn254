package elgamal

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/stretchr/testify/require"
)

// TestKeyGen_HonorsRng verifies that KeyGen actually uses the rng parameter.
// Previously SetRandom() hardcoded crypto/rand and silently ignored the
// argument; this test pins the new behavior where deterministic seeds yield
// deterministic keys (enabling KAT / test-vector generation).
func TestKeyGen_HonorsRng(t *testing.T) {
	// Use a deterministic byte source. 128 bytes is plenty for one scalar draw
	// even with rejection sampling.
	seedBytes := make([]byte, 128)
	for i := range seedBytes {
		seedBytes[i] = byte(i ^ 0xA5)
	}

	sk1, pk1, err := KeyGen(bytes.NewReader(seedBytes))
	require.NoError(t, err)
	sk2, pk2, err := KeyGen(bytes.NewReader(seedBytes))
	require.NoError(t, err)

	require.True(t, sk1.Equal(&sk2), "KeyGen with same seeded reader must produce same sk")
	require.True(t, pk1.Equal(&pk2), "KeyGen with same seeded reader must produce same pk")

	// And different seed should produce a different key.
	otherSeed := make([]byte, 128)
	for i := range otherSeed {
		otherSeed[i] = byte(i ^ 0x5A)
	}
	sk3, _, err := KeyGen(bytes.NewReader(otherSeed))
	require.NoError(t, err)
	require.False(t, sk1.Equal(&sk3), "different seeds must produce different keys")
}

func TestKeyGen(t *testing.T) {
	sk, pk, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	// sk must not be zero.
	var zero fr.Element
	require.False(t, sk.Equal(&zero), "secret key must not be zero")

	// pk must be a valid public key (on curve, not identity).
	err = ValidatePublicKey(&pk)
	require.NoError(t, err, "public key must be valid")
}

func TestEncryptDecrypt(t *testing.T) {
	sk, pk, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	amount := uint64(1000000)
	ct, _, err := Encrypt(amount, &pk, rand.Reader)
	require.NoError(t, err)

	table := NewDecryptionTable(20)
	decrypted, err := Decrypt(&ct, &sk, table)
	require.NoError(t, err)
	require.Equal(t, amount, decrypted, "decrypted amount must match original")
}

func TestEncryptDecryptZero(t *testing.T) {
	sk, pk, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	ct, _, err := Encrypt(0, &pk, rand.Reader)
	require.NoError(t, err)

	table := NewDecryptionTable(20)
	decrypted, err := Decrypt(&ct, &sk, table)
	require.NoError(t, err)
	require.Equal(t, uint64(0), decrypted, "decrypted amount must be 0")
}

func TestHomomorphicAdd(t *testing.T) {
	sk, pk, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	ct1, _, err := Encrypt(300, &pk, rand.Reader)
	require.NoError(t, err)

	ct2, _, err := Encrypt(700, &pk, rand.Reader)
	require.NoError(t, err)

	sum := Add(&ct1, &ct2)

	table := NewDecryptionTable(20)
	decrypted, err := Decrypt(&sum, &sk, table)
	require.NoError(t, err)
	require.Equal(t, uint64(1000), decrypted, "300 + 700 must equal 1000")
}

// TestAdd_NilPanicsClearly pins the public API: Add must reject nil with a
// clear panic (not a generic SIGSEGV), matching the nil-check hygiene of
// Decrypt. A nil ciphertext is a programming error, so panic is the right
// signal (the function signature has no error return).
func TestAdd_NilPanicsClearly(t *testing.T) {
	_, pk, err := KeyGen(rand.Reader)
	require.NoError(t, err)
	ct, _, err := Encrypt(1, &pk, rand.Reader)
	require.NoError(t, err)

	require.PanicsWithValue(t, "elgamal: Add called with nil ciphertext", func() {
		_ = Add(nil, &ct)
	})
	require.PanicsWithValue(t, "elgamal: Add called with nil ciphertext", func() {
		_ = Add(&ct, nil)
	})
}

func TestSub_NilPanicsClearly(t *testing.T) {
	_, pk, err := KeyGen(rand.Reader)
	require.NoError(t, err)
	ct, _, err := Encrypt(1, &pk, rand.Reader)
	require.NoError(t, err)

	require.PanicsWithValue(t, "elgamal: Sub called with nil ciphertext", func() {
		_ = Sub(nil, &ct)
	})
	require.PanicsWithValue(t, "elgamal: Sub called with nil ciphertext", func() {
		_ = Sub(&ct, nil)
	})
}

func TestHomomorphicSub(t *testing.T) {
	sk, pk, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	ct1, _, err := Encrypt(1000, &pk, rand.Reader)
	require.NoError(t, err)

	ct2, _, err := Encrypt(300, &pk, rand.Reader)
	require.NoError(t, err)

	diff := Sub(&ct1, &ct2)

	table := NewDecryptionTable(20)
	decrypted, err := Decrypt(&diff, &sk, table)
	require.NoError(t, err)
	require.Equal(t, uint64(700), decrypted, "1000 - 300 must equal 700")
}
