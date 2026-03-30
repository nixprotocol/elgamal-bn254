package elgamal

import (
	"crypto/rand"
	"fmt"
	"math"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/stretchr/testify/require"
)

// knownValueDecryptor implements the Decryptor interface by verifying the
// decrypted point matches an expected value. This avoids needing a BSGS table
// that covers 2^64, which would require ~320 GB of RAM.
type knownValueDecryptor struct {
	expected uint64
}

func (d *knownValueDecryptor) DiscreteLog(mG *bn254.G1Affine) (uint64, error) {
	var expectedMG bn254.G1Affine
	expectedMG.ScalarMultiplication(&G, new(big.Int).SetUint64(d.expected))
	if expectedMG.Equal(mG) {
		return d.expected, nil
	}
	return 0, fmt.Errorf("point does not match expected value %d", d.expected)
}

// ---------------------------------------------------------------------------
// Encrypt/Decrypt correctness for large values
// ---------------------------------------------------------------------------

func TestEncryptDecrypt_LargeValues(t *testing.T) {
	sk, pk, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	values := []struct {
		name   string
		amount uint64
	}{
		{"2^32", 1 << 32},
		{"2^48", 1 << 48},
		{"2^63", 1 << 63},
		{"2^64-1", math.MaxUint64},
		{"2^64-2", math.MaxUint64 - 1},
		{"2^63+1", (1 << 63) + 1},
		{"large odd", 0xDEADBEEFCAFEBABE},
	}

	for _, tc := range values {
		t.Run(tc.name, func(t *testing.T) {
			ct, _, err := Encrypt(tc.amount, &pk, rand.Reader)
			require.NoError(t, err, "encrypt should succeed")

			// Decrypt using known-value verifier.
			dec, err := Decrypt(&ct, &sk, &knownValueDecryptor{expected: tc.amount})
			require.NoError(t, err, "decryption point must match expected v*G")
			require.Equal(t, tc.amount, dec)
		})
	}
}

// ---------------------------------------------------------------------------
// Homomorphic operations on large values
// ---------------------------------------------------------------------------

func TestHomomorphicAdd_LargeValues(t *testing.T) {
	sk, pk, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	// Two values that sum to less than 2^64.
	a := uint64(math.MaxUint64 - 1000)
	b := uint64(500)
	expected := a + b // wraps if a+b >= 2^64, but here it doesn't

	ctA, _, err := Encrypt(a, &pk, rand.Reader)
	require.NoError(t, err)
	ctB, _, err := Encrypt(b, &pk, rand.Reader)
	require.NoError(t, err)

	sum := Add(&ctA, &ctB)

	dec, err := Decrypt(&sum, &sk, &knownValueDecryptor{expected: expected})
	require.NoError(t, err)
	require.Equal(t, expected, dec)
}

func TestHomomorphicSub_LargeValues(t *testing.T) {
	sk, pk, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	a := uint64(math.MaxUint64)
	b := uint64(math.MaxUint64 - 42)
	expected := a - b // = 42

	ctA, _, err := Encrypt(a, &pk, rand.Reader)
	require.NoError(t, err)
	ctB, _, err := Encrypt(b, &pk, rand.Reader)
	require.NoError(t, err)

	diff := Sub(&ctA, &ctB)

	// Result is small (42), so standard BSGS works too.
	table := NewDecryptionTable(10)
	dec, err := Decrypt(&diff, &sk, table)
	require.NoError(t, err)
	require.Equal(t, expected, dec)
}

// ---------------------------------------------------------------------------
// DLEQ proofs with large values
// ---------------------------------------------------------------------------

func TestDLEQ_LargeValues(t *testing.T) {
	sk, pk, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	values := []uint64{
		1 << 48,
		1 << 63,
		math.MaxUint64,
		math.MaxUint64 - 1,
		0xDEADBEEFCAFEBABE,
	}

	for _, amount := range values {
		ct, _, err := Encrypt(amount, &pk, rand.Reader)
		require.NoError(t, err)

		proof, err := ProveDLEQ(&sk, &pk, &ct, amount, nil)
		require.NoError(t, err, "prove should succeed for %d", amount)

		ok := VerifyDLEQ(&proof, &pk, &ct, amount, nil)
		require.True(t, ok, "verify should succeed for %d", amount)

		// Verify with wrong amount fails.
		ok = VerifyDLEQ(&proof, &pk, &ct, amount-1, nil)
		require.False(t, ok, "verify with wrong amount should fail for %d", amount)
	}
}

// ---------------------------------------------------------------------------
// Equality proofs with large values
// ---------------------------------------------------------------------------

func TestEquality_LargeValues(t *testing.T) {
	_, pk1, err := KeyGen(rand.Reader)
	require.NoError(t, err)
	_, pk2, err := KeyGen(rand.Reader)
	require.NoError(t, err)
	_, pk3, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	amount := uint64(math.MaxUint64)

	ct1, r1, err := Encrypt(amount, &pk1, rand.Reader)
	require.NoError(t, err)
	ct2, r2, err := Encrypt(amount, &pk2, rand.Reader)
	require.NoError(t, err)
	ct3, r3, err := Encrypt(amount, &pk3, rand.Reader)
	require.NoError(t, err)

	proof, err := ProveEquality(amount, &r1, &r2, &r3, &pk1, &pk2, &pk3, &ct1, &ct2, &ct3, nil)
	require.NoError(t, err)

	ok := VerifyEquality(&proof, &pk1, &pk2, &pk3, &ct1, &ct2, &ct3, nil)
	require.True(t, ok, "equality proof should verify for MaxUint64")
}

// ---------------------------------------------------------------------------
// Deterministic encryption with large values
// ---------------------------------------------------------------------------

func TestEncryptWithRandomness_LargeValues(t *testing.T) {
	_, pk, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	amount := uint64(math.MaxUint64)

	// Two encryptions with different randomness must produce different ciphertexts.
	ct1, _, err := Encrypt(amount, &pk, rand.Reader)
	require.NoError(t, err)
	ct2, _, err := Encrypt(amount, &pk, rand.Reader)
	require.NoError(t, err)

	require.False(t, ct1.C1.Equal(&ct2.C1), "different randomness should produce different C1")
	require.False(t, ct1.C2.Equal(&ct2.C2), "different randomness should produce different C2")
}

// ---------------------------------------------------------------------------
// Serialization round-trip for large-value ciphertexts
// ---------------------------------------------------------------------------

func TestCiphertextSerialize_LargeValues(t *testing.T) {
	_, pk, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	amounts := []uint64{math.MaxUint64, math.MaxUint64 - 1, 1 << 63}

	for _, amount := range amounts {
		ct, _, err := Encrypt(amount, &pk, rand.Reader)
		require.NoError(t, err)

		data, err := ct.Marshal()
		require.NoError(t, err)
		require.Len(t, data, CiphertextSize)

		var ct2 Ciphertext
		err = ct2.Unmarshal(data)
		require.NoError(t, err)

		require.True(t, ct.C1.Equal(&ct2.C1), "C1 round-trip failed for %d", amount)
		require.True(t, ct.C2.Equal(&ct2.C2), "C2 round-trip failed for %d", amount)
	}
}
