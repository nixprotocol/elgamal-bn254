package elgamal

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEqualityProof_Valid(t *testing.T) {
	_, pk1, err := KeyGen(rand.Reader)
	require.NoError(t, err)
	_, pk2, err := KeyGen(rand.Reader)
	require.NoError(t, err)
	_, pk3, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	amount := uint64(12345)

	ct1, r1, err := Encrypt(amount, &pk1, rand.Reader)
	require.NoError(t, err)
	ct2, r2, err := Encrypt(amount, &pk2, rand.Reader)
	require.NoError(t, err)
	ct3, r3, err := Encrypt(amount, &pk3, rand.Reader)
	require.NoError(t, err)

	proof, err := ProveEquality(amount, &r1, &r2, &r3, &pk1, &pk2, &pk3, &ct1, &ct2, &ct3)
	require.NoError(t, err)

	ok := VerifyEquality(&proof, &pk1, &pk2, &pk3, &ct1, &ct2, &ct3)
	require.True(t, ok, "valid equality proof must verify")
}

func TestEqualityProof_DifferentAmounts(t *testing.T) {
	_, pk1, err := KeyGen(rand.Reader)
	require.NoError(t, err)
	_, pk2, err := KeyGen(rand.Reader)
	require.NoError(t, err)
	_, pk3, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	amount1 := uint64(12345)
	amount2 := uint64(99999) // different

	ct1, r1, err := Encrypt(amount1, &pk1, rand.Reader)
	require.NoError(t, err)
	ct2, r2, err := Encrypt(amount2, &pk2, rand.Reader) // wrong amount
	require.NoError(t, err)
	ct3, r3, err := Encrypt(amount1, &pk3, rand.Reader)
	require.NoError(t, err)

	// Prover tries to prove equality with amount1, but ct2 encrypts amount2.
	proof, err := ProveEquality(amount1, &r1, &r2, &r3, &pk1, &pk2, &pk3, &ct1, &ct2, &ct3)
	require.NoError(t, err)

	ok := VerifyEquality(&proof, &pk1, &pk2, &pk3, &ct1, &ct2, &ct3)
	require.False(t, ok, "equality proof with different amounts must not verify")
}

func TestEqualityProof_WrongKey(t *testing.T) {
	_, pk1, err := KeyGen(rand.Reader)
	require.NoError(t, err)
	_, pk2, err := KeyGen(rand.Reader)
	require.NoError(t, err)
	_, pk3, err := KeyGen(rand.Reader)
	require.NoError(t, err)
	_, pk3Wrong, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	amount := uint64(12345)

	ct1, r1, err := Encrypt(amount, &pk1, rand.Reader)
	require.NoError(t, err)
	ct2, r2, err := Encrypt(amount, &pk2, rand.Reader)
	require.NoError(t, err)
	ct3, r3, err := Encrypt(amount, &pk3, rand.Reader)
	require.NoError(t, err)

	proof, err := ProveEquality(amount, &r1, &r2, &r3, &pk1, &pk2, &pk3, &ct1, &ct2, &ct3)
	require.NoError(t, err)

	// Verify with wrong pk3
	ok := VerifyEquality(&proof, &pk1, &pk2, &pk3Wrong, &ct1, &ct2, &ct3)
	require.False(t, ok, "equality proof with wrong public key must not verify")
}
