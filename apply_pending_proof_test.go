package elgamal

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestApplyPendingProof_Valid(t *testing.T) {
	sk, pk, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	// Simulate a pending ciphertext (someone encrypted 500 to our key)
	amount := uint64(500)
	pending, _, err := Encrypt(amount, &pk, rand.Reader)
	require.NoError(t, err)

	// Decrypt to verify (using BSGS)
	table := NewDecryptionTable(16)
	decrypted, err := Decrypt(&pending, &sk, table)
	require.NoError(t, err)
	require.Equal(t, amount, decrypted)

	// Re-encrypt with fresh randomness under the same key
	newCt, rNew, err := Encrypt(amount, &pk, rand.Reader)
	require.NoError(t, err)

	// Prove that pending and newCt encrypt the same amount
	proof, err := ProveApplyPending(&sk, &pk, &pending, &newCt, amount, &rNew)
	require.NoError(t, err)

	ok := VerifyApplyPending(&proof, &pk, &pending, &newCt)
	require.True(t, ok, "valid ApplyPending proof must verify")
}

func TestApplyPendingProof_WrongAmount(t *testing.T) {
	sk, pk, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	// Pending encrypts 500
	amount := uint64(500)
	pending, _, err := Encrypt(amount, &pk, rand.Reader)
	require.NoError(t, err)

	// Re-encrypt with a DIFFERENT amount (999)
	wrongAmount := uint64(999)
	newCt, rNew, err := Encrypt(wrongAmount, &pk, rand.Reader)
	require.NoError(t, err)

	// Prover dishonestly claims amount=500 but newCt encrypts 999.
	// The proof should fail because the relations are inconsistent.
	proof, err := ProveApplyPending(&sk, &pk, &pending, &newCt, amount, &rNew)
	require.NoError(t, err)

	ok := VerifyApplyPending(&proof, &pk, &pending, &newCt)
	require.False(t, ok, "ApplyPending proof with wrong amount must not verify")
}
