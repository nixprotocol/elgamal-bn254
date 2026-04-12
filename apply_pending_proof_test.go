package elgamal

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
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
	proof, err := ProveApplyPending(&sk, &pk, &pending, &newCt, amount, &rNew, nil, nil)
	require.NoError(t, err)

	ok := VerifyApplyPending(&proof, &pk, &pending, &newCt, nil)
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
	proof, err := ProveApplyPending(&sk, &pk, &pending, &newCt, amount, &rNew, nil, nil)
	require.NoError(t, err)

	ok := VerifyApplyPending(&proof, &pk, &pending, &newCt, nil)
	require.False(t, ok, "ApplyPending proof with wrong amount must not verify")
}

func TestApplyPendingProof_IdentityKeyRejected(t *testing.T) {
	sk, pk, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	amount := uint64(500)
	pending, _, err := Encrypt(amount, &pk, rand.Reader)
	require.NoError(t, err)
	newCt, rNew, err := Encrypt(amount, &pk, rand.Reader)
	require.NoError(t, err)

	proof, err := ProveApplyPending(&sk, &pk, &pending, &newCt, amount, &rNew, nil, nil)
	require.NoError(t, err)

	var identity bn254.G1Affine
	ok := VerifyApplyPending(&proof, &identity, &pending, &newCt, nil)
	require.False(t, ok, "VerifyApplyPending must reject identity public key")
}

// TestApplyPendingProof_DegeneratePendingRejected pins defense-in-depth
// against the C1=identity attack applied to the pending ciphertext.
func TestApplyPendingProof_DegeneratePendingRejected(t *testing.T) {
	sk, pk, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	amount := uint64(500)
	// Degenerate pending ciphertext: C1 = O, C2 = amount*G. Any sk "decrypts"
	// it to amount (sk*O = O → C2 - O = amount*G → m = amount).
	var pendingDegen Ciphertext
	var amountBig big.Int
	amountBig.SetUint64(amount)
	pendingDegen.C2.ScalarMultiplication(&G, &amountBig)

	newCt, rNew, err := Encrypt(amount, &pk, rand.Reader)
	require.NoError(t, err)

	proof, err := ProveApplyPending(&sk, &pk, &pendingDegen, &newCt, amount, &rNew, nil, nil)
	require.NoError(t, err)

	ok := VerifyApplyPending(&proof, &pk, &pendingDegen, &newCt, nil)
	require.False(t, ok, "VerifyApplyPending must reject pending with C1 = identity")
}

func TestApplyPendingProof_DegenerateNewCtRejected(t *testing.T) {
	sk, pk, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	amount := uint64(500)
	pending, _, err := Encrypt(amount, &pk, rand.Reader)
	require.NoError(t, err)

	// Degenerate newCt: C1 = O, C2 = amount*G, rNew = 0.
	var newCtDegen Ciphertext
	var amountBig big.Int
	amountBig.SetUint64(amount)
	newCtDegen.C2.ScalarMultiplication(&G, &amountBig)
	var rZero fr.Element

	proof, err := ProveApplyPending(&sk, &pk, &pending, &newCtDegen, amount, &rZero, nil, nil)
	require.NoError(t, err)

	ok := VerifyApplyPending(&proof, &pk, &pending, &newCtDegen, nil)
	require.False(t, ok, "VerifyApplyPending must reject newCt with C1 = identity")
}

func TestApplyPendingProof_WrongKey(t *testing.T) {
	sk, pk, err := KeyGen(rand.Reader)
	require.NoError(t, err)
	_, pkWrong, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	amount := uint64(500)
	pending, _, err := Encrypt(amount, &pk, rand.Reader)
	require.NoError(t, err)
	newCt, rNew, err := Encrypt(amount, &pk, rand.Reader)
	require.NoError(t, err)

	proof, err := ProveApplyPending(&sk, &pk, &pending, &newCt, amount, &rNew, nil, nil)
	require.NoError(t, err)

	ok := VerifyApplyPending(&proof, &pkWrong, &pending, &newCt, nil)
	require.False(t, ok, "ApplyPending proof with wrong public key must not verify")
}

func TestApplyPendingProof_WithTranscript(t *testing.T) {
	sk, pk, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	amount := uint64(500)
	pending, _, err := Encrypt(amount, &pk, rand.Reader)
	require.NoError(t, err)

	newCt, rNew, err := Encrypt(amount, &pk, rand.Reader)
	require.NoError(t, err)

	// Create transcript with context (simulating Cosmos module)
	proverT := NewTranscript("x/confidential/v1")
	proverT.AppendBytes("chain_id", []byte("nix-1"))
	proverT.AppendBytes("sender", []byte("cosmos1abc"))

	proof, err := ProveApplyPending(&sk, &pk, &pending, &newCt, amount, &rNew, proverT, nil)
	require.NoError(t, err)

	// Verifier must use identical transcript context
	verifierT := NewTranscript("x/confidential/v1")
	verifierT.AppendBytes("chain_id", []byte("nix-1"))
	verifierT.AppendBytes("sender", []byte("cosmos1abc"))

	require.True(t, VerifyApplyPending(&proof, &pk, &pending, &newCt, verifierT))

	// Different context should fail
	wrongT := NewTranscript("x/confidential/v1")
	wrongT.AppendBytes("chain_id", []byte("other-chain"))
	wrongT.AppendBytes("sender", []byte("cosmos1abc"))

	require.False(t, VerifyApplyPending(&proof, &pk, &pending, &newCt, wrongT))
}
