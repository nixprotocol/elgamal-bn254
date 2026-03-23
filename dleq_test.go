package elgamal

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDLEQProof_Valid(t *testing.T) {
	sk, pk, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	amount := uint64(42000)
	ct, _, err := Encrypt(amount, &pk, rand.Reader)
	require.NoError(t, err)

	proof, err := ProveDLEQ(&sk, &pk, &ct, amount, nil)
	require.NoError(t, err)

	ok := VerifyDLEQ(&proof, &pk, &ct, amount, nil)
	require.True(t, ok, "valid DLEQ proof must verify")
}

func TestDLEQProof_WrongAmount(t *testing.T) {
	sk, pk, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	amount := uint64(42000)
	ct, _, err := Encrypt(amount, &pk, rand.Reader)
	require.NoError(t, err)

	proof, err := ProveDLEQ(&sk, &pk, &ct, amount, nil)
	require.NoError(t, err)

	ok := VerifyDLEQ(&proof, &pk, &ct, 99999, nil)
	require.False(t, ok, "DLEQ proof with wrong amount must not verify")
}

func TestDLEQProof_WrongKey(t *testing.T) {
	sk1, pk1, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	_, pk2, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	amount := uint64(42000)
	ct, _, err := Encrypt(amount, &pk1, rand.Reader)
	require.NoError(t, err)

	proof, err := ProveDLEQ(&sk1, &pk1, &ct, amount, nil)
	require.NoError(t, err)

	ok := VerifyDLEQ(&proof, &pk2, &ct, amount, nil)
	require.False(t, ok, "DLEQ proof with wrong public key must not verify")
}

func TestDLEQProof_WithTranscript(t *testing.T) {
	sk, pk, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	ct, _, err := Encrypt(42000, &pk, rand.Reader)
	require.NoError(t, err)

	// Create transcript with context (simulating Cosmos module)
	proverT := NewTranscript("x/confidential/v1")
	proverT.AppendBytes("chain_id", []byte("nix-1"))
	proverT.AppendBytes("sender", []byte("cosmos1abc"))

	proof, err := ProveDLEQ(&sk, &pk, &ct, 42000, proverT)
	require.NoError(t, err)

	// Verifier must use identical transcript context
	verifierT := NewTranscript("x/confidential/v1")
	verifierT.AppendBytes("chain_id", []byte("nix-1"))
	verifierT.AppendBytes("sender", []byte("cosmos1abc"))

	require.True(t, VerifyDLEQ(&proof, &pk, &ct, 42000, verifierT))

	// Different context should fail
	wrongT := NewTranscript("x/confidential/v1")
	wrongT.AppendBytes("chain_id", []byte("other-chain"))
	wrongT.AppendBytes("sender", []byte("cosmos1abc"))

	require.False(t, VerifyDLEQ(&proof, &pk, &ct, 42000, wrongT))
}
