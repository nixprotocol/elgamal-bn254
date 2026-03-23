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

	proof, err := ProveDLEQ(&sk, &pk, &ct, amount)
	require.NoError(t, err)

	ok := VerifyDLEQ(&proof, &pk, &ct, amount)
	require.True(t, ok, "valid DLEQ proof must verify")
}

func TestDLEQProof_WrongAmount(t *testing.T) {
	sk, pk, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	amount := uint64(42000)
	ct, _, err := Encrypt(amount, &pk, rand.Reader)
	require.NoError(t, err)

	proof, err := ProveDLEQ(&sk, &pk, &ct, amount)
	require.NoError(t, err)

	ok := VerifyDLEQ(&proof, &pk, &ct, 99999)
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

	proof, err := ProveDLEQ(&sk1, &pk1, &ct, amount)
	require.NoError(t, err)

	ok := VerifyDLEQ(&proof, &pk2, &ct, amount)
	require.False(t, ok, "DLEQ proof with wrong public key must not verify")
}
