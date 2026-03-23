package elgamal

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/stretchr/testify/require"
)

func TestDecryptionTable_SmallValues(t *testing.T) {
	table := NewDecryptionTable(10)

	amounts := []uint64{0, 1, 100, 1000, 999999}
	for _, amount := range amounts {
		var mG bn254.G1Affine
		mG.ScalarMultiplication(&G, new(big.Int).SetUint64(amount))

		result, err := table.DiscreteLog(&mG)
		require.NoError(t, err, "failed for amount %d", amount)
		require.Equal(t, amount, result, "discrete log mismatch for amount %d", amount)
	}
}

func TestDecryptionTable_Identity(t *testing.T) {
	table := NewDecryptionTable(10)

	// 0*G is the identity (point at infinity).
	var identity bn254.G1Affine
	result, err := table.DiscreteLog(&identity)
	require.NoError(t, err)
	require.Equal(t, uint64(0), result, "discrete log of identity must be 0")
}

func TestDecryptionTable_NotFound(t *testing.T) {
	// halfBits=5 → max range = 2^10 = 1024.
	table := NewDecryptionTable(5)

	// amount=2000 is out of range.
	var mG bn254.G1Affine
	mG.ScalarMultiplication(&G, new(big.Int).SetUint64(2000))

	_, err := table.DiscreteLog(&mG)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not found")
}
