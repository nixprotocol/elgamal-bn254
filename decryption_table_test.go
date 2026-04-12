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

// TestNewDecryptionTable_PanicOnExcessiveHalfBits pins bounds checking:
// halfBits >= 64 silently overflows `1 << halfBits` to 0 and builds an
// almost-empty table that then fails every DiscreteLog call. Values in
// [32, 64) don't overflow but attempt to allocate a multi-GB map (OOM).
// Both must be rejected at construction time with a clear panic.
func TestNewDecryptionTable_PanicOnExcessiveHalfBits(t *testing.T) {
	require.Panics(t, func() { NewDecryptionTable(64) }, "halfBits=64 must panic (overflow)")
	require.Panics(t, func() { NewDecryptionTable(65) }, "halfBits=65 must panic (overflow)")
	require.Panics(t, func() { NewDecryptionTable(40) }, "halfBits=40 must panic (OOM risk)")
}

func TestNewDecryptionTableWithBase_PanicOnExcessiveHalfBits(t *testing.T) {
	require.Panics(t, func() { NewDecryptionTableWithBase(64, &G) })
}
