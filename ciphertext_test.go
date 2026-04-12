package elgamal

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/stretchr/testify/require"
)

// scalarMulG returns scalar * G where G is the BN254 G1 generator.
func scalarMulG(scalar *big.Int) bn254.G1Affine {
	var gen bn254.G1Affine
	// Get the generator for G1.
	_, _, g1, _ := bn254.Generators()
	gen.Set(&g1)

	var result bn254.G1Affine
	result.ScalarMultiplication(&gen, scalar)
	return result
}

func TestCiphertextMarshalRoundTrip(t *testing.T) {
	// Create two known points by multiplying the generator by known scalars.
	p1 := scalarMulG(big.NewInt(42))
	p2 := scalarMulG(big.NewInt(137))

	ct := &Ciphertext{C1: p1, C2: p2}

	data := ct.Marshal()
	require.Len(t, data, CiphertextSize)

	var ct2 Ciphertext
	err := ct2.Unmarshal(data)
	require.NoError(t, err)

	require.True(t, ct.C1.Equal(&ct2.C1), "C1 mismatch after round-trip")
	require.True(t, ct.C2.Equal(&ct2.C2), "C2 mismatch after round-trip")
}

func TestCiphertextSize(t *testing.T) {
	require.Equal(t, 128, CiphertextSize)
}

func TestCiphertextUnmarshalInvalid(t *testing.T) {
	var ct Ciphertext

	// Too short.
	err := ct.Unmarshal([]byte{0x01, 0x02, 0x03})
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid ciphertext length")

	// Too long.
	err = ct.Unmarshal(make([]byte, 256))
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid ciphertext length")
}

// TestCiphertextUnmarshalRejectsIdentityC1 asserts that a ciphertext whose C1
// component is the point at infinity is rejected. C1 = O degrades ElGamal
// decryption to C2 regardless of sk, making the "ciphertext" a public value
// and enabling protocol-level attacks on balance accounting.
func TestCiphertextUnmarshalRejectsIdentityC1(t *testing.T) {
	var validC2 bn254.G1Affine
	validC2.ScalarMultiplication(&G, big.NewInt(5))

	data := make([]byte, CiphertextSize)
	// First 64 bytes = C1 = all zeros (identity).
	copy(data[64:], validC2.Marshal())

	var ct Ciphertext
	err := ct.Unmarshal(data)
	require.Error(t, err, "ciphertext with C1 = identity must be rejected")
	require.Contains(t, err.Error(), "C1")
}

func TestValidatePublicKey(t *testing.T) {
	// Valid key: generator * 7.
	pk := scalarMulG(big.NewInt(7))
	err := ValidatePublicKey(&pk)
	require.NoError(t, err)

	// Identity point should fail.
	var identity bn254.G1Affine // zero value is the point at infinity
	err = ValidatePublicKey(&identity)
	require.Error(t, err)
	require.Contains(t, err.Error(), "identity point")
}

func TestValidatePublicKeyInvalidPoint(t *testing.T) {
	// Construct a point that is NOT on the curve by setting arbitrary coordinates.
	var bad bn254.G1Affine
	bad.X.SetInt64(1)
	bad.Y.SetInt64(1)

	err := ValidatePublicKey(&bad)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not on the curve")
}
