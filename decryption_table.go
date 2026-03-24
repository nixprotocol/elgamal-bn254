package elgamal

import (
	"errors"

	"github.com/consensys/gnark-crypto/ecc/bn254"
)

// Decryptor is the interface for discrete-log solvers used by Decrypt.
// Both DecryptionTable (standard BSGS) and SplitDecryptionTable (hi/lo
// decomposition for 64-bit amounts) implement this interface.
type Decryptor interface {
	DiscreteLog(mG *bn254.G1Affine) (uint64, error)
}

// DecryptionTable implements baby-step giant-step (BSGS) discrete log
// over the BN254 G1 group for values in [0, 2^(2*halfBits)).
type DecryptionTable struct {
	halfBits  uint
	base      bn254.G1Affine // generator used for this table (usually G)
	table     map[bn254.G1Affine]uint64
	giantStep bn254.G1Affine
}

// NewDecryptionTable builds a BSGS lookup table using the standard generator G.
// Baby steps: store i*G for i in [0, 2^halfBits).
// Giant step: -(2^halfBits)*G.
func NewDecryptionTable(halfBits uint) *DecryptionTable {
	return NewDecryptionTableWithBase(halfBits, &G)
}

// NewDecryptionTableWithBase builds a BSGS lookup table using a custom base point.
// Baby steps: store i*base for i in [0, 2^halfBits).
// Giant step: -(2^halfBits)*base.
// This is useful for SplitDecryptionTable where the hi table uses nG as its base.
func NewDecryptionTableWithBase(halfBits uint, base *bn254.G1Affine) *DecryptionTable {
	n := uint64(1) << halfBits // 2^halfBits

	dt := &DecryptionTable{
		halfBits: halfBits,
		base:     *base,
		table:    make(map[bn254.G1Affine]uint64, n),
	}

	// Baby steps: compute i*base for i in [0, n).
	var current bn254.G1Affine
	// Start with the identity (point at infinity) for i=0.
	current.X.SetZero()
	current.Y.SetZero()
	// Identity in affine is the zero value (IsInfinity() == true).

	// Store identity for i=0.
	dt.table[current] = 0

	// Accumulate by adding base each step.
	var currentJac bn254.G1Jac
	// currentJac starts as identity (zero value of G1Jac is identity).

	var baseJac bn254.G1Jac
	baseJac.FromAffine(base)

	for i := uint64(1); i < n; i++ {
		// currentJac += base
		currentJac.AddAssign(&baseJac)

		current.FromJacobian(&currentJac)
		dt.table[current] = i
	}

	// Giant step: -(2^halfBits)*base = -(n*base).
	// We already have (n-1)*base in currentJac, add one more base.
	currentJac.AddAssign(&baseJac)
	// currentJac is now n*base.

	var nBase bn254.G1Affine
	nBase.FromJacobian(&currentJac)
	nBase.Neg(&nBase)
	dt.giantStep = nBase

	return dt
}

// DiscreteLog finds m such that mG = *mG using BSGS.
// Returns an error if m is outside the table's range.
func (dt *DecryptionTable) DiscreteLog(mG *bn254.G1Affine) (uint64, error) {
	n := uint64(1) << dt.halfBits

	// gamma starts as mG, then we add giantStep each giant step.
	var gammaJac bn254.G1Jac
	gammaJac.FromAffine(mG)

	var giantJac bn254.G1Jac
	giantJac.FromAffine(&dt.giantStep)

	var gamma bn254.G1Affine

	for j := uint64(0); j < n; j++ {
		gamma.FromJacobian(&gammaJac)

		if i, ok := dt.table[gamma]; ok {
			return j*n + i, nil
		}

		// gamma += giantStep
		gammaJac.AddAssign(&giantJac)
	}

	return 0, errors.New("discrete log not found: value out of table range")
}
