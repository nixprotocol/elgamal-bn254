package elgamal

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
)

// SplitDecryptionTable decomposes amounts as amount = hi * 2^splitBits + lo
// and recovers the discrete log in two steps:
//  1. Iterate over all possible lo values in [0, 2^splitBits)
//  2. For each lo, use a standard BSGS table (with base nG = 2^splitBits * G)
//     to find hi from the residual mG - lo*G = hi*nG
//
// Coverage: amounts up to 2^splitBits * 2^(2*hiHalfBits).
//
// Complexity: O(2^splitBits * 2^hiHalfBits) worst case. Choose parameters so that
// this product is tolerable:
//
//	splitBits=8,  hiHalfBits=16 → covers 2^40,  worst ~16M iters (~1-2s)
//	splitBits=8,  hiHalfBits=20 → covers 2^48,  worst ~256M iters (~25s)
//	splitBits=16, hiHalfBits=8  → covers 2^32,  worst ~16M iters (~1-2s)
//	splitBits=16, hiHalfBits=16 → covers 2^48,  worst ~4B iters (slow)
//
// Memory: dominated by the hi BSGS baby table (~2^hiHalfBits * 64 bytes).
type SplitDecryptionTable struct {
	splitBits uint             // number of bits in the low part
	hiTable   *DecryptionTable // BSGS table with base nG for hi values
	nG        bn254.G1Affine   // precomputed (2^splitBits) * G
}

// NewSplitDecryptionTable creates a split BSGS table for large-range decryption.
//
// Parameters:
//   - splitBits: bits in the low part (typically 8 or 16; must be <= 32)
//   - loHalfBits: kept for API compatibility (unused; lo is brute-forced)
//   - hiHalfBits: BSGS half-bits for the hi part
//
// Total range: 2^splitBits * 2^(2*hiHalfBits).
// Memory: ~2^hiHalfBits * 64 bytes for the hi baby table.
// Worst-case decryption: O(2^splitBits * 2^hiHalfBits) iterations.
func NewSplitDecryptionTable(splitBits, loHalfBits, hiHalfBits uint) *SplitDecryptionTable {
	if splitBits > 32 {
		panic("splitBits must be <= 32")
	}
	if 2*loHalfBits < splitBits {
		panic("loHalfBits too small: 2*loHalfBits must be >= splitBits")
	}

	// Precompute nG = (2^splitBits) * G
	var nG bn254.G1Affine
	n := new(big.Int).Lsh(big.NewInt(1), splitBits)
	nG.ScalarMultiplication(&G, n)

	hiTable := NewDecryptionTableWithBase(hiHalfBits, &nG)

	return &SplitDecryptionTable{
		splitBits: splitBits,
		hiTable:   hiTable,
		nG:        nG,
	}
}

// DiscreteLog recovers m from m*G by decomposing m = hi * 2^splitBits + lo.
//
// For each candidate lo in [0, 2^splitBits):
//
//	residual = mG - lo*G
//	hi, err = hiTable.DiscreteLog(residual)   // standard BSGS with base nG
//	if found: return hi * 2^splitBits + lo
//
// The correct lo produces a residual that is a valid multiple of nG, which the
// hi BSGS table will find. All other lo values produce residuals that are not
// multiples of nG, so the hi BSGS search fails (after exhausting all giant steps).
func (sdt *SplitDecryptionTable) DiscreteLog(mG *bn254.G1Affine) (uint64, error) {
	n := uint64(1) << sdt.splitBits

	// Precompute -G in Jacobian for efficient iterative subtraction.
	var negG bn254.G1Affine
	negG.Neg(&G)
	var negGJac bn254.G1Jac
	negGJac.FromAffine(&negG)

	// residualJac = mG - lo*G, starting with lo=0.
	var residualJac bn254.G1Jac
	residualJac.FromAffine(mG)

	var residual bn254.G1Affine

	for lo := uint64(0); lo < n; lo++ {
		residual.FromJacobian(&residualJac)

		hi, err := sdt.hiTable.DiscreteLog(&residual)
		if err == nil {
			return hi*n + lo, nil
		}

		// residual -= G (advance to next lo candidate)
		residualJac.AddAssign(&negGJac)
	}

	return 0, fmt.Errorf("split discrete log not found: value out of range")
}
