package elgamal

import (
	"encoding/binary"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// DLEQProof is a discrete-log equality proof showing that the prover knows
// sk such that pk = sk*G AND (C2 - m*G) = sk*C1. This proves correct
// decryption of a ciphertext.
type DLEQProof struct {
	S  fr.Element     // response scalar
	R1 bn254.G1Affine // k*G
	R2 bn254.G1Affine // k*C1
}

// ProveDLEQ generates a DLEQ proof that the ciphertext ct decrypts to amount
// under the secret key sk (with corresponding public key pk).
// If transcript is nil, a default transcript is created.
func ProveDLEQ(sk *fr.Element, pk *bn254.G1Affine, ct *Ciphertext, amount uint64, transcript *Transcript) (DLEQProof, error) {
	// 1. Random nonce k
	var k fr.Element
	if _, err := k.SetRandom(); err != nil {
		return DLEQProof{}, err
	}
	kBig := k.BigInt(new(big.Int))

	// 2. R1 = k*G
	var r1 bn254.G1Affine
	r1.ScalarMultiplication(&G, kBig)

	// 3. R2 = k*C1
	var r2 bn254.G1Affine
	r2.ScalarMultiplication(&ct.C1, kBig)

	// 4. Build transcript and get challenge
	if transcript == nil {
		transcript = NewTranscript("x/confidential/v1")
	}
	transcript.AppendBytes("proof_type", []byte("dleq"))
	transcript.AppendPoint("pk", pk)
	transcript.AppendPoint("C1", &ct.C1)
	transcript.AppendPoint("C2", &ct.C2)

	var amountBuf [8]byte
	binary.LittleEndian.PutUint64(amountBuf[:], amount)
	transcript.AppendBytes("amount", amountBuf[:])

	transcript.AppendPoint("R1", &r1)
	transcript.AppendPoint("R2", &r2)

	e := transcript.ChallengeScalar("dleq_challenge")

	// 5. S = k + e*sk
	var eSk fr.Element
	eSk.Mul(&e, sk)
	var s fr.Element
	s.Add(&k, &eSk)

	return DLEQProof{S: s, R1: r1, R2: r2}, nil
}

// VerifyDLEQ verifies a DLEQ proof that ct decrypts to amount under public key pk.
// If transcript is nil, a default transcript is created.
func VerifyDLEQ(proof *DLEQProof, pk *bn254.G1Affine, ct *Ciphertext, amount uint64, transcript *Transcript) bool {
	// 1. Reconstruct challenge
	if transcript == nil {
		transcript = NewTranscript("x/confidential/v1")
	}
	transcript.AppendBytes("proof_type", []byte("dleq"))
	transcript.AppendPoint("pk", pk)
	transcript.AppendPoint("C1", &ct.C1)
	transcript.AppendPoint("C2", &ct.C2)

	var amountBuf [8]byte
	binary.LittleEndian.PutUint64(amountBuf[:], amount)
	transcript.AppendBytes("amount", amountBuf[:])

	transcript.AppendPoint("R1", &proof.R1)
	transcript.AppendPoint("R2", &proof.R2)

	e := transcript.ChallengeScalar("dleq_challenge")
	eBig := e.BigInt(new(big.Int))
	sBig := proof.S.BigInt(new(big.Int))

	// 2. Check: S*G == R1 + e*pk
	var lhs1 bn254.G1Affine
	lhs1.ScalarMultiplication(&G, sBig)

	var ePk bn254.G1Affine
	ePk.ScalarMultiplication(pk, eBig)

	var rhs1 bn254.G1Affine
	var rhs1Jac, r1Jac, ePkJac bn254.G1Jac
	r1Jac.FromAffine(&proof.R1)
	ePkJac.FromAffine(&ePk)
	rhs1Jac.Set(&r1Jac)
	rhs1Jac.AddAssign(&ePkJac)
	rhs1.FromJacobian(&rhs1Jac)

	if !lhs1.Equal(&rhs1) {
		return false
	}

	// 3. Check: S*C1 == R2 + e*(C2 - amount*G)
	var lhs2 bn254.G1Affine
	lhs2.ScalarMultiplication(&ct.C1, sBig)

	// C2 - amount*G
	var amountG bn254.G1Affine
	amountG.ScalarMultiplication(&G, new(big.Int).SetUint64(amount))
	var negAmountG bn254.G1Affine
	negAmountG.Neg(&amountG)

	var diff bn254.G1Affine
	var diffJac, c2Jac, negAmountGJac bn254.G1Jac
	c2Jac.FromAffine(&ct.C2)
	negAmountGJac.FromAffine(&negAmountG)
	diffJac.Set(&c2Jac)
	diffJac.AddAssign(&negAmountGJac)
	diff.FromJacobian(&diffJac)

	// e*(C2 - amount*G)
	var eDiff bn254.G1Affine
	eDiff.ScalarMultiplication(&diff, eBig)

	var rhs2 bn254.G1Affine
	var rhs2Jac, r2Jac, eDiffJac bn254.G1Jac
	r2Jac.FromAffine(&proof.R2)
	eDiffJac.FromAffine(&eDiff)
	rhs2Jac.Set(&r2Jac)
	rhs2Jac.AddAssign(&eDiffJac)
	rhs2.FromJacobian(&rhs2Jac)

	return lhs2.Equal(&rhs2)
}
