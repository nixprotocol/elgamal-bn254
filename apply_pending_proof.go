package elgamal

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// ApplyPendingProof is a 3-variable Schnorr proof that a new ciphertext and a
// pending ciphertext encrypt the same amount. Witness: (m, sk, r_new).
// The prover can decrypt pending (knows sk) and re-encrypt fresh (knows r_new).
//
// Relations proved:
//   - pending_C2 = m*G + sk*pending_C1  (correct decryption)
//   - pk = sk*G                          (key ownership)
//   - new_C1 = r_new*G                  (structure)
//   - new_C2 = m*G + r_new*pk           (structure)
type ApplyPendingProof struct {
	Sm, Ssk, Srn       fr.Element
	R1, R2, R3, R4 bn254.G1Affine
}

// ProveApplyPending generates a proof that the pending ciphertext and the new
// ciphertext encrypt the same amount. The prover knows sk (to decrypt pending)
// and rNew (the randomness for the new ciphertext).
// If transcript is nil, a default transcript is created.
func ProveApplyPending(
	sk *fr.Element,
	pk *bn254.G1Affine,
	pending, newCt *Ciphertext,
	amount uint64,
	rNew *fr.Element,
	transcript *Transcript,
) (ApplyPendingProof, error) {
	// 1. Random nonces km, ksk, krn
	var km, ksk, krn fr.Element
	for _, s := range []*fr.Element{&km, &ksk, &krn} {
		if _, err := s.SetRandom(); err != nil {
			return ApplyPendingProof{}, err
		}
	}

	kmBig := km.BigInt(new(big.Int))
	kskBig := ksk.BigInt(new(big.Int))
	krnBig := krn.BigInt(new(big.Int))

	// 2. R1 = km*G + ksk*pending_C1  (decryption commitment)
	//    Relation: pending_C2 = m*G + sk*pending_C1
	var kmG1, kskPC1 bn254.G1Affine
	kmG1.ScalarMultiplication(&G, kmBig)
	kskPC1.ScalarMultiplication(&pending.C1, kskBig)

	var r1 bn254.G1Affine
	var r1Jac, kmG1Jac, kskPC1Jac bn254.G1Jac
	kmG1Jac.FromAffine(&kmG1)
	kskPC1Jac.FromAffine(&kskPC1)
	r1Jac.Set(&kmG1Jac)
	r1Jac.AddAssign(&kskPC1Jac)
	r1.FromJacobian(&r1Jac)

	// 3. R2 = ksk*G  (key ownership commitment)
	var r2 bn254.G1Affine
	r2.ScalarMultiplication(&G, kskBig)

	// 4. R3 = krn*G  (new_C1 commitment)
	var r3 bn254.G1Affine
	r3.ScalarMultiplication(&G, krnBig)

	// 5. R4 = km*G + krn*pk  (new_C2 commitment)
	var kmG4, krnPk bn254.G1Affine
	kmG4.ScalarMultiplication(&G, kmBig)
	krnPk.ScalarMultiplication(pk, krnBig)

	var r4 bn254.G1Affine
	var r4Jac, kmG4Jac, krnPkJac bn254.G1Jac
	kmG4Jac.FromAffine(&kmG4)
	krnPkJac.FromAffine(&krnPk)
	r4Jac.Set(&kmG4Jac)
	r4Jac.AddAssign(&krnPkJac)
	r4.FromJacobian(&r4Jac)

	// 6. Transcript -> challenge e
	if transcript == nil {
		transcript = NewTranscript("x/confidential/v1")
	}
	transcript.AppendBytes("proof_type", []byte("apply_pending"))

	transcript.AppendPoint("pk", pk)
	transcript.AppendPoint("pending_C1", &pending.C1)
	transcript.AppendPoint("pending_C2", &pending.C2)
	transcript.AppendPoint("new_C1", &newCt.C1)
	transcript.AppendPoint("new_C2", &newCt.C2)

	transcript.AppendPoint("R1", &r1)
	transcript.AppendPoint("R2", &r2)
	transcript.AppendPoint("R3", &r3)
	transcript.AppendPoint("R4", &r4)

	e := transcript.ChallengeScalar("apply_pending_challenge")

	// 7. Responses: Sm = km + e*m, Ssk = ksk + e*sk, Srn = krn + e*rNew
	var mFr fr.Element
	mFr.SetUint64(amount)

	var sm, ssk, srn fr.Element

	var tmp fr.Element
	tmp.Mul(&e, &mFr)
	sm.Add(&km, &tmp)

	tmp.Mul(&e, sk)
	ssk.Add(&ksk, &tmp)

	tmp.Mul(&e, rNew)
	srn.Add(&krn, &tmp)

	return ApplyPendingProof{
		Sm: sm, Ssk: ssk, Srn: srn,
		R1: r1, R2: r2, R3: r3, R4: r4,
	}, nil
}

// VerifyApplyPending verifies that the pending and new ciphertexts encrypt the
// same amount under the given public key.
// If transcript is nil, a default transcript is created.
func VerifyApplyPending(
	proof *ApplyPendingProof,
	pk *bn254.G1Affine,
	pending, newCt *Ciphertext,
	transcript *Transcript,
) bool {
	// 1. Reconstruct challenge
	if transcript == nil {
		transcript = NewTranscript("x/confidential/v1")
	}
	transcript.AppendBytes("proof_type", []byte("apply_pending"))

	transcript.AppendPoint("pk", pk)
	transcript.AppendPoint("pending_C1", &pending.C1)
	transcript.AppendPoint("pending_C2", &pending.C2)
	transcript.AppendPoint("new_C1", &newCt.C1)
	transcript.AppendPoint("new_C2", &newCt.C2)

	transcript.AppendPoint("R1", &proof.R1)
	transcript.AppendPoint("R2", &proof.R2)
	transcript.AppendPoint("R3", &proof.R3)
	transcript.AppendPoint("R4", &proof.R4)

	e := transcript.ChallengeScalar("apply_pending_challenge")
	eBig := e.BigInt(new(big.Int))

	smBig := proof.Sm.BigInt(new(big.Int))
	sskBig := proof.Ssk.BigInt(new(big.Int))
	srnBig := proof.Srn.BigInt(new(big.Int))

	// Check 1: Sm*G + Ssk*pending_C1 == R1 + e*pending_C2
	{
		var smG, sskPC1 bn254.G1Affine
		smG.ScalarMultiplication(&G, smBig)
		sskPC1.ScalarMultiplication(&pending.C1, sskBig)

		var lhs bn254.G1Affine
		var lhsJac, smGJac, sskPC1Jac bn254.G1Jac
		smGJac.FromAffine(&smG)
		sskPC1Jac.FromAffine(&sskPC1)
		lhsJac.Set(&smGJac)
		lhsJac.AddAssign(&sskPC1Jac)
		lhs.FromJacobian(&lhsJac)

		var ePC2 bn254.G1Affine
		ePC2.ScalarMultiplication(&pending.C2, eBig)

		var rhs bn254.G1Affine
		var rhsJac, r1Jac, ePC2Jac bn254.G1Jac
		r1Jac.FromAffine(&proof.R1)
		ePC2Jac.FromAffine(&ePC2)
		rhsJac.Set(&r1Jac)
		rhsJac.AddAssign(&ePC2Jac)
		rhs.FromJacobian(&rhsJac)

		if !lhs.Equal(&rhs) {
			return false
		}
	}

	// Check 2: Ssk*G == R2 + e*pk
	{
		var lhs bn254.G1Affine
		lhs.ScalarMultiplication(&G, sskBig)

		var ePk bn254.G1Affine
		ePk.ScalarMultiplication(pk, eBig)

		var rhs bn254.G1Affine
		var rhsJac, r2Jac, ePkJac bn254.G1Jac
		r2Jac.FromAffine(&proof.R2)
		ePkJac.FromAffine(&ePk)
		rhsJac.Set(&r2Jac)
		rhsJac.AddAssign(&ePkJac)
		rhs.FromJacobian(&rhsJac)

		if !lhs.Equal(&rhs) {
			return false
		}
	}

	// Check 3: Srn*G == R3 + e*new_C1
	{
		var lhs bn254.G1Affine
		lhs.ScalarMultiplication(&G, srnBig)

		var eNC1 bn254.G1Affine
		eNC1.ScalarMultiplication(&newCt.C1, eBig)

		var rhs bn254.G1Affine
		var rhsJac, r3Jac, eNC1Jac bn254.G1Jac
		r3Jac.FromAffine(&proof.R3)
		eNC1Jac.FromAffine(&eNC1)
		rhsJac.Set(&r3Jac)
		rhsJac.AddAssign(&eNC1Jac)
		rhs.FromJacobian(&rhsJac)

		if !lhs.Equal(&rhs) {
			return false
		}
	}

	// Check 4: Sm*G + Srn*pk == R4 + e*new_C2
	{
		var smG, srnPk bn254.G1Affine
		smG.ScalarMultiplication(&G, smBig)
		srnPk.ScalarMultiplication(pk, srnBig)

		var lhs bn254.G1Affine
		var lhsJac, smGJac, srnPkJac bn254.G1Jac
		smGJac.FromAffine(&smG)
		srnPkJac.FromAffine(&srnPk)
		lhsJac.Set(&smGJac)
		lhsJac.AddAssign(&srnPkJac)
		lhs.FromJacobian(&lhsJac)

		var eNC2 bn254.G1Affine
		eNC2.ScalarMultiplication(&newCt.C2, eBig)

		var rhs bn254.G1Affine
		var rhsJac, r4Jac, eNC2Jac bn254.G1Jac
		r4Jac.FromAffine(&proof.R4)
		eNC2Jac.FromAffine(&eNC2)
		rhsJac.Set(&r4Jac)
		rhsJac.AddAssign(&eNC2Jac)
		rhs.FromJacobian(&rhsJac)

		if !lhs.Equal(&rhs) {
			return false
		}
	}

	return true
}
