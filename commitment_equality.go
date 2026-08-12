package elgamal

import (
	"errors"
	"io"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// CommitmentEqualityProof proves that an ElGamal ciphertext and a Pedersen
// commitment hide the same value.
//
// # Why this exists
//
// An ElGamal ciphertext is ct = (C1 = r*G, C2 = v*G + r*pk). It is tempting to
// treat C2 as a Pedersen commitment to v with blinding base pk and run a range
// proof directly on it. That is unsound: pk = sk*G, and the account owner knows
// sk, so C2 = (v + r*sk)*G can be re-opened to *any* value v' by choosing
// r' = (v + r*sk - v')/sk. A range proof over C2 with Hbase = pk therefore
// constrains nothing for the one party who submits it.
//
// The fix is to run range proofs over a real Pedersen commitment
// P = v*G + s*H, where H is a nothing-up-my-sleeve generator whose discrete log
// with respect to G nobody knows, and to prove separately that P and ct hide
// the same v. This proof is that link.
//
// Statement: the prover knows (v, r, s) such that
//
//	C1 = r*G
//	C2 = v*G + r*pk
//	P  = v*G + s*H
//
// The same response Zv appears in the second and third verification equations,
// which is what forces the value in the ciphertext and the value in the
// commitment to be equal.
type CommitmentEqualityProof struct {
	Zv, Zr, Zs fr.Element     // responses for value, ciphertext randomness, commitment blinding
	A1         bn254.G1Affine // kr*G
	A2         bn254.G1Affine // kv*G + kr*pk
	A3         bn254.G1Affine // kv*G + ks*H
}

// appendCommitmentEqualityTranscript writes the shared prefix used by both the
// prover and the verifier. Keeping it in one place makes divergence impossible.
func appendCommitmentEqualityTranscript(
	t *Transcript,
	pk, H *bn254.G1Affine,
	ct *Ciphertext,
	commitment *bn254.G1Affine,
	a1, a2, a3 *bn254.G1Affine,
) {
	t.AppendBytes("proof_type", []byte("commitment-equality"))
	t.AppendPoint("pk", pk)
	t.AppendPoint("H", H)
	t.AppendPoint("C1", &ct.C1)
	t.AppendPoint("C2", &ct.C2)
	t.AppendPoint("P", commitment)
	t.AppendPoint("A1", a1)
	t.AppendPoint("A2", a2)
	t.AppendPoint("A3", a3)
}

// ProveCommitmentEquality proves that ct and commitment hide the same value.
//
// The caller supplies the witness: value v, the ciphertext randomness r such
// that ct = (r*G, v*G + r*pk), and the blinding s such that
// commitment = v*G + s*H.
//
// If transcript is nil a default transcript is created. If rng is nil,
// crypto/rand.Reader is used; pass a deterministic reader for KAT generation.
func ProveCommitmentEquality(
	value *fr.Element,
	r, s *fr.Element,
	pk, H *bn254.G1Affine,
	ct *Ciphertext,
	commitment *bn254.G1Affine,
	transcript *Transcript,
	rng io.Reader,
) (CommitmentEqualityProof, error) {
	if value == nil || r == nil || s == nil {
		return CommitmentEqualityProof{}, errors.New("commitment equality: nil witness component")
	}
	if ct == nil || commitment == nil {
		return CommitmentEqualityProof{}, errors.New("commitment equality: nil statement component")
	}
	if err := ValidatePublicKey(pk); err != nil {
		return CommitmentEqualityProof{}, err
	}
	if err := ValidatePublicKey(H); err != nil {
		return CommitmentEqualityProof{}, errors.New("commitment equality: invalid H base")
	}

	// 1. Nonces.
	kv, err := randomScalar(rng)
	if err != nil {
		return CommitmentEqualityProof{}, err
	}
	kr, err := randomScalar(rng)
	if err != nil {
		return CommitmentEqualityProof{}, err
	}
	ks, err := randomScalar(rng)
	if err != nil {
		return CommitmentEqualityProof{}, err
	}

	kvBig := kv.BigInt(new(big.Int))
	krBig := kr.BigInt(new(big.Int))
	ksBig := ks.BigInt(new(big.Int))

	// 2. A1 = kr*G
	var a1 bn254.G1Affine
	a1.ScalarMultiplication(&G, krBig)

	// 3. A2 = kv*G + kr*pk
	var kvG, krPk bn254.G1Affine
	kvG.ScalarMultiplication(&G, kvBig)
	krPk.ScalarMultiplication(pk, krBig)
	a2 := addAffine(&kvG, &krPk)

	// 4. A3 = kv*G + ks*H
	var ksH bn254.G1Affine
	ksH.ScalarMultiplication(H, ksBig)
	a3 := addAffine(&kvG, &ksH)

	// 5. Challenge.
	if transcript == nil {
		transcript = NewTranscript("x/confidential/v1")
	}
	appendCommitmentEqualityTranscript(transcript, pk, H, ct, commitment, &a1, &a2, &a3)
	e := transcript.ChallengeScalar("commitment_equality_challenge")

	// 6. Responses: z = k + e*witness.
	var zv, zr, zs, tmp fr.Element

	tmp.Mul(&e, value)
	zv.Add(&kv, &tmp)

	tmp.Mul(&e, r)
	zr.Add(&kr, &tmp)

	tmp.Mul(&e, s)
	zs.Add(&ks, &tmp)

	return CommitmentEqualityProof{Zv: zv, Zr: zr, Zs: zs, A1: a1, A2: a2, A3: a3}, nil
}

// VerifyCommitmentEquality verifies that ct and commitment hide the same value.
//
// H must be a generator whose discrete log with respect to G is unknown to the
// prover; passing a caller-controlled point here reintroduces exactly the
// unsoundness this proof exists to remove.
func VerifyCommitmentEquality(
	proof *CommitmentEqualityProof,
	pk, H *bn254.G1Affine,
	ct *Ciphertext,
	commitment *bn254.G1Affine,
	transcript *Transcript,
) bool {
	if proof == nil || commitment == nil {
		return false
	}
	// Reject degenerate inputs: an identity pk or H would collapse a
	// verification equation and make it trivially satisfiable.
	if err := ValidatePublicKey(pk); err != nil {
		return false
	}
	if err := ValidatePublicKey(H); err != nil {
		return false
	}
	if err := ct.Validate(); err != nil {
		return false
	}
	if !commitment.IsOnCurve() || commitment.IsInfinity() {
		return false
	}
	// Reject identity nonce commitments as well. Not known to be exploitable —
	// A_i = O just pins the corresponding nonce to 0, which is already within
	// the prover's freedom and does not let the ciphertext and the commitment
	// hide different values — but a degenerate proof element has no legitimate
	// use, and rejecting it keeps the accepted-input set as small as the
	// statement requires.
	for _, p := range []*bn254.G1Affine{&proof.A1, &proof.A2, &proof.A3} {
		if !p.IsOnCurve() || p.IsInfinity() {
			return false
		}
	}

	if transcript == nil {
		transcript = NewTranscript("x/confidential/v1")
	}
	appendCommitmentEqualityTranscript(transcript, pk, H, ct, commitment, &proof.A1, &proof.A2, &proof.A3)
	e := transcript.ChallengeScalar("commitment_equality_challenge")

	eBig := e.BigInt(new(big.Int))
	zvBig := proof.Zv.BigInt(new(big.Int))
	zrBig := proof.Zr.BigInt(new(big.Int))
	zsBig := proof.Zs.BigInt(new(big.Int))

	// Check 1: Zr*G == A1 + e*C1   (binds r to the ciphertext's C1)
	var lhs1 bn254.G1Affine
	lhs1.ScalarMultiplication(&G, zrBig)

	var eC1 bn254.G1Affine
	eC1.ScalarMultiplication(&ct.C1, eBig)
	rhs1 := addAffine(&proof.A1, &eC1)

	if !lhs1.Equal(&rhs1) {
		return false
	}

	// Check 2: Zv*G + Zr*pk == A2 + e*C2   (binds v to the ciphertext)
	var zvG, zrPk bn254.G1Affine
	zvG.ScalarMultiplication(&G, zvBig)
	zrPk.ScalarMultiplication(pk, zrBig)
	lhs2 := addAffine(&zvG, &zrPk)

	var eC2 bn254.G1Affine
	eC2.ScalarMultiplication(&ct.C2, eBig)
	rhs2 := addAffine(&proof.A2, &eC2)

	if !lhs2.Equal(&rhs2) {
		return false
	}

	// Check 3: Zv*G + Zs*H == A3 + e*P   (binds the same v to the commitment)
	var zsH bn254.G1Affine
	zsH.ScalarMultiplication(H, zsBig)
	lhs3 := addAffine(&zvG, &zsH)

	var eP bn254.G1Affine
	eP.ScalarMultiplication(commitment, eBig)
	rhs3 := addAffine(&proof.A3, &eP)

	return lhs3.Equal(&rhs3)
}

// addAffine returns a + b for two affine points.
func addAffine(a, b *bn254.G1Affine) bn254.G1Affine {
	var aJac, bJac bn254.G1Jac
	aJac.FromAffine(a)
	bJac.FromAffine(b)
	aJac.AddAssign(&bJac)

	var out bn254.G1Affine
	out.FromJacobian(&aJac)
	return out
}
