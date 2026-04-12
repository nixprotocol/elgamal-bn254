package elgamal

import (
	"io"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// EqualityProof is a multi-relation Schnorr proof that 3 ciphertexts under
// 3 different public keys all encrypt the same amount m. Witness: (m, r1, r2, r3).
type EqualityProof struct {
	Sm, Sr1, Sr2, Sr3 fr.Element
	R11, R21          bn254.G1Affine // commitments for key 1
	R12, R22          bn254.G1Affine // commitments for key 2
	R13, R23          bn254.G1Affine // commitments for key 3
}

// ProveEquality generates a proof that ct1, ct2, ct3 all encrypt the same amount
// under pk1, pk2, pk3 respectively. The prover supplies the amount and the
// randomness r1, r2, r3 used to create each ciphertext.
// If transcript is nil, a default transcript is created.
// If rng is nil, crypto/rand.Reader is used; pass a deterministic reader
// for KAT / test-vector generation.
func ProveEquality(
	amount uint64,
	r1, r2, r3 *fr.Element,
	pk1, pk2, pk3 *bn254.G1Affine,
	ct1, ct2, ct3 *Ciphertext,
	transcript *Transcript,
	rng io.Reader,
) (EqualityProof, error) {
	// 1. Random nonces (from caller-supplied rng)
	km, err := randomScalar(rng)
	if err != nil {
		return EqualityProof{}, err
	}
	kr1, err := randomScalar(rng)
	if err != nil {
		return EqualityProof{}, err
	}
	kr2, err := randomScalar(rng)
	if err != nil {
		return EqualityProof{}, err
	}
	kr3, err := randomScalar(rng)
	if err != nil {
		return EqualityProof{}, err
	}

	kmBig := km.BigInt(new(big.Int))
	kr1Big := kr1.BigInt(new(big.Int))
	kr2Big := kr2.BigInt(new(big.Int))
	kr3Big := kr3.BigInt(new(big.Int))

	// 2. For each key i: R1_i = kr_i * G, R2_i = km*G + kr_i*pk_i
	pks := [3]*bn254.G1Affine{pk1, pk2, pk3}
	krBigs := [3]*big.Int{kr1Big, kr2Big, kr3Big}

	var r1s, r2s [3]bn254.G1Affine
	for i := 0; i < 3; i++ {
		// R1_i = kr_i * G
		r1s[i].ScalarMultiplication(&G, krBigs[i])

		// R2_i = km*G + kr_i*pk_i
		var kmG, krPk bn254.G1Affine
		kmG.ScalarMultiplication(&G, kmBig)
		krPk.ScalarMultiplication(pks[i], krBigs[i])

		var r2Jac, kmGJac, krPkJac bn254.G1Jac
		kmGJac.FromAffine(&kmG)
		krPkJac.FromAffine(&krPk)
		r2Jac.Set(&kmGJac)
		r2Jac.AddAssign(&krPkJac)
		r2s[i].FromJacobian(&r2Jac)
	}

	// 3. Build transcript and get challenge
	if transcript == nil {
		transcript = NewTranscript("x/confidential/v1")
	}
	transcript.AppendBytes("proof_type", []byte("equality"))

	transcript.AppendPoint("pk1", pk1)
	transcript.AppendPoint("pk2", pk2)
	transcript.AppendPoint("pk3", pk3)

	transcript.AppendPoint("ct1_C1", &ct1.C1)
	transcript.AppendPoint("ct1_C2", &ct1.C2)
	transcript.AppendPoint("ct2_C1", &ct2.C1)
	transcript.AppendPoint("ct2_C2", &ct2.C2)
	transcript.AppendPoint("ct3_C1", &ct3.C1)
	transcript.AppendPoint("ct3_C2", &ct3.C2)

	transcript.AppendPoint("R11", &r1s[0])
	transcript.AppendPoint("R21", &r2s[0])
	transcript.AppendPoint("R12", &r1s[1])
	transcript.AppendPoint("R22", &r2s[1])
	transcript.AppendPoint("R13", &r1s[2])
	transcript.AppendPoint("R23", &r2s[2])

	e := transcript.ChallengeScalar("equality_challenge")

	// 4. Responses: Sm = km + e*m, Sr_i = kr_i + e*r_i
	var mFr fr.Element
	mFr.SetUint64(amount)

	var sm fr.Element
	var eMul fr.Element
	eMul.Mul(&e, &mFr)
	sm.Add(&km, &eMul)

	rs := [3]*fr.Element{r1, r2, r3}
	krs := [3]*fr.Element{&kr1, &kr2, &kr3}
	var srs [3]fr.Element
	for i := 0; i < 3; i++ {
		var eR fr.Element
		eR.Mul(&e, rs[i])
		srs[i].Add(krs[i], &eR)
	}

	return EqualityProof{
		Sm:  sm,
		Sr1: srs[0], Sr2: srs[1], Sr3: srs[2],
		R11: r1s[0], R21: r2s[0],
		R12: r1s[1], R22: r2s[1],
		R13: r1s[2], R23: r2s[2],
	}, nil
}

// VerifyEquality verifies that the 3 ciphertexts under 3 public keys all
// encrypt the same amount.
// If transcript is nil, a default transcript is created.
//
// Note: this function does NOT require pk1, pk2, pk3 to be distinct. The
// proof is mathematically sound for any valid keys (including identical
// ones), since it simply proves that the plaintext committed in the three
// ciphertexts is the same. A protocol that relies on the keys representing
// distinct parties (e.g., sender / recipient / auditor) MUST enforce
// distinctness at its own layer — the library intentionally does not reject
// pk1==pk2 because legitimate uses exist (auditor == sender, self-transfers,
// etc.).
func VerifyEquality(
	proof *EqualityProof,
	pk1, pk2, pk3 *bn254.G1Affine,
	ct1, ct2, ct3 *Ciphertext,
	transcript *Transcript,
) bool {
	// 0. Validate all public keys and ciphertexts (reject identity / off-curve
	// as defense-in-depth against degenerate-input attacks).
	for _, pk := range []*bn254.G1Affine{pk1, pk2, pk3} {
		if err := ValidatePublicKey(pk); err != nil {
			return false
		}
	}
	for _, c := range []*Ciphertext{ct1, ct2, ct3} {
		if err := c.Validate(); err != nil {
			return false
		}
	}

	// 1. Reconstruct challenge
	if transcript == nil {
		transcript = NewTranscript("x/confidential/v1")
	}
	transcript.AppendBytes("proof_type", []byte("equality"))

	transcript.AppendPoint("pk1", pk1)
	transcript.AppendPoint("pk2", pk2)
	transcript.AppendPoint("pk3", pk3)

	transcript.AppendPoint("ct1_C1", &ct1.C1)
	transcript.AppendPoint("ct1_C2", &ct1.C2)
	transcript.AppendPoint("ct2_C1", &ct2.C1)
	transcript.AppendPoint("ct2_C2", &ct2.C2)
	transcript.AppendPoint("ct3_C1", &ct3.C1)
	transcript.AppendPoint("ct3_C2", &ct3.C2)

	transcript.AppendPoint("R11", &proof.R11)
	transcript.AppendPoint("R21", &proof.R21)
	transcript.AppendPoint("R12", &proof.R12)
	transcript.AppendPoint("R22", &proof.R22)
	transcript.AppendPoint("R13", &proof.R13)
	transcript.AppendPoint("R23", &proof.R23)

	e := transcript.ChallengeScalar("equality_challenge")
	eBig := e.BigInt(new(big.Int))

	smBig := proof.Sm.BigInt(new(big.Int))
	sr := [3]*big.Int{
		proof.Sr1.BigInt(new(big.Int)),
		proof.Sr2.BigInt(new(big.Int)),
		proof.Sr3.BigInt(new(big.Int)),
	}

	pks := [3]*bn254.G1Affine{pk1, pk2, pk3}
	cts := [3]*Ciphertext{ct1, ct2, ct3}
	r1s := [3]*bn254.G1Affine{&proof.R11, &proof.R12, &proof.R13}
	r2s := [3]*bn254.G1Affine{&proof.R21, &proof.R22, &proof.R23}

	for i := 0; i < 3; i++ {
		// Check 1: Sr_i * G == R1_i + e * C1_i
		var lhs1 bn254.G1Affine
		lhs1.ScalarMultiplication(&G, sr[i])

		var eC1 bn254.G1Affine
		eC1.ScalarMultiplication(&cts[i].C1, eBig)

		var rhs1 bn254.G1Affine
		var rhs1Jac, r1Jac, eC1Jac bn254.G1Jac
		r1Jac.FromAffine(r1s[i])
		eC1Jac.FromAffine(&eC1)
		rhs1Jac.Set(&r1Jac)
		rhs1Jac.AddAssign(&eC1Jac)
		rhs1.FromJacobian(&rhs1Jac)

		if !lhs1.Equal(&rhs1) {
			return false
		}

		// Check 2: Sm * G + Sr_i * pk_i == R2_i + e * C2_i
		var smG bn254.G1Affine
		smG.ScalarMultiplication(&G, smBig)

		var srPk bn254.G1Affine
		srPk.ScalarMultiplication(pks[i], sr[i])

		var lhs2 bn254.G1Affine
		var lhs2Jac, smGJac, srPkJac bn254.G1Jac
		smGJac.FromAffine(&smG)
		srPkJac.FromAffine(&srPk)
		lhs2Jac.Set(&smGJac)
		lhs2Jac.AddAssign(&srPkJac)
		lhs2.FromJacobian(&lhs2Jac)

		var eC2 bn254.G1Affine
		eC2.ScalarMultiplication(&cts[i].C2, eBig)

		var rhs2 bn254.G1Affine
		var rhs2Jac, r2Jac, eC2Jac bn254.G1Jac
		r2Jac.FromAffine(r2s[i])
		eC2Jac.FromAffine(&eC2)
		rhs2Jac.Set(&r2Jac)
		rhs2Jac.AddAssign(&eC2Jac)
		rhs2.FromJacobian(&rhs2Jac)

		if !lhs2.Equal(&rhs2) {
			return false
		}
	}

	return true
}

// ---------- 2-key equality proof ----------

// Equality2Proof proves two ciphertexts under two different keys encrypt the same amount.
// Used for MsgRotateKey (old key -> new key re-encryption).
type Equality2Proof struct {
	Sm, Sr1, Sr2 fr.Element     // response scalars (m, r1, r2)
	R11, R21     bn254.G1Affine // commitments for key 1
	R12, R22     bn254.G1Affine // commitments for key 2
}

// ProveEquality2 generates a proof that ct1 and ct2 encrypt the same amount
// under pk1 and pk2 respectively. The prover supplies the amount and the
// randomness r1, r2 used to create each ciphertext.
// If transcript is nil, a default transcript is created.
// If rng is nil, crypto/rand.Reader is used; pass a deterministic reader
// for KAT / test-vector generation.
func ProveEquality2(
	amount uint64,
	r1, r2 *fr.Element,
	pk1, pk2 *bn254.G1Affine,
	ct1, ct2 *Ciphertext,
	transcript *Transcript,
	rng io.Reader,
) (Equality2Proof, error) {
	// 1. Random nonces (from caller-supplied rng)
	km, err := randomScalar(rng)
	if err != nil {
		return Equality2Proof{}, err
	}
	kr1, err := randomScalar(rng)
	if err != nil {
		return Equality2Proof{}, err
	}
	kr2, err := randomScalar(rng)
	if err != nil {
		return Equality2Proof{}, err
	}

	kmBig := km.BigInt(new(big.Int))
	kr1Big := kr1.BigInt(new(big.Int))
	kr2Big := kr2.BigInt(new(big.Int))

	// 2. For each key i: R1_i = kr_i * G, R2_i = km*G + kr_i*pk_i
	pks := [2]*bn254.G1Affine{pk1, pk2}
	krBigs := [2]*big.Int{kr1Big, kr2Big}

	var r1s, r2s [2]bn254.G1Affine
	for i := 0; i < 2; i++ {
		// R1_i = kr_i * G
		r1s[i].ScalarMultiplication(&G, krBigs[i])

		// R2_i = km*G + kr_i*pk_i
		var kmG, krPk bn254.G1Affine
		kmG.ScalarMultiplication(&G, kmBig)
		krPk.ScalarMultiplication(pks[i], krBigs[i])

		var r2Jac, kmGJac, krPkJac bn254.G1Jac
		kmGJac.FromAffine(&kmG)
		krPkJac.FromAffine(&krPk)
		r2Jac.Set(&kmGJac)
		r2Jac.AddAssign(&krPkJac)
		r2s[i].FromJacobian(&r2Jac)
	}

	// 3. Build transcript and get challenge
	if transcript == nil {
		transcript = NewTranscript("x/confidential/v1")
	}
	transcript.AppendBytes("proof_type", []byte("equality2"))

	transcript.AppendPoint("pk1", pk1)
	transcript.AppendPoint("pk2", pk2)

	transcript.AppendPoint("ct1_C1", &ct1.C1)
	transcript.AppendPoint("ct1_C2", &ct1.C2)
	transcript.AppendPoint("ct2_C1", &ct2.C1)
	transcript.AppendPoint("ct2_C2", &ct2.C2)

	transcript.AppendPoint("R11", &r1s[0])
	transcript.AppendPoint("R21", &r2s[0])
	transcript.AppendPoint("R12", &r1s[1])
	transcript.AppendPoint("R22", &r2s[1])

	e := transcript.ChallengeScalar("equality2_challenge")

	// 4. Responses: Sm = km + e*m, Sr_i = kr_i + e*r_i
	var mFr fr.Element
	mFr.SetUint64(amount)

	var sm fr.Element
	var eMul fr.Element
	eMul.Mul(&e, &mFr)
	sm.Add(&km, &eMul)

	rs := [2]*fr.Element{r1, r2}
	krs := [2]*fr.Element{&kr1, &kr2}
	var srs [2]fr.Element
	for i := 0; i < 2; i++ {
		var eR fr.Element
		eR.Mul(&e, rs[i])
		srs[i].Add(krs[i], &eR)
	}

	return Equality2Proof{
		Sm:  sm,
		Sr1: srs[0], Sr2: srs[1],
		R11: r1s[0], R21: r2s[0],
		R12: r1s[1], R22: r2s[1],
	}, nil
}

// VerifyEquality2 verifies that 2 ciphertexts under 2 public keys encrypt the same amount.
// If transcript is nil, a default transcript is created.
//
// Note: this function does NOT require pk1 != pk2. For the key-rotation use
// case the caller presumably wants pk1 != pk2 (rotating to the same key is
// pointless), but that's a protocol-layer concern. The proof is sound
// regardless. See VerifyEquality for the full rationale.
func VerifyEquality2(
	proof *Equality2Proof,
	pk1, pk2 *bn254.G1Affine,
	ct1, ct2 *Ciphertext,
	transcript *Transcript,
) bool {
	// 0. Validate both public keys and ciphertexts. For the key-rotation use
	// case, rejecting pk2 = identity is critical (rotating to an identity key
	// would expose balances). Ciphertext validation blocks the C1 = identity
	// degenerate-input attack at the verifier entry point.
	for _, pk := range []*bn254.G1Affine{pk1, pk2} {
		if err := ValidatePublicKey(pk); err != nil {
			return false
		}
	}
	for _, c := range []*Ciphertext{ct1, ct2} {
		if err := c.Validate(); err != nil {
			return false
		}
	}

	// 1. Reconstruct challenge
	if transcript == nil {
		transcript = NewTranscript("x/confidential/v1")
	}
	transcript.AppendBytes("proof_type", []byte("equality2"))

	transcript.AppendPoint("pk1", pk1)
	transcript.AppendPoint("pk2", pk2)

	transcript.AppendPoint("ct1_C1", &ct1.C1)
	transcript.AppendPoint("ct1_C2", &ct1.C2)
	transcript.AppendPoint("ct2_C1", &ct2.C1)
	transcript.AppendPoint("ct2_C2", &ct2.C2)

	transcript.AppendPoint("R11", &proof.R11)
	transcript.AppendPoint("R21", &proof.R21)
	transcript.AppendPoint("R12", &proof.R12)
	transcript.AppendPoint("R22", &proof.R22)

	e := transcript.ChallengeScalar("equality2_challenge")
	eBig := e.BigInt(new(big.Int))

	smBig := proof.Sm.BigInt(new(big.Int))
	sr := [2]*big.Int{
		proof.Sr1.BigInt(new(big.Int)),
		proof.Sr2.BigInt(new(big.Int)),
	}

	pks := [2]*bn254.G1Affine{pk1, pk2}
	cts := [2]*Ciphertext{ct1, ct2}
	r1s := [2]*bn254.G1Affine{&proof.R11, &proof.R12}
	r2s := [2]*bn254.G1Affine{&proof.R21, &proof.R22}

	for i := 0; i < 2; i++ {
		// Check 1: Sr_i * G == R1_i + e * C1_i
		var lhs1 bn254.G1Affine
		lhs1.ScalarMultiplication(&G, sr[i])

		var eC1 bn254.G1Affine
		eC1.ScalarMultiplication(&cts[i].C1, eBig)

		var rhs1 bn254.G1Affine
		var rhs1Jac, r1Jac, eC1Jac bn254.G1Jac
		r1Jac.FromAffine(r1s[i])
		eC1Jac.FromAffine(&eC1)
		rhs1Jac.Set(&r1Jac)
		rhs1Jac.AddAssign(&eC1Jac)
		rhs1.FromJacobian(&rhs1Jac)

		if !lhs1.Equal(&rhs1) {
			return false
		}

		// Check 2: Sm * G + Sr_i * pk_i == R2_i + e * C2_i
		var smG bn254.G1Affine
		smG.ScalarMultiplication(&G, smBig)

		var srPk bn254.G1Affine
		srPk.ScalarMultiplication(pks[i], sr[i])

		var lhs2 bn254.G1Affine
		var lhs2Jac, smGJac, srPkJac bn254.G1Jac
		smGJac.FromAffine(&smG)
		srPkJac.FromAffine(&srPk)
		lhs2Jac.Set(&smGJac)
		lhs2Jac.AddAssign(&srPkJac)
		lhs2.FromJacobian(&lhs2Jac)

		var eC2 bn254.G1Affine
		eC2.ScalarMultiplication(&cts[i].C2, eBig)

		var rhs2 bn254.G1Affine
		var rhs2Jac, r2Jac, eC2Jac bn254.G1Jac
		r2Jac.FromAffine(r2s[i])
		eC2Jac.FromAffine(&eC2)
		rhs2Jac.Set(&r2Jac)
		rhs2Jac.AddAssign(&eC2Jac)
		rhs2.FromJacobian(&rhs2Jac)

		if !lhs2.Equal(&rhs2) {
			return false
		}
	}

	return true
}
