package elgamal

import (
	"fmt"
	"io"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// PopProofSize is the byte size of a serialized PopProof:
// 1 scalar (32 bytes) + 1 G1 point (64 bytes) = 96 bytes.
const PopProofSize = 32 + 64

// PopProof is a Schnorr proof of knowledge of the secret key behind a public
// key — a proof of possession.
//
// Registering a public key nobody can prove ownership of lets an account bind
// itself to a key it does not control (for instance by copying another
// account's key), which permanently strands anything sent to it. Requiring a
// proof of possession at registration removes that class of mistake and the
// key-substitution confusion that comes with it.
//
// The transcript should bind the registering identity so a proof of possession
// observed on-chain cannot be replayed by a different account.
type PopProof struct {
	Z fr.Element     // response: k + e*sk
	A bn254.G1Affine // commitment: k*G
}

func appendPopTranscript(t *Transcript, pk, a *bn254.G1Affine) {
	t.AppendBytes("proof_type", []byte("pop"))
	t.AppendPoint("pk", pk)
	t.AppendPoint("A", a)
}

// ProvePossession proves knowledge of sk such that pk = sk*G.
func ProvePossession(sk *fr.Element, pk *bn254.G1Affine, transcript *Transcript, rng io.Reader) (PopProof, error) {
	if sk == nil {
		return PopProof{}, fmt.Errorf("pop: nil secret key")
	}
	if err := ValidatePublicKey(pk); err != nil {
		return PopProof{}, err
	}

	k, err := randomScalar(rng)
	if err != nil {
		return PopProof{}, err
	}

	var a bn254.G1Affine
	a.ScalarMultiplication(&G, k.BigInt(new(big.Int)))

	if transcript == nil {
		transcript = NewTranscript("x/confidential/v1")
	}
	appendPopTranscript(transcript, pk, &a)
	e := transcript.ChallengeScalar("pop_challenge")

	var z, eSk fr.Element
	eSk.Mul(&e, sk)
	z.Add(&k, &eSk)

	return PopProof{Z: z, A: a}, nil
}

// VerifyPossession verifies a proof of possession for pk.
func VerifyPossession(proof *PopProof, pk *bn254.G1Affine, transcript *Transcript) bool {
	if proof == nil {
		return false
	}
	if err := ValidatePublicKey(pk); err != nil {
		return false
	}
	// Reject an identity nonce commitment; see VerifyCommitmentEquality.
	if !proof.A.IsOnCurve() || proof.A.IsInfinity() {
		return false
	}

	if transcript == nil {
		transcript = NewTranscript("x/confidential/v1")
	}
	appendPopTranscript(transcript, pk, &proof.A)
	e := transcript.ChallengeScalar("pop_challenge")

	// Check: Z*G == A + e*pk
	var lhs bn254.G1Affine
	lhs.ScalarMultiplication(&G, proof.Z.BigInt(new(big.Int)))

	var ePk bn254.G1Affine
	ePk.ScalarMultiplication(pk, e.BigInt(new(big.Int)))
	rhs := addAffine(&proof.A, &ePk)

	return lhs.Equal(&rhs)
}

// Marshal serializes the PopProof as Z(32) || A(64).
func (p *PopProof) Marshal() []byte {
	buf := make([]byte, PopProofSize)
	off := marshalScalar(buf, 0, &p.Z)
	marshalPoint(buf, off, &p.A)
	return buf
}

// Unmarshal deserializes a PopProof from bytes.
func (p *PopProof) Unmarshal(data []byte) error {
	if len(data) != PopProofSize {
		return fmt.Errorf("invalid PopProof length: expected %d bytes, got %d", PopProofSize, len(data))
	}
	off, err := unmarshalScalar(data, 0, &p.Z)
	if err != nil {
		return fmt.Errorf("failed to unmarshal Z: %w", err)
	}
	if _, err := unmarshalPoint(data, off, &p.A); err != nil {
		return fmt.Errorf("failed to unmarshal A: %w", err)
	}
	return nil
}
