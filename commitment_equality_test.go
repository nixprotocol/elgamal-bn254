package elgamal

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// testH returns a nothing-up-my-sleeve second generator. The bulletproofs
// package cannot be imported here (it depends on this one), so the test derives
// its own via hash-to-curve, exactly as bulletproofs does.
func testH(t *testing.T) bn254.G1Affine {
	t.Helper()
	h, err := bn254.HashToG1([]byte("elgamal-bn254/test/H"), []byte("elgamal-bn254-test"))
	if err != nil {
		t.Fatalf("hash to curve: %v", err)
	}
	return h
}

// commitWith computes v*G + s*H.
func commitWith(v, s *fr.Element, H *bn254.G1Affine) bn254.G1Affine {
	var vG, sH bn254.G1Affine
	vG.ScalarMultiplication(&G, v.BigInt(new(big.Int)))
	sH.ScalarMultiplication(H, s.BigInt(new(big.Int)))
	return addAffine(&vG, &sH)
}

func setupCommitmentEquality(t *testing.T, amount uint64) (
	pk bn254.G1Affine, H bn254.G1Affine, ct Ciphertext,
	commitment bn254.G1Affine, value, r, s fr.Element,
) {
	t.Helper()
	_, pk, err := KeyGen(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	H = testH(t)

	if _, err := r.SetRandom(); err != nil {
		t.Fatalf("rand r: %v", err)
	}
	ct, _, err = EncryptWithRandomness(amount, &pk, &r)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	if _, err := s.SetRandom(); err != nil {
		t.Fatalf("rand s: %v", err)
	}
	value.SetUint64(amount)
	commitment = commitWith(&value, &s, &H)
	return
}

func TestCommitmentEquality_Valid(t *testing.T) {
	pk, H, ct, commitment, value, r, s := setupCommitmentEquality(t, 12345)

	proof, err := ProveCommitmentEquality(&value, &r, &s, &pk, &H, &ct, &commitment,
		NewTranscript("x/confidential/v1"), rand.Reader)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}

	if !VerifyCommitmentEquality(&proof, &pk, &H, &ct, &commitment,
		NewTranscript("x/confidential/v1")) {
		t.Fatal("valid proof was rejected")
	}
}

// The whole point of this proof: a prover who knows sk can still open the
// ElGamal C2 to any value, but cannot make the Pedersen commitment disagree
// with the ciphertext.
func TestCommitmentEquality_RejectsMismatchedValue(t *testing.T) {
	pk, H, ct, _, _, r, s := setupCommitmentEquality(t, 1_000_000)

	// Commit to 0 while the ciphertext encrypts 1,000,000.
	var zero fr.Element
	lyingCommitment := commitWith(&zero, &s, &H)

	// Prove with the value the commitment actually holds.
	proof, err := ProveCommitmentEquality(&zero, &r, &s, &pk, &H, &ct, &lyingCommitment,
		NewTranscript("x/confidential/v1"), rand.Reader)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}
	if VerifyCommitmentEquality(&proof, &pk, &H, &ct, &lyingCommitment,
		NewTranscript("x/confidential/v1")) {
		t.Fatal("proof linking a 1,000,000 ciphertext to a commitment of 0 was accepted")
	}

	// And with the value the ciphertext actually holds.
	var real fr.Element
	real.SetUint64(1_000_000)
	proof2, err := ProveCommitmentEquality(&real, &r, &s, &pk, &H, &ct, &lyingCommitment,
		NewTranscript("x/confidential/v1"), rand.Reader)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}
	if VerifyCommitmentEquality(&proof2, &pk, &H, &ct, &lyingCommitment,
		NewTranscript("x/confidential/v1")) {
		t.Fatal("proof with mismatched commitment blinding was accepted")
	}
}

func TestCommitmentEquality_RejectsTamperedCiphertext(t *testing.T) {
	pk, H, ct, commitment, value, r, s := setupCommitmentEquality(t, 500)

	proof, err := ProveCommitmentEquality(&value, &r, &s, &pk, &H, &ct, &commitment,
		NewTranscript("x/confidential/v1"), rand.Reader)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}

	var other fr.Element
	if _, err := other.SetRandom(); err != nil {
		t.Fatalf("rand: %v", err)
	}
	tampered, _, err := EncryptWithRandomness(501, &pk, &other)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	if VerifyCommitmentEquality(&proof, &pk, &H, &tampered, &commitment,
		NewTranscript("x/confidential/v1")) {
		t.Fatal("proof verified against a different ciphertext")
	}
}

func TestCommitmentEquality_RejectsWrongTranscript(t *testing.T) {
	pk, H, ct, commitment, value, r, s := setupCommitmentEquality(t, 7)

	proof, err := ProveCommitmentEquality(&value, &r, &s, &pk, &H, &ct, &commitment,
		NewTranscript("x/confidential/v1"), rand.Reader)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}

	bound := NewTranscript("x/confidential/v1")
	bound.AppendBytes("sender", []byte("someone-else"))
	if VerifyCommitmentEquality(&proof, &pk, &H, &ct, &commitment, bound) {
		t.Fatal("proof verified under a different transcript context")
	}
}

func TestCommitmentEquality_RejectsIdentityBases(t *testing.T) {
	pk, H, ct, commitment, value, r, s := setupCommitmentEquality(t, 42)
	proof, err := ProveCommitmentEquality(&value, &r, &s, &pk, &H, &ct, &commitment,
		NewTranscript("x/confidential/v1"), rand.Reader)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}

	var identity bn254.G1Affine
	if VerifyCommitmentEquality(&proof, &identity, &H, &ct, &commitment,
		NewTranscript("x/confidential/v1")) {
		t.Fatal("identity pk was accepted")
	}
	if VerifyCommitmentEquality(&proof, &pk, &identity, &ct, &commitment,
		NewTranscript("x/confidential/v1")) {
		t.Fatal("identity H was accepted")
	}
	if VerifyCommitmentEquality(&proof, &pk, &H, &ct, &identity,
		NewTranscript("x/confidential/v1")) {
		t.Fatal("identity commitment was accepted")
	}
}

func TestCommitmentEquality_Serialization(t *testing.T) {
	pk, H, ct, commitment, value, r, s := setupCommitmentEquality(t, 999)

	proof, err := ProveCommitmentEquality(&value, &r, &s, &pk, &H, &ct, &commitment,
		NewTranscript("x/confidential/v1"), rand.Reader)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}

	data := proof.Marshal()
	if len(data) != CommitmentEqualityProofSize {
		t.Fatalf("expected %d bytes, got %d", CommitmentEqualityProofSize, len(data))
	}

	var decoded CommitmentEqualityProof
	if err := decoded.Unmarshal(data); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !VerifyCommitmentEquality(&decoded, &pk, &H, &ct, &commitment,
		NewTranscript("x/confidential/v1")) {
		t.Fatal("round-tripped proof failed to verify")
	}

	if err := decoded.Unmarshal(data[:len(data)-1]); err == nil {
		t.Fatal("truncated proof was accepted")
	}
}
