package elgamal

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/stretchr/testify/require"
)

func TestDLEQProof_Valid(t *testing.T) {
	sk, pk, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	amount := uint64(42000)
	ct, _, err := Encrypt(amount, &pk, rand.Reader)
	require.NoError(t, err)

	proof, err := ProveDLEQ(&sk, &pk, &ct, amount, nil, nil)
	require.NoError(t, err)

	ok := VerifyDLEQ(&proof, &pk, &ct, amount, nil)
	require.True(t, ok, "valid DLEQ proof must verify")
}

func TestDLEQProof_WrongAmount(t *testing.T) {
	sk, pk, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	amount := uint64(42000)
	ct, _, err := Encrypt(amount, &pk, rand.Reader)
	require.NoError(t, err)

	proof, err := ProveDLEQ(&sk, &pk, &ct, amount, nil, nil)
	require.NoError(t, err)

	ok := VerifyDLEQ(&proof, &pk, &ct, 99999, nil)
	require.False(t, ok, "DLEQ proof with wrong amount must not verify")
}

func TestDLEQProof_WrongKey(t *testing.T) {
	sk1, pk1, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	_, pk2, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	amount := uint64(42000)
	ct, _, err := Encrypt(amount, &pk1, rand.Reader)
	require.NoError(t, err)

	proof, err := ProveDLEQ(&sk1, &pk1, &ct, amount, nil, nil)
	require.NoError(t, err)

	ok := VerifyDLEQ(&proof, &pk2, &ct, amount, nil)
	require.False(t, ok, "DLEQ proof with wrong public key must not verify")
}

// TestDLEQProof_ForgedWithIdentityKey demonstrates a genuine forgery attack:
// when pk = identity is accepted, a malicious prover can construct a DLEQ
// "proof" that a ciphertext decrypts to ANY amount of their choosing, without
// knowing any secret key. This test constructs such a forged proof and asserts
// that VerifyDLEQ rejects it (which requires ValidatePublicKey at verify time).
//
// Forgery strategy:
//   - Attacker picks any C1 (say, G itself).
//   - Attacker sets C2 = claimedAmount*G so that (C2 - m*G) = O.
//   - Attacker picks random k, sets R1 = k*G, R2 = k*C1, S = k.
//   - With pk = O:
//     Check 1: S*G == R1 + e*O  →  k*G == k*G  ✓
//     Check 2: S*C1 == R2 + e*(C2 - m*G)  →  k*C1 == k*C1 + e*O  →  k*C1 == k*C1  ✓
//   - The proof verifies for ANY challenge e and ANY claimedAmount.
func TestDLEQProof_ForgedWithIdentityKey(t *testing.T) {
	var identity bn254.G1Affine // point at infinity

	// Attacker crafts a ciphertext: C1 = 7*G (any valid point), C2 = m*G.
	claimedAmount := uint64(999999) // attacker chooses freely
	var c1, c2 bn254.G1Affine
	c1.ScalarMultiplication(&G, big.NewInt(7))
	c2.ScalarMultiplication(&G, new(big.Int).SetUint64(claimedAmount))
	ct := &Ciphertext{C1: c1, C2: c2}

	// Attacker picks random k, sets R1 = k*G, R2 = k*C1, S = k.
	var k fr.Element
	_, err := k.SetRandom()
	require.NoError(t, err)
	kBig := k.BigInt(new(big.Int))

	var r1, r2 bn254.G1Affine
	r1.ScalarMultiplication(&G, kBig)
	r2.ScalarMultiplication(&ct.C1, kBig)

	proof := DLEQProof{S: k, R1: r1, R2: r2}

	// Without ValidatePublicKey, this forged proof verifies.
	ok := VerifyDLEQ(&proof, &identity, ct, claimedAmount, nil)
	require.False(t, ok, "forged DLEQ proof targeting identity pk must be rejected")
}

// TestProveDLEQ_HonorsRng pins deterministic proof generation under a seeded
// RNG — the same inputs + same seed must produce the same proof byte-for-byte.
// Required for KAT / cross-implementation test vectors.
func TestProveDLEQ_HonorsRng(t *testing.T) {
	// Deterministic keypair (so the test doesn't depend on KeyGen randomness).
	seed := make([]byte, 256)
	for i := range seed {
		seed[i] = byte(i)
	}
	sk, pk, err := KeyGen(bytes.NewReader(seed))
	require.NoError(t, err)
	// Deterministic ciphertext too.
	ct, _, err := Encrypt(42, &pk, bytes.NewReader(seed))
	require.NoError(t, err)

	proofSeed := make([]byte, 256)
	for i := range proofSeed {
		proofSeed[i] = byte(0xA5 ^ i)
	}
	p1, err := ProveDLEQ(&sk, &pk, &ct, 42, nil, bytes.NewReader(proofSeed))
	require.NoError(t, err)
	p2, err := ProveDLEQ(&sk, &pk, &ct, 42, nil, bytes.NewReader(proofSeed))
	require.NoError(t, err)

	require.Equal(t, p1.Marshal(), p2.Marshal(), "same seed must produce same DLEQ proof")

	// Different seed should produce a different proof.
	otherSeed := make([]byte, 256)
	for i := range otherSeed {
		otherSeed[i] = byte(0x5A ^ i)
	}
	p3, err := ProveDLEQ(&sk, &pk, &ct, 42, nil, bytes.NewReader(otherSeed))
	require.NoError(t, err)
	require.NotEqual(t, p1.Marshal(), p3.Marshal(), "different seed must produce different proof")

	// Both proofs must verify.
	require.True(t, VerifyDLEQ(&p1, &pk, &ct, 42, nil))
	require.True(t, VerifyDLEQ(&p3, &pk, &ct, 42, nil))
}

// TestDLEQProof_DegenerateCiphertextRejected demonstrates a real attack path
// against a caller that builds a Ciphertext struct directly (bypassing
// Ciphertext.Unmarshal, which rejects C1 = identity). An attacker picks any
// amount m, builds ct = {C1: O, C2: m*G}, and honestly runs ProveDLEQ. The
// proof verifies today because:
//
//	Check 1: S*G == R1 + e*pk  (standard Schnorr knowledge of sk — passes)
//	Check 2: S*C1 == R2 + e*(C2 - m*G)  →  O == O  (vacuous, because C1 = O
//	        forces LHS = O, and C2 - m*G = O by construction forces RHS = O)
//
// The result is that the chain accepts a publicly-readable "ciphertext" as if
// it were a legitimate confidential encryption — any observer can read the
// amount by computing m*G and checking it equals C2. For a confidential-
// transfer protocol this destroys privacy for any balance touched by the
// crafted ciphertext. VerifyDLEQ must reject C1 = identity at the entry point.
func TestDLEQProof_DegenerateCiphertextRejected(t *testing.T) {
	// Attacker has a real keypair (passes ValidatePublicKey).
	sk, pk, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	// Attacker picks an arbitrary amount and crafts the degenerate ciphertext.
	claimedAmount := uint64(1_000_000)
	var c2 bn254.G1Affine
	c2.ScalarMultiplication(&G, new(big.Int).SetUint64(claimedAmount))
	// Ciphertext constructed directly — C1 is the zero value G1Affine which
	// is the point at infinity. Unmarshal would reject, but a caller reading
	// pre-deserialized state into the struct would not.
	var degenCt Ciphertext
	degenCt.C2 = c2
	require.True(t, degenCt.C1.IsInfinity(), "test setup: C1 must be identity")

	// Attacker honestly runs the prover. The math works because both
	// verification equations collapse to trivially-satisfiable relations.
	proof, err := ProveDLEQ(&sk, &pk, &degenCt, claimedAmount, nil, nil)
	require.NoError(t, err)

	ok := VerifyDLEQ(&proof, &pk, &degenCt, claimedAmount, nil)
	require.False(t, ok, "VerifyDLEQ must reject a ciphertext with C1 = identity")
}

// TestDLEQProof_IdentityKeyRejectedBenign is a weaker, defense-in-depth check:
// a valid proof generated against a real (sk, pk) must still be rejected when
// the verifier is called with pk = identity (caller fed an unvalidated key).
func TestDLEQProof_IdentityKeyRejectedBenign(t *testing.T) {
	sk, pk, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	amount := uint64(42000)
	ct, _, err := Encrypt(amount, &pk, rand.Reader)
	require.NoError(t, err)

	proof, err := ProveDLEQ(&sk, &pk, &ct, amount, nil, nil)
	require.NoError(t, err)

	var identity bn254.G1Affine
	ok := VerifyDLEQ(&proof, &identity, &ct, amount, nil)
	require.False(t, ok, "VerifyDLEQ must reject identity public key")
}

func TestDLEQProof_WithTranscript(t *testing.T) {
	sk, pk, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	ct, _, err := Encrypt(42000, &pk, rand.Reader)
	require.NoError(t, err)

	// Create transcript with context (simulating Cosmos module)
	proverT := NewTranscript("x/confidential/v1")
	proverT.AppendBytes("chain_id", []byte("nix-1"))
	proverT.AppendBytes("sender", []byte("cosmos1abc"))

	proof, err := ProveDLEQ(&sk, &pk, &ct, 42000, proverT, nil)
	require.NoError(t, err)

	// Verifier must use identical transcript context
	verifierT := NewTranscript("x/confidential/v1")
	verifierT.AppendBytes("chain_id", []byte("nix-1"))
	verifierT.AppendBytes("sender", []byte("cosmos1abc"))

	require.True(t, VerifyDLEQ(&proof, &pk, &ct, 42000, verifierT))

	// Different context should fail
	wrongT := NewTranscript("x/confidential/v1")
	wrongT.AppendBytes("chain_id", []byte("other-chain"))
	wrongT.AppendBytes("sender", []byte("cosmos1abc"))

	require.False(t, VerifyDLEQ(&proof, &pk, &ct, 42000, wrongT))
}
