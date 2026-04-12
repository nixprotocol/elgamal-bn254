package elgamal

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/stretchr/testify/require"
)

func TestEqualityProof_Valid(t *testing.T) {
	_, pk1, err := KeyGen(rand.Reader)
	require.NoError(t, err)
	_, pk2, err := KeyGen(rand.Reader)
	require.NoError(t, err)
	_, pk3, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	amount := uint64(12345)

	ct1, r1, err := Encrypt(amount, &pk1, rand.Reader)
	require.NoError(t, err)
	ct2, r2, err := Encrypt(amount, &pk2, rand.Reader)
	require.NoError(t, err)
	ct3, r3, err := Encrypt(amount, &pk3, rand.Reader)
	require.NoError(t, err)

	proof, err := ProveEquality(amount, &r1, &r2, &r3, &pk1, &pk2, &pk3, &ct1, &ct2, &ct3, nil, nil)
	require.NoError(t, err)

	ok := VerifyEquality(&proof, &pk1, &pk2, &pk3, &ct1, &ct2, &ct3, nil)
	require.True(t, ok, "valid equality proof must verify")
}

func TestEqualityProof_DifferentAmounts(t *testing.T) {
	_, pk1, err := KeyGen(rand.Reader)
	require.NoError(t, err)
	_, pk2, err := KeyGen(rand.Reader)
	require.NoError(t, err)
	_, pk3, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	amount1 := uint64(12345)
	amount2 := uint64(99999) // different

	ct1, r1, err := Encrypt(amount1, &pk1, rand.Reader)
	require.NoError(t, err)
	ct2, r2, err := Encrypt(amount2, &pk2, rand.Reader) // wrong amount
	require.NoError(t, err)
	ct3, r3, err := Encrypt(amount1, &pk3, rand.Reader)
	require.NoError(t, err)

	// Prover tries to prove equality with amount1, but ct2 encrypts amount2.
	proof, err := ProveEquality(amount1, &r1, &r2, &r3, &pk1, &pk2, &pk3, &ct1, &ct2, &ct3, nil, nil)
	require.NoError(t, err)

	ok := VerifyEquality(&proof, &pk1, &pk2, &pk3, &ct1, &ct2, &ct3, nil)
	require.False(t, ok, "equality proof with different amounts must not verify")
}

func TestEqualityProof_WrongKey(t *testing.T) {
	_, pk1, err := KeyGen(rand.Reader)
	require.NoError(t, err)
	_, pk2, err := KeyGen(rand.Reader)
	require.NoError(t, err)
	_, pk3, err := KeyGen(rand.Reader)
	require.NoError(t, err)
	_, pk3Wrong, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	amount := uint64(12345)

	ct1, r1, err := Encrypt(amount, &pk1, rand.Reader)
	require.NoError(t, err)
	ct2, r2, err := Encrypt(amount, &pk2, rand.Reader)
	require.NoError(t, err)
	ct3, r3, err := Encrypt(amount, &pk3, rand.Reader)
	require.NoError(t, err)

	proof, err := ProveEquality(amount, &r1, &r2, &r3, &pk1, &pk2, &pk3, &ct1, &ct2, &ct3, nil, nil)
	require.NoError(t, err)

	// Verify with wrong pk3
	ok := VerifyEquality(&proof, &pk1, &pk2, &pk3Wrong, &ct1, &ct2, &ct3, nil)
	require.False(t, ok, "equality proof with wrong public key must not verify")
}

func TestEqualityProof_IdentityKeyRejected(t *testing.T) {
	_, pk1, err := KeyGen(rand.Reader)
	require.NoError(t, err)
	_, pk2, err := KeyGen(rand.Reader)
	require.NoError(t, err)
	_, pk3, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	amount := uint64(12345)
	ct1, r1, err := Encrypt(amount, &pk1, rand.Reader)
	require.NoError(t, err)
	ct2, r2, err := Encrypt(amount, &pk2, rand.Reader)
	require.NoError(t, err)
	ct3, r3, err := Encrypt(amount, &pk3, rand.Reader)
	require.NoError(t, err)

	proof, err := ProveEquality(amount, &r1, &r2, &r3, &pk1, &pk2, &pk3, &ct1, &ct2, &ct3, nil, nil)
	require.NoError(t, err)

	var identity bn254.G1Affine
	// Replace pk3 with identity.
	ok := VerifyEquality(&proof, &pk1, &pk2, &identity, &ct1, &ct2, &ct3, nil)
	require.False(t, ok, "VerifyEquality must reject identity public key")
}

func TestEquality2Proof_IdentityKeyRejected(t *testing.T) {
	_, pk1, err := KeyGen(rand.Reader)
	require.NoError(t, err)
	_, pk2, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	amount := uint64(12345)
	ct1, r1, err := Encrypt(amount, &pk1, rand.Reader)
	require.NoError(t, err)
	ct2, r2, err := Encrypt(amount, &pk2, rand.Reader)
	require.NoError(t, err)

	proof, err := ProveEquality2(amount, &r1, &r2, &pk1, &pk2, &ct1, &ct2, nil, nil)
	require.NoError(t, err)

	var identity bn254.G1Affine
	ok := VerifyEquality2(&proof, &pk1, &identity, &ct1, &ct2, nil)
	require.False(t, ok, "VerifyEquality2 must reject identity public key (rotation to identity would leak balance)")
}

// TestEqualityProof_DegenerateCiphertextRejected pins defense-in-depth against
// the C1=identity attack: a caller constructing ct3 as {C1: O, C2: m*G}
// directly (bypassing Unmarshal) would otherwise get a proof that verifies.
func TestEqualityProof_DegenerateCiphertextRejected(t *testing.T) {
	_, pk1, err := KeyGen(rand.Reader)
	require.NoError(t, err)
	_, pk2, err := KeyGen(rand.Reader)
	require.NoError(t, err)
	_, pk3, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	amount := uint64(12345)
	ct1, r1, err := Encrypt(amount, &pk1, rand.Reader)
	require.NoError(t, err)
	ct2, r2, err := Encrypt(amount, &pk2, rand.Reader)
	require.NoError(t, err)

	// Degenerate third ciphertext: C1 = O, C2 = amount*G.
	var ct3Degen Ciphertext
	ct3Degen.C2.ScalarMultiplication(&G, big.NewInt(int64(amount)))
	var r3Zero fr.Element // zero randomness — matches C1 = 0*G = O

	proof, err := ProveEquality(amount, &r1, &r2, &r3Zero, &pk1, &pk2, &pk3, &ct1, &ct2, &ct3Degen, nil, nil)
	require.NoError(t, err)

	ok := VerifyEquality(&proof, &pk1, &pk2, &pk3, &ct1, &ct2, &ct3Degen, nil)
	require.False(t, ok, "VerifyEquality must reject ct with C1 = identity")
}

func TestEquality2Proof_DegenerateCiphertextRejected(t *testing.T) {
	_, pk1, err := KeyGen(rand.Reader)
	require.NoError(t, err)
	_, pk2, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	amount := uint64(12345)
	ct1, r1, err := Encrypt(amount, &pk1, rand.Reader)
	require.NoError(t, err)

	var ct2Degen Ciphertext
	ct2Degen.C2.ScalarMultiplication(&G, big.NewInt(int64(amount)))
	var r2Zero fr.Element

	proof, err := ProveEquality2(amount, &r1, &r2Zero, &pk1, &pk2, &ct1, &ct2Degen, nil, nil)
	require.NoError(t, err)

	ok := VerifyEquality2(&proof, &pk1, &pk2, &ct1, &ct2Degen, nil)
	require.False(t, ok, "VerifyEquality2 must reject ct with C1 = identity")
}

func TestEquality2Proof_WrongKey(t *testing.T) {
	_, pk1, err := KeyGen(rand.Reader)
	require.NoError(t, err)
	_, pk2, err := KeyGen(rand.Reader)
	require.NoError(t, err)
	_, pk2Wrong, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	amount := uint64(12345)
	ct1, r1, err := Encrypt(amount, &pk1, rand.Reader)
	require.NoError(t, err)
	ct2, r2, err := Encrypt(amount, &pk2, rand.Reader)
	require.NoError(t, err)

	proof, err := ProveEquality2(amount, &r1, &r2, &pk1, &pk2, &ct1, &ct2, nil, nil)
	require.NoError(t, err)

	ok := VerifyEquality2(&proof, &pk1, &pk2Wrong, &ct1, &ct2, nil)
	require.False(t, ok, "2-key equality proof with wrong pk2 must not verify")
}

func TestEqualityProof_WithTranscript(t *testing.T) {
	_, pk1, err := KeyGen(rand.Reader)
	require.NoError(t, err)
	_, pk2, err := KeyGen(rand.Reader)
	require.NoError(t, err)
	_, pk3, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	amount := uint64(12345)

	ct1, r1, err := Encrypt(amount, &pk1, rand.Reader)
	require.NoError(t, err)
	ct2, r2, err := Encrypt(amount, &pk2, rand.Reader)
	require.NoError(t, err)
	ct3, r3, err := Encrypt(amount, &pk3, rand.Reader)
	require.NoError(t, err)

	// Create transcript with context (simulating Cosmos module)
	proverT := NewTranscript("x/confidential/v1")
	proverT.AppendBytes("chain_id", []byte("nix-1"))
	proverT.AppendBytes("sender", []byte("cosmos1abc"))

	proof, err := ProveEquality(amount, &r1, &r2, &r3, &pk1, &pk2, &pk3, &ct1, &ct2, &ct3, proverT, nil)
	require.NoError(t, err)

	// Verifier must use identical transcript context
	verifierT := NewTranscript("x/confidential/v1")
	verifierT.AppendBytes("chain_id", []byte("nix-1"))
	verifierT.AppendBytes("sender", []byte("cosmos1abc"))

	require.True(t, VerifyEquality(&proof, &pk1, &pk2, &pk3, &ct1, &ct2, &ct3, verifierT))

	// Different context should fail
	wrongT := NewTranscript("x/confidential/v1")
	wrongT.AppendBytes("chain_id", []byte("other-chain"))
	wrongT.AppendBytes("sender", []byte("cosmos1abc"))

	require.False(t, VerifyEquality(&proof, &pk1, &pk2, &pk3, &ct1, &ct2, &ct3, wrongT))
}

// ---------- 2-key equality proof tests ----------

func TestEquality2Proof_Valid(t *testing.T) {
	_, pk1, err := KeyGen(rand.Reader)
	require.NoError(t, err)
	_, pk2, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	amount := uint64(12345)

	ct1, r1, err := Encrypt(amount, &pk1, rand.Reader)
	require.NoError(t, err)
	ct2, r2, err := Encrypt(amount, &pk2, rand.Reader)
	require.NoError(t, err)

	proof, err := ProveEquality2(amount, &r1, &r2, &pk1, &pk2, &ct1, &ct2, nil, nil)
	require.NoError(t, err)

	ok := VerifyEquality2(&proof, &pk1, &pk2, &ct1, &ct2, nil)
	require.True(t, ok, "valid 2-key equality proof must verify")
}

func TestEquality2Proof_DifferentAmounts(t *testing.T) {
	_, pk1, err := KeyGen(rand.Reader)
	require.NoError(t, err)
	_, pk2, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	amount1 := uint64(12345)
	amount2 := uint64(99999) // different

	ct1, r1, err := Encrypt(amount1, &pk1, rand.Reader)
	require.NoError(t, err)
	ct2, r2, err := Encrypt(amount2, &pk2, rand.Reader) // wrong amount
	require.NoError(t, err)

	// Prover tries to prove equality with amount1, but ct2 encrypts amount2.
	proof, err := ProveEquality2(amount1, &r1, &r2, &pk1, &pk2, &ct1, &ct2, nil, nil)
	require.NoError(t, err)

	ok := VerifyEquality2(&proof, &pk1, &pk2, &ct1, &ct2, nil)
	require.False(t, ok, "2-key equality proof with different amounts must not verify")
}

func TestEquality2Proof_WithTranscript(t *testing.T) {
	_, pk1, err := KeyGen(rand.Reader)
	require.NoError(t, err)
	_, pk2, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	amount := uint64(12345)

	ct1, r1, err := Encrypt(amount, &pk1, rand.Reader)
	require.NoError(t, err)
	ct2, r2, err := Encrypt(amount, &pk2, rand.Reader)
	require.NoError(t, err)

	// Create transcript with context (simulating Cosmos module)
	proverT := NewTranscript("x/confidential/v1")
	proverT.AppendBytes("chain_id", []byte("nix-1"))
	proverT.AppendBytes("sender", []byte("cosmos1abc"))

	proof, err := ProveEquality2(amount, &r1, &r2, &pk1, &pk2, &ct1, &ct2, proverT, nil)
	require.NoError(t, err)

	// Verifier must use identical transcript context
	verifierT := NewTranscript("x/confidential/v1")
	verifierT.AppendBytes("chain_id", []byte("nix-1"))
	verifierT.AppendBytes("sender", []byte("cosmos1abc"))

	require.True(t, VerifyEquality2(&proof, &pk1, &pk2, &ct1, &ct2, verifierT))

	// Different context should fail
	wrongT := NewTranscript("x/confidential/v1")
	wrongT.AppendBytes("chain_id", []byte("other-chain"))
	wrongT.AppendBytes("sender", []byte("cosmos1abc"))

	require.False(t, VerifyEquality2(&proof, &pk1, &pk2, &ct1, &ct2, wrongT))
}
