package elgamal

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/stretchr/testify/require"
)

// ---------- Round-trip tests ----------

func TestDLEQProofMarshalRoundTrip(t *testing.T) {
	sk, pk, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	amount := uint64(42000)
	ct, _, err := Encrypt(amount, &pk, rand.Reader)
	require.NoError(t, err)

	proof, err := ProveDLEQ(&sk, &pk, &ct, amount, nil, nil)
	require.NoError(t, err)

	// Marshal
	data := proof.Marshal()
	require.Len(t, data, DLEQProofSize)

	// Unmarshal
	var proof2 DLEQProof
	err = proof2.Unmarshal(data)
	require.NoError(t, err)

	// Verify the unmarshaled proof still verifies
	ok := VerifyDLEQ(&proof2, &pk, &ct, amount, nil)
	require.True(t, ok, "unmarshaled DLEQ proof must still verify")
}

func TestEqualityProofMarshalRoundTrip(t *testing.T) {
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

	// Marshal
	data := proof.Marshal()
	require.Len(t, data, EqualityProofSize)

	// Unmarshal
	var proof2 EqualityProof
	err = proof2.Unmarshal(data)
	require.NoError(t, err)

	// Verify the unmarshaled proof still verifies
	ok := VerifyEquality(&proof2, &pk1, &pk2, &pk3, &ct1, &ct2, &ct3, nil)
	require.True(t, ok, "unmarshaled equality proof must still verify")
}

func TestEquality2ProofMarshalRoundTrip(t *testing.T) {
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

	// Marshal
	data := proof.Marshal()
	require.Len(t, data, Equality2ProofSize)

	// Unmarshal
	var proof2 Equality2Proof
	err = proof2.Unmarshal(data)
	require.NoError(t, err)

	// Verify the unmarshaled proof still verifies
	ok := VerifyEquality2(&proof2, &pk1, &pk2, &ct1, &ct2, nil)
	require.True(t, ok, "unmarshaled 2-key equality proof must still verify")
}

func TestApplyPendingProofMarshalRoundTrip(t *testing.T) {
	sk, pk, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	amount := uint64(500)
	pending, _, err := Encrypt(amount, &pk, rand.Reader)
	require.NoError(t, err)

	newCt, rNew, err := Encrypt(amount, &pk, rand.Reader)
	require.NoError(t, err)

	proof, err := ProveApplyPending(&sk, &pk, &pending, &newCt, amount, &rNew, nil, nil)
	require.NoError(t, err)

	// Marshal
	data := proof.Marshal()
	require.Len(t, data, ApplyPendingProofSize)

	// Unmarshal
	var proof2 ApplyPendingProof
	err = proof2.Unmarshal(data)
	require.NoError(t, err)

	// Verify the unmarshaled proof still verifies
	ok := VerifyApplyPending(&proof2, &pk, &pending, &newCt, nil)
	require.True(t, ok, "unmarshaled ApplyPending proof must still verify")
}

// ---------- Size tests ----------

func TestDLEQProofSize(t *testing.T) {
	require.Equal(t, 160, DLEQProofSize)
}

func TestEqualityProofSize(t *testing.T) {
	require.Equal(t, 512, EqualityProofSize)
}

func TestEquality2ProofSize(t *testing.T) {
	require.Equal(t, 352, Equality2ProofSize)
}

func TestApplyPendingProofSize(t *testing.T) {
	require.Equal(t, 352, ApplyPendingProofSize)
}

// ---------- Invalid input tests ----------

func TestDLEQProofUnmarshalInvalid(t *testing.T) {
	var proof DLEQProof

	// Too short
	err := proof.Unmarshal([]byte{0x01, 0x02, 0x03})
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid DLEQProof length")

	// Too long
	err = proof.Unmarshal(make([]byte, 256))
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid DLEQProof length")
}

func TestEqualityProofUnmarshalInvalid(t *testing.T) {
	var proof EqualityProof

	// Too short
	err := proof.Unmarshal([]byte{0x01, 0x02, 0x03})
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid EqualityProof length")

	// Too long
	err = proof.Unmarshal(make([]byte, 1024))
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid EqualityProof length")
}

// ---------- Scalar canonicalization (malleability) tests ----------

// TestDLEQProofUnmarshalNonCanonicalScalar verifies that a valid DLEQ proof's
// serialization is strictly canonical: rewriting the S scalar as (S + q) where
// q is the fr modulus must be rejected, not silently reduced.
func TestDLEQProofUnmarshalNonCanonicalScalar(t *testing.T) {
	sk, pk, err := KeyGen(rand.Reader)
	require.NoError(t, err)
	amount := uint64(42000)
	ct, _, err := Encrypt(amount, &pk, rand.Reader)
	require.NoError(t, err)
	proof, err := ProveDLEQ(&sk, &pk, &ct, amount, nil, nil)
	require.NoError(t, err)

	data := proof.Marshal()

	// Replace the S scalar (first 32 bytes, big-endian) with S + q.
	// fr modulus q < 2^254, S < q, so S + q < 2^255 < 2^256 — fits in 32 bytes.
	sBytes := proof.S.Bytes()
	sBig := new(big.Int).SetBytes(sBytes[:])
	q := fr.Modulus()
	sPlusQ := new(big.Int).Add(sBig, q)

	// Sanity: S + q mod q == S, so non-canonical encoding decodes to same scalar
	// via the old (buggy) path.
	require.True(t, new(big.Int).Mod(sPlusQ, q).Cmp(sBig) == 0)

	// Serialize S + q into 32 big-endian bytes (left-padded).
	nonCanonical := sPlusQ.Bytes()
	require.LessOrEqual(t, len(nonCanonical), 32, "S+q must fit in 32 bytes")
	tampered := make([]byte, len(data))
	copy(tampered, data)
	// Zero the scalar slot then left-pad.
	for i := 0; i < 32; i++ {
		tampered[i] = 0
	}
	copy(tampered[32-len(nonCanonical):32], nonCanonical)

	var p2 DLEQProof
	err = p2.Unmarshal(tampered)
	require.Error(t, err, "non-canonical scalar encoding must be rejected")
}

// TestEqualityProofUnmarshalNonCanonicalScalar is the same malleability check
// against the 3-key equality proof's Sm slot.
func TestEqualityProofUnmarshalNonCanonicalScalar(t *testing.T) {
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

	data := proof.Marshal()

	// Tamper with the Sm slot (first scalar).
	smBytes := proof.Sm.Bytes()
	smBig := new(big.Int).SetBytes(smBytes[:])
	q := fr.Modulus()
	smPlusQ := new(big.Int).Add(smBig, q)

	tampered := make([]byte, len(data))
	copy(tampered, data)
	for i := 0; i < 32; i++ {
		tampered[i] = 0
	}
	nc := smPlusQ.Bytes()
	copy(tampered[32-len(nc):32], nc)

	var p2 EqualityProof
	err = p2.Unmarshal(tampered)
	require.Error(t, err, "non-canonical Sm must be rejected")
}

// ---------- Public key round-trip ----------

func TestPublicKeyMarshalRoundTrip(t *testing.T) {
	_, pk, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	data := MarshalPublicKey(&pk)
	require.Len(t, data, PublicKeySize)

	pk2, err := UnmarshalPublicKey(data)
	require.NoError(t, err)

	require.True(t, pk.Equal(&pk2), "public key mismatch after round-trip")
}
