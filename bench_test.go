package elgamal

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func BenchmarkEncrypt(b *testing.B) {
	_, pk, err := KeyGen(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := Encrypt(42, &pk, rand.Reader)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecrypt(b *testing.B) {
	sk, pk, err := KeyGen(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	ct, _, err := Encrypt(100, &pk, rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	table := NewDecryptionTable(20)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Decrypt(&ct, &sk, table)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAdd(b *testing.B) {
	_, pk, err := KeyGen(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	ct1, _, err := Encrypt(10, &pk, rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	ct2, _, err := Encrypt(20, &pk, rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Add(&ct1, &ct2)
	}
}

func BenchmarkSub(b *testing.B) {
	_, pk, err := KeyGen(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	ct1, _, err := Encrypt(30, &pk, rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	ct2, _, err := Encrypt(10, &pk, rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Sub(&ct1, &ct2)
	}
}

func BenchmarkDLEQProve(b *testing.B) {
	sk, pk, err := KeyGen(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	var amount uint64 = 42
	ct, _, err := Encrypt(amount, &pk, rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ProveDLEQ(&sk, &pk, &ct, amount, nil, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDLEQVerify(b *testing.B) {
	sk, pk, err := KeyGen(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	var amount uint64 = 42
	ct, _, err := Encrypt(amount, &pk, rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	proof, err := ProveDLEQ(&sk, &pk, &ct, amount, nil, nil)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !VerifyDLEQ(&proof, &pk, &ct, amount, nil) {
			b.Fatal("verification failed")
		}
	}
}

func BenchmarkEqualityProve(b *testing.B) {
	_, pk1, err := KeyGen(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	_, pk2, err := KeyGen(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	_, pk3, err := KeyGen(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	var amount uint64 = 77
	ct1, r1, err := Encrypt(amount, &pk1, rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	ct2, r2, err := Encrypt(amount, &pk2, rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	ct3, r3, err := Encrypt(amount, &pk3, rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ProveEquality(amount, &r1, &r2, &r3, &pk1, &pk2, &pk3, &ct1, &ct2, &ct3, nil, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEqualityVerify(b *testing.B) {
	_, pk1, err := KeyGen(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	_, pk2, err := KeyGen(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	_, pk3, err := KeyGen(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	var amount uint64 = 77
	ct1, r1, err := Encrypt(amount, &pk1, rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	ct2, r2, err := Encrypt(amount, &pk2, rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	ct3, r3, err := Encrypt(amount, &pk3, rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	proof, err := ProveEquality(amount, &r1, &r2, &r3, &pk1, &pk2, &pk3, &ct1, &ct2, &ct3, nil, nil)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !VerifyEquality(&proof, &pk1, &pk2, &pk3, &ct1, &ct2, &ct3, nil) {
			b.Fatal("verification failed")
		}
	}
}

func BenchmarkApplyPendingProve(b *testing.B) {
	sk, pk, err := KeyGen(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	var amount uint64 = 55
	pending, _, err := Encrypt(amount, &pk, rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	newCt, rNew, err := Encrypt(amount, &pk, rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ProveApplyPending(&sk, &pk, &pending, &newCt, amount, &rNew, nil, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkApplyPendingVerify(b *testing.B) {
	sk, pk, err := KeyGen(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	var amount uint64 = 55
	pending, _, err := Encrypt(amount, &pk, rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	newCt, rNew, err := Encrypt(amount, &pk, rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	proof, err := ProveApplyPending(&sk, &pk, &pending, &newCt, amount, &rNew, nil, nil)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !VerifyApplyPending(&proof, &pk, &pending, &newCt, nil) {
			b.Fatal("verification failed")
		}
	}
}

func BenchmarkDecryptionTableInit_16(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NewDecryptionTable(16)
	}
}

// ---------------------------------------------------------------------------
// CommitmentEqualityProof — ties a Pedersen commitment to an ElGamal ciphertext
// so range proofs can run over a binding commitment. Verified twice per
// ConfidentialSend and once per Unshield, so its cost sits on the hot path.
// ---------------------------------------------------------------------------

// benchH is a stand-in for the NUMS blinding base. The bulletproofs package
// cannot be imported here (it depends on this one), so derive an equivalent.
func benchH(b *testing.B) bn254.G1Affine {
	b.Helper()
	h, err := bn254.HashToG1([]byte("elgamal-bn254/bench/H"), []byte("elgamal-bn254-bench"))
	if err != nil {
		b.Fatal(err)
	}
	return h
}

func benchCommitmentStatement(b *testing.B) (
	pk, H bn254.G1Affine, ct Ciphertext, commitment bn254.G1Affine, value, r, s fr.Element,
) {
	b.Helper()
	_, pk, err := KeyGen(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	H = benchH(b)

	if _, err := r.SetRandom(); err != nil {
		b.Fatal(err)
	}
	ct, _, err = EncryptWithRandomness(42, &pk, &r)
	if err != nil {
		b.Fatal(err)
	}

	if _, err := s.SetRandom(); err != nil {
		b.Fatal(err)
	}
	value.SetUint64(42)

	var vG, sH bn254.G1Affine
	vG.ScalarMultiplication(&G, value.BigInt(new(big.Int)))
	sH.ScalarMultiplication(&H, s.BigInt(new(big.Int)))
	commitment = addAffine(&vG, &sH)
	return
}

func BenchmarkCommitmentEqualityProve(b *testing.B) {
	pk, H, ct, commitment, value, r, s := benchCommitmentStatement(b)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ProveCommitmentEquality(&value, &r, &s, &pk, &H, &ct, &commitment, nil, rand.Reader); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCommitmentEqualityVerify(b *testing.B) {
	pk, H, ct, commitment, value, r, s := benchCommitmentStatement(b)

	proof, err := ProveCommitmentEquality(&value, &r, &s, &pk, &H, &ct, &commitment,
		NewTranscript("bench"), rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !VerifyCommitmentEquality(&proof, &pk, &H, &ct, &commitment, NewTranscript("bench")) {
			b.Fatal("verification failed")
		}
	}
}

// ---------------------------------------------------------------------------
// PopProof — proof of possession, verified once per RegisterKey.
// ---------------------------------------------------------------------------

func BenchmarkPossessionProve(b *testing.B) {
	sk, pk, err := KeyGen(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ProvePossession(&sk, &pk, nil, rand.Reader); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPossessionVerify(b *testing.B) {
	sk, pk, err := KeyGen(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	proof, err := ProvePossession(&sk, &pk, NewTranscript("bench"), rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !VerifyPossession(&proof, &pk, NewTranscript("bench")) {
			b.Fatal("verification failed")
		}
	}
}
