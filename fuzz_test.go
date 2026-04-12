package elgamal

import (
	"crypto/rand"
	"testing"
)

// FuzzDLEQProofUnmarshal feeds arbitrary bytes to DLEQProof.Unmarshal to catch
// panics on untrusted input. The unmarshal may return an error for any input
// of the wrong length, non-canonical scalars, or off-curve points — but it
// must NEVER panic.
func FuzzDLEQProofUnmarshal(f *testing.F) {
	// Seed with a valid proof.
	sk, pk, err := KeyGen(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	ct, _, err := Encrypt(100, &pk, rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	proof, err := ProveDLEQ(&sk, &pk, &ct, 100, nil, nil)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(proof.Marshal())
	f.Add(make([]byte, DLEQProofSize))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		var p DLEQProof
		_ = p.Unmarshal(data)
	})
}

func FuzzEqualityProofUnmarshal(f *testing.F) {
	_, pk1, err := KeyGen(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	_, pk2, err := KeyGen(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	_, pk3, err := KeyGen(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	ct1, r1, err := Encrypt(7, &pk1, rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	ct2, r2, err := Encrypt(7, &pk2, rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	ct3, r3, err := Encrypt(7, &pk3, rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	proof, err := ProveEquality(7, &r1, &r2, &r3, &pk1, &pk2, &pk3, &ct1, &ct2, &ct3, nil, nil)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(proof.Marshal())
	f.Add(make([]byte, EqualityProofSize))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		var p EqualityProof
		_ = p.Unmarshal(data)
	})
}

func FuzzEquality2ProofUnmarshal(f *testing.F) {
	_, pk1, err := KeyGen(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	_, pk2, err := KeyGen(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	ct1, r1, err := Encrypt(9, &pk1, rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	ct2, r2, err := Encrypt(9, &pk2, rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	proof, err := ProveEquality2(9, &r1, &r2, &pk1, &pk2, &ct1, &ct2, nil, nil)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(proof.Marshal())
	f.Add(make([]byte, Equality2ProofSize))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		var p Equality2Proof
		_ = p.Unmarshal(data)
	})
}

func FuzzApplyPendingProofUnmarshal(f *testing.F) {
	sk, pk, err := KeyGen(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	pending, _, err := Encrypt(11, &pk, rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	newCt, rNew, err := Encrypt(11, &pk, rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	proof, err := ProveApplyPending(&sk, &pk, &pending, &newCt, 11, &rNew, nil, nil)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(proof.Marshal())
	f.Add(make([]byte, ApplyPendingProofSize))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		var p ApplyPendingProof
		_ = p.Unmarshal(data)
	})
}

func FuzzCiphertextUnmarshal(f *testing.F) {
	_, pk, err := KeyGen(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	ct, _, err := Encrypt(42, &pk, rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	data := ct.Marshal()
	f.Add(data)
	f.Add(make([]byte, CiphertextSize))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		var c Ciphertext
		_ = c.Unmarshal(data)
	})
}

func FuzzDecryptMemo(f *testing.F) {
	sk, pk, err := KeyGen(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	enc, err := EncryptMemo([]byte("hello"), &pk)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(enc)
	f.Add(make([]byte, MemoOverhead+MemoTagSize+1))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DecryptMemo(data, &sk)
	})
}
