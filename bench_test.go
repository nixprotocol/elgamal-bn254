package elgamal

import (
	"crypto/rand"
	"testing"
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
		_, err := ProveDLEQ(&sk, &pk, &ct, amount)
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

	proof, err := ProveDLEQ(&sk, &pk, &ct, amount)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !VerifyDLEQ(&proof, &pk, &ct, amount) {
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
		_, err := ProveEquality(amount, &r1, &r2, &r3, &pk1, &pk2, &pk3, &ct1, &ct2, &ct3)
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

	proof, err := ProveEquality(amount, &r1, &r2, &r3, &pk1, &pk2, &pk3, &ct1, &ct2, &ct3)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !VerifyEquality(&proof, &pk1, &pk2, &pk3, &ct1, &ct2, &ct3) {
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
		_, err := ProveApplyPending(&sk, &pk, &pending, &newCt, amount, &rNew)
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

	proof, err := ProveApplyPending(&sk, &pk, &pending, &newCt, amount, &rNew)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !VerifyApplyPending(&proof, &pk, &pending, &newCt) {
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
