package elgamal

import (
	cryptorand "crypto/rand"
	"errors"
	"io"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// randomScalar samples a scalar uniformly from [0, q) using the provided
// reader. If rng is nil, it falls back to crypto/rand. Uses rejection sampling
// via crypto/rand.Int so arbitrary io.Readers (seeded for KAT, HSM-backed,
// etc.) produce uniform scalars.
func randomScalar(rng io.Reader) (fr.Element, error) {
	var e fr.Element
	if rng == nil {
		rng = cryptorand.Reader
	}
	n, err := cryptorand.Int(rng, fr.Modulus())
	if err != nil {
		return fr.Element{}, err
	}
	e.SetBigInt(n)
	return e, nil
}

// G is the BN254 G1 generator, initialized in init().
var G bn254.G1Affine

func init() {
	_, _, g1, _ := bn254.Generators()
	G = g1
}

// KeyGen generates an ElGamal key pair using randomness from rng.
// Passing nil uses crypto/rand.Reader. Any io.Reader with uniform bytes works
// (e.g., a deterministic seed for test-vector generation).
// Returns (secret key, public key = sk*G, error).
func KeyGen(rng io.Reader) (fr.Element, bn254.G1Affine, error) {
	sk, err := randomScalar(rng)
	if err != nil {
		return fr.Element{}, bn254.G1Affine{}, err
	}

	var pk bn254.G1Affine
	skBig := sk.BigInt(new(big.Int))
	pk.ScalarMultiplication(&G, skBig)

	return sk, pk, nil
}

// Encrypt encrypts an amount under the given public key using randomness
// drawn from rng (pass nil for crypto/rand.Reader).
// Returns (ciphertext, randomness r, error).
// C1 = r*G, C2 = amount*G + r*pk.
func Encrypt(amount uint64, pk *bn254.G1Affine, rng io.Reader) (Ciphertext, fr.Element, error) {
	if err := ValidatePublicKey(pk); err != nil {
		return Ciphertext{}, fr.Element{}, err
	}

	r, err := randomScalar(rng)
	if err != nil {
		return Ciphertext{}, fr.Element{}, err
	}

	return EncryptWithRandomness(amount, pk, &r)
}

// EncryptWithRandomness encrypts an amount under the given public key with
// the provided randomness r. This is the deterministic variant.
// C1 = r*G, C2 = amount*G + r*pk.
func EncryptWithRandomness(amount uint64, pk *bn254.G1Affine, r *fr.Element) (Ciphertext, fr.Element, error) {
	if err := ValidatePublicKey(pk); err != nil {
		return Ciphertext{}, fr.Element{}, err
	}
	if r == nil {
		return Ciphertext{}, fr.Element{}, errors.New("randomness r is nil")
	}

	rBig := r.BigInt(new(big.Int))

	// C1 = r * G
	var c1 bn254.G1Affine
	c1.ScalarMultiplication(&G, rBig)

	// amount * G
	var amountG bn254.G1Affine
	amountG.ScalarMultiplication(&G, new(big.Int).SetUint64(amount))

	// r * pk
	var rPk bn254.G1Affine
	rPk.ScalarMultiplication(pk, rBig)

	// C2 = amount*G + r*pk
	var c2 bn254.G1Affine
	var c2Jac bn254.G1Jac
	var amountGJac, rPkJac bn254.G1Jac
	amountGJac.FromAffine(&amountG)
	rPkJac.FromAffine(&rPk)
	c2Jac.Set(&amountGJac)
	c2Jac.AddAssign(&rPkJac)
	c2.FromJacobian(&c2Jac)

	ct := Ciphertext{C1: c1, C2: c2}
	return ct, *r, nil
}

// Decrypt decrypts a ciphertext using the secret key and a discrete-log solver.
// Computes m*G = C2 - sk*C1, then solves the discrete log via the provided Decryptor.
// Both *DecryptionTable and *SplitDecryptionTable implement the Decryptor interface.
func Decrypt(ct *Ciphertext, sk *fr.Element, table Decryptor) (uint64, error) {
	if ct == nil {
		return 0, errors.New("ciphertext is nil")
	}
	if sk == nil {
		return 0, errors.New("secret key is nil")
	}
	if table == nil {
		return 0, errors.New("decryption table is nil")
	}

	skBig := sk.BigInt(new(big.Int))

	// sk * C1
	var skC1 bn254.G1Affine
	skC1.ScalarMultiplication(&ct.C1, skBig)

	// m*G = C2 - sk*C1
	var negSkC1 bn254.G1Affine
	negSkC1.Neg(&skC1)

	var mG bn254.G1Affine
	var mGJac bn254.G1Jac
	var c2Jac, negSkC1Jac bn254.G1Jac
	c2Jac.FromAffine(&ct.C2)
	negSkC1Jac.FromAffine(&negSkC1)
	mGJac.Set(&c2Jac)
	mGJac.AddAssign(&negSkC1Jac)
	mG.FromJacobian(&mGJac)

	return table.DiscreteLog(&mG)
}

// Add homomorphically adds two ciphertexts.
// Result: (C1_a + C1_b, C2_a + C2_b).
// Panics if either argument is nil (programming error — the function
// signature has no error return, matching the nil-check policy of Decrypt).
func Add(a, b *Ciphertext) Ciphertext {
	if a == nil || b == nil {
		panic("elgamal: Add called with nil ciphertext")
	}
	var c1, c2 bn254.G1Affine
	var c1Jac, c2Jac bn254.G1Jac
	var aJac, bJac bn254.G1Jac

	aJac.FromAffine(&a.C1)
	bJac.FromAffine(&b.C1)
	c1Jac.Set(&aJac)
	c1Jac.AddAssign(&bJac)
	c1.FromJacobian(&c1Jac)

	aJac.FromAffine(&a.C2)
	bJac.FromAffine(&b.C2)
	c2Jac.Set(&aJac)
	c2Jac.AddAssign(&bJac)
	c2.FromJacobian(&c2Jac)

	return Ciphertext{C1: c1, C2: c2}
}

// Sub homomorphically subtracts ciphertext b from a.
// Result: (C1_a - C1_b, C2_a - C2_b).
// Panics if either argument is nil.
func Sub(a, b *Ciphertext) Ciphertext {
	if a == nil || b == nil {
		panic("elgamal: Sub called with nil ciphertext")
	}
	var negB Ciphertext
	negB.C1.Neg(&b.C1)
	negB.C2.Neg(&b.C2)
	return Add(a, &negB)
}
