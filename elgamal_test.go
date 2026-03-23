package elgamal

import (
	"crypto/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/stretchr/testify/require"
)

func TestKeyGen(t *testing.T) {
	sk, pk, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	// sk must not be zero.
	var zero fr.Element
	require.False(t, sk.Equal(&zero), "secret key must not be zero")

	// pk must be a valid public key (on curve, not identity).
	err = ValidatePublicKey(&pk)
	require.NoError(t, err, "public key must be valid")
}

func TestEncryptDecrypt(t *testing.T) {
	sk, pk, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	amount := uint64(1000000)
	ct, _, err := Encrypt(amount, &pk, rand.Reader)
	require.NoError(t, err)

	table := NewDecryptionTable(20)
	decrypted, err := Decrypt(&ct, &sk, table)
	require.NoError(t, err)
	require.Equal(t, amount, decrypted, "decrypted amount must match original")
}

func TestEncryptDecryptZero(t *testing.T) {
	sk, pk, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	ct, _, err := Encrypt(0, &pk, rand.Reader)
	require.NoError(t, err)

	table := NewDecryptionTable(20)
	decrypted, err := Decrypt(&ct, &sk, table)
	require.NoError(t, err)
	require.Equal(t, uint64(0), decrypted, "decrypted amount must be 0")
}

func TestHomomorphicAdd(t *testing.T) {
	sk, pk, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	ct1, _, err := Encrypt(300, &pk, rand.Reader)
	require.NoError(t, err)

	ct2, _, err := Encrypt(700, &pk, rand.Reader)
	require.NoError(t, err)

	sum := Add(&ct1, &ct2)

	table := NewDecryptionTable(20)
	decrypted, err := Decrypt(&sum, &sk, table)
	require.NoError(t, err)
	require.Equal(t, uint64(1000), decrypted, "300 + 700 must equal 1000")
}

func TestHomomorphicSub(t *testing.T) {
	sk, pk, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	ct1, _, err := Encrypt(1000, &pk, rand.Reader)
	require.NoError(t, err)

	ct2, _, err := Encrypt(300, &pk, rand.Reader)
	require.NoError(t, err)

	diff := Sub(&ct1, &ct2)

	table := NewDecryptionTable(20)
	decrypted, err := Decrypt(&diff, &sk, table)
	require.NoError(t, err)
	require.Equal(t, uint64(700), decrypted, "1000 - 300 must equal 700")
}
