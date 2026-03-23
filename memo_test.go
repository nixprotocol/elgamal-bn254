package elgamal

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEncryptDecryptMemo(t *testing.T) {
	sk, pk, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	message := []byte("Hello, Bob!")
	encrypted, err := EncryptMemo(message, &pk)
	require.NoError(t, err)
	require.NotNil(t, encrypted)

	// Encrypted output should be larger than original message by overhead + tag.
	require.Equal(t, MemoOverhead+len(message)+MemoTagSize, len(encrypted))

	decrypted, err := DecryptMemo(encrypted, &sk)
	require.NoError(t, err)
	require.Equal(t, message, decrypted)
}

func TestEncryptDecryptMemo_LargeMessage(t *testing.T) {
	sk, pk, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	message := make([]byte, 1000)
	_, err = rand.Read(message)
	require.NoError(t, err)

	encrypted, err := EncryptMemo(message, &pk)
	require.NoError(t, err)

	decrypted, err := DecryptMemo(encrypted, &sk)
	require.NoError(t, err)
	require.Equal(t, message, decrypted)
}

func TestEncryptMemo_MaxSize(t *testing.T) {
	sk, pk, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	// Exactly MaxMemoSize bytes should succeed.
	message := make([]byte, MaxMemoSize)
	_, err = rand.Read(message)
	require.NoError(t, err)

	encrypted, err := EncryptMemo(message, &pk)
	require.NoError(t, err)

	decrypted, err := DecryptMemo(encrypted, &sk)
	require.NoError(t, err)
	require.Equal(t, message, decrypted)
}

func TestEncryptMemo_TooLarge(t *testing.T) {
	_, pk, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	message := make([]byte, MaxMemoSize+1)
	_, err = rand.Read(message)
	require.NoError(t, err)

	_, err = EncryptMemo(message, &pk)
	require.Error(t, err)
	require.Contains(t, err.Error(), "memo exceeds max size")
}

func TestEncryptMemo_Empty(t *testing.T) {
	_, pk, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	_, err = EncryptMemo([]byte{}, &pk)
	require.Error(t, err)
	require.Contains(t, err.Error(), "memo cannot be empty")
}

func TestDecryptMemo_WrongKey(t *testing.T) {
	_, pk, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	// Generate a different keypair.
	wrongSk, _, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	message := []byte("secret message")
	encrypted, err := EncryptMemo(message, &pk)
	require.NoError(t, err)

	// Decrypting with the wrong key should fail.
	_, err = DecryptMemo(encrypted, &wrongSk)
	require.Error(t, err)
	require.Contains(t, err.Error(), "decryption failed")
}

func TestDecryptMemo_TamperedCiphertext(t *testing.T) {
	sk, pk, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	message := []byte("authentic message")
	encrypted, err := EncryptMemo(message, &pk)
	require.NoError(t, err)

	// Tamper with the AES ciphertext portion (after overhead).
	tampered := make([]byte, len(encrypted))
	copy(tampered, encrypted)
	tampered[MemoOverhead+5] ^= 0xff

	_, err = DecryptMemo(tampered, &sk)
	require.Error(t, err)
	require.Contains(t, err.Error(), "decryption failed")
}

func TestEncryptMemo_DifferentRecipients(t *testing.T) {
	_, pk1, err := KeyGen(rand.Reader)
	require.NoError(t, err)
	_, pk2, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	message := []byte("same message")
	enc1, err := EncryptMemo(message, &pk1)
	require.NoError(t, err)
	enc2, err := EncryptMemo(message, &pk2)
	require.NoError(t, err)

	// Different recipients (and different ephemeral keys) should produce different ciphertexts.
	require.NotEqual(t, enc1, enc2)
}
