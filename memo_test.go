package elgamal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
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

// TestDecryptMemo_OversizedRejected pins the symmetric size cap on the decrypt
// side. EncryptMemo caps input at MaxMemoSize, but DecryptMemo previously
// accepted arbitrarily large buffers — letting an attacker craft a huge
// "ciphertext" (no valid MAC) and force the library to allocate / process it
// before the GCM tag check fails. Mirror the cap on decrypt.
func TestDecryptMemo_OversizedRejected(t *testing.T) {
	sk, _, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	// Buffer larger than any legitimate memo. 2 MB is well past MaxMemoSize
	// (1 KB) + overhead + tag.
	oversized := make([]byte, 2*1024*1024)
	// Put something that at least has a valid-looking ephemeral pk, so we
	// don't short-circuit earlier than the size check.
	_, pk, _ := KeyGen(rand.Reader)
	copy(oversized, pk.Marshal())

	_, err = DecryptMemo(oversized, &sk)
	require.Error(t, err, "DecryptMemo must reject oversized input")
	require.Contains(t, err.Error(), "too large")
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
	sk, pk, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	// Empty memos are legitimate — AES-GCM handles zero-length plaintext and
	// still emits the 16-byte auth tag. Roundtrip must succeed.
	encrypted, err := EncryptMemo([]byte{}, &pk)
	require.NoError(t, err)

	decrypted, err := DecryptMemo(encrypted, &sk)
	require.NoError(t, err)
	require.Empty(t, decrypted)
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

// TestDecryptMemo_IdentityEphemeralKeyRejected demonstrates that an attacker
// can forge a memo whose ephemeralPk is the identity point (encoded as 64
// zero bytes). Without pubkey validation:
//   - shared secret = sk * O = O
//   - AES key = SHA256(O.Marshal()) — a fixed, publicly computable value
//   - Attacker encrypts chosen plaintext with that key and the recipient
//     successfully "decrypts" attacker-chosen bytes.
//
// With pubkey validation, DecryptMemo must reject this.
func TestDecryptMemo_IdentityEphemeralKeyRejected(t *testing.T) {
	sk, _, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	// Compute the AES key that DecryptMemo will derive: SHA256(O.Marshal()).
	var identity bn254.G1Affine
	sharedBytes := identity.Marshal()
	keyHash := sha256.Sum256(sharedBytes)
	aesKey := keyHash[:]

	// Attacker crafts a memo with attacker-chosen plaintext.
	attackerMessage := []byte("injected attacker memo")
	block, err := aes.NewCipher(aesKey)
	require.NoError(t, err)
	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)

	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	require.NoError(t, err)

	aesCt := gcm.Seal(nil, nonce, attackerMessage, nil)

	forged := make([]byte, 0, MemoOverhead+len(aesCt))
	forged = append(forged, make([]byte, MemoEphemeralKeySize)...) // 64 zero bytes = identity
	forged = append(forged, nonce...)
	forged = append(forged, aesCt...)

	// Without ValidatePublicKey, DecryptMemo would return attackerMessage.
	_, err = DecryptMemo(forged, &sk)
	require.Error(t, err, "DecryptMemo must reject identity ephemeral pubkey")
}

// TestDecryptMemo_OldFormatRejected encrypts a memo using the legacy
// construction (plain SHA-256 of the raw ECDH point, no AAD, no HKDF info) and
// asserts the new DecryptMemo rejects it. This pins the new KDF to HKDF with
// (domain || ephemeralPk || recipientPk) as info and AAD, guarding against an
// accidental revert to the weaker construction.
func TestDecryptMemo_OldFormatRejected(t *testing.T) {
	sk, pk, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	// Construct a memo using the OLD scheme inline:
	//   shared = r * pk
	//   key = SHA256(shared.Marshal())
	//   nonce = random(12)
	//   ct = AES-GCM.Seal(nil, nonce, msg, nil)  // nil AAD
	var r fr.Element
	_, err = r.SetRandom()
	require.NoError(t, err)
	rBig := r.BigInt(new(big.Int))
	var ephPk bn254.G1Affine
	ephPk.ScalarMultiplication(&G, rBig)
	var shared bn254.G1Affine
	shared.ScalarMultiplication(&pk, rBig)

	keyHash := sha256.Sum256(shared.Marshal())
	block, err := aes.NewCipher(keyHash[:])
	require.NoError(t, err)
	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)
	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	require.NoError(t, err)
	oldCt := gcm.Seal(nil, nonce, []byte("old-format memo"), nil)

	forged := make([]byte, 0, MemoOverhead+len(oldCt))
	forged = append(forged, ephPk.Marshal()...)
	forged = append(forged, nonce...)
	forged = append(forged, oldCt...)

	_, err = DecryptMemo(forged, &sk)
	require.Error(t, err, "memo encrypted with legacy KDF must not decrypt with new DecryptMemo")
}

// TestEncryptMemo_IdentityRecipientRejected ensures the sender-side path also
// refuses to encrypt to an invalid (identity) recipient. Otherwise the memo
// would be encrypted under a publicly-known key.
func TestEncryptMemo_IdentityRecipientRejected(t *testing.T) {
	var identity bn254.G1Affine
	_, err := EncryptMemo([]byte("hi"), &identity)
	require.Error(t, err, "EncryptMemo must reject identity recipient pubkey")
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
