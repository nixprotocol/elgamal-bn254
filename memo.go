package elgamal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

const (
	MemoEphemeralKeySize = 64 // uncompressed G1 point
	MemoNonceSize        = 12 // AES-GCM nonce
	MemoTagSize          = 16 // AES-GCM auth tag (included in ciphertext)
	MemoOverhead         = MemoEphemeralKeySize + MemoNonceSize // 76 bytes overhead before ciphertext
	MaxMemoSize          = 1024 // max plaintext memo size
)

// EncryptMemo encrypts arbitrary bytes to a recipient's ElGamal public key.
// Uses ECDH to derive a shared secret, then AES-256-GCM for authenticated encryption.
//
// Output layout: ephemeral_pubkey (64 bytes) || nonce (12 bytes) || aes_ciphertext (len(message) + 16 tag)
//
// The recipient decrypts with their ElGamal private key.
// The auditor can also decrypt if a separate copy is encrypted to the auditor's key.
func EncryptMemo(message []byte, recipientPk *bn254.G1Affine) ([]byte, error) {
	if len(message) > MaxMemoSize {
		return nil, fmt.Errorf("memo exceeds max size %d bytes", MaxMemoSize)
	}
	if len(message) == 0 {
		return nil, fmt.Errorf("memo cannot be empty")
	}

	// Generate ephemeral keypair
	var r fr.Element
	if _, err := r.SetRandom(); err != nil {
		return nil, fmt.Errorf("random generation: %w", err)
	}
	rBig := r.BigInt(new(big.Int))

	// Ephemeral public key: R = r * G
	var ephemeralPk bn254.G1Affine
	ephemeralPk.ScalarMultiplication(&G, rBig)

	// Shared secret: S = r * recipientPk
	var shared bn254.G1Affine
	shared.ScalarMultiplication(recipientPk, rBig)

	// Derive AES-256 key from shared secret: key = SHA256(S.x || S.y)
	sharedBytes := shared.Marshal() // 64 bytes
	keyHash := sha256.Sum256(sharedBytes)
	aesKey := keyHash[:] // 32 bytes = AES-256

	// AES-256-GCM encrypt
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize()) // 12 bytes
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}

	aesCiphertext := gcm.Seal(nil, nonce, message, nil)

	// Output: ephemeralPk (64) || nonce (12) || aesCiphertext (len + 16 tag)
	result := make([]byte, 0, MemoOverhead+len(aesCiphertext))
	result = append(result, ephemeralPk.Marshal()...)
	result = append(result, nonce...)
	result = append(result, aesCiphertext...)

	return result, nil
}

// DecryptMemo decrypts an encrypted memo using the recipient's ElGamal private key.
func DecryptMemo(encrypted []byte, sk *fr.Element) ([]byte, error) {
	if len(encrypted) < MemoOverhead+MemoTagSize+1 {
		return nil, fmt.Errorf("encrypted memo too short: %d bytes", len(encrypted))
	}

	// Parse ephemeral public key
	var ephemeralPk bn254.G1Affine
	if err := ephemeralPk.Unmarshal(encrypted[:MemoEphemeralKeySize]); err != nil {
		return nil, fmt.Errorf("ephemeral key: %w", err)
	}

	// Parse nonce
	nonce := encrypted[MemoEphemeralKeySize : MemoEphemeralKeySize+MemoNonceSize]

	// Parse AES ciphertext
	aesCiphertext := encrypted[MemoOverhead:]

	// Shared secret: S = sk * ephemeralPk
	skBig := sk.BigInt(new(big.Int))
	var shared bn254.G1Affine
	shared.ScalarMultiplication(&ephemeralPk, skBig)

	// Derive AES key
	sharedBytes := shared.Marshal()
	keyHash := sha256.Sum256(sharedBytes)
	aesKey := keyHash[:]

	// Decrypt
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, aesCiphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}
