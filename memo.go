package elgamal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"golang.org/x/crypto/hkdf"
)

// memoKDFDomain is the HKDF info-prefix and AAD domain tag for memo
// encryption. Bumping this version string deliberately invalidates older
// ciphertexts.
const memoKDFDomain = "elgamal-bn254-memo-v1"

// deriveMemoKey derives a 32-byte AES-256 key from the ECDH shared secret via
// HKDF-SHA256. The info parameter binds the key to (domain || ephemeralPk ||
// recipientPk), so a key cannot be reused across a different (eph, recipient)
// tuple even if the raw shared secret coincided.
func deriveMemoKey(shared, ephemeralPk, recipientPk *bn254.G1Affine) ([]byte, error) {
	sharedBytes := shared.Marshal()
	info := make([]byte, 0, len(memoKDFDomain)+2*64)
	info = append(info, []byte(memoKDFDomain)...)
	info = append(info, ephemeralPk.Marshal()...)
	info = append(info, recipientPk.Marshal()...)

	h := hkdf.New(sha256.New, sharedBytes, nil /*salt*/, info)
	key := make([]byte, 32)
	if _, err := io.ReadFull(h, key); err != nil {
		return nil, err
	}
	return key, nil
}

// memoAAD is the GCM additional-authenticated-data binding for a memo. It
// authenticates the ephemeral and recipient public keys so that swapping
// either one tampers the ciphertext.
func memoAAD(ephemeralPk, recipientPk *bn254.G1Affine) []byte {
	aad := make([]byte, 0, len(memoKDFDomain)+2*64)
	aad = append(aad, []byte(memoKDFDomain)...)
	aad = append(aad, ephemeralPk.Marshal()...)
	aad = append(aad, recipientPk.Marshal()...)
	return aad
}

const (
	MemoEphemeralKeySize = 64                                   // uncompressed G1 point
	MemoNonceSize        = 12                                   // AES-GCM nonce
	MemoTagSize          = 16                                   // AES-GCM auth tag (included in ciphertext)
	MemoOverhead         = MemoEphemeralKeySize + MemoNonceSize // 76 bytes overhead before ciphertext
	MaxMemoSize          = 1024                                 // max plaintext memo size
)

// EncryptMemo encrypts arbitrary bytes to a recipient's ElGamal public key.
// Uses ECDH to derive a shared secret, then AES-256-GCM for authenticated encryption.
//
// Output layout: ephemeral_pubkey (64 bytes) || nonce (12 bytes) || aes_ciphertext (len(message) + 16 tag)
//
// The recipient decrypts with their ElGamal private key.
// The auditor can also decrypt if a separate copy is encrypted to the auditor's key.
func EncryptMemo(message []byte, recipientPk *bn254.G1Affine) ([]byte, error) {
	if err := ValidatePublicKey(recipientPk); err != nil {
		return nil, fmt.Errorf("recipient public key: %w", err)
	}
	if len(message) > MaxMemoSize {
		return nil, fmt.Errorf("memo exceeds max size %d bytes", MaxMemoSize)
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

	// Derive AES-256 key via HKDF-SHA256 bound to (domain, ephemeralPk, recipientPk).
	aesKey, err := deriveMemoKey(&shared, &ephemeralPk, recipientPk)
	if err != nil {
		return nil, fmt.Errorf("hkdf: %w", err)
	}

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

	aad := memoAAD(&ephemeralPk, recipientPk)
	aesCiphertext := gcm.Seal(nil, nonce, message, aad)

	// Output: ephemeralPk (64) || nonce (12) || aesCiphertext (len + 16 tag)
	result := make([]byte, 0, MemoOverhead+len(aesCiphertext))
	result = append(result, ephemeralPk.Marshal()...)
	result = append(result, nonce...)
	result = append(result, aesCiphertext...)

	return result, nil
}

// DecryptMemo decrypts an encrypted memo using the recipient's ElGamal private key.
func DecryptMemo(encrypted []byte, sk *fr.Element) ([]byte, error) {
	// Minimum: 64 (ephemeral pk) + 12 (nonce) + 16 (tag) = 92 bytes for an
	// empty-plaintext memo; longer memos grow from there.
	if len(encrypted) < MemoOverhead+MemoTagSize {
		return nil, fmt.Errorf("encrypted memo too short: %d bytes", len(encrypted))
	}
	// Mirror EncryptMemo's MaxMemoSize cap on the decrypt side so a hostile
	// input can't force the library to allocate / GCM-process an arbitrarily
	// large buffer before the tag check fails.
	if len(encrypted) > MemoOverhead+MemoTagSize+MaxMemoSize {
		return nil, fmt.Errorf("encrypted memo too large: %d bytes (max %d)", len(encrypted), MemoOverhead+MemoTagSize+MaxMemoSize)
	}

	// Parse ephemeral public key
	var ephemeralPk bn254.G1Affine
	if err := ephemeralPk.Unmarshal(encrypted[:MemoEphemeralKeySize]); err != nil {
		return nil, fmt.Errorf("ephemeral key: %w", err)
	}
	// Reject identity / off-curve. An attacker can pass 64 zero bytes as the
	// ephemeral key, making the shared secret O and the derived AES key
	// publicly computable — allowing injection of attacker-chosen plaintext.
	if err := ValidatePublicKey(&ephemeralPk); err != nil {
		return nil, fmt.Errorf("ephemeral key: %w", err)
	}

	// Parse nonce
	nonce := encrypted[MemoEphemeralKeySize : MemoEphemeralKeySize+MemoNonceSize]

	// Parse AES ciphertext
	aesCiphertext := encrypted[MemoOverhead:]

	// Recipient's own public key: pk = sk*G. Needed as HKDF info and as AAD
	// so the construction matches the sender's. This also catches sk = 0 /
	// other degenerate keys — the derived pk would be identity and fail validation.
	skBig := sk.BigInt(new(big.Int))
	var recipientPk bn254.G1Affine
	recipientPk.ScalarMultiplication(&G, skBig)
	if err := ValidatePublicKey(&recipientPk); err != nil {
		return nil, fmt.Errorf("recipient key derived from sk: %w", err)
	}

	// Shared secret: S = sk * ephemeralPk
	var shared bn254.G1Affine
	shared.ScalarMultiplication(&ephemeralPk, skBig)

	// Derive AES key via HKDF bound to (domain, ephemeralPk, recipientPk).
	aesKey, err := deriveMemoKey(&shared, &ephemeralPk, &recipientPk)
	if err != nil {
		return nil, fmt.Errorf("hkdf: %w", err)
	}

	// Decrypt
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}

	aad := memoAAD(&ephemeralPk, &recipientPk)
	plaintext, err := gcm.Open(nil, nonce, aesCiphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}
