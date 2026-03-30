package elgamal

import (
	"crypto/rand"
	"fmt"
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

// Uses knownValueDecryptor from large_value_test.go to verify decryption
// correctness at large values without needing impractical BSGS tables.

// ---------------------------------------------------------------------------
// Auditor encrypt/decrypt: basic flow
// ---------------------------------------------------------------------------

func TestAuditorDecrypt_SmallValue(t *testing.T) {
	// Auditor can decrypt with a real BSGS table for small values.
	auditorSk, auditorPk, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	amount := uint64(1000)
	ct, _, err := Encrypt(amount, &auditorPk, rand.Reader)
	require.NoError(t, err)

	table := NewDecryptionTable(20)
	dec, err := Decrypt(&ct, &auditorSk, table)
	require.NoError(t, err)
	require.Equal(t, amount, dec)
}

// ---------------------------------------------------------------------------
// Auditor decrypt at large values (using known-value decryptor)
// ---------------------------------------------------------------------------

func TestAuditorDecrypt_LargeValues(t *testing.T) {
	auditorSk, auditorPk, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	values := []struct {
		name   string
		amount uint64
	}{
		{"2^32", 1 << 32},
		{"2^48", 1 << 48},
		{"2^63", 1 << 63},
		{"2^64-1", math.MaxUint64},
		{"2^64-2", math.MaxUint64 - 1},
		{"large_odd", 0xDEADBEEFCAFEBABE},
	}

	for _, tc := range values {
		t.Run(tc.name, func(t *testing.T) {
			ct, _, err := Encrypt(tc.amount, &auditorPk, rand.Reader)
			require.NoError(t, err)

			dec, err := Decrypt(&ct, &auditorSk, &knownValueDecryptor{expected: tc.amount})
			require.NoError(t, err)
			require.Equal(t, tc.amount, dec)
		})
	}
}

// ---------------------------------------------------------------------------
// Full confidential send pattern: auditor decrypts the auditor ciphertext
// while sender and receiver use their own keys.
// ---------------------------------------------------------------------------

func TestAuditorDecrypt_ConfidentialSendFlow(t *testing.T) {
	_, senderPk, err := KeyGen(rand.Reader)
	require.NoError(t, err)
	_, receiverPk, err := KeyGen(rand.Reader)
	require.NoError(t, err)
	auditorSk, auditorPk, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	amounts := []uint64{
		42,
		1_000_000,
		1 << 48,
		math.MaxUint64,
	}

	for _, amount := range amounts {
		t.Run(fmt.Sprintf("amount_%d", amount), func(t *testing.T) {
			// Sender encrypts under all three keys.
			senderCt, rSender, err := Encrypt(amount, &senderPk, rand.Reader)
			require.NoError(t, err)
			receiverCt, rReceiver, err := Encrypt(amount, &receiverPk, rand.Reader)
			require.NoError(t, err)
			auditorCt, rAuditor, err := Encrypt(amount, &auditorPk, rand.Reader)
			require.NoError(t, err)

			// Prove equality: all three encrypt the same amount.
			proof, err := ProveEquality(
				amount,
				&rSender, &rReceiver, &rAuditor,
				&senderPk, &receiverPk, &auditorPk,
				&senderCt, &receiverCt, &auditorCt,
				nil,
			)
			require.NoError(t, err)

			ok := VerifyEquality(&proof, &senderPk, &receiverPk, &auditorPk,
				&senderCt, &receiverCt, &auditorCt, nil)
			require.True(t, ok, "equality proof must verify")

			// Auditor decrypts the auditor ciphertext.
			dec, err := Decrypt(&auditorCt, &auditorSk, &knownValueDecryptor{expected: amount})
			require.NoError(t, err)
			require.Equal(t, amount, dec)
		})
	}
}

// ---------------------------------------------------------------------------
// Auditor decrypts multiple transfers and sums them (homomorphic audit trail)
// ---------------------------------------------------------------------------

func TestAuditorDecrypt_HomomorphicAuditTrail(t *testing.T) {
	auditorSk, auditorPk, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	// Simulate three confidential sends to the same receiver, auditor accumulates.
	amounts := []uint64{
		math.MaxUint64 / 3,
		math.MaxUint64 / 3,
		math.MaxUint64 / 3,
	}
	expectedTotal := amounts[0] + amounts[1] + amounts[2]

	var accumulated *Ciphertext
	for _, amount := range amounts {
		ct, _, err := Encrypt(amount, &auditorPk, rand.Reader)
		require.NoError(t, err)

		// Verify each individual ciphertext decrypts correctly.
		dec, err := Decrypt(&ct, &auditorSk, &knownValueDecryptor{expected: amount})
		require.NoError(t, err)
		require.Equal(t, amount, dec)

		if accumulated == nil {
			accumulated = &ct
		} else {
			sum := Add(accumulated, &ct)
			accumulated = &sum
		}
	}

	// The homomorphic sum should decrypt to the total.
	dec, err := Decrypt(accumulated, &auditorSk, &knownValueDecryptor{expected: expectedTotal})
	require.NoError(t, err)
	require.Equal(t, expectedTotal, dec)
}

// ---------------------------------------------------------------------------
// Auditor with SplitDecryptionTable for medium-large values
// ---------------------------------------------------------------------------

func TestAuditorDecrypt_SplitTable_MediumValues(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping split table test in short mode")
	}

	auditorSk, auditorPk, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	// splitBits=8, hiHalfBits=12 → covers 2^32
	table := NewSplitDecryptionTable(8, 4, 12)

	amounts := []uint64{
		1 << 24,          // 16M
		1 << 30,          // ~1B
		(1 << 32) - 1,    // max in range
	}

	for _, amount := range amounts {
		ct, _, err := Encrypt(amount, &auditorPk, rand.Reader)
		require.NoError(t, err)

		dec, err := Decrypt(&ct, &auditorSk, table)
		require.NoError(t, err, "failed for amount %d", amount)
		require.Equal(t, amount, dec, "mismatch for amount %d", amount)
	}
}

// ---------------------------------------------------------------------------
// Auditor decrypts with wrong key should fail
// ---------------------------------------------------------------------------

func TestAuditorDecrypt_WrongKey(t *testing.T) {
	_, auditorPk, err := KeyGen(rand.Reader)
	require.NoError(t, err)
	wrongSk, _, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	amount := uint64(42)
	ct, _, err := Encrypt(amount, &auditorPk, rand.Reader)
	require.NoError(t, err)

	// Decrypting with the wrong secret key produces a random point,
	// which won't match the expected value.
	_, err = Decrypt(&ct, &wrongSk, &knownValueDecryptor{expected: amount})
	require.Error(t, err, "wrong key should fail decryption")
}

// ---------------------------------------------------------------------------
// Auditor encrypted memo at large values
// ---------------------------------------------------------------------------

func TestAuditorMemo_EncryptDecrypt(t *testing.T) {
	auditorSk, auditorPk, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	// Memo describing a large transfer.
	memo := []byte(fmt.Sprintf("transfer amount: %d", uint64(math.MaxUint64)))

	encrypted, err := EncryptMemo(memo, &auditorPk)
	require.NoError(t, err)

	decrypted, err := DecryptMemo(encrypted, &auditorSk)
	require.NoError(t, err)
	require.Equal(t, memo, decrypted)
}

func TestAuditorMemo_WrongKey(t *testing.T) {
	_, auditorPk, err := KeyGen(rand.Reader)
	require.NoError(t, err)
	wrongSk, _, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	memo := []byte("secret transfer details")
	encrypted, err := EncryptMemo(memo, &auditorPk)
	require.NoError(t, err)

	_, err = DecryptMemo(encrypted, &wrongSk)
	require.Error(t, err, "wrong key should fail memo decryption")
}

// ---------------------------------------------------------------------------
// Auditor key rotation: old key decrypts old ciphertexts,
// new key decrypts new ciphertexts
// ---------------------------------------------------------------------------

func TestAuditorKeyRotation(t *testing.T) {
	oldSk, oldPk, err := KeyGen(rand.Reader)
	require.NoError(t, err)
	newSk, newPk, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	amount := uint64(math.MaxUint64)

	// Encrypted under old auditor key.
	oldCt, _, err := Encrypt(amount, &oldPk, rand.Reader)
	require.NoError(t, err)

	// Encrypted under new auditor key.
	newCt, _, err := Encrypt(amount, &newPk, rand.Reader)
	require.NoError(t, err)

	// Old key decrypts old ciphertext.
	dec, err := Decrypt(&oldCt, &oldSk, &knownValueDecryptor{expected: amount})
	require.NoError(t, err)
	require.Equal(t, amount, dec)

	// New key decrypts new ciphertext.
	dec, err = Decrypt(&newCt, &newSk, &knownValueDecryptor{expected: amount})
	require.NoError(t, err)
	require.Equal(t, amount, dec)

	// Old key cannot decrypt new ciphertext.
	_, err = Decrypt(&newCt, &oldSk, &knownValueDecryptor{expected: amount})
	require.Error(t, err, "old key should not decrypt new ciphertext")

	// New key cannot decrypt old ciphertext.
	_, err = Decrypt(&oldCt, &newSk, &knownValueDecryptor{expected: amount})
	require.Error(t, err, "new key should not decrypt old ciphertext")
}

// ---------------------------------------------------------------------------
// Auditor decrypts ciphertext from serialized bytes (round-trip)
// ---------------------------------------------------------------------------

func TestAuditorDecrypt_FromSerializedCiphertext(t *testing.T) {
	auditorSk, auditorPk, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	amount := uint64(math.MaxUint64)
	ct, _, err := Encrypt(amount, &auditorPk, rand.Reader)
	require.NoError(t, err)

	// Serialize (as stored on-chain in events).
	data, err := ct.Marshal()
	require.NoError(t, err)

	// Deserialize (as auditor would receive from chain events).
	var recovered Ciphertext
	err = recovered.Unmarshal(data)
	require.NoError(t, err)

	// Decrypt.
	dec, err := Decrypt(&recovered, &auditorSk, &knownValueDecryptor{expected: amount})
	require.NoError(t, err)
	require.Equal(t, amount, dec)
}
