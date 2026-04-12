package elgamal

import (
	"errors"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254"
)

const (
	// CiphertextSize is the byte size of a serialized Ciphertext (2 x 64-byte G1 points).
	CiphertextSize = 128

	// PublicKeySize is the byte size of a serialized public key (one G1 point).
	PublicKeySize = 64
)

// Ciphertext represents an ElGamal ciphertext consisting of two G1 points.
type Ciphertext struct {
	C1, C2 bn254.G1Affine
}

// Marshal serializes the ciphertext as C1 || C2 (128 bytes).
func (ct *Ciphertext) Marshal() []byte {
	out := make([]byte, 0, CiphertextSize)
	out = append(out, ct.C1.Marshal()...)
	out = append(out, ct.C2.Marshal()...)
	return out
}

// Unmarshal deserializes a ciphertext from bytes and validates its components.
func (ct *Ciphertext) Unmarshal(data []byte) error {
	if len(data) != CiphertextSize {
		return fmt.Errorf("invalid ciphertext length: expected %d bytes, got %d", CiphertextSize, len(data))
	}

	if err := ct.C1.Unmarshal(data[:64]); err != nil {
		return fmt.Errorf("failed to unmarshal C1: %w", err)
	}

	if err := ct.C2.Unmarshal(data[64:]); err != nil {
		return fmt.Errorf("failed to unmarshal C2: %w", err)
	}

	return ct.Validate()
}

// IsZero returns true if both C1 and C2 are the identity (point at infinity).
func (ct *Ciphertext) IsZero() bool {
	return ct.C1.IsInfinity() && ct.C2.IsInfinity()
}

// Validate checks that both ciphertext components are on the BN254 G1 curve
// and that C1 is not the identity point. This mirrors the checks performed
// by Ciphertext.Unmarshal, but is intended for callers that construct a
// Ciphertext struct directly (e.g., by reading pre-deserialized fields from
// a smart contract state) — they would otherwise bypass those checks.
//
// C1 = identity is rejected because it causes the DLEQ verification equation
// S*C1 == R2 + e*(C2 - m*G) to collapse to a vacuous identity whenever
// C2 = m*G, letting an attacker submit a publicly-readable "ciphertext" with
// a valid proof. C2 = identity is NOT rejected: it is a legitimate encoding
// of amount=0 with randomness=0 and has no impact on soundness.
func (ct *Ciphertext) Validate() error {
	if ct == nil {
		return errors.New("ciphertext is nil")
	}
	if !ct.C1.IsOnCurve() {
		return errors.New("C1 is not on the curve")
	}
	if !ct.C2.IsOnCurve() {
		return errors.New("C2 is not on the curve")
	}
	if ct.C1.IsInfinity() {
		return errors.New("C1 is the identity point")
	}
	return nil
}

// ValidatePublicKey checks that the given public key is on the BN254 G1 curve
// and is not the identity point. Since BN254 G1 has cofactor 1, on-curve plus
// non-identity is sufficient to guarantee the point is in the correct subgroup.
func ValidatePublicKey(pk *bn254.G1Affine) error {
	if pk == nil {
		return errors.New("public key is nil")
	}
	if !pk.IsOnCurve() {
		return errors.New("public key is not on the curve")
	}
	if pk.IsInfinity() {
		return errors.New("public key is the identity point")
	}
	return nil
}
