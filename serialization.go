package elgamal

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

const (
	// DLEQProofSize is the byte size of a serialized DLEQProof.
	// 1 scalar (32 bytes) + 2 G1 points (64 bytes each) = 160 bytes.
	DLEQProofSize = 32 + 2*64 // 160

	// EqualityProofSize is the byte size of a serialized EqualityProof.
	// 4 scalars (32 bytes each) + 6 G1 points (64 bytes each) = 512 bytes.
	EqualityProofSize = 4*32 + 6*64 // 512

	// Equality2ProofSize is the byte size of a serialized Equality2Proof.
	// 3 scalars (32 bytes each) + 4 G1 points (64 bytes each) = 352 bytes.
	Equality2ProofSize = 3*32 + 4*64 // 352

	// ApplyPendingProofSize is the byte size of a serialized ApplyPendingProof.
	// 3 scalars (32 bytes each) + 4 G1 points (64 bytes each) = 352 bytes.
	ApplyPendingProofSize = 3*32 + 4*64 // 352
)

// marshalScalar writes a scalar into buf at the given offset and returns the new offset.
func marshalScalar(buf []byte, offset int, s *fr.Element) int {
	b := s.Bytes()
	copy(buf[offset:], b[:])
	return offset + 32
}

// marshalPoint writes a G1 point into buf at the given offset and returns the new offset.
func marshalPoint(buf []byte, offset int, p *bn254.G1Affine) int {
	copy(buf[offset:], p.Marshal())
	return offset + 64
}

// unmarshalScalar reads a canonical 32-byte big-endian scalar from data at the
// given offset. The scalar must be strictly less than the fr modulus; values
// in [q, 2^256) are rejected with an error to prevent proof-byte malleability.
func unmarshalScalar(data []byte, offset int, s *fr.Element) (int, error) {
	if err := s.SetBytesCanonical(data[offset : offset+32]); err != nil {
		return offset, err
	}
	return offset + 32, nil
}

// unmarshalPoint reads a G1 point from data at the given offset and returns the new offset and any error.
func unmarshalPoint(data []byte, offset int, p *bn254.G1Affine) (int, error) {
	if err := p.Unmarshal(data[offset : offset+64]); err != nil {
		return offset, err
	}
	return offset + 64, nil
}

// ---------- DLEQProof ----------

// Marshal serializes the DLEQProof as S(32) || R1(64) || R2(64).
func (p *DLEQProof) Marshal() []byte {
	buf := make([]byte, DLEQProofSize)
	off := 0
	off = marshalScalar(buf, off, &p.S)
	off = marshalPoint(buf, off, &p.R1)
	marshalPoint(buf, off, &p.R2)
	return buf
}

// Unmarshal deserializes a DLEQProof from bytes.
func (p *DLEQProof) Unmarshal(data []byte) error {
	if len(data) != DLEQProofSize {
		return fmt.Errorf("invalid DLEQProof length: expected %d bytes, got %d", DLEQProofSize, len(data))
	}
	off := 0
	var err error
	off, err = unmarshalScalar(data, off, &p.S)
	if err != nil {
		return fmt.Errorf("failed to unmarshal S: %w", err)
	}

	off, err = unmarshalPoint(data, off, &p.R1)
	if err != nil {
		return fmt.Errorf("failed to unmarshal R1: %w", err)
	}
	_, err = unmarshalPoint(data, off, &p.R2)
	if err != nil {
		return fmt.Errorf("failed to unmarshal R2: %w", err)
	}
	return nil
}

// ---------- EqualityProof ----------

// Marshal serializes the EqualityProof as
// Sm(32) || Sr1(32) || Sr2(32) || Sr3(32) || R11(64) || R21(64) || R12(64) || R22(64) || R13(64) || R23(64).
func (p *EqualityProof) Marshal() []byte {
	buf := make([]byte, EqualityProofSize)
	off := 0
	off = marshalScalar(buf, off, &p.Sm)
	off = marshalScalar(buf, off, &p.Sr1)
	off = marshalScalar(buf, off, &p.Sr2)
	off = marshalScalar(buf, off, &p.Sr3)
	off = marshalPoint(buf, off, &p.R11)
	off = marshalPoint(buf, off, &p.R21)
	off = marshalPoint(buf, off, &p.R12)
	off = marshalPoint(buf, off, &p.R22)
	off = marshalPoint(buf, off, &p.R13)
	marshalPoint(buf, off, &p.R23)
	return buf
}

// Unmarshal deserializes an EqualityProof from bytes.
func (p *EqualityProof) Unmarshal(data []byte) error {
	if len(data) != EqualityProofSize {
		return fmt.Errorf("invalid EqualityProof length: expected %d bytes, got %d", EqualityProofSize, len(data))
	}
	off := 0
	var err error
	scalars := []*fr.Element{&p.Sm, &p.Sr1, &p.Sr2, &p.Sr3}
	scalarNames := []string{"Sm", "Sr1", "Sr2", "Sr3"}
	for i, s := range scalars {
		off, err = unmarshalScalar(data, off, s)
		if err != nil {
			return fmt.Errorf("failed to unmarshal %s: %w", scalarNames[i], err)
		}
	}

	points := []*bn254.G1Affine{&p.R11, &p.R21, &p.R12, &p.R22, &p.R13, &p.R23}
	names := []string{"R11", "R21", "R12", "R22", "R13", "R23"}
	for i, pt := range points {
		off, err = unmarshalPoint(data, off, pt)
		if err != nil {
			return fmt.Errorf("failed to unmarshal %s: %w", names[i], err)
		}
	}
	return nil
}

// ---------- Equality2Proof ----------

// Marshal serializes the Equality2Proof as
// Sm(32) || Sr1(32) || Sr2(32) || R11(64) || R21(64) || R12(64) || R22(64).
func (p *Equality2Proof) Marshal() []byte {
	buf := make([]byte, Equality2ProofSize)
	off := 0
	off = marshalScalar(buf, off, &p.Sm)
	off = marshalScalar(buf, off, &p.Sr1)
	off = marshalScalar(buf, off, &p.Sr2)
	off = marshalPoint(buf, off, &p.R11)
	off = marshalPoint(buf, off, &p.R21)
	off = marshalPoint(buf, off, &p.R12)
	marshalPoint(buf, off, &p.R22)
	return buf
}

// Unmarshal deserializes an Equality2Proof from bytes.
func (p *Equality2Proof) Unmarshal(data []byte) error {
	if len(data) != Equality2ProofSize {
		return fmt.Errorf("invalid Equality2Proof length: expected %d bytes, got %d", Equality2ProofSize, len(data))
	}
	off := 0
	var err error
	scalars := []*fr.Element{&p.Sm, &p.Sr1, &p.Sr2}
	scalarNames := []string{"Sm", "Sr1", "Sr2"}
	for i, s := range scalars {
		off, err = unmarshalScalar(data, off, s)
		if err != nil {
			return fmt.Errorf("failed to unmarshal %s: %w", scalarNames[i], err)
		}
	}

	points := []*bn254.G1Affine{&p.R11, &p.R21, &p.R12, &p.R22}
	names := []string{"R11", "R21", "R12", "R22"}
	for i, pt := range points {
		off, err = unmarshalPoint(data, off, pt)
		if err != nil {
			return fmt.Errorf("failed to unmarshal %s: %w", names[i], err)
		}
	}
	return nil
}

// ---------- ApplyPendingProof ----------

// Marshal serializes the ApplyPendingProof as
// Sm(32) || Ssk(32) || Srn(32) || R1(64) || R2(64) || R3(64) || R4(64).
func (p *ApplyPendingProof) Marshal() []byte {
	buf := make([]byte, ApplyPendingProofSize)
	off := 0
	off = marshalScalar(buf, off, &p.Sm)
	off = marshalScalar(buf, off, &p.Ssk)
	off = marshalScalar(buf, off, &p.Srn)
	off = marshalPoint(buf, off, &p.R1)
	off = marshalPoint(buf, off, &p.R2)
	off = marshalPoint(buf, off, &p.R3)
	marshalPoint(buf, off, &p.R4)
	return buf
}

// Unmarshal deserializes an ApplyPendingProof from bytes.
func (p *ApplyPendingProof) Unmarshal(data []byte) error {
	if len(data) != ApplyPendingProofSize {
		return fmt.Errorf("invalid ApplyPendingProof length: expected %d bytes, got %d", ApplyPendingProofSize, len(data))
	}
	off := 0
	var err error
	scalars := []*fr.Element{&p.Sm, &p.Ssk, &p.Srn}
	scalarNames := []string{"Sm", "Ssk", "Srn"}
	for i, s := range scalars {
		off, err = unmarshalScalar(data, off, s)
		if err != nil {
			return fmt.Errorf("failed to unmarshal %s: %w", scalarNames[i], err)
		}
	}

	points := []*bn254.G1Affine{&p.R1, &p.R2, &p.R3, &p.R4}
	names := []string{"R1", "R2", "R3", "R4"}
	for i, pt := range points {
		off, err = unmarshalPoint(data, off, pt)
		if err != nil {
			return fmt.Errorf("failed to unmarshal %s: %w", names[i], err)
		}
	}
	return nil
}

// ---------- Public Key helpers ----------

// MarshalPublicKey serializes a public key as an uncompressed G1 point (64 bytes).
func MarshalPublicKey(pk *bn254.G1Affine) []byte {
	return pk.Marshal()
}

// UnmarshalPublicKey deserializes and validates a public key from bytes.
func UnmarshalPublicKey(data []byte) (bn254.G1Affine, error) {
	var pk bn254.G1Affine
	if len(data) != PublicKeySize {
		return pk, fmt.Errorf("public key must be %d bytes, got %d", PublicKeySize, len(data))
	}
	if err := pk.Unmarshal(data); err != nil {
		return pk, err
	}
	if err := ValidatePublicKey(&pk); err != nil {
		return pk, err
	}
	return pk, nil
}
