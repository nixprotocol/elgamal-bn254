package elgamal

import (
	"encoding/binary"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"golang.org/x/crypto/sha3"
)

// Transcript implements a Fiat-Shamir transcript for proof generation.
// It accumulates labels and data, then produces challenge scalars via Keccak256.
type Transcript struct {
	state []byte
}

// NewTranscript creates a new transcript with the given domain separator.
// The domain is length-prefixed just like AppendBytes data so the transcript
// encoding is unambiguous: no two distinct (domain, data-sequence) pairs can
// produce the same byte stream.
func NewTranscript(domain string) *Transcript {
	t := &Transcript{}
	var lenBuf [4]byte
	binary.LittleEndian.PutUint32(lenBuf[:], uint32(len(domain)))
	t.state = append(t.state, lenBuf[:]...)
	t.state = append(t.state, []byte(domain)...)
	return t
}

// AppendBytes appends labelled data to the transcript.
// Format: 4-byte LE label length || label || 4-byte LE data length || data.
// Both the label and data are length-prefixed so that no two distinct
// (label, data) sequences can produce the same byte concatenation.
func (t *Transcript) AppendBytes(label string, data []byte) {
	var lenBuf [4]byte
	binary.LittleEndian.PutUint32(lenBuf[:], uint32(len(label)))
	t.state = append(t.state, lenBuf[:]...)
	t.state = append(t.state, []byte(label)...)
	binary.LittleEndian.PutUint32(lenBuf[:], uint32(len(data)))
	t.state = append(t.state, lenBuf[:]...)
	t.state = append(t.state, data...)
}

// AppendPoint appends a G1 affine point to the transcript.
func (t *Transcript) AppendPoint(label string, p *bn254.G1Affine) {
	data := p.Marshal()
	t.AppendBytes(label, data)
}

// AppendScalar appends a field element to the transcript.
func (t *Transcript) AppendScalar(label string, s *fr.Element) {
	b := s.Bytes()
	t.AppendBytes(label, b[:])
}

// ChallengeScalar produces a challenge scalar by hashing the current transcript
// state (with the label length-prefixed and appended first), then folds the
// resulting hash back into the state so that any subsequent challenges drawn
// from the same transcript absorb this challenge as an input.
//
// Folding the challenge back into state is critical for multi-round proofs:
// without it, drawing two challenges from the same state with different
// labels produces correlated outputs that an adversary could exploit.
//
// Bias analysis.
//
// This function reduces a 256-bit Keccak256 output modulo the BN254 scalar
// modulus q ≈ 0.756·2^254. Because q does not evenly divide 2^256, the
// resulting distribution over [0, q) is not perfectly uniform:
//
//	k = floor(2^256 / q) = 5
//	r = 2^256 mod q ≈ 0.216·2^254
//
// So ~r residues in [0, r) are each hit 6 times by the 2^256 possible hash
// outputs, and the remaining ~(q − r) residues in [r, q) are each hit 5
// times. Uniform would be 2^256/q ≈ 5.29 hits per residue.
//
// The statistical distance from uniform is ≈ 3.85%, but that is not the
// quantity that matters for proof soundness. What matters is the cheating
// prover's best strategy: pre-guess the most likely challenge. Under
// uniform challenges, success probability is 1/q ≈ 2^(-253.98). Under this
// biased reduction, success probability is (6/2^256) ≈ 2^(-253.42). The
// soundness loss is therefore ~0.56 bits, reducing effective soundness
// from ~254 bits to ~253 bits — still far above the 128-bit security
// target (margin of ~125 bits).
//
// A standards-track alternative (RFC 9380 hash_to_field, Merlin) would
// sample 48 bytes instead of 32 and reduce, dropping the bias to ~2^(-130).
// That is intentionally not adopted here: the current construction is
// sound for any realistic threat model and changing it would break the
// transcript wire format without any security benefit. If a future
// cross-implementation interop requirement forces a change, this is the
// place to do it.
func (t *Transcript) ChallengeScalar(label string) fr.Element {
	// Length-prefix the challenge label for the same reason AppendBytes does.
	var lenBuf [4]byte
	binary.LittleEndian.PutUint32(lenBuf[:], uint32(len(label)))
	t.state = append(t.state, lenBuf[:]...)
	t.state = append(t.state, []byte(label)...)

	h := sha3.NewLegacyKeccak256()
	h.Write(t.state)
	hash := h.Sum(nil)

	// Fold the challenge output back into the transcript state.
	t.state = append(t.state, hash...)

	var challenge fr.Element
	challenge.SetBytes(hash)

	return challenge
}
