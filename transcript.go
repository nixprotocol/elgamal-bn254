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
