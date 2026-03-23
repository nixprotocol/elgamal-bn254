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
func NewTranscript(domain string) *Transcript {
	t := &Transcript{}
	t.state = append(t.state, []byte(domain)...)
	return t
}

// AppendBytes appends labelled data to the transcript.
// Format: label || 4-byte little-endian length || data.
func (t *Transcript) AppendBytes(label string, data []byte) {
	t.state = append(t.state, []byte(label)...)
	var lenBuf [4]byte
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

// ChallengeScalar produces a challenge scalar by hashing the current transcript state.
// It appends the label, hashes the state with Keccak256, and interprets the result
// as an fr.Element.
func (t *Transcript) ChallengeScalar(label string) fr.Element {
	t.state = append(t.state, []byte(label)...)

	h := sha3.NewLegacyKeccak256()
	h.Write(t.state)
	hash := h.Sum(nil)

	var challenge fr.Element
	challenge.SetBytes(hash)

	return challenge
}
