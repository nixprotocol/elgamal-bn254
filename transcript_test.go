package elgamal

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/stretchr/testify/require"
)

func TestTranscriptDeterministic(t *testing.T) {
	// Same inputs must produce the same challenge.
	t1 := NewTranscript("test-domain")
	t1.AppendBytes("label1", []byte("hello"))
	c1 := t1.ChallengeScalar("challenge")

	t2 := NewTranscript("test-domain")
	t2.AppendBytes("label1", []byte("hello"))
	c2 := t2.ChallengeScalar("challenge")

	require.True(t, c1.Equal(&c2), "same inputs must produce same challenge")
}

func TestTranscriptDifferentDomains(t *testing.T) {
	t1 := NewTranscript("domain-A")
	t1.AppendBytes("label", []byte("data"))
	c1 := t1.ChallengeScalar("challenge")

	t2 := NewTranscript("domain-B")
	t2.AppendBytes("label", []byte("data"))
	c2 := t2.ChallengeScalar("challenge")

	require.False(t, c1.Equal(&c2), "different domains must produce different challenges")
}

func TestTranscriptOrderMatters(t *testing.T) {
	var s1, s2 fr.Element
	s1.SetUint64(42)
	s2.SetUint64(137)

	t1 := NewTranscript("order-test")
	t1.AppendScalar("a", &s1)
	t1.AppendScalar("b", &s2)
	c1 := t1.ChallengeScalar("challenge")

	t2 := NewTranscript("order-test")
	t2.AppendScalar("b", &s2)
	t2.AppendScalar("a", &s1)
	c2 := t2.ChallengeScalar("challenge")

	require.False(t, c1.Equal(&c2), "different order must produce different challenges")
}
