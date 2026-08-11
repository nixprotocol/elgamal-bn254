package elgamal

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// gnark stores the encoding format in the top two bits of the first byte:
// 0b00 uncompressed, 0b10 compressed-smallest, 0b11 compressed-largest,
// 0b01 compressed-infinity.
const (
	flagUncompressed       = 0b00 << 6
	flagCompressedSmallest = 0b10 << 6
	flagCompressedLargest  = 0b11 << 6
	flagCompressedInfinity = 0b01 << 6
)

// reencode returns a copy of a 64-byte uncompressed point slot rewritten with
// the given format flag, filling the (then ignored) Y half with garbage.
func reencode(slot []byte, flag byte) []byte {
	out := append([]byte(nil), slot...)
	out[0] = (out[0] &^ (0b11 << 6)) | flag
	for i := 32; i < 64; i++ {
		out[i] = 0xAB
	}
	return out
}

// TestPointEncodingMustBeUncompressed is the regression test for proof and
// ciphertext malleability.
//
// Every point here occupies a fixed 64-byte slot, but gnark reads the format
// from flag bits: a compressed encoding consumes only the 32-byte X coordinate
// and derives Y, silently ignoring the trailing 32 bytes. That gave one
// ciphertext or proof many valid byte representations — pick the flag matching
// Y's branch and the tail is free — and flipping to the other branch produced a
// DIFFERENT valid point from the same X.
//
// Scalars were already pinned via SetBytesCanonical; points were the remaining
// malleable input. Any consumer that dedups, replay-protects, or keys state by
// ciphertext or proof bytes depends on this.
func TestPointEncodingMustBeUncompressed(t *testing.T) {
	_, pk, err := KeyGen(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ct, _, err := Encrypt(42, &pk, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	canonical := ct.Marshal()

	// Canonical form still round-trips.
	var ok Ciphertext
	if err := ok.Unmarshal(canonical); err != nil {
		t.Fatalf("canonical encoding rejected: %v", err)
	}

	for name, flag := range map[string]byte{
		"compressed-smallest": flagCompressedSmallest,
		"compressed-largest":  flagCompressedLargest,
		"compressed-infinity": flagCompressedInfinity,
	} {
		mutated := append(reencode(canonical[:64], flag), canonical[64:]...)
		if bytes.Equal(mutated, canonical) {
			t.Fatalf("%s: test bug, bytes did not change", name)
		}
		var got Ciphertext
		if err := got.Unmarshal(mutated); err == nil {
			t.Fatalf("%s: non-canonical ciphertext encoding was accepted", name)
		}
	}
}

// TestPublicKeyEncodingMustBeUncompressed covers the registered-key path: a
// non-canonical encoding of the same key would otherwise be a second valid
// wire form for one account.
func TestPublicKeyEncodingMustBeUncompressed(t *testing.T) {
	_, pk, err := KeyGen(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw := MarshalPublicKey(&pk)

	if _, err := UnmarshalPublicKey(raw); err != nil {
		t.Fatalf("canonical public key rejected: %v", err)
	}
	for _, flag := range []byte{flagCompressedSmallest, flagCompressedLargest} {
		if _, err := UnmarshalPublicKey(reencode(raw, flag)); err == nil {
			t.Fatalf("non-canonical public key encoding (flag %02x) was accepted", flag)
		}
	}
}

// TestProofEncodingMustBeUncompressed covers a proof actually verified on the
// consensus path. A re-encoded DLEQ proof previously stayed byte-distinct yet
// still verified.
func TestProofEncodingMustBeUncompressed(t *testing.T) {
	sk, pk, err := KeyGen(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ct, _, err := Encrypt(7, &pk, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := ProveDLEQ(&sk, &pk, &ct, 7, NewTranscript("t"), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw := proof.Marshal()

	var round DLEQProof
	if err := round.Unmarshal(raw); err != nil {
		t.Fatalf("canonical proof rejected: %v", err)
	}

	// R1 sits directly after the 32-byte scalar S.
	mutated := append([]byte(nil), raw...)
	copy(mutated[32:96], reencode(raw[32:96], flagCompressedLargest))

	var tampered DLEQProof
	if err := tampered.Unmarshal(mutated); err == nil {
		t.Fatal("re-encoded DLEQ proof was accepted; proof bytes are malleable")
	}
}
