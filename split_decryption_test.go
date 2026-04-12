package elgamal

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/stretchr/testify/require"
)

func TestSplitDecrypt_Zero(t *testing.T) {
	// splitBits=4, hiHalfBits=4 → covers 2^12, fast table
	table := NewSplitDecryptionTable(4, 4)
	sk, pk, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	ct, _, err := Encrypt(0, &pk, rand.Reader)
	require.NoError(t, err)

	decrypted, err := Decrypt(&ct, &sk, table)
	require.NoError(t, err)
	require.Equal(t, uint64(0), decrypted)
}

func TestSplitDecrypt_SmallValues(t *testing.T) {
	// splitBits=4, hiHalfBits=5 → covers 2^14 = 16384
	// Worst case: 16 * 32 = 512 iterations per lo candidate. Fast.
	table := NewSplitDecryptionTable(4, 5)
	sk, pk, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	amounts := []uint64{1, 15, 16, 17, 42, 255, 256, 1000, 10000}
	for _, amount := range amounts {
		ct, _, err := Encrypt(amount, &pk, rand.Reader)
		require.NoError(t, err)

		decrypted, err := Decrypt(&ct, &sk, table)
		require.NoError(t, err, "failed for amount %d", amount)
		require.Equal(t, amount, decrypted, "mismatch for amount %d", amount)
	}
}

func TestSplitDecrypt_BoundaryValues(t *testing.T) {
	// splitBits=8, hiHalfBits=8 → covers 2^24 = 16M
	// Worst case: 256 * 256 = 65536 iterations.
	table := NewSplitDecryptionTable(8, 8)
	sk, pk, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	// hi=0, lo=max (255)
	testDecryptAmount(t, table, &sk, &pk, 255)

	// hi=1, lo=0 (exact split boundary)
	testDecryptAmount(t, table, &sk, &pk, 256)

	// hi=1, lo=1
	testDecryptAmount(t, table, &sk, &pk, 257)

	// hi=max at baby boundary
	testDecryptAmount(t, table, &sk, &pk, 255*256+255)

	// Near max of range: hi = 2^16 - 1 = 65535, lo = 255
	testDecryptAmount(t, table, &sk, &pk, 65535*256+255)
}

func TestSplitDecrypt_MediumValue(t *testing.T) {
	// splitBits=8, hiHalfBits=10 → covers 2^28 = 268M
	// Worst case: 256 * 1024 = 262144 iterations. ~0.5s.
	table := NewSplitDecryptionTable(8, 10)
	sk, pk, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	// 100 million — about 2^26.5
	testDecryptAmount(t, table, &sk, &pk, 100_000_000)
}

func TestSplitDecrypt_LargeValue(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping large value test in short mode")
	}
	// splitBits=8, hiHalfBits=12 → covers 2^32 = 4B
	// Worst case: 256 * 4096 = ~1M iterations. ~1s.
	table := NewSplitDecryptionTable(8, 12)
	sk, pk, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	// Value > 2^30 (impossible with standard halfBits=15 table)
	amount := uint64(3_000_000_000) // 3 billion, about 2^31.5
	testDecryptAmount(t, table, &sk, &pk, amount)
}

func TestSplitDecrypt_Beyond40Bit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping >40-bit test in short mode")
	}
	// splitBits=8, hiHalfBits=17 → covers 2^8 * 2^34 = 2^42 ≈ 4.4 trillion
	// Worst case: 256 * 2^17 = 2^25 ≈ 33M iterations.
	table := NewSplitDecryptionTable(8, 17)
	sk, pk, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	// 1.5 trillion ≈ 2^40.4. Impossible with standard DecryptionTable(20) which covers 2^40.
	testDecryptAmount(t, table, &sk, &pk, 1_500_000_000_000)

	// Also test a value with nonzero lo part: 1_500_000_000_099 (lo=99 mod 256 = 99)
	testDecryptAmount(t, table, &sk, &pk, 1_500_000_000_099)
}

func TestSplitDecrypt_MaxUSDC(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping USDC test in short mode")
	}
	// $100M USDC (6 decimals) = 100_000_000_000_000 ≈ 2^46.5
	// splitBits=8, hiHalfBits=20 → covers 2^48
	// Worst case: 256 * 2^20 = 2^28 ≈ 268M iterations. ~30s.
	// But for this specific value, hi = 100_000_000_000_000 / 256 ≈ 390_625_000_000
	// which is about 2^38.5. BSGS with halfBits=20 covers 2^40, so hi is in range.
	// The actual BSGS iteration for the correct lo: ~2^20 giant steps worst case.
	// With 256 lo candidates failing first: 256 * 2^20 = 2^28 ≈ 268M. ~30s.
	// Let's use splitBits=4 to reduce lo iterations: 16 * 2^22 = 2^26 ≈ 67M. ~8s.
	table := NewSplitDecryptionTable(4, 22)
	sk, pk, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	amount := uint64(100_000_000_000_000) // $100M USDC
	testDecryptAmount(t, table, &sk, &pk, amount)
}

func TestSplitDecrypt_DiscreteLogDirect(t *testing.T) {
	// Test DiscreteLog directly on m*G (without encryption/decryption).
	table := NewSplitDecryptionTable(4, 5)

	amounts := []uint64{0, 1, 15, 16, 17, 255, 1000}
	for _, amount := range amounts {
		var mG bn254.G1Affine
		mG.ScalarMultiplication(&G, new(big.Int).SetUint64(amount))

		result, err := table.DiscreteLog(&mG)
		require.NoError(t, err, "failed for amount %d", amount)
		require.Equal(t, amount, result, "mismatch for amount %d", amount)
	}
}

func TestSplitDecrypt_OutOfRange(t *testing.T) {
	// splitBits=2, hiHalfBits=2 → covers 2^2 * 2^4 = 64
	table := NewSplitDecryptionTable(2, 2)

	// 64 is out of range (max = 63).
	var mG bn254.G1Affine
	mG.ScalarMultiplication(&G, new(big.Int).SetUint64(64))

	_, err := table.DiscreteLog(&mG)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not found")
}

func TestSplitDecrypt_DecryptorInterface(t *testing.T) {
	// Verify that both DecryptionTable and SplitDecryptionTable satisfy Decryptor.
	var _ Decryptor = (*DecryptionTable)(nil)
	var _ Decryptor = (*SplitDecryptionTable)(nil)

	// And that Decrypt works with both.
	sk, pk, err := KeyGen(rand.Reader)
	require.NoError(t, err)

	amount := uint64(42)
	ct, _, err := Encrypt(amount, &pk, rand.Reader)
	require.NoError(t, err)

	// Standard table
	stdTable := NewDecryptionTable(10)
	dec1, err := Decrypt(&ct, &sk, stdTable)
	require.NoError(t, err)
	require.Equal(t, amount, dec1)

	// Split table
	splitTable := NewSplitDecryptionTable(4, 5)
	dec2, err := Decrypt(&ct, &sk, splitTable)
	require.NoError(t, err)
	require.Equal(t, amount, dec2)
}

func TestNewSplitDecryptionTable_PanicSplitBitsTooLarge(t *testing.T) {
	require.Panics(t, func() {
		NewSplitDecryptionTable(33, 16)
	})
}

// TestNewSplitDecryptionTable_PanicHiHalfBitsTooLarge pins bounds checking on
// hiHalfBits, which previously flowed unchecked into NewDecryptionTableWithBase
// and could silently overflow (`1 << hiHalfBits == 0` for hiHalfBits >= 64)
// or OOM (pre-sizing a multi-GB map for hiHalfBits >= 32).
func TestNewSplitDecryptionTable_PanicHiHalfBitsTooLarge(t *testing.T) {
	require.Panics(t, func() { NewSplitDecryptionTable(8, 64) }, "hiHalfBits=64 must panic")
	require.Panics(t, func() { NewSplitDecryptionTable(8, 40) }, "hiHalfBits=40 must panic (OOM)")
}

func BenchmarkSplitDecrypt_8_4_8(b *testing.B) {
	// splitBits=8, covers up to 2^24 with fast lookup
	table := NewSplitDecryptionTable(8, 8)
	sk, pk, err := KeyGen(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	amount := uint64(1_000_000)
	ct, _, err := Encrypt(amount, &pk, rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Decrypt(&ct, &sk, table)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSplitDecryptionTableInit_8_4_8(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NewSplitDecryptionTable(8, 8)
	}
}

// testDecryptAmount is a helper that encrypts and decrypts an amount,
// asserting that the decrypted value matches.
func testDecryptAmount(t *testing.T, table Decryptor, sk *fr.Element, pk *bn254.G1Affine, amount uint64) {
	t.Helper()
	ct, _, err := Encrypt(amount, pk, rand.Reader)
	require.NoError(t, err)

	decrypted, err := Decrypt(&ct, sk, table)
	require.NoError(t, err, "failed for amount %d", amount)
	require.Equal(t, amount, decrypted, "mismatch for amount %d", amount)
}
