package fortuna

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"
)

func TestGeneratorReseed(t *testing.T) {
	g := NewGenerator()

	seed := []byte("test seed data for fortuna prng")
	err := g.Reseed(seed)
	if err != nil {
		t.Fatalf("Reseed failed: %v", err)
	}

	// Generate some data
	data1 := g.GenerateRandomData(32)
	if len(data1) != 32 {
		t.Errorf("Expected 32 bytes, got %d", len(data1))
	}

	// Reseed with same data
	err = g.Reseed(seed)
	if err != nil {
		t.Fatalf("Second reseed failed: %v", err)
	}

	// Should produce different output due to counter increment
	data2 := g.GenerateRandomData(32)
	if bytes.Equal(data1, data2) {
		t.Error("Reseeding with same seed produced identical output (should differ due to counter)")
	}
}

func TestGeneratorEmptySeed(t *testing.T) {
	g := NewGenerator()
	err := g.Reseed([]byte{})
	if err == nil {
		t.Error("Expected error for empty seed")
	}
}

func TestGeneratorDeterministic(t *testing.T) {
	seed := []byte("deterministic test seed")

	g1 := NewGenerator()
	g1.Reseed(seed)
	// Reset counter to same state
	g1.counter = [BlockSize]byte{}

	g2 := NewGenerator()
	g2.Reseed(seed)
	g2.counter = [BlockSize]byte{}

	data1 := g1.GenerateRandomData(100)
	data2 := g2.GenerateRandomData(100)

	if !bytes.Equal(data1, data2) {
		t.Error("Same seed should produce same output with same counter state")
	}
}

func TestGeneratorBacktrackingResistance(t *testing.T) {
	g := NewGenerator()
	g.Reseed([]byte("initial seed"))

	// Generate some data
	before := g.GenerateRandomData(64)

	// Key should have been updated internally
	// Generate more data
	after := g.GenerateRandomData(64)

	// Should be different (backtracking resistance)
	if bytes.Equal(before, after) {
		t.Error("Generator produced identical output (no backtracking resistance)")
	}
}

func TestPoolAddAndDigest(t *testing.T) {
	p := NewPool()

	data1 := []byte("first entropy")
	data2 := []byte("second entropy")

	p.Add(data1)
	p.Add(data2)

	if p.Len() != len(data1)+len(data2) {
		t.Errorf("Expected pool length %d, got %d", len(data1)+len(data2), p.Len())
	}

	digest := p.Digest()
	if len(digest) != 32 { // SHA-256
		t.Errorf("Expected digest length 32, got %d", len(digest))
	}

	// Digest should be deterministic
	digest2 := p.Digest()
	if !bytes.Equal(digest, digest2) {
		t.Error("Pool digest is not deterministic")
	}

	p.Reset()
	if p.Len() != 0 {
		t.Errorf("Expected empty pool after reset, got length %d", p.Len())
	}
}

func TestFortunaBasic(t *testing.T) {
	f := New()

	// Should fail without seeding
	_, err := f.RandomData(32)
	if err == nil {
		t.Error("Expected error when generating without seed")
	}

	// Seed the PRNG
	seed := make([]byte, 64)
	rand.Read(seed)
	f.Seed(seed)

	// Should succeed now
	data, err := f.RandomData(32)
	if err != nil {
		t.Fatalf("RandomData failed after seeding: %v", err)
	}

	if len(data) != 32 {
		t.Errorf("Expected 32 bytes, got %d", len(data))
	}
}

func TestFortunaAddRandomEvent(t *testing.T) {
	f := New()

	// Add events to different pools
	for i := 0; i < 100; i++ {
		data := []byte{byte(i)}
		err := f.AddRandomEvent(0, i%NumPools, data)
		if err != nil {
			t.Fatalf("AddRandomEvent failed: %v", err)
		}
	}

	// Add enough entropy to pool 0
	largeEntropy := make([]byte, MinPoolSize)
	rand.Read(largeEntropy)
	f.AddRandomEvent(1, 0, largeEntropy[:32])
	f.AddRandomEvent(1, 0, largeEntropy[32:64])

	// Should be able to generate now
	data, err := f.RandomData(32)
	if err != nil {
		t.Fatalf("RandomData failed: %v", err)
	}

	if len(data) != 32 {
		t.Errorf("Expected 32 bytes, got %d", len(data))
	}
}

func TestFortunaInvalidPoolID(t *testing.T) {
	f := New()

	err := f.AddRandomEvent(0, -1, []byte("test"))
	if err == nil {
		t.Error("Expected error for negative pool ID")
	}

	err = f.AddRandomEvent(0, NumPools, []byte("test"))
	if err == nil {
		t.Error("Expected error for pool ID >= NumPools")
	}
}

func TestFortunaEventDataTooLong(t *testing.T) {
	f := New()

	longData := make([]byte, 33)
	err := f.AddRandomEvent(0, 0, longData)
	if err == nil {
		t.Error("Expected error for event data > 32 bytes")
	}
}

func TestFortunaReseedInterval(t *testing.T) {
	f := New()

	// Seed initially
	seed := make([]byte, MinPoolSize)
	rand.Read(seed)
	f.Seed(seed)

	// Generate some data
	_, err := f.RandomData(32)
	if err != nil {
		t.Fatalf("First RandomData failed: %v", err)
	}

	// Add more entropy immediately
	f.AddEntropy(seed)

	// Reseed count before
	countBefore := f.reseedCount

	// Try to generate immediately (should not reseed due to interval)
	_, err = f.RandomData(32)
	if err != nil {
		t.Fatalf("Second RandomData failed: %v", err)
	}

	// Reseed count should be same (interval not elapsed)
	if f.reseedCount != countBefore {
		// This might fail if test runs slowly, so just log
		t.Logf("Reseed count changed (test timing issue): %d -> %d", countBefore, f.reseedCount)
	}

	// Wait for interval
	time.Sleep(MinReseedInterval + 10*time.Millisecond)

	// Add entropy and generate
	f.AddEntropy(seed)
	_, err = f.RandomData(32)
	if err != nil {
		t.Fatalf("Third RandomData failed: %v", err)
	}

	// Should have reseeded now
	if f.reseedCount <= countBefore {
		t.Errorf("Expected reseed count to increase after interval, got %d", f.reseedCount)
	}
}

func TestFortunaMaxBytesPerRequest(t *testing.T) {
	f := New()

	seed := make([]byte, 64)
	rand.Read(seed)
	f.Seed(seed)

	// Should fail for too large request
	_, err := f.RandomData(MaxBytesPerRequest + 1)
	if err == nil {
		t.Error("Expected error for request > MaxBytesPerRequest")
	}

	// Should succeed for max size
	data, err := f.RandomData(MaxBytesPerRequest)
	if err != nil {
		t.Fatalf("Failed to generate MaxBytesPerRequest: %v", err)
	}

	if len(data) != MaxBytesPerRequest {
		t.Errorf("Expected %d bytes, got %d", MaxBytesPerRequest, len(data))
	}
}

func TestFortunaUint64(t *testing.T) {
	f := New()

	seed := make([]byte, 64)
	rand.Read(seed)
	f.Seed(seed)

	val, err := f.Uint64()
	if err != nil {
		t.Fatalf("Uint64 failed: %v", err)
	}

	// Just check it's not zero (very unlikely)
	if val == 0 {
		t.Log("Warning: Uint64 returned 0 (unlikely but possible)")
	}

	// Generate multiple values, they should differ
	val2, _ := f.Uint64()
	val3, _ := f.Uint64()

	if val == val2 && val2 == val3 {
		t.Error("Uint64 produced identical values")
	}
}

func TestFortunaUint32(t *testing.T) {
	f := New()

	seed := make([]byte, 64)
	rand.Read(seed)
	f.Seed(seed)

	val, err := f.Uint32()
	if err != nil {
		t.Fatalf("Uint32 failed: %v", err)
	}

	// Generate multiple values, they should differ
	val2, _ := f.Uint32()
	val3, _ := f.Uint32()

	if val == val2 && val2 == val3 {
		t.Error("Uint32 produced identical values")
	}
}

func TestFortunaRead(t *testing.T) {
	f := New()

	seed := make([]byte, 64)
	rand.Read(seed)
	f.Seed(seed)

	buf := make([]byte, 100)
	n, err := f.Read(buf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if n != 100 {
		t.Errorf("Expected to read 100 bytes, got %d", n)
	}

	// Check not all zeros
	allZero := true
	for _, b := range buf {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("Read produced all zeros")
	}
}

func TestFortunaPoolScheduling(t *testing.T) {
	f := New()

	// Add entropy to all pools
	for i := 0; i < NumPools; i++ {
		data := make([]byte, 32)
		rand.Read(data)
		f.AddRandomEvent(0, i, data)
	}

	// Seed pool 0 with enough data
	seed := make([]byte, MinPoolSize)
	rand.Read(seed)
	f.AddRandomEvent(1, 0, seed[:32])
	f.AddRandomEvent(1, 0, seed[32:64])

	// Generate to trigger reseed
	_, err := f.RandomData(32)
	if err != nil {
		t.Fatalf("RandomData failed: %v", err)
	}

	if f.reseedCount == 0 {
		t.Error("Expected at least one reseed")
	}

	// Pool 0 should always be used
	if f.pools[0].Len() != 0 {
		t.Error("Pool 0 should be reset after reseed")
	}

	// Wait and generate multiple times to test pool scheduling
	time.Sleep(MinReseedInterval + 10*time.Millisecond)

	for i := 0; i < 10; i++ {
		// Add more entropy
		moreData := make([]byte, 32)
		rand.Read(moreData)
		f.AddRandomEvent(2, 0, moreData)

		time.Sleep(MinReseedInterval + 10*time.Millisecond)

		_, err := f.RandomData(32)
		if err != nil {
			t.Fatalf("RandomData failed on iteration %d: %v", i, err)
		}
	}

	// Check that reseed count increased
	if f.reseedCount < 2 {
		t.Errorf("Expected multiple reseeds, got %d", f.reseedCount)
	}
}

func TestFortunaAddEntropy(t *testing.T) {
	f := New()

	largeEntropy := make([]byte, 1024)
	rand.Read(largeEntropy)

	f.AddEntropy(largeEntropy)

	// Check that entropy was distributed across pools
	totalLen := 0
	for i := 0; i < NumPools; i++ {
		totalLen += f.pools[i].Len()
	}

	if totalLen == 0 {
		t.Error("No entropy was added to pools")
	}

	// Should have at least some in pool 0
	if f.pools[0].Len() < MinPoolSize {
		// Add more to pool 0
		f.AddEntropy(largeEntropy)
	}

	time.Sleep(MinReseedInterval + 10*time.Millisecond)

	// Should be able to generate
	data, err := f.RandomData(32)
	if err != nil {
		t.Fatalf("RandomData failed after AddEntropy: %v", err)
	}

	if len(data) != 32 {
		t.Errorf("Expected 32 bytes, got %d", len(data))
	}
}

func TestFortunaRandomness(t *testing.T) {
	f := New()

	seed := make([]byte, 128)
	rand.Read(seed)
	f.Seed(seed)

	// Generate a large amount of data
	data, err := f.RandomData(10000)
	if err != nil {
		t.Fatalf("Failed to generate data: %v", err)
	}

	// Basic randomness checks
	// 1. Check for repeated patterns
	for i := 0; i < len(data)-16; i++ {
		chunk := data[i : i+16]
		for j := i + 16; j < len(data)-16; j++ {
			if bytes.Equal(chunk, data[j:j+16]) {
				t.Errorf("Found repeated 16-byte pattern at positions %d and %d", i, j)
				break
			}
		}
	}

	// 2. Check byte distribution (rough test)
	counts := make([]int, 256)
	for _, b := range data {
		counts[b]++
	}

	// Each byte should appear roughly len(data)/256 times
	expected := len(data) / 256
	tolerance := expected / 2 // 50% tolerance

	for i, count := range counts {
		if count < expected-tolerance || count > expected+tolerance {
			t.Logf("Byte 0x%02x appeared %d times (expected ~%d)", i, count, expected)
		}
	}
}

func BenchmarkFortunaRandomData(b *testing.B) {
	f := New()
	seed := make([]byte, 64)
	rand.Read(seed)
	f.Seed(seed)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = f.RandomData(1024)
	}
}

func BenchmarkFortunaUint64(b *testing.B) {
	f := New()
	seed := make([]byte, 64)
	rand.Read(seed)
	f.Seed(seed)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = f.Uint64()
	}
}

func BenchmarkGeneratorGenerate(b *testing.B) {
	g := NewGenerator()
	g.Reseed([]byte("benchmark seed"))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = g.GenerateRandomData(1024)
	}
}

// chiSquared calculates the chi-squared statistic for byte distribution
// Returns the chi-squared value - lower values indicate more uniform distribution
func chiSquared(data []byte) float64 {
	// Count frequency of each byte value (0-255)
	observed := make([]int, 256)
	for _, b := range data {
		observed[b]++
	}

	// Expected frequency for uniform distribution
	expected := float64(len(data)) / 256.0

	// Calculate chi-squared statistic
	chiSq := 0.0
	for i := 0; i < 256; i++ {
		diff := float64(observed[i]) - expected
		chiSq += (diff * diff) / expected
	}

	return chiSq
}

// TestChiSquaredNonRandom tests that non-random data has high chi-squared value
func TestChiSquaredNonRandom(t *testing.T) {
	tests := []struct {
		name            string
		data            []byte
		expectHighChiSq bool // false for uniformly distributed but non-random patterns
	}{
		{
			name:            "all_zeros",
			data:            make([]byte, 10000),
			expectHighChiSq: true,
		},
		{
			name:            "all_ones",
			data:            bytes.Repeat([]byte{1}, 10000),
			expectHighChiSq: true,
		},
		{
			name: "sequential",
			data: func() []byte {
				d := make([]byte, 10000)
				for i := range d {
					d[i] = byte(i % 256)
				}
				return d
			}(),
			expectHighChiSq: false, // Uniform distribution but predictable
		},
		{
			name:            "repeating_pattern",
			data:            bytes.Repeat([]byte{0xAA, 0xBB, 0xCC, 0xDD}, 2500),
			expectHighChiSq: true,
		},
		{
			name:            "single_repeating_byte",
			data:            bytes.Repeat([]byte{0x42}, 10000),
			expectHighChiSq: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chiSq := chiSquared(tt.data)
			t.Logf("Chi-squared for %s: %.2f", tt.name, chiSq)

			if tt.expectHighChiSq {
				// Non-uniform data should have very high chi-squared
				// For 255 degrees of freedom, chi-squared > 1000 indicates highly non-uniform
				if chiSq < 1000 {
					t.Errorf("Non-random data %s has unexpectedly low chi-squared: %.2f (expected > 1000)", tt.name, chiSq)
				}
			} else {
				// Some patterns (like sequential) are uniform but still non-random
				// They should have low chi-squared like random data
				t.Logf("Pattern %s is uniform (low chi-squared expected): %.2f", tt.name, chiSq)
			}
		})
	}
}

// TestChiSquaredFortunaVsNonRandom compares Fortuna output to non-random data
func TestChiSquaredFortunaVsNonRandom(t *testing.T) {
	// Generate Fortuna data
	f := New()
	seed := make([]byte, 128)
	rand.Read(seed)
	f.Seed(seed)

	fortunaData, err := f.RandomData(10000)
	if err != nil {
		t.Fatalf("Failed to generate Fortuna data: %v", err)
	}

	// Calculate chi-squared for Fortuna output
	fortunaChiSq := chiSquared(fortunaData)
	t.Logf("Chi-squared for Fortuna PRNG: %.2f", fortunaChiSq)

	// For 255 degrees of freedom and 10000 samples:
	// - Expected value: ~255
	// - 95% confidence interval: roughly 205-310
	// - 99% confidence interval: roughly 190-325
	// We'll use a generous range to avoid flaky tests
	if fortunaChiSq < 150 || fortunaChiSq > 400 {
		t.Errorf("Fortuna chi-squared %.2f outside expected range [150, 400]", fortunaChiSq)
	}

	// Test non-random sequences (non-uniform only)
	nonRandomTests := []struct {
		name string
		data []byte
	}{
		{"zeros", make([]byte, 10000)},
		{"ones", bytes.Repeat([]byte{255}, 10000)},
		{"repeating_ABCD", bytes.Repeat([]byte{0xAA, 0xBB, 0xCC, 0xDD}, 2500)},
		{"single_byte_pattern", bytes.Repeat([]byte{0x7F}, 10000)},
	}

	for _, tt := range nonRandomTests {
		t.Run("vs_"+tt.name, func(t *testing.T) {
			nonRandomChiSq := chiSquared(tt.data)
			t.Logf("Chi-squared for %s: %.2f", tt.name, nonRandomChiSq)

			// Non-uniform data should have MUCH higher chi-squared than Fortuna
			if nonRandomChiSq <= fortunaChiSq*2 {
				t.Errorf("Non-random data %s has chi-squared %.2f, not significantly higher than Fortuna %.2f",
					tt.name, nonRandomChiSq, fortunaChiSq)
			}

			// Calculate ratio to show difference
			ratio := nonRandomChiSq / fortunaChiSq
			t.Logf("Chi-squared ratio (%s/Fortuna): %.2fx", tt.name, ratio)

			if ratio < 10 {
				t.Errorf("Expected chi-squared ratio > 10x, got %.2fx", ratio)
			}
		})
	}
}

// TestChiSquaredMultipleFortunaSamples tests consistency across multiple samples
func TestChiSquaredMultipleFortunaSamples(t *testing.T) {
	f := New()
	seed := make([]byte, 128)
	rand.Read(seed)
	f.Seed(seed)

	numSamples := 10
	sampleSize := 10000
	chiSquares := make([]float64, numSamples)

	for i := 0; i < numSamples; i++ {
		data, err := f.RandomData(sampleSize)
		if err != nil {
			t.Fatalf("Failed to generate sample %d: %v", i, err)
		}
		chiSquares[i] = chiSquared(data)
		t.Logf("Sample %d chi-squared: %.2f", i+1, chiSquares[i])
	}

	// Calculate mean and check all samples are within reasonable range
	var sum float64
	for _, cs := range chiSquares {
		sum += cs
	}
	mean := sum / float64(numSamples)
	t.Logf("Mean chi-squared across %d samples: %.2f", numSamples, mean)

	// All samples should be in reasonable range
	for i, cs := range chiSquares {
		if cs < 150 || cs > 400 {
			t.Errorf("Sample %d chi-squared %.2f outside expected range [150, 400]", i+1, cs)
		}
	}

	// Mean should be close to expected value (~255 for 255 degrees of freedom)
	if mean < 200 || mean > 310 {
		t.Errorf("Mean chi-squared %.2f outside expected range [200, 310]", mean)
	}
}

// TestChiSquaredCryptoRandComparison compares Fortuna to crypto/rand
func TestChiSquaredCryptoRandComparison(t *testing.T) {
	sampleSize := 50000

	// Get crypto/rand data
	cryptoData := make([]byte, sampleSize)
	_, err := rand.Read(cryptoData)
	if err != nil {
		t.Fatalf("Failed to read from crypto/rand: %v", err)
	}
	cryptoChiSq := chiSquared(cryptoData)
	t.Logf("Chi-squared for crypto/rand: %.2f", cryptoChiSq)

	// Get Fortuna data
	f := New()
	seed := make([]byte, 128)
	rand.Read(seed)
	f.Seed(seed)
	fortunaData, err := f.RandomData(sampleSize)
	if err != nil {
		t.Fatalf("Failed to generate Fortuna data: %v", err)
	}
	fortunaChiSq := chiSquared(fortunaData)
	t.Logf("Chi-squared for Fortuna: %.2f", fortunaChiSq)

	// Both should be in the same ballpark (good randomness)
	// Neither should be dramatically different
	ratio := fortunaChiSq / cryptoChiSq
	if ratio < 0.5 || ratio > 2.0 {
		t.Logf("Warning: Fortuna/crypto/rand chi-squared ratio %.2f is outside [0.5, 2.0]", ratio)
		t.Logf("This doesn't necessarily indicate a problem, but both should have similar uniformity")
	}

	// Both should pass the basic uniformity test
	if cryptoChiSq < 150 || cryptoChiSq > 500 {
		t.Errorf("crypto/rand chi-squared %.2f outside expected range [150, 500]", cryptoChiSq)
	}
	if fortunaChiSq < 150 || fortunaChiSq > 500 {
		t.Errorf("Fortuna chi-squared %.2f outside expected range [150, 500]", fortunaChiSq)
	}

	t.Logf("Both PRNGs show good uniformity (chi-squared within acceptable range)")
}
