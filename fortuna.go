package fortuna

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync"
	"time"
)

const (
	// NumPools is the number of entropy pools (must be 32)
	NumPools = 32

	// MinPoolSize is minimum bytes in pool 0 before reseed
	MinPoolSize = 64

	// MinReseedInterval is minimum time between reseeds (100ms)
	MinReseedInterval = 100 * time.Millisecond

	// MaxBytesPerRequest is max bytes to generate before automatic reseed
	MaxBytesPerRequest = 1 << 20 // 1 MB

	// KeySize for AES-256
	KeySize = 32

	// BlockSize for AES
	BlockSize = 16
)

// Generator produces random output using AES-256 in counter mode
type Generator struct {
	key     [KeySize]byte
	counter [BlockSize]byte
	cipher  cipher.Block
}

// NewGenerator creates a new generator with zero key
func NewGenerator() *Generator {
	g := &Generator{}
	g.Reseed(make([]byte, KeySize))
	return g
}

// Reseed updates the generator's key
func (g *Generator) Reseed(seed []byte) error {
	if len(seed) == 0 {
		return errors.New("seed must not be empty")
	}

	// Hash current key concatenated with seed
	h := sha256.New()
	h.Write(g.key[:])
	h.Write(seed)
	copy(g.key[:], h.Sum(nil))

	// Increment counter to prevent backtracking
	g.incrementCounter()

	// Create new cipher
	var err error
	g.cipher, err = aes.NewCipher(g.key[:])
	return err
}

// GenerateBlocks generates n blocks of random data
func (g *Generator) GenerateBlocks(n int) []byte {
	if n <= 0 {
		return nil
	}

	output := make([]byte, n*BlockSize)

	for i := 0; i < n; i++ {
		// Encrypt counter to produce random block
		g.cipher.Encrypt(output[i*BlockSize:], g.counter[:])
		g.incrementCounter()
	}

	return output
}

// GenerateRandomData generates exactly n bytes of random data
func (g *Generator) GenerateRandomData(n int) []byte {
	if n <= 0 {
		return nil
	}

	// Calculate number of blocks needed
	blocks := (n + BlockSize - 1) / BlockSize
	data := g.GenerateBlocks(blocks)

	// Generate new key to prevent backtracking
	newKey := g.GenerateBlocks(KeySize / BlockSize)
	copy(g.key[:], newKey)
	var err error
	g.cipher, err = aes.NewCipher(g.key[:])
	if err != nil {
		panic(err) // Should never happen with valid key size
	}

	return data[:n]
}

// incrementCounter increments the 128-bit counter
func (g *Generator) incrementCounter() {
	for i := 0; i < BlockSize; i++ {
		g.counter[i]++
		if g.counter[i] != 0 {
			break
		}
	}
}

// Pool is an entropy pool that accumulates entropy
type Pool struct {
	data []byte
}

// NewPool creates a new entropy pool
func NewPool() *Pool {
	return &Pool{
		data: make([]byte, 0, 1024),
	}
}

// Add adds entropy data to the pool
func (p *Pool) Add(data []byte) {
	p.data = append(p.data, data...)
}

// Digest returns the SHA-256 digest of all accumulated entropy
func (p *Pool) Digest() []byte {
	h := sha256.New()
	h.Write(p.data)
	return h.Sum(nil)
}

// Reset clears the pool
func (p *Pool) Reset() {
	p.data = p.data[:0]
}

// Len returns the number of bytes in the pool
func (p *Pool) Len() int {
	return len(p.data)
}

// Fortuna is the main PRNG
type Fortuna struct {
	mu              sync.Mutex
	generator       *Generator
	pools           [NumPools]*Pool
	reseedCount     uint64
	lastReseedTime  time.Time
	initialized     bool
}

// New creates a new Fortuna PRNG
func New() *Fortuna {
	f := &Fortuna{
		generator: NewGenerator(),
	}

	for i := 0; i < NumPools; i++ {
		f.pools[i] = NewPool()
	}

	return f
}

// AddRandomEvent adds entropy to the accumulator
// source: identifies the entropy source (0-255)
// poolID: which pool to add to (0-31)
// data: entropy data
func (f *Fortuna) AddRandomEvent(source byte, poolID int, data []byte) error {
	if poolID < 0 || poolID >= NumPools {
		return errors.New("invalid pool ID")
	}

	if len(data) > 32 {
		return errors.New("event data too long (max 32 bytes)")
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	// Add: source || length || data
	event := make([]byte, 0, len(data)+2)
	event = append(event, source)
	event = append(event, byte(len(data)))
	event = append(event, data...)

	f.pools[poolID].Add(event)

	return nil
}

// AddEntropy is a convenience function to add entropy distributed across pools
func (f *Fortuna) AddEntropy(data []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Distribute across pools in round-robin fashion
	chunkSize := 32
	poolIdx := 0

	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}

		chunk := data[i:end]
		f.pools[poolIdx%NumPools].Add(chunk)
		poolIdx++
	}
}

// reseed reseeds the generator from the pools
func (f *Fortuna) reseed() {
	now := time.Now()

	// Check minimum reseed interval
	if now.Sub(f.lastReseedTime) < MinReseedInterval {
		return
	}

	// Check minimum pool size
	if f.pools[0].Len() < MinPoolSize {
		return
	}

	f.reseedCount++
	f.lastReseedTime = now

	// Collect seed from pools
	// Pool i is included if 2^i divides reseedCount
	seed := make([]byte, 0, NumPools*sha256.Size)

	for i := 0; i < NumPools; i++ {
		// Check if pool i should be included
		// Pool 0 is always included
		// Pool i is included if reseedCount % 2^i == 0
		if i == 0 || (f.reseedCount%(1<<uint(i))) == 0 {
			seed = append(seed, f.pools[i].Digest()...)
			f.pools[i].Reset()
		}
	}

	f.generator.Reseed(seed)
	f.initialized = true
}

// RandomData generates n bytes of random data
func (f *Fortuna) RandomData(n int) ([]byte, error) {
	if n <= 0 {
		return nil, errors.New("invalid length")
	}

	if n > MaxBytesPerRequest {
		return nil, errors.New("request too large")
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	// Try to reseed
	f.reseed()

	if !f.initialized {
		return nil, errors.New("PRNG not seeded")
	}

	return f.generator.GenerateRandomData(n), nil
}

// Read implements io.Reader interface
func (f *Fortuna) Read(p []byte) (n int, err error) {
	data, err := f.RandomData(len(p))
	if err != nil {
		return 0, err
	}
	return copy(p, data), nil
}

// Uint64 returns a random uint64
func (f *Fortuna) Uint64() (uint64, error) {
	b, err := f.RandomData(8)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(b), nil
}

// Uint32 returns a random uint32
func (f *Fortuna) Uint32() (uint32, error) {
	b, err := f.RandomData(4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b), nil
}

// Seed seeds the PRNG with initial entropy
func (f *Fortuna) Seed(seed []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if len(seed) < KeySize {
		// Expand seed if too short
		h := sha256.New()
		h.Write(seed)
		seed = h.Sum(nil)
	}

	// Add to pool 0 for immediate reseeding
	f.pools[0].Add(seed)
	f.reseed()
}
