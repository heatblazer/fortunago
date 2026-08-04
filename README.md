# Fortuna PRNG

A pure Go implementation of the Fortuna cryptographically secure pseudo-random number generator (CSPRNG) designed by Bruce Schneier and Niels Ferguson.

**No external dependencies** - uses only Go standard library (`crypto/aes`, `crypto/sha256`).

## Features

- **Cryptographically secure**: Uses AES-256 in counter mode with SHA-256 hashing
- **Backtracking resistance**: Previous outputs cannot be computed even if current state is compromised
- **Pool-based entropy accumulation**: 32 entropy pools with exponential scheduling
- **Automatic reseeding**: Reseeds from accumulated entropy with configurable intervals
- **Thread-safe**: Safe for concurrent use
- **io.Reader compatible**: Can be used anywhere an io.Reader is expected

## Installation

```bash
go get fortuna
```

## Quick Start

```go
package main

import (
    "crypto/rand"
    "fmt"
    "fortuna"
)

func main() {
    // Create PRNG instance
    f := fortuna.New()

    // Seed with initial entropy (required)
    seed := make([]byte, 64)
    rand.Read(seed)
    f.Seed(seed)

    // Generate random bytes
    data, _ := f.RandomData(32)
    fmt.Printf("Random bytes: %x\n", data)

    // Generate random integers
    val, _ := f.Uint64()
    fmt.Printf("Random uint64: %d\n", val)
}
```

## API

### Creating a PRNG

```go
f := fortuna.New()
```

### Seeding

```go
// Seed with initial entropy (required before first use)
seed := []byte{...}
f.Seed(seed)
```

### Adding Entropy

```go
// Add entropy event from a specific source to a specific pool
f.AddRandomEvent(sourceID byte, poolID int, data []byte)

// Convenience function: distribute entropy across all pools
f.AddEntropy(data []byte)
```

### Generating Random Data

```go
// Generate n random bytes
data, err := f.RandomData(n int)

// Generate random uint64
val, err := f.Uint64()

// Generate random uint32  
val, err := f.Uint32()

// Use as io.Reader
buf := make([]byte, 32)
n, err := f.Read(buf)
```

## Architecture

Fortuna consists of two main components:

### 1. Generator (AES-256 Counter Mode)

- Maintains a 256-bit key and 128-bit counter
- Generates random output by encrypting the counter
- Automatically generates new key after each request (backtracking resistance)
- Uses AES-256 for cryptographic strength

### 2. Accumulator (32 Entropy Pools)

- 32 pools accumulate entropy from various sources
- Pool 0 is used on every reseed
- Pool i is used every 2^i reseeds (exponential scheduling)
- Ensures all pools are eventually used, even if entropy collection is irregular

### Reseed Logic

Reseeding occurs when:
1. Pool 0 has at least 64 bytes of entropy
2. At least 100ms have passed since last reseed
3. A random data generation request is made

During reseed:
- Pool scheduling determines which pools to include
- Selected pools are hashed (SHA-256)
- Hashes are concatenated and used to reseed generator
- Used pools are reset

## Security Properties

### Backtracking Resistance

After generating random output, the internal key is updated using output from the generator itself. An attacker who learns the current state cannot determine previous outputs.

### Pool Scheduling

The exponential pool schedule ensures:
- Fresh entropy is always used (pool 0 on every reseed)
- Long-term entropy is preserved (higher pools used rarely)
- Defense against entropy source failures
- Recovery from state compromise over time

### Reseed Rate Limiting

Minimum 100ms between reseeds prevents:
- Denial of service through forced reseeding
- Excessive pool reset before sufficient entropy accumulates

## Constants

```go
const (
    NumPools           = 32              // Number of entropy pools
    MinPoolSize        = 64              // Min bytes in pool 0 before reseed
    MinReseedInterval  = 100ms           // Min time between reseeds
    MaxBytesPerRequest = 1MB             // Max bytes per generation request
    KeySize            = 32              // AES-256 key size
    BlockSize          = 16              // AES block size
)
```

## Example: Multiple Entropy Sources

```go
f := fortuna.New()

// Initial seed from OS
osSeed := make([]byte, 64)
rand.Read(osSeed)
f.Seed(osSeed)

// Add entropy from different sources
const (
    SOURCE_SYSTEM_TIME = 0
    SOURCE_PROCESS_ID  = 1
    SOURCE_NETWORK     = 2
)

// Add timing entropy to pool 0
timingData := []byte{...}
f.AddRandomEvent(SOURCE_SYSTEM_TIME, 0, timingData)

// Add process info to pool 1
processData := []byte{...}
f.AddRandomEvent(SOURCE_PROCESS_ID, 1, processData)

// Add network timing to pool 2
networkData := []byte{...}
f.AddRandomEvent(SOURCE_NETWORK, 2, networkData)

// Generate random data (will reseed from pools if enough time passed)
data, _ := f.RandomData(256)
```

## Testing

```bash
# Run tests
go test -v

# Run tests with race detector
go test -race

# Run benchmarks
go test -bench=.
```

## Performance

Typical performance on modern hardware:

- **RandomData(1024)**: ~200,000 ops/sec (~200 MB/s)
- **Uint64()**: ~2,000,000 ops/sec
- **Reseed**: <1ms

The generator is fast enough for most applications while maintaining cryptographic security.

## Thread Safety

All public methods are thread-safe and can be called concurrently from multiple goroutines. Internal state is protected by a mutex.

## Comparison to crypto/rand

| Feature | Fortuna | crypto/rand |
|---------|---------|-------------|
| Deterministic (for testing) | ✓ (with fixed seed) | ✗ |
| Entropy accumulation | ✓ (32 pools) | ✗ (direct OS) |
| Custom entropy sources | ✓ | ✗ |
| Backtracking resistance | ✓ | N/A |
| OS dependency | ✗ (after seed) | ✓ (always) |
| Speed | ~200 MB/s | Varies by OS |

Use `crypto/rand` when you need to rely directly on OS entropy. Use Fortuna when you need:
- Deterministic output for testing
- Custom entropy accumulation
- Independence from OS after initial seed
- Consistent cross-platform behavior

## References

- **Practical Cryptography** by Niels Ferguson and Bruce Schneier (Chapter 10)
- [Fortuna specification](https://www.schneier.com/academic/fortuna/)

## License

MIT License

## Security Notice

This implementation follows the Fortuna specification but has not been independently audited. For production cryptographic use, consider:
1. Using `crypto/rand` for initial seeding
2. Regular security audits
3. Proper key management
4. Following your organization's security policies
