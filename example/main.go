package main

import (
    "crypto/rand"
    "fmt"
    "fortuna"
    "log"
    "time"
)

func main() {
    fmt.Println("=== Fortuna PRNG Example ===\n")

    // Create a new Fortuna instance
    f := fortuna.New()

    // Seed with initial entropy (required before use)
    initialSeed := make([]byte, 64)
    _, err := rand.Read(initialSeed)
    if err != nil {
        log.Fatal(err)
    }
    f.Seed(initialSeed)
    fmt.Println("✓ Seeded PRNG with 64 bytes of entropy")

    // Generate random bytes
    randomBytes, err := f.RandomData(32)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("\nGenerated 32 random bytes: %x\n", randomBytes)

    // Generate random uint64
    val64, err := f.Uint64()
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Random uint64: %d\n", val64)

    // Generate random uint32
    val32, err := f.Uint32()
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Random uint32: %d\n", val32)

    // Add entropy events from different sources
    fmt.Println("\n--- Adding entropy from multiple sources ---")

    // Simulate entropy from different sources
    sources := []struct {
        id   byte
        name string
    }{
        {0, "system_time"},
        {1, "process_id"},
        {2, "network_timing"},
    }

    for _, src := range sources {
        // Distribute entropy across pools
        for pool := 0; pool < 4; pool++ {
            entropy := make([]byte, 16)
            rand.Read(entropy)

            err := f.AddRandomEvent(src.id, pool, entropy)
            if err != nil {
                log.Fatal(err)
            }
        }
        fmt.Printf("✓ Added entropy from source '%s' (id=%d)\n", src.name, src.id)
    }

    // Wait for reseed interval
    time.Sleep(150 * time.Millisecond)

    // Generate more data (will trigger reseed with accumulated entropy)
    fmt.Println("\n--- Generating after entropy accumulation ---")
    moreBytes, err := f.RandomData(64)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Generated 64 bytes: %x\n", moreBytes[:32])
    fmt.Printf("                    %x\n", moreBytes[32:])

    // Use as io.Reader
    fmt.Println("\n--- Using as io.Reader ---")
    buf := make([]byte, 16)
    n, err := f.Read(buf)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Read %d bytes: %x\n", n, buf)

    // Add bulk entropy
    fmt.Println("\n--- Adding bulk entropy ---")
    bulkEntropy := make([]byte, 256)
    rand.Read(bulkEntropy)
    f.AddEntropy(bulkEntropy)
    fmt.Println("✓ Added 256 bytes of entropy (distributed across pools)")

    // Generate a large amount
    fmt.Println("\n--- Generating large amount ---")
    large, err := f.RandomData(1024)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Generated %d bytes (first 32): %x\n", len(large), large[:32])

    // Demonstrate continuous use
    fmt.Println("\n--- Continuous generation ---")
    for i := 0; i < 5; i++ {
        val, err := f.Uint64()
        if err != nil {
            log.Fatal(err)
        }
        fmt.Printf("  Random value %d: %d\n", i+1, val)
    }

    fmt.Println("\n✓ Fortuna PRNG example completed successfully")
}
