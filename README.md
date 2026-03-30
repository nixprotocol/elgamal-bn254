# elgamal-bn254

Homomorphic ElGamal encryption over the BN254 G1 curve with zero-knowledge proofs, designed for confidential token transfers on blockchain.

Amounts are encrypted as ElGamal ciphertexts that support homomorphic addition and subtraction. The library provides Schnorr-style proofs (DLEQ, equality, apply-pending) so on-chain verifiers can confirm correctness without learning plaintext values. Encrypted memos (ECDH + AES-256-GCM) allow transaction metadata to be shared privately with recipients.

## Installation

```bash
go get github.com/nixprotocol/elgamal-bn254
```

## Usage

### Key Generation and Encryption

```go
package main

import (
    "crypto/rand"
    "fmt"

    elgamal "github.com/nixprotocol/elgamal-bn254"
)

func main() {
    // Generate a key pair
    sk, pk, err := elgamal.KeyGen(rand.Reader)
    if err != nil {
        panic(err)
    }

    // Encrypt an amount
    ct, r, err := elgamal.Encrypt(1000, &pk, rand.Reader)
    if err != nil {
        panic(err)
    }

    // Decrypt using a BSGS table (covers values up to 2^32)
    table := elgamal.NewDecryptionTable(16)
    amount, err := elgamal.Decrypt(&ct, &sk, table)
    if err != nil {
        panic(err)
    }
    fmt.Printf("Decrypted: %d\n", amount) // 1000

    _ = r // randomness can be used for proofs
}
```

### Homomorphic Operations

```go
// Encrypt two amounts
ct1, _, _ := elgamal.Encrypt(300, &pk, rand.Reader)
ct2, _, _ := elgamal.Encrypt(700, &pk, rand.Reader)

// Add ciphertexts (300 + 700 = 1000)
sum := elgamal.Add(&ct1, &ct2)
amount, _ := elgamal.Decrypt(&sum, &sk, table)
fmt.Println(amount) // 1000

// Subtract ciphertexts (700 - 300 = 400)
diff := elgamal.Sub(&ct2, &ct1)
amount, _ = elgamal.Decrypt(&diff, &sk, table)
fmt.Println(amount) // 400
```

### DLEQ Proof (Correct Decryption)

Prove that a ciphertext decrypts to a claimed amount without revealing the secret key:

```go
// Prover generates proof
proof, err := elgamal.ProveDLEQ(&sk, &pk, &ct, 1000, nil)
if err != nil {
    panic(err)
}

// Verifier checks proof (no secret key needed)
valid := elgamal.VerifyDLEQ(&proof, &pk, &ct, 1000, nil)
fmt.Println("DLEQ valid:", valid) // true
```

### Equality Proof (Confidential Transfer)

Prove that three ciphertexts under three different public keys all encrypt the same amount — used for sender/recipient/auditor transfers:

```go
skS, pkS, _ := elgamal.KeyGen(rand.Reader)
skR, pkR, _ := elgamal.KeyGen(rand.Reader)
skA, pkA, _ := elgamal.KeyGen(rand.Reader)

amount := uint64(500)
ct1, r1, _ := elgamal.Encrypt(amount, &pkS, rand.Reader)
ct2, r2, _ := elgamal.Encrypt(amount, &pkR, rand.Reader)
ct3, r3, _ := elgamal.Encrypt(amount, &pkA, rand.Reader)

// Prover generates proof
proof, err := elgamal.ProveEquality(amount, &r1, &r2, &r3, &pkS, &pkR, &pkA, &ct1, &ct2, &ct3, nil)
if err != nil {
    panic(err)
}

// Verifier checks all three encrypt the same value
valid := elgamal.VerifyEquality(&proof, &pkS, &pkR, &pkA, &ct1, &ct2, &ct3, nil)
fmt.Println("Equality valid:", valid) // true

_ = skS; _ = skR; _ = skA
```

### 2-Key Equality Proof (Key Rotation)

Prove two ciphertexts under two different keys encrypt the same amount — used for `MsgRotateKey`:

```go
_, pkOld, _ := elgamal.KeyGen(rand.Reader)
_, pkNew, _ := elgamal.KeyGen(rand.Reader)

amount := uint64(1000)
ct1, r1, _ := elgamal.Encrypt(amount, &pkOld, rand.Reader)
ct2, r2, _ := elgamal.Encrypt(amount, &pkNew, rand.Reader)

proof, _ := elgamal.ProveEquality2(amount, &r1, &r2, &pkOld, &pkNew, &ct1, &ct2, nil)
valid := elgamal.VerifyEquality2(&proof, &pkOld, &pkNew, &ct1, &ct2, nil)
fmt.Println("Rotation valid:", valid) // true
```

### Apply-Pending Proof

Prove that a pending ciphertext (received from someone else) and a freshly re-encrypted ciphertext contain the same amount — used when absorbing incoming transfers:

```go
sk, pk, _ := elgamal.KeyGen(rand.Reader)

// Incoming ciphertext from a sender (encrypted to our key)
pending, _, _ := elgamal.Encrypt(500, &pk, rand.Reader)

// Decrypt and re-encrypt with fresh randomness
amount, _ := elgamal.Decrypt(&pending, &sk, table)
newCt, rNew, _ := elgamal.Encrypt(amount, &pk, rand.Reader)

// Prove pending and newCt encrypt the same amount
proof, _ := elgamal.ProveApplyPending(&sk, &pk, &pending, &newCt, amount, &rNew, nil)
valid := elgamal.VerifyApplyPending(&proof, &pk, &pending, &newCt, nil)
fmt.Println("Apply-pending valid:", valid) // true
```

### Encrypted Memo

Attach private metadata to transactions using ECDH + AES-256-GCM:

```go
_, recipientPk, _ := elgamal.KeyGen(rand.Reader)
recipientSk, _, _ := elgamal.KeyGen(rand.Reader)

// Encrypt a memo to the recipient
memo := []byte("Payment for invoice #42")
encrypted, err := elgamal.EncryptMemo(memo, &recipientPk)
if err != nil {
    panic(err)
}

// Recipient decrypts
plaintext, err := elgamal.DecryptMemo(encrypted, &recipientSk)
if err != nil {
    panic(err)
}
fmt.Println(string(plaintext)) // "Payment for invoice #42"
```

### Large Value Decryption

For amounts larger than 2^32, use `SplitDecryptionTable` which decomposes values as `hi * 2^splitBits + lo`:

```go
// Covers amounts up to ~2^48 (splitBits=8, hiHalfBits=20)
// Memory: ~64 MB for the hi baby table
// Worst-case decryption: ~256M iterations (~25s)
splitTable := elgamal.NewSplitDecryptionTable(8, 4, 20)

ct, _, _ := elgamal.Encrypt(1_000_000_000_000, &pk, rand.Reader)
amount, err := elgamal.Decrypt(&ct, &sk, splitTable)
fmt.Println(amount) // 1000000000000
```

**Parameter guide:**

| splitBits | hiHalfBits | Range | Memory | Worst-case time |
|-----------|-----------|-------|--------|-----------------|
| 8 | 16 | 2^40 | ~4 MB | ~1-2s |
| 8 | 20 | 2^48 | ~64 MB | ~25s |
| 16 | 8 | 2^32 | ~16 KB | ~1-2s |
| 16 | 16 | 2^48 | ~4 MB | slow |

### Serialization

All types support deterministic Marshal/Unmarshal:

```go
// Ciphertext (128 bytes)
data, _ := ct.Marshal()
var ct2 elgamal.Ciphertext
ct2.Unmarshal(data)

// Public key (64 bytes)
pkBytes := elgamal.MarshalPublicKey(&pk)
pk2, err := elgamal.UnmarshalPublicKey(pkBytes)

// Proofs
dleqBytes := proof.Marshal()
var proof2 elgamal.DLEQProof
proof2.Unmarshal(dleqBytes)
```

**Wire sizes:**

| Type | Size |
|------|------|
| Ciphertext | 128 bytes |
| Public key | 64 bytes |
| DLEQProof | 160 bytes |
| EqualityProof | 512 bytes |
| Equality2Proof | 352 bytes |
| ApplyPendingProof | 352 bytes |
| Memo overhead | 76 bytes + ciphertext |

## API

### Core

| Function | Description |
|----------|-------------|
| `KeyGen(rng io.Reader)` | Generate ElGamal key pair (sk, pk) |
| `Encrypt(amount, pk, rng)` | Encrypt with fresh randomness |
| `EncryptWithRandomness(amount, pk, r)` | Encrypt with given randomness |
| `Decrypt(ct, sk, table)` | Decrypt via discrete-log solver |
| `Add(a, b)` | Homomorphic addition of ciphertexts |
| `Sub(a, b)` | Homomorphic subtraction of ciphertexts |
| `ValidatePublicKey(pk)` | On-curve + non-identity check |

### Proofs

| Function | Description |
|----------|-------------|
| `ProveDLEQ` / `VerifyDLEQ` | Correct decryption proof |
| `ProveEquality` / `VerifyEquality` | 3-key same-amount proof |
| `ProveEquality2` / `VerifyEquality2` | 2-key same-amount proof (key rotation) |
| `ProveApplyPending` / `VerifyApplyPending` | Pending absorption proof |

### Decryption Tables

| Function | Description |
|----------|-------------|
| `NewDecryptionTable(halfBits)` | Standard BSGS, covers [0, 2^(2*halfBits)) |
| `NewDecryptionTableWithBase(halfBits, base)` | BSGS with custom base point |
| `NewSplitDecryptionTable(splitBits, loHalfBits, hiHalfBits)` | Hi/lo decomposition for large values |

### Memo

| Function | Description |
|----------|-------------|
| `EncryptMemo(message, recipientPk)` | ECDH + AES-256-GCM encryption (max 1024 bytes) |
| `DecryptMemo(encrypted, sk)` | Decrypt memo with private key |

### Transcript (Fiat-Shamir)

| Function | Description |
|----------|-------------|
| `NewTranscript(domain)` | Create domain-separated transcript |
| `AppendBytes` / `AppendPoint` / `AppendScalar` | Add data to transcript |
| `ChallengeScalar(label)` | Derive challenge via Keccak256 |

## Threat Model

### What this library does

- **Encryption**: ElGamal over BN254 G1 with homomorphic properties
- **Proofs**: Schnorr-style ZK proofs with Fiat-Shamir (Keccak256)
- **Memo encryption**: ECDH key agreement + AES-256-GCM
- **Discrete log**: Baby-step giant-step (standard and split) for decryption

### Trust boundaries

| Input | Trust level | Validation |
|-------|-------------|------------|
| Public keys from chain | Untrusted | `ValidatePublicKey()` — on-curve + non-identity |
| Ciphertext from chain | Untrusted | `Unmarshal()` — length + on-curve checks |
| Proof bytes from chain | Untrusted | `Unmarshal()` + `Verify*()` |
| Secret keys | Trusted (your own) | Nil checks only |
| Memo content | Trusted (your own) | Size limit (1024 bytes) |

### Assumptions

- **RNG quality**: All randomness uses `crypto/rand`. Compromised RNG breaks all security.
- **gnark-crypto correctness**: Curve arithmetic delegated to [gnark-crypto](https://github.com/consensys/gnark-crypto), a widely-audited library.
- **BN254 G1 cofactor = 1**: On-curve + non-identity is sufficient for subgroup validation.
- **No side-channel hardening**: Beyond what gnark-crypto provides. Not suitable for environments where timing analysis is a threat.

### Out of scope

- Key storage / encryption at rest
- Transport security
- Range proofs (proving amount is non-negative)
- Post-quantum security

## Performance

Benchmarks on Apple M-series:

| Operation | Time | Allocs |
|-----------|------|--------|
| Encrypt | ~136 µs | 14 |
| Decrypt (BSGS 2^32) | ~45 µs | 7 |
| Add | ~3 µs | 0 |
| Sub | ~3 µs | 0 |
| DLEQ Prove | ~121 µs | 18 |
| DLEQ Verify | ~234 µs | 31 |
| Equality Prove (3-key) | ~540 µs | 61 |
| Equality Verify (3-key) | ~835 µs | 89 |
| ApplyPending Prove | ~354 µs | 44 |
| ApplyPending Verify | ~546 µs | 63 |
| DecryptionTable init (2^32) | ~209 ms | 259 |
| SplitDecryptionTable init | ~668 µs | 8 |
| Split decrypt (2^40 range) | ~43 ms | 71 |

```bash
go test -bench=. -benchmem
```

## Testing

```bash
# All tests (94.8% coverage)
go test -v ./...

# Coverage report
go test -coverprofile=cover.out ./... && go tool cover -html=cover.out

# Race detector
go test -race ./...

# Benchmarks
go test -bench=. -benchmem
```

## Dependencies

- [`gnark-crypto`](https://github.com/consensys/gnark-crypto) — BN254 curve arithmetic
- [`golang.org/x/crypto`](https://pkg.go.dev/golang.org/x/crypto) — Keccak256 (SHA3)
- [`testify`](https://github.com/stretchr/testify) — Test assertions (test only)

## License

Apache 2.0 — See [LICENSE](LICENSE).

## Author

[NixProtocol](https://nixprotocol.com) ([GitHub](https://github.com/nixprotocol))
