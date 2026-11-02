# PostQuantum

[![CI](https://github.com/manalejandro/postquantum/actions/workflows/ci.yml/badge.svg)](https://github.com/manalejandro/postquantum/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Java 17+](https://img.shields.io/badge/Java-17%2B-orange.svg)](https://adoptium.net/)
[![FIPS 203](https://img.shields.io/badge/FIPS-203-informational.svg)](https://doi.org/10.6028/NIST.FIPS.203)

A dependency-free, pure Java implementation of **ML-KEM** (FIPS 203, the module-lattice key
encapsulation mechanism standardised by NIST) with an authenticated hybrid encryption layer and
first-class Spring Boot support.

PostQuantum implements all three standardised parameter sets — **ML-KEM-512**, **ML-KEM-768**
and **ML-KEM-1024** — and validates the implementation against the official NIST ACVP test
vectors. It has **no runtime dependencies** beyond the JDK: no BouncyCastle, no native code, no
JNI.

```java
MlKem mlKem = MlKem.getInstance(MlKemParameterSet.ML_KEM_768);
MlKemKeyPair keyPair = mlKem.generateKeyPair();

MlKemEncapsulation encapsulation = mlKem.encapsulate(keyPair.publicKey());
byte[] sharedSecret = mlKem.decapsulate(keyPair.privateKey(), encapsulation.getCiphertext());
```

---

## Contents

- [Why this library](#why-this-library)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick start: ML-KEM](#quick-start-ml-kem)
- [Encrypting data: the hybrid cipher](#encrypting-data-the-hybrid-cipher)
- [Envelope format](#envelope-format)
- [Spring Boot integration](#spring-boot-integration)
- [Security notes](#security-notes)
- [Performance](#performance)
- [Building and testing](#building-and-testing)
- [Project layout](#project-layout)
- [Compatibility](#compatibility)
- [Contributing](#contributing)
- [License](#license)

## Why this library

ML-KEM is a **key encapsulation mechanism**, not a cipher. It produces a 32 byte shared secret
that two parties can use, but it does not encrypt application data. Using it correctly means
combining it with a symmetric authenticated cipher, deriving the key properly and binding the
KEM ciphertext to the resulting key.

PostQuantum packages both pieces:

- a complete, readable implementation of FIPS 203 (`MlKem`), and
- a ready-to-use envelope cipher (`HybridCipher`) built from ML-KEM + HKDF-SHA256 + AES-256-GCM,

plus a Spring Boot auto-configuration so applications can inject either one as a bean.

## Features

- **All FIPS 203 parameter sets**: ML-KEM-512, ML-KEM-768 and ML-KEM-1024.
- **Validated against NIST ACVP vectors**: key generation, encapsulation, decapsulation
  (including implicit rejection) and the encapsulation/decapsulation key checks — 240 test cases
  in total.
- **Pure Java 17+**: no external dependencies, no native libraries, no reflection tricks at
  runtime.
- **Constant-time conscious**: implicit rejection uses a branch-free mask, ciphertext comparison
  does not short-circuit, and secret buffers are wiped after use.
- **Authenticated hybrid encryption**: self-describing envelopes with AES-256-GCM, HKDF-SHA256,
  optional associated data and parameter-set binding.
- **Spring Boot auto-configuration**: `MlKem` and `HybridCipher` beans, externalised
  configuration, and an Actuator health indicator that runs a real crypto self-test.
- **Interoperable**: keys and ciphertexts are the raw FIPS 203 encodings, and the test suite
  cross-checks them against the ML-KEM implementation in JDK 24 (`javax.crypto.KEM`).
- **MIT licensed** and documented for reuse.

## Requirements

| Component | Version |
|-----------|---------|
| Java | 17 or newer |
| Spring Boot (optional) | 3.x for the beans, 4.x for the health indicator |
| Build | Maven 3.9+ or the bundled `./mvnw` |

The ML-KEM core has no framework dependency at all; it can be used from plain Java, Jakarta EE,
Quarkus, Micronaut or any other runtime. Spring is only needed for the `autoconfigure` package.

## Installation

The library is published as `com.manalejandro:postquantum`. Until it is available in Maven
Central, install it locally:

```bash
git clone https://github.com/manalejandro/postquantum.git
cd postquantum
./mvnw install
```

Then declare the dependency.

**Maven**

```xml
<dependency>
    <groupId>com.manalejandro</groupId>
    <artifactId>postquantum</artifactId>
    <version>0.1.0</version>
</dependency>
```

**Gradle**

```kotlin
implementation("com.manalejandro:postquantum:0.1.0")
```

Because the artifact is a library, do not add `spring-boot-maven-plugin` to it; the jar contains
no `Main-Class` and is meant to be consumed as a normal dependency.

## Quick start: ML-KEM

### Generating keys

```java
import com.manalejandro.postquantum.core.MlKem;
import com.manalejandro.postquantum.core.MlKemKeyPair;
import com.manalejandro.postquantum.core.MlKemParameterSet;

MlKem mlKem = MlKem.getInstance(MlKemParameterSet.ML_KEM_768);
MlKemKeyPair keyPair = mlKem.generateKeyPair();

byte[] publicKey = keyPair.publicKey().getEncoded();   // 1184 bytes, publish this
byte[] privateKey = keyPair.privateKey().getEncoded(); // 2400 bytes, keep this secret
```

Keys are plain FIPS 203 encodings. They can be persisted, sent over the wire or stored in a
keystore; wrap them again with `MlKemPublicKey.fromEncoded(...)` and
`MlKemPrivateKey.fromEncoded(...)` when you need them back.

### Encapsulation and decapsulation

```java
// Sender: derive a secret for the owner of the public key
MlKemEncapsulation encapsulation = mlKem.encapsulate(keyPair.publicKey());
byte[] ciphertext = encapsulation.getCiphertext();   // 1088 bytes for ML-KEM-768
byte[] senderSecret = encapsulation.getSharedSecret();

// Receiver: recover the same secret
byte[] receiverSecret = mlKem.decapsulate(keyPair.privateKey(), ciphertext);
```

The shared secret is 32 bytes. Treat it as opaque key material and feed it into a KDF before
using it with a symmetric cipher — or let `HybridCipher` do that for you.

### Choosing a parameter set

| Parameter set | NIST category | Public key | Private key | Ciphertext | Shared secret |
|---------------|---------------|-----------:|------------:|-----------:|--------------:|
| `ML_KEM_512`  | 1             | 800 B      | 1632 B      | 768 B      | 32 B          |
| `ML_KEM_768`  | 3             | 1184 B     | 2400 B      | 1088 B     | 32 B          |
| `ML_KEM_1024` | 5             | 1568 B     | 3168 B      | 1568 B     | 32 B          |

`ML-KEM-768` is the recommended default: it matches the security level of AES-192 and is the
parameter set used by most deployed protocols. Use `ML-KEM-1024` when you need the highest
margin, and `ML-KEM-512` only for constrained environments or legacy compatibility.

### Handling invalid input

FIPS 203 mandates **implicit rejection**: when a ciphertext does not decrypt to a valid
encapsulation, the implementation does not fail — it returns a pseudorandom secret derived from
the rejection value `z` and the ciphertext. This prevents an attacker from using decapsulation
failures as an oracle.

```java
byte[] tampered = encapsulation.getCiphertext();
tampered[0] ^= 0x01;

// Returns a deterministic but unrelated 32 byte secret; it does not throw.
byte[] secret = mlKem.decapsulate(keyPair.privateKey(), tampered);
```

This means you **must** authenticate the result. `HybridCipher` does that with AES-GCM: a
tampered envelope fails with `HybridDecryptionException`.

`IllegalArgumentException` is reserved for structurally invalid input: a ciphertext of the wrong
length, a key from another parameter set, or a key that fails the FIPS 203 modulus/hash checks.
Use `MlKem#isValidEncapsulationKey` and `MlKem#isValidDecapsulationKey` to validate untrusted
key material before using it.

## Encrypting data: the hybrid cipher

`HybridCipher` turns ML-KEM into authenticated public key encryption:

```java
import com.manalejandro.postquantum.hybrid.HybridCipher;

HybridCipher cipher = HybridCipher.forParameterSet(MlKemParameterSet.ML_KEM_768);
MlKemKeyPair keyPair = cipher.generateKeyPair();

byte[] envelope = cipher.encrypt(keyPair.publicKey(), "attack at dawn".getBytes(UTF_8));
byte[] plaintext = cipher.decrypt(keyPair.privateKey(), envelope);
```

Associated data is authenticated but not encrypted, which is useful for binding an envelope to a
tenant, a message id or a protocol version:

```java
byte[] aad = "tenant-42".getBytes(UTF_8);
byte[] envelope = cipher.encrypt(keyPair.publicKey(), payload, aad);

// Decryption only succeeds with the exact same associated data.
byte[] payload = cipher.decrypt(keyPair.privateKey(), envelope, aad);
```

Any modification to the header, the KEM ciphertext, the AES-GCM ciphertext, the tag or the
associated data is detected and reported as `HybridDecryptionException`.

Useful helpers:

```java
HybridCipher.isEnvelope(bytes);                              // magic check
HybridCipher.inspectParameterSet(bytes);                     // route without a private key
HybridCipher.envelopeLength(MlKemParameterSet.ML_KEM_768, 42); // 18 + 1088 + 42 + 16
```

`HybridCipher` instances are stateless apart from their `SecureRandom` and are safe for
concurrent use.

## Envelope format

```
 offset  size  field
 ------  ----  ---------------------------------------------------------------
      0     4  magic: "PQH1" (0x50 0x51 0x48 0x01), the last byte is the version
      4     1  parameter set id: 1 = ML-KEM-512, 2 = ML-KEM-768, 3 = ML-KEM-1024
      5     1  reserved flags, must be 0
      6    12  AES-GCM nonce, fresh for every envelope
     18     n  ML-KEM ciphertext (768, 1088 or 1568 bytes)
  18+n     m  AES-256-GCM ciphertext followed by the 16 byte authentication tag
```

The first 18 bytes are passed to AES-GCM as associated data, so the parameter set id and the
nonce are authenticated. The ML-KEM ciphertext is used as the HKDF salt, which binds the derived
AES key to it; tampering with the KEM ciphertext therefore changes the key and the tag check
fails.

Key derivation:

```
shared_secret = ML-KEM.Decaps(dk, kem_ciphertext)
aes_key       = HKDF-SHA256(ikm = shared_secret,
                            salt = kem_ciphertext,
                            info = "postquantum-hybrid-v1:" + parameter_set_name,
                            length = 32)
plaintext     = AES-256-GCM-Decrypt(aes_key, nonce, aad = header, ciphertext)
```

The format is versioned through the magic bytes; future revisions will use a different version
byte rather than silently changing the layout.

## Spring Boot integration

The auto-configuration registers the following beans when they are not already defined:

| Bean | Type | Description |
|------|------|-------------|
| `mlKem` | `MlKem` | ML-KEM instance for the configured parameter set |
| `hybridCipher` | `HybridCipher` | Envelope cipher backed by `mlKem` |
| `mlKemHealthIndicator` | `MlKemHealthIndicator` | Actuator health check (optional) |

### Configuration

```yaml
postquantum:
  enabled: true                 # false disables every bean
  parameter-set: ML-KEM-768     # ML-KEM-512, ML-KEM-768 or ML-KEM-1024
  health-indicator-enabled: true
```

| Property | Default | Description |
|----------|---------|-------------|
| `postquantum.enabled` | `true` | Master switch for the auto-configuration |
| `postquantum.parameter-set` | `ML-KEM-768` | Parameter set used by the beans |
| `postquantum.health-indicator-enabled` | `true` | Registers the Actuator health indicator |

Relaxed names are accepted, so `ML_KEM_768`, `ml-kem-768` and `mlkem768` all work.

### Injecting the beans

```java
@Service
public class MessageService {

    private final HybridCipher cipher;
    private final MlKemKeyPair keyPair; // load or generate your own key pair

    public MessageService(HybridCipher cipher) {
        this.cipher = cipher;
        this.keyPair = cipher.generateKeyPair();
    }

    public byte[] seal(byte[] payload) {
        return cipher.encrypt(keyPair.publicKey(), payload);
    }
}
```

### Overriding the defaults

Declare your own bean and the auto-configuration backs off:

```java
@Configuration
class CryptoConfiguration {

    @Bean
    MlKem mlKem() {
        return MlKem.getInstance(MlKemParameterSet.ML_KEM_1024);
    }
}
```

### Health indicator

When Spring Boot Actuator is on the classpath, `mlKemHealthIndicator` runs a complete round trip
on every health check: key generation, encapsulation, decapsulation and a hybrid
encrypt/decrypt. It reports `UP` with the parameter set and key sizes, or `DOWN` with the reason.
This catches broken or restricted JCE providers before the first real request fails.

The indicator is built on the Spring Boot 4 health API (`org.springframework.boot.health`).
On Spring Boot 3.x the beans are still auto-configured, but the indicator is not registered.

## Security notes

- **Not a FIPS validated module.** The implementation follows FIPS 203 and passes the NIST ACVP
  vectors, but it has not been submitted to the NIST CMVP programme. If you need a validated
  module, use a certified provider.
- **Constant-time behaviour is a best effort on the JVM.** The implementation avoids
  secret-dependent branches and table lookups in the decapsulation path, but the JIT can
  introduce optimisations that a native implementation would not. For the strongest side-channel
  guarantees, use a native provider.
- **Randomness matters.** Key generation and encapsulation use `SecureRandom`. Do not inject a
  predictable `SecureRandom` in production; the overloads that accept one exist for testing and
  for integration with HSM-backed sources.
- **ML-KEM alone is not encryption.** Always combine it with an authenticated cipher (as
  `HybridCipher` does) and always authenticate the derived key.
- **This is not a classical/post-quantum hybrid.** `HybridCipher` combines ML-KEM with
  HKDF-SHA256 and AES-256-GCM; it does not perform an X25519 or ECDH exchange. Its security rests
  on ML-KEM and AES-256-GCM alone. If your threat model requires defence in depth against a
  future break of ML-KEM, add a classical KEM at the protocol layer.
- **Key management is your responsibility.** Private keys are returned as raw bytes. Store them
  encrypted, rotate them, and never log them. `toString()` implementations redact key material
  and shared secrets.
- **Envelope size.** ML-KEM public keys and ciphertexts are large. Budget roughly 1.2 KB of
  overhead per envelope for ML-KEM-768 (18 byte header + 1088 byte KEM ciphertext + 16 byte tag)
  before the payload.

Please report security issues privately as described in [SECURITY.md](SECURITY.md).

## Performance

Indicative throughput on a modern x86-64 machine (OpenJDK 24, single thread, after JIT warm-up):

| Parameter set | Key generation | Encapsulation | Decapsulation | Hybrid decrypt (1 KiB) |
|---------------|---------------:|--------------:|--------------:|-----------------------:|
| ML-KEM-512    | ~13,000 ops/s  | ~12,000 ops/s | ~9,100 ops/s  | ~8,400 ops/s           |
| ML-KEM-768    | ~8,900 ops/s   | ~8,000 ops/s  | ~6,000 ops/s  | ~5,700 ops/s           |
| ML-KEM-1024   | ~5,900 ops/s   | ~5,500 ops/s  | ~4,200 ops/s  | ~4,100 ops/s           |

Treat these as orders of magnitude, not benchmarks: results depend on the CPU, the JDK version
and the JIT. For context, ML-KEM-768 encapsulation costs a fraction of a millisecond, so
per-request key establishment is usually cheaper than the network round trip that carries it.

## Building and testing

```bash
./mvnw verify          # compile, run all tests and package the jar
./mvnw test            # tests only
./mvnw -DskipTests package
```

The test suite contains:

- **`AcvpMlKemTest`** — 240 official NIST ACVP cases for key generation, encapsulation,
  decapsulation and key validation.
- **`KeccakTest`** — SHA3-256, SHA3-512, SHAKE128 and SHAKE256 known-answer tests.
- **`HkdfTest`** — RFC 5869 HKDF-SHA256 test vectors.
- **`MlKemTest`** — public API behaviour, implicit rejection, input validation, immutability.
- **`HybridCipherTest`** — round trips, tamper detection, AAD binding, envelope parsing.
- **`JdkMlKemInteropTest`** — cross-checks raw keys and ciphertexts against the JDK 24
  `javax.crypto.KEM` ML-KEM implementation (skipped on older JDKs).
- **`PostQuantumAutoConfigurationTest`** and **`MlKemHealthIndicatorTest`** — Spring wiring,
  property binding, bean back-off and health reporting.

The ACVP vectors live in `src/test/resources/acvp/ml-kem-fips203.json.gz` and can be regenerated
with `python3 tools/fetch-acvp-vectors.py`.

## Releasing

Releases are published by the [Release workflow](.github/workflows/release.yml). It builds,
tests and packages the library, generates `SHA256SUMS`, and attaches the main jar plus the
`-sources` and `-javadoc` jars to the GitHub Release for the tag.

```bash
git tag v0.1.0
git push origin v0.1.0
```

The tag must match the Maven version, so bump `<version>` in `pom.xml` before tagging: the
workflow fails when `v0.1.0` and `0.1.0` disagree. A manual run from the Actions tab is also
possible; it asks for the tag to publish.

The workflow authenticates with the `TOKEN` repository secret:

```bash
gh secret set TOKEN --body "<personal access token with contents:write>"
```

`TOKEN` must be a fine-grained personal access token (or a classic token with the `repo` scope)
that is allowed to create releases in this repository. Without it the workflow cannot upload the
artifacts.

## Project layout

```
src/main/java/com/manalejandro/postquantum/
├── core/                     public ML-KEM API (MlKem, keys, parameter sets)
│   └── internal/             FIPS 203 primitives (Keccak, NTT, sampling, encoding, K-PKE)
├── hybrid/                   HybridCipher, HKDF, decryption exception
├── autoconfigure/            Spring Boot auto-configuration and properties
└── health/                   Actuator health indicator
```

The `internal` package is an implementation detail and is not part of the public API. It is
public only so that tests can reach deterministic entry points; do not depend on it.

## Compatibility

| | Java 17 | Java 21 | Java 24+ |
|---|---|---|---|
| ML-KEM core | ✅ | ✅ | ✅ |
| Spring auto-configuration | ✅ (Boot 3.x / 4.x) | ✅ | ✅ |
| Actuator health indicator | ✅ (Boot 4.x) | ✅ | ✅ |
| JDK interop test | skipped | skipped | ✅ |

The core library is framework agnostic. The auto-configuration works with Spring Boot 3.x and
4.x; the Actuator health indicator uses the Spring Boot 4 health API
(`org.springframework.boot.health`) and is only registered when that API is present. On Spring
Boot 3.x the beans are still created, and you can add your own health indicator against the
`org.springframework.boot.actuate.health` API if you need one.

## Contributing

Issues and pull requests are welcome. Please:

1. Keep the code dependency-free and Java 17 compatible.
2. Add tests for every behavioural change; cryptographic changes must keep the ACVP suite green.
3. Run `./mvnw verify` before opening a pull request.
4. Follow the existing style: no wildcard imports, explicit null checks at API boundaries, and
   Javadoc on every public type and method.

## License

MIT — see [LICENSE](LICENSE). Copyright (c) 2026 manalejandro.

## References

- [FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard](https://doi.org/10.6028/NIST.FIPS.203)
- [NIST ACVP Server test vectors](https://github.com/usnistgov/ACVP-Server)
- [RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF)](https://www.rfc-editor.org/rfc/rfc5869)
- [NIST SP 800-227: Recommendations for Key-Encapsulation Mechanisms](https://doi.org/10.6028/NIST.SP.800-227)
