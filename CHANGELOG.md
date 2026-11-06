# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-11-06

### Changed

- `MlKemPublicKey.fromEncoded` and `MlKemPrivateKey.fromEncoded` now run the FIPS 203 input
  validation (modulus check, plus the hash check for decapsulation keys) when the key is
  imported. Invalid keys can no longer be wrapped, and encapsulation and decapsulation no longer
  repeat the check on every operation.
- `MlKemPrivateKey.equals` and `MlKemEncapsulation.equals` compare key material and shared
  secrets in constant time.
- Spring is now an optional dependency in the published POM. Applications that only use the
  ML-KEM core no longer inherit Spring on their classpath.

### Fixed

- `HybridCipher.envelopeLength` and `HybridCipher.encrypt` now reject plaintext sizes whose
  envelope would not fit in an `int`, instead of overflowing and returning a negative length.

### Security

- The ML-KEM key generation, encapsulation and decapsulation paths now wipe seed expansions,
  intermediate polynomials, the unpacked decapsulation key and candidate shared secrets once
  they are no longer needed, matching what `HybridCipher` already did for its own secrets.

## [0.1.0] - 2026-11-03

### Added

- Pure Java implementation of ML-KEM as standardised by FIPS 203, with support for ML-KEM-512,
  ML-KEM-768 and ML-KEM-1024.
- `MlKem` public API with key generation, encapsulation, decapsulation and key validation,
  including deterministic key generation from a 64 byte FIPS 203 seed.
- `MlKemPublicKey`, `MlKemPrivateKey`, `MlKemKeyPair` and `MlKemEncapsulation` value types with
  defensive copies and redacted `toString()` output.
- FIPS 203 implicit rejection with a branch-free constant-time selection.
- `HybridCipher`: authenticated public key encryption built from ML-KEM, HKDF-SHA256 and
  AES-256-GCM, with a self-describing `PQH1` envelope and associated data support.
- Spring Boot auto-configuration exposing `MlKem` and `HybridCipher` beans, configurable through
  the `postquantum.*` properties.
- Optional Actuator health indicator that performs a full ML-KEM and hybrid cipher round trip.
- Validation against the official NIST ACVP vectors: 240 cases covering key generation,
  encapsulation, decapsulation and key checks.
- Cross-checks against the ML-KEM implementation in JDK 24 and JDK 25 (`javax.crypto.KEM`),
  covering both the expanded and the seed-only private key encodings.
- MIT license, README, security policy and GitHub Actions CI workflow.
- GPG-signed artifacts published to Maven Central from the release workflow, with an opt-in
  `central` profile so that local builds do not need a signing key.

[Unreleased]: https://github.com/manalejandro/postquantum/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/manalejandro/postquantum/releases/tag/v0.1.1
[0.1.0]: https://github.com/manalejandro/postquantum/releases/tag/v0.1.0
