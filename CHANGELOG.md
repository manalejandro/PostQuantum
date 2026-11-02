# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-11-02

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

[Unreleased]: https://github.com/manalejandro/postquantum/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/manalejandro/postquantum/releases/tag/v0.1.0
