# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅        |

## Reporting a vulnerability

Please **do not** open a public issue for security problems. Report them privately through
GitHub's [private vulnerability reporting](https://github.com/manalejandro/postquantum/security/advisories/new)
or by email to the maintainer listed in the repository profile.

Include, when possible:

- the affected version and parameter set,
- a description of the issue and its impact,
- a minimal reproduction or proof of concept,
- any suggested remediation.

You can expect an acknowledgement within 72 hours and a first assessment within seven days.
Once a fix is ready, a security advisory and a patched release will be published; credit will be
given unless you prefer to remain anonymous.

## Scope

In scope:

- incorrect or non-standard behaviour of the FIPS 203 implementation,
- deviations from the ACVP test vectors,
- flaws in the hybrid envelope construction (key derivation, nonce handling, associated data,
  authentication),
- timing or other side-channel issues introduced by this library,
- unsafe defaults in the Spring Boot auto-configuration.

Out of scope:

- vulnerabilities in the JDK, the JCE providers or Spring Boot itself,
- misuse of the API (for example logging private keys, reusing a `SecureRandom` seed, or
  encrypting without authentication),
- the absence of a NIST CMVP certificate (this project is not a validated module),
- attacks that require the private key to be compromised.

## Threat model

PostQuantum assumes:

- the attacker can read, modify, drop and replay any data sent over the channel,
- the attacker has access to the recipient's public key,
- the recipient's private key and the process memory are trusted.

Under these assumptions, `HybridCipher` provides confidentiality and integrity for the payload
and for the associated data, and binds each envelope to a parameter set. It does not provide
forward secrecy by itself: that is a property of the protocol that uses it, not of a single
envelope. It also does not hide the envelope size, which leaks an approximation of the plaintext
length.

## Cryptography disclaimer

This library follows FIPS 203 and passes the official NIST ACVP vectors, but it has not been
evaluated or certified by the NIST Cryptographic Module Validation Program. It is provided under
the MIT license, without warranty. Evaluate it against your own requirements before using it to
protect production secrets.
