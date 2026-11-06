/*
 * Copyright (c) 2026 manalejandro
 *
 * MIT License - see the LICENSE file at the root of the repository.
 */

package com.manalejandro.postquantum.core;

import com.manalejandro.postquantum.core.internal.MlKemEngine;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

/**
 * Entry point for the ML-KEM key encapsulation mechanism standardised by NIST in FIPS 203.
 *
 * <p>ML-KEM is a key encapsulation mechanism, not a general purpose cipher: it establishes a
 * 32 byte shared secret between two parties over an insecure channel. To encrypt application
 * data, combine it with a symmetric cipher; {@code com.manalejandro.postquantum.hybrid.HybridCipher}
 * does exactly that.
 *
 * <p>Example:
 * <pre>{@code
 * MlKem mlKem = MlKem.getInstance(MlKemParameterSet.ML_KEM_768);
 *
 * MlKemKeyPair keyPair = mlKem.generateKeyPair();
 *
 * // Sender side
 * MlKemEncapsulation encapsulation = mlKem.encapsulate(keyPair.publicKey());
 * byte[] ciphertext = encapsulation.getCiphertext();
 * byte[] senderSecret = encapsulation.getSharedSecret();
 *
 * // Receiver side
 * byte[] receiverSecret = mlKem.decapsulate(keyPair.privateKey(), ciphertext);
 * }</pre>
 *
 * <p>Instances are stateless apart from the {@link SecureRandom} they use and are safe for
 * concurrent use. For deterministic (test vector) operations use the package-private overloads.
 */
public final class MlKem {

    private static final int SEED_LENGTH = 32;

    private final MlKemParameterSet parameterSet;
    private final SecureRandom secureRandom;
    private final MlKemEngine engine;

    private MlKem(MlKemParameterSet parameterSet, SecureRandom secureRandom) {
        this.parameterSet = parameterSet;
        this.secureRandom = secureRandom;
        this.engine = new MlKemEngine(parameterSet);
    }

    /**
     * Creates an ML-KEM instance for the given parameter set using a fresh {@link SecureRandom}.
     *
     * @param parameterSet the parameter set to use
     * @return a ready to use ML-KEM instance
     */
    public static MlKem getInstance(MlKemParameterSet parameterSet) {
        return getInstance(parameterSet, new SecureRandom());
    }

    /**
     * Creates an ML-KEM instance with an explicit source of randomness.
     *
     * @param parameterSet the parameter set to use
     * @param secureRandom the randomness source used for keys and encapsulation messages
     * @return a ready to use ML-KEM instance
     */
    public static MlKem getInstance(MlKemParameterSet parameterSet, SecureRandom secureRandom) {
        Objects.requireNonNull(parameterSet, "parameterSet must not be null");
        Objects.requireNonNull(secureRandom, "secureRandom must not be null");
        return new MlKem(parameterSet, secureRandom);
    }

    /**
     * The parameter set of this instance.
     *
     * @return the parameter set of this instance
     */
    public MlKemParameterSet getParameterSet() {
        return parameterSet;
    }

    /**
     * Generates a new key pair using fresh randomness, as described by FIPS 203, Algorithm 19.
     *
     * @return a new ML-KEM key pair
     */
    public MlKemKeyPair generateKeyPair() {
        byte[] d = new byte[SEED_LENGTH];
        byte[] z = new byte[SEED_LENGTH];
        try {
            secureRandom.nextBytes(d);
            secureRandom.nextBytes(z);
            return generateKeyPair(d, z);
        } finally {
            Arrays.fill(d, (byte) 0);
            Arrays.fill(z, (byte) 0);
        }
    }

    /**
     * Derives a key pair from a 64 byte seed, as described by FIPS 203, Algorithm 19.
     *
     * <p>The seed is the concatenation of the {@code d} and {@code z} values used by the
     * standard, which is also how the JDK stores ML-KEM private keys from Java 25 onwards. The
     * same seed always produces the same key pair, so this overload is meant for importing key
     * material from a KMS or an HSM, for restoring a backup, and for test vectors. For regular
     * key generation use {@link #generateKeyPair()}.
     *
     * @param seed the 64 byte seed, holding {@code d} followed by {@code z}
     * @return the key pair derived from the seed
     * @throws IllegalArgumentException when the seed is not 64 bytes long
     */
    public MlKemKeyPair generateKeyPair(byte[] seed) {
        Objects.requireNonNull(seed, "seed must not be null");
        if (seed.length != 2 * SEED_LENGTH) {
            throw new IllegalArgumentException("seed must be " + (2 * SEED_LENGTH)
                    + " bytes long but got " + seed.length);
        }
        byte[] d = Arrays.copyOfRange(seed, 0, SEED_LENGTH);
        byte[] z = Arrays.copyOfRange(seed, SEED_LENGTH, 2 * SEED_LENGTH);
        try {
            return generateKeyPair(d, z);
        } finally {
            Arrays.fill(d, (byte) 0);
            Arrays.fill(z, (byte) 0);
        }
    }

    /**
     * Encapsulates a fresh shared secret for the owner of {@code publicKey} (FIPS 203,
     * Algorithm 20).
     *
     * @param publicKey the recipient encapsulation key
     * @return the ciphertext to transmit and the shared secret to use locally
     * @throws IllegalArgumentException when the key uses another parameter set
     */
    public MlKemEncapsulation encapsulate(MlKemPublicKey publicKey) {
        Objects.requireNonNull(publicKey, "publicKey must not be null");
        requireSameParameterSet(publicKey.getParameterSet());
        byte[] message = new byte[SEED_LENGTH];
        try {
            secureRandom.nextBytes(message);
            return encapsulateDeterministic(publicKey, message);
        } finally {
            Arrays.fill(message, (byte) 0);
        }
    }

    /**
     * Recovers the shared secret from a ciphertext (FIPS 203, Algorithm 21).
     *
     * <p>If the ciphertext is invalid, FIPS 203 mandates implicit rejection: a pseudorandom but
     * deterministic value is returned instead of an error. Callers must therefore treat the
     * resulting secret as opaque and rely on the authenticated layer (for example AES-GCM) to
     * detect tampering.
     *
     * @param privateKey the recipient decapsulation key
     * @param ciphertext the ciphertext produced by {@link #encapsulate(MlKemPublicKey)}
     * @return the 32 byte shared secret
     * @throws IllegalArgumentException when the key belongs to another parameter set or the
     *     ciphertext has the wrong length
     */
    public byte[] decapsulate(MlKemPrivateKey privateKey, byte[] ciphertext) {
        Objects.requireNonNull(privateKey, "privateKey must not be null");
        Objects.requireNonNull(ciphertext, "ciphertext must not be null");
        requireSameParameterSet(privateKey.getParameterSet());
        if (ciphertext.length != parameterSet.ciphertextLength()) {
            throw new IllegalArgumentException("invalid ciphertext length: expected "
                    + parameterSet.ciphertextLength() + " bytes but got " + ciphertext.length);
        }
        byte[] encodedKey = privateKey.getEncoded();
        try {
            return engine.decapsulate(encodedKey, ciphertext);
        } finally {
            Arrays.fill(encodedKey, (byte) 0);
        }
    }

    /**
     * Checks whether a raw encapsulation key passes the FIPS 203 input validation (length and
     * modulus check).
     *
     * @param encodedKey the raw key bytes
     * @return {@code true} when the key can be used for encapsulation
     */
    public boolean isValidEncapsulationKey(byte[] encodedKey) {
        return engine.isValidEncapsulationKey(encodedKey);
    }

    /**
     * Checks whether a raw decapsulation key passes the FIPS 203 input validation (length, hash
     * check and modulus check).
     *
     * @param encodedKey the raw key bytes
     * @return {@code true} when the key can be used for decapsulation
     */
    public boolean isValidDecapsulationKey(byte[] encodedKey) {
        return engine.isValidDecapsulationKey(encodedKey);
    }

    /** FIPS 203, Algorithm 19 with caller supplied seeds. Used by the ACVP test vectors. */
    MlKemKeyPair generateKeyPair(byte[] d, byte[] z) {
        byte[][] keys = engine.keyGen(d, z);
        try {
            return new MlKemKeyPair(
                    MlKemPublicKey.fromValidatedEncoding(parameterSet, keys[0]),
                    MlKemPrivateKey.fromValidatedEncoding(parameterSet, keys[1]));
        } finally {
            // Both value objects hold their own copy, so the engine buffer can be cleared.
            Arrays.fill(keys[1], (byte) 0);
        }
    }

    /** FIPS 203, Algorithm 20 with a caller supplied message. Used by the ACVP test vectors. */
    MlKemEncapsulation encapsulateDeterministic(MlKemPublicKey publicKey, byte[] message) {
        Objects.requireNonNull(publicKey, "publicKey must not be null");
        requireSameParameterSet(publicKey.getParameterSet());
        byte[][] result = engine.encapsulate(publicKey.getEncoded(), message);
        try {
            return MlKemEncapsulation.of(result[0], result[1]);
        } finally {
            Arrays.fill(result[1], (byte) 0);
        }
    }

    private void requireSameParameterSet(MlKemParameterSet other) {
        if (parameterSet != other) {
            throw new IllegalArgumentException("key uses " + other + " but this instance uses " + parameterSet);
        }
    }

    @Override
    public String toString() {
        return "MlKem[" + parameterSet + "]";
    }
}
