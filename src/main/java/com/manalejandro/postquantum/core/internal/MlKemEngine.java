/*
 * Copyright (c) 2026 manalejandro
 *
 * MIT License - see the LICENSE file at the root of the repository.
 */

package com.manalejandro.postquantum.core.internal;

import com.manalejandro.postquantum.core.MlKemParameterSet;

import java.util.Arrays;

/**
 * FIPS 203 ML-KEM internal functions: ML-KEM.KeyGen_internal, ML-KEM.Encaps_internal and
 * ML-KEM.Decaps_internal (Algorithms 16 to 18), plus the input validation of Section 7.
 */
public final class MlKemEngine {

    private final MlKemParameterSet parameters;
    private final Kpke kpke;

    /**
     * Creates an engine bound to a parameter set.
     *
     * @param parameters the ML-KEM parameter set that selects the sizes and sampling ranges
     */
    public MlKemEngine(MlKemParameterSet parameters) {
        this.parameters = parameters;
        this.kpke = new Kpke(parameters);
    }

    /**
     * FIPS 203, Algorithm 16: ML-KEM.KeyGen_internal.
     *
     * @param d the 32 byte seed that derives the PKE key pair
     * @param z the 32 byte seed used for implicit rejection
     * @return a two element array holding {@code {ek, dk}}
     */
    public byte[][] keyGen(byte[] d, byte[] z) {
        requireLength(d, 32, "d");
        requireLength(z, 32, "z");

        byte[][] pkeKeys = kpke.keyGen(d);
        byte[] encapsulationKey = pkeKeys[0];
        byte[] decapsulationKey = Bytes.concat(
                pkeKeys[1],
                encapsulationKey,
                Keccak.sha3_256(encapsulationKey),
                z);
        // The PKE decapsulation key is secret and has just been copied into the full ML-KEM
        // decapsulation key, so the intermediate copy can be cleared.
        Bytes.wipe(pkeKeys[1]);
        return new byte[][]{encapsulationKey, decapsulationKey};
    }

    /**
     * FIPS 203, Algorithm 17: ML-KEM.Encaps_internal.
     *
     * @param encapsulationKey the validated encapsulation key of the recipient
     * @param message the 32 byte random message
     * @return a two element array holding {@code {c, K}}
     */
    public byte[][] encapsulate(byte[] encapsulationKey, byte[] message) {
        requireLength(message, 32, "message");

        byte[] keyAndRandomness = Keccak.sha3_512(Bytes.concat(message, Keccak.sha3_256(encapsulationKey)));
        byte[] key = Arrays.copyOfRange(keyAndRandomness, 0, 32);
        byte[] randomness = Arrays.copyOfRange(keyAndRandomness, 32, 64);
        try {
            byte[] ciphertext = kpke.encrypt(encapsulationKey, message, randomness);
            return new byte[][]{ciphertext, key};
        } finally {
            Bytes.wipe(keyAndRandomness, randomness);
        }
    }

    /**
     * FIPS 203, Algorithm 18: ML-KEM.Decaps_internal, including implicit rejection.
     *
     * @param decapsulationKey the decapsulation key of the recipient
     * @param ciphertext the ciphertext produced by the sender
     * @return the 32 byte shared secret, or the implicit rejection secret when the ciphertext
     *         does not re-encrypt correctly
     */
    public byte[] decapsulate(byte[] decapsulationKey, byte[] ciphertext) {
        int k = parameters.rank();

        byte[] decapsulationKeyPke = Arrays.copyOfRange(decapsulationKey, 0, 384 * k);
        byte[] encapsulationKey = Arrays.copyOfRange(decapsulationKey, 384 * k, 768 * k + 32);
        byte[] storedHash = Arrays.copyOfRange(decapsulationKey, 768 * k + 32, 768 * k + 64);
        byte[] z = Arrays.copyOfRange(decapsulationKey, 768 * k + 64, 768 * k + 96);
        byte[] message = null;
        byte[] keyAndRandomness = null;
        byte[] candidateKey = null;
        byte[] randomness = null;
        byte[] rejectionKey = null;
        byte[] recomputedCiphertext = null;
        try {
            message = kpke.decrypt(decapsulationKeyPke, ciphertext);
            keyAndRandomness = Keccak.sha3_512(Bytes.concat(message, storedHash));
            candidateKey = Arrays.copyOfRange(keyAndRandomness, 0, 32);
            randomness = Arrays.copyOfRange(keyAndRandomness, 32, 64);
            rejectionKey = Keccak.shake256(Bytes.concat(z, ciphertext), 32);

            recomputedCiphertext = kpke.encrypt(encapsulationKey, message, randomness);
            int mask = Bytes.constantTimeMask(ciphertext, recomputedCiphertext);
            return Bytes.constantTimeSelect(mask, candidateKey, rejectionKey);
        } finally {
            // Every intermediate that can hold the private key, the message or a candidate shared
            // secret is cleared on both the success and the failure path.
            Bytes.wipe(decapsulationKeyPke, z);
            Bytes.wipe(message, keyAndRandomness, candidateKey, randomness, rejectionKey,
                    recomputedCiphertext);
        }
    }

    /**
     * FIPS 203, Section 7.2: encapsulation key check (length and modulus check).
     *
     * @param encapsulationKey the encoded key to validate
     * @return {@code true} when the key has the expected length and all coefficients are reduced
     */
    public boolean isValidEncapsulationKey(byte[] encapsulationKey) {
        if (encapsulationKey == null || encapsulationKey.length != parameters.encapsulationKeyLength()) {
            return false;
        }
        int k = parameters.rank();
        for (int i = 0; i < k; i++) {
            int[] coefficients = Encoding.decode(12, encapsulationKey, i * 384);
            for (int coefficient : coefficients) {
                if (coefficient >= Ntt.Q) {
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * FIPS 203, Section 7.3: decapsulation key check (hash check and modulus check).
     *
     * @param decapsulationKey the encoded key to validate
     * @return {@code true} when the key has the expected length, its embedded encapsulation key is
     *         valid and the stored hash matches
     */
    public boolean isValidDecapsulationKey(byte[] decapsulationKey) {
        if (decapsulationKey == null || decapsulationKey.length != parameters.decapsulationKeyLength()) {
            return false;
        }
        int k = parameters.rank();
        byte[] encapsulationKey = Arrays.copyOfRange(decapsulationKey, 384 * k, 768 * k + 32);
        byte[] storedHash = Arrays.copyOfRange(decapsulationKey, 768 * k + 32, 768 * k + 64);
        return isValidEncapsulationKey(encapsulationKey)
                && Bytes.constantTimeMask(storedHash, Keccak.sha3_256(encapsulationKey)) != 0;
    }

    private static void requireLength(byte[] value, int expected, String name) {
        if (value == null) {
            throw new IllegalArgumentException(name + " must not be null");
        }
        if (value.length != expected) {
            throw new IllegalArgumentException(name + " must be " + expected + " bytes long");
        }
    }
}
