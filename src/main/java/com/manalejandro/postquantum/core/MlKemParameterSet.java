/*
 * Copyright (c) 2026 manalejandro
 *
 * MIT License - see the LICENSE file at the root of the repository.
 */

package com.manalejandro.postquantum.core;

import java.util.Locale;

/**
 * The three parameter sets defined by FIPS 203 (ML-KEM-512, ML-KEM-768 and ML-KEM-1024).
 *
 * <p>Each parameter set fixes the module rank {@code k}, the noise distributions
 * {@code eta1}/{@code eta2} and the ciphertext compression parameters {@code du}/{@code dv}.
 * The derived key and ciphertext sizes match Section 8 of the standard.
 */
public enum MlKemParameterSet {

    /** NIST security category 1. Suitable for legacy compatibility; 768 is the general default. */
    ML_KEM_512(2, 3, 2, 10, 4, 1, "ML-KEM-512"),

    /** NIST security category 3. Recommended default for most applications. */
    ML_KEM_768(3, 2, 2, 10, 4, 2, "ML-KEM-768"),

    /** NIST security category 5. Highest security margin, largest keys. */
    ML_KEM_1024(4, 2, 2, 11, 5, 3, "ML-KEM-1024");

    private final int rank;
    private final int eta1;
    private final int eta2;
    private final int du;
    private final int dv;
    private final int identifier;
    private final String algorithmName;

    MlKemParameterSet(int rank, int eta1, int eta2, int du, int dv, int identifier, String algorithmName) {
        this.rank = rank;
        this.eta1 = eta1;
        this.eta2 = eta2;
        this.du = du;
        this.dv = dv;
        this.identifier = identifier;
        this.algorithmName = algorithmName;
    }

    /**
     * The module rank {@code k}.
     *
     * @return the module rank {@code k}
     */
    public int rank() {
        return rank;
    }

    /**
     * The standard deviation parameter used for the secret and error vectors.
     *
     * @return the standard deviation parameter used for the secret and error vectors
     */
    public int eta1() {
        return eta1;
    }

    /**
     * The standard deviation parameter used for the encryption noise.
     *
     * @return the standard deviation parameter used for the encryption noise
     */
    public int eta2() {
        return eta2;
    }

    /**
     * The number of bits used to compress {@code u}.
     *
     * @return the number of bits used to compress {@code u}
     */
    public int du() {
        return du;
    }

    /**
     * The number of bits used to compress {@code v}.
     *
     * @return the number of bits used to compress {@code v}
     */
    public int dv() {
        return dv;
    }

    /**
     * A stable one byte identifier used by the hybrid envelope format (1, 2 or 3).
     *
     * @return a stable one byte identifier used by the hybrid envelope format (1, 2 or 3)
     */
    public int identifier() {
        return identifier;
    }

    /**
     * The FIPS 203 name of the parameter set, for example {@code ML-KEM-768}.
     *
     * @return the FIPS 203 name of the parameter set, for example {@code ML-KEM-768}
     */
    public String algorithmName() {
        return algorithmName;
    }

    /**
     * The length in bytes of an encapsulation (public) key.
     *
     * @return the length in bytes of an encapsulation (public) key
     */
    public int encapsulationKeyLength() {
        return 384 * rank + 32;
    }

    /**
     * The length in bytes of a decapsulation (private) key.
     *
     * @return the length in bytes of a decapsulation (private) key
     */
    public int decapsulationKeyLength() {
        return 768 * rank + 96;
    }

    /**
     * The length in bytes of a ciphertext.
     *
     * @return the length in bytes of a ciphertext
     */
    public int ciphertextLength() {
        return 32 * (du * rank + dv);
    }

    /**
     * The length in bytes of the shared secret produced by encapsulation.
     *
     * @return the length in bytes of the shared secret produced by encapsulation
     */
    public int sharedSecretLength() {
        return 32;
    }

    /**
     * Resolves a parameter set from a name such as {@code ML-KEM-768}, {@code ML_KEM_768} or
     * {@code mlkem768}.
     *
     * @param name the parameter set name, case insensitive
     * @return the matching parameter set
     * @throws IllegalArgumentException when the name does not match a known parameter set
     */
    public static MlKemParameterSet fromName(String name) {
        if (name == null) {
            throw new IllegalArgumentException("parameter set name must not be null");
        }
        String normalized = name.trim().toUpperCase(Locale.ROOT).replace('-', '_');
        if ("MLKEM512".equals(normalized)) {
            return ML_KEM_512;
        }
        if ("MLKEM768".equals(normalized)) {
            return ML_KEM_768;
        }
        if ("MLKEM1024".equals(normalized)) {
            return ML_KEM_1024;
        }
        try {
            return valueOf(normalized);
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException("unknown ML-KEM parameter set: " + name, ex);
        }
    }

    @Override
    public String toString() {
        return algorithmName;
    }
}
