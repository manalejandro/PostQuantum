/*
 * Copyright (c) 2026 manalejandro
 *
 * MIT License - see the LICENSE file at the root of the repository.
 */

package com.manalejandro.postquantum.core;

import com.manalejandro.postquantum.core.internal.MlKemEngine;

import java.util.Arrays;
import java.util.Objects;

/**
 * An ML-KEM encapsulation key (the public key of FIPS 203).
 *
 * <p>Instances are immutable and safe to share between threads. The key material is encoded
 * exactly as specified by FIPS 203 (Section 7.1) and can be transported as raw bytes.
 */
public final class MlKemPublicKey {

    private final MlKemParameterSet parameterSet;
    private final byte[] encoded;

    private MlKemPublicKey(MlKemParameterSet parameterSet, byte[] encoded) {
        this.parameterSet = parameterSet;
        this.encoded = encoded;
    }

    /**
     * Wraps a raw encapsulation key.
     *
     * @param parameterSet the parameter set the key belongs to
     * @param encoded the FIPS 203 encoding of the key
     * @return an immutable key object
     * @throws IllegalArgumentException when the encoded length does not match the parameter set
     *     or the key fails the FIPS 203 input validation
     */
    public static MlKemPublicKey fromEncoded(MlKemParameterSet parameterSet, byte[] encoded) {
        Objects.requireNonNull(parameterSet, "parameterSet must not be null");
        Objects.requireNonNull(encoded, "encoded must not be null");
        if (encoded.length != parameterSet.encapsulationKeyLength()) {
            throw new IllegalArgumentException("invalid encapsulation key length: expected "
                    + parameterSet.encapsulationKeyLength() + " bytes but got " + encoded.length);
        }
        byte[] copy = encoded.clone();
        if (!new MlKemEngine(parameterSet).isValidEncapsulationKey(copy)) {
            throw new IllegalArgumentException("encapsulation key failed the FIPS 203 input validation");
        }
        return new MlKemPublicKey(parameterSet, copy);
    }

    /**
     * Wraps a key the library has just generated or already validated. Package private so that
     * callers can never bypass the FIPS 203 input validation.
     *
     * @param parameterSet the parameter set the key belongs to
     * @param encoded the already validated encoding
     * @return an immutable key object holding its own copy of the encoding
     */
    static MlKemPublicKey fromValidatedEncoding(MlKemParameterSet parameterSet, byte[] encoded) {
        return new MlKemPublicKey(parameterSet, encoded.clone());
    }

    /**
     * The parameter set of this key.
     *
     * @return the parameter set of this key
     */
    public MlKemParameterSet getParameterSet() {
        return parameterSet;
    }

    /**
     * A defensive copy of the FIPS 203 encoded key.
     *
     * @return a defensive copy of the FIPS 203 encoded key
     */
    public byte[] getEncoded() {
        return encoded.clone();
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof MlKemPublicKey that)) {
            return false;
        }
        return parameterSet == that.parameterSet && Arrays.equals(encoded, that.encoded);
    }

    @Override
    public int hashCode() {
        return 31 * parameterSet.hashCode() + Arrays.hashCode(encoded);
    }

    @Override
    public String toString() {
        return "MlKemPublicKey[" + parameterSet + ", " + encoded.length + " bytes]";
    }
}
