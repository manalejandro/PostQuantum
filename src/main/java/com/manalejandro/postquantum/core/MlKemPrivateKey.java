/*
 * Copyright (c) 2026 manalejandro
 *
 * MIT License - see the LICENSE file at the root of the repository.
 */

package com.manalejandro.postquantum.core;

import com.manalejandro.postquantum.core.internal.MlKemEngine;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Objects;

/**
 * An ML-KEM decapsulation key (the private key of FIPS 203).
 *
 * <p>The key is stored in the FIPS 203 format: the K-PKE decryption key, the corresponding
 * encapsulation key, its SHA3-256 hash and the implicit rejection value {@code z}. Instances are
 * immutable and never expose the key material through {@link #toString()}.
 */
public final class MlKemPrivateKey {

    private final MlKemParameterSet parameterSet;
    private final byte[] encoded;

    private MlKemPrivateKey(MlKemParameterSet parameterSet, byte[] encoded) {
        this.parameterSet = parameterSet;
        this.encoded = encoded;
    }

    /**
     * Wraps a raw decapsulation key.
     *
     * @param parameterSet the parameter set the key belongs to
     * @param encoded the FIPS 203 encoding of the key
     * @return an immutable key object
     * @throws IllegalArgumentException when the encoded length does not match the parameter set
     *     or the key fails the FIPS 203 input validation (hash check and modulus check)
     */
    public static MlKemPrivateKey fromEncoded(MlKemParameterSet parameterSet, byte[] encoded) {
        Objects.requireNonNull(parameterSet, "parameterSet must not be null");
        Objects.requireNonNull(encoded, "encoded must not be null");
        if (encoded.length != parameterSet.decapsulationKeyLength()) {
            throw new IllegalArgumentException("invalid decapsulation key length: expected "
                    + parameterSet.decapsulationKeyLength() + " bytes but got " + encoded.length);
        }
        byte[] copy = encoded.clone();
        if (!new MlKemEngine(parameterSet).isValidDecapsulationKey(copy)) {
            throw new IllegalArgumentException("decapsulation key failed the FIPS 203 input validation");
        }
        return new MlKemPrivateKey(parameterSet, copy);
    }

    /**
     * Wraps a key the library has just generated or already validated. Package private so that
     * callers can never bypass the FIPS 203 input validation.
     *
     * @param parameterSet the parameter set the key belongs to
     * @param encoded the already validated encoding
     * @return an immutable key object holding its own copy of the encoding
     */
    static MlKemPrivateKey fromValidatedEncoding(MlKemParameterSet parameterSet, byte[] encoded) {
        return new MlKemPrivateKey(parameterSet, encoded.clone());
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

    /**
     * The encapsulation key embedded in this decapsulation key.
     *
     * @return the encapsulation key embedded in this decapsulation key
     */
    public MlKemPublicKey getPublicKey() {
        int start = 384 * parameterSet.rank();
        int end = 768 * parameterSet.rank() + 32;
        return MlKemPublicKey.fromValidatedEncoding(parameterSet, Arrays.copyOfRange(encoded, start, end));
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof MlKemPrivateKey that)) {
            return false;
        }
        // MessageDigest.isEqual compares without leaking the position of the first difference.
        return parameterSet == that.parameterSet && MessageDigest.isEqual(encoded, that.encoded);
    }

    @Override
    public int hashCode() {
        return 31 * parameterSet.hashCode() + Arrays.hashCode(encoded);
    }

    @Override
    public String toString() {
        return "MlKemPrivateKey[" + parameterSet + ", " + encoded.length + " bytes]";
    }
}
