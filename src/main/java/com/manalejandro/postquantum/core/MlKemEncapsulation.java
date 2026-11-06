/*
 * Copyright (c) 2026 manalejandro
 *
 * MIT License - see the LICENSE file at the root of the repository.
 */

package com.manalejandro.postquantum.core;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Objects;

/**
 * The result of an ML-KEM encapsulation: the ciphertext to send to the key owner and the shared
 * secret that both parties derive (FIPS 203, Section 7.1).
 */
public final class MlKemEncapsulation {

    private final byte[] ciphertext;
    private final byte[] sharedSecret;

    MlKemEncapsulation(byte[] ciphertext, byte[] sharedSecret) {
        this.ciphertext = ciphertext;
        this.sharedSecret = sharedSecret;
    }

    /**
     * A defensive copy of the FIPS 203 encoded ciphertext.
     *
     * @return a defensive copy of the FIPS 203 encoded ciphertext
     */
    public byte[] getCiphertext() {
        return ciphertext.clone();
    }

    /**
     * A defensive copy of the 32 byte shared secret.
     *
     * @return a defensive copy of the 32 byte shared secret
     */
    public byte[] getSharedSecret() {
        return sharedSecret.clone();
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof MlKemEncapsulation that)) {
            return false;
        }
        return Arrays.equals(ciphertext, that.ciphertext)
                && MessageDigest.isEqual(sharedSecret, that.sharedSecret);
    }

    @Override
    public int hashCode() {
        return 31 * Arrays.hashCode(ciphertext) + Arrays.hashCode(sharedSecret);
    }

    @Override
    public String toString() {
        return "MlKemEncapsulation[ciphertext=" + ciphertext.length + " bytes, sharedSecret=redacted]";
    }

    static MlKemEncapsulation of(byte[] ciphertext, byte[] sharedSecret) {
        Objects.requireNonNull(ciphertext, "ciphertext must not be null");
        Objects.requireNonNull(sharedSecret, "sharedSecret must not be null");
        return new MlKemEncapsulation(ciphertext.clone(), sharedSecret.clone());
    }
}
