/*
 * Copyright (c) 2026 manalejandro
 *
 * MIT License - see the LICENSE file at the root of the repository.
 */

package com.manalejandro.postquantum.hybrid;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/** HKDF-SHA256 (RFC 5869) used to derive the AES key from the ML-KEM shared secret. */
final class Hkdf {

    private static final int HASH_LENGTH = 32;

    private Hkdf() {
    }

    static byte[] deriveKey(byte[] inputKeyMaterial, byte[] salt, byte[] info, int length) {
        if (length <= 0 || length > 255 * HASH_LENGTH) {
            throw new IllegalArgumentException("invalid HKDF output length: " + length);
        }
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            byte[] effectiveSalt = salt.length == 0 ? new byte[HASH_LENGTH] : salt;
            mac.init(new SecretKeySpec(effectiveSalt, "HmacSHA256"));
            byte[] pseudoRandomKey = mac.doFinal(inputKeyMaterial);

            mac.init(new SecretKeySpec(pseudoRandomKey, "HmacSHA256"));
            byte[] output = new byte[length];
            byte[] previous = new byte[0];
            int offset = 0;
            int counter = 1;
            while (offset < length) {
                mac.update(previous);
                mac.update(info);
                mac.update((byte) counter++);
                previous = mac.doFinal();
                int chunk = Math.min(previous.length, length - offset);
                System.arraycopy(previous, 0, output, offset, chunk);
                offset += chunk;
            }
            Arrays.fill(previous, (byte) 0);
            Arrays.fill(pseudoRandomKey, (byte) 0);
            return output;
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("HmacSHA256 is not available", ex);
        }
    }
}
