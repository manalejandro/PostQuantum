/*
 * Copyright (c) 2026 manalejandro
 *
 * MIT License - see the LICENSE file at the root of the repository.
 */

package com.manalejandro.postquantum.hybrid;

import com.manalejandro.postquantum.PostQuantumException;

/**
 * Thrown when a hybrid envelope cannot be authenticated: the AES-GCM tag did not verify, which
 * means the ciphertext, the encapsulated key, the header or the associated data was modified.
 */
public class HybridDecryptionException extends PostQuantumException {

    /**
     * Creates an exception with a descriptive message.
     *
     * @param message the detail message
     */
    public HybridDecryptionException(String message) {
        super(message);
    }

    /**
     * Creates an exception with a descriptive message and an underlying cause.
     *
     * @param message the detail message
     * @param cause the exception that triggered this one
     */
    public HybridDecryptionException(String message, Throwable cause) {
        super(message, cause);
    }
}
