/*
 * Copyright (c) 2026 manalejandro
 *
 * MIT License - see the LICENSE file at the root of the repository.
 */

package com.manalejandro.postquantum;

/**
 * Base runtime exception for the library. Unchecked so that it can be used transparently from
 * Spring components without polluting every signature.
 */
public class PostQuantumException extends RuntimeException {

    /**
     * Creates an exception with a descriptive message.
     *
     * @param message the detail message
     */
    public PostQuantumException(String message) {
        super(message);
    }

    /**
     * Creates an exception with a descriptive message and an underlying cause.
     *
     * @param message the detail message
     * @param cause the exception that triggered this one
     */
    public PostQuantumException(String message, Throwable cause) {
        super(message, cause);
    }
}
