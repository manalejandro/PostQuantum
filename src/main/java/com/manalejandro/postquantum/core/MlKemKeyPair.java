/*
 * Copyright (c) 2026 manalejandro
 *
 * MIT License - see the LICENSE file at the root of the repository.
 */

package com.manalejandro.postquantum.core;

/**
 * An ML-KEM key pair.
 *
 * @param publicKey the encapsulation key to publish
 * @param privateKey the decapsulation key to keep secret
 */
public record MlKemKeyPair(MlKemPublicKey publicKey, MlKemPrivateKey privateKey) {

    /**
     * Validates that both keys are present and use the same parameter set.
     *
     * @param publicKey the encapsulation key to publish
     * @param privateKey the decapsulation key to keep secret
     * @throws IllegalArgumentException when a key is missing or the parameter sets differ
     */
    public MlKemKeyPair {
        if (publicKey == null || privateKey == null) {
            throw new IllegalArgumentException("key pair components must not be null");
        }
        if (publicKey.getParameterSet() != privateKey.getParameterSet()) {
            throw new IllegalArgumentException("public and private keys use different parameter sets");
        }
    }
}
