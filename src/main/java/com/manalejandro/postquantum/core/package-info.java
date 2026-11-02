/*
 * Copyright (c) 2026 manalejandro
 *
 * MIT License - see the LICENSE file at the root of the repository.
 */

/**
 * Public ML-KEM API implementing FIPS 203.
 *
 * <p>{@link com.manalejandro.postquantum.core.MlKem} is the entry point. It produces
 * {@link com.manalejandro.postquantum.core.MlKemKeyPair} instances, encapsulates shared secrets
 * into {@link com.manalejandro.postquantum.core.MlKemEncapsulation} values and decapsulates
 * ciphertexts back into 32 byte secrets.
 *
 * <p>All encodings are the raw FIPS 203 byte strings, so keys and ciphertexts interoperate with
 * any conforming ML-KEM implementation.
 *
 * @since 0.1.0
 */
package com.manalejandro.postquantum.core;
