/*
 * Copyright (c) 2026 manalejandro
 *
 * MIT License - see the LICENSE file at the root of the repository.
 */

/**
 * Authenticated public key encryption built on top of ML-KEM.
 *
 * <p>{@link com.manalejandro.postquantum.hybrid.HybridCipher} combines ML-KEM with HKDF-SHA256
 * and AES-256-GCM to produce self-contained envelopes. It is the recommended way to encrypt
 * application data with this library.
 *
 * @since 0.1.0
 */
package com.manalejandro.postquantum.hybrid;
