/*
 * Copyright (c) 2026 manalejandro
 *
 * MIT License - see the LICENSE file at the root of the repository.
 */

/**
 * Spring Boot Actuator integration.
 *
 * <p>{@link com.manalejandro.postquantum.health.MlKemHealthIndicator} runs a complete ML-KEM and
 * hybrid cipher round trip so that a broken JCE provider is detected before the first real
 * request fails.
 *
 * @since 0.1.0
 */
package com.manalejandro.postquantum.health;
