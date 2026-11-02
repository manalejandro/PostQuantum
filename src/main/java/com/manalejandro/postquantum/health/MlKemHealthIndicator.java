/*
 * Copyright (c) 2026 manalejandro
 *
 * MIT License - see the LICENSE file at the root of the repository.
 */

package com.manalejandro.postquantum.health;

import com.manalejandro.postquantum.core.MlKem;
import com.manalejandro.postquantum.core.MlKemEncapsulation;
import com.manalejandro.postquantum.core.MlKemKeyPair;
import com.manalejandro.postquantum.core.MlKemParameterSet;
import com.manalejandro.postquantum.hybrid.HybridCipher;
import org.springframework.boot.health.contributor.AbstractHealthIndicator;
import org.springframework.boot.health.contributor.Health;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Objects;

/**
 * Actuator health indicator that runs a complete ML-KEM and hybrid encryption round trip.
 *
 * <p>It verifies that the running JVM can generate a key pair, encapsulate and decapsulate a
 * shared secret, and that HKDF-SHA256 plus AES-256-GCM produce a recoverable plaintext. This
 * catches broken or restricted JCE providers before the first real request fails.
 *
 * <p>Registered by {@link com.manalejandro.postquantum.autoconfigure.PostQuantumAutoConfiguration}
 * only when Spring Boot Actuator is on the classpath and
 * {@code postquantum.health-indicator-enabled} is {@code true}.
 */
public class MlKemHealthIndicator extends AbstractHealthIndicator {

    private static final byte[] PROBE = "postquantum-health-probe".getBytes(StandardCharsets.US_ASCII);

    private final MlKem mlKem;
    private final HybridCipher hybridCipher;

    /**
     * Creates a health indicator for the given ML-KEM and hybrid cipher.
     *
     * @param mlKem the ML-KEM instance under test
     * @param hybridCipher the hybrid cipher under test
     */
    public MlKemHealthIndicator(MlKem mlKem, HybridCipher hybridCipher) {
        super("ML-KEM health check failed");
        this.mlKem = Objects.requireNonNull(mlKem, "mlKem must not be null");
        this.hybridCipher = Objects.requireNonNull(hybridCipher, "hybridCipher must not be null");
    }

    @Override
    protected void doHealthCheck(Health.Builder builder) throws Exception {
        MlKemParameterSet parameterSet = mlKem.getParameterSet();

        MlKemKeyPair keyPair = mlKem.generateKeyPair();
        MlKemEncapsulation encapsulation = mlKem.encapsulate(keyPair.publicKey());
        byte[] decapsulated = mlKem.decapsulate(keyPair.privateKey(), encapsulation.getCiphertext());
        if (!MessageDigest.isEqual(encapsulation.getSharedSecret(), decapsulated)) {
            builder.down().withDetail("reason", "ML-KEM shared secrets do not match");
            return;
        }

        byte[] envelope = hybridCipher.encrypt(keyPair.publicKey(), PROBE);
        byte[] recovered = hybridCipher.decrypt(keyPair.privateKey(), envelope);
        if (!MessageDigest.isEqual(PROBE, recovered)) {
            builder.down().withDetail("reason", "hybrid cipher round trip failed");
            return;
        }

        builder.up()
                .withDetail("parameterSet", parameterSet.algorithmName())
                .withDetail("encapsulationKeyLength", parameterSet.encapsulationKeyLength())
                .withDetail("ciphertextLength", parameterSet.ciphertextLength())
                .withDetail("hybridCipher", "ML-KEM + HKDF-SHA256 + AES-256-GCM");
    }
}
