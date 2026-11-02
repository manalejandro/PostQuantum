/*
 * Copyright (c) 2026 manalejandro
 *
 * MIT License - see the LICENSE file at the root of the repository.
 */

package com.manalejandro.postquantum.autoconfigure;

import com.manalejandro.postquantum.core.MlKem;
import com.manalejandro.postquantum.health.MlKemHealthIndicator;
import com.manalejandro.postquantum.hybrid.HybridCipher;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Auto-configuration that exposes ML-KEM and the hybrid cipher as Spring beans.
 *
 * <p>The configuration is active by default and can be disabled with
 * {@code postquantum.enabled=false}. Every bean is conditional on missing, so an application
 * can always declare its own {@link MlKem} or {@link HybridCipher} and keep full control over
 * the parameter set or the source of randomness.
 */
@AutoConfiguration
@ConditionalOnClass(MlKem.class)
@EnableConfigurationProperties(PostQuantumProperties.class)
@ConditionalOnProperty(prefix = "postquantum", name = "enabled", havingValue = "true", matchIfMissing = true)
public class PostQuantumAutoConfiguration {

    /** Creates the auto-configuration. */
    public PostQuantumAutoConfiguration() {
    }

    /**
     * Creates the ML-KEM instance for the configured parameter set.
     *
     * @param properties the postquantum configuration
     * @return a thread safe ML-KEM instance
     */
    @Bean
    @ConditionalOnMissingBean
    public MlKem mlKem(PostQuantumProperties properties) {
        return MlKem.getInstance(properties.getParameterSet());
    }

    /**
     * Creates the hybrid envelope cipher backed by the auto-configured ML-KEM instance.
     *
     * @param mlKem the ML-KEM instance
     * @return a thread safe hybrid cipher
     */
    @Bean
    @ConditionalOnMissingBean
    public HybridCipher hybridCipher(MlKem mlKem) {
        return HybridCipher.using(mlKem);
    }

    /**
     * Registers the actuator health indicator when Spring Boot Actuator is present. The class
     * name is checked as a string so that the auto-configuration can load on applications
     * without Actuator.
     */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = "org.springframework.boot.health.contributor.HealthIndicator")
    @ConditionalOnProperty(
            prefix = "postquantum",
            name = "health-indicator-enabled",
            havingValue = "true",
            matchIfMissing = true)
    static class HealthIndicatorConfiguration {

        @Bean
        @ConditionalOnMissingBean(name = "mlKemHealthIndicator")
        MlKemHealthIndicator mlKemHealthIndicator(MlKem mlKem, HybridCipher hybridCipher) {
            return new MlKemHealthIndicator(mlKem, hybridCipher);
        }
    }
}
