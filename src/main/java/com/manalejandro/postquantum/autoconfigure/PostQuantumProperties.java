/*
 * Copyright (c) 2026 manalejandro
 *
 * MIT License - see the LICENSE file at the root of the repository.
 */

package com.manalejandro.postquantum.autoconfigure;

import com.manalejandro.postquantum.core.MlKemParameterSet;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration for the PostQuantum auto-configuration.
 *
 * <p>All properties live under the {@code postquantum} prefix:
 *
 * <pre>
 * postquantum:
 *   enabled: true
 *   parameter-set: ML-KEM-768
 *   health-indicator-enabled: true
 * </pre>
 */
@ConfigurationProperties(prefix = "postquantum")
public class PostQuantumProperties {

    /**
     * Whether the ML-KEM and hybrid cipher beans are created. Set to {@code false} to keep the
     * library on the classpath without registering any bean.
     */
    private boolean enabled = true;

    /**
     * ML-KEM parameter set used by the auto-configured beans. One of {@code ML-KEM-512},
     * {@code ML-KEM-768} or {@code ML-KEM-1024}.
     */
    private MlKemParameterSet parameterSet = MlKemParameterSet.ML_KEM_768;

    /**
     * Whether the {@code mlKem} health indicator is registered. Requires Spring Boot Actuator
     * and a health endpoint on the classpath.
     */
    private boolean healthIndicatorEnabled = true;

    /**
     * Creates an empty properties object populated by Spring Boot's configuration binder.
     */
    public PostQuantumProperties() {
    }

    /**
     * Whether the ML-KEM and hybrid cipher beans are created.
     *
     * @return whether the ML-KEM and hybrid cipher beans are created
     */
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Sets whether the ML-KEM and hybrid cipher beans are created.
     *
     * @param enabled {@code false} to disable the auto-configuration
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * The ML-KEM parameter set used by the auto-configured beans.
     *
     * @return the ML-KEM parameter set used by the auto-configured beans
     */
    public MlKemParameterSet getParameterSet() {
        return parameterSet;
    }

    /**
     * Sets the ML-KEM parameter set used by the auto-configured beans.
     *
     * @param parameterSet the parameter set to use
     */
    public void setParameterSet(MlKemParameterSet parameterSet) {
        this.parameterSet = parameterSet;
    }

    /**
     * Whether the Actuator health indicator is registered.
     *
     * @return whether the Actuator health indicator is registered
     */
    public boolean isHealthIndicatorEnabled() {
        return healthIndicatorEnabled;
    }

    /**
     * Sets whether the Actuator health indicator is registered.
     *
     * @param healthIndicatorEnabled {@code false} to skip the health indicator
     */
    public void setHealthIndicatorEnabled(boolean healthIndicatorEnabled) {
        this.healthIndicatorEnabled = healthIndicatorEnabled;
    }

    @Override
    public String toString() {
        return "PostQuantumProperties[enabled=" + enabled
                + ", parameterSet=" + parameterSet
                + ", healthIndicatorEnabled=" + healthIndicatorEnabled + "]";
    }
}
