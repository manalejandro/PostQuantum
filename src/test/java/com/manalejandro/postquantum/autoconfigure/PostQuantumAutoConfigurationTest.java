/*
 * Copyright (c) 2026 manalejandro
 *
 * MIT License - see the LICENSE file at the root of the repository.
 */

package com.manalejandro.postquantum.autoconfigure;

import com.manalejandro.postquantum.core.MlKem;
import com.manalejandro.postquantum.core.MlKemParameterSet;
import com.manalejandro.postquantum.health.MlKemHealthIndicator;
import com.manalejandro.postquantum.hybrid.HybridCipher;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

class PostQuantumAutoConfigurationTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(PostQuantumAutoConfiguration.class));

    @Test
    void registersMlKemAndHybridCipherByDefault() {
        contextRunner.run(context -> {
            assertThat(context).hasSingleBean(MlKem.class);
            assertThat(context).hasSingleBean(HybridCipher.class);
            assertThat(context).hasSingleBean(PostQuantumProperties.class);
            assertThat(context).hasSingleBean(MlKemHealthIndicator.class);

            MlKem mlKem = context.getBean(MlKem.class);
            assertThat(mlKem.getParameterSet()).isEqualTo(MlKemParameterSet.ML_KEM_768);
            assertThat(context.getBean(HybridCipher.class).getParameterSet())
                    .isEqualTo(MlKemParameterSet.ML_KEM_768);
        });
    }

    @Test
    void bindsTheConfiguredParameterSet() {
        contextRunner
                .withPropertyValues("postquantum.parameter-set=ML-KEM-1024")
                .run(context -> {
                    assertThat(context.getBean(PostQuantumProperties.class).getParameterSet())
                            .isEqualTo(MlKemParameterSet.ML_KEM_1024);
                    assertThat(context.getBean(MlKem.class).getParameterSet())
                            .isEqualTo(MlKemParameterSet.ML_KEM_1024);
                    assertThat(context.getBean(HybridCipher.class).getParameterSet())
                            .isEqualTo(MlKemParameterSet.ML_KEM_1024);
                });
    }

    @Test
    void acceptsRelaxedParameterSetNames() {
        contextRunner
                .withPropertyValues("postquantum.parameter-set=ml_kem_512")
                .run(context -> assertThat(context.getBean(MlKem.class).getParameterSet())
                        .isEqualTo(MlKemParameterSet.ML_KEM_512));
    }

    @Test
    void canBeDisabled() {
        contextRunner
                .withPropertyValues("postquantum.enabled=false")
                .run(context -> {
                    assertThat(context).doesNotHaveBean(MlKem.class);
                    assertThat(context).doesNotHaveBean(HybridCipher.class);
                    assertThat(context).doesNotHaveBean(MlKemHealthIndicator.class);
                });
    }

    @Test
    void backsOffWhenTheApplicationDefinesItsOwnBeans() {
        MlKem custom = MlKem.getInstance(MlKemParameterSet.ML_KEM_512);
        contextRunner
                .withBean("customMlKem", MlKem.class, () -> custom)
                .run(context -> {
                    assertThat(context).hasSingleBean(MlKem.class);
                    assertThat(context.getBean(MlKem.class)).isSameAs(custom);
                    assertThat(context.getBean(HybridCipher.class).getParameterSet())
                            .isEqualTo(MlKemParameterSet.ML_KEM_512);
                });
    }

    @Test
    void backsOffTheHealthIndicatorWhenTheApplicationDefinesOne() {
        contextRunner
                .withBean(MlKemHealthIndicator.class, () -> new MlKemHealthIndicator(
                        MlKem.getInstance(MlKemParameterSet.ML_KEM_512),
                        HybridCipher.forParameterSet(MlKemParameterSet.ML_KEM_512)))
                .run(context -> {
                    assertThat(context).hasSingleBean(MlKemHealthIndicator.class);
                    assertThat(context.getBean(MlKemHealthIndicator.class)).isNotNull();
                });
    }

    @Test
    void canDisableTheHealthIndicatorOnly() {
        contextRunner
                .withPropertyValues("postquantum.health-indicator-enabled=false")
                .run(context -> {
                    assertThat(context).hasSingleBean(MlKem.class);
                    assertThat(context).doesNotHaveBean(MlKemHealthIndicator.class);
                });
    }
}
