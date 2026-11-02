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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.Status;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class MlKemHealthIndicatorTest {

    @ParameterizedTest
    @EnumSource(MlKemParameterSet.class)
    void reportsUpWithDetailsForEveryParameterSet(MlKemParameterSet parameterSet) {
        MlKem mlKem = MlKem.getInstance(parameterSet);
        MlKemHealthIndicator indicator = new MlKemHealthIndicator(
                mlKem, HybridCipher.using(mlKem));

        Health health = indicator.health();

        assertThat(health.getStatus()).isEqualTo(Status.UP);
        assertThat(health.getDetails())
                .containsEntry("parameterSet", parameterSet.algorithmName())
                .containsEntry("encapsulationKeyLength", parameterSet.encapsulationKeyLength())
                .containsEntry("ciphertextLength", parameterSet.ciphertextLength())
                .containsEntry("hybridCipher", "ML-KEM + HKDF-SHA256 + AES-256-GCM");
    }

    @Test
    void reportsDownWhenTheSharedSecretsDoNotMatch() {
        MlKem mlKem = mock(MlKem.class);
        MlKem real = MlKem.getInstance(MlKemParameterSet.ML_KEM_768);
        MlKemKeyPair keyPair = real.generateKeyPair();
        MlKemEncapsulation encapsulation = real.encapsulate(keyPair.publicKey());

        when(mlKem.getParameterSet()).thenReturn(MlKemParameterSet.ML_KEM_768);
        when(mlKem.generateKeyPair()).thenReturn(keyPair);
        when(mlKem.encapsulate(any())).thenReturn(encapsulation);
        when(mlKem.decapsulate(any(), any())).thenReturn(new byte[32]);

        Health health = new MlKemHealthIndicator(mlKem, HybridCipher.using(real)).health();

        assertThat(health.getStatus()).isEqualTo(Status.DOWN);
        assertThat(health.getDetails()).containsEntry("reason", "ML-KEM shared secrets do not match");
    }

    @Test
    void reportsDownWhenTheHybridRoundTripFails() {
        MlKem mlKem = MlKem.getInstance(MlKemParameterSet.ML_KEM_768);
        HybridCipher cipher = mock(HybridCipher.class);
        when(cipher.encrypt(any(), any())).thenReturn(new byte[0]);
        when(cipher.decrypt(any(), any())).thenReturn(new byte[0]);

        Health health = new MlKemHealthIndicator(mlKem, cipher).health();

        assertThat(health.getStatus()).isEqualTo(Status.DOWN);
        assertThat(health.getDetails()).containsEntry("reason", "hybrid cipher round trip failed");
    }

    @Test
    void reportsDownWhenTheHealthCheckThrows() {
        MlKem mlKem = mock(MlKem.class);
        when(mlKem.getParameterSet()).thenReturn(MlKemParameterSet.ML_KEM_768);
        when(mlKem.generateKeyPair()).thenThrow(new IllegalStateException("entropy source unavailable"));

        Health health = new MlKemHealthIndicator(mlKem, mock(HybridCipher.class)).health();

        assertThat(health.getStatus()).isEqualTo(Status.DOWN);
        assertThat(health.getDetails()).containsKey("error");
    }
}
