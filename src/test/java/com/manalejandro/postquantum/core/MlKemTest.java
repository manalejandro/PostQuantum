/*
 * Copyright (c) 2026 manalejandro
 *
 * MIT License - see the LICENSE file at the root of the repository.
 */

package com.manalejandro.postquantum.core;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Behavioural tests for the public ML-KEM API. The cryptographic correctness against NIST is
 * covered by {@code AcvpMlKemTest}; this class covers the contract of the public surface.
 */
class MlKemTest {

    @ParameterizedTest
    @EnumSource(MlKemParameterSet.class)
    void encapsulatesAndDecapsulatesForEveryParameterSet(MlKemParameterSet parameterSet) {
        MlKem mlKem = MlKem.getInstance(parameterSet);

        MlKemKeyPair keyPair = mlKem.generateKeyPair();
        MlKemEncapsulation encapsulation = mlKem.encapsulate(keyPair.publicKey());
        byte[] recovered = mlKem.decapsulate(keyPair.privateKey(), encapsulation.getCiphertext());

        assertThat(recovered).isEqualTo(encapsulation.getSharedSecret());
        assertThat(encapsulation.getSharedSecret()).hasSize(32);
        assertThat(encapsulation.getCiphertext()).hasSize(parameterSet.ciphertextLength());
    }

    @ParameterizedTest
    @EnumSource(MlKemParameterSet.class)
    void reportsTheSizesRequiredByFips203(MlKemParameterSet parameterSet) {
        MlKemKeyPair keyPair = MlKem.getInstance(parameterSet).generateKeyPair();

        assertThat(keyPair.publicKey().getEncoded()).hasSize(parameterSet.encapsulationKeyLength());
        assertThat(keyPair.privateKey().getEncoded()).hasSize(parameterSet.decapsulationKeyLength());
    }

    @Test
    void usesTheExpectedSizesForTheThreeStandardParameterSets() {
        assertThat(MlKemParameterSet.ML_KEM_512.encapsulationKeyLength()).isEqualTo(800);
        assertThat(MlKemParameterSet.ML_KEM_512.decapsulationKeyLength()).isEqualTo(1632);
        assertThat(MlKemParameterSet.ML_KEM_512.ciphertextLength()).isEqualTo(768);

        assertThat(MlKemParameterSet.ML_KEM_768.encapsulationKeyLength()).isEqualTo(1184);
        assertThat(MlKemParameterSet.ML_KEM_768.decapsulationKeyLength()).isEqualTo(2400);
        assertThat(MlKemParameterSet.ML_KEM_768.ciphertextLength()).isEqualTo(1088);

        assertThat(MlKemParameterSet.ML_KEM_1024.encapsulationKeyLength()).isEqualTo(1568);
        assertThat(MlKemParameterSet.ML_KEM_1024.decapsulationKeyLength()).isEqualTo(3168);
        assertThat(MlKemParameterSet.ML_KEM_1024.ciphertextLength()).isEqualTo(1568);
    }

    @ParameterizedTest
    @EnumSource(MlKemParameterSet.class)
    void generatesDistinctKeysAndCiphertexts(MlKemParameterSet parameterSet) {
        MlKem mlKem = MlKem.getInstance(parameterSet);

        MlKemKeyPair first = mlKem.generateKeyPair();
        MlKemKeyPair second = mlKem.generateKeyPair();
        assertThat(first.publicKey()).isNotEqualTo(second.publicKey());
        assertThat(first.privateKey()).isNotEqualTo(second.privateKey());

        byte[] ciphertextA = mlKem.encapsulate(first.publicKey()).getCiphertext();
        byte[] ciphertextB = mlKem.encapsulate(first.publicKey()).getCiphertext();
        assertThat(ciphertextA).isNotEqualTo(ciphertextB);
    }

    @ParameterizedTest
    @EnumSource(MlKemParameterSet.class)
    void derivesTheSameKeyPairFromTheSameSeed(MlKemParameterSet parameterSet) {
        MlKem mlKem = MlKem.getInstance(parameterSet);
        byte[] seed = new byte[64];
        for (int i = 0; i < seed.length; i++) {
            seed[i] = (byte) i;
        }

        MlKemKeyPair first = mlKem.generateKeyPair(seed);
        MlKemKeyPair second = mlKem.generateKeyPair(seed.clone());

        assertThat(first).isEqualTo(second);
        assertThat(first.publicKey()).isEqualTo(second.publicKey());
        assertThat(first.privateKey()).isEqualTo(second.privateKey());

        byte[] otherSeed = seed.clone();
        otherSeed[0] ^= 0x01;
        assertThat(mlKem.generateKeyPair(otherSeed).publicKey()).isNotEqualTo(first.publicKey());

        MlKemEncapsulation encapsulation = mlKem.encapsulate(first.publicKey());
        assertThat(mlKem.decapsulate(first.privateKey(), encapsulation.getCiphertext()))
                .isEqualTo(encapsulation.getSharedSecret());
    }

    @Test
    void rejectsSeedsWithTheWrongLength() {
        MlKem mlKem = MlKem.getInstance(MlKemParameterSet.ML_KEM_768);

        assertThatThrownBy(() -> mlKem.generateKeyPair(new byte[63]))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("64 bytes");
        assertThatThrownBy(() -> mlKem.generateKeyPair(new byte[65]))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("64 bytes");
        assertThatThrownBy(() -> mlKem.generateKeyPair(null))
                .isInstanceOf(NullPointerException.class);
    }

    @ParameterizedTest
    @EnumSource(MlKemParameterSet.class)
    void rejectsTamperedCiphertextsThroughImplicitRejection(MlKemParameterSet parameterSet) {
        MlKem mlKem = MlKem.getInstance(parameterSet);
        MlKemKeyPair keyPair = mlKem.generateKeyPair();
        MlKemEncapsulation encapsulation = mlKem.encapsulate(keyPair.publicKey());

        byte[] tampered = encapsulation.getCiphertext();
        tampered[0] ^= 0x01;

        byte[] rejectedA = mlKem.decapsulate(keyPair.privateKey(), tampered);
        byte[] rejectedB = mlKem.decapsulate(keyPair.privateKey(), tampered);

        assertThat(rejectedA).hasSize(32);
        assertThat(rejectedA).isNotEqualTo(encapsulation.getSharedSecret());
        // Implicit rejection is deterministic, as required by FIPS 203.
        assertThat(rejectedA).isEqualTo(rejectedB);
    }

    @Test
    void implicitRejectionDependsOnTheCiphertext() {
        MlKem mlKem = MlKem.getInstance(MlKemParameterSet.ML_KEM_768);
        MlKemKeyPair keyPair = mlKem.generateKeyPair();
        byte[] ciphertext = mlKem.encapsulate(keyPair.publicKey()).getCiphertext();

        byte[] tamperedA = ciphertext.clone();
        tamperedA[10] ^= 0x01;
        byte[] tamperedB = ciphertext.clone();
        tamperedB[11] ^= 0x01;

        assertThat(mlKem.decapsulate(keyPair.privateKey(), tamperedA))
                .isNotEqualTo(mlKem.decapsulate(keyPair.privateKey(), tamperedB));
    }

    @Test
    void rejectsKeysAndCiphertextsFromAnotherParameterSet() {
        MlKem mlKem512 = MlKem.getInstance(MlKemParameterSet.ML_KEM_512);
        MlKem mlKem768 = MlKem.getInstance(MlKemParameterSet.ML_KEM_768);
        MlKemKeyPair keyPair512 = mlKem512.generateKeyPair();
        MlKemKeyPair keyPair768 = mlKem768.generateKeyPair();

        assertThatThrownBy(() -> mlKem512.encapsulate(keyPair768.publicKey()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("ML-KEM-768");

        byte[] ciphertext512 = mlKem512.encapsulate(keyPair512.publicKey()).getCiphertext();
        assertThatThrownBy(() -> mlKem768.decapsulate(keyPair512.privateKey(), ciphertext512))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("ML-KEM-512");
    }

    @Test
    void rejectsMalformedCiphertextLengths() {
        MlKem mlKem = MlKem.getInstance(MlKemParameterSet.ML_KEM_768);
        MlKemKeyPair keyPair = mlKem.generateKeyPair();

        assertThatThrownBy(() -> mlKem.decapsulate(keyPair.privateKey(), new byte[0]))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("invalid ciphertext length");
        assertThatThrownBy(() -> mlKem.decapsulate(keyPair.privateKey(), new byte[1087]))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("expected 1088");
    }

    @Test
    void rejectsNullArguments() {
        MlKem mlKem = MlKem.getInstance(MlKemParameterSet.ML_KEM_768);
        MlKemKeyPair keyPair = mlKem.generateKeyPair();

        assertThatThrownBy(() -> MlKem.getInstance(null)).isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> MlKem.getInstance(MlKemParameterSet.ML_KEM_768, null))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> mlKem.encapsulate(null)).isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> mlKem.decapsulate(null, new byte[1088]))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> mlKem.decapsulate(keyPair.privateKey(), null))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void validatesEncapsulationKeys() {
        MlKem mlKem = MlKem.getInstance(MlKemParameterSet.ML_KEM_768);
        MlKemKeyPair keyPair = mlKem.generateKeyPair();
        byte[] encoded = keyPair.publicKey().getEncoded();

        assertThat(mlKem.isValidEncapsulationKey(encoded)).isTrue();
        assertThat(mlKem.isValidEncapsulationKey(Arrays.copyOf(encoded, 10))).isFalse();
        assertThat(mlKem.isValidEncapsulationKey(null)).isFalse();

        // 0x0FFF = 4095 is greater than q - 1 = 3328, so the modulus check must fail.
        byte[] nonCanonical = encoded.clone();
        nonCanonical[0] = (byte) 0xFF;
        nonCanonical[1] = (byte) 0x0F;
        assertThat(mlKem.isValidEncapsulationKey(nonCanonical)).isFalse();
        assertThatThrownBy(() -> mlKem.encapsulate(MlKemPublicKey.fromEncoded(
                MlKemParameterSet.ML_KEM_768, nonCanonical)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("input validation");
    }

    @Test
    void validatesDecapsulationKeys() {
        MlKem mlKem = MlKem.getInstance(MlKemParameterSet.ML_KEM_768);
        MlKemKeyPair keyPair = mlKem.generateKeyPair();
        byte[] encoded = keyPair.privateKey().getEncoded();

        assertThat(mlKem.isValidDecapsulationKey(encoded)).isTrue();
        assertThat(mlKem.isValidDecapsulationKey(Arrays.copyOf(encoded, 10))).isFalse();
        assertThat(mlKem.isValidDecapsulationKey(null)).isFalse();

        // The embedded H(ek) no longer matches after modifying the stored public key.
        byte[] tampered = encoded.clone();
        tampered[384 * MlKemParameterSet.ML_KEM_768.rank() + 10] ^= 0x01;
        assertThat(mlKem.isValidDecapsulationKey(tampered)).isFalse();
    }

    @Test
    void keysAreImmutableAndComparable() {
        MlKem mlKem = MlKem.getInstance(MlKemParameterSet.ML_KEM_512);
        MlKemKeyPair keyPair = mlKem.generateKeyPair();

        byte[] publicBytes = keyPair.publicKey().getEncoded();
        publicBytes[0] ^= 0x01;
        assertThat(keyPair.publicKey().getEncoded()).isNotEqualTo(publicBytes);
        assertThat(MlKemPublicKey.fromEncoded(MlKemParameterSet.ML_KEM_512, keyPair.publicKey().getEncoded()))
                .isEqualTo(keyPair.publicKey())
                .hasSameHashCodeAs(keyPair.publicKey());

        byte[] privateBytes = keyPair.privateKey().getEncoded();
        privateBytes[0] ^= 0x01;
        assertThat(keyPair.privateKey().getEncoded()).isNotEqualTo(privateBytes);
        assertThat(MlKemPrivateKey.fromEncoded(MlKemParameterSet.ML_KEM_512, keyPair.privateKey().getEncoded()))
                .isEqualTo(keyPair.privateKey())
                .hasSameHashCodeAs(keyPair.privateKey());
    }

    @Test
    void exposesThePublicKeyEmbeddedInThePrivateKey() {
        for (MlKemParameterSet parameterSet : MlKemParameterSet.values()) {
            MlKemKeyPair keyPair = MlKem.getInstance(parameterSet).generateKeyPair();
            assertThat(keyPair.privateKey().getPublicKey()).isEqualTo(keyPair.publicKey());
            assertThat(keyPair.privateKey().getPublicKey().getParameterSet()).isEqualTo(parameterSet);
        }
    }

    @Test
    void rejectsKeysWithWrongEncodedLength() {
        assertThatThrownBy(() -> MlKemPublicKey.fromEncoded(MlKemParameterSet.ML_KEM_1024, new byte[10]))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("expected 1568");
        assertThatThrownBy(() -> MlKemPrivateKey.fromEncoded(MlKemParameterSet.ML_KEM_1024, new byte[10]))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("expected 3168");
        assertThatThrownBy(() -> MlKemPublicKey.fromEncoded(null, new byte[800]))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> MlKemPrivateKey.fromEncoded(MlKemParameterSet.ML_KEM_512, null))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void keyPairRejectsMismatchedOrMissingComponents() {
        MlKemKeyPair keyPair512 = MlKem.getInstance(MlKemParameterSet.ML_KEM_512).generateKeyPair();
        MlKemKeyPair keyPair768 = MlKem.getInstance(MlKemParameterSet.ML_KEM_768).generateKeyPair();

        assertThatThrownBy(() -> new MlKemKeyPair(keyPair512.publicKey(), keyPair768.privateKey()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("different parameter sets");
        assertThatThrownBy(() -> new MlKemKeyPair(null, keyPair512.privateKey()))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new MlKemKeyPair(keyPair512.publicKey(), null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void neverPrintsPrivateKeyMaterial() {
        MlKemKeyPair keyPair = MlKem.getInstance(MlKemParameterSet.ML_KEM_768).generateKeyPair();

        assertThat(keyPair.privateKey().toString())
                .contains("MlKemPrivateKey")
                .contains("ML-KEM-768")
                .doesNotContain(bytesToHex(keyPair.privateKey().getEncoded()));
        assertThat(keyPair.publicKey().toString()).contains("MlKemPublicKey").contains("1184 bytes");
        assertThat(keyPair.toString()).doesNotContain(bytesToHex(keyPair.privateKey().getEncoded()));
    }

    @Test
    void redactsSharedSecretsInToString() {
        MlKem mlKem = MlKem.getInstance(MlKemParameterSet.ML_KEM_512);
        MlKemKeyPair keyPair = mlKem.generateKeyPair();
        MlKemEncapsulation encapsulation = mlKem.encapsulate(keyPair.publicKey());

        assertThat(encapsulation.toString())
                .contains("sharedSecret=redacted")
                .doesNotContain(bytesToHex(encapsulation.getSharedSecret()));
        assertThat(encapsulation.getCiphertext()).isNotSameAs(encapsulation.getCiphertext());
        assertThat(encapsulation.getSharedSecret()).isNotSameAs(encapsulation.getSharedSecret());
        assertThat(mlKem.toString()).isEqualTo("MlKem[ML-KEM-512]");
    }

    @Test
    void resolvesParameterSetsFromNames() {
        assertThat(MlKemParameterSet.fromName("ML-KEM-512")).isEqualTo(MlKemParameterSet.ML_KEM_512);
        assertThat(MlKemParameterSet.fromName("ML-KEM-768")).isEqualTo(MlKemParameterSet.ML_KEM_768);
        assertThat(MlKemParameterSet.fromName("ML-KEM-1024")).isEqualTo(MlKemParameterSet.ML_KEM_1024);
        assertThat(MlKemParameterSet.fromName("ml_kem_1024")).isEqualTo(MlKemParameterSet.ML_KEM_1024);
        assertThat(MlKemParameterSet.fromName(" mlkem768 ")).isEqualTo(MlKemParameterSet.ML_KEM_768);
        assertThat(MlKemParameterSet.fromName("ML_KEM_512")).isEqualTo(MlKemParameterSet.ML_KEM_512);

        assertThatThrownBy(() -> MlKemParameterSet.fromName("ML-KEM-2048"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("unknown ML-KEM parameter set");
        assertThatThrownBy(() -> MlKemParameterSet.fromName(null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void exposesStableEnvelopeIdentifiers() {
        Set<Integer> identifiers = new HashSet<>();
        for (MlKemParameterSet parameterSet : MlKemParameterSet.values()) {
            identifiers.add(parameterSet.identifier());
            assertThat(parameterSet.algorithmName()).startsWith("ML-KEM-");
            assertThat(parameterSet.sharedSecretLength()).isEqualTo(32);
            assertThat(parameterSet.rank()).isBetween(2, 4);
        }
        assertThat(identifiers).containsExactlyInAnyOrder(1, 2, 3);
    }

    @Test
    void supportsExplicitRandomnessForReproducibleKeys() {
        MlKem mlKem = MlKem.getInstance(MlKemParameterSet.ML_KEM_768);
        byte[] d = "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.US_ASCII);
        byte[] z = "fedcba9876543210fedcba9876543210".getBytes(StandardCharsets.US_ASCII);

        MlKemKeyPair first = mlKem.generateKeyPair(d, z);
        MlKemKeyPair second = mlKem.generateKeyPair(d, z);

        assertThat(first.publicKey()).isEqualTo(second.publicKey());
        assertThat(first.privateKey()).isEqualTo(second.privateKey());
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder builder = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            builder.append(String.format("%02x", value));
        }
        return builder.toString();
    }
}
