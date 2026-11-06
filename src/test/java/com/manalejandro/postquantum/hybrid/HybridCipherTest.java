/*
 * Copyright (c) 2026 manalejandro
 *
 * MIT License - see the LICENSE file at the root of the repository.
 */

package com.manalejandro.postquantum.hybrid;

import com.manalejandro.postquantum.core.MlKem;
import com.manalejandro.postquantum.core.MlKemKeyPair;
import com.manalejandro.postquantum.core.MlKemParameterSet;
import com.manalejandro.postquantum.core.MlKemPrivateKey;
import com.manalejandro.postquantum.core.MlKemPublicKey;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class HybridCipherTest {

    private static final byte[] MESSAGE = "attack at dawn".getBytes(StandardCharsets.UTF_8);

    @ParameterizedTest
    @EnumSource(MlKemParameterSet.class)
    void roundTripsForEveryParameterSet(MlKemParameterSet parameterSet) {
        HybridCipher cipher = HybridCipher.forParameterSet(parameterSet);
        MlKemKeyPair keyPair = cipher.generateKeyPair();

        byte[] envelope = cipher.encrypt(keyPair.publicKey(), MESSAGE);
        byte[] plaintext = cipher.decrypt(keyPair.privateKey(), envelope);

        assertThat(plaintext).isEqualTo(MESSAGE);
        assertThat(envelope).hasSize(HybridCipher.envelopeLength(parameterSet, MESSAGE.length));
    }

    @Test
    void roundTripsEmptyAndLargePayloads() {
        HybridCipher cipher = HybridCipher.forParameterSet(MlKemParameterSet.ML_KEM_768);
        MlKemKeyPair keyPair = cipher.generateKeyPair();

        assertThat(cipher.decrypt(keyPair.privateKey(), cipher.encrypt(keyPair.publicKey(), new byte[0])))
                .isEmpty();

        byte[] large = new byte[1024 * 1024];
        for (int i = 0; i < large.length; i++) {
            large[i] = (byte) (i * 31);
        }
        byte[] recovered = cipher.decrypt(keyPair.privateKey(), cipher.encrypt(keyPair.publicKey(), large));
        assertThat(recovered).isEqualTo(large);
    }

    @Test
    void authenticatesAssociatedData() {
        HybridCipher cipher = HybridCipher.forParameterSet(MlKemParameterSet.ML_KEM_768);
        MlKemKeyPair keyPair = cipher.generateKeyPair();
        byte[] associatedData = "tenant-42".getBytes(StandardCharsets.UTF_8);

        byte[] envelope = cipher.encrypt(keyPair.publicKey(), MESSAGE, associatedData);
        assertThat(cipher.decrypt(keyPair.privateKey(), envelope, associatedData)).isEqualTo(MESSAGE);
        assertThat(envelope).hasSameSizeAs(cipher.encrypt(keyPair.publicKey(), MESSAGE));

        assertThatThrownBy(() -> cipher.decrypt(
                keyPair.privateKey(), envelope, "tenant-43".getBytes(StandardCharsets.UTF_8)))
                .isInstanceOf(HybridDecryptionException.class)
                .hasMessageContaining("authentication failed");
        assertThatThrownBy(() -> cipher.decrypt(keyPair.privateKey(), envelope))
                .isInstanceOf(HybridDecryptionException.class);
    }

    @Test
    void writesASelfDescribingHeader() {
        for (MlKemParameterSet parameterSet : MlKemParameterSet.values()) {
            HybridCipher cipher = HybridCipher.forParameterSet(parameterSet);
            MlKemKeyPair keyPair = cipher.generateKeyPair();
            byte[] envelope = cipher.encrypt(keyPair.publicKey(), MESSAGE);

            assertThat(Arrays.copyOfRange(envelope, 0, 4))
                    .isEqualTo(new byte[]{'P', 'Q', 'H', 0x01});
            assertThat(envelope[4]).isEqualTo((byte) parameterSet.identifier());
            assertThat(envelope[5]).isZero();
            assertThat(HybridCipher.inspectParameterSet(envelope)).isEqualTo(parameterSet);
            assertThat(HybridCipher.isEnvelope(envelope)).isTrue();
        }
    }

    @Test
    void usesAFreshNonceForEveryEnvelope() {
        HybridCipher cipher = HybridCipher.forParameterSet(MlKemParameterSet.ML_KEM_512);
        MlKemKeyPair keyPair = cipher.generateKeyPair();

        Set<String> nonces = new HashSet<>();
        Set<String> ciphertexts = new HashSet<>();
        for (int i = 0; i < 64; i++) {
            byte[] envelope = cipher.encrypt(keyPair.publicKey(), MESSAGE);
            nonces.add(java.util.HexFormat.of().formatHex(
                    Arrays.copyOfRange(envelope, 6, HybridCipher.HEADER_LENGTH)));
            ciphertexts.add(java.util.HexFormat.of().formatHex(envelope));
        }

        assertThat(nonces).hasSize(64);
        assertThat(ciphertexts).hasSize(64);
    }

    @Test
    void rejectsTamperedHeaders() {
        HybridCipher cipher = HybridCipher.forParameterSet(MlKemParameterSet.ML_KEM_768);
        MlKemKeyPair keyPair = cipher.generateKeyPair();
        byte[] envelope = cipher.encrypt(keyPair.publicKey(), MESSAGE);

        byte[] badMagic = envelope.clone();
        badMagic[0] = 'X';
        assertThatThrownBy(() -> cipher.decrypt(keyPair.privateKey(), badMagic))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("not a PostQuantum envelope");
        assertThat(HybridCipher.isEnvelope(badMagic)).isFalse();

        byte[] badIdentifier = envelope.clone();
        badIdentifier[4] = 3;
        assertThatThrownBy(() -> cipher.decrypt(keyPair.privateKey(), badIdentifier))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("parameter set id 3");

        byte[] badFlags = envelope.clone();
        badFlags[5] = 1;
        assertThatThrownBy(() -> cipher.decrypt(keyPair.privateKey(), badFlags))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("unsupported envelope flags");
    }

    @Test
    void rejectsTamperedNonceCiphertextAndTag() {
        HybridCipher cipher = HybridCipher.forParameterSet(MlKemParameterSet.ML_KEM_768);
        MlKemKeyPair keyPair = cipher.generateKeyPair();
        byte[] envelope = cipher.encrypt(keyPair.publicKey(), MESSAGE);

        assertTamperingIsDetected(cipher, keyPair, envelope, 6);
        assertTamperingIsDetected(cipher, keyPair, envelope, HybridCipher.HEADER_LENGTH);
        assertTamperingIsDetected(cipher, keyPair, envelope, HybridCipher.HEADER_LENGTH + 100);
        assertTamperingIsDetected(cipher, keyPair, envelope, envelope.length - 1);
        assertTamperingIsDetected(cipher, keyPair, envelope, envelope.length - HybridCipher.TAG_LENGTH);
    }

    @Test
    void rejectsTruncatedAndExtendedEnvelopes() {
        HybridCipher cipher = HybridCipher.forParameterSet(MlKemParameterSet.ML_KEM_768);
        MlKemKeyPair keyPair = cipher.generateKeyPair();
        byte[] envelope = cipher.encrypt(keyPair.publicKey(), MESSAGE);

        assertThatThrownBy(() -> cipher.decrypt(keyPair.privateKey(), new byte[0]))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("invalid envelope length");
        assertThatThrownBy(() -> cipher.decrypt(
                keyPair.privateKey(), Arrays.copyOf(envelope, HybridCipher.HEADER_LENGTH + 100)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("invalid envelope length");

        // Dropping a single byte keeps the envelope above the minimum length, so the failure is
        // reported as an authentication error rather than a format error.
        assertThatThrownBy(() -> cipher.decrypt(
                keyPair.privateKey(), Arrays.copyOf(envelope, envelope.length - 1)))
                .isInstanceOf(HybridDecryptionException.class);

        byte[] extended = Arrays.copyOf(envelope, envelope.length + 1);
        assertThatThrownBy(() -> cipher.decrypt(keyPair.privateKey(), extended))
                .isInstanceOf(HybridDecryptionException.class);
    }

    @Test
    void failsWhenTheEnvelopeBelongsToAnotherParameterSet() {
        HybridCipher cipher512 = HybridCipher.forParameterSet(MlKemParameterSet.ML_KEM_512);
        HybridCipher cipher768 = HybridCipher.forParameterSet(MlKemParameterSet.ML_KEM_768);
        MlKemKeyPair keyPair768 = cipher768.generateKeyPair();
        byte[] envelope = cipher768.encrypt(keyPair768.publicKey(), MESSAGE);

        assertThatThrownBy(() -> cipher512.decrypt(keyPair768.privateKey(), envelope))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("parameter set id 2");

        MlKemKeyPair keyPair512 = cipher512.generateKeyPair();
        assertThatThrownBy(() -> cipher512.encrypt(keyPair768.publicKey(), MESSAGE))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("ML-KEM-768");
        assertThatThrownBy(() -> cipher768.encrypt(keyPair512.publicKey(), MESSAGE))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("ML-KEM-512");
    }

    @Test
    void failsWhenDecryptingWithTheWrongKey() {
        HybridCipher cipher = HybridCipher.forParameterSet(MlKemParameterSet.ML_KEM_1024);
        MlKemKeyPair intended = cipher.generateKeyPair();
        MlKemKeyPair other = cipher.generateKeyPair();
        byte[] envelope = cipher.encrypt(intended.publicKey(), MESSAGE);

        assertThatThrownBy(() -> cipher.decrypt(other.privateKey(), envelope))
                .isInstanceOf(HybridDecryptionException.class);
    }

    @Test
    void inspectsAndRejectsForeignData() {
        assertThatThrownBy(() -> HybridCipher.inspectParameterSet(new byte[3]))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("too short");
        assertThatThrownBy(() -> HybridCipher.inspectParameterSet(new byte[HybridCipher.HEADER_LENGTH]))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("not a PostQuantum envelope");

        byte[] unknownParameterSet = new byte[HybridCipher.HEADER_LENGTH];
        System.arraycopy(new byte[]{'P', 'Q', 'H', 0x01}, 0, unknownParameterSet, 0, 4);
        unknownParameterSet[4] = 9;
        assertThatThrownBy(() -> HybridCipher.inspectParameterSet(unknownParameterSet))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("unknown ML-KEM parameter set id");

        assertThat(HybridCipher.isEnvelope(null)).isFalse();
        assertThat(HybridCipher.isEnvelope(new byte[4])).isFalse();
    }

    @Test
    void computesEnvelopeLengths() {
        for (MlKemParameterSet parameterSet : MlKemParameterSet.values()) {
            assertThat(HybridCipher.envelopeLength(parameterSet, 0))
                    .isEqualTo(HybridCipher.HEADER_LENGTH + parameterSet.ciphertextLength() + HybridCipher.TAG_LENGTH);
        }
        assertThatThrownBy(() -> HybridCipher.envelopeLength(MlKemParameterSet.ML_KEM_512, -1))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> HybridCipher.envelopeLength(null, 10))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void rejectsEnvelopeLengthsThatWouldOverflow() {
        for (MlKemParameterSet parameterSet : MlKemParameterSet.values()) {
            int overhead = HybridCipher.HEADER_LENGTH + parameterSet.ciphertextLength() + HybridCipher.TAG_LENGTH;
            assertThat(HybridCipher.envelopeLength(parameterSet, Integer.MAX_VALUE - overhead))
                    .as("%s at the maximum representable length", parameterSet)
                    .isEqualTo(Integer.MAX_VALUE);

            assertThatThrownBy(() -> HybridCipher.envelopeLength(parameterSet, Integer.MAX_VALUE - overhead + 1))
                    .as("%s one byte past the maximum", parameterSet)
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Integer.MAX_VALUE");
        }
        assertThatThrownBy(() -> HybridCipher.envelopeLength(MlKemParameterSet.ML_KEM_768, Integer.MAX_VALUE))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void canReuseAnExistingMlKemInstance() {
        MlKem mlKem = MlKem.getInstance(MlKemParameterSet.ML_KEM_768);
        HybridCipher cipher = HybridCipher.using(mlKem);
        MlKemKeyPair keyPair = cipher.generateKeyPair();

        assertThat(cipher.getParameterSet()).isEqualTo(MlKemParameterSet.ML_KEM_768);
        assertThat(keyPair.privateKey().getParameterSet()).isEqualTo(mlKem.getParameterSet());
        assertThat(cipher.decrypt(keyPair.privateKey(), cipher.encrypt(keyPair.publicKey(), MESSAGE)))
                .isEqualTo(MESSAGE);
        assertThat(cipher.toString())
                .contains("ML-KEM-768")
                .contains("HKDF-SHA256")
                .contains("AES-256-GCM");
    }

    @Test
    void rejectsNullArguments() {
        HybridCipher cipher = HybridCipher.forParameterSet(MlKemParameterSet.ML_KEM_512);
        MlKemKeyPair keyPair = cipher.generateKeyPair();
        MlKemPublicKey publicKey = keyPair.publicKey();
        MlKemPrivateKey privateKey = keyPair.privateKey();
        byte[] envelope = cipher.encrypt(publicKey, MESSAGE);

        assertThatThrownBy(() -> HybridCipher.forParameterSet(null))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> HybridCipher.forParameterSet(MlKemParameterSet.ML_KEM_512, null))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> HybridCipher.using(null)).isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> cipher.encrypt(null, MESSAGE)).isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> cipher.encrypt(publicKey, null)).isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> cipher.encrypt(publicKey, MESSAGE, null))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> cipher.decrypt(null, envelope)).isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> cipher.decrypt(privateKey, null)).isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> cipher.decrypt(privateKey, envelope, null))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> HybridCipher.inspectParameterSet(null))
                .isInstanceOf(NullPointerException.class);
    }

    private static void assertTamperingIsDetected(
            HybridCipher cipher, MlKemKeyPair keyPair, byte[] envelope, int offset) {
        byte[] tampered = envelope.clone();
        tampered[offset] ^= 0x01;
        assertThatThrownBy(() -> cipher.decrypt(keyPair.privateKey(), tampered))
                .as("tampering at offset %d must be detected", offset)
                .isInstanceOf(HybridDecryptionException.class)
                .hasMessageContaining("authentication failed");
    }
}
