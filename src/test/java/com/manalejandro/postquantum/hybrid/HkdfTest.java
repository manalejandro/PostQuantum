/*
 * Copyright (c) 2026 manalejandro
 *
 * MIT License - see the LICENSE file at the root of the repository.
 */

package com.manalejandro.postquantum.hybrid;

import org.junit.jupiter.api.Test;

import java.util.HexFormat;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * HKDF-SHA256 test vectors from RFC 5869, Appendix A.
 */
class HkdfTest {

    private static final HexFormat HEX = HexFormat.of();

    @Test
    void matchesRfc5869TestCase1() {
        byte[] inputKeyMaterial = HEX.parseHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        byte[] salt = HEX.parseHex("000102030405060708090a0b0c");
        byte[] info = HEX.parseHex("f0f1f2f3f4f5f6f7f8f9");

        byte[] output = Hkdf.deriveKey(inputKeyMaterial, salt, info, 42);

        assertThat(HEX.formatHex(output)).isEqualTo(
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                        + "34007208d5b887185865");
    }

    @Test
    void matchesRfc5869TestCase2WithLongerInputs() {
        byte[] inputKeyMaterial = hexSequence(0x00, 0x4f);
        byte[] salt = hexSequence(0x60, 0xaf);
        byte[] info = hexSequence(0xb0, 0xff);

        byte[] output = Hkdf.deriveKey(inputKeyMaterial, salt, info, 82);

        assertThat(HEX.formatHex(output)).isEqualTo(
                "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
                        + "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
                        + "cc30c58179ec3e87c14c01d5c1f3434f1d87");
    }

    @Test
    void matchesRfc5869TestCase3WithEmptySaltAndInfo() {
        byte[] inputKeyMaterial = HEX.parseHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        byte[] output = Hkdf.deriveKey(inputKeyMaterial, new byte[0], new byte[0], 42);

        assertThat(HEX.formatHex(output)).isEqualTo(
                "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
                        + "9d201395faa4b61a96c8");
    }

    @Test
    void rejectsInvalidOutputLengths() {
        byte[] inputKeyMaterial = new byte[32];
        assertThatThrownBy(() -> Hkdf.deriveKey(inputKeyMaterial, new byte[0], new byte[0], 0))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("invalid HKDF output length");
        assertThatThrownBy(() -> Hkdf.deriveKey(inputKeyMaterial, new byte[0], new byte[0], 255 * 32 + 1))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void producesDifferentKeysForDifferentSaltsOrInfo() {
        byte[] inputKeyMaterial = HEX.parseHex("0102030405060708090a0b0c0d0e0f10");
        byte[] saltA = HEX.parseHex("a0a1a2a3");
        byte[] saltB = HEX.parseHex("b0b1b2b3");

        byte[] withSaltA = Hkdf.deriveKey(inputKeyMaterial, saltA, new byte[0], 32);
        byte[] withSaltB = Hkdf.deriveKey(inputKeyMaterial, saltB, new byte[0], 32);
        byte[] withInfo = Hkdf.deriveKey(inputKeyMaterial, saltA, new byte[]{1}, 32);

        assertThat(withSaltA).isNotEqualTo(withSaltB).isNotEqualTo(withInfo);
    }

    private static byte[] hexSequence(int from, int to) {
        byte[] bytes = new byte[to - from + 1];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) (from + i);
        }
        return bytes;
    }
}
