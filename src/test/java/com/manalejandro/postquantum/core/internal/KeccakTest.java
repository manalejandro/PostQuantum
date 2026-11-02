/*
 * Copyright (c) 2026 manalejandro
 *
 * MIT License - see the LICENSE file at the root of the repository.
 */

package com.manalejandro.postquantum.core.internal;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Random;

import static org.assertj.core.api.Assertions.assertThat;

class KeccakTest {

    private static final HexFormat HEX = HexFormat.of();

    @Test
    void sha3MatchesKnownVectors() {
        assertThat(Keccak.sha3_256(new byte[0]))
                .isEqualTo(HEX.parseHex("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"));
        assertThat(Keccak.sha3_512(new byte[0]))
                .isEqualTo(HEX.parseHex("a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6"
                        + "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"));
        assertThat(Keccak.sha3_256("abc".getBytes(StandardCharsets.US_ASCII)))
                .isEqualTo(HEX.parseHex("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"));
    }

    @Test
    void sha3MatchesJdkForRandomInputs() throws Exception {
        MessageDigest sha3_256 = MessageDigest.getInstance("SHA3-256");
        MessageDigest sha3_512 = MessageDigest.getInstance("SHA3-512");
        Random random = new Random(20260813L);
        for (int length : new int[]{0, 1, 2, 7, 71, 72, 135, 136, 137, 500, 4096}) {
            byte[] input = new byte[length];
            random.nextBytes(input);
            assertThat(Keccak.sha3_256(input)).as("SHA3-256 length %d", length).isEqualTo(sha3_256.digest(input));
            assertThat(Keccak.sha3_512(input)).as("SHA3-512 length %d", length).isEqualTo(sha3_512.digest(input));
        }
    }

    @Test
    void shakeMatchesKnownVectors() {
        assertThat(Keccak.shake128(new byte[0], 32))
                .isEqualTo(HEX.parseHex("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"));
        assertThat(Keccak.shake256(new byte[0], 32))
                .isEqualTo(HEX.parseHex("46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"));
        assertThat(Keccak.shake256("abc".getBytes(StandardCharsets.US_ASCII), 64))
                .isEqualTo(HEX.parseHex("483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739"
                        + "d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4"));
        assertThat(Keccak.shake128("abc".getBytes(StandardCharsets.US_ASCII), 16))
                .isEqualTo(HEX.parseHex("5881092dd818bf5cf8a3ddb793fbcba7"));
    }

    @Test
    void incrementalSqueezingMatchesOneShot() {
        byte[] input = "incremental".getBytes(StandardCharsets.US_ASCII);
        Keccak.Sponge sponge = Keccak.shake128Xof(input);
        byte[] incremental = new byte[700];
        int offset = 0;
        while (offset < incremental.length) {
            int chunk = Math.min(13, incremental.length - offset);
            sponge.squeeze(incremental, offset, chunk);
            offset += chunk;
        }
        assertThat(incremental).isEqualTo(Keccak.shake128(input, incremental.length));
    }
}
