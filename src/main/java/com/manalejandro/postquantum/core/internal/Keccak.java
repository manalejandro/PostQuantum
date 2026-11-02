/*
 * Copyright (c) 2026 manalejandro
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package com.manalejandro.postquantum.core.internal;

/**
 * Keccak sponge implementing the hash functions required by FIPS 203: SHA3-256, SHA3-512,
 * SHAKE128 and SHAKE256 (FIPS 202).
 *
 * <p>This class is an implementation detail of the ML-KEM engine and is not part of the public
 * API. It is intentionally small and dependency free.
 */
final class Keccak {

    private static final int KECCAK_ROUNDS = 24;
    private static final int STATE_LANES = 25;
    private static final int STATE_BYTES = STATE_LANES * Long.BYTES;

    private static final long[] ROUND_CONSTANTS = {
            0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL, 0x8000000080008000L,
            0x000000000000808bL, 0x0000000080000001L, 0x8000000080008081L, 0x8000000000008009L,
            0x000000000000008aL, 0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
            0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L, 0x8000000000008003L,
            0x8000000000008002L, 0x8000000000000080L, 0x000000000000800aL, 0x800000008000000aL,
            0x8000000080008081L, 0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
    };

    /** Rotation offsets for the combined rho/pi step. */
    private static final int[] ROTATIONS = {
            1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
            27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
    };

    /** Lane permutation for the combined rho/pi step. */
    private static final int[] PI_LANES = {
            10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
            15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
    };

    private static final int SHA3_256_RATE = 136;
    private static final int SHA3_512_RATE = 72;
    private static final int SHAKE128_RATE = 168;
    private static final int SHAKE256_RATE = 136;

    private static final byte SHA3_DOMAIN = 0x06;
    private static final byte SHAKE_DOMAIN = 0x1F;

    private Keccak() {
    }

    /** Computes SHA3-256 over {@code input}. */
    static byte[] sha3_256(byte[] input) {
        return digest(SHA3_256_RATE, SHA3_DOMAIN, input, 32);
    }

    /** Computes SHA3-512 over {@code input}. */
    static byte[] sha3_512(byte[] input) {
        return digest(SHA3_512_RATE, SHA3_DOMAIN, input, 64);
    }

    /** Computes SHAKE128 over {@code input}, producing {@code outputLength} bytes. */
    static byte[] shake128(byte[] input, int outputLength) {
        return digest(SHAKE128_RATE, SHAKE_DOMAIN, input, outputLength);
    }

    /** Computes SHAKE256 over {@code input}, producing {@code outputLength} bytes. */
    static byte[] shake256(byte[] input, int outputLength) {
        return digest(SHAKE256_RATE, SHAKE_DOMAIN, input, outputLength);
    }

    /**
     * Returns a SHAKE128 sponge that has already absorbed and padded {@code input}. Bytes can be
     * squeezed incrementally with {@link Sponge#squeeze(byte[], int, int)}.
     */
    static Sponge shake128Xof(byte[] input) {
        Sponge sponge = new Sponge(SHAKE128_RATE, SHAKE_DOMAIN);
        sponge.absorb(input, 0, input.length);
        sponge.pad();
        return sponge;
    }

    private static byte[] digest(int rate, byte domain, byte[] input, int outputLength) {
        Sponge sponge = new Sponge(rate, domain);
        sponge.absorb(input, 0, input.length);
        sponge.pad();
        byte[] output = new byte[outputLength];
        sponge.squeeze(output, 0, outputLength);
        return output;
    }

    private static void permute(long[] state) {
        long[] c = new long[5];
        for (int round = 0; round < KECCAK_ROUNDS; round++) {
            // theta
            for (int x = 0; x < 5; x++) {
                c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
            }
            for (int x = 0; x < 5; x++) {
                long d = c[(x + 4) % 5] ^ Long.rotateLeft(c[(x + 1) % 5], 1);
                for (int y = 0; y < 25; y += 5) {
                    state[y + x] ^= d;
                }
            }

            // rho and pi
            long current = state[1];
            for (int i = 0; i < 24; i++) {
                int target = PI_LANES[i];
                long saved = state[target];
                state[target] = Long.rotateLeft(current, ROTATIONS[i]);
                current = saved;
            }

            // chi
            for (int y = 0; y < 25; y += 5) {
                long s0 = state[y];
                long s1 = state[y + 1];
                long s2 = state[y + 2];
                long s3 = state[y + 3];
                long s4 = state[y + 4];
                state[y] = s0 ^ (~s1 & s2);
                state[y + 1] = s1 ^ (~s2 & s3);
                state[y + 2] = s2 ^ (~s3 & s4);
                state[y + 3] = s3 ^ (~s4 & s0);
                state[y + 4] = s4 ^ (~s0 & s1);
            }

            // iota
            state[0] ^= ROUND_CONSTANTS[round];
        }
    }

    /**
     * A Keccak sponge in absorb/squeeze mode. Instances are not thread safe.
     */
    static final class Sponge {

        private final long[] state = new long[STATE_LANES];
        private final int rate;
        private final byte domain;
        private int position;

        private Sponge(int rate, byte domain) {
            if (rate <= 0 || rate >= STATE_BYTES) {
                throw new IllegalArgumentException("invalid rate: " + rate);
            }
            this.rate = rate;
            this.domain = domain;
        }

        void absorb(byte[] input, int offset, int length) {
            for (int i = 0; i < length; i++) {
                int lane = position >>> 3;
                int shift = (position & 7) << 3;
                state[lane] ^= (long) (input[offset + i] & 0xFF) << shift;
                position++;
                if (position == rate) {
                    permute(state);
                    position = 0;
                }
            }
        }

        void pad() {
            int lane = position >>> 3;
            int shift = (position & 7) << 3;
            state[lane] ^= (long) (domain & 0xFF) << shift;

            int last = rate - 1;
            state[last >>> 3] ^= 0x80L << ((last & 7) << 3);

            permute(state);
            position = 0;
        }

        void squeeze(byte[] output, int offset, int length) {
            for (int i = 0; i < length; i++) {
                if (position == rate) {
                    permute(state);
                    position = 0;
                }
                int lane = position >>> 3;
                int shift = (position & 7) << 3;
                output[offset + i] = (byte) (state[lane] >>> shift);
                position++;
            }
        }

        byte squeezeByte() {
            if (position == rate) {
                permute(state);
                position = 0;
            }
            int lane = position >>> 3;
            int shift = (position & 7) << 3;
            byte value = (byte) (state[lane] >>> shift);
            position++;
            return value;
        }
    }
}
