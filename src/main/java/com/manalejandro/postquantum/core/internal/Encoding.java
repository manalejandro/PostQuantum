/*
 * Copyright (c) 2026 manalejandro
 *
 * MIT License - see the LICENSE file at the root of the repository.
 */

package com.manalejandro.postquantum.core.internal;

/**
 * Bit packing and coefficient compression as defined by FIPS 203 (Algorithms 4 to 6).
 *
 * <p>Bit strings are packed least-significant bit first, exactly as the standard requires.
 */
final class Encoding {

    private Encoding() {
    }

    /** FIPS 203, Algorithm 5: ByteEncode_d. Returns {@code 32 * d} bytes for 256 coefficients. */
    static byte[] encode(int bits, int[] coefficients) {
        if (coefficients.length != Ntt.N) {
            throw new IllegalArgumentException("expected 256 coefficients, got " + coefficients.length);
        }
        byte[] output = new byte[Ntt.N * bits / 8];
        long buffer = 0;
        int bufferedBits = 0;
        int position = 0;
        int mask = (1 << bits) - 1;
        for (int coefficient : coefficients) {
            if (coefficient < 0 || (coefficient & mask) != coefficient) {
                throw new IllegalArgumentException("coefficient does not fit in " + bits + " bits: " + coefficient);
            }
            buffer |= (long) coefficient << bufferedBits;
            bufferedBits += bits;
            while (bufferedBits >= 8) {
                output[position++] = (byte) buffer;
                buffer >>>= 8;
                bufferedBits -= 8;
            }
        }
        if (position != output.length) {
            throw new IllegalStateException("unexpected encoded length " + position);
        }
        return output;
    }

    /** FIPS 203, Algorithm 6: ByteDecode_d. */
    static int[] decode(int bits, byte[] input, int offset) {
        int[] coefficients = new int[Ntt.N];
        long buffer = 0;
        int bufferedBits = 0;
        int position = offset;
        int mask = (1 << bits) - 1;
        for (int i = 0; i < Ntt.N; i++) {
            while (bufferedBits < bits) {
                buffer |= (long) (input[position++] & 0xFF) << bufferedBits;
                bufferedBits += 8;
            }
            coefficients[i] = (int) (buffer & mask);
            buffer >>>= bits;
            bufferedBits -= bits;
        }
        return coefficients;
    }

    /** Encodes a vector of {@code k} polynomials. */
    static byte[] encodeVector(int bits, int[][] polynomials) {
        byte[] output = new byte[polynomials.length * Ntt.N * bits / 8];
        int offset = 0;
        for (int[] polynomial : polynomials) {
            byte[] encoded = encode(bits, polynomial);
            System.arraycopy(encoded, 0, output, offset, encoded.length);
            offset += encoded.length;
        }
        return output;
    }

    /** Decodes a vector of {@code k} polynomials from {@code input} starting at {@code offset}. */
    static int[][] decodeVector(int bits, byte[] input, int offset, int length) {
        int[][] polynomials = new int[length][];
        int polyBytes = Ntt.N * bits / 8;
        for (int i = 0; i < length; i++) {
            polynomials[i] = decode(bits, input, offset + i * polyBytes);
        }
        return polynomials;
    }

    /** FIPS 203, Algorithm 4: Compress_d. */
    static int[] compress(int bits, int[] coefficients) {
        int[] result = new int[Ntt.N];
        int scale = 1 << bits;
        int mask = scale - 1;
        for (int i = 0; i < Ntt.N; i++) {
            result[i] = (int) (((long) coefficients[i] * scale + Ntt.Q / 2) / Ntt.Q) & mask;
        }
        return result;
    }

    /** FIPS 203, Algorithm 4 (inverse): Decompress_d. */
    static int[] decompress(int bits, int[] coefficients) {
        int[] result = new int[Ntt.N];
        int rounding = 1 << (bits - 1);
        for (int i = 0; i < Ntt.N; i++) {
            result[i] = (Ntt.Q * coefficients[i] + rounding) >> bits;
        }
        return result;
    }
}
