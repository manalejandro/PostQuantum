/*
 * Copyright (c) 2026 manalejandro
 *
 * MIT License - see the LICENSE file at the root of the repository.
 */

package com.manalejandro.postquantum.core.internal;

/**
 * Deterministic sampling routines from FIPS 203: SampleNTT (Algorithm 7) and SamplePolyCBD
 * (Algorithm 8), together with the PRF and XOF instantiations from Section 4.1.
 */
final class Sampling {

    private Sampling() {
    }

    /**
     * FIPS 203, Algorithm 13/14: generates the {@code k x k} matrix {@code A} in the NTT domain.
     *
     * <p>Entry {@code (i, j)} is sampled from {@code XOF(rho || j || i)}, which is the ordering
     * used by K-PKE.KeyGen. K-PKE.Encrypt defines its matrix with the indices swapped, which is
     * the transpose of this matrix; {@link Ntt#multiplyTransposeAccumulate} takes care of that.
     */
    static int[][][] sampleMatrix(byte[] rho, int k) {
        int[][][] matrix = new int[k][k][];
        for (int i = 0; i < k; i++) {
            for (int j = 0; j < k; j++) {
                matrix[i][j] = sampleNtt(xofSeed(rho, (byte) j, (byte) i));
            }
        }
        return matrix;
    }

    /** FIPS 203, Algorithm 7: SampleNTT. */
    static int[] sampleNtt(byte[] seed) {
        Keccak.Sponge xof = Keccak.shake128Xof(seed);
        int[] coefficients = new int[Ntt.N];
        int count = 0;
        while (count < Ntt.N) {
            int b0 = xof.squeezeByte() & 0xFF;
            int b1 = xof.squeezeByte() & 0xFF;
            int b2 = xof.squeezeByte() & 0xFF;

            int d1 = b0 | ((b1 & 0x0F) << 8);
            int d2 = (b1 >>> 4) | (b2 << 4);

            if (d1 < Ntt.Q) {
                coefficients[count++] = d1;
            }
            if (d2 < Ntt.Q && count < Ntt.N) {
                coefficients[count++] = d2;
            }
        }
        return coefficients;
    }

    /** FIPS 203, Algorithm 8: SamplePolyCBD_eta. The input is the 64*eta byte PRF output. */
    static int[] samplePolyCbd(byte[] input, int eta) {
        int[] coefficients = new int[Ntt.N];
        for (int i = 0; i < Ntt.N; i++) {
            int ones = 0;
            int zeros = 0;
            int base = 2 * i * eta;
            for (int j = 0; j < eta; j++) {
                ones += bit(input, base + j);
                zeros += bit(input, base + eta + j);
            }
            coefficients[i] = Ntt.mod(ones - zeros);
        }
        return coefficients;
    }

    /** FIPS 203, Section 4.1: PRF_eta(s, b) = SHAKE256(s || b, 64 * eta). */
    static byte[] prf(byte[] seed, int counter, int eta) {
        byte[] input = new byte[seed.length + 1];
        System.arraycopy(seed, 0, input, 0, seed.length);
        input[seed.length] = (byte) counter;
        return Keccak.shake256(input, 64 * eta);
    }

    private static byte[] xofSeed(byte[] rho, byte first, byte second) {
        byte[] seed = new byte[rho.length + 2];
        System.arraycopy(rho, 0, seed, 0, rho.length);
        seed[rho.length] = first;
        seed[rho.length + 1] = second;
        return seed;
    }

    private static int bit(byte[] data, int index) {
        return (data[index >>> 3] >>> (index & 7)) & 1;
    }
}
