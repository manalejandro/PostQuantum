/*
 * Copyright (c) 2026 manalejandro
 *
 * MIT License - see the LICENSE file at the root of the repository.
 */

package com.manalejandro.postquantum.core.internal;

/**
 * Number theoretic transform over the ring {@code Z_q[X]/(X^256 + 1)} with {@code q = 3329},
 * as specified by FIPS 203 (Algorithms 9 to 12).
 *
 * <p>Polynomials are represented as {@code int[256]} arrays of coefficients in {@code [0, q)}.
 * All arithmetic is done with {@code long} intermediates so no Montgomery-specific
 * representation is required; the implementation is deliberately straightforward so that it can
 * be audited against the standard.
 */
final class Ntt {

    static final int Q = 3329;
    static final int N = 256;

    private static final int ROOT = 17;
    private static final int INVERSE_128 = 3303;

    private static final int[] ZETAS = new int[N / 2];
    private static final int[] GAMMAS = new int[N / 2];

    static {
        for (int i = 0; i < N / 2; i++) {
            int exponent = bitReverse7(i);
            ZETAS[i] = power(ROOT, exponent);
            GAMMAS[i] = power(ROOT, 2 * exponent + 1);
        }
    }

    private Ntt() {
    }

    /** FIPS 203, Algorithm 9: NTT. */
    static int[] forward(int[] f) {
        int[] result = f.clone();
        int index = 1;
        for (int length = 128; length >= 2; length >>= 1) {
            for (int start = 0; start < N; start += 2 * length) {
                int zeta = ZETAS[index++];
                for (int j = start; j < start + length; j++) {
                    int t = multiply(zeta, result[j + length]);
                    int current = result[j];
                    result[j + length] = mod(current - t);
                    result[j] = mod(current + t);
                }
            }
        }
        return result;
    }

    /** FIPS 203, Algorithm 10: NTT^-1. */
    static int[] inverse(int[] f) {
        int[] result = f.clone();
        int index = 127;
        for (int length = 2; length <= 128; length <<= 1) {
            for (int start = 0; start < N; start += 2 * length) {
                int zeta = ZETAS[index--];
                for (int j = start; j < start + length; j++) {
                    int current = result[j];
                    int upper = result[j + length];
                    result[j] = mod(current + upper);
                    result[j + length] = multiply(zeta, mod(upper - current));
                }
            }
        }
        for (int i = 0; i < N; i++) {
            result[i] = multiply(result[i], INVERSE_128);
        }
        return result;
    }

    /** FIPS 203, Algorithm 11: MultiplyNTTs. */
    static int[] multiplyNtts(int[] a, int[] b) {
        int[] result = new int[N];
        for (int i = 0; i < N / 2; i++) {
            baseCaseMultiply(a, b, i, result, i);
        }
        return result;
    }

    /** FIPS 203, Algorithm 12: BaseCaseMultiply. */
    private static void baseCaseMultiply(int[] a, int[] b, int index, int[] out, int outIndex) {
        int a0 = a[2 * index];
        int a1 = a[2 * index + 1];
        int b0 = b[2 * index];
        int b1 = b[2 * index + 1];

        long c0 = ((long) a0 * b0 + (long) multiply(multiply(a1, b1), GAMMAS[index]));
        long c1 = ((long) a0 * b1 + (long) a1 * b0);
        out[2 * outIndex] = (int) (c0 % Q);
        out[2 * outIndex + 1] = (int) (c1 % Q);
    }

    /** Adds two coefficient arrays, reducing modulo {@code q}. */
    static int[] add(int[] a, int[] b) {
        int[] result = new int[N];
        for (int i = 0; i < N; i++) {
            result[i] = mod(a[i] + b[i]);
        }
        return result;
    }

    /** Adds {@code b} into {@code a} (in place) and reduces modulo {@code q}. */
    static void addInPlace(int[] a, int[] b) {
        for (int i = 0; i < N; i++) {
            a[i] = mod(a[i] + b[i]);
        }
    }

    /** Computes the sum of the NTT-domain products {@code sum(a[i] * b[i])}. */
    static int[] multiplyAccumulate(int[][] a, int[][] b) {
        int[] result = new int[N];
        for (int i = 0; i < a.length; i++) {
            addInPlace(result, multiplyNtts(a[i], b[i]));
        }
        return result;
    }

    /** Computes {@code sum(a[i][column] * b[i])}, i.e. the transpose matrix-vector product. */
    static int[] multiplyTransposeAccumulate(int[][][] matrix, int column, int[][] vector) {
        int[] result = new int[N];
        for (int i = 0; i < vector.length; i++) {
            addInPlace(result, multiplyNtts(matrix[i][column], vector[i]));
        }
        return result;
    }

    static int multiply(int a, int b) {
        return (int) ((long) a * b % Q);
    }

    static int mod(int value) {
        int reduced = value % Q;
        return reduced < 0 ? reduced + Q : reduced;
    }

    private static int power(int base, int exponent) {
        long result = 1;
        long factor = base;
        int remaining = exponent;
        while (remaining > 0) {
            if ((remaining & 1) == 1) {
                result = result * factor % Q;
            }
            factor = factor * factor % Q;
            remaining >>= 1;
        }
        return (int) result;
    }

    private static int bitReverse7(int value) {
        int result = 0;
        for (int i = 0; i < 7; i++) {
            result = (result << 1) | ((value >> i) & 1);
        }
        return result;
    }
}
