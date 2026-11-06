/*
 * Copyright (c) 2026 manalejandro
 *
 * MIT License - see the LICENSE file at the root of the repository.
 */

package com.manalejandro.postquantum.core.internal;

import java.util.Arrays;

/** Small byte array helpers used by the ML-KEM engine. */
final class Bytes {

    private Bytes() {
    }

    /**
     * Overwrites every byte of the given arrays with zero. Null entries are ignored so that
     * callers can pass partially initialised locals from a {@code finally} block.
     *
     * @param arrays the arrays to clear
     */
    static void wipe(byte[]... arrays) {
        for (byte[] array : arrays) {
            if (array != null) {
                Arrays.fill(array, (byte) 0);
            }
        }
    }

    /**
     * Overwrites every coefficient of the given arrays with zero. Null entries are ignored.
     *
     * @param arrays the arrays to clear
     */
    static void wipe(int[]... arrays) {
        for (int[] array : arrays) {
            if (array != null) {
                Arrays.fill(array, 0);
            }
        }
    }

    /**
     * Overwrites every coefficient of the given vectors of polynomials with zero.
     *
     * @param vectors the vectors to clear
     */
    static void wipeVectors(int[][]... vectors) {
        for (int[][] vector : vectors) {
            if (vector != null) {
                for (int[] polynomial : vector) {
                    if (polynomial != null) {
                        Arrays.fill(polynomial, 0);
                    }
                }
            }
        }
    }

    static byte[] concat(byte[]... parts) {
        int length = 0;
        for (byte[] part : parts) {
            length += part.length;
        }
        byte[] result = new byte[length];
        int offset = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, result, offset, part.length);
            offset += part.length;
        }
        return result;
    }

    /**
     * Compares two byte arrays in constant time, always traversing the shorter length, and
     * returns an all-bits-set mask ({@code -1}) when the arrays are equal and {@code 0}
     * otherwise.
     *
     * <p>The result is computed without branching so that it can be used directly by
     * {@link #constantTimeSelect(int, byte[], byte[])}.
     */
    static int constantTimeMask(byte[] left, byte[] right) {
        int difference = left.length ^ right.length;
        int length = Math.min(left.length, right.length);
        for (int i = 0; i < length; i++) {
            difference |= left[i] ^ right[i];
        }
        // Sign bit of (x | -x) is set for every non-zero x, including Integer.MIN_VALUE.
        int nonZero = (difference | -difference) >> 31;
        return ~nonZero;
    }

    /**
     * Returns {@code left} when {@code mask} has all bits set and {@code right} when it is
     * {@code 0}, without branching. Both arrays must have the same length.
     */
    static byte[] constantTimeSelect(int mask, byte[] left, byte[] right) {
        if (left.length != right.length) {
            throw new IllegalArgumentException("arrays must have the same length");
        }
        byte[] result = new byte[left.length];
        for (int i = 0; i < left.length; i++) {
            result[i] = (byte) ((left[i] & mask) | (right[i] & ~mask));
        }
        return result;
    }
}
