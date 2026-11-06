/*
 * Copyright (c) 2026 manalejandro
 *
 * MIT License - see the LICENSE file at the root of the repository.
 */

package com.manalejandro.postquantum.core.internal;

import com.manalejandro.postquantum.core.MlKemParameterSet;

import java.util.Arrays;

/**
 * The IND-CPA secure public key encryption scheme K-PKE that underpins ML-KEM (FIPS 203,
 * Algorithms 13 to 15).
 */
final class Kpke {

    private final MlKemParameterSet parameters;

    Kpke(MlKemParameterSet parameters) {
        this.parameters = parameters;
    }

    /**
     * FIPS 203, Algorithm 13: K-PKE.KeyGen.
     *
     * @return a two element array containing the encapsulation key and the decapsulation key of
     *     the PKE scheme
     */
    byte[][] keyGen(byte[] d) {
        int k = parameters.rank();

        byte[] expandedSeed = new byte[33];
        System.arraycopy(d, 0, expandedSeed, 0, 32);
        expandedSeed[32] = (byte) k;
        byte[] expanded = Keccak.sha3_512(expandedSeed);
        byte[] rho = Arrays.copyOfRange(expanded, 0, 32);
        byte[] sigma = Arrays.copyOfRange(expanded, 32, 64);

        int[][][] aHat = Sampling.sampleMatrix(rho, k);

        int[][] s = new int[k][];
        int[][] e = new int[k][];
        int[][] sHat = new int[k][];
        int[][] eHat = new int[k][];
        try {
            int counter = 0;
            for (int i = 0; i < k; i++) {
                s[i] = Sampling.samplePolyCbd(Sampling.prf(sigma, counter++, parameters.eta1()), parameters.eta1());
            }
            for (int i = 0; i < k; i++) {
                e[i] = Sampling.samplePolyCbd(Sampling.prf(sigma, counter++, parameters.eta1()), parameters.eta1());
            }

            for (int i = 0; i < k; i++) {
                sHat[i] = Ntt.forward(s[i]);
                eHat[i] = Ntt.forward(e[i]);
            }

            int[][] tHat = new int[k][];
            for (int i = 0; i < k; i++) {
                tHat[i] = Ntt.add(Ntt.multiplyAccumulate(aHat[i], sHat), eHat[i]);
            }

            byte[] encapsulationKey = Bytes.concat(Encoding.encodeVector(12, tHat), rho);
            byte[] decapsulationKey = Encoding.encodeVector(12, sHat);
            return new byte[][]{encapsulationKey, decapsulationKey};
        } finally {
            // The seed expansion and the noise polynomials are secret; the encoded keys returned
            // above are independent copies, so they can be cleared before the method exits.
            Bytes.wipe(expandedSeed, expanded, sigma);
            Bytes.wipeVectors(s, e, sHat, eHat);
        }
    }

    /** FIPS 203, Algorithm 14: K-PKE.Encrypt. */
    byte[] encrypt(byte[] encapsulationKey, byte[] message, byte[] randomness) {
        int k = parameters.rank();
        int du = parameters.du();
        int dv = parameters.dv();

        int[][] tHat = Encoding.decodeVector(12, encapsulationKey, 0, k);
        byte[] rho = Arrays.copyOfRange(encapsulationKey, 384 * k, 384 * k + 32);
        int[][][] aHat = Sampling.sampleMatrix(rho, k);

        int[][] r = new int[k][];
        int[][] e1 = new int[k][];
        int[][] rHat = new int[k][];
        int[] e2 = null;
        int[] messagePolynomial = null;
        try {
            int counter = 0;
            for (int i = 0; i < k; i++) {
                r[i] = Sampling.samplePolyCbd(Sampling.prf(randomness, counter++, parameters.eta1()), parameters.eta1());
            }
            for (int i = 0; i < k; i++) {
                e1[i] = Sampling.samplePolyCbd(Sampling.prf(randomness, counter++, parameters.eta2()), parameters.eta2());
            }
            e2 = Sampling.samplePolyCbd(Sampling.prf(randomness, counter, parameters.eta2()), parameters.eta2());

            for (int i = 0; i < k; i++) {
                rHat[i] = Ntt.forward(r[i]);
            }

            int[][] u = new int[k][];
            for (int i = 0; i < k; i++) {
                int[] product = Ntt.multiplyTransposeAccumulate(aHat, i, rHat);
                u[i] = Ntt.add(Ntt.inverse(product), e1[i]);
            }

            messagePolynomial = Encoding.decompress(1, Encoding.decode(1, message, 0));
            int[] v = Ntt.add(Ntt.add(Ntt.inverse(Ntt.multiplyAccumulate(tHat, rHat)), e2), messagePolynomial);

            byte[] c1 = Encoding.encodeVector(du, compressVector(du, u));
            byte[] c2 = Encoding.encode(dv, Encoding.compress(dv, v));
            return Bytes.concat(c1, c2);
        } finally {
            Bytes.wipeVectors(r, e1, rHat);
            Bytes.wipe(e2, messagePolynomial);
        }
    }

    /** FIPS 203, Algorithm 15: K-PKE.Decrypt. */
    byte[] decrypt(byte[] decapsulationKey, byte[] ciphertext) {
        int k = parameters.rank();
        int du = parameters.du();
        int dv = parameters.dv();

        int[][] u = Encoding.decodeVector(du, ciphertext, 0, k);
        int[][] uDecompressed = new int[k][];
        for (int i = 0; i < k; i++) {
            uDecompressed[i] = Encoding.decompress(du, u[i]);
        }
        int[] v = Encoding.decompress(dv, Encoding.decode(dv, ciphertext, 32 * du * k));

        int[][] sHat = Encoding.decodeVector(12, decapsulationKey, 0, k);
        int[] product = null;
        int[] w = null;
        try {
            int[][] uHat = new int[k][];
            for (int i = 0; i < k; i++) {
                uHat[i] = Ntt.forward(uDecompressed[i]);
            }

            product = Ntt.inverse(Ntt.multiplyAccumulate(sHat, uHat));
            w = new int[Ntt.N];
            for (int i = 0; i < Ntt.N; i++) {
                w[i] = Ntt.mod(v[i] - product[i]);
            }
            return Encoding.encode(1, Encoding.compress(1, w));
        } finally {
            Bytes.wipeVectors(sHat);
            Bytes.wipe(product, w);
        }
    }

    private static int[][] compressVector(int bits, int[][] polynomials) {
        int[][] result = new int[polynomials.length][];
        for (int i = 0; i < polynomials.length; i++) {
            result[i] = Encoding.compress(bits, polynomials[i]);
        }
        return result;
    }
}
