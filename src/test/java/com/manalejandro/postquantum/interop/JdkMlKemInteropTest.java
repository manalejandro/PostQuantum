/*
 * Copyright (c) 2026 manalejandro
 *
 * MIT License - see the LICENSE file at the root of the repository.
 */

package com.manalejandro.postquantum.interop;

import com.manalejandro.postquantum.core.MlKem;
import com.manalejandro.postquantum.core.MlKemEncapsulation;
import com.manalejandro.postquantum.core.MlKemKeyPair;
import com.manalejandro.postquantum.core.MlKemParameterSet;
import com.manalejandro.postquantum.core.MlKemPrivateKey;
import com.manalejandro.postquantum.core.MlKemPublicKey;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.lang.reflect.Method;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Interoperability tests against the ML-KEM implementation shipped with JDK 24
 * ({@code javax.crypto.KEM}). The test uses reflection because the library compiles against the
 * Java 17 API, and it is skipped when the running JDK does not provide ML-KEM.
 */
class JdkMlKemInteropTest {

    /** Length of the FIPS 203 seed, the concatenation of {@code d} and {@code z}. */
    private static final int SEED_LENGTH = 64;

    @ParameterizedTest
    @EnumSource(MlKemParameterSet.class)
    void jdkDecapsulatesOurCiphertext(MlKemParameterSet parameterSet) throws Exception {
        assumeJdkMlKemIsAvailable();

        KeyPair jdkKeyPair = KeyPairGenerator.getInstance(parameterSet.algorithmName()).generateKeyPair();
        MlKemPublicKey publicKey = MlKemPublicKey.fromEncoded(
                parameterSet, tail(jdkKeyPair.getPublic().getEncoded(), parameterSet.encapsulationKeyLength()));

        MlKemEncapsulation encapsulation = MlKem.getInstance(parameterSet).encapsulate(publicKey);

        Object kem = newKem(parameterSet.algorithmName());
        Object decapsulator = kem.getClass()
                .getMethod("newDecapsulator", PrivateKey.class)
                .invoke(kem, jdkKeyPair.getPrivate());
        Key secret = (Key) decapsulator.getClass()
                .getMethod("decapsulate", byte[].class)
                .invoke(decapsulator, (Object) encapsulation.getCiphertext());

        assertThat(secret.getEncoded()).isEqualTo(encapsulation.getSharedSecret());
    }

    @ParameterizedTest
    @EnumSource(MlKemParameterSet.class)
    void weDecapsulateJdkCiphertextWithAJdkPrivateKey(MlKemParameterSet parameterSet) throws Exception {
        assumeJdkMlKemIsAvailable();

        KeyPair jdkKeyPair = KeyPairGenerator.getInstance(parameterSet.algorithmName()).generateKeyPair();
        MlKemPrivateKey privateKey = privateKeyOf(parameterSet, jdkKeyPair);

        Object kem = newKem(parameterSet.algorithmName());
        Object encapsulator = kem.getClass()
                .getMethod("newEncapsulator", PublicKey.class)
                .invoke(kem, jdkKeyPair.getPublic());
        Object encapsulated = encapsulator.getClass().getMethod("encapsulate").invoke(encapsulator);
        byte[] ciphertext = (byte[]) encapsulated.getClass().getMethod("encapsulation").invoke(encapsulated);
        Key secret = (Key) encapsulated.getClass().getMethod("key").invoke(encapsulated);

        byte[] recovered = MlKem.getInstance(parameterSet).decapsulate(privateKey, ciphertext);

        assertThat(recovered).isEqualTo(secret.getEncoded());
        assertThat(MessageDigest.isEqual(recovered, secret.getEncoded())).isTrue();
    }

    @ParameterizedTest
    @EnumSource(MlKemParameterSet.class)
    void jdkEncapsulatesToOurKey(MlKemParameterSet parameterSet) throws Exception {
        assumeJdkMlKemIsAvailable();

        KeyPair jdkKeyPair = KeyPairGenerator.getInstance(parameterSet.algorithmName()).generateKeyPair();
        MlKemKeyPair ourKeyPair = MlKem.getInstance(parameterSet).generateKeyPair();

        byte[] spki = jdkKeyPair.getPublic().getEncoded();
        byte[] ourKey = ourKeyPair.publicKey().getEncoded();
        System.arraycopy(ourKey, 0, spki, spki.length - ourKey.length, ourKey.length);
        PublicKey publicKey = KeyFactory.getInstance(parameterSet.algorithmName())
                .generatePublic(new X509EncodedKeySpec(spki));

        Object kem = newKem(parameterSet.algorithmName());
        Object encapsulator = kem.getClass()
                .getMethod("newEncapsulator", PublicKey.class)
                .invoke(kem, publicKey);
        Object encapsulated = encapsulator.getClass().getMethod("encapsulate").invoke(encapsulator);
        byte[] ciphertext = (byte[]) encapsulated.getClass().getMethod("encapsulation").invoke(encapsulated);
        Key secret = (Key) encapsulated.getClass().getMethod("key").invoke(encapsulated);

        byte[] recovered = MlKem.getInstance(parameterSet).decapsulate(ourKeyPair.privateKey(), ciphertext);

        assertThat(recovered).isEqualTo(secret.getEncoded());
    }

    private static Object newKem(String algorithmName) throws Exception {
        Class<?> kemClass = Class.forName("javax.crypto.KEM");
        Method getInstance = kemClass.getMethod("getInstance", String.class);
        return getInstance.invoke(null, algorithmName);
    }

    /**
     * Converts a JDK ML-KEM private key into our representation. JDK 24 encodes the expanded
     * decapsulation key in the PKCS#8 structure; JDK 25 and later encode the 64 byte seed
     * instead, so the key pair has to be derived again.
     */
    private static MlKemPrivateKey privateKeyOf(MlKemParameterSet parameterSet, KeyPair jdkKeyPair) {
        byte[] encoded = jdkKeyPair.getPrivate().getEncoded();
        int keyLength = parameterSet.decapsulationKeyLength();
        if (encoded.length > keyLength) {
            return MlKemPrivateKey.fromEncoded(
                    parameterSet, Arrays.copyOfRange(encoded, encoded.length - keyLength, encoded.length));
        }

        byte[] seed = Arrays.copyOfRange(encoded, encoded.length - SEED_LENGTH, encoded.length);
        MlKemKeyPair keyPair = MlKem.getInstance(parameterSet).generateKeyPair(seed);
        MlKemPublicKey jdkPublicKey = MlKemPublicKey.fromEncoded(
                parameterSet, tail(jdkKeyPair.getPublic().getEncoded(), parameterSet.encapsulationKeyLength()));
        assertThat(keyPair.publicKey())
                .as("the seed in the PKCS#8 encoding must reproduce the JDK public key")
                .isEqualTo(jdkPublicKey);
        return keyPair.privateKey();
    }

    private static byte[] tail(byte[] encoded, int length) {
        assertThat(encoded.length).isGreaterThan(length);
        return Arrays.copyOfRange(encoded, encoded.length - length, encoded.length);
    }

    private static void assumeJdkMlKemIsAvailable() {
        boolean available = Runtime.version().feature() >= 24;
        if (available) {
            try {
                Class.forName("javax.crypto.KEM");
                KeyPairGenerator.getInstance(MlKemParameterSet.ML_KEM_768.algorithmName());
            } catch (ClassNotFoundException | GeneralSecurityException ex) {
                available = false;
            }
        }
        Assumptions.assumeTrue(available, "javax.crypto.KEM ML-KEM is not available on this JDK");
    }
}
