/*
 * Copyright (c) 2026 manalejandro
 *
 * MIT License - see the LICENSE file at the root of the repository.
 */

package com.manalejandro.postquantum.hybrid;

import com.manalejandro.postquantum.PostQuantumException;
import com.manalejandro.postquantum.core.MlKem;
import com.manalejandro.postquantum.core.MlKemEncapsulation;
import com.manalejandro.postquantum.core.MlKemKeyPair;
import com.manalejandro.postquantum.core.MlKemParameterSet;
import com.manalejandro.postquantum.core.MlKemPrivateKey;
import com.manalejandro.postquantum.core.MlKemPublicKey;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

/**
 * Authenticated public key encryption built from ML-KEM, HKDF-SHA256 and AES-256-GCM.
 *
 * <p>ML-KEM on its own only establishes a shared secret; it cannot encrypt application data.
 * This class turns it into a self-contained envelope cipher:
 *
 * <ol>
 *   <li>the sender encapsulates a fresh ML-KEM shared secret for the recipient;</li>
 *   <li>the shared secret is expanded with HKDF-SHA256, using the ML-KEM ciphertext as the
 *       salt, into a 256 bit AES key;</li>
 *   <li>the plaintext is encrypted with AES-256-GCM under a fresh 96 bit nonce, with the
 *       envelope header as associated data.</li>
 * </ol>
 *
 * <p>The resulting envelope is self-describing and can be stored or transmitted as opaque bytes:
 *
 * <pre>
 * +--------+--------+----------+------------+------------------+------------------+
 * | "PQH1" | setId  | reserved | nonce (12) | ML-KEM ct (n)    | AES-GCM ct+tag   |
 * +--------+--------+----------+------------+------------------+------------------+
 *   4 bytes  1 byte   1 byte     12 bytes     parameter set       plaintext + 16
 * </pre>
 *
 * <p>The 18 header bytes are authenticated as AES-GCM associated data, so the parameter set
 * identifier and the nonce cannot be modified without invalidating the tag. The ML-KEM
 * ciphertext is bound to the derived key because it is used as the HKDF salt.
 *
 * <p>Instances are stateless apart from the {@link SecureRandom} they use and are safe for
 * concurrent use.
 *
 * <p>Example:
 * <pre>{@code
 * HybridCipher cipher = HybridCipher.forParameterSet(MlKemParameterSet.ML_KEM_768);
 * MlKemKeyPair keyPair = cipher.generateKeyPair();
 *
 * byte[] envelope = cipher.encrypt(keyPair.publicKey(), "attack at dawn".getBytes(UTF_8));
 * byte[] plaintext = cipher.decrypt(keyPair.privateKey(), envelope);
 * }</pre>
 *
 * <p>This is a post-quantum construction, not a hybrid in the classical-plus-post-quantum
 * sense: no elliptic curve key exchange is combined with ML-KEM. It relies exclusively on the
 * security of ML-KEM and AES-256-GCM.
 */
public final class HybridCipher {

    /** Envelope magic bytes. The last byte is the format version. */
    private static final byte[] MAGIC = {'P', 'Q', 'H', 0x01};

    /** Length of the authenticated header: magic, parameter set id, reserved byte and nonce. */
    public static final int HEADER_LENGTH = 18;

    /** Length of the AES-GCM nonce in bytes. */
    public static final int NONCE_LENGTH = 12;

    /** Length of the AES-GCM authentication tag in bytes. */
    public static final int TAG_LENGTH = 16;

    /** Length of the AES key derived from the ML-KEM shared secret. */
    public static final int KEY_LENGTH = 32;

    private static final int PARAMETER_SET_OFFSET = 4;
    private static final int RESERVED_OFFSET = 5;
    private static final int NONCE_OFFSET = 6;
    private static final int KEM_CIPHERTEXT_OFFSET = HEADER_LENGTH;

    private static final byte[] HKDF_INFO_PREFIX =
            "postquantum-hybrid-v1:".getBytes(StandardCharsets.US_ASCII);

    private final MlKem mlKem;
    private final SecureRandom secureRandom;

    private HybridCipher(MlKem mlKem, SecureRandom secureRandom) {
        this.mlKem = mlKem;
        this.secureRandom = secureRandom;
    }

    /**
     * Creates a cipher for the given parameter set using a fresh {@link SecureRandom}.
     *
     * @param parameterSet the ML-KEM parameter set used to establish keys
     * @return a ready to use cipher
     */
    public static HybridCipher forParameterSet(MlKemParameterSet parameterSet) {
        return forParameterSet(parameterSet, new SecureRandom());
    }

    /**
     * Creates a cipher for the given parameter set with an explicit source of randomness.
     *
     * @param parameterSet the ML-KEM parameter set used to establish keys
     * @param secureRandom the randomness source used for keys, encapsulation and nonces
     * @return a ready to use cipher
     */
    public static HybridCipher forParameterSet(MlKemParameterSet parameterSet, SecureRandom secureRandom) {
        Objects.requireNonNull(parameterSet, "parameterSet must not be null");
        Objects.requireNonNull(secureRandom, "secureRandom must not be null");
        return new HybridCipher(MlKem.getInstance(parameterSet, secureRandom), secureRandom);
    }

    /**
     * Creates a cipher that reuses an existing ML-KEM instance.
     *
     * @param mlKem the ML-KEM instance whose parameter set defines the envelope format
     * @return a ready to use cipher
     */
    public static HybridCipher using(MlKem mlKem) {
        Objects.requireNonNull(mlKem, "mlKem must not be null");
        return new HybridCipher(mlKem, new SecureRandom());
    }

    /**
     * The parameter set of the envelopes produced and accepted by this cipher.
     *
     * @return the ML-KEM parameter set in use
     */
    public MlKemParameterSet getParameterSet() {
        return mlKem.getParameterSet();
    }

    /**
     * Generates a key pair usable with this cipher.
     *
     * @return a new ML-KEM key pair
     */
    public MlKemKeyPair generateKeyPair() {
        return mlKem.generateKeyPair();
    }

    /**
     * Encrypts {@code plaintext} for the owner of {@code publicKey} without associated data.
     *
     * @param publicKey the recipient encapsulation key
     * @param plaintext the data to encrypt
     * @return a self-contained envelope
     */
    public byte[] encrypt(MlKemPublicKey publicKey, byte[] plaintext) {
        return encrypt(publicKey, plaintext, new byte[0]);
    }

    /**
     * Encrypts {@code plaintext} for the owner of {@code publicKey}.
     *
     * @param publicKey the recipient encapsulation key
     * @param plaintext the data to encrypt
     * @param associatedData additional data authenticated but not encrypted, may be empty
     * @return a self-contained envelope
     * @throws IllegalArgumentException when the key belongs to another parameter set or is invalid
     */
    public byte[] encrypt(MlKemPublicKey publicKey, byte[] plaintext, byte[] associatedData) {
        Objects.requireNonNull(publicKey, "publicKey must not be null");
        Objects.requireNonNull(plaintext, "plaintext must not be null");
        Objects.requireNonNull(associatedData, "associatedData must not be null");
        // Fail before consuming randomness or doing KEM work if the envelope cannot be sized.
        int envelopeSize = checkedEnvelopeLength(getParameterSet().ciphertextLength(), plaintext.length);

        MlKemEncapsulation encapsulation = mlKem.encapsulate(publicKey);
        byte[] kemCiphertext = encapsulation.getCiphertext();
        byte[] sharedSecret = encapsulation.getSharedSecret();

        byte[] header = new byte[HEADER_LENGTH];
        System.arraycopy(MAGIC, 0, header, 0, MAGIC.length);
        header[PARAMETER_SET_OFFSET] = (byte) getParameterSet().identifier();
        header[RESERVED_OFFSET] = 0;
        byte[] nonce = new byte[NONCE_LENGTH];
        secureRandom.nextBytes(nonce);
        System.arraycopy(nonce, 0, header, NONCE_OFFSET, NONCE_LENGTH);

        byte[] aesKey = null;
        try {
            aesKey = Hkdf.deriveKey(sharedSecret, kemCiphertext, hkdfInfo(), KEY_LENGTH);
            byte[] sealed = aesGcm(Cipher.ENCRYPT_MODE, aesKey, nonce, header, associatedData, plaintext);

            byte[] envelope = new byte[envelopeSize];
            System.arraycopy(header, 0, envelope, 0, HEADER_LENGTH);
            System.arraycopy(kemCiphertext, 0, envelope, KEM_CIPHERTEXT_OFFSET, kemCiphertext.length);
            System.arraycopy(sealed, 0, envelope, KEM_CIPHERTEXT_OFFSET + kemCiphertext.length, sealed.length);
            return envelope;
        } finally {
            Arrays.fill(sharedSecret, (byte) 0);
            if (aesKey != null) {
                Arrays.fill(aesKey, (byte) 0);
            }
        }
    }

    /**
     * Decrypts an envelope produced by {@link #encrypt(MlKemPublicKey, byte[])}.
     *
     * @param privateKey the recipient decapsulation key
     * @param envelope the envelope to decrypt
     * @return the recovered plaintext
     * @throws IllegalArgumentException when the envelope is malformed or belongs to another
     *     parameter set
     * @throws HybridDecryptionException when the envelope is well formed but fails authentication
     */
    public byte[] decrypt(MlKemPrivateKey privateKey, byte[] envelope) {
        return decrypt(privateKey, envelope, new byte[0]);
    }

    /**
     * Decrypts an envelope produced by {@link #encrypt(MlKemPublicKey, byte[], byte[])}.
     *
     * @param privateKey the recipient decapsulation key
     * @param envelope the envelope to decrypt
     * @param associatedData the associated data supplied at encryption time, may be empty
     * @return the recovered plaintext
     * @throws IllegalArgumentException when the envelope is malformed or belongs to another
     *     parameter set
     * @throws HybridDecryptionException when the envelope is well formed but fails authentication
     */
    public byte[] decrypt(MlKemPrivateKey privateKey, byte[] envelope, byte[] associatedData) {
        Objects.requireNonNull(privateKey, "privateKey must not be null");
        Objects.requireNonNull(envelope, "envelope must not be null");
        Objects.requireNonNull(associatedData, "associatedData must not be null");

        MlKemParameterSet parameterSet = getParameterSet();
        int kemCiphertextLength = parameterSet.ciphertextLength();
        int minimumLength = HEADER_LENGTH + kemCiphertextLength + TAG_LENGTH;
        if (envelope.length < minimumLength) {
            throw new IllegalArgumentException("invalid envelope length: expected at least "
                    + minimumLength + " bytes but got " + envelope.length);
        }
        requireMagic(envelope);
        int identifier = envelope[PARAMETER_SET_OFFSET] & 0xFF;
        if (identifier != parameterSet.identifier()) {
            throw new IllegalArgumentException("envelope uses parameter set id " + identifier
                    + " but this cipher uses " + parameterSet);
        }
        if (envelope[RESERVED_OFFSET] != 0) {
            throw new IllegalArgumentException("unsupported envelope flags: " + envelope[RESERVED_OFFSET]);
        }

        byte[] header = Arrays.copyOfRange(envelope, 0, HEADER_LENGTH);
        byte[] nonce = Arrays.copyOfRange(envelope, NONCE_OFFSET, NONCE_OFFSET + NONCE_LENGTH);
        byte[] kemCiphertext = Arrays.copyOfRange(
                envelope, KEM_CIPHERTEXT_OFFSET, KEM_CIPHERTEXT_OFFSET + kemCiphertextLength);
        byte[] sealed = Arrays.copyOfRange(
                envelope, KEM_CIPHERTEXT_OFFSET + kemCiphertextLength, envelope.length);

        byte[] sharedSecret = mlKem.decapsulate(privateKey, kemCiphertext);
        byte[] aesKey = null;
        try {
            aesKey = Hkdf.deriveKey(sharedSecret, kemCiphertext, hkdfInfo(), KEY_LENGTH);
            return aesGcm(Cipher.DECRYPT_MODE, aesKey, nonce, header, associatedData, sealed);
        } finally {
            Arrays.fill(sharedSecret, (byte) 0);
            if (aesKey != null) {
                Arrays.fill(aesKey, (byte) 0);
            }
        }
    }

    /**
     * Reads the parameter set identifier from an envelope without decrypting it. Useful to route
     * an envelope to the right key before touching the private key.
     *
     * @param envelope a candidate envelope
     * @return the parameter set announced by the header
     * @throws IllegalArgumentException when the data is not a PostQuantum envelope or announces
     *     an unknown parameter set
     */
    public static MlKemParameterSet inspectParameterSet(byte[] envelope) {
        Objects.requireNonNull(envelope, "envelope must not be null");
        if (envelope.length < HEADER_LENGTH) {
            throw new IllegalArgumentException("data is too short to be a PostQuantum envelope");
        }
        requireMagic(envelope);
        int identifier = envelope[PARAMETER_SET_OFFSET] & 0xFF;
        for (MlKemParameterSet candidate : MlKemParameterSet.values()) {
            if (candidate.identifier() == identifier) {
                return candidate;
            }
        }
        throw new IllegalArgumentException("unknown ML-KEM parameter set id: " + identifier);
    }

    /**
     * Checks whether the data starts with the PostQuantum envelope magic bytes.
     *
     * @param data candidate bytes
     * @return {@code true} when the magic matches
     */
    public static boolean isEnvelope(byte[] data) {
        if (data == null || data.length < HEADER_LENGTH) {
            return false;
        }
        for (int i = 0; i < MAGIC.length; i++) {
            if (data[i] != MAGIC[i]) {
                return false;
            }
        }
        return true;
    }

    /**
     * Computes the envelope length for a plaintext of the given size.
     *
     * @param parameterSet the parameter set in use
     * @param plaintextLength the plaintext length in bytes
     * @return the total envelope length in bytes
     * @throws IllegalArgumentException when the length is negative or the envelope would not fit
     *     in an {@code int}
     */
    public static int envelopeLength(MlKemParameterSet parameterSet, int plaintextLength) {
        Objects.requireNonNull(parameterSet, "parameterSet must not be null");
        if (plaintextLength < 0) {
            throw new IllegalArgumentException("plaintextLength must not be negative");
        }
        return checkedEnvelopeLength(parameterSet.ciphertextLength(), plaintextLength);
    }

    /**
     * Adds the fixed envelope overhead to the plaintext length, failing instead of silently
     * overflowing when the result does not fit in an {@code int}.
     *
     * @param kemCiphertextLength the ML-KEM ciphertext length for the parameter set in use
     * @param plaintextLength the plaintext length in bytes
     * @return the total envelope length in bytes
     * @throws IllegalArgumentException when the sum overflows
     */
    private static int checkedEnvelopeLength(int kemCiphertextLength, int plaintextLength) {
        try {
            int overhead = Math.addExact(HEADER_LENGTH, kemCiphertextLength);
            int sealed = Math.addExact(plaintextLength, TAG_LENGTH);
            return Math.addExact(overhead, sealed);
        } catch (ArithmeticException ex) {
            throw new IllegalArgumentException("envelope length exceeds Integer.MAX_VALUE for a "
                    + plaintextLength + " byte plaintext", ex);
        }
    }

    private byte[] hkdfInfo() {
        byte[] algorithmName = getParameterSet().algorithmName().getBytes(StandardCharsets.US_ASCII);
        byte[] info = new byte[HKDF_INFO_PREFIX.length + algorithmName.length];
        System.arraycopy(HKDF_INFO_PREFIX, 0, info, 0, HKDF_INFO_PREFIX.length);
        System.arraycopy(algorithmName, 0, info, HKDF_INFO_PREFIX.length, algorithmName.length);
        return info;
    }

    private static byte[] aesGcm(int mode, byte[] key, byte[] nonce, byte[] header, byte[] associatedData, byte[] input) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_LENGTH * 8, nonce));
            cipher.updateAAD(header);
            if (associatedData.length > 0) {
                cipher.updateAAD(associatedData);
            }
            return cipher.doFinal(input);
        } catch (AEADBadTagException ex) {
            throw new HybridDecryptionException("envelope authentication failed", ex);
        } catch (GeneralSecurityException ex) {
            throw new PostQuantumException("AES-256-GCM is not available", ex);
        }
    }

    private static void requireMagic(byte[] envelope) {
        for (int i = 0; i < MAGIC.length; i++) {
            if (envelope[i] != MAGIC[i]) {
                throw new IllegalArgumentException("data is not a PostQuantum envelope");
            }
        }
    }

    @Override
    public String toString() {
        return "HybridCipher[" + getParameterSet() + ", ML-KEM + HKDF-SHA256 + AES-256-GCM]";
    }
}
