/*
 * Copyright (c) 2026 manalejandro
 *
 * MIT License - see the LICENSE file at the root of the repository.
 */

package com.manalejandro.postquantum.core;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.util.HexFormat;
import java.util.zip.GZIPInputStream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Runs the official NIST ACVP test vectors for ML-KEM (FIPS 203).
 *
 * <p>The vectors are downloaded by {@code tools/fetch-acvp-vectors.py} from the NIST ACVP-Server
 * repository and cover key generation, encapsulation, decapsulation (including implicit
 * rejection) and the encapsulation/decapsulation key checks.
 */
class AcvpMlKemTest {

    private static final HexFormat HEX = HexFormat.of();

    private static JsonNode vectors;

    @BeforeAll
    static void loadVectors() throws Exception {
        try (InputStream input = AcvpMlKemTest.class.getResourceAsStream("/acvp/ml-kem-fips203.json.gz")) {
            assertThat(input).as("ACVP vector file").isNotNull();
            vectors = new ObjectMapper().readTree(new GZIPInputStream(input));
        }
    }

    @Test
    void keyGenerationMatchesNistVectors() {
        assertThat(vectors.get("keyGen")).isNotEmpty();
        for (JsonNode vector : vectors.get("keyGen")) {
            MlKemParameterSet parameterSet = MlKemParameterSet.fromName(vector.get("parameterSet").asText());
            MlKem mlKem = MlKem.getInstance(parameterSet);

            MlKemKeyPair keyPair = mlKem.generateKeyPair(hex(vector, "d"), hex(vector, "z"));

            assertThat(keyPair.publicKey().getEncoded())
                    .as("%s tcId %d encapsulation key", parameterSet, vector.get("tcId").asInt())
                    .isEqualTo(hex(vector, "ek"));
            assertThat(keyPair.privateKey().getEncoded())
                    .as("%s tcId %d decapsulation key", parameterSet, vector.get("tcId").asInt())
                    .isEqualTo(hex(vector, "dk"));
        }
    }

    @Test
    void encapsulationMatchesNistVectors() {
        assertThat(vectors.get("encapsulation")).isNotEmpty();
        for (JsonNode vector : vectors.get("encapsulation")) {
            MlKemParameterSet parameterSet = MlKemParameterSet.fromName(vector.get("parameterSet").asText());
            MlKem mlKem = MlKem.getInstance(parameterSet);
            MlKemPublicKey publicKey = MlKemPublicKey.fromEncoded(parameterSet, hex(vector, "ek"));

            MlKemEncapsulation encapsulation = mlKem.encapsulateDeterministic(publicKey, hex(vector, "m"));

            assertThat(encapsulation.getCiphertext())
                    .as("%s tcId %d ciphertext", parameterSet, vector.get("tcId").asInt())
                    .isEqualTo(hex(vector, "c"));
            assertThat(encapsulation.getSharedSecret())
                    .as("%s tcId %d shared secret", parameterSet, vector.get("tcId").asInt())
                    .isEqualTo(hex(vector, "k"));
        }
    }

    @Test
    void decapsulationMatchesNistVectors() {
        assertThat(vectors.get("decapsulation")).isNotEmpty();
        for (JsonNode vector : vectors.get("decapsulation")) {
            MlKemParameterSet parameterSet = MlKemParameterSet.fromName(vector.get("parameterSet").asText());
            MlKem mlKem = MlKem.getInstance(parameterSet);
            MlKemPrivateKey privateKey = MlKemPrivateKey.fromEncoded(parameterSet, hex(vector, "dk"));

            byte[] sharedSecret = mlKem.decapsulate(privateKey, hex(vector, "c"));

            assertThat(sharedSecret)
                    .as("%s tcId %d shared secret", parameterSet, vector.get("tcId").asInt())
                    .isEqualTo(hex(vector, "k"));
        }
    }

    @Test
    void encapsulationKeyChecksMatchNistVectors() {
        assertThat(vectors.get("encapsulationKeyCheck")).isNotEmpty();
        for (JsonNode vector : vectors.get("encapsulationKeyCheck")) {
            MlKemParameterSet parameterSet = MlKemParameterSet.fromName(vector.get("parameterSet").asText());
            MlKem mlKem = MlKem.getInstance(parameterSet);

            assertThat(mlKem.isValidEncapsulationKey(hex(vector, "ek")))
                    .as("%s tcId %d", parameterSet, vector.get("tcId").asInt())
                    .isEqualTo(vector.get("valid").asBoolean());
        }
    }

    @Test
    void decapsulationKeyChecksMatchNistVectors() {
        assertThat(vectors.get("decapsulationKeyCheck")).isNotEmpty();
        for (JsonNode vector : vectors.get("decapsulationKeyCheck")) {
            MlKemParameterSet parameterSet = MlKemParameterSet.fromName(vector.get("parameterSet").asText());
            MlKem mlKem = MlKem.getInstance(parameterSet);

            assertThat(mlKem.isValidDecapsulationKey(hex(vector, "dk")))
                    .as("%s tcId %d", parameterSet, vector.get("tcId").asInt())
                    .isEqualTo(vector.get("valid").asBoolean());
        }
    }

    private static byte[] hex(JsonNode node, String field) {
        return HEX.parseHex(node.get(field).asText());
    }
}
