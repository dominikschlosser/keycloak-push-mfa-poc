/*
 * Copyright 2026 Bundesagentur für Arbeit
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.arbeitsagentur.keycloak.push;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import de.arbeitsagentur.keycloak.push.util.PushMfaKeyUtil;
import jakarta.ws.rs.BadRequestException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.crypto.KeyType;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jws.Algorithm;

class PushMfaResourceTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @BeforeAll
    static void initCrypto() {
        CryptoIntegration.init(PushMfaResourceTest.class.getClassLoader());
    }

    @Test
    void computeThumbprintMatchesNimbusForRsa() throws Exception {
        RSAKey rsaKey = new RSAKeyGenerator(2048).generate().toPublicJWK();
        String json = rsaKey.toJSONString();
        String expected = rsaKey.computeThumbprint().toString();
        String actual = PushMfaKeyUtil.computeJwkThumbprint(json);
        assertEquals(expected, actual);
    }

    @Test
    void computeThumbprintMatchesNimbusForEc() throws Exception {
        ECKey ecKey = new ECKeyGenerator(Curve.P_256).generate().toPublicJWK();
        String json = ecKey.toJSONString();
        String expected = ecKey.computeThumbprint().toString();
        String actual = PushMfaKeyUtil.computeJwkThumbprint(json);
        assertEquals(expected, actual);
    }

    @Test
    void ensureKeyMatchesRejectsMismatchedAlgorithm() {
        KeyWrapper rsa = new KeyWrapper();
        rsa.setType(KeyType.RSA);
        rsa.setAlgorithm("RS256");
        assertThrows(BadRequestException.class, () -> PushMfaKeyUtil.ensureKeyMatchesAlgorithm(rsa, "ES256"));
    }

    @Test
    void ensureKeyMatchesRejectsCurveMismatch() {
        KeyWrapper ec = new KeyWrapper();
        ec.setType(KeyType.EC);
        ec.setAlgorithm("ES256");
        ec.setCurve("P-384");
        assertThrows(BadRequestException.class, () -> PushMfaKeyUtil.ensureKeyMatchesAlgorithm(ec, "ES256"));
    }

    @Test
    void ensureKeyMatchesAcceptsValidRs256Combination() {
        KeyWrapper rsa = new KeyWrapper();
        rsa.setType(KeyType.RSA);
        rsa.setAlgorithm("RS256");
        // Should not throw - valid RS256 key/algorithm combination
        PushMfaKeyUtil.ensureKeyMatchesAlgorithm(rsa, "RS256");
    }

    @Test
    void requireSupportedAlgorithmRejectsNullAlgorithmEnum() {
        Algorithm nullAlgorithm = null;
        assertThrows(BadRequestException.class, () -> PushMfaKeyUtil.requireSupportedAlgorithm(nullAlgorithm, "test"));
    }

    @Test
    void requireSupportedAlgorithmRejectsNullString() {
        String nullString = null;
        assertThrows(BadRequestException.class, () -> PushMfaKeyUtil.requireSupportedAlgorithm(nullString, "test"));
    }

    @Test
    void requireAlgorithmFromJwkRejectsNullNode() {
        assertThrows(BadRequestException.class, () -> PushMfaKeyUtil.requireAlgorithmFromJwk(null, "test"));
    }

    @Test
    void requireAlgorithmFromJwkRejectsMissingAlgField() throws Exception {
        JsonNode nodeWithoutAlg = MAPPER.readTree("{\"kty\":\"EC\"}");
        assertThrows(BadRequestException.class, () -> PushMfaKeyUtil.requireAlgorithmFromJwk(nodeWithoutAlg, "test"));
    }

    @Test
    void keyWrapperFromNodeRejectsNullNode() {
        assertThrows(BadRequestException.class, () -> PushMfaKeyUtil.keyWrapperFromNode(null));
    }

    @Test
    void keyWrapperFromStringRejectsNullString() {
        assertThrows(BadRequestException.class, () -> PushMfaKeyUtil.keyWrapperFromString(null));
    }

    @Test
    void keyWrapperFromStringRejectsBlankString() {
        assertThrows(BadRequestException.class, () -> PushMfaKeyUtil.keyWrapperFromString("   "));
    }

    @Test
    void keyWrapperFromStringRejectsInvalidJson() {
        assertThrows(BadRequestException.class, () -> PushMfaKeyUtil.keyWrapperFromString("not valid json"));
    }

    @Test
    void ensureKeyMatchesAlgorithmRejectsNullKeyWrapper() {
        assertThrows(BadRequestException.class, () -> PushMfaKeyUtil.ensureKeyMatchesAlgorithm(null, "ES256"));
    }

    @Test
    void computeJwkThumbprintRejectsUnsupportedKeyType() {
        String oktJson = "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"abc\"}";
        assertThrows(BadRequestException.class, () -> PushMfaKeyUtil.computeJwkThumbprint(oktJson));
    }

    @Test
    void ensureKeyMatchesAcceptsValidEs256Combination() throws Exception {
        ECKey ecKey = new ECKeyGenerator(Curve.P_256).generate().toPublicJWK();
        KeyWrapper keyWrapper = PushMfaKeyUtil.keyWrapperFromString(ecKey.toJSONString());
        // Should not throw - valid ES256 key/algorithm combination
        assertDoesNotThrow(() -> PushMfaKeyUtil.ensureKeyMatchesAlgorithm(keyWrapper, "ES256"));
    }
}
