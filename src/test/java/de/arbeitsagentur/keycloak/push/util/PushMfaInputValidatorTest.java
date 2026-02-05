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

package de.arbeitsagentur.keycloak.push.util;

import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.ws.rs.BadRequestException;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Tests for {@link PushMfaInputValidator}.
 */
@DisplayName("PushMfaInputValidator")
class PushMfaInputValidatorTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String FIELD_NAME = "testField";

    @Nested
    @DisplayName("require()")
    class RequireTests {

        @Test
        @DisplayName("returns valid non-blank string")
        void returnsValidNonBlankString() {
            String result = PushMfaInputValidator.require("validValue", FIELD_NAME);
            assertEquals("validValue", result);
        }

        @Test
        @DisplayName("accepts string with only special characters")
        void acceptsStringWithOnlySpecialCharacters() {
            String result = PushMfaInputValidator.require("!@#$%^&*()", FIELD_NAME);
            assertEquals("!@#$%^&*()", result);
        }

        @ParameterizedTest
        @NullAndEmptySource
        @ValueSource(strings = {"   ", "\t", "\n", "\r\n", "  \t\n  "})
        @DisplayName("throws BadRequestException for blank values")
        void throwsForBlankValues(String value) {
            BadRequestException ex =
                    assertThrows(BadRequestException.class, () -> PushMfaInputValidator.require(value, FIELD_NAME));
            assertTrue(ex.getMessage().contains(FIELD_NAME));
            assertTrue(ex.getMessage().contains("Missing field"));
        }
    }

    @Nested
    @DisplayName("requireMaxLength()")
    class RequireMaxLengthTests {

        @Test
        @DisplayName("allows null value")
        void allowsNullValue() {
            assertDoesNotThrow(() -> PushMfaInputValidator.requireMaxLength(null, 10, FIELD_NAME));
        }

        @Test
        @DisplayName("allows empty string")
        void allowsEmptyString() {
            assertDoesNotThrow(() -> PushMfaInputValidator.requireMaxLength("", 10, FIELD_NAME));
        }

        @Test
        @DisplayName("allows string at exact max length")
        void allowsStringAtExactMaxLength() {
            String value = "a".repeat(100);
            assertDoesNotThrow(() -> PushMfaInputValidator.requireMaxLength(value, 100, FIELD_NAME));
        }

        @Test
        @DisplayName("allows string under max length")
        void allowsStringUnderMaxLength() {
            String value = "a".repeat(50);
            assertDoesNotThrow(() -> PushMfaInputValidator.requireMaxLength(value, 100, FIELD_NAME));
        }

        @Test
        @DisplayName("throws for string exceeding max length by one")
        void throwsForStringExceedingMaxLengthByOne() {
            String value = "a".repeat(101);
            BadRequestException ex = assertThrows(
                    BadRequestException.class, () -> PushMfaInputValidator.requireMaxLength(value, 100, FIELD_NAME));
            assertTrue(ex.getMessage().contains(FIELD_NAME));
            assertTrue(ex.getMessage().contains("too long"));
        }

        @Test
        @DisplayName("throws for very long string")
        void throwsForVeryLongString() {
            String value = "a".repeat(10000);
            BadRequestException ex = assertThrows(
                    BadRequestException.class, () -> PushMfaInputValidator.requireMaxLength(value, 100, FIELD_NAME));
            assertTrue(ex.getMessage().contains("too long"));
        }

        @Test
        @DisplayName("counts unicode characters by code unit length")
        void countsUnicodeCharactersByCodeUnitLength() {
            // Emoji with surrogate pair (2 code units)
            String emoji = "\uD83D\uDE00"; // 😀
            assertEquals(2, emoji.length());
            assertDoesNotThrow(() -> PushMfaInputValidator.requireMaxLength(emoji, 2, FIELD_NAME));
            assertThrows(BadRequestException.class, () -> PushMfaInputValidator.requireMaxLength(emoji, 1, FIELD_NAME));
        }
    }

    @Nested
    @DisplayName("requireBoundedText()")
    class RequireBoundedTextTests {

        @Test
        @DisplayName("returns valid bounded text")
        void returnsValidBoundedText() {
            String result = PushMfaInputValidator.requireBoundedText("validText", 100, FIELD_NAME);
            assertEquals("validText", result);
        }

        @Test
        @DisplayName("allows string at exact max length")
        void allowsStringAtExactMaxLength() {
            String value = "a".repeat(50);
            String result = PushMfaInputValidator.requireBoundedText(value, 50, FIELD_NAME);
            assertEquals(value, result);
        }

        @ParameterizedTest
        @NullAndEmptySource
        @ValueSource(strings = {"   ", "\t\n"})
        @DisplayName("throws for blank values")
        void throwsForBlankValues(String value) {
            assertThrows(
                    BadRequestException.class, () -> PushMfaInputValidator.requireBoundedText(value, 100, FIELD_NAME));
        }

        @Test
        @DisplayName("throws for string exceeding max length")
        void throwsForStringExceedingMaxLength() {
            String value = "a".repeat(101);
            BadRequestException ex = assertThrows(
                    BadRequestException.class, () -> PushMfaInputValidator.requireBoundedText(value, 100, FIELD_NAME));
            assertTrue(ex.getMessage().contains("too long"));
        }

        @ParameterizedTest
        @ValueSource(strings = {"\u0000", "\u0001", "\u001F", "\u007F"})
        @DisplayName("throws for control characters")
        void throwsForControlCharacters(String controlChar) {
            String value = "text" + controlChar + "more";
            BadRequestException ex = assertThrows(
                    BadRequestException.class, () -> PushMfaInputValidator.requireBoundedText(value, 100, FIELD_NAME));
            assertTrue(ex.getMessage().contains("Invalid characters"));
        }

        @Test
        @DisplayName("throws for newline characters")
        void throwsForNewlineCharacters() {
            assertThrows(
                    BadRequestException.class,
                    () -> PushMfaInputValidator.requireBoundedText("text\nmore", 100, FIELD_NAME));
            assertThrows(
                    BadRequestException.class,
                    () -> PushMfaInputValidator.requireBoundedText("text\rmore", 100, FIELD_NAME));
        }

        @Test
        @DisplayName("throws for tab characters")
        void throwsForTabCharacters() {
            assertThrows(
                    BadRequestException.class,
                    () -> PushMfaInputValidator.requireBoundedText("text\tmore", 100, FIELD_NAME));
        }
    }

    @Nested
    @DisplayName("optionalBoundedText()")
    class OptionalBoundedTextTests {

        @Test
        @DisplayName("returns null for null input")
        void returnsNullForNullInput() {
            String result = PushMfaInputValidator.optionalBoundedText(null, 100, FIELD_NAME);
            assertNull(result);
        }

        @Test
        @DisplayName("returns valid text")
        void returnsValidText() {
            String result = PushMfaInputValidator.optionalBoundedText("validText", 100, FIELD_NAME);
            assertEquals("validText", result);
        }

        @Test
        @DisplayName("allows empty string")
        void allowsEmptyString() {
            String result = PushMfaInputValidator.optionalBoundedText("", 100, FIELD_NAME);
            assertEquals("", result);
        }

        @Test
        @DisplayName("allows string at exact max length")
        void allowsStringAtExactMaxLength() {
            String value = "a".repeat(50);
            String result = PushMfaInputValidator.optionalBoundedText(value, 50, FIELD_NAME);
            assertEquals(value, result);
        }

        @Test
        @DisplayName("throws for string exceeding max length")
        void throwsForStringExceedingMaxLength() {
            String value = "a".repeat(101);
            assertThrows(
                    BadRequestException.class, () -> PushMfaInputValidator.optionalBoundedText(value, 100, FIELD_NAME));
        }

        @ParameterizedTest
        @ValueSource(strings = {"\u0000", "\u0001", "\n", "\r", "\t"})
        @DisplayName("throws for control characters")
        void throwsForControlCharacters(String controlChar) {
            String value = "text" + controlChar + "more";
            assertThrows(
                    BadRequestException.class, () -> PushMfaInputValidator.optionalBoundedText(value, 100, FIELD_NAME));
        }
    }

    @Nested
    @DisplayName("requireUuid()")
    class RequireUuidTests {

        @Test
        @DisplayName("returns valid UUID string")
        void returnsValidUuidString() {
            String uuid = UUID.randomUUID().toString();
            String result = PushMfaInputValidator.requireUuid(uuid, FIELD_NAME);
            assertEquals(uuid, result);
        }

        @Test
        @DisplayName("accepts lowercase UUID")
        void acceptsLowercaseUuid() {
            String uuid = "550e8400-e29b-41d4-a716-446655440000";
            String result = PushMfaInputValidator.requireUuid(uuid, FIELD_NAME);
            assertEquals(uuid, result);
        }

        @Test
        @DisplayName("accepts uppercase UUID")
        void acceptsUppercaseUuid() {
            String uuid = "550E8400-E29B-41D4-A716-446655440000";
            String result = PushMfaInputValidator.requireUuid(uuid, FIELD_NAME);
            assertEquals(uuid, result);
        }

        @Test
        @DisplayName("accepts mixed case UUID")
        void acceptsMixedCaseUuid() {
            String uuid = "550e8400-E29B-41d4-A716-446655440000";
            String result = PushMfaInputValidator.requireUuid(uuid, FIELD_NAME);
            assertEquals(uuid, result);
        }

        @ParameterizedTest
        @NullAndEmptySource
        @ValueSource(strings = {"   ", "\t"})
        @DisplayName("throws for blank values")
        void throwsForBlankValues(String value) {
            assertThrows(BadRequestException.class, () -> PushMfaInputValidator.requireUuid(value, FIELD_NAME));
        }

        @Test
        @DisplayName("throws for UUID without hyphens")
        void throwsForUuidWithoutHyphens() {
            String uuid = "550e8400e29b41d4a716446655440000";
            assertThrows(BadRequestException.class, () -> PushMfaInputValidator.requireUuid(uuid, FIELD_NAME));
        }

        @Test
        @DisplayName("throws for UUID with braces")
        void throwsForUuidWithBraces() {
            String uuid = "{550e8400-e29b-41d4-a716-446655440000}";
            assertThrows(BadRequestException.class, () -> PushMfaInputValidator.requireUuid(uuid, FIELD_NAME));
        }

        @Test
        @DisplayName("throws for too short string")
        void throwsForTooShortString() {
            String value = "550e8400-e29b-41d4-a716";
            BadRequestException ex =
                    assertThrows(BadRequestException.class, () -> PushMfaInputValidator.requireUuid(value, FIELD_NAME));
            assertTrue(ex.getMessage().contains("Invalid UUID"));
        }

        @Test
        @DisplayName("throws for too long string")
        void throwsForTooLongString() {
            String value = "550e8400-e29b-41d4-a716-446655440000-extra";
            BadRequestException ex =
                    assertThrows(BadRequestException.class, () -> PushMfaInputValidator.requireUuid(value, FIELD_NAME));
            assertTrue(ex.getMessage().contains("Invalid UUID"));
        }

        @Test
        @DisplayName("throws for malformed UUID with correct length")
        void throwsForMalformedUuidWithCorrectLength() {
            // 36 characters but not valid UUID format
            String value = "not-a-valid-uuid-string-but-36-chars";
            assertEquals(36, value.length());
            assertThrows(BadRequestException.class, () -> PushMfaInputValidator.requireUuid(value, FIELD_NAME));
        }

        @Test
        @DisplayName("throws for UUID with invalid characters")
        void throwsForUuidWithInvalidCharacters() {
            String value = "550e8400-e29b-41d4-a716-44665544000g";
            assertThrows(BadRequestException.class, () -> PushMfaInputValidator.requireUuid(value, FIELD_NAME));
        }

        @Test
        @DisplayName("throws for UUID with control characters")
        void throwsForUuidWithControlCharacters() {
            String value = "550e8400-e29b-41d4-a716-44665544000\u0000";
            assertThrows(BadRequestException.class, () -> PushMfaInputValidator.requireUuid(value, FIELD_NAME));
        }
    }

    @Nested
    @DisplayName("ensurePublicJwk()")
    class EnsurePublicJwkTests {

        @Test
        @DisplayName("accepts valid public JWK")
        void acceptsValidPublicJwk() {
            ObjectNode jwk = JsonNodeFactory.instance.objectNode();
            jwk.put("kty", "RSA");
            jwk.put("n", "some-modulus");
            jwk.put("e", "AQAB");

            assertDoesNotThrow(() -> PushMfaInputValidator.ensurePublicJwk(jwk, FIELD_NAME));
        }

        @Test
        @DisplayName("accepts EC public JWK")
        void acceptsEcPublicJwk() {
            ObjectNode jwk = JsonNodeFactory.instance.objectNode();
            jwk.put("kty", "EC");
            jwk.put("crv", "P-256");
            jwk.put("x", "some-x");
            jwk.put("y", "some-y");

            assertDoesNotThrow(() -> PushMfaInputValidator.ensurePublicJwk(jwk, FIELD_NAME));
        }

        @Test
        @DisplayName("throws for null node")
        void throwsForNullNode() {
            BadRequestException ex = assertThrows(
                    BadRequestException.class, () -> PushMfaInputValidator.ensurePublicJwk(null, FIELD_NAME));
            assertTrue(ex.getMessage().contains("Missing field"));
        }

        @Test
        @DisplayName("throws for null JSON node")
        void throwsForNullJsonNode() {
            JsonNode nullNode = JsonNodeFactory.instance.nullNode();
            BadRequestException ex = assertThrows(
                    BadRequestException.class, () -> PushMfaInputValidator.ensurePublicJwk(nullNode, FIELD_NAME));
            assertTrue(ex.getMessage().contains("Missing field"));
        }

        @Test
        @DisplayName("throws for missing node")
        void throwsForMissingNode() {
            JsonNode missingNode = JsonNodeFactory.instance.missingNode();
            assertThrows(
                    BadRequestException.class, () -> PushMfaInputValidator.ensurePublicJwk(missingNode, FIELD_NAME));
        }

        @Test
        @DisplayName("throws for non-object node")
        void throwsForNonObjectNode() {
            JsonNode arrayNode = JsonNodeFactory.instance.arrayNode();
            BadRequestException ex = assertThrows(
                    BadRequestException.class, () -> PushMfaInputValidator.ensurePublicJwk(arrayNode, FIELD_NAME));
            assertTrue(ex.getMessage().contains("must be an object"));
        }

        @Test
        @DisplayName("throws for string node")
        void throwsForStringNode() {
            JsonNode stringNode = JsonNodeFactory.instance.textNode("not-an-object");
            assertThrows(
                    BadRequestException.class, () -> PushMfaInputValidator.ensurePublicJwk(stringNode, FIELD_NAME));
        }

        @Nested
        @DisplayName("Private key parameter rejection")
        class PrivateKeyParameterRejection {

            @Test
            @DisplayName("throws for JWK with 'd' parameter (RSA/EC private exponent)")
            void throwsForJwkWithDParameter() {
                ObjectNode jwk = JsonNodeFactory.instance.objectNode();
                jwk.put("kty", "RSA");
                jwk.put("n", "modulus");
                jwk.put("e", "AQAB");
                jwk.put("d", "private-exponent");

                BadRequestException ex = assertThrows(
                        BadRequestException.class, () -> PushMfaInputValidator.ensurePublicJwk(jwk, FIELD_NAME));
                assertTrue(ex.getMessage().contains("private key"));
            }

            @Test
            @DisplayName("throws for JWK with 'p' parameter (RSA first prime)")
            void throwsForJwkWithPParameter() {
                ObjectNode jwk = createPublicRsaJwk();
                jwk.put("p", "first-prime");

                assertThrows(BadRequestException.class, () -> PushMfaInputValidator.ensurePublicJwk(jwk, FIELD_NAME));
            }

            @Test
            @DisplayName("throws for JWK with 'q' parameter (RSA second prime)")
            void throwsForJwkWithQParameter() {
                ObjectNode jwk = createPublicRsaJwk();
                jwk.put("q", "second-prime");

                assertThrows(BadRequestException.class, () -> PushMfaInputValidator.ensurePublicJwk(jwk, FIELD_NAME));
            }

            @Test
            @DisplayName("throws for JWK with 'dp' parameter (RSA d mod p-1)")
            void throwsForJwkWithDpParameter() {
                ObjectNode jwk = createPublicRsaJwk();
                jwk.put("dp", "dp-value");

                assertThrows(BadRequestException.class, () -> PushMfaInputValidator.ensurePublicJwk(jwk, FIELD_NAME));
            }

            @Test
            @DisplayName("throws for JWK with 'dq' parameter (RSA d mod q-1)")
            void throwsForJwkWithDqParameter() {
                ObjectNode jwk = createPublicRsaJwk();
                jwk.put("dq", "dq-value");

                assertThrows(BadRequestException.class, () -> PushMfaInputValidator.ensurePublicJwk(jwk, FIELD_NAME));
            }

            @Test
            @DisplayName("throws for JWK with 'qi' parameter (RSA CRT coefficient)")
            void throwsForJwkWithQiParameter() {
                ObjectNode jwk = createPublicRsaJwk();
                jwk.put("qi", "qi-value");

                assertThrows(BadRequestException.class, () -> PushMfaInputValidator.ensurePublicJwk(jwk, FIELD_NAME));
            }

            @Test
            @DisplayName("throws for JWK with 'oth' parameter (RSA other primes)")
            void throwsForJwkWithOthParameter() {
                ObjectNode jwk = createPublicRsaJwk();
                jwk.set("oth", JsonNodeFactory.instance.arrayNode());

                assertThrows(BadRequestException.class, () -> PushMfaInputValidator.ensurePublicJwk(jwk, FIELD_NAME));
            }

            @Test
            @DisplayName("throws for JWK with 'k' parameter (symmetric key)")
            void throwsForJwkWithKParameter() {
                ObjectNode jwk = JsonNodeFactory.instance.objectNode();
                jwk.put("kty", "oct");
                jwk.put("k", "symmetric-key-value");

                assertThrows(BadRequestException.class, () -> PushMfaInputValidator.ensurePublicJwk(jwk, FIELD_NAME));
            }

            @Test
            @DisplayName("allows JWK with null private key field")
            void allowsJwkWithNullPrivateKeyField() {
                ObjectNode jwk = createPublicRsaJwk();
                jwk.putNull("d");

                assertDoesNotThrow(() -> PushMfaInputValidator.ensurePublicJwk(jwk, FIELD_NAME));
            }
        }
    }

    @Nested
    @DisplayName("Security: Control character and length validation")
    class SecurityValidation {

        @Test
        @DisplayName("Non-UUID format strings are rejected")
        void nonUuidFormatIsRejected() {
            String invalidFormat = "not-a-valid-uuid-format";
            assertThrows(BadRequestException.class, () -> PushMfaInputValidator.requireUuid(invalidFormat, FIELD_NAME));
        }

        @Test
        @DisplayName("Strings with special syntax characters are accepted in bounded text")
        void specialSyntaxCharactersAcceptedInBoundedText() {
            // Validator only checks length and control characters, not content semantics
            String specialChars = "test${}[]<>'\"";
            String result = PushMfaInputValidator.requireBoundedText(specialChars, 100, FIELD_NAME);
            assertEquals(specialChars, result);
        }

        @Test
        @DisplayName("Very long strings are rejected by length check")
        void veryLongStringsRejectedByLengthCheck() {
            String longPayload = "A".repeat(5000);
            assertThrows(
                    BadRequestException.class,
                    () -> PushMfaInputValidator.requireBoundedText(longPayload, 100, FIELD_NAME));
        }

        @Test
        @DisplayName("Null byte in UUID is rejected")
        void nullByteInUuidIsRejected() {
            String withNullByte = "550e8400-e29b-41d4-a716-44665544\u00000";
            assertThrows(BadRequestException.class, () -> PushMfaInputValidator.requireUuid(withNullByte, FIELD_NAME));
        }

        @Test
        @DisplayName("Null byte in bounded text is rejected")
        void nullByteInBoundedTextIsRejected() {
            String withNullByte = "normal\u0000text";
            assertThrows(
                    BadRequestException.class,
                    () -> PushMfaInputValidator.requireBoundedText(withNullByte, 100, FIELD_NAME));
        }

        @Test
        @DisplayName("CRLF characters are rejected")
        void crlfCharactersRejected() {
            String withCrlf = "header\r\nmore text";
            assertThrows(
                    BadRequestException.class,
                    () -> PushMfaInputValidator.requireBoundedText(withCrlf, 100, FIELD_NAME));
        }

        @Test
        @DisplayName("Path-like strings are accepted if valid format")
        void pathLikeStringsAccepted() {
            // Validator checks format, not path semantics
            String pathLike = "../../../etc/passwd";
            String result = PushMfaInputValidator.requireBoundedText(pathLike, 100, FIELD_NAME);
            assertEquals(pathLike, result);
        }
    }

    @Nested
    @DisplayName("Edge cases")
    class EdgeCases {

        @Test
        @DisplayName("handles zero max length")
        void handlesZeroMaxLength() {
            assertThrows(BadRequestException.class, () -> PushMfaInputValidator.requireBoundedText("a", 0, FIELD_NAME));
        }

        @Test
        @DisplayName("empty string passes requireBoundedText max length but fails require")
        void emptyStringPassesMaxLengthButFailsRequire() {
            assertThrows(
                    BadRequestException.class, () -> PushMfaInputValidator.requireBoundedText("", 100, FIELD_NAME));
        }

        @Test
        @DisplayName("single character passes all validations")
        void singleCharacterPassesAllValidations() {
            String result = PushMfaInputValidator.requireBoundedText("a", 100, FIELD_NAME);
            assertEquals("a", result);
        }

        @Test
        @DisplayName("whitespace-only string fails require but control chars caught first in boundedText")
        void whitespaceOnlyStringHandling() {
            // Space is not a control character, so "   " fails the require check
            assertThrows(
                    BadRequestException.class, () -> PushMfaInputValidator.requireBoundedText("   ", 100, FIELD_NAME));
        }

        @Test
        @DisplayName("optionalBoundedText allows whitespace-only if no control chars")
        void optionalBoundedTextAllowsWhitespaceOnly() {
            // Spaces are not control characters
            String result = PushMfaInputValidator.optionalBoundedText("   ", 100, FIELD_NAME);
            assertEquals("   ", result);
        }

        @Test
        @DisplayName("special unicode characters are allowed in bounded text")
        void specialUnicodeCharactersAreAllowedInBoundedText() {
            String unicode = "Test \u00e4\u00f6\u00fc\u00df \u4e2d\u6587 \uD83D\uDE00";
            String result = PushMfaInputValidator.requireBoundedText(unicode, 100, FIELD_NAME);
            assertEquals(unicode, result);
        }

        @Test
        @DisplayName("NIL UUID is valid")
        void nilUuidIsValid() {
            String nilUuid = "00000000-0000-0000-0000-000000000000";
            String result = PushMfaInputValidator.requireUuid(nilUuid, FIELD_NAME);
            assertEquals(nilUuid, result);
        }

        @Test
        @DisplayName("max UUID is valid")
        void maxUuidIsValid() {
            String maxUuid = "ffffffff-ffff-ffff-ffff-ffffffffffff";
            String result = PushMfaInputValidator.requireUuid(maxUuid, FIELD_NAME);
            assertEquals(maxUuid, result);
        }
    }

    private static ObjectNode createPublicRsaJwk() {
        ObjectNode jwk = JsonNodeFactory.instance.objectNode();
        jwk.put("kty", "RSA");
        jwk.put("n", "modulus");
        jwk.put("e", "AQAB");
        return jwk;
    }
}
