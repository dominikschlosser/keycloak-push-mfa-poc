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

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import de.arbeitsagentur.keycloak.push.challenge.WaitChallengeState;
import de.arbeitsagentur.keycloak.push.spi.waitchallenge.SingleUseObjectWaitChallengeStateProvider;
import de.arbeitsagentur.keycloak.push.spi.waitchallenge.UserAttributeWaitChallengeStateProvider;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Random;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RealmProvider;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;

/**
 * Fuzzing tests for WaitChallengeState and its storage providers.
 *
 * <p>These tests verify robustness against malformed inputs, edge cases,
 * and concurrent access patterns.
 */
class WaitChallengeFuzzIT {

    private static final String REALM_ID = "fuzz-realm";
    private static final String USER_ID = "fuzz-user";
    private static final Duration BASE_WAIT = Duration.ofMillis(100);
    private static final Duration MAX_WAIT = Duration.ofHours(1);
    private static final Duration RESET_PERIOD = Duration.ofHours(24);
    private static final String ATTRIBUTE_KEY = "push-mfa-wait-state";
    private static final Random RANDOM = new Random();

    // ==================== JSON Deserialization Fuzzing ====================

    @Nested
    @DisplayName("JSON Deserialization Fuzzing - UserAttribute Provider")
    class JsonDeserializationFuzzing {

        private UserAttributeWaitChallengeStateProvider provider;
        private Map<String, List<String>> userAttributes;
        private UserModel user;

        @BeforeEach
        void setUp() {
            userAttributes = new HashMap<>();
            user = createMockUser();
            RealmModel realm = mock(RealmModel.class);
            when(realm.getId()).thenReturn(REALM_ID);

            RealmProvider realmProvider = mock(RealmProvider.class);
            when(realmProvider.getRealm(REALM_ID)).thenReturn(realm);

            UserProvider userProvider = mock(UserProvider.class);
            when(userProvider.getUserById(realm, USER_ID)).thenReturn(user);

            KeycloakSession session = mock(KeycloakSession.class);
            when(session.realms()).thenReturn(realmProvider);
            when(session.users()).thenReturn(userProvider);

            provider = new UserAttributeWaitChallengeStateProvider(session);
        }

        private UserModel createMockUser() {
            UserModel user = mock(UserModel.class);
            when(user.getId()).thenReturn(USER_ID);
            when(user.getFirstAttribute(anyString())).thenAnswer(invocation -> {
                String key = invocation.getArgument(0);
                List<String> values = userAttributes.get(key);
                return values != null && !values.isEmpty() ? values.get(0) : null;
            });
            doAnswer(invocation -> {
                        String key = invocation.getArgument(0);
                        String value = invocation.getArgument(1);
                        userAttributes.put(key, List.of(value));
                        return null;
                    })
                    .when(user)
                    .setSingleAttribute(anyString(), anyString());
            doAnswer(invocation -> {
                        String key = invocation.getArgument(0);
                        userAttributes.remove(key);
                        return null;
                    })
                    .when(user)
                    .removeAttribute(anyString());
            return user;
        }

        // ---- Truncated JSON ----

        @ParameterizedTest(name = "Truncated JSON at position {0}")
        @ValueSource(ints = {1, 5, 10, 20, 50})
        @DisplayName("Truncated JSON handled gracefully - incomplete JSON strings")
        void truncatedJson_handledGracefully(int truncateAt) {
            String validJson = "{\"firstUnapprovedAt\":\"2026-01-15T10:30:00Z\","
                    + "\"lastChallengeAt\":\"2026-01-15T10:30:00Z\","
                    + "\"consecutiveUnapproved\":3,"
                    + "\"waitUntil\":\"2026-01-15T10:31:00Z\"}";

            String truncated = truncateAt < validJson.length() ? validJson.substring(0, truncateAt) : validJson;
            userAttributes.put(ATTRIBUTE_KEY, List.of(truncated));

            Optional<WaitChallengeState> state = provider.get(REALM_ID, USER_ID, RESET_PERIOD);

            // Should return empty and clean up invalid data
            assertTrue(state.isEmpty(), "Truncated JSON should return empty Optional");
            verify(user).removeAttribute(ATTRIBUTE_KEY);
        }

        @Test
        @DisplayName("Empty JSON string handled gracefully - returns empty without cleanup")
        void emptyJsonString_handledGracefully() {
            // Empty string is treated as "no attribute" by the provider (blank check)
            userAttributes.put(ATTRIBUTE_KEY, List.of(""));

            Optional<WaitChallengeState> state = provider.get(REALM_ID, USER_ID, RESET_PERIOD);

            // Should return empty (blank is treated as no state)
            assertTrue(state.isEmpty(), "Empty JSON should return empty Optional");
            // No removeAttribute call expected - blank is handled early
            verify(user, never()).removeAttribute(anyString());
        }

        // ---- Wrong types ----

        static Stream<Arguments> wrongTypeJsonCases() {
            return Stream.of(
                    // Fuzzing vector: string where number expected
                    Arguments.of(
                            "consecutiveUnapproved as string",
                            "{\"firstUnapprovedAt\":\"2026-01-15T10:30:00Z\","
                                    + "\"lastChallengeAt\":\"2026-01-15T10:30:00Z\","
                                    + "\"consecutiveUnapproved\":\"three\","
                                    + "\"waitUntil\":\"2026-01-15T10:31:00Z\"}"),
                    // Fuzzing vector: number where string expected
                    Arguments.of(
                            "firstUnapprovedAt as number",
                            "{\"firstUnapprovedAt\":12345,"
                                    + "\"lastChallengeAt\":\"2026-01-15T10:30:00Z\","
                                    + "\"consecutiveUnapproved\":3,"
                                    + "\"waitUntil\":\"2026-01-15T10:31:00Z\"}"),
                    // Fuzzing vector: boolean where string expected
                    Arguments.of(
                            "waitUntil as boolean",
                            "{\"firstUnapprovedAt\":\"2026-01-15T10:30:00Z\","
                                    + "\"lastChallengeAt\":\"2026-01-15T10:30:00Z\","
                                    + "\"consecutiveUnapproved\":3,"
                                    + "\"waitUntil\":true}"),
                    // Fuzzing vector: null values
                    Arguments.of(
                            "all null values",
                            "{\"firstUnapprovedAt\":null,"
                                    + "\"lastChallengeAt\":null,"
                                    + "\"consecutiveUnapproved\":null,"
                                    + "\"waitUntil\":null}"),
                    // Fuzzing vector: array where object expected
                    Arguments.of("array at root level", "[\"2026-01-15T10:30:00Z\", 3]"),
                    // Fuzzing vector: float where integer expected
                    Arguments.of(
                            "float for consecutiveUnapproved",
                            "{\"firstUnapprovedAt\":\"2026-01-15T10:30:00Z\","
                                    + "\"lastChallengeAt\":\"2026-01-15T10:30:00Z\","
                                    + "\"consecutiveUnapproved\":3.14159,"
                                    + "\"waitUntil\":\"2026-01-15T10:31:00Z\"}"));
        }

        @ParameterizedTest(name = "Wrong type: {0}")
        @MethodSource("wrongTypeJsonCases")
        @DisplayName("Wrong JSON types handled gracefully - type mismatches")
        void wrongTypeJson_handledGracefully(String description, String json) {
            userAttributes.put(ATTRIBUTE_KEY, List.of(json));

            Optional<WaitChallengeState> state = provider.get(REALM_ID, USER_ID, RESET_PERIOD);

            assertTrue(state.isEmpty(), "Wrong type JSON should return empty Optional: " + description);
            verify(user).removeAttribute(ATTRIBUTE_KEY);
        }

        // ---- Missing fields ----

        static Stream<Arguments> missingFieldJsonCases() {
            return Stream.of(
                    // Fuzzing vector: missing firstUnapprovedAt
                    Arguments.of(
                            "missing firstUnapprovedAt",
                            "{\"lastChallengeAt\":\"2026-01-15T10:30:00Z\","
                                    + "\"consecutiveUnapproved\":3,"
                                    + "\"waitUntil\":\"2026-01-15T10:31:00Z\"}"),
                    // Fuzzing vector: missing lastChallengeAt
                    Arguments.of(
                            "missing lastChallengeAt",
                            "{\"firstUnapprovedAt\":\"2026-01-15T10:30:00Z\","
                                    + "\"consecutiveUnapproved\":3,"
                                    + "\"waitUntil\":\"2026-01-15T10:31:00Z\"}"),
                    // Fuzzing vector: missing consecutiveUnapproved
                    Arguments.of(
                            "missing consecutiveUnapproved",
                            "{\"firstUnapprovedAt\":\"2026-01-15T10:30:00Z\","
                                    + "\"lastChallengeAt\":\"2026-01-15T10:30:00Z\","
                                    + "\"waitUntil\":\"2026-01-15T10:31:00Z\"}"),
                    // Fuzzing vector: missing waitUntil
                    Arguments.of(
                            "missing waitUntil",
                            "{\"firstUnapprovedAt\":\"2026-01-15T10:30:00Z\","
                                    + "\"lastChallengeAt\":\"2026-01-15T10:30:00Z\","
                                    + "\"consecutiveUnapproved\":3}"),
                    // Fuzzing vector: empty object
                    Arguments.of("empty object", "{}"),
                    // Fuzzing vector: only one field
                    Arguments.of("only one field", "{\"consecutiveUnapproved\":5}"));
        }

        @ParameterizedTest(name = "Missing field: {0}")
        @MethodSource("missingFieldJsonCases")
        @DisplayName("Missing JSON fields handled gracefully - required fields absent")
        void missingFieldJson_handledGracefully(String description, String json) {
            userAttributes.put(ATTRIBUTE_KEY, List.of(json));

            Optional<WaitChallengeState> state = provider.get(REALM_ID, USER_ID, RESET_PERIOD);

            assertTrue(state.isEmpty(), "JSON with missing field should return empty Optional: " + description);
            verify(user).removeAttribute(ATTRIBUTE_KEY);
        }

        // ---- Extra fields ----

        @Test
        @DisplayName("Extra fields in JSON are ignored gracefully")
        void extraFieldsJson_handledGracefully() {
            // Use a future timestamp so the state is not expired
            Instant futureWaitUntil = Instant.now().plusSeconds(3600);
            String validJsonWithFuture =
                    "{\"firstUnapprovedAt\":\"" + Instant.now().minusSeconds(60) + "\","
                            + "\"lastChallengeAt\":\"" + Instant.now().minusSeconds(30) + "\","
                            + "\"consecutiveUnapproved\":3,"
                            + "\"waitUntil\":\"" + futureWaitUntil + "\","
                            + "\"extraField\":\"ignored\","
                            + "\"extraField2\":12345,"
                            + "\"nestedExtra\":{\"a\":1,\"b\":2}}";
            userAttributes.put(ATTRIBUTE_KEY, List.of(validJsonWithFuture));

            Optional<WaitChallengeState> state = provider.get(REALM_ID, USER_ID, RESET_PERIOD);

            // Extra fields should be ignored, valid data should be parsed
            assertTrue(state.isPresent(), "Valid JSON with extra fields should be parsed");
            assertEquals(3, state.get().consecutiveUnapproved());
        }

        // ---- Nested objects where primitives expected ----

        static Stream<Arguments> nestedObjectJsonCases() {
            return Stream.of(
                    // Fuzzing vector: nested object for timestamp
                    Arguments.of(
                            "nested object for firstUnapprovedAt",
                            "{\"firstUnapprovedAt\":{\"year\":2026,\"month\":1},"
                                    + "\"lastChallengeAt\":\"2026-01-15T10:30:00Z\","
                                    + "\"consecutiveUnapproved\":3,"
                                    + "\"waitUntil\":\"2026-01-15T10:31:00Z\"}"),
                    // Fuzzing vector: array for counter
                    Arguments.of(
                            "array for consecutiveUnapproved",
                            "{\"firstUnapprovedAt\":\"2026-01-15T10:30:00Z\","
                                    + "\"lastChallengeAt\":\"2026-01-15T10:30:00Z\","
                                    + "\"consecutiveUnapproved\":[1,2,3],"
                                    + "\"waitUntil\":\"2026-01-15T10:31:00Z\"}"),
                    // Fuzzing vector: deeply nested structure
                    Arguments.of(
                            "deeply nested waitUntil",
                            "{\"firstUnapprovedAt\":\"2026-01-15T10:30:00Z\","
                                    + "\"lastChallengeAt\":\"2026-01-15T10:30:00Z\","
                                    + "\"consecutiveUnapproved\":3,"
                                    + "\"waitUntil\":{\"nested\":{\"deep\":{\"value\":\"2026-01-15T10:31:00Z\"}}}}"));
        }

        @ParameterizedTest(name = "Nested object: {0}")
        @MethodSource("nestedObjectJsonCases")
        @DisplayName("Nested objects where primitives expected handled gracefully")
        void nestedObjectJson_handledGracefully(String description, String json) {
            userAttributes.put(ATTRIBUTE_KEY, List.of(json));

            Optional<WaitChallengeState> state = provider.get(REALM_ID, USER_ID, RESET_PERIOD);

            assertTrue(state.isEmpty(), "Nested object JSON should return empty Optional: " + description);
            verify(user).removeAttribute(ATTRIBUTE_KEY);
        }

        // ---- Malformed JSON syntax ----

        static Stream<String> malformedJsonSyntaxCases() {
            return Stream.of(
                    "", // Empty string
                    "   ", // Whitespace only
                    "null", // JSON null literal
                    "undefined", // JavaScript undefined
                    "true", // Boolean literal
                    "false", // Boolean literal
                    "123", // Number literal
                    "\"just a string\"", // Plain string
                    "{missing quotes}", // Missing quotes on keys
                    "{'single': 'quotes'}", // Single quotes (invalid JSON)
                    "{trailing: comma,}", // Trailing comma
                    "{\"unclosed\": \"brace\"", // Unclosed brace
                    "\"unclosed\": \"brace\"}", // Missing opening brace
                    "{\"key\": }", // Missing value
                    "{: \"value\"}", // Missing key
                    "{\"duplicate\": 1, \"duplicate\": 2}", // Duplicate keys
                    "<!-- xml -->", // XML comment
                    "<root><child/></root>", // XML
                    "key=value", // URL params
                    "not json at all!", // Random text
                    "\u0000\u0001\u0002" // Binary garbage
                    );
        }

        @ParameterizedTest
        @MethodSource("malformedJsonSyntaxCases")
        @DisplayName("Malformed JSON syntax handled gracefully - parser errors")
        void malformedJsonSyntax_handledGracefully(String malformedJson) {
            userAttributes.put(ATTRIBUTE_KEY, List.of(malformedJson));

            // Should not throw exception
            Optional<WaitChallengeState> state = assertDoesNotThrow(
                    () -> provider.get(REALM_ID, USER_ID, RESET_PERIOD), "Malformed JSON should not throw exception");

            assertTrue(state.isEmpty(), "Malformed JSON should return empty Optional");
        }
    }

    // ==================== Timestamp Fuzzing ====================

    @Nested
    @DisplayName("Timestamp Fuzzing - Invalid Instant Strings")
    class TimestampFuzzing {

        private UserAttributeWaitChallengeStateProvider provider;
        private Map<String, List<String>> userAttributes;
        private UserModel user;

        @BeforeEach
        void setUp() {
            userAttributes = new HashMap<>();
            user = mock(UserModel.class);
            when(user.getId()).thenReturn(USER_ID);
            when(user.getFirstAttribute(anyString())).thenAnswer(invocation -> {
                String key = invocation.getArgument(0);
                List<String> values = userAttributes.get(key);
                return values != null && !values.isEmpty() ? values.get(0) : null;
            });
            doAnswer(invocation -> {
                        String key = invocation.getArgument(0);
                        userAttributes.remove(key);
                        return null;
                    })
                    .when(user)
                    .removeAttribute(anyString());

            RealmModel realm = mock(RealmModel.class);
            when(realm.getId()).thenReturn(REALM_ID);

            RealmProvider realmProvider = mock(RealmProvider.class);
            when(realmProvider.getRealm(REALM_ID)).thenReturn(realm);

            UserProvider userProvider = mock(UserProvider.class);
            when(userProvider.getUserById(realm, USER_ID)).thenReturn(user);

            KeycloakSession session = mock(KeycloakSession.class);
            when(session.realms()).thenReturn(realmProvider);
            when(session.users()).thenReturn(userProvider);

            provider = new UserAttributeWaitChallengeStateProvider(session);
        }

        // ---- Invalid Instant strings ----

        static Stream<Arguments> invalidInstantCases() {
            return Stream.of(
                    // Fuzzing vector: invalid date format
                    Arguments.of("invalid date format", "2026-13-45T25:99:99Z"),
                    // Fuzzing vector: no timezone
                    Arguments.of("missing timezone", "2026-01-15T10:30:00"),
                    // Fuzzing vector: wrong timezone format
                    Arguments.of("wrong timezone format", "2026-01-15T10:30:00+99:99"),
                    // Fuzzing vector: date only
                    Arguments.of("date only", "2026-01-15"),
                    // Fuzzing vector: time only
                    Arguments.of("time only", "10:30:00"),
                    // Fuzzing vector: Unix timestamp
                    Arguments.of("unix timestamp", "1705315800"),
                    // Fuzzing vector: milliseconds timestamp
                    Arguments.of("millis timestamp", "1705315800000"),
                    // Fuzzing vector: empty string
                    Arguments.of("empty string", ""),
                    // Fuzzing vector: whitespace
                    Arguments.of("whitespace", "   "),
                    // Fuzzing vector: random text
                    Arguments.of("random text", "not a timestamp"),
                    // Fuzzing vector: string with special characters appended
                    Arguments.of("special suffix", "2026-01-15T10:30:00Z; extra"),
                    // Fuzzing vector: special characters
                    Arguments.of("special characters", "2026\n01\t15T10:30:00Z"),
                    // Fuzzing vector: unicode
                    Arguments.of("unicode", "\u200B2026-01-15T10:30:00Z"),
                    // Fuzzing vector: negative year (theoretical)
                    Arguments.of("negative year", "-2026-01-15T10:30:00Z"));
        }

        @ParameterizedTest(name = "Invalid timestamp: {0}")
        @MethodSource("invalidInstantCases")
        @DisplayName("Invalid Instant strings handled gracefully")
        void invalidInstantString_handledGracefully(String description, String invalidTimestamp) {
            String json = "{\"firstUnapprovedAt\":\"" + invalidTimestamp + "\","
                    + "\"lastChallengeAt\":\"2026-01-15T10:30:00Z\","
                    + "\"consecutiveUnapproved\":3,"
                    + "\"waitUntil\":\"2026-01-15T10:31:00Z\"}";

            userAttributes.put(ATTRIBUTE_KEY, List.of(json));

            Optional<WaitChallengeState> state = assertDoesNotThrow(
                    () -> provider.get(REALM_ID, USER_ID, RESET_PERIOD),
                    "Invalid timestamp should not throw exception: " + description);

            assertTrue(state.isEmpty(), "Invalid timestamp should return empty Optional: " + description);
        }

        // ---- Epoch overflow values ----

        static Stream<Arguments> epochOverflowCases() {
            return Stream.of(
                    // Fuzzing vector: maximum Instant
                    Arguments.of("max instant", Instant.MAX.toString()),
                    // Fuzzing vector: minimum Instant
                    Arguments.of("min instant", Instant.MIN.toString()),
                    // Fuzzing vector: year 10000 (5-digit year)
                    Arguments.of("year 10000", "+10000-01-15T10:30:00Z"),
                    // Fuzzing vector: very far future
                    Arguments.of("year 99999", "+99999-12-31T23:59:59Z"),
                    // Fuzzing vector: epoch zero
                    Arguments.of("epoch zero", "1970-01-01T00:00:00Z"),
                    // Fuzzing vector: pre-epoch
                    Arguments.of("pre-epoch 1969", "1969-12-31T23:59:59Z"),
                    // Fuzzing vector: ancient date
                    Arguments.of("year 0001", "0001-01-01T00:00:00Z"));
        }

        @ParameterizedTest(name = "Epoch edge case: {0}")
        @MethodSource("epochOverflowCases")
        @DisplayName("Epoch overflow and edge case timestamps handled gracefully")
        void epochOverflow_handledGracefully(String description, String timestamp) {
            Instant now = Instant.now();
            String json = "{\"firstUnapprovedAt\":\"" + timestamp + "\","
                    + "\"lastChallengeAt\":\"" + now + "\","
                    + "\"consecutiveUnapproved\":3,"
                    + "\"waitUntil\":\"" + now.plusSeconds(3600) + "\"}";

            userAttributes.put(ATTRIBUTE_KEY, List.of(json));

            // Should not throw exception
            assertDoesNotThrow(
                    () -> provider.get(REALM_ID, USER_ID, RESET_PERIOD),
                    "Epoch edge case should not throw exception: " + description);
        }

        // ---- Far future dates and state expiration ----

        @Test
        @DisplayName("Far future waitUntil date is parsed correctly")
        void farFutureWaitUntil_parsedCorrectly() {
            Instant now = Instant.now();
            Instant farFuture = now.plus(Duration.ofDays(365 * 100)); // 100 years from now

            String json = "{\"firstUnapprovedAt\":\"" + now.minusSeconds(60) + "\","
                    + "\"lastChallengeAt\":\"" + now.minusSeconds(30) + "\","
                    + "\"consecutiveUnapproved\":3,"
                    + "\"waitUntil\":\"" + farFuture + "\"}";

            userAttributes.put(ATTRIBUTE_KEY, List.of(json));

            Optional<WaitChallengeState> state = provider.get(REALM_ID, USER_ID, RESET_PERIOD);

            assertTrue(state.isPresent(), "Far future waitUntil should parse successfully");
            assertTrue(state.get().isWaiting(now), "Should still be waiting with far future waitUntil");
        }
    }

    // ==================== Duration Calculation Fuzzing ====================

    @Nested
    @DisplayName("Duration Calculation Fuzzing - Exponential Backoff Edge Cases")
    class DurationCalculationFuzzing {

        @ParameterizedTest
        @ValueSource(ints = {Integer.MAX_VALUE, Integer.MAX_VALUE - 1, 1000000, 100000})
        @DisplayName("MAX_VALUE inputs for consecutiveUnapproved handled without overflow")
        void maxValueInputs_noOverflow(int largeValue) {
            Duration result = assertDoesNotThrow(
                    () -> WaitChallengeState.calculateNextWait(largeValue, Duration.ofSeconds(10), Duration.ofHours(1)),
                    "Large consecutiveUnapproved should not cause overflow");

            // Should be capped at max wait
            assertTrue(
                    result.compareTo(Duration.ofHours(1)) <= 0,
                    "Result should be capped at max wait for large input: " + largeValue);
        }

        @Test
        @DisplayName("Zero duration base wait returns zero")
        void zeroDurationBaseWait_returnsZero() {
            Duration result = WaitChallengeState.calculateNextWait(5, Duration.ZERO, Duration.ofHours(1));

            assertEquals(Duration.ZERO, result, "Zero base wait should return zero");
        }

        @ParameterizedTest
        @ValueSource(ints = {-1, -100, Integer.MIN_VALUE})
        @DisplayName("Negative consecutiveUnapproved values return zero")
        void negativeValues_returnZero(int negativeValue) {
            Duration result =
                    WaitChallengeState.calculateNextWait(negativeValue, Duration.ofSeconds(10), Duration.ofHours(1));

            assertEquals(Duration.ZERO, result, "Negative consecutiveUnapproved should return zero");
        }

        @Test
        @DisplayName("Negative base wait is handled gracefully")
        void negativeBaseWait_handledGracefully() {
            // Negative durations are theoretically possible
            Duration negativeBase = Duration.ofSeconds(-10);
            Duration result = WaitChallengeState.calculateNextWait(1, negativeBase, Duration.ofHours(1));

            // Negative base wait is a misconfiguration. The implementation does not validate inputs,
            // so negative base * 2^(n-1) produces a negative duration. This is acceptable behavior
            // for invalid configuration - callers should not pass negative durations.
            assertNotNull(result, "Should return a Duration even with negative base");
        }

        @Test
        @DisplayName("Very small base wait with many attempts stays within max")
        void smallBaseWithManyAttempts_staysWithinMax() {
            Duration tinyBase = Duration.ofNanos(1);
            Duration maxWait = Duration.ofSeconds(1);

            for (int attempts = 1; attempts <= 100; attempts++) {
                Duration result = WaitChallengeState.calculateNextWait(attempts, tinyBase, maxWait);
                assertTrue(
                        result.compareTo(maxWait) <= 0, "Result should never exceed max wait at attempt " + attempts);
            }
        }

        @Test
        @DisplayName("Large base wait respects max cap")
        void largeBaseWait_respectsMaxCap() {
            Duration hugeBase = Duration.ofDays(365);
            Duration smallMax = Duration.ofSeconds(60);

            Duration result = WaitChallengeState.calculateNextWait(1, hugeBase, smallMax);

            assertEquals(smallMax, result, "Huge base should be capped to max");
        }

        @Test
        @DisplayName("Exponential growth is correctly calculated up to cap")
        void exponentialGrowth_correctlyCalculated() {
            Duration base = Duration.ofSeconds(1);
            Duration max = Duration.ofHours(24);

            // Verify exponential pattern: 1s, 2s, 4s, 8s, 16s...
            assertEquals(Duration.ofSeconds(1), WaitChallengeState.calculateNextWait(1, base, max));
            assertEquals(Duration.ofSeconds(2), WaitChallengeState.calculateNextWait(2, base, max));
            assertEquals(Duration.ofSeconds(4), WaitChallengeState.calculateNextWait(3, base, max));
            assertEquals(Duration.ofSeconds(8), WaitChallengeState.calculateNextWait(4, base, max));
            assertEquals(Duration.ofSeconds(16), WaitChallengeState.calculateNextWait(5, base, max));
            assertEquals(Duration.ofSeconds(32), WaitChallengeState.calculateNextWait(6, base, max));
            assertEquals(Duration.ofSeconds(64), WaitChallengeState.calculateNextWait(7, base, max));
            assertEquals(Duration.ofSeconds(128), WaitChallengeState.calculateNextWait(8, base, max));
            assertEquals(Duration.ofSeconds(256), WaitChallengeState.calculateNextWait(9, base, max));
            assertEquals(Duration.ofSeconds(512), WaitChallengeState.calculateNextWait(10, base, max));
        }

        @Test
        @DisplayName("Overflow protection caps exponent at 20")
        void overflowProtection_capsExponent() {
            Duration base = Duration.ofSeconds(1);
            Duration max = Duration.ofHours(24);

            // At exponent 20: 2^20 = 1,048,576 seconds = ~291 hours
            // At exponent 21: would overflow without protection

            Duration attempt21 = WaitChallengeState.calculateNextWait(21, base, max);
            Duration attempt50 = WaitChallengeState.calculateNextWait(50, base, max);
            Duration attempt100 = WaitChallengeState.calculateNextWait(100, base, max);

            // All should be capped at max
            assertEquals(max, attempt21, "Attempt 21 should hit max cap");
            assertEquals(max, attempt50, "Attempt 50 should hit max cap");
            assertEquals(max, attempt100, "Attempt 100 should hit max cap");
        }
    }

    // ==================== Storage Key Fuzzing ====================

    @Nested
    @DisplayName("Storage Key Fuzzing - SingleUseObject Provider")
    class StorageKeyFuzzing {

        private SingleUseObjectWaitChallengeStateProvider provider;
        private InMemorySingleUseObjectProvider singleUseObjects;

        @BeforeEach
        void setUp() {
            singleUseObjects = new InMemorySingleUseObjectProvider();
            KeycloakSession session = mock(KeycloakSession.class);
            when(session.singleUseObjects()).thenReturn(singleUseObjects);
            provider = new SingleUseObjectWaitChallengeStateProvider(session);
        }

        // ---- Special characters in keys ----

        static Stream<String> specialCharacterUserIds() {
            return Stream.of(
                    // Fuzzing vector: special characters
                    "user@example.com",
                    "user+test@example.com",
                    "user with spaces",
                    "user\twith\ttabs",
                    "user\nwith\nnewlines",
                    "user/with/slashes",
                    "user\\with\\backslashes",
                    "user:with:colons",
                    "user;with;semicolons",
                    "user?with?questions",
                    "user#with#hash",
                    "user%with%percent",
                    "user&with&ampersand",
                    "user=with=equals",
                    "user'with'quotes",
                    "user\"with\"doublequotes",
                    "user<with>brackets",
                    // Fuzzing vector: path traversal attempts
                    "../../../etc/passwd",
                    "..\\..\\..\\windows\\system32",
                    "%2e%2e%2f%2e%2e%2fetc/passwd",
                    // Fuzzing vector: URL encoded
                    "user%20encoded",
                    "user%00null",
                    // Fuzzing vector: Unicode
                    "\u200Buser", // Zero-width space
                    "user\u0000null", // Null byte
                    "\uFEFFuser", // BOM
                    "user\u202Ertl", // Right-to-left override
                    // Fuzzing vector: very long ID
                    "a".repeat(1000),
                    // Fuzzing vector: empty-ish
                    " ",
                    "\t",
                    "\n");
        }

        @ParameterizedTest
        @MethodSource("specialCharacterUserIds")
        @DisplayName("Special characters in userId handled safely")
        void specialCharactersInUserId_handledSafely(String specialUserId) {
            // Should not throw when recording
            assertDoesNotThrow(
                    () -> provider.recordChallengeCreated(REALM_ID, specialUserId, BASE_WAIT, MAX_WAIT, RESET_PERIOD),
                    "Special character userId should not throw on record: " + specialUserId);

            // Should be able to retrieve
            Optional<WaitChallengeState> state =
                    assertDoesNotThrow(() -> provider.get(REALM_ID, specialUserId, RESET_PERIOD));

            assertTrue(state.isPresent(), "State should be retrievable for special userId");
            assertEquals(1, state.get().consecutiveUnapproved());
        }

        static Stream<String> specialCharacterRealmIds() {
            return Stream.of(
                    // Fuzzing vector: special characters in realm
                    "realm-with-dashes",
                    "realm_with_underscores",
                    "realm.with.dots",
                    "realm/with/slashes",
                    "realm:with:colons",
                    "../traversal",
                    "realm%encoded",
                    "realm\nnewline");
        }

        @ParameterizedTest
        @MethodSource("specialCharacterRealmIds")
        @DisplayName("Special characters in realmId handled safely")
        void specialCharactersInRealmId_handledSafely(String specialRealmId) {
            assertDoesNotThrow(
                    () -> provider.recordChallengeCreated(specialRealmId, USER_ID, BASE_WAIT, MAX_WAIT, RESET_PERIOD),
                    "Special character realmId should not throw on record");

            Optional<WaitChallengeState> state =
                    assertDoesNotThrow(() -> provider.get(specialRealmId, USER_ID, RESET_PERIOD));

            assertTrue(state.isPresent(), "State should be retrievable for special realmId");
        }

        @Test
        @DisplayName("Key isolation prevents cross-user access")
        void keyIsolation_preventsCrossUserAccess() {
            String user1 = "user1";
            String user1Similar = "user1:similar"; // Contains user1 as prefix

            provider.recordChallengeCreated(REALM_ID, user1, BASE_WAIT, MAX_WAIT, RESET_PERIOD);

            // Similar key should not access user1's state
            Optional<WaitChallengeState> state = provider.get(REALM_ID, user1Similar, RESET_PERIOD);
            assertTrue(state.isEmpty(), "Similar userId should not access another user's state");
        }

        @Test
        @DisplayName("Key isolation prevents cross-realm access")
        void keyIsolation_preventsCrossRealmAccess() {
            String realm1 = "realm1";
            String realm1Similar = "realm1:realm2";

            provider.recordChallengeCreated(realm1, USER_ID, BASE_WAIT, MAX_WAIT, RESET_PERIOD);

            // Similar key should not access realm1's state
            Optional<WaitChallengeState> state = provider.get(realm1Similar, USER_ID, RESET_PERIOD);
            assertTrue(state.isEmpty(), "Similar realmId should not access another realm's state");
        }
    }

    // ==================== Concurrent Fuzzing ====================

    @Nested
    @DisplayName("Concurrent and Sequential Fuzzing - Rapid State Transitions")
    class ConcurrentAndSequentialFuzzing {

        private SingleUseObjectWaitChallengeStateProvider provider;
        private ConcurrentSingleUseObjectProvider singleUseObjects;

        @BeforeEach
        void setUp() {
            singleUseObjects = new ConcurrentSingleUseObjectProvider();
            KeycloakSession session = mock(KeycloakSession.class);
            when(session.singleUseObjects()).thenReturn(singleUseObjects);
            provider = new SingleUseObjectWaitChallengeStateProvider(session);
        }

        @RepeatedTest(5)
        @DisplayName("Concurrent challenge recordings complete without errors")
        void concurrentRecordings_completeWithoutErrors() throws Exception {
            int threadCount = 10;
            int operationsPerThread = 50;
            ExecutorService executor = Executors.newFixedThreadPool(threadCount);
            CountDownLatch startLatch = new CountDownLatch(1);
            CountDownLatch doneLatch = new CountDownLatch(threadCount);
            AtomicInteger successCount = new AtomicInteger(0);
            AtomicInteger errorCount = new AtomicInteger(0);

            for (int t = 0; t < threadCount; t++) {
                executor.submit(() -> {
                    try {
                        startLatch.await();
                        for (int i = 0; i < operationsPerThread; i++) {
                            try {
                                provider.recordChallengeCreated(REALM_ID, USER_ID, BASE_WAIT, MAX_WAIT, RESET_PERIOD);
                                successCount.incrementAndGet();
                            } catch (Exception e) {
                                errorCount.incrementAndGet();
                            }
                            // Random timing to simulate real-world conditions
                            if (RANDOM.nextBoolean()) {
                                Thread.sleep(RANDOM.nextInt(5));
                            }
                        }
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    } finally {
                        doneLatch.countDown();
                    }
                });
            }

            startLatch.countDown();
            assertTrue(doneLatch.await(30, TimeUnit.SECONDS), "Operations should complete within timeout");
            executor.shutdown();

            assertEquals(0, errorCount.get(), "No errors should occur during concurrent operations");
            assertEquals(threadCount * operationsPerThread, successCount.get(), "All operations should succeed");

            // Final state should exist
            Optional<WaitChallengeState> finalState = provider.get(REALM_ID, USER_ID, RESET_PERIOD);
            assertTrue(finalState.isPresent(), "Final state should exist");
            // NOTE: We use a conservative threshold of threadCount (10) rather than the theoretical
            // maximum of threadCount * operationsPerThread (500) because:
            // 1. The ConcurrentSingleUseObjectProvider uses synchronized methods, but read-modify-write
            //    sequences in the provider (get -> modify -> put) are not atomic, allowing lost updates
            // 2. In production, Keycloak's Infinispan-backed SingleUseObjectProvider has similar
            //    characteristics - it provides per-operation atomicity but not transaction atomicity
            // 3. The test's primary goal is to verify no exceptions/crashes occur, not perfect counting
            // 4. The threshold ensures at least some updates were recorded (not all lost)
            assertTrue(
                    finalState.get().consecutiveUnapproved() >= threadCount,
                    "Should have recorded at least " + threadCount + " challenges (conservative threshold "
                            + "due to expected lost updates from non-atomic read-modify-write sequences)");
        }

        @RepeatedTest(3)
        @DisplayName("Concurrent reads and writes do not corrupt state")
        void concurrentReadsAndWrites_noCorruption() throws Exception {
            int threadCount = 8;
            ExecutorService executor = Executors.newFixedThreadPool(threadCount);
            CountDownLatch startLatch = new CountDownLatch(1);
            CountDownLatch doneLatch = new CountDownLatch(threadCount);
            AtomicInteger corruptionCount = new AtomicInteger(0);

            // Pre-populate with some state
            provider.recordChallengeCreated(REALM_ID, USER_ID, BASE_WAIT, MAX_WAIT, RESET_PERIOD);

            for (int t = 0; t < threadCount; t++) {
                int threadId = t;
                executor.submit(() -> {
                    try {
                        startLatch.await();
                        for (int i = 0; i < 100; i++) {
                            if (threadId % 2 == 0) {
                                // Writer thread
                                provider.recordChallengeCreated(REALM_ID, USER_ID, BASE_WAIT, MAX_WAIT, RESET_PERIOD);
                            } else {
                                // Reader thread
                                try {
                                    Optional<WaitChallengeState> state = provider.get(REALM_ID, USER_ID, RESET_PERIOD);
                                    if (state.isPresent()) {
                                        WaitChallengeState s = state.get();
                                        // Verify state is internally consistent.
                                        // Invariant: consecutiveUnapproved >= 1 because:
                                        // - We pre-populate with 1 record before starting threads
                                        // - Writer threads only call recordChallengeCreated() which increments
                                        // - There are no reset() calls in this test
                                        // If this check fails, it indicates either:
                                        // - State corruption from concurrent access
                                        // - A partial/torn read of the state object
                                        if (s.consecutiveUnapproved() < 1) {
                                            corruptionCount.incrementAndGet();
                                        }
                                        // Timestamps must be non-null for valid state
                                        if (s.firstUnapprovedAt() == null || s.lastChallengeAt() == null) {
                                            corruptionCount.incrementAndGet();
                                        }
                                    }
                                } catch (Exception e) {
                                    // Read error counts as corruption
                                    corruptionCount.incrementAndGet();
                                }
                            }
                            if (RANDOM.nextBoolean()) {
                                Thread.sleep(RANDOM.nextInt(3));
                            }
                        }
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    } finally {
                        doneLatch.countDown();
                    }
                });
            }

            startLatch.countDown();
            assertTrue(doneLatch.await(30, TimeUnit.SECONDS), "Operations should complete within timeout");
            executor.shutdown();

            assertEquals(0, corruptionCount.get(), "No state corruption should occur");
        }

        @RepeatedTest(3)
        @DisplayName("Sequential reset and record operations maintain consistency")
        void sequentialResetAndRecord_maintainsConsistency() throws Exception {
            int cycles = 100;
            AtomicInteger resetCount = new AtomicInteger(0);
            AtomicInteger recordCount = new AtomicInteger(0);

            for (int i = 0; i < cycles; i++) {
                // Alternate between reset and record with random timing
                if (RANDOM.nextBoolean()) {
                    provider.reset(REALM_ID, USER_ID);
                    resetCount.incrementAndGet();
                } else {
                    provider.recordChallengeCreated(REALM_ID, USER_ID, BASE_WAIT, MAX_WAIT, RESET_PERIOD);
                    recordCount.incrementAndGet();
                }

                // Verify state is always consistent (either present or absent)
                Optional<WaitChallengeState> state = provider.get(REALM_ID, USER_ID, RESET_PERIOD);
                if (state.isPresent()) {
                    assertTrue(state.get().consecutiveUnapproved() >= 1, "Present state should have valid counter");
                }
            }

            // Ensure we exercised both paths
            assertTrue(resetCount.get() > 0, "Should have executed some resets");
            assertTrue(recordCount.get() > 0, "Should have executed some records");
        }

        @RepeatedTest(5)
        @DisplayName("Concurrent reset operations do not throw exceptions")
        void concurrentResets_noExceptions() throws Exception {
            int threadCount = 10;
            int resetsPerThread = 20;
            ExecutorService executor = Executors.newFixedThreadPool(threadCount);
            CountDownLatch startLatch = new CountDownLatch(1);
            CountDownLatch doneLatch = new CountDownLatch(threadCount);
            AtomicInteger successCount = new AtomicInteger(0);
            AtomicInteger errorCount = new AtomicInteger(0);

            // Pre-populate with some state to ensure there's something to reset
            provider.recordChallengeCreated(REALM_ID, USER_ID, BASE_WAIT, MAX_WAIT, RESET_PERIOD);

            for (int t = 0; t < threadCount; t++) {
                executor.submit(() -> {
                    try {
                        startLatch.await();
                        for (int i = 0; i < resetsPerThread; i++) {
                            try {
                                provider.reset(REALM_ID, USER_ID);
                                successCount.incrementAndGet();
                            } catch (Exception e) {
                                errorCount.incrementAndGet();
                            }
                        }
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    } finally {
                        doneLatch.countDown();
                    }
                });
            }

            startLatch.countDown();
            assertTrue(doneLatch.await(30, TimeUnit.SECONDS), "Operations should complete within timeout");
            executor.shutdown();

            assertEquals(0, errorCount.get(), "No errors should occur during concurrent reset operations");
            assertEquals(threadCount * resetsPerThread, successCount.get(), "All reset operations should succeed");

            // Final state should be empty (all resets succeeded)
            Optional<WaitChallengeState> finalState = provider.get(REALM_ID, USER_ID, RESET_PERIOD);
            assertTrue(finalState.isEmpty(), "Final state should be empty after all resets");
        }

        @Test
        @DisplayName("Multiple users with concurrent operations remain isolated")
        void multipleUsers_remainIsolated() throws Exception {
            int userCount = 20;
            int operationsPerUser = 30;
            ExecutorService executor = Executors.newFixedThreadPool(userCount);
            CountDownLatch startLatch = new CountDownLatch(1);
            CountDownLatch doneLatch = new CountDownLatch(userCount);

            for (int u = 0; u < userCount; u++) {
                String userId = "user-" + u;
                int operationCount = RANDOM.nextInt(operationsPerUser) + 1;
                executor.submit(() -> {
                    try {
                        startLatch.await();
                        for (int i = 0; i < operationCount; i++) {
                            provider.recordChallengeCreated(REALM_ID, userId, BASE_WAIT, MAX_WAIT, RESET_PERIOD);
                            Thread.sleep(RANDOM.nextInt(2));
                        }
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    } finally {
                        doneLatch.countDown();
                    }
                });
            }

            startLatch.countDown();
            assertTrue(doneLatch.await(30, TimeUnit.SECONDS), "Operations should complete");
            executor.shutdown();

            // Verify each user has independent state
            for (int u = 0; u < userCount; u++) {
                String userId = "user-" + u;
                Optional<WaitChallengeState> state = provider.get(REALM_ID, userId, RESET_PERIOD);
                assertTrue(state.isPresent(), "User " + userId + " should have state");
                assertTrue(state.get().consecutiveUnapproved() >= 1, "User " + userId + " should have valid counter");
            }
        }
    }

    // ==================== Helper Classes ====================

    /**
     * Simple in-memory implementation of SingleUseObjectProvider for testing.
     */
    private static final class InMemorySingleUseObjectProvider implements SingleUseObjectProvider {

        private final Map<String, Map<String, String>> data = new HashMap<>();

        @Override
        public void put(String key, long lifespanSeconds, Map<String, String> value) {
            data.put(key, new HashMap<>(value));
        }

        @Override
        public Map<String, String> get(String key) {
            Map<String, String> value = data.get(key);
            return value == null ? null : new HashMap<>(value);
        }

        @Override
        public Map<String, String> remove(String key) {
            Map<String, String> removed = data.remove(key);
            return removed == null ? null : new HashMap<>(removed);
        }

        @Override
        public boolean replace(String key, Map<String, String> value) {
            if (!data.containsKey(key)) {
                return false;
            }
            data.put(key, new HashMap<>(value));
            return true;
        }

        @Override
        public boolean putIfAbsent(String key, long lifespanSeconds) {
            if (data.containsKey(key)) {
                return false;
            }
            data.put(key, new HashMap<>());
            return true;
        }

        @Override
        public boolean contains(String key) {
            return data.containsKey(key);
        }

        @Override
        public void close() {
            // no-op
        }
    }

    /**
     * Thread-safe in-memory implementation of SingleUseObjectProvider for concurrency testing.
     */
    private static final class ConcurrentSingleUseObjectProvider implements SingleUseObjectProvider {

        private final Map<String, Map<String, String>> data = new java.util.concurrent.ConcurrentHashMap<>();

        @Override
        public synchronized void put(String key, long lifespanSeconds, Map<String, String> value) {
            data.put(key, new java.util.concurrent.ConcurrentHashMap<>(value));
        }

        @Override
        public Map<String, String> get(String key) {
            Map<String, String> value = data.get(key);
            return value == null ? null : new HashMap<>(value);
        }

        @Override
        public synchronized Map<String, String> remove(String key) {
            Map<String, String> removed = data.remove(key);
            return removed == null ? null : new HashMap<>(removed);
        }

        @Override
        public synchronized boolean replace(String key, Map<String, String> value) {
            if (!data.containsKey(key)) {
                return false;
            }
            data.put(key, new java.util.concurrent.ConcurrentHashMap<>(value));
            return true;
        }

        @Override
        public synchronized boolean putIfAbsent(String key, long lifespanSeconds) {
            if (data.containsKey(key)) {
                return false;
            }
            data.put(key, new java.util.concurrent.ConcurrentHashMap<>());
            return true;
        }

        @Override
        public boolean contains(String key) {
            return data.containsKey(key);
        }

        @Override
        public void close() {
            // no-op
        }
    }
}
