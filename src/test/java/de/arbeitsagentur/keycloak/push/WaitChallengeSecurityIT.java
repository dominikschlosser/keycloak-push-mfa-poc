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

import de.arbeitsagentur.keycloak.push.challenge.WaitChallengeState;
import de.arbeitsagentur.keycloak.push.spi.WaitChallengeStateProvider;
import de.arbeitsagentur.keycloak.push.spi.waitchallenge.SingleUseObjectWaitChallengeStateProvider;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.SingleUseObjectProvider;
import org.mockito.Mockito;

/**
 * Security-focused integration tests for the Wait Challenge feature.
 *
 * <p>These tests focus on INPUT VALIDATION attacks against the wait challenge
 * rate limiting mechanism, including:
 * <ul>
 *   <li>Malformed User IDs - Long strings, special characters, null bytes, Unicode edge cases</li>
 *   <li>Invalid Realm IDs - Cross-realm attack attempts</li>
 *   <li>Configuration Boundary Tests - Zero/negative values, extreme values, overflow attempts</li>
 *   <li>Storage Key Injection - Special characters in storage keys</li>
 * </ul>
 */
class WaitChallengeSecurityIT {

    private static final Duration BASE_WAIT = Duration.ofSeconds(10);
    private static final Duration MAX_WAIT = Duration.ofHours(1);
    private static final Duration RESET_PERIOD = Duration.ofHours(24);
    private static final String VALID_REALM_ID = "test-realm";
    private static final String VALID_USER_ID = "550e8400-e29b-41d4-a716-446655440000";

    private WaitChallengeStateProvider provider;
    private InMemorySingleUseObjectProvider singleUseObjects;

    @BeforeEach
    void setUp() {
        singleUseObjects = new InMemorySingleUseObjectProvider();
        KeycloakSession session = Mockito.mock(KeycloakSession.class);
        Mockito.when(session.singleUseObjects()).thenReturn(singleUseObjects);
        provider = new SingleUseObjectWaitChallengeStateProvider(session);
    }

    // ==================== Malformed User IDs ====================

    @Nested
    @DisplayName("Malformed User ID Attacks")
    class MalformedUserIdAttacks {

        @Test
        @DisplayName("Extremely long user ID (10KB) should not cause memory issues or crashes")
        void extremelyLongUserIdHandledGracefully() {
            // ATTACK: Attempt to cause memory exhaustion or buffer overflow with oversized user ID
            String longUserId = "a".repeat(10240);

            assertDoesNotThrow(() -> {
                provider.recordChallengeCreated(VALID_REALM_ID, longUserId, BASE_WAIT, MAX_WAIT, RESET_PERIOD);
                Optional<WaitChallengeState> state = provider.get(VALID_REALM_ID, longUserId, RESET_PERIOD);
                assertTrue(state.isPresent(), "State should be stored even for long user IDs");
            });

            // Verify isolation: normal user should not be affected
            provider.recordChallengeCreated(VALID_REALM_ID, VALID_USER_ID, BASE_WAIT, MAX_WAIT, RESET_PERIOD);
            Optional<WaitChallengeState> normalState = provider.get(VALID_REALM_ID, VALID_USER_ID, RESET_PERIOD);
            assertTrue(normalState.isPresent());
            assertEquals(1, normalState.get().consecutiveUnapproved());
        }

        @Test
        @DisplayName("Null bytes in user ID should be handled safely")
        void nullBytesInUserIdHandledSafely() {
            // ATTACK: Null byte injection to potentially truncate strings or bypass validation
            String userIdWithNullByte = "user-id\u0000-malicious-suffix";

            assertDoesNotThrow(() -> {
                provider.recordChallengeCreated(VALID_REALM_ID, userIdWithNullByte, BASE_WAIT, MAX_WAIT, RESET_PERIOD);
                Optional<WaitChallengeState> state = provider.get(VALID_REALM_ID, userIdWithNullByte, RESET_PERIOD);
                assertTrue(state.isPresent());
            });

            // Verify the full string is used (not truncated at null byte)
            String truncatedUserId = "user-id";
            Optional<WaitChallengeState> truncatedState = provider.get(VALID_REALM_ID, truncatedUserId, RESET_PERIOD);
            assertTrue(truncatedState.isEmpty(), "Null byte should not cause string truncation");
        }

        @ParameterizedTest(name = "Special character: {0}")
        @DisplayName("Special characters in user ID should be handled safely")
        @ValueSource(
                strings = {
                    "user:id", // Colon - used in storage key format
                    "user:realm:inject", // Multiple colons - key format injection
                    "../../../etc/passwd", // Path-like string
                    "user\nid", // Newline
                    "user\rid", // Carriage return
                    "user\tid", // Tab
                    "user id", // Space
                    "user<>id", // Angle brackets
                    "user'\"id", // Quotes
                    "user${}id", // Dollar and braces
                    "user{{}}id" // Double braces
                })
        void specialCharactersInUserIdHandledSafely(String specialUserId) {
            // Verify special characters in user IDs don't cause storage issues
            assertDoesNotThrow(() -> {
                provider.recordChallengeCreated(VALID_REALM_ID, specialUserId, BASE_WAIT, MAX_WAIT, RESET_PERIOD);
                Optional<WaitChallengeState> state = provider.get(VALID_REALM_ID, specialUserId, RESET_PERIOD);
                assertTrue(state.isPresent(), "Special characters should be handled, not rejected");
                assertEquals(1, state.get().consecutiveUnapproved());
            });
        }

        @ParameterizedTest(name = "Unicode case: {0}")
        @DisplayName("Unicode edge cases in user ID should be handled safely")
        @MethodSource("de.arbeitsagentur.keycloak.push.WaitChallengeSecurityIT#unicodeEdgeCases")
        void unicodeEdgeCasesInUserIdHandledSafely(String description, String unicodeUserId) {
            // ATTACK: Unicode normalization attacks, homograph attacks, or encoding issues
            assertDoesNotThrow(() -> {
                provider.recordChallengeCreated(VALID_REALM_ID, unicodeUserId, BASE_WAIT, MAX_WAIT, RESET_PERIOD);
                Optional<WaitChallengeState> state = provider.get(VALID_REALM_ID, unicodeUserId, RESET_PERIOD);
                assertTrue(state.isPresent(), "Unicode should be handled: " + description);
            });
        }

        @Test
        @DisplayName("Empty user ID should not cause errors")
        void emptyUserIdHandled() {
            // ATTACK: Edge case that might cause null pointer or empty key issues
            assertDoesNotThrow(() -> {
                provider.recordChallengeCreated(VALID_REALM_ID, "", BASE_WAIT, MAX_WAIT, RESET_PERIOD);
            });

            // Empty string is a valid user ID, system should store and retrieve state
            Optional<WaitChallengeState> state = provider.get(VALID_REALM_ID, "", RESET_PERIOD);
            assertTrue(state.isPresent(), "State should be stored for empty user ID");
            assertEquals(1, state.get().consecutiveUnapproved(), "Counter should be incremented");
        }
    }

    // ==================== Invalid Realm ID Attacks ====================

    @Nested
    @DisplayName("Invalid Realm ID / Cross-Realm Attacks")
    class InvalidRealmIdAttacks {

        @Test
        @DisplayName("State should be isolated between different realms")
        void crossRealmIsolation() {
            // ATTACK: Attempt to access state from a different realm
            String realm1 = "victim-realm";
            String realm2 = "attacker-realm";

            // Create state in victim realm
            provider.recordChallengeCreated(realm1, VALID_USER_ID, BASE_WAIT, MAX_WAIT, RESET_PERIOD);
            provider.recordChallengeCreated(realm1, VALID_USER_ID, BASE_WAIT, MAX_WAIT, RESET_PERIOD);

            // Attacker tries to access from different realm
            Optional<WaitChallengeState> attackerView = provider.get(realm2, VALID_USER_ID, RESET_PERIOD);
            assertTrue(attackerView.isEmpty(), "Cross-realm access should not be possible");

            // Verify victim's state is intact
            Optional<WaitChallengeState> victimState = provider.get(realm1, VALID_USER_ID, RESET_PERIOD);
            assertTrue(victimState.isPresent());
            assertEquals(2, victimState.get().consecutiveUnapproved());
        }

        @Test
        @DisplayName("Realm/user IDs with colons do not cause key collisions")
        void realmIdWithColonIsolation() {
            // ATTACK: Craft realm ID to collide with another realm:user combination
            //
            // With length-prefixed key format, these are now distinct:
            //   realm="realm", userId="id:fake-user" -> key: push-mfa:wait-state:5:realm:id:fake-user
            //   realm="realm:id", userId="fake-user" -> key: push-mfa:wait-state:8:realm:id:fake-user
            //
            // This supports customers using URN-style IDs like "urn:x:y:uuid"

            String realm1 = "realm";
            String user1 = "id:fake-user"; // Contains colon

            String realm2 = "realm:id"; // Contains colon
            String user2 = "fake-user";

            provider.recordChallengeCreated(realm1, user1, BASE_WAIT, MAX_WAIT, RESET_PERIOD);
            provider.recordChallengeCreated(realm2, user2, BASE_WAIT, MAX_WAIT, RESET_PERIOD);

            Optional<WaitChallengeState> state1 = provider.get(realm1, user1, RESET_PERIOD);
            Optional<WaitChallengeState> state2 = provider.get(realm2, user2, RESET_PERIOD);

            assertTrue(state1.isPresent());
            assertTrue(state2.isPresent());

            // Each should have count of 1 - they are properly isolated
            assertEquals(
                    1, state1.get().consecutiveUnapproved(), "Keys should not collide with length-prefixed encoding");
            assertEquals(
                    1, state2.get().consecutiveUnapproved(), "Keys should not collide with length-prefixed encoding");
        }

        @Test
        @DisplayName("URN-style user IDs are properly isolated")
        void urnStyleUserIdsAreIsolated() {
            // Real-world scenario: customer using URN-style IDs
            String urnUser1 = "urn:company:division:user:12345";
            String urnUser2 = "urn:company:division:user:67890";

            provider.recordChallengeCreated(VALID_REALM_ID, urnUser1, BASE_WAIT, MAX_WAIT, RESET_PERIOD);
            provider.recordChallengeCreated(VALID_REALM_ID, urnUser2, BASE_WAIT, MAX_WAIT, RESET_PERIOD);

            Optional<WaitChallengeState> state1 = provider.get(VALID_REALM_ID, urnUser1, RESET_PERIOD);
            Optional<WaitChallengeState> state2 = provider.get(VALID_REALM_ID, urnUser2, RESET_PERIOD);

            assertTrue(state1.isPresent());
            assertTrue(state2.isPresent());

            assertEquals(1, state1.get().consecutiveUnapproved());
            assertEquals(1, state2.get().consecutiveUnapproved());
        }

        @ParameterizedTest(name = "Malicious realm ID: {0}")
        @DisplayName("Malicious realm IDs should be handled safely")
        @MethodSource("de.arbeitsagentur.keycloak.push.WaitChallengeSecurityIT#maliciousRealmIds")
        void maliciousRealmIdsHandledSafely(String maliciousRealm) {
            assertDoesNotThrow(() -> {
                provider.recordChallengeCreated(maliciousRealm, VALID_USER_ID, BASE_WAIT, MAX_WAIT, RESET_PERIOD);
                provider.get(maliciousRealm, VALID_USER_ID, RESET_PERIOD);
            });
        }
    }

    // ==================== Configuration Boundary Tests ====================

    @Nested
    @DisplayName("Configuration Boundary Attacks")
    class ConfigurationBoundaryAttacks {

        @Test
        @DisplayName("Zero base seconds should use sensible minimum (returns zero wait)")
        void zeroBaseSecondsHandled() {
            // ATTACK: Zero configuration to bypass rate limiting
            Duration zeroBase = Duration.ZERO;

            provider.recordChallengeCreated(VALID_REALM_ID, VALID_USER_ID, zeroBase, MAX_WAIT, RESET_PERIOD);
            Optional<WaitChallengeState> state = provider.get(VALID_REALM_ID, VALID_USER_ID, RESET_PERIOD);

            assertTrue(state.isPresent());
            // With zero base, wait time is zero - this tests that the system handles it without error
            Duration expectedWait = WaitChallengeState.calculateNextWait(1, zeroBase, MAX_WAIT);
            assertEquals(Duration.ZERO, expectedWait);
        }

        @Test
        @DisplayName("Negative base seconds (via Duration) should be handled")
        void negativeBaseSecondsHandled() {
            // ATTACK: Negative values to potentially cause underflow or bypass
            Duration negativeBase = Duration.ofSeconds(-10);

            // The system should handle this without crashing
            // Behavior: negative durations are technically valid Duration objects
            assertDoesNotThrow(() -> {
                provider.recordChallengeCreated(VALID_REALM_ID, VALID_USER_ID, negativeBase, MAX_WAIT, RESET_PERIOD);
            });

            // Negative base wait is a misconfiguration. The implementation does not validate inputs,
            // so negative base * 2^(n-1) produces a negative duration. This is acceptable behavior
            // for invalid configuration - callers should not pass negative durations.
            Duration calculatedWait = WaitChallengeState.calculateNextWait(1, negativeBase, MAX_WAIT);
            assertNotNull(calculatedWait, "Should return a Duration even with negative base");
        }

        @Test
        @DisplayName("Zero max seconds should cap wait time to zero")
        void zeroMaxSecondsHandled() {
            // ATTACK: Zero max to effectively disable rate limiting
            Duration zeroMax = Duration.ZERO;

            provider.recordChallengeCreated(VALID_REALM_ID, VALID_USER_ID, BASE_WAIT, zeroMax, RESET_PERIOD);
            Optional<WaitChallengeState> state = provider.get(VALID_REALM_ID, VALID_USER_ID, RESET_PERIOD);

            assertTrue(state.isPresent());
            // Wait should be capped at zero
            Duration wait = WaitChallengeState.calculateNextWait(1, BASE_WAIT, zeroMax);
            assertEquals(Duration.ZERO, wait);
        }

        @Test
        @DisplayName("Zero reset period should immediately expire state")
        void zeroResetPeriodHandled() {
            // ATTACK: Zero reset period to bypass accumulated state
            Duration zeroReset = Duration.ZERO;

            provider.recordChallengeCreated(VALID_REALM_ID, VALID_USER_ID, BASE_WAIT, MAX_WAIT, zeroReset);

            // With zero reset period, state should be considered immediately expired
            Optional<WaitChallengeState> state = provider.get(VALID_REALM_ID, VALID_USER_ID, zeroReset);

            // The state might be present but expired, or already cleaned up
            if (state.isPresent()) {
                assertTrue(state.get().isExpired(Instant.now(), zeroReset));
            }
        }

        @Test
        @DisplayName("Extremely large base seconds should not cause overflow")
        void extremelyLargeBaseSecondsHandled() {
            // ATTACK: Integer overflow attempt
            Duration hugeBase = Duration.ofSeconds(Long.MAX_VALUE / 2);

            assertDoesNotThrow(() -> {
                Duration result = WaitChallengeState.calculateNextWait(1, hugeBase, Duration.ofHours(24));
                // Should be capped at max
                assertTrue(result.compareTo(Duration.ofHours(24)) <= 0);
            });
        }

        @Test
        @DisplayName("Extremely large consecutive count should not cause overflow")
        void extremelyLargeConsecutiveCountHandled() {
            // ATTACK: Integer overflow in exponential calculation
            // Formula: baseWait * 2^(count-1) could overflow
            int hugeCount = 100;
            Duration base = Duration.ofSeconds(10);
            Duration max = Duration.ofHours(1);

            assertDoesNotThrow(() -> {
                Duration result = WaitChallengeState.calculateNextWait(hugeCount, base, max);
                // Should be capped at max, not overflow to negative
                assertTrue(result.compareTo(max) <= 0);
                assertFalse(result.isNegative(), "Duration should not overflow to negative");
            });
        }

        @Test
        @DisplayName("Integer.MAX_VALUE consecutive count should be handled safely")
        void intMaxValueConsecutiveCountHandled() {
            // ATTACK: Maximum integer value to cause overflow
            int maxCount = Integer.MAX_VALUE;

            assertDoesNotThrow(() -> {
                Duration result =
                        WaitChallengeState.calculateNextWait(maxCount, Duration.ofSeconds(1), Duration.ofHours(1));
                assertTrue(result.compareTo(Duration.ofHours(1)) <= 0);
                assertFalse(result.isNegative());
            });
        }

        @Test
        @DisplayName("Integer.MIN_VALUE consecutive count should be handled safely")
        void intMinValueConsecutiveCountHandled() {
            // ATTACK: Minimum integer value
            int minCount = Integer.MIN_VALUE;

            assertDoesNotThrow(() -> {
                Duration result =
                        WaitChallengeState.calculateNextWait(minCount, Duration.ofSeconds(1), Duration.ofHours(1));
                // Negative count should return zero wait
                assertEquals(Duration.ZERO, result);
            });
        }

        @Test
        @DisplayName("Max wait smaller than base wait should cap at max")
        void maxSmallerThanBaseHandled() {
            // ATTACK: Misconfiguration where max < base
            Duration smallMax = Duration.ofSeconds(5);
            Duration largeBase = Duration.ofSeconds(60);

            Duration result = WaitChallengeState.calculateNextWait(1, largeBase, smallMax);
            // Should be capped at max
            assertEquals(smallMax, result);
        }
    }

    // ==================== Storage Key Injection ====================

    @Nested
    @DisplayName("Storage Key Injection Attacks")
    class StorageKeyInjectionAttacks {

        @Test
        @DisplayName("Key prefix injection attempt should not allow access to arbitrary keys")
        void keyPrefixInjectionPrevented() {
            // ATTACK: Try to manipulate the key to access different prefixes
            // Key format: push-mfa:wait-state:{realmId}:{userId}

            String maliciousUserId = "user-id";
            String attackRealm = "anything:push-mfa:wait-state:other-realm";

            provider.recordChallengeCreated(attackRealm, maliciousUserId, BASE_WAIT, MAX_WAIT, RESET_PERIOD);

            // Should not be able to access data from "other-realm"
            Optional<WaitChallengeState> otherRealmState = provider.get("other-realm", maliciousUserId, RESET_PERIOD);
            assertTrue(otherRealmState.isEmpty(), "Key injection should not allow cross-realm access");
        }

        @Test
        @DisplayName("Multiple colons in user ID should not cause key parsing issues")
        void multipleColonsInUserId() {
            // ATTACK: Confuse key parsing with multiple delimiters
            String userId = "user:with:many:colons";

            provider.recordChallengeCreated(VALID_REALM_ID, userId, BASE_WAIT, MAX_WAIT, RESET_PERIOD);
            Optional<WaitChallengeState> state = provider.get(VALID_REALM_ID, userId, RESET_PERIOD);

            assertTrue(state.isPresent());
            assertEquals(1, state.get().consecutiveUnapproved());
        }

        @Test
        @DisplayName("Unicode normalization should not cause key collision")
        void unicodeNormalizationKeyCollision() {
            // ATTACK: Different Unicode representations of the same character
            // These look the same but are different code points
            String userId1 = "caf\u00e9"; // e with acute (precomposed)
            String userId2 = "cafe\u0301"; // e + combining acute (decomposed)

            provider.recordChallengeCreated(VALID_REALM_ID, userId1, BASE_WAIT, MAX_WAIT, RESET_PERIOD);
            provider.recordChallengeCreated(VALID_REALM_ID, userId2, BASE_WAIT, MAX_WAIT, RESET_PERIOD);

            Optional<WaitChallengeState> state1 = provider.get(VALID_REALM_ID, userId1, RESET_PERIOD);
            Optional<WaitChallengeState> state2 = provider.get(VALID_REALM_ID, userId2, RESET_PERIOD);

            assertTrue(state1.isPresent());
            assertTrue(state2.isPresent());
            // These should be treated as different users (no normalization collision)
            // Each should have count of 1
            assertEquals(1, state1.get().consecutiveUnapproved());
            assertEquals(1, state2.get().consecutiveUnapproved());
        }

        @Test
        @DisplayName("Case sensitivity should be preserved in keys")
        void caseSensitivityPreserved() {
            // ATTACK: Case insensitivity might allow user impersonation
            String lowerUser = "userid";
            String upperUser = "USERID";
            String mixedUser = "UserId";

            provider.recordChallengeCreated(VALID_REALM_ID, lowerUser, BASE_WAIT, MAX_WAIT, RESET_PERIOD);
            provider.recordChallengeCreated(VALID_REALM_ID, upperUser, BASE_WAIT, MAX_WAIT, RESET_PERIOD);
            provider.recordChallengeCreated(VALID_REALM_ID, mixedUser, BASE_WAIT, MAX_WAIT, RESET_PERIOD);

            // All three should be distinct
            assertEquals(
                    1,
                    provider.get(VALID_REALM_ID, lowerUser, RESET_PERIOD)
                            .orElseThrow()
                            .consecutiveUnapproved());
            assertEquals(
                    1,
                    provider.get(VALID_REALM_ID, upperUser, RESET_PERIOD)
                            .orElseThrow()
                            .consecutiveUnapproved());
            assertEquals(
                    1,
                    provider.get(VALID_REALM_ID, mixedUser, RESET_PERIOD)
                            .orElseThrow()
                            .consecutiveUnapproved());
        }
    }

    // ==================== State Manipulation Attacks ====================

    @Nested
    @DisplayName("State Manipulation Attacks")
    class StateManipulationAttacks {

        /**
         * Tests that sequential rapid requests properly increment the counter.
         *
         * <p>Note: This test runs single-threaded and verifies sequential request handling.
         * It does NOT test actual race conditions or concurrent access. For true concurrency
         * testing, use a multi-threaded test with proper synchronization barriers.
         */
        @Test
        @DisplayName("Rapid fire requests should properly increment counter")
        void rapidFireRequestsHandled() {
            // Sequential rapid requests - verifies counter increments correctly
            int rapidCount = 100;

            for (int i = 0; i < rapidCount; i++) {
                provider.recordChallengeCreated(VALID_REALM_ID, VALID_USER_ID, BASE_WAIT, MAX_WAIT, RESET_PERIOD);
            }

            Optional<WaitChallengeState> state = provider.get(VALID_REALM_ID, VALID_USER_ID, RESET_PERIOD);
            assertTrue(state.isPresent());
            assertEquals(rapidCount, state.get().consecutiveUnapproved());
        }

        @Test
        @DisplayName("Reset should completely clear state, not just decrement")
        void resetCompletelyClearsState() {
            // ATTACK: Verify reset actually removes state, not partial clear
            provider.recordChallengeCreated(VALID_REALM_ID, VALID_USER_ID, BASE_WAIT, MAX_WAIT, RESET_PERIOD);
            provider.recordChallengeCreated(VALID_REALM_ID, VALID_USER_ID, BASE_WAIT, MAX_WAIT, RESET_PERIOD);
            provider.recordChallengeCreated(VALID_REALM_ID, VALID_USER_ID, BASE_WAIT, MAX_WAIT, RESET_PERIOD);

            provider.reset(VALID_REALM_ID, VALID_USER_ID);

            Optional<WaitChallengeState> afterReset = provider.get(VALID_REALM_ID, VALID_USER_ID, RESET_PERIOD);
            assertTrue(afterReset.isEmpty(), "Reset should completely clear state");
        }

        @Test
        @DisplayName("Reset for one user should not affect other users")
        void resetIsolatedPerUser() {
            // ATTACK: Reset might accidentally clear other users' state
            String user1 = "user1";
            String user2 = "user2";

            provider.recordChallengeCreated(VALID_REALM_ID, user1, BASE_WAIT, MAX_WAIT, RESET_PERIOD);
            provider.recordChallengeCreated(VALID_REALM_ID, user2, BASE_WAIT, MAX_WAIT, RESET_PERIOD);

            provider.reset(VALID_REALM_ID, user1);

            assertTrue(provider.get(VALID_REALM_ID, user1, RESET_PERIOD).isEmpty());
            assertTrue(provider.get(VALID_REALM_ID, user2, RESET_PERIOD).isPresent());
        }
    }

    // ==================== Denial of Service Tests ====================

    @Nested
    @DisplayName("Denial of Service Attacks")
    class DenialOfServiceAttacks {

        /**
         * DOS ATTACK: Victim Lockout via Challenge Exhaustion
         *
         * <p>Attack vector: An attacker who knows the victim's username repeatedly triggers
         * MFA challenges and lets them expire. This builds up the victim's wait counter,
         * potentially locking them out even when they try to legitimately authenticate.
         *
         * <p>Security property: The maxWait configuration MUST bound the maximum lockout
         * period. Even after many unapproved challenges, the victim should never be locked
         * out for longer than maxWait.
         */
        @Test
        @DisplayName("maxWait bounds the maximum denial of service period")
        void maxWaitBoundsMaximumDenialPeriod() {
            Duration shortMax = Duration.ofSeconds(30);

            // Simulate many unapproved challenges (attacker DoS attempt)
            for (int i = 0; i < 20; i++) {
                provider.recordChallengeCreated(VALID_REALM_ID, VALID_USER_ID, BASE_WAIT, shortMax, RESET_PERIOD);
            }

            Optional<WaitChallengeState> state = provider.get(VALID_REALM_ID, VALID_USER_ID, RESET_PERIOD);
            assertTrue(state.isPresent());

            // The wait time should NEVER exceed maxWait, regardless of how many failures
            Duration calculatedWait =
                    WaitChallengeState.calculateNextWait(state.get().consecutiveUnapproved(), BASE_WAIT, shortMax);
            assertTrue(
                    calculatedWait.compareTo(shortMax) <= 0,
                    "Wait time must be bounded by maxWait. Got: " + calculatedWait + ", max: " + shortMax);

            // Verify the actual remaining wait is also bounded
            Instant now = Instant.now();
            Duration remaining = state.get().remainingWait(now);
            assertTrue(
                    remaining.compareTo(shortMax) <= 0, "Remaining wait must be bounded by maxWait. Got: " + remaining);
        }

        /**
         * DOS ATTACK: Permanent Lockout Prevention
         *
         * <p>Attack vector: An attacker continuously triggers challenges over an extended
         * period, attempting to permanently lock out a user.
         *
         * <p>Security property: The resetPeriod configuration ensures that wait state
         * expires after a period of no activity. Users cannot be permanently locked out.
         */
        @Test
        @DisplayName("Reset period prevents permanent lockout")
        void resetPeriodPreventsPermanentLockout() {
            Duration shortReset = Duration.ofSeconds(10);

            // Build up significant wait state
            for (int i = 0; i < 10; i++) {
                provider.recordChallengeCreated(VALID_REALM_ID, VALID_USER_ID, BASE_WAIT, MAX_WAIT, shortReset);
            }

            Optional<WaitChallengeState> stateBeforeExpiry = provider.get(VALID_REALM_ID, VALID_USER_ID, shortReset);
            assertTrue(stateBeforeExpiry.isPresent());
            assertEquals(10, stateBeforeExpiry.get().consecutiveUnapproved());

            // Simulate time passing beyond the reset period
            Instant futureTime = Instant.now().plus(shortReset).plusSeconds(1);
            assertTrue(
                    stateBeforeExpiry.get().isExpired(futureTime, shortReset),
                    "State should be expired after reset period");
        }

        /**
         * DOS ATTACK: Exponential Backoff Overflow
         *
         * <p>Attack vector: An attacker triggers an extreme number of failed challenges,
         * hoping the exponential backoff calculation will overflow and wrap around to
         * a small or negative value, bypassing rate limiting.
         *
         * <p>Security property: The backoff calculation must handle overflow safely and
         * always return a positive, bounded value.
         */
        @Test
        @DisplayName("Exponential backoff never overflows to bypass rate limiting")
        void exponentialBackoffNeverOverflows() {
            // Test with extreme values that could cause overflow
            int[] extremeAttempts = {30, 50, 100, 1000, Integer.MAX_VALUE};

            for (int attempts : extremeAttempts) {
                Duration result = WaitChallengeState.calculateNextWait(attempts, BASE_WAIT, MAX_WAIT);

                assertFalse(result.isNegative(), "Wait should never be negative for attempts=" + attempts);
                assertTrue(
                        result.compareTo(MAX_WAIT) <= 0, "Wait should be capped at maxWait for attempts=" + attempts);
                assertTrue(
                        result.compareTo(Duration.ZERO) >= 0, "Wait should be non-negative for attempts=" + attempts);
            }
        }

        /**
         * DOS ATTACK: Zero/Negative Configuration Exploitation
         *
         * <p>Attack vector: If misconfigured with zero or negative values, an attacker
         * might exploit this to bypass rate limiting entirely.
         *
         * <p>Security property: Even with zero/negative configuration, the system should
         * behave predictably and not crash.
         */
        @Test
        @DisplayName("Zero configuration values are handled safely")
        void zeroConfigurationValuesHandledSafely() {
            Duration zeroBase = Duration.ZERO;
            Duration zeroMax = Duration.ZERO;

            // Should not throw
            assertDoesNotThrow(() -> {
                provider.recordChallengeCreated(VALID_REALM_ID, VALID_USER_ID, zeroBase, zeroMax, RESET_PERIOD);
            });

            // Zero base means no wait (acceptable - misconfiguration disables protection)
            Duration result = WaitChallengeState.calculateNextWait(5, zeroBase, MAX_WAIT);
            assertEquals(Duration.ZERO, result, "Zero base should result in zero wait");

            // Zero max means wait is capped at zero
            Duration resultWithZeroMax = WaitChallengeState.calculateNextWait(5, BASE_WAIT, zeroMax);
            assertEquals(Duration.ZERO, resultWithZeroMax, "Zero max should cap wait at zero");
        }

        /**
         * DOS ATTACK: Resource Exhaustion via Many Users
         *
         * <p>Attack vector: An attacker creates wait state for many different users,
         * attempting to exhaust storage resources.
         *
         * <p>Security property: The system should handle many users without degradation.
         * This is a smoke test - real resource exhaustion testing requires load testing.
         */
        @Test
        @DisplayName("System handles wait state for many users")
        void systemHandlesWaitStateForManyUsers() {
            int userCount = 1000;

            // Create wait state for many users
            for (int i = 0; i < userCount; i++) {
                String userId = "user-" + i;
                provider.recordChallengeCreated(VALID_REALM_ID, userId, BASE_WAIT, MAX_WAIT, RESET_PERIOD);
            }

            // Verify all states are accessible and isolated
            for (int i = 0; i < userCount; i++) {
                String userId = "user-" + i;
                Optional<WaitChallengeState> state = provider.get(VALID_REALM_ID, userId, RESET_PERIOD);
                assertTrue(state.isPresent(), "State should exist for user-" + i);
                assertEquals(1, state.get().consecutiveUnapproved(), "Each user should have count=1");
            }
        }

        /**
         * DOS ATTACK: Rapid Counter Increment
         *
         * <p>Attack vector: An attacker rapidly triggers challenges to quickly build up
         * a victim's wait counter.
         *
         * <p>Security property: Each challenge should properly increment the counter,
         * and the wait time should grow exponentially but be bounded.
         */
        @Test
        @DisplayName("Rapid counter increment is properly tracked")
        void rapidCounterIncrementProperlyTracked() {
            int rapidCount = 50;

            for (int i = 0; i < rapidCount; i++) {
                provider.recordChallengeCreated(VALID_REALM_ID, VALID_USER_ID, BASE_WAIT, MAX_WAIT, RESET_PERIOD);
            }

            Optional<WaitChallengeState> state = provider.get(VALID_REALM_ID, VALID_USER_ID, RESET_PERIOD);
            assertTrue(state.isPresent());
            assertEquals(rapidCount, state.get().consecutiveUnapproved(), "All increments should be tracked");

            // Wait time should be at max due to high counter
            Duration expectedWait = WaitChallengeState.calculateNextWait(rapidCount, BASE_WAIT, MAX_WAIT);
            assertEquals(MAX_WAIT, expectedWait, "After many attempts, wait should be at max");
        }

        /**
         * DOS ATTACK: Cross-Realm Resource Isolation
         *
         * <p>Attack vector: An attacker in one realm creates excessive wait states,
         * attempting to affect users in other realms or exhaust shared resources.
         *
         * <p>Security property: Wait states must be isolated per realm. Activity in
         * one realm must not affect another realm's users or resources.
         */
        @Test
        @DisplayName("Cross-realm activity does not affect other realms")
        void crossRealmActivityDoesNotAffectOtherRealms() {
            String attackerRealm = "attacker-realm";
            String victimRealm = "victim-realm";
            String sharedUserId = "shared-user-id";

            // Attacker creates many wait states in their realm
            for (int i = 0; i < 100; i++) {
                provider.recordChallengeCreated(attackerRealm, "user-" + i, BASE_WAIT, MAX_WAIT, RESET_PERIOD);
            }

            // Attacker also creates state for a user ID that exists in victim realm
            for (int i = 0; i < 10; i++) {
                provider.recordChallengeCreated(attackerRealm, sharedUserId, BASE_WAIT, MAX_WAIT, RESET_PERIOD);
            }

            // Victim realm should be completely unaffected
            Optional<WaitChallengeState> victimState = provider.get(victimRealm, sharedUserId, RESET_PERIOD);
            assertTrue(victimState.isEmpty(), "Victim realm should have no state from attacker activity");

            // Verify attacker's state is contained to their realm
            Optional<WaitChallengeState> attackerState = provider.get(attackerRealm, sharedUserId, RESET_PERIOD);
            assertTrue(attackerState.isPresent());
            assertEquals(10, attackerState.get().consecutiveUnapproved());
        }

        /**
         * DOS ATTACK: Clock Skew Handling
         *
         * <p>Attack vector: If server clocks are skewed (common in distributed systems),
         * an attacker might exploit this to bypass wait periods or cause unexpected behavior.
         *
         * <p>Security property: The system should handle reasonable clock skew gracefully.
         * Past timestamps should be treated as expired, future timestamps should be enforced.
         */
        @Test
        @DisplayName("Clock skew is handled gracefully")
        void clockSkewIsHandledGracefully() {
            Instant now = Instant.now();

            // Simulate state created with slightly skewed clock (future)
            Instant skewedPast = now.minusSeconds(5);
            Instant skewedWaitUntil = now.plusSeconds(30);
            WaitChallengeState futureSkewState = new WaitChallengeState(skewedPast, skewedPast, 3, skewedWaitUntil);

            // Should still be waiting (waitUntil is in future relative to now)
            assertTrue(futureSkewState.isWaiting(now), "Should be waiting when waitUntil is in future");
            assertTrue(futureSkewState.remainingWait(now).toSeconds() > 0, "Should have positive remaining wait");

            // Simulate state where clock was ahead when state was created
            Instant pastWaitUntil = now.minusSeconds(10);
            WaitChallengeState pastSkewState = new WaitChallengeState(skewedPast, skewedPast, 3, pastWaitUntil);

            // Should not be waiting (waitUntil is in past)
            assertFalse(pastSkewState.isWaiting(now), "Should not be waiting when waitUntil is in past");
            assertEquals(Duration.ZERO, pastSkewState.remainingWait(now), "Remaining wait should be zero");
        }

        /**
         * DOS ATTACK: Wait Period vs Challenge TTL Edge Cases
         *
         * <p>Attack vector: When wait period and challenge TTL have specific relationships,
         * an attacker might exploit timing windows.
         *
         * <p>Security property: The wait period should be enforced independently of
         * challenge TTL. A user in a wait period cannot create new challenges.
         */
        @Test
        @DisplayName("Wait period enforced independently of challenge TTL")
        void waitPeriodEnforcedIndependentlyOfChallengeTtl() {
            Instant now = Instant.now();

            // Scenario: Challenge TTL is shorter than wait period
            // User creates challenge, it expires (TTL), wait period starts
            // User should not be able to create new challenge during wait period

            // Simulate: User had a challenge that expired, now in wait period
            Instant challengeExpired = now.minusSeconds(5); // Challenge expired 5 seconds ago
            Instant waitUntil = now.plusSeconds(25); // But wait period lasts 25 more seconds

            WaitChallengeState state = new WaitChallengeState(
                    challengeExpired.minusSeconds(10), // First unapproved
                    challengeExpired, // Last challenge
                    2, // Two unapproved challenges
                    waitUntil);

            // Even though challenge TTL has passed, wait period should still block
            assertTrue(state.isWaiting(now), "Wait period should block even after challenge TTL expires");
            assertTrue(state.remainingWait(now).toSeconds() > 20, "Should have significant remaining wait time");
        }

        /**
         * DOS ATTACK: Minimal Wait Period Cannot Be Bypassed
         *
         * <p>Attack vector: Even with the minimum configured wait period (1 second),
         * the rate limiting should still provide some protection.
         *
         * <p>Security property: Any non-zero wait period should be enforced.
         */
        @Test
        @DisplayName("Minimal wait period still provides protection")
        void minimalWaitPeriodStillProvidesProtection() {
            Duration minimalBase = Duration.ofMillis(100);
            Duration minimalMax = Duration.ofSeconds(1);

            // Even with minimal wait, state should track properly
            provider.recordChallengeCreated(VALID_REALM_ID, VALID_USER_ID, minimalBase, minimalMax, RESET_PERIOD);
            provider.recordChallengeCreated(VALID_REALM_ID, VALID_USER_ID, minimalBase, minimalMax, RESET_PERIOD);

            Optional<WaitChallengeState> state = provider.get(VALID_REALM_ID, VALID_USER_ID, RESET_PERIOD);
            assertTrue(state.isPresent());
            assertEquals(2, state.get().consecutiveUnapproved());

            // Wait time should be minimal but non-zero
            Duration calculatedWait = WaitChallengeState.calculateNextWait(2, minimalBase, minimalMax);
            assertTrue(calculatedWait.toMillis() > 0, "Even minimal wait should be positive");
            assertTrue(calculatedWait.compareTo(minimalMax) <= 0, "Should be capped at max");
        }
    }

    // ==================== Null Parameter Handling ====================

    @Nested
    @DisplayName("Null Parameter Handling")
    class NullParameterHandling {

        @Test
        @DisplayName("Null userId should be handled gracefully")
        void nullUserIdHandledGracefully() {
            // The implementation handles null userId gracefully (stores/retrieves with null as part of key)
            // This is acceptable behavior - null is treated as a valid (albeit unusual) user identifier
            assertDoesNotThrow(
                    () -> provider.recordChallengeCreated(VALID_REALM_ID, null, BASE_WAIT, MAX_WAIT, RESET_PERIOD),
                    "Null userId should be handled gracefully");

            assertDoesNotThrow(
                    () -> provider.get(VALID_REALM_ID, null, RESET_PERIOD),
                    "Null userId in get should be handled gracefully");
        }

        @Test
        @DisplayName("Null realmId should be handled gracefully")
        void nullRealmIdHandledGracefully() {
            // ATTACK: Passing null realmId might cause NPE or undefined behavior
            assertThrows(
                    NullPointerException.class,
                    () -> {
                        provider.recordChallengeCreated(null, VALID_USER_ID, BASE_WAIT, MAX_WAIT, RESET_PERIOD);
                    },
                    "Null realmId should throw NPE early");

            assertThrows(
                    NullPointerException.class,
                    () -> {
                        provider.get(null, VALID_USER_ID, RESET_PERIOD);
                    },
                    "Null realmId in get should throw NPE early");
        }

        @Test
        @DisplayName("Null baseWait Duration should be handled gracefully")
        void nullBaseWaitHandledGracefully() {
            // ATTACK: Passing null Duration for baseWait might cause NPE during calculation
            assertThrows(
                    NullPointerException.class,
                    () -> {
                        provider.recordChallengeCreated(VALID_REALM_ID, VALID_USER_ID, null, MAX_WAIT, RESET_PERIOD);
                    },
                    "Null baseWait should throw NPE early");
        }

        @Test
        @DisplayName("Null maxWait Duration should be handled gracefully")
        void nullMaxWaitHandledGracefully() {
            // ATTACK: Passing null Duration for maxWait might cause NPE during capping
            assertThrows(
                    NullPointerException.class,
                    () -> {
                        provider.recordChallengeCreated(VALID_REALM_ID, VALID_USER_ID, BASE_WAIT, null, RESET_PERIOD);
                    },
                    "Null maxWait should throw NPE early");
        }

        @Test
        @DisplayName("Null resetPeriod Duration should be handled gracefully")
        void nullResetPeriodHandledGracefully() {
            // ATTACK: Passing null Duration for resetPeriod might cause NPE during TTL calculation
            assertThrows(
                    NullPointerException.class,
                    () -> {
                        provider.recordChallengeCreated(VALID_REALM_ID, VALID_USER_ID, BASE_WAIT, MAX_WAIT, null);
                    },
                    "Null resetPeriod should throw NPE early");

            // Also test null resetPeriod in get method
            provider.recordChallengeCreated(VALID_REALM_ID, VALID_USER_ID, BASE_WAIT, MAX_WAIT, RESET_PERIOD);
            assertThrows(
                    NullPointerException.class,
                    () -> {
                        provider.get(VALID_REALM_ID, VALID_USER_ID, null);
                    },
                    "Null resetPeriod in get should throw NPE early");
        }
    }

    // ==================== Helper Methods and Test Data ====================

    static Stream<Arguments> unicodeEdgeCases() {
        return Stream.of(
                Arguments.of("Right-to-left override", "user\u202Eid"),
                Arguments.of("Zero-width joiner", "user\u200Did"),
                Arguments.of("Zero-width non-joiner", "user\u200Cid"),
                Arguments.of("Zero-width space", "user\u200Bid"),
                Arguments.of("BOM character", "\uFEFFuserid"),
                Arguments.of("Surrogate pair (emoji)", "user\uD83D\uDE00id"),
                Arguments.of("Combining diacritical", "user\u0308id"),
                Arguments.of("Private use area", "user\uE000id"),
                Arguments.of("Replacement character", "user\uFFFDid"),
                Arguments.of("Cyrillic lookalike (homograph)", "user\u0430id"), // Cyrillic 'a'
                Arguments.of("Greek lookalike", "user\u03B1id"), // Greek 'alpha'
                Arguments.of("Full-width characters", "\uFF55\uFF53\uFF45\uFF52") // Full-width "user"
                );
    }

    static Stream<String> maliciousRealmIds() {
        return Stream.of(
                "", // Empty
                "realm:user:inject", // Key format injection
                "../../../other-realm", // Path traversal
                "realm\u0000real", // Null byte
                "realm%00real", // URL-encoded null byte
                "a".repeat(1000) // Very long
                );
    }

    // ==================== In-Memory Provider for Testing ====================

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
}
