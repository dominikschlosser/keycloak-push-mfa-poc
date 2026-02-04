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

package de.arbeitsagentur.keycloak.push.spi.waitchallenge;

import static org.junit.jupiter.api.Assertions.*;

import de.arbeitsagentur.keycloak.push.challenge.WaitChallengeState;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.SingleUseObjectProvider;
import org.mockito.Mockito;

class SingleUseObjectWaitChallengeStateProviderTest {

    private static final String REALM_ID = "test-realm";
    private static final String USER_ID = "test-user";
    private static final Duration BASE_WAIT = Duration.ofMillis(100);
    private static final Duration MAX_WAIT = Duration.ofSeconds(10);
    private static final Duration RESET_PERIOD = Duration.ofHours(24);

    private SingleUseObjectWaitChallengeStateProvider provider;
    private InMemorySingleUseObjectProvider singleUseObjects;

    @BeforeEach
    void setUp() {
        singleUseObjects = new InMemorySingleUseObjectProvider();
        KeycloakSession session = Mockito.mock(KeycloakSession.class);
        Mockito.when(session.singleUseObjects()).thenReturn(singleUseObjects);
        provider = new SingleUseObjectWaitChallengeStateProvider(session);
    }

    @Test
    void get_returnsEmpty_whenNoState() {
        Optional<WaitChallengeState> state = provider.get(REALM_ID, USER_ID, RESET_PERIOD);
        assertTrue(state.isEmpty());
    }

    @Test
    void recordChallengeCreated_createsState() {
        provider.recordChallengeCreated(REALM_ID, USER_ID, BASE_WAIT, MAX_WAIT, RESET_PERIOD);

        Optional<WaitChallengeState> state = provider.get(REALM_ID, USER_ID, RESET_PERIOD);
        assertTrue(state.isPresent());
        assertEquals(1, state.get().consecutiveUnapproved());
        assertNotNull(state.get().firstUnapprovedAt());
        assertNotNull(state.get().lastChallengeAt());
        assertNotNull(state.get().waitUntil());
    }

    @Test
    void recordChallengeCreated_incrementsCounter() {
        provider.recordChallengeCreated(REALM_ID, USER_ID, BASE_WAIT, MAX_WAIT, RESET_PERIOD);
        provider.recordChallengeCreated(REALM_ID, USER_ID, BASE_WAIT, MAX_WAIT, RESET_PERIOD);
        provider.recordChallengeCreated(REALM_ID, USER_ID, BASE_WAIT, MAX_WAIT, RESET_PERIOD);

        Optional<WaitChallengeState> state = provider.get(REALM_ID, USER_ID, RESET_PERIOD);
        assertTrue(state.isPresent());
        assertEquals(3, state.get().consecutiveUnapproved());
    }

    @Test
    void recordChallengeCreated_calculatesExponentialBackoff() {
        // First attempt: 100ms
        provider.recordChallengeCreated(REALM_ID, USER_ID, BASE_WAIT, MAX_WAIT, RESET_PERIOD);
        WaitChallengeState state1 =
                provider.get(REALM_ID, USER_ID, RESET_PERIOD).orElseThrow();
        long wait1 =
                Duration.between(state1.lastChallengeAt(), state1.waitUntil()).toMillis();
        assertEquals(100, wait1);

        // Second attempt: 200ms
        provider.recordChallengeCreated(REALM_ID, USER_ID, BASE_WAIT, MAX_WAIT, RESET_PERIOD);
        WaitChallengeState state2 =
                provider.get(REALM_ID, USER_ID, RESET_PERIOD).orElseThrow();
        long wait2 =
                Duration.between(state2.lastChallengeAt(), state2.waitUntil()).toMillis();
        assertEquals(200, wait2);

        // Third attempt: 400ms
        provider.recordChallengeCreated(REALM_ID, USER_ID, BASE_WAIT, MAX_WAIT, RESET_PERIOD);
        WaitChallengeState state3 =
                provider.get(REALM_ID, USER_ID, RESET_PERIOD).orElseThrow();
        long wait3 =
                Duration.between(state3.lastChallengeAt(), state3.waitUntil()).toMillis();
        assertEquals(400, wait3);
    }

    @Test
    void reset_clearsState() {
        provider.recordChallengeCreated(REALM_ID, USER_ID, BASE_WAIT, MAX_WAIT, RESET_PERIOD);
        assertTrue(provider.get(REALM_ID, USER_ID, RESET_PERIOD).isPresent());

        provider.reset(REALM_ID, USER_ID);
        assertTrue(provider.get(REALM_ID, USER_ID, RESET_PERIOD).isEmpty());
    }

    // E2E tests with actual waiting

    @Test
    void waitEnforcement_blocksImmediateRetry() throws Exception {
        provider.recordChallengeCreated(REALM_ID, USER_ID, BASE_WAIT, MAX_WAIT, RESET_PERIOD);
        WaitChallengeState state = provider.get(REALM_ID, USER_ID, RESET_PERIOD).orElseThrow();
        assertTrue(state.isWaiting(Instant.now()));

        // Wait for the wait period to expire
        Thread.sleep(150);

        WaitChallengeState after = provider.get(REALM_ID, USER_ID, RESET_PERIOD).orElseThrow();
        assertFalse(after.isWaiting(Instant.now()));
    }

    @Test
    void waitEnforcement_doublesOnSecondAttempt() throws Exception {
        // First attempt: 100ms wait
        provider.recordChallengeCreated(REALM_ID, USER_ID, BASE_WAIT, MAX_WAIT, RESET_PERIOD);
        Thread.sleep(150);

        // Second attempt: 200ms wait
        provider.recordChallengeCreated(REALM_ID, USER_ID, BASE_WAIT, MAX_WAIT, RESET_PERIOD);
        WaitChallengeState state = provider.get(REALM_ID, USER_ID, RESET_PERIOD).orElseThrow();

        assertEquals(2, state.consecutiveUnapproved());
        // Should still be waiting because 200ms > time elapsed
        assertTrue(state.isWaiting(Instant.now()));
        assertTrue(state.remainingWait(Instant.now()).toMillis() > 100);
    }

    @Test
    void resetPeriod_clearsStateAfterExpiry() throws Exception {
        // Use very short reset period for test
        Duration shortResetPeriod = Duration.ofMillis(100);
        provider.recordChallengeCreated(REALM_ID, USER_ID, BASE_WAIT, MAX_WAIT, shortResetPeriod);

        Thread.sleep(150);

        // State should be considered expired
        Optional<WaitChallengeState> state = provider.get(REALM_ID, USER_ID, shortResetPeriod);
        assertTrue(state.isEmpty());
    }

    @Test
    void preservesFirstUnapprovedAt_acrossMultipleAttempts() {
        provider.recordChallengeCreated(REALM_ID, USER_ID, BASE_WAIT, MAX_WAIT, RESET_PERIOD);
        WaitChallengeState first = provider.get(REALM_ID, USER_ID, RESET_PERIOD).orElseThrow();
        Instant firstUnapprovedAt = first.firstUnapprovedAt();

        provider.recordChallengeCreated(REALM_ID, USER_ID, BASE_WAIT, MAX_WAIT, RESET_PERIOD);
        provider.recordChallengeCreated(REALM_ID, USER_ID, BASE_WAIT, MAX_WAIT, RESET_PERIOD);

        WaitChallengeState latest =
                provider.get(REALM_ID, USER_ID, RESET_PERIOD).orElseThrow();
        assertEquals(firstUnapprovedAt, latest.firstUnapprovedAt());
        assertEquals(3, latest.consecutiveUnapproved());
    }

    @Test
    void isolatesStateByUser() {
        String user1 = "user-1";
        String user2 = "user-2";

        provider.recordChallengeCreated(REALM_ID, user1, BASE_WAIT, MAX_WAIT, RESET_PERIOD);
        provider.recordChallengeCreated(REALM_ID, user1, BASE_WAIT, MAX_WAIT, RESET_PERIOD);
        provider.recordChallengeCreated(REALM_ID, user2, BASE_WAIT, MAX_WAIT, RESET_PERIOD);

        assertEquals(
                2, provider.get(REALM_ID, user1, RESET_PERIOD).orElseThrow().consecutiveUnapproved());
        assertEquals(
                1, provider.get(REALM_ID, user2, RESET_PERIOD).orElseThrow().consecutiveUnapproved());
    }

    @Test
    void isolatesStateByRealm() {
        String realm1 = "realm-1";
        String realm2 = "realm-2";

        provider.recordChallengeCreated(realm1, USER_ID, BASE_WAIT, MAX_WAIT, RESET_PERIOD);
        provider.recordChallengeCreated(realm1, USER_ID, BASE_WAIT, MAX_WAIT, RESET_PERIOD);
        provider.recordChallengeCreated(realm2, USER_ID, BASE_WAIT, MAX_WAIT, RESET_PERIOD);

        assertEquals(
                2, provider.get(realm1, USER_ID, RESET_PERIOD).orElseThrow().consecutiveUnapproved());
        assertEquals(
                1, provider.get(realm2, USER_ID, RESET_PERIOD).orElseThrow().consecutiveUnapproved());
    }

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
