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
import static org.mockito.Mockito.*;

import de.arbeitsagentur.keycloak.push.challenge.WaitChallengeState;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RealmProvider;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;

class UserAttributeWaitChallengeStateProviderTest {

    private static final String REALM_ID = "test-realm";
    private static final String USER_ID = "test-user";
    private static final Duration BASE_WAIT = Duration.ofMillis(100);
    private static final Duration MAX_WAIT = Duration.ofSeconds(10);
    private static final Duration RESET_PERIOD = Duration.ofHours(24);
    private static final String ATTRIBUTE_KEY = "push-mfa-wait-state";

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
        when(user.getAttributeStream(anyString())).thenAnswer(invocation -> {
            String key = invocation.getArgument(0);
            List<String> values = userAttributes.get(key);
            return values != null ? values.stream() : Stream.empty();
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

    @Test
    void get_returnsEmpty_whenNoAttribute() {
        Optional<WaitChallengeState> state = provider.get(REALM_ID, USER_ID, RESET_PERIOD);
        assertTrue(state.isEmpty());
    }

    @Test
    void recordChallengeCreated_storesAttributeAsJson() {
        provider.recordChallengeCreated(REALM_ID, USER_ID, BASE_WAIT, MAX_WAIT, RESET_PERIOD);

        String json = userAttributes.get(ATTRIBUTE_KEY).get(0);
        assertNotNull(json);
        assertTrue(json.contains("firstUnapprovedAt"));
        assertTrue(json.contains("consecutiveUnapproved"));
        assertTrue(json.contains("waitUntil"));
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
    void reset_removesAttribute() {
        provider.recordChallengeCreated(REALM_ID, USER_ID, BASE_WAIT, MAX_WAIT, RESET_PERIOD);
        assertTrue(provider.get(REALM_ID, USER_ID, RESET_PERIOD).isPresent());

        provider.reset(REALM_ID, USER_ID);
        assertTrue(provider.get(REALM_ID, USER_ID, RESET_PERIOD).isEmpty());
        assertNull(userAttributes.get(ATTRIBUTE_KEY));
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
    void onDemandCleanup_deletesExpiredAttribute() throws Exception {
        // Use very short reset period for test
        Duration shortResetPeriod = Duration.ofMillis(100);
        provider.recordChallengeCreated(REALM_ID, USER_ID, BASE_WAIT, MAX_WAIT, shortResetPeriod);

        // Verify attribute exists
        assertNotNull(userAttributes.get(ATTRIBUTE_KEY));

        Thread.sleep(150);

        // On get(), the expired state should be deleted
        Optional<WaitChallengeState> state = provider.get(REALM_ID, USER_ID, shortResetPeriod);
        assertTrue(state.isEmpty());

        // Verify attribute was actually deleted (on-demand cleanup)
        verify(user).removeAttribute(ATTRIBUTE_KEY);
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
    void handlesInvalidJson_gracefully() {
        userAttributes.put(ATTRIBUTE_KEY, List.of("invalid json"));

        Optional<WaitChallengeState> state = provider.get(REALM_ID, USER_ID, RESET_PERIOD);
        assertTrue(state.isEmpty());

        // Should have removed the invalid attribute
        verify(user).removeAttribute(ATTRIBUTE_KEY);
    }

    @Test
    void handlesIncompleteJson_gracefully() {
        userAttributes.put(ATTRIBUTE_KEY, List.of("{\"firstUnapprovedAt\":\"2026-01-01T00:00:00Z\"}"));

        Optional<WaitChallengeState> state = provider.get(REALM_ID, USER_ID, RESET_PERIOD);
        assertTrue(state.isEmpty());

        // Should have removed the invalid attribute
        verify(user).removeAttribute(ATTRIBUTE_KEY);
    }
}
