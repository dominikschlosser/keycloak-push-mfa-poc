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

package de.arbeitsagentur.keycloak.push.resource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.arbeitsagentur.keycloak.push.challenge.PushChallenge;
import de.arbeitsagentur.keycloak.push.challenge.PushChallengeStatus;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;

class PushMfaSseRegistryTest {

    @Test
    void connectionPermitsCanBeReleasedAndReused() {
        PushMfaSseRegistry registry = registry(challengeReader(challenge(PushChallenge.Type.AUTHENTICATION)));

        assertTrue(registry.tryAcquireConnection());
        assertFalse(registry.tryAcquireConnection());

        registry.releaseConnection();

        assertTrue(registry.tryAcquireConnection());
    }

    @Test
    void authenticationReadsRejectNonAuthenticationChallenges() {
        PushMfaSseRegistry registry = registry(challengeReader(challenge(PushChallenge.Type.ENROLLMENT)));

        PushMfaSseRegistry.ChallengeReadResult result =
                registry.readAuthenticationChallenge("challenge-1", "watch-secret");

        assertNull(result.challenge());
        assertEquals("BAD_TYPE", result.failureStatus());
    }

    @Test
    void enrollmentReadsAllowEnrollmentChallenges() {
        PushMfaSseRegistry registry = registry(challengeReader(challenge(PushChallenge.Type.ENROLLMENT)));

        PushMfaSseRegistry.ChallengeReadResult result = registry.readEnrollmentChallenge("challenge-1", "watch-secret");

        assertEquals(PushChallenge.Type.ENROLLMENT, result.challenge().getType());
        assertNull(result.failureStatus());
    }

    @Test
    void readsRejectWrongSecret() {
        PushMfaSseRegistry registry = registry(challengeReader(challenge(PushChallenge.Type.AUTHENTICATION)));

        PushMfaSseRegistry.ChallengeReadResult result =
                registry.readAuthenticationChallenge("challenge-1", "wrong-secret");

        assertNull(result.challenge());
        assertEquals("FORBIDDEN", result.failureStatus());
    }

    private PushMfaSseRegistry registry(PushMfaSseRegistry.ChallengeReader challengeReader) {
        return new PushMfaSseRegistry(1, 5000L, 60000L, challengeReader);
    }

    private PushMfaSseRegistry.ChallengeReader challengeReader(PushChallenge challenge) {
        return new PushMfaSseRegistry.ChallengeReader() {
            @Override
            public PushMfaSseRegistry.ChallengeReadResult readEnrollmentChallenge(String challengeId, String secret) {
                return read(challengeId, secret, false);
            }

            @Override
            public PushMfaSseRegistry.ChallengeReadResult readAuthenticationChallenge(
                    String challengeId, String secret) {
                return read(challengeId, secret, true);
            }

            private PushMfaSseRegistry.ChallengeReadResult read(String challengeId, String secret, boolean authOnly) {
                if (!challenge.getId().equals(challengeId)) {
                    return PushMfaSseRegistry.ChallengeReadResult.failure("NOT_FOUND");
                }
                if (!challenge.getWatchSecret().equals(secret)) {
                    return PushMfaSseRegistry.ChallengeReadResult.failure("FORBIDDEN");
                }
                if (authOnly && challenge.getType() != PushChallenge.Type.AUTHENTICATION) {
                    return PushMfaSseRegistry.ChallengeReadResult.failure("BAD_TYPE");
                }
                return PushMfaSseRegistry.ChallengeReadResult.success(challenge);
            }
        };
    }

    private PushChallenge challenge(PushChallenge.Type type) {
        Instant now = Instant.now();
        return new PushChallenge(
                "challenge-1",
                "realm-1",
                "user-1",
                new byte[0],
                "credential-1",
                "client-1",
                "watch-secret",
                "root-session-1",
                now.plusSeconds(60),
                type,
                PushChallengeStatus.PENDING,
                now,
                null,
                PushChallenge.UserVerificationMode.NONE,
                null,
                List.of());
    }
}
