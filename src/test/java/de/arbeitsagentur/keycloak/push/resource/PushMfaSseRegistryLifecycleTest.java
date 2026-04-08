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
import static org.junit.jupiter.api.Assertions.assertNull;

import de.arbeitsagentur.keycloak.push.challenge.PushChallenge;
import de.arbeitsagentur.keycloak.push.challenge.PushChallengeStatus;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class PushMfaSseRegistryLifecycleTest {

    @Test
    void retriesTransientChallengeNotFoundReadsForAuthentication() {
        AtomicInteger reads = new AtomicInteger();
        PushChallenge challenge = authenticationChallenge(PushChallengeStatus.PENDING);
        PushMfaSseRegistry registry =
                new PushMfaSseRegistry(2, 5000L, 60000L, new PushMfaSseRegistry.ChallengeReader() {
                    @Override
                    public PushMfaSseRegistry.ChallengeReadResult readEnrollmentChallenge(
                            String challengeId, String secret) {
                        return PushMfaSseRegistry.ChallengeReadResult.failure("BAD_TYPE");
                    }

                    @Override
                    public PushMfaSseRegistry.ChallengeReadResult readAuthenticationChallenge(
                            String challengeId, String secret) {
                        if (reads.incrementAndGet() == 1) {
                            return PushMfaSseRegistry.ChallengeReadResult.failure("NOT_FOUND");
                        }
                        return PushMfaSseRegistry.ChallengeReadResult.success(challenge);
                    }
                });

        PushMfaSseRegistry.ChallengeReadResult result =
                registry.readAuthenticationChallenge(challenge.getId(), challenge.getWatchSecret());

        assertEquals(2, reads.get());
        assertEquals(PushChallengeStatus.PENDING, result.challenge().getStatus());
        assertNull(result.failureStatus());
    }

    @Test
    void doesNotRetryNonTransientFailures() {
        AtomicInteger reads = new AtomicInteger();
        PushMfaSseRegistry registry = new PushMfaSseRegistry(2, 1234L, 5678L, new PushMfaSseRegistry.ChallengeReader() {
            @Override
            public PushMfaSseRegistry.ChallengeReadResult readEnrollmentChallenge(String challengeId, String secret) {
                reads.incrementAndGet();
                return PushMfaSseRegistry.ChallengeReadResult.failure("FORBIDDEN");
            }

            @Override
            public PushMfaSseRegistry.ChallengeReadResult readAuthenticationChallenge(
                    String challengeId, String secret) {
                reads.incrementAndGet();
                return PushMfaSseRegistry.ChallengeReadResult.failure("FORBIDDEN");
            }
        });

        PushMfaSseRegistry.ChallengeReadResult result = registry.readAuthenticationChallenge("challenge-1", "secret");

        assertEquals(1, reads.get());
        assertEquals("FORBIDDEN", result.failureStatus());
    }

    @Test
    void exposesConfiguredHeartbeatAndLifetime() {
        PushMfaSseRegistry registry = new PushMfaSseRegistry(3, 1234L, 5678L, new PushMfaSseRegistry.ChallengeReader() {
            @Override
            public PushMfaSseRegistry.ChallengeReadResult readEnrollmentChallenge(String challengeId, String secret) {
                return PushMfaSseRegistry.ChallengeReadResult.failure("NOT_FOUND");
            }

            @Override
            public PushMfaSseRegistry.ChallengeReadResult readAuthenticationChallenge(
                    String challengeId, String secret) {
                return PushMfaSseRegistry.ChallengeReadResult.failure("NOT_FOUND");
            }
        });

        assertEquals(3, registry.maxConnections());
        assertEquals(1234L, registry.heartbeatIntervalMillis());
        assertEquals(5678L, registry.maxConnectionLifetimeMillis());
    }

    private PushChallenge authenticationChallenge(PushChallengeStatus status) {
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
                PushChallenge.Type.AUTHENTICATION,
                status,
                now,
                status == PushChallengeStatus.PENDING ? null : now,
                PushChallenge.UserVerificationMode.NONE,
                null,
                List.of());
    }
}
