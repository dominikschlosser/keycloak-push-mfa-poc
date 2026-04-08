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

import de.arbeitsagentur.keycloak.push.challenge.PushChallenge;
import de.arbeitsagentur.keycloak.push.challenge.PushChallengeStore;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.Semaphore;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.utils.KeycloakModelUtils;

final class PushMfaSseRegistry {

    private static final int CHALLENGE_READ_ATTEMPTS = 5;
    private static final long CHALLENGE_READ_RETRY_MILLIS = 50L;

    private final int maxConnections;
    private final long heartbeatIntervalMillis;
    private final long maxConnectionLifetimeMillis;
    private final Semaphore permits;
    private final ChallengeReader challengeReader;

    PushMfaSseRegistry(
            int maxConnections,
            long heartbeatIntervalMillis,
            long maxConnectionLifetimeMillis,
            KeycloakSessionFactory sessionFactory) {
        this(
                maxConnections,
                heartbeatIntervalMillis,
                maxConnectionLifetimeMillis,
                createChallengeReader(sessionFactory));
    }

    PushMfaSseRegistry(
            int maxConnections,
            long heartbeatIntervalMillis,
            long maxConnectionLifetimeMillis,
            ChallengeReader challengeReader) {
        this.maxConnections = maxConnections;
        this.heartbeatIntervalMillis = heartbeatIntervalMillis;
        this.maxConnectionLifetimeMillis = maxConnectionLifetimeMillis;
        this.permits = new Semaphore(maxConnections);
        this.challengeReader = Objects.requireNonNull(challengeReader);
    }

    int maxConnections() {
        return maxConnections;
    }

    boolean tryAcquireConnection() {
        return permits.tryAcquire();
    }

    void releaseConnection() {
        permits.release();
    }

    long heartbeatIntervalMillis() {
        return heartbeatIntervalMillis;
    }

    long maxConnectionLifetimeMillis() {
        return maxConnectionLifetimeMillis;
    }

    ChallengeReadResult readEnrollmentChallenge(String challengeId, String secret) {
        return readWithRetry(() -> challengeReader.readEnrollmentChallenge(challengeId, secret));
    }

    ChallengeReadResult readAuthenticationChallenge(String challengeId, String secret) {
        return readWithRetry(() -> challengeReader.readAuthenticationChallenge(challengeId, secret));
    }

    private ChallengeReadResult readWithRetry(ChallengeLookup lookup) {
        ChallengeReadResult result = lookup.read();
        for (int attempt = 1;
                "NOT_FOUND".equals(result.failureStatus()) && attempt < CHALLENGE_READ_ATTEMPTS;
                attempt++) {
            try {
                Thread.sleep(CHALLENGE_READ_RETRY_MILLIS);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                return result;
            }
            result = lookup.read();
        }
        return result;
    }

    private static ChallengeReader createChallengeReader(KeycloakSessionFactory sessionFactory) {
        return new ChallengeReader() {
            @Override
            public ChallengeReadResult readEnrollmentChallenge(String challengeId, String secret) {
                return KeycloakModelUtils.runJobInTransactionWithResult(
                        sessionFactory, session -> readChallenge(session, challengeId, secret, false));
            }

            @Override
            public ChallengeReadResult readAuthenticationChallenge(String challengeId, String secret) {
                return KeycloakModelUtils.runJobInTransactionWithResult(
                        sessionFactory, session -> readChallenge(session, challengeId, secret, true));
            }
        };
    }

    private static ChallengeReadResult readChallenge(
            org.keycloak.models.KeycloakSession session,
            String challengeId,
            String secret,
            boolean authenticationOnly) {
        PushChallengeStore challengeStore = new PushChallengeStore(session);
        Optional<PushChallenge> challengeOpt = challengeStore.get(challengeId);
        if (challengeOpt.isEmpty()) {
            return ChallengeReadResult.failure("NOT_FOUND");
        }

        PushChallenge challenge = challengeOpt.get();
        if (authenticationOnly && challenge.getType() != PushChallenge.Type.AUTHENTICATION) {
            return ChallengeReadResult.failure("BAD_TYPE");
        }
        if (!Objects.equals(secret, challenge.getWatchSecret())) {
            return ChallengeReadResult.failure("FORBIDDEN");
        }
        return ChallengeReadResult.success(challenge);
    }

    @FunctionalInterface
    private interface ChallengeLookup {
        ChallengeReadResult read();
    }

    interface ChallengeReader {
        ChallengeReadResult readEnrollmentChallenge(String challengeId, String secret);

        ChallengeReadResult readAuthenticationChallenge(String challengeId, String secret);
    }

    record ChallengeReadResult(PushChallenge challenge, String failureStatus) {
        static ChallengeReadResult success(PushChallenge challenge) {
            return new ChallengeReadResult(challenge, null);
        }

        static ChallengeReadResult failure(String failureStatus) {
            return new ChallengeReadResult(null, failureStatus);
        }
    }
}
