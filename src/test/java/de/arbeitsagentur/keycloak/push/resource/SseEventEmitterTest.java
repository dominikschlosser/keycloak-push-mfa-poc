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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.arbeitsagentur.keycloak.push.challenge.PushChallenge;
import de.arbeitsagentur.keycloak.push.challenge.PushChallengeStatus;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;

class SseEventEmitterTest {

    @Test
    void statusEventOmitsRetryWhenNotRequested() throws Exception {
        SseEventEmitter emitter = new SseEventEmitter();
        ByteArrayOutputStream output = new ByteArrayOutputStream();

        emitter.writeStatusEvent(
                output, "PENDING", challenge(PushChallengeStatus.PENDING), SseEventEmitter.EventType.LOGIN);

        String event = output.toString(StandardCharsets.UTF_8);
        assertTrue(event.contains("event: status"));
        assertTrue(event.contains("\"status\":\"PENDING\""));
        assertFalse(event.contains("retry:"));
    }

    @Test
    void retryStatusEventIncludesReconnectDelay() throws Exception {
        SseEventEmitter emitter = new SseEventEmitter();
        ByteArrayOutputStream output = new ByteArrayOutputStream();

        emitter.writeRetryStatusEvent(
                output,
                "TOO_MANY_CONNECTIONS",
                challenge(PushChallengeStatus.PENDING),
                SseEventEmitter.EventType.LOGIN,
                1500L);

        String event = output.toString(StandardCharsets.UTF_8);
        assertTrue(event.contains("retry: 1500"));
        assertTrue(event.contains("\"retryAfterMillis\":1500"));
    }

    @Test
    void heartbeatUsesSseCommentFormat() throws Exception {
        SseEventEmitter emitter = new SseEventEmitter();
        ByteArrayOutputStream output = new ByteArrayOutputStream();

        emitter.writeHeartbeat(output);

        assertTrue(output.toString(StandardCharsets.UTF_8).contains(": keepalive"));
    }

    private PushChallenge challenge(PushChallengeStatus status) {
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
