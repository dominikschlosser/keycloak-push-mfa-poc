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
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import org.keycloak.util.JsonSerialization;

/** Helper for writing SSE events for enrollment and login challenges. */
public final class SseEventEmitter {

    public enum EventType {
        LOGIN,
        ENROLLMENT
    }

    public void writeStatusEvent(OutputStream output, String status, EventType type) throws IOException {
        writeStatusEvent(output, status, type, payloadForStatus(status));
    }

    public void writeStatusEvent(OutputStream output, String status, PushChallenge challenge, EventType type)
            throws IOException {
        writeStatusEvent(output, status, type, payloadForStatus(status, challenge, type));
    }

    public void writeRetryStatusEvent(
            OutputStream output, String status, PushChallenge challenge, EventType type, long retryAfterMillis)
            throws IOException {
        Map<String, Object> payload = payloadForStatus(status, challenge, type);
        payload.put("retryAfterMillis", retryAfterMillis);
        write(output, "retry: " + retryAfterMillis + '\n');
        writeStatusEvent(output, status, type, payload);
    }

    public void writeHeartbeat(OutputStream output) throws IOException {
        write(output, ": keepalive\n\n");
    }

    private void writeStatusEvent(OutputStream output, String status, EventType type, Map<String, Object> payload)
            throws IOException {
        write(output, "event: status\n");
        write(output, "data: " + JsonSerialization.writeValueAsString(payload) + "\n\n");
    }

    private Map<String, Object> payloadForStatus(String status) {
        Map<String, Object> payload = new HashMap<>();
        payload.put("status", status);
        return payload;
    }

    private Map<String, Object> payloadForStatus(String status, PushChallenge challenge, EventType type) {
        Map<String, Object> payload = payloadForStatus(status);
        payload.put("challengeId", challenge.getId());
        payload.put("expiresAt", challenge.getExpiresAt().toString());
        if (type == EventType.LOGIN) {
            payload.put("clientId", challenge.getClientId());
        }
        return payload;
    }

    private void write(OutputStream output, String event) throws IOException {
        output.write(event.getBytes(StandardCharsets.UTF_8));
        output.flush();
    }
}
