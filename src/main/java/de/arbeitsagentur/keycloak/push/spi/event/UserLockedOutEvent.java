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

package de.arbeitsagentur.keycloak.push.spi.event;

import java.time.Instant;

/**
 * Event fired when a device requests to lock out the user's account.
 *
 * @param realmId            Realm where the lockout was requested
 * @param userId             User who was locked out
 * @param deviceCredentialId Credential ID of the device that requested lockout
 * @param deviceId           Device that requested the lockout
 * @param timestamp          When this event occurred
 */
public record UserLockedOutEvent(
        String realmId, String userId, String deviceCredentialId, String deviceId, Instant timestamp)
        implements PushMfaEvent {

    @Override
    public String eventType() {
        return PushMfaEventDetails.EventTypes.USER_LOCKED_OUT;
    }
}
