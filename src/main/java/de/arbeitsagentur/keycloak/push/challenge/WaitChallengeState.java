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

package de.arbeitsagentur.keycloak.push.challenge;

import java.time.Duration;
import java.time.Instant;

/**
 * Immutable record representing the wait challenge rate limiting state for a user.
 *
 * <p>This tracks consecutive unapproved push challenges and enforces exponential
 * backoff wait times.
 *
 * @param firstUnapprovedAt timestamp of the first unapproved challenge in the current streak
 * @param lastChallengeAt timestamp of the most recent challenge creation
 * @param consecutiveUnapproved count of consecutive challenges that were not accepted
 * @param waitUntil timestamp until which the user must wait before creating a new challenge
 */
public record WaitChallengeState(
        Instant firstUnapprovedAt, Instant lastChallengeAt, int consecutiveUnapproved, Instant waitUntil) {

    /**
     * Checks if the user is currently required to wait before creating a new challenge.
     *
     * @param now the current time
     * @return true if the user must wait, false otherwise
     */
    public boolean isWaiting(Instant now) {
        return waitUntil != null && now.isBefore(waitUntil);
    }

    /**
     * Calculates the remaining wait duration.
     *
     * @param now the current time
     * @return the remaining duration to wait, or zero if not waiting
     */
    public Duration remainingWait(Instant now) {
        if (!isWaiting(now)) {
            return Duration.ZERO;
        }
        return Duration.between(now, waitUntil);
    }

    /**
     * Checks if the wait state has expired based on the reset period.
     *
     * <p>The state expires when the time since the first unapproved challenge
     * exceeds the configured reset period.
     *
     * @param now the current time
     * @param resetPeriod the maximum period after which the state should reset
     * @return true if the state has expired, false otherwise
     */
    public boolean isExpired(Instant now, Duration resetPeriod) {
        if (firstUnapprovedAt == null) {
            return true;
        }
        return Duration.between(firstUnapprovedAt, now).compareTo(resetPeriod) > 0;
    }

    /**
     * Calculates the next wait duration using exponential backoff.
     *
     * <p>The wait time doubles with each consecutive unapproved challenge,
     * starting from the base wait time and capped at the maximum wait time.
     *
     * @param consecutiveUnapproved the number of consecutive unapproved challenges
     * @param baseWait the base wait duration for the first attempt
     * @param maxWait the maximum wait duration cap
     * @return the calculated wait duration
     */
    public static Duration calculateNextWait(int consecutiveUnapproved, Duration baseWait, Duration maxWait) {
        if (consecutiveUnapproved <= 0) {
            return Duration.ZERO;
        }
        // First unapproved = base wait, second = 2x, third = 4x, etc.
        int exponent = Math.min(consecutiveUnapproved - 1, 20); // Prevent overflow
        long multiplier = 1L << exponent;
        Duration calculated = baseWait.multipliedBy(multiplier);
        return calculated.compareTo(maxWait) > 0 ? maxWait : calculated;
    }
}
