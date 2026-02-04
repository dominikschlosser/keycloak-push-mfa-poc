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

import static org.junit.jupiter.api.Assertions.*;

import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class WaitChallengeStateTest {

    @Test
    void isWaiting_returnsTrue_whenBeforeWaitUntil() {
        Instant now = Instant.now();
        WaitChallengeState state = new WaitChallengeState(now, now, 1, now.plusSeconds(60));

        assertTrue(state.isWaiting(now));
        assertTrue(state.isWaiting(now.plusSeconds(30)));
    }

    @Test
    void isWaiting_returnsFalse_whenAfterWaitUntil() {
        Instant now = Instant.now();
        WaitChallengeState state = new WaitChallengeState(now, now, 1, now.plusSeconds(60));

        assertFalse(state.isWaiting(now.plusSeconds(60)));
        assertFalse(state.isWaiting(now.plusSeconds(120)));
    }

    @Test
    void isWaiting_returnsFalse_whenWaitUntilIsNull() {
        Instant now = Instant.now();
        WaitChallengeState state = new WaitChallengeState(now, now, 1, null);

        assertFalse(state.isWaiting(now));
    }

    @Test
    void remainingWait_returnsCorrectDuration() {
        Instant now = Instant.now();
        WaitChallengeState state = new WaitChallengeState(now, now, 1, now.plusSeconds(60));

        Duration remaining = state.remainingWait(now);
        assertEquals(60, remaining.toSeconds());

        Duration remainingLater = state.remainingWait(now.plusSeconds(30));
        assertEquals(30, remainingLater.toSeconds());
    }

    @Test
    void remainingWait_returnsZero_whenNotWaiting() {
        Instant now = Instant.now();
        WaitChallengeState state = new WaitChallengeState(now, now, 1, now.minusSeconds(10));

        assertEquals(Duration.ZERO, state.remainingWait(now));
    }

    @Test
    void remainingWait_returnsZero_whenWaitUntilIsNull() {
        Instant now = Instant.now();
        WaitChallengeState state = new WaitChallengeState(now, now, 1, null);

        assertEquals(Duration.ZERO, state.remainingWait(now));
    }

    @Test
    void isExpired_returnsTrue_afterResetPeriod() {
        Instant now = Instant.now();
        Instant firstUnapproved = now.minus(Duration.ofHours(25));
        WaitChallengeState state = new WaitChallengeState(firstUnapproved, now, 1, now.plusSeconds(60));

        assertTrue(state.isExpired(now, Duration.ofHours(24)));
    }

    @Test
    void isExpired_returnsFalse_withinResetPeriod() {
        Instant now = Instant.now();
        Instant firstUnapproved = now.minus(Duration.ofHours(12));
        WaitChallengeState state = new WaitChallengeState(firstUnapproved, now, 1, now.plusSeconds(60));

        assertFalse(state.isExpired(now, Duration.ofHours(24)));
    }

    @Test
    void isExpired_returnsTrue_whenFirstUnapprovedAtIsNull() {
        Instant now = Instant.now();
        WaitChallengeState state = new WaitChallengeState(null, now, 1, now.plusSeconds(60));

        assertTrue(state.isExpired(now, Duration.ofHours(24)));
    }

    @Test
    void calculateNextWait_returnsZero_forZeroAttempts() {
        assertEquals(
                Duration.ZERO, WaitChallengeState.calculateNextWait(0, Duration.ofSeconds(10), Duration.ofHours(1)));
    }

    @Test
    void calculateNextWait_returnsBase_forFirstAttempt() {
        Duration result = WaitChallengeState.calculateNextWait(1, Duration.ofSeconds(10), Duration.ofHours(1));
        assertEquals(Duration.ofSeconds(10), result);
    }

    @Test
    void calculateNextWait_doublesEachAttempt() {
        Duration base = Duration.ofSeconds(10);
        Duration max = Duration.ofHours(1);

        assertEquals(Duration.ofSeconds(10), WaitChallengeState.calculateNextWait(1, base, max));
        assertEquals(Duration.ofSeconds(20), WaitChallengeState.calculateNextWait(2, base, max));
        assertEquals(Duration.ofSeconds(40), WaitChallengeState.calculateNextWait(3, base, max));
        assertEquals(Duration.ofSeconds(80), WaitChallengeState.calculateNextWait(4, base, max));
        assertEquals(Duration.ofSeconds(160), WaitChallengeState.calculateNextWait(5, base, max));
        assertEquals(Duration.ofSeconds(320), WaitChallengeState.calculateNextWait(6, base, max));
        assertEquals(Duration.ofSeconds(640), WaitChallengeState.calculateNextWait(7, base, max));
        assertEquals(Duration.ofSeconds(1280), WaitChallengeState.calculateNextWait(8, base, max));
        assertEquals(Duration.ofSeconds(2560), WaitChallengeState.calculateNextWait(9, base, max));
    }

    @Test
    void calculateNextWait_capsAtMaxWait() {
        Duration base = Duration.ofSeconds(10);
        Duration max = Duration.ofSeconds(3600);

        // At attempt 9, without cap: 2560s
        // At attempt 10, without cap: 5120s > 3600s, should be capped
        assertEquals(Duration.ofSeconds(3600), WaitChallengeState.calculateNextWait(10, base, max));
        assertEquals(Duration.ofSeconds(3600), WaitChallengeState.calculateNextWait(15, base, max));
        assertEquals(Duration.ofSeconds(3600), WaitChallengeState.calculateNextWait(100, base, max));
    }

    @Test
    void calculateNextWait_handlesOverflow() {
        // With exponent capped at 20, we avoid overflow
        Duration result = WaitChallengeState.calculateNextWait(50, Duration.ofSeconds(1), Duration.ofHours(24));
        assertTrue(result.compareTo(Duration.ofHours(24)) <= 0);
    }

    @Test
    void calculateNextWait_handlesNegativeAttempts() {
        assertEquals(
                Duration.ZERO, WaitChallengeState.calculateNextWait(-1, Duration.ofSeconds(10), Duration.ofHours(1)));
    }
}
