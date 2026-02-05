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

package de.arbeitsagentur.keycloak.push.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.arbeitsagentur.keycloak.push.challenge.PushChallenge;
import de.arbeitsagentur.keycloak.push.util.PushMfaConstants;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.keycloak.models.AuthenticatorConfigModel;

class AuthenticatorConfigHelperTest {

    private static final String TEST_KEY = "testKey";

    // --- parseDurationSeconds tests ---

    @Test
    void parseDurationSecondsWithValidValue() {
        AuthenticatorConfigModel config = createConfig(TEST_KEY, "60");

        Duration result = AuthenticatorConfigHelper.parseDurationSeconds(config, TEST_KEY, Duration.ofSeconds(10));

        assertEquals(Duration.ofSeconds(60), result);
    }

    @Test
    void parseDurationSecondsWithLargeValue() {
        AuthenticatorConfigModel config = createConfig(TEST_KEY, "3600");

        Duration result = AuthenticatorConfigHelper.parseDurationSeconds(config, TEST_KEY, Duration.ofSeconds(10));

        assertEquals(Duration.ofSeconds(3600), result);
    }

    @Test
    void parseDurationSecondsWithNullConfigReturnsDefault() {
        Duration defaultValue = Duration.ofSeconds(30);

        Duration result = AuthenticatorConfigHelper.parseDurationSeconds(null, TEST_KEY, defaultValue);

        assertEquals(defaultValue, result);
    }

    @Test
    void parseDurationSecondsWithNullConfigMapReturnsDefault() {
        AuthenticatorConfigModel config = new AuthenticatorConfigModel();
        config.setConfig(null);
        Duration defaultValue = Duration.ofSeconds(30);

        Duration result = AuthenticatorConfigHelper.parseDurationSeconds(config, TEST_KEY, defaultValue);

        assertEquals(defaultValue, result);
    }

    @Test
    void parseDurationSecondsWithMissingKeyReturnsDefault() {
        AuthenticatorConfigModel config = createConfig("otherKey", "60");
        Duration defaultValue = Duration.ofSeconds(30);

        Duration result = AuthenticatorConfigHelper.parseDurationSeconds(config, TEST_KEY, defaultValue);

        assertEquals(defaultValue, result);
    }

    @Test
    void parseDurationSecondsWithBlankValueReturnsDefault() {
        AuthenticatorConfigModel config = createConfig(TEST_KEY, "   ");
        Duration defaultValue = Duration.ofSeconds(30);

        Duration result = AuthenticatorConfigHelper.parseDurationSeconds(config, TEST_KEY, defaultValue);

        assertEquals(defaultValue, result);
    }

    @Test
    void parseDurationSecondsWithEmptyStringReturnsDefault() {
        AuthenticatorConfigModel config = createConfig(TEST_KEY, "");
        Duration defaultValue = Duration.ofSeconds(30);

        Duration result = AuthenticatorConfigHelper.parseDurationSeconds(config, TEST_KEY, defaultValue);

        assertEquals(defaultValue, result);
    }

    @Test
    void parseDurationSecondsWithNonNumericValueReturnsDefault() {
        AuthenticatorConfigModel config = createConfig(TEST_KEY, "not-a-number");
        Duration defaultValue = Duration.ofSeconds(30);

        Duration result = AuthenticatorConfigHelper.parseDurationSeconds(config, TEST_KEY, defaultValue);

        assertEquals(defaultValue, result);
    }

    @Test
    void parseDurationSecondsWithZeroReturnsDefault() {
        AuthenticatorConfigModel config = createConfig(TEST_KEY, "0");
        Duration defaultValue = Duration.ofSeconds(30);

        Duration result = AuthenticatorConfigHelper.parseDurationSeconds(config, TEST_KEY, defaultValue);

        assertEquals(defaultValue, result);
    }

    @Test
    void parseDurationSecondsWithNegativeValueReturnsDefault() {
        AuthenticatorConfigModel config = createConfig(TEST_KEY, "-10");
        Duration defaultValue = Duration.ofSeconds(30);

        Duration result = AuthenticatorConfigHelper.parseDurationSeconds(config, TEST_KEY, defaultValue);

        assertEquals(defaultValue, result);
    }

    @Test
    void parseDurationSecondsTrimsWhitespace() {
        AuthenticatorConfigModel config = createConfig(TEST_KEY, "  120  ");

        Duration result = AuthenticatorConfigHelper.parseDurationSeconds(config, TEST_KEY, Duration.ofSeconds(10));

        assertEquals(Duration.ofSeconds(120), result);
    }

    // --- parseBoolean tests ---

    @Test
    void parseBooleanWithTrueString() {
        AuthenticatorConfigModel config = createConfig(TEST_KEY, "true");

        boolean result = AuthenticatorConfigHelper.parseBoolean(config, TEST_KEY, false);

        assertTrue(result);
    }

    @Test
    void parseBooleanWithFalseString() {
        AuthenticatorConfigModel config = createConfig(TEST_KEY, "false");

        boolean result = AuthenticatorConfigHelper.parseBoolean(config, TEST_KEY, true);

        assertFalse(result);
    }

    @Test
    void parseBooleanWithTrueUppercase() {
        AuthenticatorConfigModel config = createConfig(TEST_KEY, "TRUE");

        boolean result = AuthenticatorConfigHelper.parseBoolean(config, TEST_KEY, false);

        assertTrue(result);
    }

    @Test
    void parseBooleanWithNullConfigReturnsDefault() {
        boolean result = AuthenticatorConfigHelper.parseBoolean(null, TEST_KEY, true);

        assertTrue(result);
    }

    @Test
    void parseBooleanWithNullConfigReturnsDefaultFalse() {
        boolean result = AuthenticatorConfigHelper.parseBoolean(null, TEST_KEY, false);

        assertFalse(result);
    }

    @Test
    void parseBooleanWithMissingKeyReturnsDefault() {
        AuthenticatorConfigModel config = createConfig("otherKey", "true");

        boolean result = AuthenticatorConfigHelper.parseBoolean(config, TEST_KEY, false);

        assertFalse(result);
    }

    @Test
    void parseBooleanWithBlankValueReturnsDefault() {
        AuthenticatorConfigModel config = createConfig(TEST_KEY, "   ");

        boolean result = AuthenticatorConfigHelper.parseBoolean(config, TEST_KEY, true);

        assertTrue(result);
    }

    @Test
    void parseBooleanWithInvalidValueReturnsFalse() {
        // Boolean.parseBoolean returns false for any non-"true" string
        AuthenticatorConfigModel config = createConfig(TEST_KEY, "invalid");

        boolean result = AuthenticatorConfigHelper.parseBoolean(config, TEST_KEY, true);

        assertFalse(result);
    }

    @Test
    void parseBooleanWithYesReturnsFalse() {
        // Boolean.parseBoolean only recognizes "true", not "yes"
        AuthenticatorConfigModel config = createConfig(TEST_KEY, "yes");

        boolean result = AuthenticatorConfigHelper.parseBoolean(config, TEST_KEY, true);

        assertFalse(result);
    }

    // --- parsePositiveInt tests ---

    @Test
    void parsePositiveIntWithValidValue() {
        AuthenticatorConfigModel config = createConfig(TEST_KEY, "42");

        int result = AuthenticatorConfigHelper.parsePositiveInt(config, TEST_KEY, 10);

        assertEquals(42, result);
    }

    @Test
    void parsePositiveIntWithNullConfigReturnsDefault() {
        int result = AuthenticatorConfigHelper.parsePositiveInt(null, TEST_KEY, 10);

        assertEquals(10, result);
    }

    @Test
    void parsePositiveIntWithZeroReturnsDefault() {
        AuthenticatorConfigModel config = createConfig(TEST_KEY, "0");

        int result = AuthenticatorConfigHelper.parsePositiveInt(config, TEST_KEY, 10);

        assertEquals(10, result);
    }

    @Test
    void parsePositiveIntWithNegativeReturnsDefault() {
        AuthenticatorConfigModel config = createConfig(TEST_KEY, "-5");

        int result = AuthenticatorConfigHelper.parsePositiveInt(config, TEST_KEY, 10);

        assertEquals(10, result);
    }

    @Test
    void parsePositiveIntWithNonNumericReturnsDefault() {
        AuthenticatorConfigModel config = createConfig(TEST_KEY, "abc");

        int result = AuthenticatorConfigHelper.parsePositiveInt(config, TEST_KEY, 10);

        assertEquals(10, result);
    }

    // --- resolveUserVerificationMode tests ---

    @Test
    void resolveUserVerificationModeWithNone() {
        AuthenticatorConfigModel config = createConfig(PushMfaConstants.USER_VERIFICATION_CONFIG, "none");

        PushChallenge.UserVerificationMode result = AuthenticatorConfigHelper.resolveUserVerificationMode(config);

        assertEquals(PushChallenge.UserVerificationMode.NONE, result);
    }

    @Test
    void resolveUserVerificationModeWithNumberMatch() {
        AuthenticatorConfigModel config = createConfig(PushMfaConstants.USER_VERIFICATION_CONFIG, "number-match");

        PushChallenge.UserVerificationMode result = AuthenticatorConfigHelper.resolveUserVerificationMode(config);

        assertEquals(PushChallenge.UserVerificationMode.NUMBER_MATCH, result);
    }

    @Test
    void resolveUserVerificationModeWithNumberMatchUnderscore() {
        AuthenticatorConfigModel config = createConfig(PushMfaConstants.USER_VERIFICATION_CONFIG, "number_match");

        PushChallenge.UserVerificationMode result = AuthenticatorConfigHelper.resolveUserVerificationMode(config);

        assertEquals(PushChallenge.UserVerificationMode.NUMBER_MATCH, result);
    }

    @Test
    void resolveUserVerificationModeWithNumberMatchCamelCase() {
        AuthenticatorConfigModel config = createConfig(PushMfaConstants.USER_VERIFICATION_CONFIG, "numberMatch");

        PushChallenge.UserVerificationMode result = AuthenticatorConfigHelper.resolveUserVerificationMode(config);

        assertEquals(PushChallenge.UserVerificationMode.NUMBER_MATCH, result);
    }

    @Test
    void resolveUserVerificationModeWithPin() {
        AuthenticatorConfigModel config = createConfig(PushMfaConstants.USER_VERIFICATION_CONFIG, "pin");

        PushChallenge.UserVerificationMode result = AuthenticatorConfigHelper.resolveUserVerificationMode(config);

        assertEquals(PushChallenge.UserVerificationMode.PIN, result);
    }

    @Test
    void resolveUserVerificationModeWithPinUppercase() {
        AuthenticatorConfigModel config = createConfig(PushMfaConstants.USER_VERIFICATION_CONFIG, "PIN");

        PushChallenge.UserVerificationMode result = AuthenticatorConfigHelper.resolveUserVerificationMode(config);

        assertEquals(PushChallenge.UserVerificationMode.PIN, result);
    }

    @Test
    void resolveUserVerificationModeWithNullConfigFallsBackToNone() {
        PushChallenge.UserVerificationMode result = AuthenticatorConfigHelper.resolveUserVerificationMode(null);

        assertEquals(PushChallenge.UserVerificationMode.NONE, result);
    }

    @Test
    void resolveUserVerificationModeWithMissingKeyFallsBackToNone() {
        AuthenticatorConfigModel config = createConfig("otherKey", "number-match");

        PushChallenge.UserVerificationMode result = AuthenticatorConfigHelper.resolveUserVerificationMode(config);

        assertEquals(PushChallenge.UserVerificationMode.NONE, result);
    }

    @Test
    void resolveUserVerificationModeWithInvalidModeFallsBackToNone() {
        AuthenticatorConfigModel config = createConfig(PushMfaConstants.USER_VERIFICATION_CONFIG, "invalid-mode");

        PushChallenge.UserVerificationMode result = AuthenticatorConfigHelper.resolveUserVerificationMode(config);

        assertEquals(PushChallenge.UserVerificationMode.NONE, result);
    }

    @Test
    void resolveUserVerificationModeWithEmptyStringFallsBackToNone() {
        AuthenticatorConfigModel config = createConfig(PushMfaConstants.USER_VERIFICATION_CONFIG, "");

        PushChallenge.UserVerificationMode result = AuthenticatorConfigHelper.resolveUserVerificationMode(config);

        assertEquals(PushChallenge.UserVerificationMode.NONE, result);
    }

    // --- resolveAppUniversalLink tests ---

    @Test
    void resolveAppUniversalLinkWithValidUrl() {
        String expectedUrl = "https://myapp.example.com/";
        AuthenticatorConfigModel config = createConfig(PushMfaConstants.LOGIN_APP_UNIVERSAL_LINK_CONFIG, expectedUrl);

        String result = AuthenticatorConfigHelper.resolveAppUniversalLink(config, "/login");

        assertEquals(expectedUrl, result);
    }

    @Test
    void resolveAppUniversalLinkFallsBackToLegacyConfig() {
        String legacyUrl = "https://legacy.example.com/";
        AuthenticatorConfigModel config = createConfig(PushMfaConstants.APP_UNIVERSAL_LINK_CONFIG, legacyUrl);

        String result = AuthenticatorConfigHelper.resolveAppUniversalLink(config, "/login");

        assertEquals(legacyUrl, result);
    }

    @Test
    void resolveAppUniversalLinkPrefersLoginConfigOverLegacy() {
        AuthenticatorConfigModel config = new AuthenticatorConfigModel();
        Map<String, String> configMap = new HashMap<>();
        configMap.put(PushMfaConstants.LOGIN_APP_UNIVERSAL_LINK_CONFIG, "https://login.example.com/");
        configMap.put(PushMfaConstants.APP_UNIVERSAL_LINK_CONFIG, "https://legacy.example.com/");
        config.setConfig(configMap);

        String result = AuthenticatorConfigHelper.resolveAppUniversalLink(config, "/login");

        assertEquals("https://login.example.com/", result);
    }

    @Test
    void resolveAppUniversalLinkWithNullConfigUsesDefault() {
        String result = AuthenticatorConfigHelper.resolveAppUniversalLink(null, "/login");

        assertEquals(PushMfaConstants.DEFAULT_APP_UNIVERSAL_LINK + "/login", result);
    }

    @Test
    void resolveAppUniversalLinkWithMissingKeysUsesDefault() {
        AuthenticatorConfigModel config = createConfig("otherKey", "value");

        String result = AuthenticatorConfigHelper.resolveAppUniversalLink(config, "/enroll");

        assertEquals(PushMfaConstants.DEFAULT_APP_UNIVERSAL_LINK + "/enroll", result);
    }

    // --- Wait challenge config tests ---

    @Test
    void isWaitChallengeEnabledWithTrueValue() {
        AuthenticatorConfigModel config = createConfig(PushMfaConstants.WAIT_CHALLENGE_ENABLED_CONFIG, "true");

        assertTrue(AuthenticatorConfigHelper.isWaitChallengeEnabled(config));
    }

    @Test
    void isWaitChallengeEnabledWithFalseValue() {
        AuthenticatorConfigModel config = createConfig(PushMfaConstants.WAIT_CHALLENGE_ENABLED_CONFIG, "false");

        assertFalse(AuthenticatorConfigHelper.isWaitChallengeEnabled(config));
    }

    @Test
    void isWaitChallengeEnabledWithNullConfigReturnsDefault() {
        boolean result = AuthenticatorConfigHelper.isWaitChallengeEnabled(null);

        assertEquals(PushMfaConstants.DEFAULT_WAIT_CHALLENGE_ENABLED, result);
    }

    @Test
    void getWaitChallengeBaseWithValidValue() {
        AuthenticatorConfigModel config = createConfig(PushMfaConstants.WAIT_CHALLENGE_BASE_SECONDS_CONFIG, "30");

        Duration result = AuthenticatorConfigHelper.getWaitChallengeBase(config);

        assertEquals(Duration.ofSeconds(30), result);
    }

    @Test
    void getWaitChallengeBaseWithNullConfigReturnsDefault() {
        Duration result = AuthenticatorConfigHelper.getWaitChallengeBase(null);

        assertEquals(Duration.ofSeconds(PushMfaConstants.DEFAULT_WAIT_CHALLENGE_BASE_SECONDS), result);
    }

    @Test
    void getWaitChallengeMaxWithValidValue() {
        AuthenticatorConfigModel config = createConfig(PushMfaConstants.WAIT_CHALLENGE_MAX_SECONDS_CONFIG, "7200");

        Duration result = AuthenticatorConfigHelper.getWaitChallengeMax(config);

        assertEquals(Duration.ofSeconds(7200), result);
    }

    @Test
    void getWaitChallengeMaxWithNullConfigReturnsDefault() {
        Duration result = AuthenticatorConfigHelper.getWaitChallengeMax(null);

        assertEquals(Duration.ofSeconds(PushMfaConstants.DEFAULT_WAIT_CHALLENGE_MAX_SECONDS), result);
    }

    @Test
    void getWaitChallengeResetPeriodWithValidValue() {
        AuthenticatorConfigModel config = createConfig(PushMfaConstants.WAIT_CHALLENGE_RESET_HOURS_CONFIG, "48");

        Duration result = AuthenticatorConfigHelper.getWaitChallengeResetPeriod(config);

        assertEquals(Duration.ofHours(48), result);
    }

    @Test
    void getWaitChallengeResetPeriodWithNullConfigReturnsDefault() {
        Duration result = AuthenticatorConfigHelper.getWaitChallengeResetPeriod(null);

        assertEquals(Duration.ofHours(PushMfaConstants.DEFAULT_WAIT_CHALLENGE_RESET_HOURS), result);
    }

    // --- shouldIncludeUserVerificationInSameDeviceToken tests ---

    @Test
    void shouldIncludeUserVerificationInSameDeviceTokenWithTrue() {
        AuthenticatorConfigModel config =
                createConfig(PushMfaConstants.SAME_DEVICE_INCLUDE_USER_VERIFICATION_CONFIG, "true");

        assertTrue(AuthenticatorConfigHelper.shouldIncludeUserVerificationInSameDeviceToken(config));
    }

    @Test
    void shouldIncludeUserVerificationInSameDeviceTokenWithFalse() {
        AuthenticatorConfigModel config =
                createConfig(PushMfaConstants.SAME_DEVICE_INCLUDE_USER_VERIFICATION_CONFIG, "false");

        assertFalse(AuthenticatorConfigHelper.shouldIncludeUserVerificationInSameDeviceToken(config));
    }

    @Test
    void shouldIncludeUserVerificationInSameDeviceTokenWithNullConfigReturnsFalse() {
        boolean result = AuthenticatorConfigHelper.shouldIncludeUserVerificationInSameDeviceToken(null);

        assertFalse(result);
    }

    // --- Helper methods ---

    private static AuthenticatorConfigModel createConfig(String key, String value) {
        AuthenticatorConfigModel config = new AuthenticatorConfigModel();
        Map<String, String> configMap = new HashMap<>();
        configMap.put(key, value);
        config.setConfig(configMap);
        return config;
    }
}
