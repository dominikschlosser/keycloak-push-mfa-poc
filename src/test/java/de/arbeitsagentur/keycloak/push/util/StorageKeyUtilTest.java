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

package de.arbeitsagentur.keycloak.push.util;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * Tests for {@link StorageKeyUtil} collision resistance.
 */
@DisplayName("StorageKeyUtil")
class StorageKeyUtilTest {

    private static final String PREFIX = "test:";

    @Nested
    @DisplayName("Key collision prevention")
    class KeyCollisionPrevention {

        @Test
        @DisplayName("Keys with colons in different positions do not collide")
        void keysWithColonsInDifferentPositionsDoNotCollide() {
            // These would collide with simple concatenation: prefix + realm + ":" + user
            // prefix:realm:user:id vs prefix:realm:user:id (ambiguous!)
            String key1 = StorageKeyUtil.buildKey(PREFIX, "realm", "user:id");
            String key2 = StorageKeyUtil.buildKey(PREFIX, "realm:user", "id");

            assertNotEquals(key1, key2, "Keys should differ when colons appear in different components");

            // Verify the actual format
            assertEquals("test:5:realm:user:id", key1);
            assertEquals("test:10:realm:user:id", key2);
        }

        @Test
        @DisplayName("URN-style IDs do not collide")
        void urnStyleIdsDoNotCollide() {
            // Real-world scenario: customer using URN-style IDs
            String key1 = StorageKeyUtil.buildKey(PREFIX, "realm", "urn:x:y:uuid-123");
            String key2 = StorageKeyUtil.buildKey(PREFIX, "realm:urn:x:y", "uuid-123");

            assertNotEquals(key1, key2, "URN-style IDs should not cause collisions");
        }

        @Test
        @DisplayName("Empty component1 is handled correctly")
        void emptyComponent1IsHandledCorrectly() {
            String key = StorageKeyUtil.buildKey(PREFIX, "", "user");
            assertEquals("test:0::user", key);
        }

        @Test
        @DisplayName("Empty component2 is handled correctly")
        void emptyComponent2IsHandledCorrectly() {
            String key = StorageKeyUtil.buildKey(PREFIX, "realm", "");
            assertEquals("test:5:realm:", key);
        }

        @Test
        @DisplayName("Both components empty produces valid key")
        void bothComponentsEmptyProducesValidKey() {
            String key = StorageKeyUtil.buildKey(PREFIX, "", "");
            assertEquals("test:0::", key);
        }
    }

    @Nested
    @DisplayName("Length prefix accuracy")
    class LengthPrefixAccuracy {

        @ParameterizedTest(name = "component1=\"{0}\" should have length prefix {1}")
        @CsvSource({
            "a, 1",
            "ab, 2",
            "abc, 3",
            "abcdefghij, 10",
            "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789, 100"
        })
        void lengthPrefixMatchesActualLength(String component1, int expectedLength) {
            String key = StorageKeyUtil.buildKey(PREFIX, component1, "user");
            assertTrue(key.startsWith(PREFIX + expectedLength + ":"), "Key should start with correct length prefix");
        }

        @Test
        @DisplayName("Unicode characters are counted by code unit length")
        void unicodeCharactersCountedByCodeUnitLength() {
            // Java String.length() returns code unit count, not code point count
            String emoji = "realm\uD83D\uDE00"; // realm + 😀 (surrogate pair = 2 code units)
            String key = StorageKeyUtil.buildKey(PREFIX, emoji, "user");
            assertEquals("test:7:" + emoji + ":user", key);
        }
    }

    @Nested
    @DisplayName("Special characters in components")
    class SpecialCharactersInComponents {

        @Test
        @DisplayName("Multiple colons in component1")
        void multipleColonsInComponent1() {
            String key = StorageKeyUtil.buildKey(PREFIX, "a:b:c:d", "user");
            assertEquals("test:7:a:b:c:d:user", key);
        }

        @Test
        @DisplayName("Multiple colons in component2")
        void multipleColonsInComponent2() {
            String key = StorageKeyUtil.buildKey(PREFIX, "realm", "a:b:c:d");
            assertEquals("test:5:realm:a:b:c:d", key);
        }

        @Test
        @DisplayName("Newlines in components")
        void newlinesInComponents() {
            String key = StorageKeyUtil.buildKey(PREFIX, "realm\nwith\nnewlines", "user");
            assertEquals("test:19:realm\nwith\nnewlines:user", key);
        }

        @Test
        @DisplayName("Null bytes in components")
        void nullBytesInComponents() {
            String key = StorageKeyUtil.buildKey(PREFIX, "realm\0evil", "user");
            assertEquals("test:10:realm\0evil:user", key);
        }

        @Test
        @DisplayName("Digits in component1 that could confuse length parsing")
        void digitsInComponent1() {
            // This tests that "123:realm" as component1 doesn't cause confusion
            // with the length prefix
            String key = StorageKeyUtil.buildKey(PREFIX, "123:realm", "user");
            assertEquals("test:9:123:realm:user", key);
        }
    }

    @Nested
    @DisplayName("Key uniqueness")
    class KeyUniqueness {

        @Test
        @DisplayName("Same inputs produce same key")
        void sameInputsProduceSameKey() {
            String key1 = StorageKeyUtil.buildKey(PREFIX, "realm", "user");
            String key2 = StorageKeyUtil.buildKey(PREFIX, "realm", "user");
            assertEquals(key1, key2);
        }

        @Test
        @DisplayName("Different prefixes produce different keys")
        void differentPrefixesProduceDifferentKeys() {
            String key1 = StorageKeyUtil.buildKey("prefix1:", "realm", "user");
            String key2 = StorageKeyUtil.buildKey("prefix2:", "realm", "user");
            assertNotEquals(key1, key2);
        }

        @Test
        @DisplayName("Different component1 produces different keys")
        void differentComponent1ProducesDifferentKeys() {
            String key1 = StorageKeyUtil.buildKey(PREFIX, "realm1", "user");
            String key2 = StorageKeyUtil.buildKey(PREFIX, "realm2", "user");
            assertNotEquals(key1, key2);
        }

        @Test
        @DisplayName("Different component2 produces different keys")
        void differentComponent2ProducesDifferentKeys() {
            String key1 = StorageKeyUtil.buildKey(PREFIX, "realm", "user1");
            String key2 = StorageKeyUtil.buildKey(PREFIX, "realm", "user2");
            assertNotEquals(key1, key2);
        }
    }

    @Nested
    @DisplayName("Three-component keys")
    class ThreeComponentKeys {

        @Test
        @DisplayName("Keys with colons in different positions do not collide (3 components)")
        void keysWithColonsInDifferentPositionsDoNotCollide() {
            // These would collide with simple concatenation
            String key1 = StorageKeyUtil.buildKey(PREFIX, "realm", "jkt", "jti:value");
            String key2 = StorageKeyUtil.buildKey(PREFIX, "realm", "jkt:jti", "value");
            String key3 = StorageKeyUtil.buildKey(PREFIX, "realm:jkt", "jti", "value");

            assertNotEquals(key1, key2, "Keys should differ when colons appear in different components");
            assertNotEquals(key1, key3, "Keys should differ when colons appear in different components");
            assertNotEquals(key2, key3, "Keys should differ when colons appear in different components");

            // Verify the actual format: prefix + len(c1) + ":" + c1 + ":" + len(c2) + ":" + c2 + ":" + c3
            assertEquals("test:5:realm:3:jkt:jti:value", key1);
            assertEquals("test:5:realm:7:jkt:jti:value", key2);
            assertEquals("test:9:realm:jkt:3:jti:value", key3);
        }

        @Test
        @DisplayName("Same inputs produce same key (3 components)")
        void sameInputsProduceSameKey() {
            String key1 = StorageKeyUtil.buildKey(PREFIX, "realm", "jkt", "jti");
            String key2 = StorageKeyUtil.buildKey(PREFIX, "realm", "jkt", "jti");
            assertEquals(key1, key2);
        }

        @Test
        @DisplayName("Different component3 produces different keys")
        void differentComponent3ProducesDifferentKeys() {
            String key1 = StorageKeyUtil.buildKey(PREFIX, "realm", "jkt", "jti1");
            String key2 = StorageKeyUtil.buildKey(PREFIX, "realm", "jkt", "jti2");
            assertNotEquals(key1, key2);
        }

        @Test
        @DisplayName("Empty components handled correctly (3 components)")
        void emptyComponentsHandledCorrectly() {
            String key = StorageKeyUtil.buildKey(PREFIX, "", "", "jti");
            assertEquals("test:0::0::jti", key);
        }

        @Test
        @DisplayName("DPoP JTI key format is correct")
        void dpopJtiKeyFormatIsCorrect() {
            // Real-world scenario: DPoP JTI replay protection
            String key =
                    StorageKeyUtil.buildKey("push-mfa:dpop:jti:", "test-realm", "abc123thumbprint", "uuid-jti-value");
            assertEquals("push-mfa:dpop:jti:10:test-realm:16:abc123thumbprint:uuid-jti-value", key);
        }
    }
}
