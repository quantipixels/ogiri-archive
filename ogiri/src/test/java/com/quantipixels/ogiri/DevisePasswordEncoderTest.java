// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.quantipixels.ogiri.account.internal.DevisePasswordEncoder;
import org.junit.jupiter.api.Test;

class DevisePasswordEncoderTest {
    @Test
    void migrationCostCanMatchTheDummyAndNewPasswordPolicy() {
        var encoder = new DevisePasswordEncoder(10);
        String hash = encoder.encode("migration-password");
        org.junit.jupiter.api.Assertions.assertTrue(hash.startsWith("$2a$10$"));
        org.junit.jupiter.api.Assertions.assertTrue(encoder.matches("migration-password", hash));
        org.junit.jupiter.api.Assertions.assertFalse(encoder.matches("wrong", hash));
    }

    @Test
    void rubyCompatibleTruncationNeverDecodesPartialUtf8() {
        var encoder = new DevisePasswordEncoder();
        String base = "a".repeat(71) + "é";
        String encoded = encoder.encode(base + "tail");
        assertTrue(encoded.startsWith("$2a$12$"));
        assertTrue(encoder.matches(base + "another-tail", encoded));
        assertFalse(encoder.matches("a".repeat(72), encoded));
        String ascii = encoder.encode("x".repeat(73));
        assertTrue(encoder.matches("x".repeat(72), ascii));
        assertTrue(encoder.matches("x".repeat(128), ascii));
        for (String prefix : new String[] {"$2a$", "$2b$", "$2y$"}) {
            assertTrue(encoder.matches("x".repeat(73), prefix + ascii.substring(4)));
        }
        assertFalse(encoder.matches("wrong", ascii));
    }
}
