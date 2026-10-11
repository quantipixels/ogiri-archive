// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.account;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.password.PasswordEncoder;

/** bcrypt-ruby input semantics, including truncation across a multibyte boundary. */
@org.jspecify.annotations.NullMarked
public final class DevisePasswordEncoder implements PasswordEncoder {
    @Override
    public String encode(@org.jspecify.annotations.Nullable CharSequence password) {
        return BCrypt.hashpw(bytes(password), BCrypt.gensalt(12));
    }

    @Override
    public boolean matches(
            @org.jspecify.annotations.Nullable CharSequence password,
            @org.jspecify.annotations.Nullable String encoded) {
        if (password == null || encoded == null) {
            return false;
        }
        try {
            return BCrypt.checkpw(bytes(password), encoded);
        } catch (IllegalArgumentException malformed) {
            return false;
        }
    }

    private static byte[] bytes(@org.jspecify.annotations.Nullable CharSequence password) {
        byte[] utf8 =
                java.util.Objects.requireNonNull(password, "password")
                        .toString()
                        .getBytes(StandardCharsets.UTF_8);
        return Arrays.copyOf(utf8, Math.min(utf8.length, 72));
    }

    @Override
    public boolean upgradeEncoding(@org.jspecify.annotations.Nullable String encoded) {
        return false;
    }
}
