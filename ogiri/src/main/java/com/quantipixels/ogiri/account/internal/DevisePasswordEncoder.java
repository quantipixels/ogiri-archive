// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.account.internal;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.password.PasswordEncoder;

/** bcrypt-ruby input semantics, including truncation across a multibyte boundary. */
@org.jspecify.annotations.NullMarked
public final class DevisePasswordEncoder implements PasswordEncoder {
    private final int cost;

    public DevisePasswordEncoder() {
        this(12);
    }

    public DevisePasswordEncoder(int cost) {
        if (cost < 4 || cost > 31)
            throw new IllegalArgumentException("bcrypt cost must be between 4 and 31");
        this.cost = cost;
    }

    @Override
    public String encode(@org.jspecify.annotations.Nullable CharSequence password) {
        return BCrypt.hashpw(bytes(password), BCrypt.gensalt(cost));
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
