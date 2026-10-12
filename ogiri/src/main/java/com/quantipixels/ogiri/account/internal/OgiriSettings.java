// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.account.internal;

import com.quantipixels.ogiri.account.OgiriAccount;
import java.time.Duration;
import java.util.List;

/** Immutable realm policy; durations are measured with the database clock. */
public record OgiriSettings(
        String realm,
        String basePath,
        boolean changeHeadersOnEachRequest,
        int maxNumberOfDevices,
        Duration tokenLifespan,
        Duration batchRequestBufferThrottle,
        boolean confirmable,
        boolean reconfirmable,
        boolean lockable,
        int maximumAttempts,
        String unlockStrategy,
        Duration unlockIn,
        boolean paranoid,
        List<String> redirectAllowlist,
        String defaultConfirmSuccessUrl,
        String defaultPasswordResetUrl,
        boolean removeTokensAfterPasswordReset,
        boolean requireClientPasswordResetToken,
        String checkCurrentPasswordBeforeUpdate,
        boolean cookieEnabled,
        Duration resetPasswordWithin,
        String cookieName,
        boolean cookieSecure,
        String cookieSameSite,
        String cookiePath,
        List<String> permittedFields) {
    private static final java.util.Set<String> RESERVED_FIELDS =
            java.util.Set.of(
                    "id",
                    "uid",
                    "email",
                    "provider",
                    "ogiri_generation",
                    "encrypted_password",
                    "password",
                    "password_confirmation",
                    "current_password",
                    "tokens",
                    "token",
                    "access_token",
                    "client",
                    "expiry",
                    "token_type",
                    "authentication_token",
                    "reset_password_token",
                    "reset_password_sent_at",
                    "allow_password_change",
                    "remember_created_at",
                    "remember_token",
                    "confirmation_token",
                    "confirmed_at",
                    "confirmation_sent_at",
                    "unconfirmed_email",
                    "failed_attempts",
                    "unlock_token",
                    "locked_at",
                    "sign_in_count",
                    "current_sign_in_at",
                    "last_sign_in_at",
                    "current_sign_in_ip",
                    "last_sign_in_ip",
                    "created_at",
                    "updated_at",
                    "password_salt");

    public OgiriSettings {
        new com.quantipixels.ogiri.Subject(realm, "", "policy");
        new com.quantipixels.ogiri.SessionPolicy(tokenLifespan, maxNumberOfDevices);
        if (!validPath(basePath)) {
            throw new IllegalArgumentException(
                    "ogiri.base-path must be a canonical literal absolute path");
        }
        if (maximumAttempts < 1
                || batchRequestBufferThrottle.isNegative()
                || unlockIn.isNegative()
                || resetPasswordWithin.isNegative()
                || resetPasswordWithin.isZero()) {
            throw new IllegalArgumentException("Ogiri durations and attempts must be positive");
        }
        if (!List.of("both", "email", "time").contains(unlockStrategy)
                || !List.of("false", "password", "attributes")
                        .contains(checkCurrentPasswordBeforeUpdate)) {
            throw new IllegalArgumentException("Invalid Ogiri unlock/password-check strategy");
        }
        redirectAllowlist = List.copyOf(redirectAllowlist);
        permittedFields = List.copyOf(permittedFields);
        for (String field : permittedFields) {
            if (RESERVED_FIELDS.contains(field.toLowerCase(java.util.Locale.ROOT)))
                throw new IllegalArgumentException(
                        "ogiri.permitted-fields cannot include reserved account column: " + field);
            if (!field.matches("[A-Za-z_][A-Za-z0-9_]*"))
                throw new IllegalArgumentException(
                        "ogiri.permitted-fields requires SQL identifiers: " + field);
        }
    }

    public com.quantipixels.ogiri.Subject subject(OgiriAccount account) {
        return new com.quantipixels.ogiri.Subject(realm, "", account.id());
    }

    /** Services enforce ownership; endpoints check only operations without a service check. */
    public void requireOwner(OgiriAccount identity, com.quantipixels.ogiri.Session session) {
        var expected = subject(identity);
        if (session == null || !expected.equals(session.subject())) {
            throw new com.quantipixels.ogiri.internal.DtaFailure(401, "Unauthorized");
        }
    }

    /** Recheck under the account lock before a previously authenticated request mutates it. */
    public void requireCurrentAccount(OgiriAccount identity, OgiriAccount current) {
        if (!subject(identity).equals(subject(current))
                || !identity.generation().equals(current.generation()))
            throw new com.quantipixels.ogiri.internal.DtaFailure(401, "Unauthorized");
    }

    private static boolean validPath(String path) {
        return path.startsWith("/")
                && path.length() > 1
                && !path.endsWith("/")
                && !path.contains("//")
                && path.chars()
                        .allMatch(
                                c ->
                                        (c >= 'A' && c <= 'Z')
                                                || (c >= 'a' && c <= 'z')
                                                || (c >= '0' && c <= '9')
                                                || "/_~-".indexOf(c) >= 0);
    }

    public static OgiriSettings defaults() {
        return new OgiriSettings(
                "users",
                "/auth",
                false,
                10,
                Duration.ofDays(14),
                Duration.ofSeconds(5),
                false,
                true,
                false,
                20,
                "both",
                Duration.ofHours(1),
                false,
                List.of(),
                "",
                "",
                false,
                false,
                "false",
                false,
                Duration.ofHours(6),
                "auth_cookie",
                true,
                "Lax",
                "/",
                List.of("name", "nickname", "image"));
    }
}
