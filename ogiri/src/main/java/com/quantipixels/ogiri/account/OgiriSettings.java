// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.account;

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
    }

    /**
     * Reject foreign session ownership before an endpoint or workflow touches this realm's store.
     */
    public void requireOwner(OgiriAccount identity, com.quantipixels.ogiri.Session session) {
        if (session == null
                || !realm.equals(session.subject().realm())
                || !identity.id().equals(session.subject().subjectId())) {
            throw new com.quantipixels.ogiri.DtaFailure(401, "Unauthorized");
        }
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
