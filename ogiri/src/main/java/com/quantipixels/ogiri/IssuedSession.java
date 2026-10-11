// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Quanti Pixels
package com.quantipixels.ogiri;

/**
 * An issuance result. Explicitly deliver token() once over TLS; never serialize or log this object.
 */
public final class IssuedSession {
    private final Session session;
    private final String token;

    IssuedSession(Session session, String token) {
        this.session = session;
        this.token = token;
    }

    public Session session() {
        return session;
    }

    public String token() {
        return token;
    }

    @Override
    public String toString() {
        return "IssuedSession[id=" + session.id() + ", token=<redacted>]";
    }
}
