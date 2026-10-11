// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.security;

import com.quantipixels.ogiri.IssuedSession;
import com.quantipixels.ogiri.Session;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;

public record ResponseCredentials(
        String token, String client, String uid, String expiry, boolean batch) {
    public ResponseCredentials(String token, String client, String uid, String expiry) {
        this(token, client, uid, expiry, false);
    }

    public static final String ATTRIBUTE = ResponseCredentials.class.getName();

    public static void issued(
            HttpServletRequest request, OgiriRuntime runtime, IssuedSession issued, String uid) {
        request.setAttribute(
                runtime.responseCredentialsAttribute(), of(issued.session(), issued.token(), uid));
    }

    public static ResponseCredentials of(Session session, String token, String uid) {
        return new ResponseCredentials(
                token,
                session.client(),
                uid,
                Long.toString(session.expiresAt().toEpochMilli() / 1000));
    }

    public Map<String, String> headers() {
        if (!batch) return authorizationHeaders();
        var headers = new java.util.LinkedHashMap<>(authorizationHeaders());
        headers.put("access-token", " ");
        headers.put("expiry", " ");
        return Map.copyOf(headers);
    }

    public Map<String, String> authorizationHeaders() {
        return Map.of(
                "access-token",
                token,
                "client",
                client,
                "uid",
                uid,
                "expiry",
                expiry,
                "token-type",
                "Bearer");
    }

    @Override
    public String toString() {
        return "ResponseCredentials[redacted]";
    }
}
