// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.security;

import com.quantipixels.ogiri.account.OgiriSettings;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.springframework.http.ResponseCookie;
import org.springframework.security.web.header.HeaderWriter;
import tools.jackson.databind.json.JsonMapper;

/** Executes on response commitment without database access. */
public final class DtaHeaderWriter implements HeaderWriter {
    private final OgiriSettings settings;
    private final JsonMapper json = JsonMapper.builder().build();

    public DtaHeaderWriter(OgiriSettings settings) {
        this.settings = settings;
    }

    @Override
    public void writeHeaders(HttpServletRequest request, HttpServletResponse response) {
        if (!(request.getAttribute(ResponseCredentials.ATTRIBUTE)
                instanceof ResponseCredentials credentials)) {
            return;
        }
        var headers = credentials.headers();
        headers.forEach(response::setHeader);
        response.setHeader("Cache-Control", "no-store");
        String encoded = json.writeValueAsString(credentials.authorizationHeaders());
        if (settings.cookieEnabled()) {
            response.addHeader(
                    "Set-Cookie",
                    cookie(java.net.URLEncoder.encode(encoded, StandardCharsets.UTF_8), -1)
                            .toString());
        } else {
            response.setHeader(
                    "Authorization",
                    "Bearer "
                            + Base64.getEncoder()
                                    .encodeToString(encoded.getBytes(StandardCharsets.UTF_8)));
        }
    }

    public ResponseCookie cookie(String value, long age) {
        return ResponseCookie.from(settings.cookieName(), value)
                .httpOnly(true)
                .secure(settings.cookieSecure())
                .sameSite(settings.cookieSameSite())
                .path(settings.cookiePath())
                .maxAge(age)
                .build();
    }
}
