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
    private final String credentialsAttribute;
    private final OgiriRealms realms;
    private final JsonMapper json = JsonMapper.builder().build();

    public DtaHeaderWriter(OgiriSettings settings) {
        this.settings = settings;
        this.realms = null;
        this.credentialsAttribute = ResponseCredentials.ATTRIBUTE;
    }

    public DtaHeaderWriter(OgiriRealms realms) {
        this.realms = realms;
        this.settings = realms.defaultRealm().settings();
        this.credentialsAttribute = realms.defaultRealm().responseCredentialsAttribute();
    }

    @Override
    public void writeHeaders(HttpServletRequest request, HttpServletResponse response) {
        if (!(request.getAttribute(
                        realms == null
                                ? credentialsAttribute
                                : realms.resolve(request).responseCredentialsAttribute())
                instanceof ResponseCredentials credentials)) {
            return;
        }
        var settings = realms == null ? this.settings : realms.resolve(request).settings();
        var headers = credentials.headers();
        headers.forEach(response::setHeader);
        response.setHeader("Cache-Control", "no-store");
        String encoded = json.writeValueAsString(credentials.authorizationHeaders());
        if (settings.cookieEnabled()) {
            if (credentials.batch()) return;
            response.addHeader(
                    "Set-Cookie",
                    new DtaHeaderWriter(settings)
                            .cookie(java.net.URLEncoder.encode(encoded, StandardCharsets.UTF_8), -1)
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
