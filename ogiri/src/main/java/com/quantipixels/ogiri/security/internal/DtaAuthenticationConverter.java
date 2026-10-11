// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.security.internal;

import com.quantipixels.ogiri.account.OgiriSettings;
import com.quantipixels.ogiri.security.DtaAuthenticationToken;
import com.quantipixels.ogiri.security.DtaCredential;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;
import tools.jackson.databind.json.JsonMapper;

public final class DtaAuthenticationConverter implements AuthenticationConverter {
    private final OgiriSettings settings;
    private final JsonMapper json = JsonMapper.builder().build();

    public DtaAuthenticationConverter(OgiriSettings settings) {
        this.settings = settings;
    }

    @Override
    public Authentication convert(HttpServletRequest request) {
        Map<?, ?> fallback = authorization(request.getHeader("Authorization"));
        boolean cookieSource = false;
        if (settings.cookieEnabled() && !hasHeaders(request) && request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if (settings.cookieName().equals(cookie.getName())) {
                    try {
                        fallback =
                                parse(
                                        java.net.URLDecoder.decode(
                                                cookie.getValue(), StandardCharsets.UTF_8));
                    } catch (IllegalArgumentException malformed) {
                        fallback = Map.of();
                    }
                    cookieSource = true;
                }
            }
        }
        String token = field(request, fallback, "access-token", "");
        String uid = field(request, fallback, "uid", "");
        String client = field(request, fallback, "client", "default");
        if (uid.isEmpty() && token.isEmpty()) {
            return null;
        }
        return new DtaAuthenticationToken(new DtaCredential(uid, client, token, cookieSource));
    }

    public static boolean hasHeaders(HttpServletRequest request) {
        return request.getHeader("access-token") != null
                || request.getHeader("uid") != null
                || request.getHeader("client") != null
                || request.getHeader("Authorization") != null;
    }

    private static String field(
            HttpServletRequest request, Map<?, ?> fallback, String key, String absent) {
        String header = request.getHeader(key);
        if (header != null) {
            return header;
        }
        Object value = fallback.get(key);
        return value instanceof String string ? string : absent;
    }

    private Map<?, ?> authorization(String value) {
        if (value == null || value.isBlank()) {
            return Map.of();
        }
        String word = value.strip().replaceFirst("(?s)^.*\\s", "");
        try {
            return parse(new String(Base64.getDecoder().decode(word), StandardCharsets.UTF_8));
        } catch (IllegalArgumentException malformed) {
            return Map.of();
        }
    }

    private Map<?, ?> parse(String value) {
        try {
            Object decoded = json.readValue(value, Object.class);
            return decoded instanceof Map<?, ?> map ? map : Map.of();
        } catch (tools.jackson.core.JacksonException malformed) {
            return Map.of();
        }
    }
}
