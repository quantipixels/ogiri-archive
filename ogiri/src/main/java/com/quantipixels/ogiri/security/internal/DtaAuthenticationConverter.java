// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.security.internal;

import com.quantipixels.ogiri.account.internal.OgiriSettings;
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
        Map<?, ?> bearer = authorization(request.getHeader("Authorization"));
        Map<?, ?> cookie = cookie(request);
        boolean cookieSource = false;
        var fields = new java.util.HashMap<String, String>();
        for (String key : java.util.List.of("access-token", "uid", "client")) {
            String header = request.getHeader(key);
            if (header != null) {
                fields.put(key, header);
            } else if (bearer.get(key) instanceof String value) {
                fields.put(key, value);
            } else if (cookie.get(key) instanceof String value) {
                fields.put(key, value);
                cookieSource = true;
            }
        }
        String token = fields.getOrDefault("access-token", "");
        String uid = fields.getOrDefault("uid", "");
        String client = fields.getOrDefault("client", "default");
        if (uid.isEmpty() && token.isEmpty()) {
            return null;
        }
        return new DtaAuthenticationToken(new DtaCredential(uid, client, token, cookieSource));
    }

    private Map<?, ?> cookie(HttpServletRequest request) {
        if (settings.cookieEnabled() && request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if (settings.cookieName().equals(cookie.getName())) {
                    try {
                        return parse(
                                java.net.URLDecoder.decode(
                                        cookie.getValue(), StandardCharsets.UTF_8));
                    } catch (IllegalArgumentException malformed) {
                        return Map.of();
                    }
                }
            }
        }
        return Map.of();
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
