// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.internal;

import com.quantipixels.ogiri.DtaFailure;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/** Link hosts come exclusively from configuration; redirects match parsed URL parts. */
public final class PublicLinks {
    private final String base;
    private final List<String> allowlist;

    public PublicLinks(String publicBase, String mount, List<String> allowlist) {
        var uri = absolute(publicBase);
        if (uri == null || uri.getRawQuery() != null || uri.getRawFragment() != null)
            throw new IllegalArgumentException(
                    "Configure ogiri.public-base-url (or spring.application.url) as an absolute HTTP(S) URL");
        base = publicBase.replaceAll("/+$", "") + mount;
        this.allowlist = List.copyOf(allowlist);
    }

    public String mail(String endpoint, Map<String, String> values) {
        return query(base + endpoint, values);
    }

    public String redirect(String supplied, String fallback, int missingStatus, String missing) {
        String target = supplied == null || supplied.isBlank() ? fallback : supplied;
        if (target == null || target.isBlank()) throw new DtaFailure(missingStatus, missing);
        if (!allowed(target)) {
            var body = new java.util.LinkedHashMap<String, Object>();
            body.put("success", false);
            body.put("errors", List.of("Redirect to '" + target + "' not allowed."));
            body.put("status", "error");
            body.put("data", null);
            throw new DtaFailure(422, body);
        }
        return target;
    }

    public boolean allowed(String value) {
        URI candidate = absolute(value);
        return candidate != null
                && (allowlist.isEmpty()
                        || allowlist.stream().anyMatch(pattern -> matches(candidate, pattern)));
    }

    private static URI absolute(String value) {
        if (value == null) return null;
        try {
            URI uri = URI.create(value);
            return List.of("http", "https").contains(uri.getScheme())
                            && uri.getHost() != null
                            && uri.getRawUserInfo() == null
                    ? uri
                    : null;
        } catch (IllegalArgumentException invalid) {
            return null;
        }
    }

    private static boolean matches(URI candidate, String pattern) {
        try {
            URI rule = URI.create(pattern);
            String authority = rule.getRawAuthority();
            if (authority == null
                    || authority.contains("@")
                    || !candidate.getScheme().equals(rule.getScheme())) return false;
            String host = authority;
            String port = "";
            int colon = authority.lastIndexOf(':');
            if (colon > authority.lastIndexOf(']')) {
                host = authority.substring(0, colon);
                port = authority.substring(colon + 1);
            }
            int actualPort =
                    candidate.getPort() < 0
                            ? defaultPort(candidate.getScheme())
                            : candidate.getPort();
            boolean portMatches =
                    port.equals("*")
                            || actualPort
                                    == (port.isEmpty()
                                            ? defaultPort(rule.getScheme())
                                            : Integer.parseInt(port));
            return portMatches
                    && glob(host.toLowerCase(java.util.Locale.ROOT), "[-a-z0-9.]*")
                            .matcher(candidate.getHost().toLowerCase(java.util.Locale.ROOT))
                            .matches()
                    && glob(rest(rule), ".*").matcher(rest(candidate)).matches();
        } catch (IllegalArgumentException invalid) {
            return false;
        }
    }

    private static int defaultPort(String scheme) {
        return scheme.equals("https") ? 443 : 80;
    }

    private static String rest(URI uri) {
        return (uri.getRawPath() == null ? "" : uri.getRawPath())
                + (uri.getRawQuery() == null ? "" : "?" + uri.getRawQuery())
                + (uri.getRawFragment() == null ? "" : "#" + uri.getRawFragment());
    }

    private static Pattern glob(String value, String wildcard) {
        return Pattern.compile(
                java.util.Arrays.stream(value.split("\\*", -1))
                        .map(Pattern::quote)
                        .collect(java.util.stream.Collectors.joining(wildcard)),
                Pattern.DOTALL);
    }

    public static String query(String target, Map<String, String> values) {
        int hash = target.indexOf('#');
        String fragment = hash < 0 ? "" : target.substring(hash);
        String path = hash < 0 ? target : target.substring(0, hash);
        String query =
                values.entrySet().stream()
                        .map(entry -> encode(entry.getKey()) + "=" + encode(entry.getValue()))
                        .collect(java.util.stream.Collectors.joining("&"));
        return path + (path.contains("?") ? "&" : "?") + query + fragment;
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
