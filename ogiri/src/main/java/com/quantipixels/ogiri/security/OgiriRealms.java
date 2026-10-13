// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.security;

import jakarta.servlet.http.HttpServletRequest;
import java.util.List;

/** Immutable mounts; requests outside a mount use the default realm. */
public record OgiriRealms(
        OgiriRuntime defaultRealm,
        List<OgiriRuntime> additional,
        java.util.Set<String> disabledEndpoints) {
    public OgiriRealms(OgiriRuntime defaultRealm, List<OgiriRuntime> additional) {
        this(defaultRealm, additional, java.util.Set.of());
    }

    public OgiriRealms {
        additional = List.copyOf(additional);
        disabledEndpoints = java.util.Set.copyOf(disabledEndpoints);
        var runtimes = new java.util.ArrayList<OgiriRuntime>();
        runtimes.add(defaultRealm);
        runtimes.addAll(additional);
        for (int i = 0; i < runtimes.size(); i++) {
            var left = runtimes.get(i).settings();
            if (left.cookieEnabled() && left.cookieName().equals("XSRF-TOKEN"))
                throw new IllegalArgumentException(
                        "Ogiri auth cookie name must differ from XSRF-TOKEN");
            for (int j = i + 1; j < runtimes.size(); j++) {
                var right = runtimes.get(j).settings();
                if (left.realm().equals(right.realm())
                        || overlaps(left.basePath(), right.basePath()))
                    throw new IllegalArgumentException(
                            "Ogiri realm names and mounts must be distinct and non-overlapping");
                if (left.cookieEnabled()
                        && right.cookieEnabled()
                        && left.cookieName().equals(right.cookieName())
                        && overlaps(left.cookiePath(), right.cookiePath()))
                    throw new IllegalArgumentException(
                            "Ogiri realm cookies require distinct names or non-overlapping paths");
            }
        }
    }

    private static boolean overlaps(String left, String right) {
        return left.equals(right)
                || left.equals("/")
                || right.equals("/")
                || left.startsWith(right + "/")
                || right.startsWith(left + "/");
    }

    public boolean endpointsEnabled(HttpServletRequest request) {
        return !disabledEndpoints.contains(resolve(request).settings().realm());
    }

    public OgiriRuntime resolve(HttpServletRequest request) {
        String path = OgiriConfigurer.path(request);
        for (var runtime : additional) {
            String mount = OgiriConfigurer.mount(request, runtime.settings().basePath());
            if (path.equals(mount) || path.startsWith(mount + "/")) return runtime;
        }
        return defaultRealm;
    }
}
