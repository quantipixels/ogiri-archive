// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri;

import java.util.List;
import java.util.Map;

/** A contract error, with no underlying infrastructure detail exposed on the wire. */
public final class DtaFailure extends RuntimeException {
    private final int status;
    private final Map<String, Object> body;

    public DtaFailure(int status, String message) {
        this(status, Map.of("success", false, "errors", List.of(message)));
    }

    public DtaFailure(int status, Map<String, Object> body) {
        super("DTA request failed (" + status + ")");
        this.status = status;
        this.body = java.util.Collections.unmodifiableMap(new java.util.LinkedHashMap<>(body));
    }

    public int status() {
        return status;
    }

    public Map<String, Object> body() {
        return body;
    }

    public static Map<String, Object> unavailable() {
        return Map.of("success", false, "errors", List.of("Authentication service unavailable."));
    }
}
