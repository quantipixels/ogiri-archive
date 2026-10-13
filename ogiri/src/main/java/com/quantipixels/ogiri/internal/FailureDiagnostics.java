// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.internal;

/** Sanitized stack traces: infrastructure exception messages may contain SQL values or mail. */
public final class FailureDiagnostics {
    private FailureDiagnostics() {}

    public static RuntimeException redacted(Throwable failure) {
        var diagnostic = new RuntimeException(failure.getClass().getName());
        diagnostic.setStackTrace(failure.getStackTrace());
        return diagnostic;
    }
}
