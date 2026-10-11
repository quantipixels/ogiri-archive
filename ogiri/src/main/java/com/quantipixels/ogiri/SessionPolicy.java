// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Quanti Pixels
package com.quantipixels.ogiri;

import java.time.Duration;
import java.util.Objects;

/** Fixed lifetime and admission limit. All application instances must use the same policy. */
public record SessionPolicy(Duration lifetime, int maximumSessions) {
    public SessionPolicy {
        Objects.requireNonNull(lifetime, "lifetime");
        if (lifetime.compareTo(Duration.ofSeconds(1)) < 0
                || lifetime.compareTo(Duration.ofDays(365)) > 0)
            throw new IllegalArgumentException("lifetime must be between one second and 365 days");
        if (maximumSessions < 1 || maximumSessions > 1000)
            throw new IllegalArgumentException("maximumSessions must be between 1 and 1000");
    }

    public static SessionPolicy defaults() {
        return new SessionPolicy(Duration.ofDays(14), 10);
    }
}
