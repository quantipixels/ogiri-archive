// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Quanti Pixels
package com.quantipixels.ogiri;

import java.util.Objects;

/** Stable account identity. An empty tenantId denotes a non-tenanted realm, never a wildcard. */
public record Subject(String realm, String tenantId, String subjectId)
        implements java.io.Serializable {
    public Subject {
        Objects.requireNonNull(realm, "realm");
        Objects.requireNonNull(tenantId, "tenantId");
        Objects.requireNonNull(subjectId, "subjectId");
        if (!realm.matches("[a-z0-9][a-z0-9._-]{0,62}"))
            throw new IllegalArgumentException("Invalid realm");
        if (tenantId.codePoints().anyMatch(cp -> cp >= 0xD800 && cp <= 0xDFFF)
                || subjectId.codePoints().anyMatch(cp -> cp >= 0xD800 && cp <= 0xDFFF))
            throw new IllegalArgumentException("Identity contains invalid Unicode");
        if (tenantId.length() > 255 || tenantId.indexOf(0) >= 0)
            throw new IllegalArgumentException("Invalid tenantId");
        if (subjectId.isBlank() || subjectId.length() > 255 || subjectId.indexOf(0) >= 0)
            throw new IllegalArgumentException("Invalid subjectId");
    }
}
