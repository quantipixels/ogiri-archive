// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Quanti Pixels
package com.quantipixels.ogiri;

import java.time.Instant;
import java.util.UUID;

/**
 * Public session metadata. The identifier is for management; it is not an authentication
 * credential.
 */
public record Session(UUID id, Subject subject, String client, Instant createdAt, Instant expiresAt)
        implements java.io.Serializable {}
