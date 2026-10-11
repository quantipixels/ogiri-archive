// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Quanti Pixels
package com.quantipixels.ogiri;

/**
 * Storage is unavailable or rejected an operation. Never translate this into a successful
 * authentication.
 */
public final class SessionStoreException extends RuntimeException {
    SessionStoreException(Throwable cause) {
        super("Session storage operation failed", cause);
    }
}
