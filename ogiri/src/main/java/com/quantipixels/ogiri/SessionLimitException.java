// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Quanti Pixels
package com.quantipixels.ogiri;

/**
 * Issuance was refused without evicting an existing session. Let the account owner revoke a device.
 */
public final class SessionLimitException extends RuntimeException {
    public SessionLimitException() {
        super("Active session limit reached");
    }
}
