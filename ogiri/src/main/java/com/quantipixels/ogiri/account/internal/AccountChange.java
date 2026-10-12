// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.account.internal;

import com.quantipixels.ogiri.account.OgiriAccount;

/** Account mutation and credential survival are decided in the same transaction. */
public record AccountChange(
        OgiriAccount account,
        boolean credentialRetained,
        com.quantipixels.ogiri.IssuedSession issued) {
    public AccountChange(OgiriAccount account, boolean credentialRetained) {
        this(account, credentialRetained, null);
    }

    @Override
    public String toString() {
        return "AccountChange[redacted]";
    }
}
