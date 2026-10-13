// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.security.internal;

public record DtaCredential(String uid, String client, String token, boolean cookie)
        implements java.io.Serializable {
    @Override
    public String toString() {
        return "DtaCredential[redacted]";
    }
}
