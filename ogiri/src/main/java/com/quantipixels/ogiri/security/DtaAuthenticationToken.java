// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.security;

import java.util.List;
import org.springframework.security.authentication.AbstractAuthenticationToken;

public final class DtaAuthenticationToken extends AbstractAuthenticationToken {
    private final DtaCredential credential;

    public DtaAuthenticationToken(DtaCredential credential) {
        super(List.of());
        this.credential = credential;
    }

    @Override
    public Object getPrincipal() {
        return credential.uid();
    }

    @Override
    public DtaCredential getCredentials() {
        return credential;
    }
}
