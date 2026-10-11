// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.security;

import com.quantipixels.ogiri.Session;
import com.quantipixels.ogiri.account.OgiriAccount;
import org.springframework.security.authentication.AbstractAuthenticationToken;

/** Account principal with server-side session metadata; prior roles are never inherited. */
public final class OgiriAuthentication extends AbstractAuthenticationToken {
    private final OgiriAccount account;
    private final Session session;

    public OgiriAuthentication(OgiriAccount account, Session session) {
        super(account.getAuthorities());
        this.account = account;
        this.session = session;
        setAuthenticated(true);
    }

    @Override
    public OgiriAccount getPrincipal() {
        return account;
    }

    @Override
    public Object getCredentials() {
        return "";
    }

    public Session session() {
        return session;
    }
}
