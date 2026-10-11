// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.security;

import com.quantipixels.ogiri.Session;
import com.quantipixels.ogiri.account.OgiriAccount;
import org.springframework.security.authentication.AbstractAuthenticationToken;

/** Account principal with server-side session metadata; prior roles are never inherited. */
public final class OgiriAuthentication extends AbstractAuthenticationToken {
    @java.io.Serial private static final long serialVersionUID = 1L;
    private final OgiriAccount account;
    private final Session session;
    private final transient ResponseCredentials responseCredentials;

    public OgiriAuthentication(OgiriAccount account, Session session) {
        this(account, session, null);
    }

    public OgiriAuthentication(
            OgiriAccount account, Session session, ResponseCredentials responseCredentials) {
        super(account.getAuthorities());
        this.account = account;
        this.session = session;
        this.responseCredentials = responseCredentials;
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

    public ResponseCredentials responseCredentials() {
        return responseCredentials;
    }

    public Session session() {
        return session;
    }
}
