// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.spring.internal;

import com.quantipixels.ogiri.account.OgiriAccount;
import com.quantipixels.ogiri.account.internal.JdbcDeviseAccountStore;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

/** Keeps DTA tokens and account columns out of application event payloads. */
public final class RedactedAuthenticationEvents implements AuthenticationEventPublisher {
    private final AuthenticationEventPublisher delegate;
    private final String realm;

    public RedactedAuthenticationEvents(AuthenticationEventPublisher delegate, String realm) {
        this.realm = realm;
        this.delegate = delegate;
    }

    private String identity(Authentication authentication) {
        String uid =
                authentication.getPrincipal() instanceof OgiriAccount account
                        ? account.uid()
                        : authentication.getName();
        return realm + ":" + uid;
    }

    @Override
    public void publishAuthenticationSuccess(Authentication authentication) {
        delegate.publishAuthenticationSuccess(
                UsernamePasswordAuthenticationToken.authenticated(
                        identity(authentication), null, java.util.List.of()));
    }

    @Override
    public void publishAuthenticationFailure(
            AuthenticationException exception, Authentication authentication) {
        delegate.publishAuthenticationFailure(
                exception,
                UsernamePasswordAuthenticationToken.unauthenticated(
                        realm + ":" + JdbcDeviseAccountStore.normalize(authentication.getName()),
                        null));
    }
}
