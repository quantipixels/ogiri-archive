// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.spring;

import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

/** Keeps DTA tokens and account columns out of application event payloads. */
final class RedactedAuthenticationEvents implements AuthenticationEventPublisher {
    private final AuthenticationEventPublisher delegate;

    RedactedAuthenticationEvents(AuthenticationEventPublisher delegate) {
        this.delegate = delegate;
    }

    @Override
    public void publishAuthenticationSuccess(Authentication authentication) {
        delegate.publishAuthenticationSuccess(
                UsernamePasswordAuthenticationToken.authenticated(
                        "ogiri", null, java.util.List.of()));
    }

    @Override
    public void publishAuthenticationFailure(
            AuthenticationException exception, Authentication authentication) {
        delegate.publishAuthenticationFailure(
                exception, UsernamePasswordAuthenticationToken.unauthenticated("ogiri", null));
    }
}
