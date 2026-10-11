// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.security;

import com.quantipixels.ogiri.SessionStoreException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.filter.OncePerRequestFilter;

public final class OgiriAuthenticationFilter extends OncePerRequestFilter {
    private final OgiriRuntime runtime;
    private final DtaAuthenticationConverter converter;
    private final org.springframework.security.authentication.AuthenticationManagerResolver<
                    HttpServletRequest>
            managers;
    private final RequestAttributeSecurityContextRepository repository =
            new RequestAttributeSecurityContextRepository();

    public OgiriAuthenticationFilter(OgiriRuntime runtime, AuthenticationManager manager) {
        this(
                runtime,
                (org.springframework.security.authentication.AuthenticationManagerResolver<
                                HttpServletRequest>)
                        request -> manager);
    }

    public OgiriAuthenticationFilter(
            OgiriRuntime runtime,
            org.springframework.security.authentication.AuthenticationManagerResolver<
                            HttpServletRequest>
                    managers) {
        this.runtime = runtime;
        this.managers = managers;
        converter = new DtaAuthenticationConverter(runtime.settings());
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        var previous = SecurityContextHolder.getContext();
        var context = SecurityContextHolder.createEmptyContext();
        SecurityContextHolder.setContext(context);
        try {
            if (!OgiriConfigurer.publicWorkflow(request, runtime.settings().basePath())) {
                var candidate = converter.convert(request);
                if (candidate != null) {
                    try {
                        var authentication =
                                (OgiriAuthentication)
                                        managers.resolve(request).authenticate(candidate);
                        context.setAuthentication(authentication);
                        ResponseCredentials credentials =
                                ResponseCredentials.of(
                                        authentication.session(),
                                        ((DtaAuthenticationToken) candidate)
                                                .getCredentials()
                                                .token(),
                                        authentication.getPrincipal().uid());
                        request.setAttribute(ResponseCredentials.ATTRIBUTE, credentials);
                        if (runtime.settings().cookieEnabled()
                                && request.getAttribute(CsrfToken.class.getName())
                                        instanceof CsrfToken csrf) {
                            csrf.getToken();
                        }
                    } catch (BadCredentialsException invalid) {
                        context.setAuthentication(null);
                    } catch (SessionStoreException failure) {
                        DtaErrors.unavailable(response);
                        return;
                    }
                }
            }
            repository.saveContext(context, request, response);
            chain.doFilter(request, response);
        } finally {
            SecurityContextHolder.setContext(previous);
        }
    }
}
