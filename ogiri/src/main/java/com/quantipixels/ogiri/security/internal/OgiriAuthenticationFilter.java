// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.security.internal;

import com.quantipixels.ogiri.SessionStoreException;
import com.quantipixels.ogiri.security.OgiriAuthentication;
import com.quantipixels.ogiri.security.OgiriConfigurer;
import com.quantipixels.ogiri.security.OgiriRealms;
import com.quantipixels.ogiri.security.OgiriRuntime;
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
    private final OgiriRealms realms;
    private final org.springframework.security.authentication.AuthenticationManagerResolver<
                    HttpServletRequest>
            managers;
    private final RequestAttributeSecurityContextRepository repository;
    private final String filterAttribute = getClass().getName() + "." + java.util.UUID.randomUUID();

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
        this.managers = managers;
        this.repository =
                new RequestAttributeSecurityContextRepository(filterAttribute + ".context");
        realms = new OgiriRealms(runtime, java.util.List.of());
    }

    public OgiriAuthenticationFilter(OgiriRealms realms) {
        this(
                realms,
                new RequestAttributeSecurityContextRepository(
                        java.util.UUID.randomUUID().toString()));
    }

    public OgiriAuthenticationFilter(
            OgiriRealms realms, RequestAttributeSecurityContextRepository repository) {
        this.repository = repository;
        this.realms = realms;
        this.managers =
                request -> realms.resolve(request).authenticationManagers().resolve(request);
    }

    @Override
    protected String getAlreadyFilteredAttributeName() {
        return filterAttribute;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        var runtime = realms.resolve(request);
        var converter = new DtaAuthenticationConverter(runtime.settings());
        var previous = SecurityContextHolder.getContext();
        try {
            var candidate =
                    realms.endpointsEnabled(request)
                                    && OgiriConfigurer.publicWorkflow(
                                            request, runtime.settings().basePath())
                            ? null
                            : converter.convert(request);
            clearForeignContext(request, previous, candidate);
            if (candidate != null) {
                var existing = previous.getAuthentication();
                if (existing != null
                        && existing.isAuthenticated()
                        && !(existing
                                instanceof
                                org.springframework.security.authentication
                                        .AnonymousAuthenticationToken)) {
                    DtaErrors.unauthorized(response);
                    return;
                }
                var context = SecurityContextHolder.createEmptyContext();
                SecurityContextHolder.setContext(context);
                if (!authenticate(request, response, candidate, context)) return;
                repository.saveContext(context, request, response);
            }
            chain.doFilter(request, response);
        } finally {
            SecurityContextHolder.setContext(previous);
        }
    }

    private void clearForeignContext(
            HttpServletRequest request,
            org.springframework.security.core.context.SecurityContext previous,
            org.springframework.security.core.Authentication candidate) {
        if (candidate == null
                && previous.getAuthentication() instanceof OgiriAuthentication
                && !repository.containsContext(request)) {
            SecurityContextHolder.setContext(SecurityContextHolder.createEmptyContext());
        }
    }

    private boolean authenticate(
            HttpServletRequest request,
            HttpServletResponse response,
            org.springframework.security.core.Authentication candidate,
            org.springframework.security.core.context.SecurityContext context)
            throws IOException {
        var runtime = realms.resolve(request);
        try {
            var authentication =
                    (OgiriAuthentication) managers.resolve(request).authenticate(candidate);
            context.setAuthentication(authentication);
            request.setAttribute(
                    runtime.responseCredentialsAttribute(),
                    authentication.responseCredentials() != null
                            ? authentication.responseCredentials()
                            : ResponseCredentials.of(
                                    authentication.session(),
                                    ((DtaAuthenticationToken) candidate).getCredentials().token(),
                                    authentication.getPrincipal().uid()));
            if (realms.resolve(request).settings().cookieEnabled()
                    && request.getAttribute(CsrfToken.class.getName()) instanceof CsrfToken csrf) {
                csrf.getToken();
            }
        } catch (BadCredentialsException invalid) {
            context.setAuthentication(null);
        } catch (SessionStoreException failure) {
            DtaErrors.unavailable(response);
            return false;
        }
        return true;
    }
}
