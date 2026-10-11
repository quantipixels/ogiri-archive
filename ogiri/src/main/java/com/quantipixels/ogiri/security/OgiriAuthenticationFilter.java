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
        try {
            var candidate =
                    OgiriConfigurer.publicWorkflow(request, runtime.settings().basePath())
                            ? null
                            : converter.convert(request);
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

    private boolean authenticate(
            HttpServletRequest request,
            HttpServletResponse response,
            org.springframework.security.core.Authentication candidate,
            org.springframework.security.core.context.SecurityContext context)
            throws IOException {
        try {
            var authentication =
                    (OgiriAuthentication) managers.resolve(request).authenticate(candidate);
            context.setAuthentication(authentication);
            request.setAttribute(
                    ResponseCredentials.ATTRIBUTE,
                    ResponseCredentials.of(
                            authentication.session(),
                            ((DtaAuthenticationToken) candidate).getCredentials().token(),
                            authentication.getPrincipal().uid()));
            if (runtime.settings().cookieEnabled()
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
