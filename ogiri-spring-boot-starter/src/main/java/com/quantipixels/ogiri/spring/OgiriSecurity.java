// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Quanti Pixels
package com.quantipixels.ogiri.spring;


import jakarta.servlet.DispatcherType;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.UUID;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.resource.BearerTokenErrors;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.springframework.security.web.util.matcher.RequestMatcher;

/** Reusable native resource-server configuration; safe to use with multiple application-owned chains. */
public final class OgiriSecurity {
    private final OgiriOpaqueTokenIntrospector introspector;
    private final OgiriProperties properties;
    private final String servletPath;

    public OgiriSecurity(OgiriOpaqueTokenIntrospector introspector, OgiriProperties properties) {
        this(introspector, properties, "");
    }

    public OgiriSecurity(OgiriOpaqueTokenIntrospector introspector, OgiriProperties properties, String servletPath) {
        this.introspector = introspector; this.properties = properties;
        this.servletPath = servletPath == null || servletPath.equals("/") ? "" : servletPath.replaceFirst("/+$", "");
    }

    /** Add bearer authentication only. Authorization, other mechanisms and login CSRF policy remain yours. */
    public HttpSecurity configure(HttpSecurity http) throws Exception {
        var nativeResolver = new DefaultBearerTokenResolver();
        return http.oauth2ResourceServer(resource -> resource
                .bearerTokenResolver(request -> {
                    var values = request.getHeaders(HttpHeaders.AUTHORIZATION);
                    if (values.hasMoreElements()) {
                        values.nextElement();
                        if (values.hasMoreElements()) throw new OAuth2AuthenticationException(
                                BearerTokenErrors.invalidRequest("Multiple Authorization headers"));
                    }
                    return nativeResolver.resolve(request);
                })
                .opaqueToken(opaque -> opaque.introspector(introspector)));
    }

    /** Only non-simple JSON sign-in; use for explicit CSRF exemptions in an application-owned chain. */
    public RequestMatcher signInRequest() {
        String endpoint = properties.basePath() + "/sign-in";
        return request -> properties.endpointsEnabled()
                && request.getMethod().equals("POST")
                && (servletPath.isEmpty()
                    ? request.getServletPath().equals(endpoint) && request.getPathInfo() == null
                    : request.getServletPath().equals(servletPath) && endpoint.equals(request.getPathInfo()))
                && "Ogiri".equals(request.getHeader("X-Requested-With"))
                && request.getContentType() != null
                && request.getContentType().split(";", 2)[0].trim().equalsIgnoreCase(MediaType.APPLICATION_JSON_VALUE);
    }

    SecurityFilterChain defaults(HttpSecurity http) throws Exception {
        configure(http);
        return http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .requestCache(cache -> cache.disable())
                .authorizeHttpRequests(routes -> {
                    routes.dispatcherTypeMatchers(DispatcherType.ERROR).permitAll();
                    if (properties.endpointsEnabled()) routes.requestMatchers(signInRequest()).permitAll();
                    routes.anyRequest().authenticated();
                })
                .csrf(csrf -> csrf.csrfTokenRepository(new CsrfTokenRepository() {
                    // The stateless chain must reject unsafe requests without persisting a CSRF token.
                    @Override public CsrfToken generateToken(HttpServletRequest request) {
                        return new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", UUID.randomUUID().toString());
                    }
                    @Override public void saveToken(CsrfToken token, HttpServletRequest request, HttpServletResponse response) {}
                    @Override public CsrfToken loadToken(HttpServletRequest request) { return null; }
                }).ignoringRequestMatchers(signInRequest()))
                .build();
    }
}
