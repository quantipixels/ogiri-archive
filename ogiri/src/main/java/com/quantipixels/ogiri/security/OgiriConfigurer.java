// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.security;

import jakarta.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.web.cors.CorsConfiguration;

public final class OgiriConfigurer extends AbstractHttpConfigurer<OgiriConfigurer, HttpSecurity> {
    public static final List<String> AUTH_HEADERS =
            List.of("access-token", "client", "uid", "expiry", "token-type", "Authorization");
    private final OgiriRuntime runtime;

    private OgiriConfigurer(OgiriRuntime runtime) {
        this.runtime = runtime;
    }

    public static OgiriConfigurer ogiri(OgiriRuntime runtime) {
        return new OgiriConfigurer(runtime);
    }

    public static void exposeHeaders(CorsConfiguration cors) {
        var exposed =
                new ArrayList<String>(
                        cors.getExposedHeaders() == null ? List.of() : cors.getExposedHeaders());
        exposed.addAll(AUTH_HEADERS);
        cors.setExposedHeaders(exposed);
    }

    @Override
    public void init(HttpSecurity http) {
        var context = http.getSharedObject(org.springframework.context.ApplicationContext.class);
        if (context != null
                && context.getBeanNamesForType(
                                        org.springframework.web.cors.CorsConfigurationSource.class)
                                .length
                        > 0) {
            http.cors(org.springframework.security.config.Customizer.withDefaults());
        }
        http.sessionManagement(
                        config -> config.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .requestCache(AbstractHttpConfigurer::disable)
                .securityContext(
                        config ->
                                config.securityContextRepository(
                                        new RequestAttributeSecurityContextRepository()))
                .csrf(
                        csrf ->
                                csrf.csrfTokenRepository(
                                                CookieCsrfTokenRepository.withHttpOnlyFalse())
                                        .csrfTokenRequestHandler(
                                                new CsrfTokenRequestAttributeHandler())
                                        .requireCsrfProtectionMatcher(this::cookieCsrfRequired))
                .exceptionHandling(
                        config ->
                                config.authenticationEntryPoint(
                                                (request, response, failure) ->
                                                        DtaErrors.unauthorized(
                                                                request,
                                                                response,
                                                                runtime.settings().basePath()))
                                        .accessDeniedHandler(
                                                (request, response, failure) ->
                                                        DtaErrors.forbidden(response)))
                .headers(config -> config.addHeaderWriter(new DtaHeaderWriter(runtime.settings())));
    }

    private boolean cookieCsrfRequired(HttpServletRequest request) {
        if (!runtime.settings().cookieEnabled()
                || DtaAuthenticationConverter.hasHeaders(request)
                || publicWorkflow(request, runtime.settings().basePath())
                || List.of("GET", "HEAD", "OPTIONS", "TRACE").contains(request.getMethod())) {
            return false;
        }
        var cookies = request.getCookies();
        if (cookies == null) {
            return false;
        }
        for (var cookie : cookies) {
            if (runtime.settings().cookieName().equals(cookie.getName())) {
                return true;
            }
        }
        return false;
    }

    @Override
    public void configure(HttpSecurity http) {
        http.addFilterBefore(
                new OgiriAuthenticationFilter(runtime, runtime.authenticationManagers()),
                AnonymousAuthenticationFilter.class);
    }

    public static String path(HttpServletRequest request) {
        String info = request.getPathInfo();
        return request.getServletPath() + (info == null ? "" : info);
    }

    public static String mount(HttpServletRequest request, String base) {
        return (request.getPathInfo() == null ? "" : request.getServletPath()) + base;
    }

    public static boolean publicWorkflow(HttpServletRequest request, String base) {
        base = mount(request, base);
        String path = path(request);
        String method = request.getMethod();
        return path.equals(base + "/sign_in")
                || path.equals(base + "/confirmation")
                || path.equals(base + "/unlock")
                || path.equals(base + "/password/edit")
                || (path.equals(base + "/password") && method.equals("POST"))
                || ((path.equals(base) || path.equals(base + "/")) && method.equals("POST"));
    }

    public static boolean endpoint(HttpServletRequest request, String base) {
        String mounted = mount(request, base);
        String path = path(request);
        return path.equals(mounted)
                || path.equals(mounted + "/")
                || List.of(
                                "sign_in",
                                "sign_out",
                                "validate_token",
                                "password",
                                "password/edit",
                                "confirmation",
                                "unlock",
                                "sessions")
                        .stream()
                        .anyMatch(part -> path.equals(mounted + "/" + part))
                || path.startsWith(mounted + "/sessions/");
    }
}
