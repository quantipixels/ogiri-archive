// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.security;

import com.quantipixels.ogiri.security.internal.DtaAuthenticationConverter;
import com.quantipixels.ogiri.security.internal.OgiriCsrfTokenRepository;
import com.quantipixels.ogiri.security.internal.OgiriRealmAuthenticationFilter;
import com.quantipixels.ogiri.security.internal.OgiriSecurityContextRepository;
import jakarta.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.web.cors.CorsConfiguration;

public final class OgiriConfigurer extends AbstractHttpConfigurer<OgiriConfigurer, HttpSecurity> {
    public static final List<String> AUTH_HEADERS =
            List.of("access-token", "client", "uid", "expiry", "token-type", "Authorization");
    private final OgiriRealms realms;
    private final OgiriSecurityContextRepository repository;

    private final boolean singleRuntime;

    private OgiriConfigurer(OgiriRealms realms, boolean singleRuntime) {
        this.realms = realms;
        this.singleRuntime = singleRuntime;
        repository = new OgiriSecurityContextRepository(realms);
    }

    public static OgiriConfigurer ogiri(OgiriRuntime runtime) {
        return new OgiriConfigurer(new OgiriRealms(runtime, List.of()), true);
    }

    public static OgiriConfigurer ogiri(OgiriRealms realms) {
        return new OgiriConfigurer(realms, false);
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
        if (singleRuntime
                && context != null
                && context.getBeanProvider(OgiriRealms.class).stream()
                        .anyMatch(mounted -> !mounted.additional().isEmpty())) {
            throw new IllegalStateException(
                    "OgiriConfigurer.ogiri(runtime) cannot be used with additional realms; use OgiriConfigurer.ogiri(realms)");
        }
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
                .securityContext(config -> config.securityContextRepository(repository))
                .csrf(
                        csrf ->
                                csrf.csrfTokenRepository(new OgiriCsrfTokenRepository(realms))
                                        .csrfTokenRequestHandler(
                                                (request, response, token) -> {
                                                    var handler =
                                                            new CsrfTokenRequestAttributeHandler();
                                                    if (realms.resolve(request)
                                                            .settings()
                                                            .cookieEnabled())
                                                        handler.setCsrfRequestAttributeName(null);
                                                    handler.handle(request, response, token);
                                                })
                                        .requireCsrfProtectionMatcher(this::cookieCsrfRequired))
                .exceptionHandling(
                        config ->
                                config.authenticationEntryPoint(
                                                (request, response, failure) ->
                                                        DtaErrors.unauthorized(
                                                                request,
                                                                response,
                                                                realms.resolve(request)
                                                                        .settings()
                                                                        .basePath()))
                                        .accessDeniedHandler(
                                                (request, response, failure) -> {
                                                    if (failure
                                                            instanceof
                                                            org.springframework.security.web.csrf
                                                                    .CsrfException) {
                                                        DtaErrors.write(
                                                                response,
                                                                403,
                                                                java.util.Map.of(
                                                                        "success",
                                                                        false,
                                                                        "errors",
                                                                        List.of(
                                                                                "Invalid CSRF token")));
                                                    } else {
                                                        DtaErrors.forbidden(response);
                                                    }
                                                }))
                .headers(config -> config.addHeaderWriter(new DtaHeaderWriter(realms)));
    }

    private boolean cookieCsrfRequired(HttpServletRequest request) {
        var runtime = realms.resolve(request);
        if (!runtime.settings().cookieEnabled()
                || List.of("GET", "HEAD", "OPTIONS", "TRACE").contains(request.getMethod())) {
            return false;
        }
        // Sign-in creates ambient credentials even when the request has no auth cookie yet.
        if (realms.endpointsEnabled(request)
                && path(request)
                        .equals(mount(request, runtime.settings().basePath()) + "/sign_in")) {
            return true;
        }
        if (realms.endpointsEnabled(request)
                && publicWorkflow(request, runtime.settings().basePath())) {
            return false;
        }
        var candidate = new DtaAuthenticationConverter(runtime.settings()).convert(request);
        return candidate instanceof DtaAuthenticationToken token && token.getCredentials().cookie();
    }

    @Override
    public void configure(HttpSecurity http) {
        http.addFilterBefore(
                new OgiriRealmAuthenticationFilter(realms, repository),
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

    public static boolean tokenResetWorkflow(
            HttpServletRequest request, com.quantipixels.ogiri.account.OgiriSettings settings) {
        return settings.requireClientPasswordResetToken()
                && path(request).equals(mount(request, settings.basePath()) + "/password")
                && List.of("PUT", "PATCH").contains(request.getMethod());
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
