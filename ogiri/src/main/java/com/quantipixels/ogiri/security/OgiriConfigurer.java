// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.security;

import com.quantipixels.ogiri.security.internal.DtaAuthenticationConverter;
import com.quantipixels.ogiri.security.internal.OgiriCsrfFilter;
import com.quantipixels.ogiri.security.internal.OgiriExceptionTranslationFilter;
import com.quantipixels.ogiri.security.internal.OgiriRealmAuthenticationFilter;
import com.quantipixels.ogiri.security.internal.OgiriSecurityContextRepository;
import jakarta.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.csrf.CsrfFilter;
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
        http.headers(config -> config.addHeaderWriter(new DtaHeaderWriter(realms)));
    }

    private boolean ogiriRequest(HttpServletRequest request) {
        var runtime = realms.resolve(request);
        return (realms.endpointsEnabled(request)
                        && endpoint(request, runtime.settings().basePath()))
                || new DtaAuthenticationConverter(runtime.settings()).convert(request) != null;
    }

    private boolean cookieCsrfRequired(HttpServletRequest request) {
        var runtime = realms.resolve(request);
        if (!runtime.settings().cookieEnabled()
                || List.of("GET", "HEAD", "OPTIONS", "TRACE").contains(request.getMethod())) {
            return false;
        }
        // Session issuance creates ambient credentials even without an incoming auth cookie.
        if (realms.endpointsEnabled(request) && canIssueAuthCookie(request, runtime)) {
            return true;
        }
        if (realms.endpointsEnabled(request)
                && publicWorkflow(request, runtime.settings().basePath())) {
            return false;
        }
        var candidate = new DtaAuthenticationConverter(runtime.settings()).convert(request);
        return candidate instanceof DtaAuthenticationToken token && token.getCredentials().cookie();
    }

    private static boolean canIssueAuthCookie(HttpServletRequest request, OgiriRuntime runtime) {
        if (!request.getMethod().equals("POST")) return false;
        String base = mount(request, runtime.settings().basePath());
        String path = path(request);
        return path.equals(base + "/sign_in")
                || (!runtime.settings().confirmable()
                        && (path.equals(base) || path.equals(base + "/")));
    }

    @Override
    public void configure(HttpSecurity http) {
        http.addFilterBefore(
                new OgiriCsrfFilter(realms, this::ogiriRequest, this::cookieCsrfRequired),
                CsrfFilter.class);
        http.addFilterAfter(
                new OgiriExceptionTranslationFilter(realms, this::ogiriRequest),
                ExceptionTranslationFilter.class);
        // Run after host session-management strategies: Ogiri must not trigger a session login.
        http.addFilterBefore(
                new OgiriRealmAuthenticationFilter(realms, repository),
                ExceptionTranslationFilter.class);
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
