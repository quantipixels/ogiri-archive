// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.security.internal;

import com.quantipixels.ogiri.security.OgiriRealms;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;

/** Selects Spring's standard double-submit repository using the auth cookie's realm scope. */
public final class OgiriCsrfTokenRepository implements CsrfTokenRepository {
    private final OgiriRealms realms;
    private final Map<String, CookieCsrfTokenRepository> repositories;

    public OgiriCsrfTokenRepository(OgiriRealms realms) {
        this.realms = realms;
        var configured = new HashMap<String, CookieCsrfTokenRepository>();
        var runtimes = new java.util.ArrayList<>(realms.additional());
        runtimes.add(realms.defaultRealm());
        for (var runtime : runtimes) {
            var settings = runtime.settings();
            var repository = CookieCsrfTokenRepository.withHttpOnlyFalse();
            repository.setCookiePath(settings.cookiePath());
            repository.setCookieCustomizer(
                    cookie ->
                            cookie.secure(settings.cookieSecure())
                                    .sameSite(settings.cookieSameSite()));
            configured.put(runtime.responseCredentialsAttribute(), repository);
        }
        repositories = Map.copyOf(configured);
    }

    private CookieCsrfTokenRepository repository(HttpServletRequest request) {
        return repositories.get(realms.resolve(request).responseCredentialsAttribute());
    }

    @Override
    public CsrfToken generateToken(HttpServletRequest request) {
        return repository(request).generateToken(request);
    }

    @Override
    public void saveToken(
            CsrfToken token, HttpServletRequest request, HttpServletResponse response) {
        repository(request).saveToken(token, request, response);
    }

    @Override
    public CsrfToken loadToken(HttpServletRequest request) {
        return repository(request).loadToken(request);
    }
}
