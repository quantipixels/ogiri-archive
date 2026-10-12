// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.security.internal;

import com.quantipixels.ogiri.security.DtaErrors;
import com.quantipixels.ogiri.security.OgiriRealms;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.GenericFilterBean;

/** Selects Ogiri's Spring CSRF filter without changing the host filter's configuration. */
public final class OgiriCsrfFilter extends GenericFilterBean {
    private final OgiriRealms realms;
    private final OgiriCsrfTokenRepository tokens;
    private final RequestMatcher requests;
    private final CsrfFilter csrf;

    public OgiriCsrfFilter(OgiriRealms realms, RequestMatcher requests, RequestMatcher required) {
        this.realms = realms;
        this.requests = requests;
        tokens = new OgiriCsrfTokenRepository(realms);
        csrf = new CsrfFilter(tokens);
        csrf.setBeanName("ogiriCsrf");
        csrf.setRequestHandler(new OgiriCsrfRequestHandler(realms));
        csrf.setRequireCsrfProtectionMatcher(required);
        csrf.setAccessDeniedHandler((request, response, failure) -> DtaErrors.csrf(response));
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        var http = (HttpServletRequest) request;
        if (!requests.matches(http)) {
            // K1 bootstraps the cookie on safe requests, without replacing host token attributes.
            if (realms.resolve(http).settings().cookieEnabled()
                    && !CsrfFilter.DEFAULT_CSRF_MATCHER.matches(http)) {
                tokens.loadDeferredToken(http, (HttpServletResponse) response).get();
            }
            chain.doFilter(request, response);
            return;
        }
        csrf.doFilter(
                request,
                response,
                (checked, result) -> {
                    // Only skip the host filter after Ogiri's own Spring filter accepted the
                    // request.
                    // Otherwise its repository/handler could issue a session or replace Ogiri's
                    // token.
                    CsrfFilter.skipRequest((HttpServletRequest) checked);
                    chain.doFilter(checked, result);
                });
    }
}
