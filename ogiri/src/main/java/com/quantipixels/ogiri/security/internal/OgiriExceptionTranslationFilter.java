// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.security.internal;

import com.quantipixels.ogiri.security.OgiriRealms;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.savedrequest.NullRequestCache;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.GenericFilterBean;

/** Ogiri failures use DTA responses and never save a request into an HTTP session. */
public final class OgiriExceptionTranslationFilter extends GenericFilterBean {
    private final RequestMatcher requests;
    private final ExceptionTranslationFilter exceptions;

    public OgiriExceptionTranslationFilter(OgiriRealms realms, RequestMatcher requests) {
        this.requests = requests;
        exceptions =
                new ExceptionTranslationFilter(
                        (request, response, failure) ->
                                DtaErrors.unauthorized(
                                        request,
                                        response,
                                        realms.resolve(request).settings().basePath()),
                        new NullRequestCache());
        exceptions.setAccessDeniedHandler(
                (request, response, failure) -> DtaErrors.forbidden(response));
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if (requests.matches((HttpServletRequest) request)) {
            exceptions.doFilter(request, response, chain);
        } else {
            chain.doFilter(request, response);
        }
    }
}
