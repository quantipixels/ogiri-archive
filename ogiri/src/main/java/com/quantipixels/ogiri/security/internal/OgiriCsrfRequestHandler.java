// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.security.internal;

import com.quantipixels.ogiri.security.OgiriRealms;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.function.Supplier;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.csrf.CsrfTokenRequestHandler;

public final class OgiriCsrfRequestHandler implements CsrfTokenRequestHandler {
    private final OgiriRealms realms;

    public OgiriCsrfRequestHandler(OgiriRealms realms) {
        this.realms = realms;
    }

    @Override
    public void handle(
            HttpServletRequest request, HttpServletResponse response, Supplier<CsrfToken> token) {
        var handler = new CsrfTokenRequestAttributeHandler();
        // setCsrfRequestAttributeName(null) issues XSRF-TOKEN on every cookie-mode response.
        if (realms.resolve(request).settings().cookieEnabled())
            handler.setCsrfRequestAttributeName(null);
        handler.handle(request, response, token);
    }

    @Override
    public String resolveCsrfTokenValue(HttpServletRequest request, CsrfToken token) {
        return request.getHeader(token.getHeaderName());
    }
}
