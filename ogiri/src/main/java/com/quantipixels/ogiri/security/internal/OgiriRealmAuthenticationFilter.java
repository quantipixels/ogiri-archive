// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.security.internal;

import com.quantipixels.ogiri.security.OgiriAuthenticationFilter;
import com.quantipixels.ogiri.security.OgiriRealms;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.springframework.web.filter.GenericFilterBean;

/** Each runtime has its own OncePerRequestFilter marker, including on nested dispatches. */
public final class OgiriRealmAuthenticationFilter extends GenericFilterBean {
    private final OgiriRealms realms;
    private final Map<String, OgiriAuthenticationFilter> filters;

    public OgiriRealmAuthenticationFilter(
            OgiriRealms realms, OgiriSecurityContextRepository repository) {
        this.realms = realms;
        var configured = new HashMap<String, OgiriAuthenticationFilter>();
        var runtimes = new java.util.ArrayList<>(realms.additional());
        runtimes.add(realms.defaultRealm());
        for (var runtime : runtimes) {
            var local = new OgiriRealms(runtime, List.of(), realms.disabledEndpoints());
            configured.put(
                    runtime.responseCredentialsAttribute(),
                    new OgiriAuthenticationFilter(local, repository.forRuntime(runtime)));
        }
        filters = Map.copyOf(configured);
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        var runtime = realms.resolve((HttpServletRequest) request);
        filters.get(runtime.responseCredentialsAttribute()).doFilter(request, response, chain);
    }
}
