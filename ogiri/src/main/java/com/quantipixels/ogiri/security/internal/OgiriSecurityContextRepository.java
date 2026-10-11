// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.security.internal;

import com.quantipixels.ogiri.security.OgiriRealms;
import com.quantipixels.ogiri.security.OgiriRuntime;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.UUID;
import org.springframework.security.core.context.DeferredSecurityContext;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;

/** Request contexts are isolated by both the configured chain and the runtime instance. */
public final class OgiriSecurityContextRepository implements SecurityContextRepository {
    private final OgiriRealms realms;
    private final String chain = getClass().getName() + "." + UUID.randomUUID();

    public OgiriSecurityContextRepository(OgiriRealms realms) {
        this.realms = realms;
    }

    public RequestAttributeSecurityContextRepository forRuntime(OgiriRuntime runtime) {
        return new RequestAttributeSecurityContextRepository(
                chain + "." + runtime.responseCredentialsAttribute());
    }

    private RequestAttributeSecurityContextRepository delegate(HttpServletRequest request) {
        return forRuntime(realms.resolve(request));
    }

    @Override
    public SecurityContext loadContext(HttpRequestResponseHolder holder) {
        return delegate(holder.getRequest()).loadContext(holder);
    }

    @Override
    public DeferredSecurityContext loadDeferredContext(HttpServletRequest request) {
        return delegate(request).loadDeferredContext(request);
    }

    @Override
    public void saveContext(
            SecurityContext context, HttpServletRequest request, HttpServletResponse response) {
        delegate(request).saveContext(context, request, response);
    }

    @Override
    public boolean containsContext(HttpServletRequest request) {
        return delegate(request).containsContext(request);
    }
}
