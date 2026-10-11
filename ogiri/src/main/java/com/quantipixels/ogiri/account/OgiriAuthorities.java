// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.account;

import java.util.Collection;
import java.util.Map;
import org.springframework.security.core.GrantedAuthority;

/** Application-owned authority projection; no roles from earlier authentications are inherited. */
@FunctionalInterface
public interface OgiriAuthorities {
    Collection<? extends GrantedAuthority> map(Map<String, Object> attributes);
}
