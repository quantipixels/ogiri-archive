// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.account;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.quantipixels.ogiri.account.internal.OgiriSettings;
import java.time.Instant;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * Snapshot of the application's account. Wire projection is explicit and excludes Devise secrets.
 */
public final class OgiriAccount implements UserDetails {
    private static final Set<String> RESOURCE =
            Set.of(
                    "id",
                    "provider",
                    "uid",
                    "email",
                    "name",
                    "nickname",
                    "image",
                    "allow_password_change",
                    "created_at",
                    "updated_at");
    private final Set<String> visible;
    private final Map<String, Object> columns;
    private final List<GrantedAuthority> authorities;

    public OgiriAccount(
            Map<String, Object> columns, Collection<? extends GrantedAuthority> authorities) {
        this(columns, authorities, List.of());
    }

    public OgiriAccount(
            Map<String, Object> columns,
            Collection<? extends GrantedAuthority> authorities,
            Collection<String> additionalColumns) {
        var allowed = new java.util.HashSet<>(RESOURCE);
        if (additionalColumns.stream()
                .anyMatch(
                        field ->
                                Set.of(
                                                "encrypted_password",
                                                "reset_password_token",
                                                "confirmation_token",
                                                "unlock_token",
                                                "tokens")
                                        .contains(field))) {
            throw new IllegalArgumentException("Secret account columns cannot be view fields");
        }
        allowed.addAll(additionalColumns);
        this.visible = Set.copyOf(allowed);
        this.columns = Collections.unmodifiableMap(new LinkedHashMap<>(columns));
        this.authorities = List.copyOf(authorities);
    }

    public String id() {
        return text("id");
    }

    /**
     * Stable for this account incarnation; custom stores must supply a fresh value on replacement.
     */
    @JsonIgnore
    public String generation() {
        String value = text("ogiri_generation");
        if (value.isBlank() || value.length() > 36)
            throw new IllegalStateException(
                    "AccountStore must supply an immutable ogiri_generation (1-36 characters)");
        return value;
    }

    public String uid() {
        return text("uid");
    }

    public String email() {
        return text("email");
    }

    public String text(String key) {
        Object value = columns.get(key);
        return value == null ? "" : value.toString();
    }

    @JsonIgnore
    public Object column(String key) {
        return columns.get(key);
    }

    public boolean flag(String key) {
        Object value = columns.get(key);
        return Boolean.TRUE.equals(value) || "1".equals(String.valueOf(value));
    }

    public Instant time(String key) {
        return (Instant) columns.get(key);
    }

    public Map<String, Object> view(boolean tokenView) {
        var result = new LinkedHashMap<>(columns);
        result.keySet().retainAll(visible);
        if (tokenView) {
            result.remove("created_at");
            result.remove("updated_at");
        }
        return Collections.unmodifiableMap(result);
    }

    public boolean active(OgiriSettings settings, long now) {
        return (!settings.confirmable() || column("confirmed_at") != null)
                && !locked(settings, now);
    }

    public boolean locked(OgiriSettings settings, long now) {
        Instant locked = time("locked_at");
        return settings.lockable()
                && locked != null
                && (settings.unlockStrategy().equals("email")
                        || now < locked.toEpochMilli() + settings.unlockIn().toMillis());
    }

    @Override
    public String getUsername() {
        return uid();
    }

    @Override
    @JsonIgnore
    public String getPassword() {
        return text("encrypted_password");
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String toString() {
        return "OgiriAccount[id=" + id() + "]";
    }
}
