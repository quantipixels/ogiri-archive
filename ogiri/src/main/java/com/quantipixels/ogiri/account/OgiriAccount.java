// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.account;

import com.fasterxml.jackson.annotation.JsonIgnore;
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
    private static final Set<String> SECRET =
            Set.of(
                    "encrypted_password",
                    "reset_password_token",
                    "reset_password_sent_at",
                    "remember_created_at",
                    "sign_in_count",
                    "current_sign_in_at",
                    "last_sign_in_at",
                    "current_sign_in_ip",
                    "last_sign_in_ip",
                    "password_salt",
                    "confirmation_token",
                    "confirmed_at",
                    "confirmation_sent_at",
                    "remember_token",
                    "unconfirmed_email",
                    "failed_attempts",
                    "unlock_token",
                    "locked_at",
                    "tokens");
    private final Map<String, Object> columns;
    private final List<GrantedAuthority> authorities;

    public OgiriAccount(
            Map<String, Object> columns, Collection<? extends GrantedAuthority> authorities) {
        this.columns = Collections.unmodifiableMap(new LinkedHashMap<>(columns));
        this.authorities = List.copyOf(authorities);
    }

    public String id() {
        return text("id");
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
        SECRET.forEach(result::remove);
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
