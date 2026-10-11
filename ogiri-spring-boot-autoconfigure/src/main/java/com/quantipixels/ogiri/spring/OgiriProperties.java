// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.spring;

import com.quantipixels.ogiri.account.OgiriSettings;
import java.time.Duration;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

@ConfigurationProperties("ogiri")
public record OgiriProperties(
        @DefaultValue("true") boolean enabled,
        @DefaultValue("users") String realm,
        @DefaultValue("/auth") String basePath,
        @DefaultValue("false") boolean changeHeadersOnEachRequest,
        @DefaultValue("10") int maxNumberOfDevices,
        @DefaultValue("14d") Duration tokenLifespan,
        @DefaultValue("5s") Duration batchRequestBufferThrottle,
        @DefaultValue("false") boolean confirmable,
        @DefaultValue("true") boolean reconfirmable,
        @DefaultValue("false") boolean lockable,
        @DefaultValue("20") int maximumAttempts,
        @DefaultValue("both") String unlockStrategy,
        @DefaultValue("1h") Duration unlockIn,
        @DefaultValue("false") boolean paranoid,
        @DefaultValue List<String> redirectAllowlist,
        @DefaultValue("") String defaultConfirmSuccessUrl,
        @DefaultValue("") String defaultPasswordResetUrl,
        @DefaultValue("false") boolean removeTokensAfterPasswordReset,
        @DefaultValue("false") boolean requireClientPasswordResetToken,
        @DefaultValue("false") String checkCurrentPasswordBeforeUpdate,
        @DefaultValue("false") boolean cookieEnabled,
        @DefaultValue("6h") Duration resetPasswordWithin,
        @DefaultValue("auth_cookie") String cookieName,
        @DefaultValue("true") boolean cookieSecure,
        @DefaultValue("Lax") String cookieSameSite,
        @DefaultValue("/") String cookiePath,
        @DefaultValue({"name", "nickname", "image"}) List<String> permittedFields,
        @DefaultValue Account account,
        @DefaultValue Endpoints endpoints,
        @DefaultValue Cleanup cleanup) {
    public OgiriProperties {
        redirectAllowlist = redirectAllowlist == null ? List.of() : List.copyOf(redirectAllowlist);
        permittedFields =
                permittedFields == null
                        ? List.of("name", "nickname", "image")
                        : List.copyOf(permittedFields);
    }

    public record Account(@DefaultValue("users") String table, @DefaultValue List<String> columns) {
        public Account {
            columns = columns == null ? List.of() : List.copyOf(columns);
        }
    }

    public record Endpoints(@DefaultValue("true") boolean enabled) {}

    public record Cleanup(Duration interval, @DefaultValue("1000") int batchSize) {}

    public OgiriSettings settings() {
        return new OgiriSettings(
                realm,
                basePath,
                changeHeadersOnEachRequest,
                maxNumberOfDevices,
                tokenLifespan,
                batchRequestBufferThrottle,
                confirmable,
                reconfirmable,
                lockable,
                maximumAttempts,
                unlockStrategy,
                unlockIn,
                paranoid,
                redirectAllowlist,
                defaultConfirmSuccessUrl,
                defaultPasswordResetUrl,
                removeTokensAfterPasswordReset,
                requireClientPasswordResetToken,
                checkCurrentPasswordBeforeUpdate,
                cookieEnabled,
                resetPasswordWithin,
                cookieName,
                cookieSecure,
                cookieSameSite,
                cookiePath,
                permittedFields);
    }
}
