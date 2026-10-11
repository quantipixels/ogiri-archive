// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.security;

import com.quantipixels.ogiri.AuthTransactions;
import com.quantipixels.ogiri.JdbcSessions;
import com.quantipixels.ogiri.account.AccountStore;
import com.quantipixels.ogiri.account.OgiriSettings;
import com.quantipixels.ogiri.account.SignInService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.authentication.ProviderManager;

public record OgiriRuntime(
        OgiriSettings settings,
        AuthTransactions transactions,
        JdbcSessions sessions,
        AccountStore accounts,
        SignInService signIn,
        AuthenticationManagerResolver<HttpServletRequest> authenticationManagers) {
    public OgiriRuntime(
            OgiriSettings settings,
            AuthTransactions transactions,
            JdbcSessions sessions,
            AccountStore accounts,
            SignInService signIn) {
        this(
                settings,
                transactions,
                sessions,
                accounts,
                signIn,
                request ->
                        new ProviderManager(
                                new OgiriTokenAuthenticationProvider(
                                        accounts, transactions, sessions, settings)));
    }
}
