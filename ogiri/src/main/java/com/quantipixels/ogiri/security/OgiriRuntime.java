// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.security;

import com.quantipixels.ogiri.account.AccountStore;
import com.quantipixels.ogiri.account.OgiriSettings;
import com.quantipixels.ogiri.account.SignInService;
import com.quantipixels.ogiri.internal.AuthTransactions;
import com.quantipixels.ogiri.internal.SessionRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.authentication.ProviderManager;

/** One immutable auth instance, including its private request-state namespace. */
public final class OgiriRuntime {
    private final OgiriSettings settings;
    private final AuthTransactions transactions;
    private final SessionRepository sessions;
    private final AccountStore accounts;
    private final SignInService signIn;
    private final AuthenticationManagerResolver<HttpServletRequest> authenticationManagers;
    private final String responseCredentialsAttribute =
            ResponseCredentials.ATTRIBUTE + "." + java.util.UUID.randomUUID();

    public OgiriRuntime(
            OgiriSettings settings,
            AuthTransactions transactions,
            SessionRepository sessions,
            AccountStore accounts,
            SignInService signIn,
            AuthenticationManagerResolver<HttpServletRequest> authenticationManagers) {
        this.settings = settings;
        this.transactions = transactions;
        this.sessions = sessions;
        this.accounts = accounts;
        this.signIn = signIn;
        this.authenticationManagers = authenticationManagers;
    }

    public OgiriRuntime(
            OgiriSettings settings,
            AuthTransactions transactions,
            SessionRepository sessions,
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

    public OgiriSettings settings() {
        return settings;
    }

    public AuthTransactions transactions() {
        return transactions;
    }

    public SessionRepository sessions() {
        return sessions;
    }

    public AccountStore accounts() {
        return accounts;
    }

    public SignInService signIn() {
        return signIn;
    }

    public AuthenticationManagerResolver<HttpServletRequest> authenticationManagers() {
        return authenticationManagers;
    }

    public String responseCredentialsAttribute() {
        return responseCredentialsAttribute;
    }
}
