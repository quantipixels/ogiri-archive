// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.security;

import com.quantipixels.ogiri.Subject;
import com.quantipixels.ogiri.account.AccountStore;
import com.quantipixels.ogiri.account.OgiriSettings;
import com.quantipixels.ogiri.internal.AuthTransactions;
import com.quantipixels.ogiri.internal.SessionRepository;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;

public final class OgiriTokenAuthenticationProvider implements AuthenticationProvider {
    private final AccountStore accounts;
    private final AuthTransactions transactions;
    private final SessionRepository sessions;
    private final OgiriSettings settings;

    public OgiriTokenAuthenticationProvider(
            AccountStore accounts,
            AuthTransactions transactions,
            SessionRepository sessions,
            OgiriSettings settings) {
        this.accounts = accounts;
        this.transactions = transactions;
        this.sessions = sessions;
        this.settings = settings;
    }

    @Override
    public Authentication authenticate(Authentication authentication) {
        DtaCredential credentials = ((DtaAuthenticationToken) authentication).getCredentials();
        return transactions.read(
                () -> {
                    var account = accounts.findByUid(credentials.uid());
                    var subject =
                            new Subject(
                                    settings.realm(),
                                    "",
                                    account.map(a -> a.id()).orElse("__ogiri_missing__"));
                    String client =
                            credentials.client().length() > 64
                                    ? "__invalid_client__"
                                    : credentials.client();
                    var session = sessions.find(subject, client, credentials.token());
                    long now = transactions.now();
                    if (account.isEmpty()
                            || session.isEmpty()
                            || credentials.client().length() > 64
                            || !account.orElseThrow().active(settings, now)) {
                        throw new BadCredentialsException("Invalid DTA credentials");
                    }
                    return new OgiriAuthentication(account.orElseThrow(), session.orElseThrow());
                });
    }

    @Override
    public boolean supports(Class<?> type) {
        return DtaAuthenticationToken.class.isAssignableFrom(type);
    }
}
