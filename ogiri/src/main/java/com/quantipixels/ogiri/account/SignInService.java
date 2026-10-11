// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.account;

import com.quantipixels.ogiri.DtaFailure;
import com.quantipixels.ogiri.IssuedSession;
import com.quantipixels.ogiri.Subject;
import com.quantipixels.ogiri.internal.AuthTransactions;
import com.quantipixels.ogiri.internal.SessionRepository;
import com.quantipixels.ogiri.internal.Tokens;
import java.util.Optional;

/** Verifies outside locks, then fences the verified hash under subject/account locks. */
public final class SignInService {
    public static final String INVALID = "Invalid login credentials. Please try again.";
    private final AccountStore accounts;
    private final AuthTransactions transactions;
    private final SessionRepository sessions;
    private final OgiriSettings settings;
    private final DevisePasswordEncoder passwords;
    private final String dummy;

    public SignInService(
            AccountStore accounts,
            AuthTransactions transactions,
            SessionRepository sessions,
            OgiriSettings settings,
            DevisePasswordEncoder passwords) {
        this.accounts = accounts;
        this.transactions = transactions;
        this.sessions = sessions;
        this.settings = settings;
        this.passwords = passwords;
        this.dummy = passwords.encode(Tokens.generate());
    }

    public record Result(OgiriAccount account, IssuedSession issued) {
        @Override
        public String toString() {
            return "SignInResult[redacted]";
        }
    }

    public Result signIn(String email, String password) {
        Optional<OgiriAccount> found =
                transactions.read(() -> accounts.findByEmail(email == null ? "" : email));
        String verified = found.map(OgiriAccount::getPassword).orElse(dummy);
        boolean matches = passwords.matches(password == null ? "" : password, verified);
        if (found.isEmpty()) {
            transactions.write(
                    () -> {
                        transactions.lock(new Subject(settings.realm(), "", "__ogiri_missing__"));
                        accounts.lock("-1");
                        return null;
                    });
            throw new DtaFailure(401, INVALID);
        }
        OgiriAccount candidate = found.orElseThrow();
        return transactions.write(
                () -> {
                    transactions.lock(subject(candidate));
                    OgiriAccount current =
                            accounts.lock(candidate.id())
                                    .orElseThrow(() -> new DtaFailure(401, INVALID));
                    long now = transactions.now();
                    checkActive(current, now);
                    if (!matches || !verified.equals(current.getPassword())) {
                        throw new DtaFailure(401, INVALID);
                    }
                    return new Result(
                            current, sessions.issueLocked(subject(current), Tokens.client()));
                });
    }

    public Subject subject(OgiriAccount account) {
        return new Subject(settings.realm(), "", account.id());
    }

    public void checkActive(OgiriAccount account, long now) {
        if (account.locked(settings, now)) {
            throw new DtaFailure(
                    401,
                    settings.paranoid()
                            ? INVALID
                            : "Your account has been locked due to an excessive number of unsuccessful sign in attempts.");
        }
        if (settings.confirmable() && account.column("confirmed_at") == null) {
            throw new DtaFailure(
                    401,
                    settings.paranoid()
                            ? INVALID
                            : "A confirmation email was sent to your account at '"
                                    + account.email()
                                    + "'. You must follow the instructions in the email before your account can be activated");
        }
    }
}
