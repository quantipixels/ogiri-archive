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
    private final ActivationService activation;

    public SignInService(
            AccountStore accounts,
            AuthTransactions transactions,
            SessionRepository sessions,
            OgiriSettings settings,
            DevisePasswordEncoder passwords,
            ActivationService activation) {
        this.accounts = accounts;
        this.transactions = transactions;
        this.sessions = sessions;
        this.settings = settings;
        this.passwords = passwords;
        this.dummy = passwords.encode(Tokens.generate());
        this.activation = activation;
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
                        return null;
                    });
            throw new DtaFailure(401, INVALID);
        }
        OgiriAccount candidate = found.orElseThrow();
        var attempt = transactions.write(() -> attempt(candidate, verified, matches));
        if (attempt.delivery() != null) attempt.delivery().verify(settings.paranoid());
        if (attempt.failure() != null) throw attempt.failure();
        return attempt.result();
    }

    private record Attempt(
            Result result, DtaFailure failure, ActivationService.Delivery delivery) {}

    private Attempt attempt(OgiriAccount candidate, String verified, boolean matches) {
        transactions.lock(subject(candidate));
        var locked = accounts.lock(candidate.id());
        if (locked.isEmpty()) return new Attempt(null, new DtaFailure(401, INVALID), null);
        var current = locked.orElseThrow();
        long now = transactions.now();
        current = clearExpiredLock(current, now);
        try {
            checkActive(current, now);
        } catch (DtaFailure inactive) {
            return new Attempt(null, inactive, null);
        }
        if (!matches
                || !verified.equals(current.getPassword())
                || !candidate.generation().equals(current.generation())) {
            var delivery = settings.lockable() ? activation.failedLocked(current) : null;
            return new Attempt(null, new DtaFailure(401, INVALID), delivery);
        }
        if (settings.lockable() && !current.text("failed_attempts").equals("0"))
            current = activation.clearLockLocked(current);
        return new Attempt(
                new Result(
                        current,
                        sessions.issueLocked(
                                subject(current), Tokens.client(), current.generation())),
                null,
                null);
    }

    private OgiriAccount clearExpiredLock(OgiriAccount account, long now) {
        return settings.lockable()
                        && account.column("locked_at") != null
                        && !account.locked(settings, now)
                ? activation.clearLockLocked(account)
                : account;
    }

    public Subject subject(OgiriAccount account) {
        return settings.subject(account);
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
