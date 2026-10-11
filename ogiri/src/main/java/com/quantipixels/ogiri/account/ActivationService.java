// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.account;

import com.quantipixels.ogiri.DtaFailure;
import com.quantipixels.ogiri.Subject;
import com.quantipixels.ogiri.internal.AuthTransactions;
import com.quantipixels.ogiri.internal.MailDispatcher;
import com.quantipixels.ogiri.internal.PublicLinks;
import com.quantipixels.ogiri.internal.SessionRepository;
import com.quantipixels.ogiri.internal.Tokens;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/** Confirmation and lockout transitions share the account admission fence. */
public final class ActivationService {
    private final AccountStore accounts;
    private final AuthTransactions transactions;
    private final SessionRepository sessions;
    private final OgiriSettings settings;
    private final MailDispatcher mail;
    private final PublicLinks links;

    public ActivationService(
            AccountStore accounts,
            AuthTransactions transactions,
            SessionRepository sessions,
            OgiriSettings settings,
            MailDispatcher mail,
            PublicLinks links) {
        this.accounts = accounts;
        this.transactions = transactions;
        this.sessions = sessions;
        this.settings = settings;
        this.mail = mail;
        this.links = links;
    }

    private Subject subject(OgiriAccount account) {
        return new Subject(settings.realm(), "", account.id());
    }

    public String confirmationTarget(String target) {
        return links.redirect(
                target,
                settings.defaultConfirmSuccessUrl(),
                422,
                "Missing 'confirm_success_url' parameter.");
    }

    public record Delivery(OgiriAccount account, MailDispatcher.Receipt receipt) {
        public void verify(boolean paranoid) {
            if (receipt != null) receipt.verify(paranoid);
        }

        @Override
        public String toString() {
            return "ActivationDelivery[redacted]";
        }
    }

    public Delivery confirmLocked(OgiriAccount current, String target, String config) {
        String token = Tokens.generate();
        var changes = new LinkedHashMap<String, Object>();
        changes.put("confirmation_token", Tokens.hexDigest(token));
        changes.put("confirmation_sent_at", Instant.ofEpochMilli(transactions.now()));
        current = accounts.update(current.id(), changes);
        var query = new LinkedHashMap<String, String>();
        query.put("confirmation_token", token);
        if (target != null && !target.isBlank()) query.put("redirect_url", target);
        if (config != null) query.put("config", config);
        String recipient =
                current.text("unconfirmed_email").isEmpty()
                        ? current.email()
                        : current.text("unconfirmed_email");
        return new Delivery(
                current,
                mail.enqueue(
                        MailDispatcher.Kind.CONFIRMATION,
                        recipient,
                        links.mail("/confirmation", query)));
    }

    public Map<String, Object> confirmation(Map<String, ?> values) {
        String email = email(values);
        var candidate = transactions.read(() -> accounts.findByEmail(email));
        if (candidate.isPresent()) {
            var sent =
                    transactions.write(
                            () -> {
                                transactions.lock(subject(candidate.orElseThrow()));
                                var current =
                                        accounts.lock(candidate.orElseThrow().id())
                                                .orElseThrow(
                                                        () ->
                                                                new DtaFailure(
                                                                        404, "User not found."));
                                if (current.column("confirmed_at") != null
                                        && current.text("unconfirmed_email").isEmpty())
                                    return new Delivery(current, null);
                                String target = text(values, "redirect_url");
                                if (target != null && !target.isBlank())
                                    target =
                                            links.redirect(
                                                    target,
                                                    settings.defaultConfirmSuccessUrl(),
                                                    422,
                                                    "Missing redirect URL.");
                                else target = settings.defaultConfirmSuccessUrl();
                                return confirmLocked(current, target, text(values, "config_name"));
                            });
            sent.verify(settings.paranoid());
        } else unknown(email);
        return message(
                email,
                "confirming your account.",
                "If your email address exists in our database, you will receive an email with instructions for how to confirm your email address in a few minutes.");
    }

    public String confirm(String token, String redirect) {
        String target =
                links.redirect(
                        redirect,
                        settings.defaultConfirmSuccessUrl(),
                        404,
                        "Invalid confirmation token.");
        boolean confirmed =
                transactions.write(
                        () -> {
                            var candidate =
                                    accounts.findByToken(
                                            "confirmation_token", PasswordService.digest(token));
                            if (candidate.isEmpty()) return false;
                            transactions.lock(subject(candidate.orElseThrow()));
                            var current = accounts.lock(candidate.orElseThrow().id());
                            if (current.isEmpty()
                                    || !sameDigest(
                                            current.orElseThrow().text("confirmation_token"),
                                            PasswordService.digest(token))) return false;
                            var account = current.orElseThrow();
                            var changes = new LinkedHashMap<String, Object>();
                            changes.put("confirmation_token", null);
                            changes.put("confirmed_at", Instant.ofEpochMilli(transactions.now()));
                            changes.put("updated_at", Instant.ofEpochMilli(transactions.now()));
                            if (!account.text("unconfirmed_email").isEmpty()) {
                                changes.put("email", account.text("unconfirmed_email"));
                                if (account.text("provider").equals("email"))
                                    changes.put("uid", account.text("unconfirmed_email"));
                                changes.put("unconfirmed_email", null);
                            }
                            accounts.update(account.id(), changes);
                            return true;
                        });
        return PublicLinks.query(
                target, Map.of("account_confirmation_success", Boolean.toString(confirmed)));
    }

    public Delivery failedLocked(OgiriAccount current) {
        int attempts = Integer.parseInt(current.text("failed_attempts")) + 1;
        var changes = new LinkedHashMap<String, Object>();
        changes.put("failed_attempts", attempts);
        if (attempts >= settings.maximumAttempts()) {
            changes.put("locked_at", Instant.ofEpochMilli(transactions.now()));
            sessions.revokeAllLocked(subject(current));
        }
        current = accounts.update(current.id(), changes);
        return attempts >= settings.maximumAttempts() && emailUnlock()
                ? unlockMailLocked(current, null)
                : new Delivery(current, null);
    }

    private boolean emailUnlock() {
        return settings.unlockStrategy().equals("both")
                || settings.unlockStrategy().equals("email");
    }

    public OgiriAccount clearLockLocked(OgiriAccount current) {
        var changes = new LinkedHashMap<String, Object>();
        changes.put("failed_attempts", 0);
        changes.put("locked_at", null);
        changes.put("unlock_token", null);
        return accounts.update(current.id(), changes);
    }

    private Delivery unlockMailLocked(OgiriAccount current, String config) {
        String token = Tokens.generate();
        current = accounts.update(current.id(), Map.of("unlock_token", Tokens.hexDigest(token)));
        var query = new LinkedHashMap<String, String>();
        query.put("unlock_token", token);
        if (config != null) query.put("config", config);
        return new Delivery(
                current,
                mail.enqueue(
                        MailDispatcher.Kind.UNLOCK, current.email(), links.mail("/unlock", query)));
    }

    public Map<String, Object> unlock(Map<String, ?> values) {
        String email = email(values);
        var candidate = transactions.read(() -> accounts.findByEmail(email));
        if (candidate.isPresent()) {
            var sent =
                    transactions.write(
                            () -> {
                                transactions.lock(subject(candidate.orElseThrow()));
                                var current =
                                        accounts.lock(candidate.orElseThrow().id())
                                                .orElseThrow(
                                                        () ->
                                                                new DtaFailure(
                                                                        404, "User not found."));
                                return current.locked(settings, transactions.now()) && emailUnlock()
                                        ? unlockMailLocked(current, text(values, "config_name"))
                                        : new Delivery(current, null);
                            });
            sent.verify(settings.paranoid());
        } else unknown(email);
        return message(
                email,
                "unlocking your account.",
                "If your account exists, you will receive an email with instructions for how to unlock it in a few minutes.");
    }

    public String unlock(String token, String config) {
        return transactions.write(
                () -> {
                    var candidate =
                            accounts.findByToken("unlock_token", PasswordService.digest(token))
                                    .orElseThrow(ActivationService::invalidUnlock);
                    transactions.lock(subject(candidate));
                    var current =
                            accounts.lock(candidate.id())
                                    .orElseThrow(ActivationService::invalidUnlock);
                    if (!emailUnlock()
                            || !current.locked(settings, transactions.now())
                            || !sameDigest(
                                    current.text("unlock_token"), PasswordService.digest(token)))
                        throw invalidUnlock();
                    current = clearLockLocked(current);
                    var issued = sessions.issueLocked(subject(current), Tokens.client());
                    var query =
                            new LinkedHashMap<>(PasswordService.authQuery(current, issued, config));
                    query.put("unlock", "true");
                    return PublicLinks.query("/", query);
                });
    }

    private static DtaFailure invalidUnlock() {
        return new DtaFailure(404, "Invalid unlock token.");
    }

    private static boolean sameDigest(String expected, String actual) {
        return java.security.MessageDigest.isEqual(
                expected.getBytes(java.nio.charset.StandardCharsets.US_ASCII),
                actual.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
    }

    private static String email(Map<String, ?> values) {
        String email = text(values, "email");
        if (email == null || email.isBlank())
            throw new DtaFailure(401, "You must provide an email address.");
        return JdbcDeviseAccountStore.normalize(email);
    }

    private void unknown(String email) {
        if (!settings.paranoid())
            throw new DtaFailure(404, "Unable to find user with email '" + email + "'.");
    }

    private Map<String, Object> message(String email, String action, String paranoid) {
        return Map.of(
                "success",
                true,
                "message",
                settings.paranoid()
                        ? paranoid
                        : "An email has been sent to '"
                                + email
                                + "' containing instructions for "
                                + action);
    }

    private static String text(Map<String, ?> values, String name) {
        return values.get(name) instanceof String value ? value : null;
    }
}
