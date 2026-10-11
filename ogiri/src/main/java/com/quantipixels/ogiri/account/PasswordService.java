// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.account;

import com.quantipixels.ogiri.AuthTransactions;
import com.quantipixels.ogiri.DtaFailure;
import com.quantipixels.ogiri.IssuedSession;
import com.quantipixels.ogiri.JdbcSessions;
import com.quantipixels.ogiri.Tokens;
import com.quantipixels.ogiri.internal.MailDispatcher;
import com.quantipixels.ogiri.internal.PublicLinks;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.validation.BeanPropertyBindingResult;

/** Recovery and password changes share account/session locking and the Devise reset transition. */
public final class PasswordService {
    private final AccountStore accounts;
    private final AuthTransactions transactions;
    private final JdbcSessions sessions;
    private final OgiriSettings settings;
    private final DevisePasswordEncoder passwords;
    private final SignInService signIn;
    private final AccountValidator validator;
    private final MailDispatcher mail;
    private final PublicLinks links;

    public PasswordService(
            AccountStore accounts,
            AuthTransactions transactions,
            JdbcSessions sessions,
            OgiriSettings settings,
            DevisePasswordEncoder passwords,
            SignInService signIn,
            AccountValidator validator,
            MailDispatcher mail,
            PublicLinks links) {
        this.accounts = accounts;
        this.transactions = transactions;
        this.sessions = sessions;
        this.settings = settings;
        this.passwords = passwords;
        this.signIn = signIn;
        this.validator = validator;
        this.mail = mail;
        this.links = links;
    }

    public Map<String, Object> request(Map<String, ?> values) {
        String target =
                links.redirect(
                        text(values, "redirect_url"),
                        settings.defaultPasswordResetUrl(),
                        401,
                        "Missing redirect URL.");
        String email = text(values, "email");
        if (email == null || email.isBlank())
            throw new DtaFailure(401, "You must provide an email address.");
        email = JdbcDeviseAccountStore.normalize(email);
        String address = email;
        var found = transactions.read(() -> accounts.findByEmail(address));
        if (found.isPresent()) {
            var receipt =
                    transactions.write(
                            () -> reset(found.orElseThrow(), target, text(values, "config_name")));
            receipt.verify(settings.paranoid());
        } else if (!settings.paranoid())
            throw new DtaFailure(404, "Unable to find user with email '" + email + "'.");
        String message =
                settings.paranoid()
                        ? "If your email address exists in our database, you will receive a password recovery link at your email address in a few minutes."
                        : "An email has been sent to '"
                                + email
                                + "' containing instructions for resetting your password.";
        return Map.of("success", true, "message", message);
    }

    private MailDispatcher.Receipt reset(OgiriAccount candidate, String target, String config) {
        transactions.lock(signIn.subject(candidate));
        var current =
                accounts.lock(candidate.id())
                        .orElseThrow(() -> new DtaFailure(404, "User not found."));
        String token = Tokens.generate();
        var changes = new LinkedHashMap<String, Object>();
        changes.put("reset_password_token", digest(token));
        changes.put("reset_password_sent_at", Instant.ofEpochMilli(transactions.now()));
        changes.put("updated_at", Instant.ofEpochMilli(transactions.now()));
        accounts.update(current.id(), changes);
        var query = new LinkedHashMap<String, String>();
        query.put("reset_password_token", token);
        query.put("redirect_url", target);
        if (config != null) query.put("config", config);
        return mail.enqueue(
                MailDispatcher.Kind.RESET, current.email(), links.mail("/password/edit", query));
    }

    public String follow(String token, String redirect, String config) {
        String target =
                links.redirect(
                        redirect,
                        settings.defaultPasswordResetUrl(),
                        404,
                        "Invalid reset password token.");
        var result =
                transactions.write(
                        () -> {
                            var current = lockToken(token);
                            var changes = new LinkedHashMap<String, Object>();
                            changes.put("allow_password_change", true);
                            if (current.column("confirmed_at") == null)
                                changes.put(
                                        "confirmed_at", Instant.ofEpochMilli(transactions.now()));
                            current = accounts.update(current.id(), changes);
                            IssuedSession issued =
                                    settings.requireClientPasswordResetToken()
                                            ? null
                                            : sessions.issueLocked(
                                                    signIn.subject(current), Tokens.client());
                            return new ResetResult(current, issued);
                        });
        var query = new LinkedHashMap<String, String>();
        if (result.issued() != null) {
            query.putAll(authQuery(result.account(), result.issued(), config));
            query.put("reset_password", "true");
        }
        query.put("reset_password_token", token);
        return PublicLinks.query(target, query);
    }

    private record ResetResult(OgiriAccount account, IssuedSession issued) {
        @Override
        public String toString() {
            return "ResetResult[redacted]";
        }
    }

    public OgiriAccount change(OgiriAccount identity, Map<String, ?> values) {
        return change(identity, values, null).account();
    }

    public AccountChange change(
            OgiriAccount identity, Map<String, ?> values, java.util.UUID credential) {
        String token = text(values, "reset_password_token");
        if (identity == null && (!settings.requireClientPasswordResetToken() || token == null))
            throw new DtaFailure(401, "Unauthorized");
        var input = AccountInput.from(values, settings, false);
        String hash = input.password() == null ? null : passwords.encode(input.password());
        return transactions.write(
                () -> {
                    OgiriAccount current;
                    if (settings.requireClientPasswordResetToken() && token != null)
                        current = lockToken(token);
                    else {
                        transactions.lock(signIn.subject(identity));
                        current =
                                accounts.lock(identity.id())
                                        .orElseThrow(() -> new DtaFailure(401, "Unauthorized"));
                    }
                    validate(current, input);
                    var changes = new LinkedHashMap<String, Object>();
                    changes.put("encrypted_password", hash);
                    changes.put("allow_password_change", false);
                    changes.put("reset_password_token", null);
                    changes.put("reset_password_sent_at", null);
                    changes.put("updated_at", Instant.ofEpochMilli(transactions.now()));
                    var updated = accounts.update(current.id(), changes);
                    if (settings.removeTokensAfterPasswordReset())
                        sessions.keepNewestLocked(signIn.subject(current));
                    return new AccountChange(
                            updated, sessions.liveLocked(signIn.subject(current), credential));
                });
    }

    private void validate(OgiriAccount current, AccountInput input) {
        requirePassword(current, input);
        var errors = new BeanPropertyBindingResult(input, "password");
        validator.validate(input, errors);
        validateCurrent(current, input, errors);
        if (errors.hasErrors())
            throw new DtaFailure(
                    422, Map.of("success", false, "errors", AccountValidator.messages(errors)));
    }

    private static void requirePassword(OgiriAccount current, AccountInput input) {
        if (!current.text("provider").equals("email")) {
            String provider = current.text("provider");
            provider = Character.toUpperCase(provider.charAt(0)) + provider.substring(1);
            throw new DtaFailure(
                    422,
                    "This account does not require a password. Sign in using your '"
                            + provider
                            + "' account instead.");
        }
        if (input.password() == null
                || input.password().isBlank()
                || input.password_confirmation() == null
                || input.password_confirmation().isBlank())
            throw new DtaFailure(
                    422,
                    "You must fill out the fields labeled 'Password' and 'Password confirmation'.");
    }

    private void validateCurrent(
            OgiriAccount current,
            AccountInput input,
            org.springframework.validation.Errors errors) {
        if (!settings.checkCurrentPasswordBeforeUpdate().equals("false")
                && !current.flag("allow_password_change")) {
            if (input.current_password() == null || input.current_password().isEmpty())
                errors.rejectValue("current_password", "blank", "can't be blank");
            else if (!passwords.matches(input.current_password(), current.getPassword()))
                errors.rejectValue("current_password", "invalid", "is invalid");
        }
    }

    private OgiriAccount lockToken(String token) {
        String digest = digest(token);
        var candidate =
                accounts.findByToken("reset_password_token", digest)
                        .orElseThrow(() -> new DtaFailure(404, "Invalid reset password token."));
        transactions.lock(signIn.subject(candidate));
        var current =
                accounts.lock(candidate.id())
                        .orElseThrow(() -> new DtaFailure(404, "Invalid reset password token."));
        Instant sent = current.time("reset_password_sent_at");
        if (!java.security.MessageDigest.isEqual(
                        digest.getBytes(java.nio.charset.StandardCharsets.US_ASCII),
                        current.text("reset_password_token")
                                .getBytes(java.nio.charset.StandardCharsets.US_ASCII))
                || sent == null
                || transactions.now()
                        >= sent.toEpochMilli() + settings.resetPasswordWithin().toMillis())
            throw new DtaFailure(404, "Invalid reset password token.");
        return current;
    }

    public static String digest(String token) {
        byte[] digest = Tokens.digest(token);
        return java.util.HexFormat.of().formatHex(digest == null ? new byte[32] : digest);
    }

    public static Map<String, String> authQuery(
            OgiriAccount account, IssuedSession issued, String config) {
        var query = new LinkedHashMap<String, String>();
        query.put("access-token", issued.token());
        query.put("token", issued.token());
        query.put("client", issued.session().client());
        query.put("client_id", issued.session().client());
        query.put("uid", account.uid());
        query.put("expiry", Long.toString(issued.session().expiresAt().toEpochMilli() / 1000));
        query.put("config", config == null ? "default" : config);
        return query;
    }

    private static String text(Map<String, ?> values, String key) {
        return values.get(key) instanceof String value ? value : null;
    }
}
