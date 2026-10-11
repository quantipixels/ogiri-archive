// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.account;

import com.quantipixels.ogiri.DtaFailure;
import com.quantipixels.ogiri.IssuedSession;
import com.quantipixels.ogiri.internal.AuthTransactions;
import com.quantipixels.ogiri.internal.SessionRepository;
import com.quantipixels.ogiri.internal.Tokens;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.validation.BeanPropertyBindingResult;

/** Atomic account/session transitions; mutations commit independently of caller transactions. */
public final class RegistrationService {
    private final AccountStore accounts;
    private final AuthTransactions transactions;
    private final SessionRepository sessions;
    private final OgiriSettings settings;
    private final DevisePasswordEncoder passwords;
    private final SignInService signIn;
    private final AccountValidator validator;
    private final ActivationService activation;

    public RegistrationService(
            AccountStore accounts,
            AuthTransactions transactions,
            SessionRepository sessions,
            OgiriSettings settings,
            DevisePasswordEncoder passwords,
            SignInService signIn,
            AccountValidator validator,
            ActivationService activation) {
        this.accounts = accounts;
        this.transactions = transactions;
        this.sessions = sessions;
        this.settings = settings;
        this.passwords = passwords;
        this.signIn = signIn;
        this.validator = validator;
        this.activation = activation;
    }

    public record Result(
            OgiriAccount account,
            IssuedSession issued,
            com.quantipixels.ogiri.internal.MailDispatcher.Receipt receipt) {
        @Override
        public String toString() {
            return "RegistrationResult[redacted]";
        }
    }

    public Result register(Map<String, ?> values) {
        var input = AccountInput.from(values, settings, true);
        requireInput(input, "sign up");
        transactions.read(
                () -> {
                    validate(input, null, true);
                    return null;
                });
        String target = settings.confirmable() ? confirmationTarget(values, input) : null;
        String hash = passwords.encode(input.password());
        try {
            var result =
                    transactions.write(
                            () -> {
                                var columns = new LinkedHashMap<>(input.attributes());
                                columns.put("email", input.email());
                                columns.put("uid", input.email());
                                columns.put("provider", "email");
                                columns.put("encrypted_password", hash);
                                Instant now = Instant.ofEpochMilli(transactions.now());
                                columns.put("created_at", now);
                                columns.put("updated_at", now);
                                OgiriAccount account = accounts.create(columns);
                                transactions.lock(signIn.subject(account));
                                if (settings.confirmable()) {
                                    var delivery =
                                            activation.confirmLocked(
                                                    account, target, text(values, "config_name"));
                                    return new Result(delivery.account(), null, delivery.receipt());
                                }
                                return new Result(
                                        account,
                                        sessions.issueLocked(
                                                signIn.subject(account), Tokens.client()),
                                        null);
                            });
            if (result.receipt() != null) result.receipt().verify(settings.paranoid());
            return result;
        } catch (com.quantipixels.ogiri.SessionStoreException failure) {
            if (failure.getCause() instanceof DuplicateKeyException)
                throw transactions.read(() -> taken(input, true));
            throw failure;
        }
    }

    public OgiriAccount update(OgiriAccount identity, Map<String, ?> values) {
        return update(identity, values, null).account();
    }

    public AccountChange update(
            OgiriAccount identity, Map<String, ?> values, java.util.UUID credential) {
        var input = AccountInput.from(values, settings, false);
        requireInput(input, "account update");
        String hash = input.password() == null ? null : passwords.encode(input.password());
        var result =
                transactions.write(
                        () -> {
                            transactions.lock(signIn.subject(identity));
                            var current =
                                    accounts.lock(identity.id())
                                            .orElseThrow(() -> failure(404, "User not found."));
                            validate(input, current, false);
                            var changes = new LinkedHashMap<>(input.attributes());
                            boolean reconfirm =
                                    input.email() != null
                                            && !input.email().equals(current.email())
                                            && settings.confirmable()
                                            && settings.reconfirmable();
                            if (reconfirm) changes.put("unconfirmed_email", input.email());
                            else if (input.email() != null) {
                                changes.put("email", input.email());
                                changes.put("uid", input.email());
                            }
                            if (hash != null) {
                                changes.put("encrypted_password", hash);
                                changes.put("allow_password_change", false);
                                changes.put("reset_password_token", null);
                                changes.put("reset_password_sent_at", null);
                            }
                            changes.put("updated_at", Instant.ofEpochMilli(transactions.now()));
                            OgiriAccount updated;
                            try {
                                updated = accounts.update(current.id(), changes);
                            } catch (DuplicateKeyException duplicate) {
                                throw taken(input, false);
                            }
                            if (hash != null && settings.removeTokensAfterPasswordReset())
                                sessions.keepNewestLocked(signIn.subject(current));
                            ActivationService.Delivery delivery =
                                    reconfirm
                                            ? activation.confirmLocked(
                                                    updated,
                                                    text(values, "confirm_success_url"),
                                                    text(values, "config_name"))
                                            : new ActivationService.Delivery(updated, null);
                            return new Mutation(
                                    new AccountChange(
                                            delivery.account(),
                                            sessions.liveLocked(
                                                    signIn.subject(current), credential)),
                                    delivery);
                        });
        result.delivery().verify(settings.paranoid());
        return result.change();
    }

    private record Mutation(AccountChange change, ActivationService.Delivery delivery) {}

    public void destroy(OgiriAccount identity) {
        transactions.write(
                () -> {
                    transactions.lock(signIn.subject(identity));
                    var locked =
                            accounts.lock(identity.id())
                                    .orElseThrow(
                                            () ->
                                                    failure(
                                                            404,
                                                            "Unable to locate account for destruction."));
                    sessions.revokeAllLocked(signIn.subject(identity));
                    accounts.delete(locked.id());
                    return null;
                });
    }

    private void validate(AccountInput input, OgiriAccount current, boolean registration) {
        var errors = new BeanPropertyBindingResult(input, "account");
        validator.validate(input, errors);
        validateCurrent(input, current, errors);
        validateUniqueEmail(input, current, errors);
        if (errors.hasErrors()) {
            var body = new LinkedHashMap<String, Object>();
            body.put("status", "error");
            body.put("errors", AccountValidator.messages(errors));
            if (registration) body.put("data", submitted(input));
            throw new DtaFailure(422, body);
        }
    }

    private void validateCurrent(
            AccountInput input,
            OgiriAccount current,
            org.springframework.validation.Errors errors) {
        if (current != null && needsCurrent(input)) {
            String supplied = input.current_password();
            if (supplied == null || supplied.isEmpty())
                errors.rejectValue("current_password", "blank", "can't be blank");
            else if (!passwords.matches(supplied, current.getPassword()))
                errors.rejectValue("current_password", "invalid", "is invalid");
        }
    }

    private void validateUniqueEmail(
            AccountInput input,
            OgiriAccount current,
            org.springframework.validation.Errors errors) {
        if (input.email() != null && !errors.hasFieldErrors("email")) {
            var existing = accounts.findByEmail(input.email());
            if (existing.isPresent()
                    && (current == null || !existing.orElseThrow().id().equals(current.id()))) {
                errors.rejectValue("email", "taken", "has already been taken");
            }
        }
    }

    private boolean needsCurrent(AccountInput input) {
        return settings.checkCurrentPasswordBeforeUpdate().equals("attributes")
                || (settings.checkCurrentPasswordBeforeUpdate().equals("password")
                        && input.password() != null);
    }

    private String confirmationTarget(Map<String, ?> values, AccountInput input) {
        try {
            return activation.confirmationTarget(text(values, "confirm_success_url"));
        } catch (DtaFailure failure) {
            var body = new LinkedHashMap<>(failure.body());
            body.put("status", "error");
            body.put("data", submitted(input));
            throw new DtaFailure(failure.status(), body);
        }
    }

    private static String text(Map<String, ?> values, String name) {
        return values.get(name) instanceof String value ? value : null;
    }

    public Map<String, Object> submitted(AccountInput input) {
        var view = new LinkedHashMap<String, Object>();
        for (String field : List.of("id", "name", "nickname", "image", "created_at", "updated_at"))
            view.put(field, null);
        view.put("provider", "email");
        view.put("uid", "");
        view.put("email", input.email());
        view.put("allow_password_change", false);
        view.putAll(input.attributes());
        return accounts.preview(view).view(false);
    }

    private static void requireInput(AccountInput input, String action) {
        if (input.empty())
            throw failure(422, "Please submit proper " + action + " data in request body.");
    }

    private DtaFailure taken(AccountInput input, boolean registration) {
        var body = new LinkedHashMap<String, Object>();
        body.put("status", "error");
        body.put(
                "errors",
                Map.of(
                        "email",
                        List.of("has already been taken"),
                        "full_messages",
                        List.of("Email has already been taken")));
        if (registration) body.put("data", submitted(input));
        return new DtaFailure(422, body);
    }

    public static DtaFailure failure(int status, String message) {
        return new DtaFailure(
                status, Map.of("success", false, "errors", List.of(message), "status", "error"));
    }
}
