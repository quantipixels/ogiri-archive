// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.web.internal;

import com.quantipixels.ogiri.DtaFailure;
import com.quantipixels.ogiri.SessionStoreException;
import com.quantipixels.ogiri.security.DtaHeaderWriter;
import com.quantipixels.ogiri.security.OgiriAuthentication;
import com.quantipixels.ogiri.security.OgiriRuntime;
import com.quantipixels.ogiri.security.ResponseCredentials;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("${ogiri.base-path:/auth}")
public final class OgiriEndpoints {
    private final OgiriRuntime runtime;
    private final com.quantipixels.ogiri.account.RegistrationService registration;
    private final com.quantipixels.ogiri.account.PasswordService passwords;
    private final com.quantipixels.ogiri.account.ActivationService activation;

    public OgiriEndpoints(
            OgiriRuntime runtime,
            com.quantipixels.ogiri.account.RegistrationService registration,
            com.quantipixels.ogiri.account.PasswordService passwords,
            com.quantipixels.ogiri.account.ActivationService activation) {
        this.runtime = runtime;
        this.registration = registration;
        this.passwords = passwords;
        this.activation = activation;
    }

    @PostMapping(path = "/confirmation", consumes = "application/json")
    public Map<String, Object> confirmation(@RequestBody Map<String, Object> values) {
        return activation.confirmation(values);
    }

    @PostMapping(path = "/confirmation", consumes = "application/x-www-form-urlencoded")
    public Map<String, Object> confirmationForm(@RequestParam Map<String, String> values) {
        return activation.confirmation(values);
    }

    @GetMapping("/confirmation")
    public ResponseEntity<Void> confirm(
            @RequestParam(required = false) String confirmation_token,
            @RequestParam(required = false) String redirect_url) {
        return ResponseEntity.status(302)
                .location(java.net.URI.create(activation.confirm(confirmation_token, redirect_url)))
                .build();
    }

    @PostMapping(path = "/unlock", consumes = "application/json")
    public Map<String, Object> unlock(@RequestBody Map<String, Object> values) {
        return activation.unlock(values);
    }

    @PostMapping(path = "/unlock", consumes = "application/x-www-form-urlencoded")
    public Map<String, Object> unlockForm(@RequestParam Map<String, String> values) {
        return activation.unlock(values);
    }

    @GetMapping("/unlock")
    public ResponseEntity<Void> unlockLink(
            @RequestParam(required = false) String unlock_token,
            @RequestParam(required = false) String config) {
        return ResponseEntity.status(302)
                .location(java.net.URI.create(activation.unlock(unlock_token, config)))
                .build();
    }

    @PostMapping(path = "/password", consumes = "application/json")
    public Map<String, Object> resetPassword(@RequestBody Map<String, Object> values) {
        return passwords.request(values);
    }

    @PostMapping(path = "/password", consumes = "application/x-www-form-urlencoded")
    public Map<String, Object> resetPasswordForm(@RequestParam Map<String, String> values) {
        return passwords.request(values);
    }

    @GetMapping("/password/edit")
    public ResponseEntity<Void> resetLink(
            @RequestParam(required = false) String reset_password_token,
            @RequestParam(required = false) String redirect_url,
            @RequestParam(required = false) String config) {
        return ResponseEntity.status(302)
                .location(
                        java.net.URI.create(
                                passwords.follow(reset_password_token, redirect_url, config)))
                .build();
    }

    @RequestMapping(
            path = "/password",
            method = {
                org.springframework.web.bind.annotation.RequestMethod.PUT,
                org.springframework.web.bind.annotation.RequestMethod.PATCH
            },
            consumes = "application/json")
    public Map<String, Object> changePassword(
            @RequestBody Map<String, Object> values,
            Authentication authentication,
            HttpServletRequest request,
            HttpServletResponse response) {
        var identity =
                authentication instanceof OgiriAuthentication current && current.isAuthenticated()
                        ? current
                        : null;
        var changed =
                passwords.change(
                        identity == null ? null : identity.getPrincipal(),
                        values,
                        identity == null ? null : identity.session());
        var account = changed.account();
        if (identity != null
                && runtime.settings().subject(account).equals(identity.session().subject())
                && !changed.credentialRetained()) clear(request, response);
        return Map.of(
                "success",
                true,
                "data",
                account.view(false),
                "message",
                "Your password has been successfully updated.");
    }

    @RequestMapping(
            path = "/password",
            method = {
                org.springframework.web.bind.annotation.RequestMethod.PUT,
                org.springframework.web.bind.annotation.RequestMethod.PATCH
            },
            consumes = "application/x-www-form-urlencoded")
    public Map<String, Object> changePasswordForm(
            @RequestParam Map<String, String> values,
            Authentication authentication,
            HttpServletRequest request,
            HttpServletResponse response) {
        return changePassword(
                new java.util.LinkedHashMap<>(values), authentication, request, response);
    }

    @RequestMapping(
            path = {"", "/", "/password", "/confirmation", "/unlock"},
            method = {
                org.springframework.web.bind.annotation.RequestMethod.POST,
                org.springframework.web.bind.annotation.RequestMethod.PUT,
                org.springframework.web.bind.annotation.RequestMethod.PATCH
            })
    public ResponseEntity<Map<String, Object>> unsupportedBody() {
        return unsupportedSignInBody();
    }

    @org.springframework.web.bind.annotation.RequestMapping(
            path = {"", "/"},
            method = org.springframework.web.bind.annotation.RequestMethod.POST,
            consumes = "application/json")
    public Map<String, Object> register(
            @RequestBody Map<String, Object> values, HttpServletRequest request) {
        var result = registration.register(values);
        if (result.issued() != null)
            ResponseCredentials.issued(request, runtime, result.issued(), result.account().uid());
        return Map.of("status", "success", "data", result.account().view(false));
    }

    @org.springframework.web.bind.annotation.RequestMapping(
            path = {"", "/"},
            method = org.springframework.web.bind.annotation.RequestMethod.POST,
            consumes = "application/x-www-form-urlencoded")
    public Map<String, Object> registerForm(
            @RequestParam Map<String, String> values, HttpServletRequest request) {
        return register(new java.util.LinkedHashMap<>(values), request);
    }

    @org.springframework.web.bind.annotation.RequestMapping(
            path = {"", "/"},
            method = {
                org.springframework.web.bind.annotation.RequestMethod.PUT,
                org.springframework.web.bind.annotation.RequestMethod.PATCH
            },
            consumes = "application/json")
    public Map<String, Object> update(
            @RequestBody Map<String, Object> values,
            Authentication authentication,
            HttpServletRequest request,
            HttpServletResponse response) {
        var identity = accountIdentity(authentication, "User not found.");
        var changed = registration.update(identity.getPrincipal(), values, identity.session());
        var account = changed.account();
        var credentials =
                (ResponseCredentials) request.getAttribute(runtime.responseCredentialsAttribute());
        if (!changed.credentialRetained()) clear(request, response);
        else if (changed.issued() != null)
            ResponseCredentials.issued(request, runtime, changed.issued(), account.uid());
        else if (credentials != null)
            request.setAttribute(
                    runtime.responseCredentialsAttribute(),
                    new ResponseCredentials(
                            credentials.token(),
                            credentials.client(),
                            account.uid(),
                            credentials.expiry(),
                            credentials.batch()));
        return Map.of("status", "success", "data", account.view(false));
    }

    @org.springframework.web.bind.annotation.RequestMapping(
            path = {"", "/"},
            method = {
                org.springframework.web.bind.annotation.RequestMethod.PUT,
                org.springframework.web.bind.annotation.RequestMethod.PATCH
            },
            consumes = "application/x-www-form-urlencoded")
    public Map<String, Object> updateForm(
            @RequestParam Map<String, String> values,
            Authentication authentication,
            HttpServletRequest request,
            HttpServletResponse response) {
        return update(new java.util.LinkedHashMap<>(values), authentication, request, response);
    }

    @DeleteMapping({"", "/"})
    public Map<String, Object> destroy(
            Authentication authentication,
            HttpServletRequest request,
            HttpServletResponse response) {
        var identity = accountIdentity(authentication, "Unable to locate account for destruction.");
        registration.destroy(identity.getPrincipal(), identity.session());
        clear(request, response);
        return Map.of(
                "status",
                "success",
                "message",
                "Account with UID '" + identity.getPrincipal().uid() + "' has been destroyed.");
    }

    private OgiriAuthentication accountIdentity(Authentication authentication, String message) {
        if (authentication instanceof OgiriAuthentication identity && identity.isAuthenticated()) {
            return identity;
        }
        throw com.quantipixels.ogiri.account.RegistrationService.failure(404, message);
    }

    public record Login(String email, String password) {
        @Override
        public String toString() {
            return "Login[redacted]";
        }
    }

    @PostMapping("/sign_in")
    public ResponseEntity<Map<String, Object>> unsupportedSignInBody() {
        return ResponseEntity.status(415)
                .body(
                        Map.of(
                                "success",
                                false,
                                "errors",
                                java.util.List.of("Unsupported request content type.")));
    }

    @PostMapping(value = "/sign_in", consumes = "application/json")
    public Map<String, Object> signIn(@RequestBody Login login, HttpServletRequest request) {
        var result =
                runtime.signIn()
                        .signIn(
                                login == null ? null : login.email(),
                                login == null ? null : login.password());
        if (result.issued() != null)
            ResponseCredentials.issued(request, runtime, result.issued(), result.account().uid());
        return Map.of("data", result.account().view(true));
    }

    @PostMapping(value = "/sign_in", consumes = "application/x-www-form-urlencoded")
    public Map<String, Object> signInForm(
            @RequestParam Map<String, String> values, HttpServletRequest request) {
        return signIn(new Login(values.get("email"), values.get("password")), request);
    }

    @SuppressWarnings("DoNotCallSuggester") // MVC route deliberately returns the contract 405.
    @GetMapping("/sign_in")
    public Map<String, Object> wrongMethod() {
        throw new DtaFailure(405, "Use POST /sign_in to sign in. GET is not supported.");
    }

    @GetMapping("/validate_token")
    public Map<String, Object> validate(Authentication authentication) {
        var current = current(authentication, 401, "Invalid login credentials");
        return Map.of("success", true, "data", current.getPrincipal().view(true));
    }

    @DeleteMapping("/sign_out")
    public Map<String, Object> signOut(
            Authentication authentication,
            HttpServletRequest request,
            HttpServletResponse response) {
        var current = current(authentication, 404, "User was not found or was not logged in.");
        runtime.sessions().revoke(current.session().subject(), current.session().id());
        clear(request, response);
        return Map.of("success", true);
    }

    @GetMapping("/sessions")
    public Map<String, Object> list(Authentication authentication) {
        var current =
                current(authentication, 401, "You need to sign in or sign up before continuing.");
        return Map.of(
                "success",
                true,
                "data",
                runtime.sessions().list(current.session().subject()).stream()
                        .map(
                                session ->
                                        Map.of(
                                                "client",
                                                session.client(),
                                                "created_at",
                                                session.createdAt().toString(),
                                                "expiry",
                                                session.expiresAt().toEpochMilli() / 1000,
                                                "current",
                                                session.id().equals(current.session().id())))
                        .toList());
    }

    @DeleteMapping("/sessions/{client}")
    public Map<String, Object> revoke(
            Authentication authentication,
            @PathVariable String client,
            HttpServletRequest request,
            HttpServletResponse response) {
        var current =
                current(authentication, 401, "You need to sign in or sign up before continuing.");
        var session =
                runtime.sessions().list(current.session().subject()).stream()
                        .filter(value -> value.client().equals(client))
                        .findFirst()
                        .orElseThrow(() -> new DtaFailure(404, "Session not found."));
        if (!runtime.sessions().revoke(current.session().subject(), session.id())) {
            throw new DtaFailure(404, "Session not found.");
        }
        if (current.session().id().equals(session.id())) {
            clear(request, response);
        }
        return Map.of("success", true);
    }

    @DeleteMapping("/sessions")
    public Map<String, Object> revokeAll(
            Authentication authentication,
            HttpServletRequest request,
            HttpServletResponse response) {
        var current =
                current(authentication, 401, "You need to sign in or sign up before continuing.");
        runtime.sessions().revokeAll(current.session().subject());
        clear(request, response);
        return Map.of("success", true);
    }

    private void clear(HttpServletRequest request, HttpServletResponse response) {
        request.removeAttribute(runtime.responseCredentialsAttribute());
        if (runtime.settings().cookieEnabled()) {
            response.addHeader(
                    "Set-Cookie", new DtaHeaderWriter(runtime.settings()).cookie("", 0).toString());
        }
    }

    private OgiriAuthentication current(Authentication authentication, int status, String message) {
        if (authentication instanceof OgiriAuthentication current && current.isAuthenticated()) {
            runtime.settings().requireOwner(current.getPrincipal(), current.session());
            return current;
        }
        throw new DtaFailure(status, message);
    }

    @ExceptionHandler({
        org.springframework.http.converter.HttpMessageNotReadableException.class,
        org.springframework.web.HttpMediaTypeNotSupportedException.class
    })
    public ResponseEntity<Map<String, Object>> invalidSignInBody(Exception failure) {
        int status =
                failure instanceof org.springframework.web.HttpMediaTypeNotSupportedException
                        ? 415
                        : 400;
        return ResponseEntity.status(status)
                .body(
                        Map.of(
                                "success",
                                false,
                                "errors",
                                java.util.List.of("Invalid request body.")));
    }

    @ExceptionHandler(DtaFailure.class)
    public ResponseEntity<Map<String, Object>> failure(DtaFailure failure) {
        return ResponseEntity.status(failure.status())
                .header("Cache-Control", "no-store")
                .body(failure.body());
    }

    @ExceptionHandler(SessionStoreException.class)
    public ResponseEntity<Map<String, Object>> outage(SessionStoreException failure) {
        return ResponseEntity.status(503)
                .header("Cache-Control", "no-store")
                .body(DtaFailure.unavailable());
    }
}
