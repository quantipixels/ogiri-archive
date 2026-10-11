// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.web;

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

    public OgiriEndpoints(OgiriRuntime runtime) {
        this.runtime = runtime;
    }

    public record Login(String email, String password) {
        @Override
        public String toString() {
            return "Login[redacted]";
        }
    }

    @PostMapping(value = "/sign_in", consumes = "application/json")
    public Map<String, Object> signIn(
            @RequestBody(required = false) Login login, HttpServletRequest request) {
        var result =
                runtime.signIn()
                        .signIn(
                                login == null ? null : login.email(),
                                login == null ? null : login.password());
        ResponseCredentials.issued(request, result.issued(), result.account().uid());
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
        request.removeAttribute(ResponseCredentials.ATTRIBUTE);
        if (runtime.settings().cookieEnabled()) {
            response.addHeader(
                    "Set-Cookie", new DtaHeaderWriter(runtime.settings()).cookie("", 0).toString());
        }
    }

    public static OgiriAuthentication current(
            Authentication authentication, int status, String message) {
        if (authentication instanceof OgiriAuthentication current && current.isAuthenticated()) {
            return current;
        }
        throw new DtaFailure(status, message);
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
