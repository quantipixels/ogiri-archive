// SPDX-License-Identifier: Apache-2.0
package example.ogiri;

import static org.junit.jupiter.api.Assertions.*;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import tools.jackson.databind.json.JsonMapper;

@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
            "spring.datasource.url=${OGIRI_TEST_JDBC_URL}",
            "spring.datasource.username=${OGIRI_TEST_JDBC_USER}",
            "spring.datasource.password=${OGIRI_TEST_JDBC_PASSWORD}",
            "spring.profiles.active=demo",
            "ogiri.confirmable=true",
            "ogiri.lockable=true",
            "ogiri.maximum-attempts=2",
            "ogiri.public-base-url=https://accounts.example.test"
        })
@Import(PasswordMailTest.MailConfiguration.class)
class ActivationMailTest {
    @Value("${local.server.port}")
    int port;

    @Autowired PasswordMailTest.RecordingMail mail;
    @Autowired JdbcTemplate jdbc;

    @Test
    void confirmationFailureKeepsCommittedDigestAndRetryConfirmsWithoutAuthHeaders()
            throws Exception {
        String email = email();
        mail.fail = true;
        try {
            var failed = signup(email);
            assertEquals(503, failed.statusCode(), failed.body());
            assertTrue(failed.headers().firstValue("access-token").isEmpty());
            String digest =
                    jdbc.queryForObject(
                            "SELECT confirmation_token FROM users WHERE email = ?",
                            String.class,
                            email);
            assertEquals(64, digest.length());
            mail.fail = false;
            var retry =
                    request(
                            "POST",
                            "/confirmation",
                            Map.of(
                                    "email",
                                    email,
                                    "redirect_url",
                                    "https://client.example.test/done"),
                            null);
            assertEquals(200, retry.statusCode(), retry.body());
            assertNotEquals(
                    digest,
                    jdbc.queryForObject(
                            "SELECT confirmation_token FROM users WHERE email = ?",
                            String.class,
                            email));
            assertEquals("accounts.example.test", URI.create(mail.link).getHost());
            var followed = follow(mail.link);
            assertEquals(302, followed.statusCode(), followed.body());
            assertTrue(followed.headers().firstValue("access-token").isEmpty());
            assertEquals(200, login(email, "test-password").statusCode());
        } finally {
            mail.fail = false;
        }
    }

    @Test
    void lockFailureCommitsAttemptsAndRevocationAndUnlockOnlyWorksWhileLocked() throws Exception {
        String email = email();
        assertEquals(200, signup(email).statusCode());
        assertEquals(302, follow(mail.link).statusCode());
        String auth =
                login(email, "test-password").headers().firstValue("Authorization").orElseThrow();
        mail.fail = true;
        try {
            assertEquals(401, login(email, "wrong-password").statusCode());
            var locked = login(email, "wrong-password");
            assertEquals(503, locked.statusCode(), locked.body());
            assertEquals(
                    2,
                    jdbc.queryForObject(
                            "SELECT failed_attempts FROM users WHERE email = ?",
                            Integer.class,
                            email));
            assertNotNull(
                    jdbc.queryForObject(
                            "SELECT locked_at FROM users WHERE email = ?", Object.class, email));
            assertEquals(401, request("GET", "/me", null, auth).statusCode());
            assertEquals(401, login(email, "test-password").statusCode());
            mail.fail = false;
            assertEquals(
                    200, request("POST", "/unlock", Map.of("email", email), null).statusCode());
            String link = mail.link;
            assertEquals(302, follow(link).statusCode());
            assertEquals(200, login(email, "test-password").statusCode());
            assertEquals(404, follow(link).statusCode());
            request("POST", "/unlock", Map.of("email", email), null);
            assertEquals(link, mail.link, "An unlocked account gets no new unlock mail");
        } finally {
            mail.fail = false;
        }
    }

    @Test
    void reconfirmationWritesOnlyThePendingAddressUntilTheLinkIsConsumed() throws Exception {
        String email = email();
        assertEquals(200, signup(email).statusCode());
        assertEquals(302, follow(mail.link).statusCode());
        String auth =
                login(email, "test-password").headers().firstValue("Authorization").orElseThrow();
        String next = "next-" + email;
        var changed = request("PATCH", "", Map.of("email", next), auth);
        assertEquals(200, changed.statusCode(), changed.body());
        assertEquals(
                email,
                jdbc.queryForObject(
                        "SELECT email FROM users WHERE unconfirmed_email = ?", String.class, next));
        URI link = URI.create(mail.link);
        var confirmed =
                request(
                        "GET",
                        link.getPath().substring(5)
                                + "?"
                                + link.getRawQuery()
                                + "&redirect_url=https://client.example.test/done",
                        null,
                        null);
        assertEquals(302, confirmed.statusCode(), confirmed.body());
        assertEquals(200, login(next, "test-password").statusCode());
        assertEquals(
                next,
                jdbc.queryForObject("SELECT uid FROM users WHERE email = ?", String.class, next));
    }

    @Test
    void reconfirmationKeepsTheProviderUidEvenWhenEmailChanges() throws Exception {
        String email = email();
        assertEquals(200, signup(email).statusCode());
        assertEquals(302, follow(mail.link).statusCode());
        String auth =
                login(email, "test-password").headers().firstValue("Authorization").orElseThrow();
        String uid = "github-" + java.util.UUID.randomUUID();
        jdbc.update("UPDATE users SET provider = 'github', uid = ? WHERE email = ?", uid, email);
        var credentials =
                JsonMapper.builder()
                        .build()
                        .readTree(java.util.Base64.getDecoder().decode(auth.substring(7)));
        auth =
                "Bearer "
                        + java.util.Base64.getEncoder()
                                .encodeToString(
                                        JsonMapper.builder()
                                                .build()
                                                .writeValueAsBytes(
                                                        Map.of(
                                                                "uid",
                                                                uid,
                                                                "client",
                                                                credentials.get("client").asText(),
                                                                "access-token",
                                                                credentials
                                                                        .get("access-token")
                                                                        .asText())));
        String next = "next-" + email;
        assertEquals(
                200,
                request(
                                "PATCH",
                                "",
                                Map.of(
                                        "email",
                                        next,
                                        "confirm_success_url",
                                        "https://client.example.test/done"),
                                auth)
                        .statusCode());
        assertEquals(302, follow(mail.link).statusCode());
        assertEquals(
                uid,
                jdbc.queryForObject("SELECT uid FROM users WHERE email = ?", String.class, next));
        assertEquals(
                "github",
                jdbc.queryForObject(
                        "SELECT provider FROM users WHERE email = ?", String.class, next));
        assertEquals(200, request("GET", "/validate_token", null, auth).statusCode());
    }

    private String email() {
        return "activation-" + java.util.UUID.randomUUID() + "@example.com";
    }

    private HttpResponse<String> signup(String email) throws Exception {
        return request(
                "POST",
                "",
                Map.of(
                        "email",
                        email,
                        "password",
                        "test-password",
                        "password_confirmation",
                        "test-password",
                        "confirm_success_url",
                        "https://client.example.test/done"),
                null);
    }

    private HttpResponse<String> login(String email, String password) throws Exception {
        return request("POST", "/sign_in", Map.of("email", email, "password", password), null);
    }

    private HttpResponse<String> follow(String link) throws Exception {
        var uri = URI.create(link);
        return request("GET", uri.getPath().substring(5) + "?" + uri.getRawQuery(), null, null);
    }

    private HttpResponse<String> request(
            String method, String path, Map<String, String> body, String auth) throws Exception {
        var request =
                HttpRequest.newBuilder(
                                URI.create(
                                        "http://localhost:"
                                                + port
                                                + (path.equals("/me") ? "" : "/auth")
                                                + path))
                        .timeout(Duration.ofSeconds(10));
        if (auth != null) request.header("Authorization", auth);
        if (body != null) request.header("Content-Type", "application/json");
        return HttpClient.newHttpClient()
                .send(
                        request.method(
                                        method,
                                        body == null
                                                ? HttpRequest.BodyPublishers.noBody()
                                                : HttpRequest.BodyPublishers.ofString(
                                                        JsonMapper.builder()
                                                                .build()
                                                                .writeValueAsString(body)))
                                .build(),
                        HttpResponse.BodyHandlers.ofString());
    }
}
