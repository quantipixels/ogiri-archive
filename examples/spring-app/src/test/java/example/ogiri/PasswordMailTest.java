// SPDX-License-Identifier: Apache-2.0
package example.ogiri;

import static org.junit.jupiter.api.Assertions.*;

import com.quantipixels.ogiri.mail.OgiriMailer;
import java.net.URI;
import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import tools.jackson.databind.json.JsonMapper;

@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
            "spring.datasource.url=${OGIRI_TEST_JDBC_URL}",
            "spring.datasource.username=${OGIRI_TEST_JDBC_USER}",
            "spring.datasource.password=${OGIRI_TEST_JDBC_PASSWORD}",
            "spring.datasource.hikari.maximum-pool-size=1",
            "spring.profiles.active=demo",
            "server.servlet.context-path=/app",
            "spring.mvc.servlet.path=/api",
            "ogiri.base-path=/login",
            "ogiri.public-base-url=https://accounts.example.test"
        })
@Import(PasswordMailTest.MailConfiguration.class)
class PasswordMailTest {
    @Value("${local.server.port}")
    int port;

    @Autowired RecordingMail mail;
    @Autowired JdbcTemplate jdbc;
    private final HttpClient http =
            HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();

    @TestConfiguration
    static class MailConfiguration {
        @Bean
        RecordingMail recordingMail() {
            return new RecordingMail();
        }
    }

    static class RecordingMail implements OgiriMailer {
        volatile String link;
        volatile boolean fail;

        public void resetPassword(String recipient, String value) {
            send(recipient, value, "reset_password_token");
        }

        public void confirmation(String recipient, String value) {
            send(recipient, value, "confirmation_token");
        }

        public void unlock(String recipient, String value) {
            send(recipient, value, "unlock_token");
        }

        private void send(String recipient, String value, String column) {
            var outside =
                    new JdbcTemplate(
                            new DriverManagerDataSource(
                                    System.getenv("OGIRI_TEST_JDBC_URL"),
                                    System.getenv("OGIRI_TEST_JDBC_USER"),
                                    System.getenv("OGIRI_TEST_JDBC_PASSWORD")));
            String stored =
                    outside.queryForObject(
                            "SELECT "
                                    + column
                                    + " FROM users WHERE (email = ? OR unconfirmed_email = ?)",
                            String.class,
                            recipient,
                            recipient);
            assertEquals(
                    java.util.HexFormat.of().formatHex(securityDigest(query(value).get(column))),
                    stored);
            link = value;
            if (fail) throw new IllegalStateException("injected delivery failure");
        }
    }

    // A separate connection above proves the reset digest committed before the mail callback.
    private static byte[] securityDigest(String value) {
        try {
            return java.security.MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.US_ASCII));
        } catch (java.security.NoSuchAlgorithmException impossible) {
            throw new AssertionError(impossible);
        }
    }

    @Test
    void recoveryUsesTrustedMountedLinksAndConsumesTheResetWindow() throws Exception {
        String email = create();
        String body =
                JsonMapper.builder()
                        .build()
                        .writeValueAsString(
                                Map.of(
                                        "email",
                                        email,
                                        "redirect_url",
                                        "https://client.example.test/reset"));
        try (var socket = new java.net.Socket("127.0.0.1", port)) {
            socket.setSoTimeout(5000);
            var bytes = body.getBytes(StandardCharsets.UTF_8);
            socket.getOutputStream()
                    .write(
                            ("POST /app/api/login/password HTTP/1.1\r\nHost: evil.test\r\nContent-Type: application/json\r\nContent-Length: "
                                            + bytes.length
                                            + "\r\nConnection: close\r\n\r\n")
                                    .getBytes(StandardCharsets.US_ASCII));
            socket.getOutputStream().write(bytes);
            assertTrue(
                    new String(socket.getInputStream().readAllBytes(), StandardCharsets.UTF_8)
                            .startsWith("HTTP/1.1 200"));
        }
        URI link = URI.create(mail.link);
        assertEquals("accounts.example.test", link.getHost());
        assertEquals("/app/api/login/password/edit", link.getPath());
        String token = query(mail.link).get("reset_password_token");
        String stored =
                jdbc.queryForObject(
                        "SELECT reset_password_token FROM users WHERE email = ?",
                        String.class,
                        email);
        assertEquals(64, stored.length());
        assertNotEquals(token, stored);
        var followed = request("GET", "/password/edit?" + link.getRawQuery(), null, null);
        assertEquals(302, followed.statusCode(), followed.body());
        var auth = query(followed.headers().firstValue("Location").orElseThrow());
        String bundle =
                "Bearer "
                        + java.util.Base64.getEncoder()
                                .encodeToString(
                                        JsonMapper.builder()
                                                .build()
                                                .writeValueAsBytes(
                                                        Map.of(
                                                                "access-token",
                                                                auth.get("access-token"),
                                                                "client",
                                                                auth.get("client"),
                                                                "uid",
                                                                auth.get("uid"))));
        var changed =
                request(
                        "PUT",
                        "/password",
                        Map.of(
                                "password",
                                "changed-password",
                                "password_confirmation",
                                "changed-password"),
                        bundle);
        assertEquals(200, changed.statusCode(), changed.body());
        assertNull(
                jdbc.queryForObject(
                        "SELECT reset_password_token FROM users WHERE email = ?",
                        String.class,
                        email));
        assertEquals(
                404,
                request("GET", "/password/edit?" + link.getRawQuery(), null, null).statusCode());
    }

    @Test
    void deliveryFailureReturns503AfterCommitAndRetryReplacesTheToken() throws Exception {
        String email = create();
        mail.fail = true;
        try {
            var result =
                    request(
                            "POST",
                            "/password",
                            Map.of(
                                    "email",
                                    email,
                                    "redirect_url",
                                    "https://client.example.test/reset"),
                            null);
            assertEquals(503, result.statusCode(), result.body());
            assertTrue(result.body().contains("Authentication service unavailable."));
            String first =
                    jdbc.queryForObject(
                            "SELECT reset_password_token FROM users WHERE email = ?",
                            String.class,
                            email);
            mail.fail = false;
            assertEquals(
                    200,
                    request(
                                    "POST",
                                    "/password",
                                    Map.of(
                                            "email",
                                            email,
                                            "redirect_url",
                                            "https://client.example.test/reset"),
                                    null)
                            .statusCode());
            assertNotEquals(
                    first,
                    jdbc.queryForObject(
                            "SELECT reset_password_token FROM users WHERE email = ?",
                            String.class,
                            email));
        } finally {
            mail.fail = false;
        }
    }

    String create() throws Exception {
        String email = "mail-" + java.util.UUID.randomUUID() + "@example.com";
        var created =
                request(
                        "POST",
                        "",
                        Map.of(
                                "email",
                                email,
                                "password",
                                "test-password",
                                "password_confirmation",
                                "test-password"),
                        null);
        assertEquals(200, created.statusCode(), created.body());
        return email;
    }

    HttpResponse<String> request(String method, String path, Map<String, String> body, String auth)
            throws Exception {
        var request =
                HttpRequest.newBuilder(
                                URI.create("http://localhost:" + port + "/app/api/login" + path))
                        .timeout(Duration.ofSeconds(10));
        if (auth != null) request.header("Authorization", auth);
        if (body != null) request.header("Content-Type", "application/json");
        return http.send(
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

    static Map<String, String> query(String link) {
        return java.util.Arrays.stream(URI.create(link).getRawQuery().split("&"))
                .map(pair -> pair.split("=", 2))
                .collect(
                        java.util.stream.Collectors.toMap(
                                pair -> URLDecoder.decode(pair[0], StandardCharsets.UTF_8),
                                pair -> URLDecoder.decode(pair[1], StandardCharsets.UTF_8)));
    }
}
