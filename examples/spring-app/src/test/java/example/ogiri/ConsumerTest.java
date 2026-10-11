// SPDX-License-Identifier: Apache-2.0
package example.ogiri;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import tools.jackson.databind.json.JsonMapper;

@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
            "spring.datasource.url=${OGIRI_TEST_JDBC_URL}",
            "spring.datasource.username=${OGIRI_TEST_JDBC_USER}",
            "spring.datasource.password=${OGIRI_TEST_JDBC_PASSWORD}",
            "spring.datasource.hikari.maximum-pool-size=1",
            "spring.profiles.active=demo",
            "ogiri.account.columns=role"
        })
class ConsumerTest {
    @Value("${local.server.port}")
    int port;

    @org.springframework.beans.factory.annotation.Autowired
    org.springframework.jdbc.core.JdbcTemplate jdbc;

    private final HttpClient http = HttpClient.newHttpClient();

    @Test
    void installedArtifactsServeDtaWithOnePooledConnection() throws Exception {
        assertEquals(401, request("GET", "/me", null, null).statusCode());
        assertEquals(401, request("GET", "/auth/sessions/adopter", null, null).statusCode());
        var login =
                request(
                        "POST",
                        "/auth/sign_in",
                        "{\"email\": \" DEMO@example.com \", \"password\": \"test-password\"}",
                        "Bearer stale");
        assertEquals(200, login.statusCode(), login.body());
        String bundle = login.headers().firstValue("Authorization").orElseThrow();
        String client = login.headers().firstValue("client").orElseThrow();
        assertEquals(43, login.headers().firstValue("access-token").orElseThrow().length());
        assertTrue(login.headers().firstValue("Cache-Control").orElseThrow().contains("no-store"));
        assertFalse(login.body().contains("encrypted_password"));
        assertEquals(200, request("GET", "/me", null, bundle).statusCode());
        assertEquals(
                Map.of("uid", "demo@example.com"),
                JsonMapper.builder()
                        .build()
                        .readValue(request("GET", "/me", null, bundle).body(), Map.class));
        var browser =
                http.send(
                        HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/me"))
                                .header("Authorization", bundle)
                                .header("Origin", "https://client.example.test")
                                .GET()
                                .build(),
                        HttpResponse.BodyHandlers.ofString());
        assertEquals(200, browser.statusCode(), browser.body());
        assertTrue(
                browser.headers()
                        .firstValue("access-control-expose-headers")
                        .orElseThrow()
                        .contains("access-token"));
        assertEquals(403, request("GET", "/admin", null, bundle).statusCode());
        assertEquals(200, request("GET", "/auth/validate_token", null, bundle).statusCode());
        var logout = request("DELETE", "/auth/sessions/" + client, null, bundle);
        assertEquals(200, logout.statusCode());
        assertTrue(logout.headers().firstValue("access-token").isEmpty());
        assertEquals(401, request("GET", "/me", null, bundle).statusCode());
        assertEquals(404, request("DELETE", "/auth/sign_out", null, bundle).statusCode());
    }

    @Test
    void registrationValidatesPermittedFieldsAndDestroysEveryClient() throws Exception {
        String email = "new-" + java.util.UUID.randomUUID() + "@example.com";
        String data =
                "{\"email\":\""
                        + email
                        + "\",\"password\":\"test-password\",\"password_confirmation\":\"test-password\",\"role\":\"admin\",\"uid\":\"forged\"}";
        var created = request("POST", "/auth", data, "Bearer stale");
        assertEquals(200, created.statusCode(), created.body());
        assertFalse(created.body().contains("encrypted_password"));
        var view = JsonMapper.builder().build().readTree(created.body()).get("data");
        assertEquals(email, view.get("uid").asText());
        assertEquals("user", view.get("role").asText());
        var duplicate = request("POST", "/auth", data, null);
        assertEquals(422, duplicate.statusCode(), duplicate.body());
        assertTrue(duplicate.body().contains("has already been taken"));
        String auth = created.headers().firstValue("Authorization").orElseThrow();
        var updated =
                request(
                        "PATCH",
                        "/auth",
                        "{\"name\":\"Changed\",\"current_password\":\"wrong\",\"role\":\"admin\"}",
                        auth);
        assertEquals(200, updated.statusCode(), updated.body());
        assertEquals(404, request("DELETE", "/auth", null, null).statusCode());
        assertEquals(200, request("DELETE", "/auth", null, auth).statusCode());
        assertEquals(401, request("GET", "/me", null, auth).statusCode());
        var invalid = request("POST", "/auth", "{\"email\":\"bad\",\"password\":\"short\"}", null);
        assertEquals(422, invalid.statusCode(), invalid.body());
        assertTrue(invalid.body().contains("is not an email"));
        assertEquals(422, request("POST", "/auth", "{\"role\":\"admin\"}", null).statusCode());
    }

    @Test
    void additionalAccountSecretsNeverEnterWireViewsAndInputErrorsUseDtaBodies() throws Exception {
        for (String column : java.util.List.of("otp_secret", "password_digest", "is_admin"))
            jdbc.execute("ALTER TABLE users ADD COLUMN " + column + " VARCHAR(40)");
        try {
            jdbc.update(
                    "UPDATE users SET otp_secret = ?, password_digest = ?, is_admin = ?",
                    "secret-otp",
                    "secret-password",
                    "true");
            var login =
                    request(
                            "POST",
                            "/auth/sign_in",
                            "{\"email\":\"demo@example.com\",\"password\":\"test-password\"}",
                            null);
            assertEquals(200, login.statusCode(), login.body());
            String auth = login.headers().firstValue("Authorization").orElseThrow();
            for (var response :
                    java.util.List.of(login, request("GET", "/auth/validate_token", null, auth))) {
                for (String forbidden :
                        java.util.List.of(
                                "otp_secret",
                                "password_digest",
                                "is_admin",
                                "secret-otp",
                                "secret-password"))
                    assertFalse(response.body().contains(forbidden), response.body());
                assertTrue(response.body().contains("role"));
            }
            var malformed = request("POST", "/auth/sign_in", "{", null);
            assertEquals(400, malformed.statusCode(), malformed.body());
            assertTrue(malformed.body().contains("\"success\":false"));
            var missing = request("POST", "/auth/sign_in", "{}", null);
            assertEquals(401, missing.statusCode(), missing.body());
            var unsupported = request("POST", "/auth/sign_in", null, null);
            assertEquals(415, unsupported.statusCode(), unsupported.body());
            assertTrue(unsupported.body().contains("\"success\":false"));
        } finally {
            for (String column : java.util.List.of("otp_secret", "password_digest", "is_admin"))
                jdbc.execute("ALTER TABLE users DROP COLUMN " + column);
        }
    }

    HttpResponse<String> request(String method, String path, String body, String auth)
            throws Exception {
        var request = HttpRequest.newBuilder(URI.create("http://localhost:" + port + path));
        if (auth != null) {
            request.header("Authorization", auth);
        }
        if (body != null) {
            request.header("Content-Type", "application/json");
        }
        return http.send(
                request.method(
                                method,
                                body == null
                                        ? HttpRequest.BodyPublishers.noBody()
                                        : HttpRequest.BodyPublishers.ofString(body))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
    }
}
