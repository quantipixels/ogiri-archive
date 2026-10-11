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
            "spring.profiles.active=demo"
        })
class ConsumerTest {
    @Value("${local.server.port}")
    int port;

    private final HttpClient http = HttpClient.newHttpClient();

    @Test
    void installedArtifactsServeDtaWithOnePooledConnection() throws Exception {
        assertEquals(401, request("GET", "/me", null, null).statusCode());
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
        assertEquals(403, request("GET", "/admin", null, bundle).statusCode());
        assertEquals(200, request("GET", "/auth/validate_token", null, bundle).statusCode());
        var logout = request("DELETE", "/auth/sessions/" + client, null, bundle);
        assertEquals(200, logout.statusCode());
        assertTrue(logout.headers().firstValue("access-token").isEmpty());
        assertEquals(401, request("GET", "/me", null, bundle).statusCode());
        assertEquals(404, request("DELETE", "/auth/sign_out", null, bundle).statusCode());
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
