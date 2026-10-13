// SPDX-License-Identifier: Apache-2.0
package example.ogiri;

import static org.junit.jupiter.api.Assertions.*;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import tools.jackson.databind.json.JsonMapper;

@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
            "spring.datasource.url=${OGIRI_TEST_JDBC_URL}",
                    "spring.datasource.username=${OGIRI_TEST_JDBC_USER}",
            "spring.datasource.password=${OGIRI_TEST_JDBC_PASSWORD}", "spring.profiles.active=demo",
            "spring.datasource.hikari.maximum-pool-size=1",
                    "ogiri.change-headers-on-each-request=true"
        })
class RotationConsumerTest {
    @Value("${local.server.port}")
    int port;

    @Test
    void batchBearerCarriesPresentedTokenAndLogoutSuppressesCredentials() throws Exception {
        var login =
                request(
                        "POST",
                        "/auth/sign_in",
                        null,
                        "{\"email\":\"demo@example.com\",\"password\":\"test-password\"}");
        assertEquals(200, login.statusCode(), login.body());
        var original = login.headers().firstValue("Authorization").orElseThrow();
        var batch = request("GET", "/me", original, null);
        assertEquals(200, batch.statusCode(), batch.body());
        var json = JsonMapper.builder().build();
        var encoded = batch.headers().firstValue("Authorization").orElseThrow().substring(7);
        var full = json.readValue(Base64.getDecoder().decode(encoded), java.util.Map.class);
        assertEquals(
                login.headers().firstValue("access-token").orElseThrow(), full.get("access-token"));
        assertEquals(login.headers().firstValue("expiry").orElseThrow(), full.get("expiry"));
        assertEquals("", batch.headers().firstValue("access-token").orElseThrow());
        var logout = request("DELETE", "/auth/sign_out", original, null);
        assertEquals(200, logout.statusCode(), logout.body());
        assertTrue(logout.headers().firstValue("Authorization").isEmpty());
        assertTrue(logout.headers().firstValue("access-token").isEmpty());
        assertEquals(401, request("GET", "/me", original, null).statusCode());
    }

    HttpResponse<String> request(String method, String path, String auth, String body)
            throws Exception {
        var builder =
                HttpRequest.newBuilder(URI.create("http://localhost:" + port + path))
                        .timeout(Duration.ofSeconds(10));
        if (auth != null) builder.header("Authorization", auth);
        if (body != null) builder.header("Content-Type", "application/json");
        return HttpClient.newHttpClient()
                .send(
                        builder.method(
                                        method,
                                        body == null
                                                ? HttpRequest.BodyPublishers.noBody()
                                                : HttpRequest.BodyPublishers.ofString(body))
                                .build(),
                        HttpResponse.BodyHandlers.ofString());
    }
}
