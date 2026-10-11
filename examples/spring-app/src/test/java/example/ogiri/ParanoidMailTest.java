// SPDX-License-Identifier: Apache-2.0
package example.ogiri;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

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
            "ogiri.paranoid=true"
        })
@Import(PasswordMailTest.MailConfiguration.class)
class ParanoidMailTest {
    @Value("${local.server.port}")
    int port;

    @Autowired PasswordMailTest.RecordingMail mail;
    @Autowired JdbcTemplate jdbc;

    @Test
    void failedDeliveryAndUnknownEmailHaveTheSameParanoidBody() throws Exception {
        String email = "paranoid-" + java.util.UUID.randomUUID() + "@example.com";
        assertEquals(
                200,
                post(
                                "",
                                Map.of(
                                        "email",
                                        email,
                                        "password",
                                        "test-password",
                                        "password_confirmation",
                                        "test-password"))
                        .statusCode());
        mail.fail = true;
        try {
            var known =
                    post(
                            "/password",
                            Map.of(
                                    "email",
                                    email,
                                    "redirect_url",
                                    "https://client.example.test/reset"));
            var unknown =
                    post(
                            "/password",
                            Map.of(
                                    "email",
                                    "unknown-" + email,
                                    "redirect_url",
                                    "https://client.example.test/reset"));
            assertEquals(200, known.statusCode(), known.body());
            assertEquals(known.statusCode(), unknown.statusCode());
            assertEquals(known.body(), unknown.body());
            assertNotNull(
                    jdbc.queryForObject(
                            "SELECT reset_password_token FROM users WHERE email = ?",
                            String.class,
                            email));
        } finally {
            mail.fail = false;
        }
    }

    private HttpResponse<String> post(String path, Map<String, String> data) throws Exception {
        return HttpClient.newHttpClient()
                .send(
                        HttpRequest.newBuilder(
                                        URI.create("http://localhost:" + port + "/auth" + path))
                                .timeout(Duration.ofSeconds(10))
                                .header("Content-Type", "application/json")
                                .POST(
                                        HttpRequest.BodyPublishers.ofString(
                                                JsonMapper.builder()
                                                        .build()
                                                        .writeValueAsString(data)))
                                .build(),
                        HttpResponse.BodyHandlers.ofString());
    }
}
