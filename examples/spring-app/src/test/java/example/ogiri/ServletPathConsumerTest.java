// SPDX-License-Identifier: Apache-2.0
package example.ogiri;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
            "spring.datasource.url=${OGIRI_TEST_JDBC_URL}",
            "spring.datasource.username=${OGIRI_TEST_JDBC_USER}",
            "spring.datasource.password=${OGIRI_TEST_JDBC_PASSWORD}",
            "spring.profiles.active=demo",
            "server.servlet.context-path=/app",
            "spring.mvc.servlet.path=/api",
            "ogiri.base-path=/login"
        })
class ServletPathConsumerTest {
    @Value("${local.server.port}")
    int port;

    @Test
    void prefixedSignInUsesDtaPathAndFormBinding() throws Exception {
        var request =
                HttpRequest.newBuilder(
                                URI.create("http://localhost:" + port + "/app/api/login/sign_in"))
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(
                                HttpRequest.BodyPublishers.ofString(
                                        "email=demo%40example.com&password=test-password"))
                        .build();
        var response =
                HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode(), response.body());
    }
}
