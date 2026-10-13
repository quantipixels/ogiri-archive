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
            "ogiri.endpoints.enabled=false"
        })
class DisabledEndpointsTest {
    @Value("${local.server.port}")
    int port;

    @Test
    void disabledEndpointsDoNotMakeAdopterRoutesPublic() throws Exception {
        for (String path : java.util.List.of("/auth/sign_in", "/auth/sessions/adopter")) {
            var response =
                    HttpClient.newHttpClient()
                            .send(
                                    HttpRequest.newBuilder(
                                                    URI.create("http://localhost:" + port + path))
                                            .GET()
                                            .build(),
                                    HttpResponse.BodyHandlers.ofString());
            assertEquals(401, response.statusCode(), response.body());
        }
    }
}
