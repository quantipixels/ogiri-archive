// SPDX-License-Identifier: Apache-2.0
package example.ogiri;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.quantipixels.ogiri.security.OgiriConfigurer;
import com.quantipixels.ogiri.security.OgiriRuntime;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@SpringBootTest(
        classes = {Application.class, HostChainTest.Host.class},
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
            "spring.datasource.url=${OGIRI_TEST_JDBC_URL}",
            "spring.datasource.username=${OGIRI_TEST_JDBC_USER}",
            "spring.datasource.password=${OGIRI_TEST_JDBC_PASSWORD}",
            "spring.profiles.active=demo"
        })
class HostChainTest {
    @Value("${local.server.port}")
    int port;

    @TestConfiguration(proxyBeanMethods = false)
    static class Host {
        @Bean
        SecurityFilterChain hostChain(HttpSecurity http, OgiriRuntime runtime) throws Exception {
            http.with(OgiriConfigurer.ogiri(runtime), config -> {});
            return http.authorizeHttpRequests(
                            routes ->
                                    routes.requestMatchers("/auth/**")
                                            .permitAll()
                                            .anyRequest()
                                            .authenticated())
                    .build();
        }
    }

    @Test
    void customChainUsesPublicConfigurerAndStaleHeadersDoNotBlockSignIn() throws Exception {
        var request =
                HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/auth/sign_in"))
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .header("Authorization", "Bearer stale")
                        .POST(
                                HttpRequest.BodyPublishers.ofString(
                                        "email=demo%40example.com&password=test-password"))
                        .build();
        var response =
                HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode(), response.body());
    }
}
