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
        classes = {Application.class, HostChainTest.Host.class, HostChainTest.BasicHost.class},
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
            http.httpBasic(org.springframework.security.config.Customizer.withDefaults());
            return http.authorizeHttpRequests(
                            routes ->
                                    routes.dispatcherTypeMatchers(
                                                    jakarta.servlet.DispatcherType.ERROR)
                                            .permitAll()
                                            .requestMatchers("/auth/**")
                                            .permitAll()
                                            .anyRequest()
                                            .authenticated())
                    .build();
        }
    }

    @TestConfiguration(proxyBeanMethods = false)
    @org.springframework.web.bind.annotation.RestController
    static class BasicHost {
        @Bean
        org.springframework.security.core.userdetails.UserDetailsService basicUsers() {
            return new org.springframework.security.provisioning.InMemoryUserDetailsManager(
                    org.springframework.security.core.userdetails.User.withUsername("host")
                            .password("{noop}host-password")
                            .roles("HOST")
                            .build());
        }

        @org.springframework.web.bind.annotation.GetMapping("/host")
        public java.util.Map<String, String> host(
                org.springframework.security.core.Authentication authentication) {
            return java.util.Map.of("name", authentication.getName());
        }
    }

    @Test
    void basicIdentitySurvivesAbsentOgiriAndMixedCredentialsAreRejected() throws Exception {
        String basic =
                java.util.Base64.getEncoder()
                        .encodeToString(
                                "host:host-password"
                                        .getBytes(java.nio.charset.StandardCharsets.UTF_8));
        var builder =
                HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/host"))
                        .header("Authorization", "Basic " + basic);
        var client = HttpClient.newHttpClient();
        var response = client.send(builder.GET().build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode(), response.body());
        assertEquals("{\"name\":\"host\"}", response.body());
        response =
                client.send(
                        builder.header("uid", "demo@example.com")
                                .header("access-token", "stale")
                                .GET()
                                .build(),
                        HttpResponse.BodyHandlers.ofString());
        assertEquals(401, response.statusCode(), response.body());
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
