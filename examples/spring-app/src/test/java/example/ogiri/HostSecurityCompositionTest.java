// SPDX-License-Identifier: Apache-2.0
package example.ogiri;

import static org.junit.jupiter.api.Assertions.*;

import com.quantipixels.ogiri.security.OgiriConfigurer;
import com.quantipixels.ogiri.security.OgiriRealms;
import jakarta.servlet.http.HttpServletRequest;
import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootTest(
        classes = {
            Application.class,
            HostSecurityCompositionTest.Host.class,
            HostChainTest.BasicHost.class
        },
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
            "spring.datasource.url=${OGIRI_TEST_JDBC_URL}",
            "spring.datasource.username=${OGIRI_TEST_JDBC_USER}",
            "spring.datasource.password=${OGIRI_TEST_JDBC_PASSWORD}",
            "spring.profiles.active=demo",
            "ogiri.cookie-secure=false"
        })
class HostSecurityCompositionTest {
    @Value("${local.server.port}")
    int port;

    @TestConfiguration(proxyBeanMethods = false)
    @RestController
    static class Host {
        @Bean
        SecurityFilterChain composedChain(
                HttpSecurity http,
                OgiriRealms realms,
                @Value("${host.cors:false}") boolean corsEnabled)
                throws Exception {
            if (corsEnabled) http.cors(Customizer.withDefaults());
            else
                http.cors(
                        org.springframework.security.config.annotation.web.configurers
                                        .AbstractHttpConfigurer
                                ::disable);
            var csrf = new HttpSessionCsrfTokenRepository();
            csrf.setHeaderName("X-HOST-CSRF");
            csrf.setParameterName("host_token");
            http.csrf(
                    config ->
                            config.csrfTokenRepository(csrf)
                                    .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler())
                                    .requireCsrfProtectionMatcher(
                                            request ->
                                                    CsrfFilter.DEFAULT_CSRF_MATCHER.matches(request)
                                                            || request.getServletPath()
                                                                    .equals("/host/strict"))
                                    .ignoringRequestMatchers("/host/ignored"));
            http.sessionManagement(
                    config -> config.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED));
            http.formLogin(Customizer.withDefaults());
            http.httpBasic(Customizer.withDefaults());
            http.with(OgiriConfigurer.ogiri(realms), config -> {});
            return http.authorizeHttpRequests(
                            routes ->
                                    routes.requestMatchers(
                                                    "/auth/**",
                                                    "/host/csrf",
                                                    "/host/ignored",
                                                    "/host/strict",
                                                    "/error")
                                            .permitAll()
                                            .anyRequest()
                                            .authenticated())
                    .build();
        }

        @GetMapping("/host/csrf")
        String csrf(HttpServletRequest request) {
            return ((CsrfToken) request.getAttribute(CsrfToken.class.getName())).getToken();
        }

        @PostMapping({"/host/change", "/host/ignored"})
        String change() {
            return "changed";
        }

        @GetMapping("/host/strict")
        String strict() {
            return "strict";
        }
    }

    protected HttpClient browser() {
        return HttpClient.newBuilder()
                .cookieHandler(new CookieManager(null, CookiePolicy.ACCEPT_ALL))
                .build();
    }

    protected HttpResponse<String> request(
            HttpClient client, String method, String path, String body, Map<String, String> headers)
            throws Exception {
        var request = HttpRequest.newBuilder(URI.create("http://localhost:" + port + path));
        headers.forEach(request::header);
        return client.send(
                request.method(method, HttpRequest.BodyPublishers.ofString(body)).build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private String basic() {
        return "Basic "
                + java.util.Base64.getEncoder()
                        .encodeToString(
                                "host:host-password"
                                        .getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    @Test
    void hostUnsafeRequestsKeepCustomRepositoryAndHandler() throws Exception {
        var client = browser();
        String token = request(client, "GET", "/host/csrf", "", Map.of()).body();
        assertEquals(
                403,
                request(client, "POST", "/host/change", "", Map.of("Authorization", basic()))
                        .statusCode());
        assertEquals(
                403,
                request(
                                client,
                                "POST",
                                "/host/change",
                                "",
                                Map.of("Authorization", basic(), "X-HOST-CSRF", "wrong"))
                        .statusCode());
        assertEquals(
                200,
                request(
                                client,
                                "POST",
                                "/host/change",
                                "",
                                Map.of("Authorization", basic(), "X-HOST-CSRF", token))
                        .statusCode());
    }

    @Test
    void hostCsrfMatcherAndExemptionsSurvive() throws Exception {
        var client = browser();
        assertEquals(403, request(client, "GET", "/host/strict", "", Map.of()).statusCode());
        assertEquals(200, request(client, "POST", "/host/ignored", "", Map.of()).statusCode());
    }

    @Test
    void formLoginKeepsItsSessionAndHostRequestCache() throws Exception {
        var client = browser();
        var challenge = request(client, "GET", "/host", "", Map.of("Accept", "text/html"));
        assertEquals(302, challenge.statusCode(), challenge.body());
        assertTrue(challenge.headers().firstValue("location").orElseThrow().endsWith("/login"));
        String csrf = request(client, "GET", "/host/csrf", "", Map.of()).body();
        assertEquals(
                403,
                request(
                                client,
                                "POST",
                                "/login",
                                "username=host&password=host-password",
                                Map.of("Content-Type", "application/x-www-form-urlencoded"))
                        .statusCode());
        var login =
                request(
                        client,
                        "POST",
                        "/login",
                        "username=host&password=host-password&host_token=" + csrf,
                        Map.of("Content-Type", "application/x-www-form-urlencoded"));
        assertEquals(302, login.statusCode(), login.body());
        assertTrue(login.headers().firstValue("location").orElseThrow().contains("/host"));
        assertEquals(200, request(client, "GET", "/host", "", Map.of()).statusCode());
        assertEquals(403, request(client, "POST", "/host/change", "", Map.of()).statusCode());
    }

    @Test
    void ogiriHeaderRequestsAndFailuresDoNotCreateHostSessions() throws Exception {
        var client = HttpClient.newHttpClient();
        var bootstrap = request(client, "GET", "/auth/sign_in", "", Map.of());
        assertNoSession(bootstrap);
        var headers = new java.util.HashMap<String, String>();
        headers.put("Content-Type", "application/x-www-form-urlencoded");
        bootstrap.headers().allValues("Set-Cookie").stream()
                .filter(cookie -> cookie.startsWith("XSRF-TOKEN="))
                .findFirst()
                .ifPresent(
                        cookie -> {
                            String pair = cookie.split(";", 2)[0];
                            headers.put("Cookie", pair);
                            headers.put("X-XSRF-TOKEN", pair.substring("XSRF-TOKEN=".length()));
                        });
        var login =
                request(
                        client,
                        "POST",
                        "/auth/sign_in",
                        "email=demo%40example.com&password=test-password",
                        headers);
        assertEquals(200, login.statusCode(), login.body());
        assertNoSession(login);
        var credentials = new java.util.HashMap<String, String>();
        for (String name : java.util.List.of("uid", "client", "access-token")) {
            credentials.put(name, login.headers().firstValue(name).orElseThrow());
        }
        var changed = request(client, "POST", "/host/change", "", credentials);
        assertEquals(200, changed.statusCode(), changed.body());
        assertNoSession(changed);
        credentials.put("access-token", "invalid");
        var rejected = request(client, "GET", "/host", "", credentials);
        assertEquals(401, rejected.statusCode(), rejected.body());
        assertNoSession(rejected);
    }

    @Test
    void forgedOgiriHeadersCannotBypassHostCsrfWithAFormLoginSession() throws Exception {
        var client = browser();
        String csrf = request(client, "GET", "/host/csrf", "", Map.of()).body();
        var login =
                request(
                        client,
                        "POST",
                        "/login",
                        "username=host&password=host-password&host_token=" + csrf,
                        Map.of("Content-Type", "application/x-www-form-urlencoded"));
        assertEquals(302, login.statusCode(), login.body());
        assertEquals(200, request(client, "GET", "/host", "", Map.of()).statusCode());
        assertEquals(403, request(client, "POST", "/host/change", "", Map.of()).statusCode());
        for (String token :
                java.util.List.of("invalid", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")) {
            var rejected =
                    request(
                            client,
                            "POST",
                            "/host/change",
                            "",
                            Map.of(
                                    "uid",
                                    "demo@example.com",
                                    "client",
                                    "forged",
                                    "access-token",
                                    token));
            assertEquals(401, rejected.statusCode(), rejected.body());
        }
        String currentCsrf = request(client, "GET", "/host/csrf", "", Map.of()).body();
        assertEquals(
                200,
                request(client, "POST", "/host/change", "", Map.of("X-HOST-CSRF", currentCsrf))
                        .statusCode());
    }

    private void assertNoSession(HttpResponse<String> response) {
        assertTrue(
                response.headers().allValues("Set-Cookie").stream()
                        .noneMatch(cookie -> cookie.startsWith("JSESSIONID=")),
                response.headers().toString());
    }

    @Test
    void hostCorsDisableSurvivesSourceBean() throws Exception {
        var response =
                request(
                        browser(),
                        "OPTIONS",
                        "/host/change",
                        "",
                        Map.of(
                                "Origin",
                                "https://client.example.test",
                                "Access-Control-Request-Method",
                                "POST"));
        assertTrue(
                response.headers().firstValue("Access-Control-Allow-Origin").isEmpty(),
                response.headers().toString());
    }
}
