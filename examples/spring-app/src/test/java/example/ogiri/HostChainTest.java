// SPDX-License-Identifier: Apache-2.0
package example.ogiri;

import static org.junit.jupiter.api.Assertions.*;
import com.quantipixels.ogiri.*;
import com.quantipixels.ogiri.spring.*;
import java.net.URI;
import java.net.http.*;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.*;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.*;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.*;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.*;
import org.springframework.security.core.userdetails.*;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.*;

@SpringBootTest(classes = {Application.class, HostChainTest.Host.class}, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "spring.datasource.url=${OGIRI_TEST_JDBC_URL}", "spring.datasource.username=${OGIRI_TEST_JDBC_USER}",
        "spring.datasource.password=${OGIRI_TEST_JDBC_PASSWORD}", "spring.profiles.active=demo",
        "ogiri.endpoints-enabled=false"
})
class HostChainTest {
    @Autowired JdbcSessions sessions;
    @Autowired org.springframework.context.ApplicationContext context;
    @Value("${local.server.port}") int port;
    private static final HttpClient HTTP = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();
    static final AtomicBoolean offline = new AtomicBoolean();

    @TestConfiguration(proxyBeanMethods = false)
    static class Host {
        @Bean OgiriAccounts scopedAccounts() {
            return new OgiriAccounts() {
                public Subject subject(Authentication authentication) { return new Subject("accounts", "tenant", "42"); }
                public UserDetails load(Subject subject) {
                    if (offline.get()) throw new IllegalStateException("private directory failure");
                    if (!subject.equals(new Subject("accounts", "tenant", "42"))) throw new UsernameNotFoundException("foreign");
                    return User.withUsername("mutable-name").password("unused").roles("USER").build();
                }
            };
        }
        @Bean @Order(1) SecurityFilterChain publicChain(HttpSecurity http) throws Exception {
            return http.securityMatcher("/public/**").authorizeHttpRequests(routes -> routes.anyRequest().permitAll()).build();
        }
        @Bean @Order(2) SecurityFilterChain applicationChain(HttpSecurity http, OgiriSecurity ogiri) throws Exception {
            ogiri.configure(http);
            return http.authorizeHttpRequests(routes -> routes.dispatcherTypeMatchers(jakarta.servlet.DispatcherType.ERROR).permitAll()
                    .requestMatchers("/auth/**").denyAll().anyRequest().authenticated()).build();
        }
    }

    @Test void customChainsAndFullIdentityMappingRemainAuthoritative() throws Exception {
        assertEquals(2, context.getBeansOfType(SecurityFilterChain.class).size());
        assertEquals(0, context.getBeansOfType(OgiriEndpoints.class).size());
        var token = sessions.issue(new Subject("accounts", "tenant", "42"), "host").token();
        var request = HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/me"))
                .header("Authorization", "Bearer " + token).GET().build();
        var response = HTTP.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode());
        assertEquals("42", response.body());
        // Host's unrelated public write still requires CSRF.
        var post = HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/public/write"))
                .POST(HttpRequest.BodyPublishers.noBody()).build();
        assertEquals(403, HTTP.send(post, HttpResponse.BodyHandlers.ofString()).statusCode());
        var disabled = HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/auth/sessions"))
                .header("Authorization", "Bearer " + token).GET().build();
        assertEquals(403, HTTP.send(disabled, HttpResponse.BodyHandlers.ofString()).statusCode());
        try {
            offline.set(true);
            var outage = HTTP.send(request, HttpResponse.BodyHandlers.ofString());
            assertEquals(500, outage.statusCode());
            assertFalse(outage.body().contains("private directory failure"));
        } finally { offline.set(false); sessions.revokeAll(new Subject("accounts", "tenant", "42")); }
    }
}
