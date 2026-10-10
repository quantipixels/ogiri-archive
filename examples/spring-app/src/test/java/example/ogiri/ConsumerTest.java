// SPDX-License-Identifier: Apache-2.0
package example.ogiri;

import static org.junit.jupiter.api.Assertions.*;
import com.quantipixels.ogiri.*;
import java.net.URI;
import java.net.http.*;
import java.time.Duration;
import java.util.UUID;
import javax.sql.DataSource;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "spring.datasource.url=${OGIRI_TEST_JDBC_URL}",
        "spring.datasource.username=${OGIRI_TEST_JDBC_USER}",
        "spring.datasource.password=${OGIRI_TEST_JDBC_PASSWORD}",
        "spring.datasource.hikari.maximum-pool-size=1",
        "spring.profiles.active=demo"
})
class ConsumerTest {
    @Value("${local.server.port}") private int port;
    @Autowired private JdbcSessions sessions;
    @Autowired private DataSource dataSource;
    private static final HttpClient HTTP = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();

    @BeforeEach void emptyDatabase() throws Exception {
        try (var connection = dataSource.getConnection(); var statement = connection.createStatement()) { statement.execute("TRUNCATE ogiri_sessions"); }
    }

    @Test void installedArtifactsServeTheFullSessionLifecycleThroughTheNativeSecurityChain() throws Exception {
        assertEquals(401, request("GET", "/me", null, null).statusCode());
        var login = login("test-password");
        assertEquals(201, login.statusCode());
        assertTrue(login.headers().firstValue("Cache-Control").orElse("").contains("no-store"));
        String bearer = login.headers().firstValue("Authorization").orElseThrow();
        assertFalse(login.body().contains(bearer.substring(7)), "Response JSON must not contain the credential");
        UUID id = sessions.list(new Subject("users", "", "demo@example.com")).get(0).id();
        assertEquals(200, request("GET", "/me", null, bearer).statusCode());
        assertEquals(200, request("GET", "/auth/sessions", null, bearer).statusCode());
        assertEquals(403, request("GET", "/admin", null, bearer).statusCode());
        var foreign = sessions.issue(new Subject("users", "another-tenant", "demo@example.com"), "foreign");
        assertEquals(404, request("DELETE", "/auth/sessions/" + foreign.session().id(), null, bearer).statusCode());
        assertTrue(sessions.authenticate(foreign.token()).isPresent());
        assertEquals(204, request("DELETE", "/auth/sessions/" + id, null, bearer).statusCode());
        assertEquals(401, request("GET", "/me", null, bearer).statusCode());
    }

    @Test void invalidLoginSimpleCrossSitePostsAndAmbiguousBearerTransportAreRejected() throws Exception {
        assertEquals(401, login("wrong-password").statusCode());
        assertEquals(403, request("POST", "/auth/sign-in", "text/plain", null).statusCode());
        assertEquals(403, request("POST", "/auth/sign-in", "application/json", null).statusCode());
        var invalid = request("GET", "/me", null, "Bearer og1_" + "A".repeat(43));
        assertEquals(401, invalid.statusCode());
        var issued = sessions.issue(new Subject("users", "", "demo@example.com"), "phone");
        assertEquals(401, request("GET", "/me?access_token=" + issued.token(), null, null).statusCode());
        var duplicate = HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/me"))
                .header("Authorization", "Bearer " + issued.token()).header("Authorization", "Bearer " + issued.token()).GET().build();
        assertEquals(400, HTTP.send(duplicate, HttpResponse.BodyHandlers.ofString()).statusCode());
        assertEquals(1, sessions.list(new Subject("users", "", "demo@example.com")).size());
    }

    @Test void signOutAndRevokeAllUseOnlyTheAuthenticatedOwner() throws Exception {
        var owner = new Subject("users", "", "demo@example.com");
        var first = sessions.issue(owner, "one");
        var second = sessions.issue(owner, "two");
        assertEquals(204, request("DELETE", "/auth/sign-out", null, "Bearer " + first.token()).statusCode());
        assertTrue(sessions.authenticate(first.token()).isEmpty());
        assertTrue(sessions.authenticate(second.token()).isPresent());
        assertEquals(204, request("DELETE", "/auth/sessions", null, "Bearer " + second.token()).statusCode());
        assertTrue(sessions.list(owner).isEmpty());
    }

    private HttpResponse<String> login(String password) throws Exception { return login("demo@example.com", password); }

    private HttpResponse<String> login(String username, String password) throws Exception {
        var request = HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/auth/sign-in"))
                .timeout(Duration.ofSeconds(10)).header("Content-Type", "application/json")
                .header("X-Requested-With", "Ogiri")
                .POST(HttpRequest.BodyPublishers.ofString("{\"username\":\"" + username + "\",\"password\":\"" + password + "\",\"client\":\"browser\"}")).build();
        return HTTP.send(request, HttpResponse.BodyHandlers.ofString());
    }
    private HttpResponse<String> request(String method, String path, String contentType, String bearer) throws Exception {
        var request = HttpRequest.newBuilder(URI.create("http://localhost:" + port + path)).timeout(Duration.ofSeconds(10));
        if (contentType != null) request.header("Content-Type", contentType);
        if (bearer != null) request.header("Authorization", bearer);
        request.method(method, contentType == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString("{}"));
        return HTTP.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }
}
