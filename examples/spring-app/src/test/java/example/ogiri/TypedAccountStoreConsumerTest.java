// SPDX-License-Identifier: Apache-2.0
package example.ogiri;

import static org.junit.jupiter.api.Assertions.*;

import com.quantipixels.ogiri.account.AccountStore;
import com.quantipixels.ogiri.account.OgiriAccount;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import tools.jackson.databind.json.JsonMapper;

@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
            "spring.datasource.url=${OGIRI_TEST_JDBC_URL}",
            "spring.datasource.username=${OGIRI_TEST_JDBC_USER}",
            "spring.datasource.password=${OGIRI_TEST_JDBC_PASSWORD}",
            "spring.datasource.hikari.maximum-pool-size=2",
            "ogiri.bcrypt-cost=4"
        })
@Import(TypedAccountStoreConsumerTest.StoreConfiguration.class)
class TypedAccountStoreConsumerTest {
    @Value("${local.server.port}")
    int port;

    @Autowired JdbcTemplate jdbc;
    private final HttpClient http =
            HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();

    @TestConfiguration
    static class StoreConfiguration {
        @Bean
        AccountStore customAccounts(JdbcTemplate jdbc) {
            return new MinimalStore(jdbc);
        }
    }

    // Application-owned table deliberately has none of the optional Devise columns.
    static class MinimalStore implements AccountStore {
        private final JdbcTemplate jdbc;

        MinimalStore(JdbcTemplate jdbc) {
            this.jdbc = jdbc;
        }

        private Optional<OgiriAccount> select(String sql, String value) {
            return jdbc
                    .query(
                            sql,
                            (row, index) ->
                                    new OgiriAccount(
                                            Map.of(
                                                    "id",
                                                    row.getString("id"),
                                                    "ogiri_generation",
                                                    row.getString("generation"),
                                                    "uid",
                                                    row.getString("email"),
                                                    "email",
                                                    row.getString("email"),
                                                    "encrypted_password",
                                                    row.getString("password_hash")),
                                            List.of()),
                            value)
                    .stream()
                    .findFirst();
        }

        public Optional<OgiriAccount> findById(String id) {
            return select("SELECT * FROM slice4_accounts WHERE id = ?", id);
        }

        public Optional<OgiriAccount> findByEmail(String email) {
            return select("SELECT * FROM slice4_accounts WHERE email = ?", email);
        }

        public Optional<OgiriAccount> findByUid(String uid, String provider) {
            return provider.equals("email") ? findByEmail(uid) : Optional.empty();
        }

        public Optional<OgiriAccount> findByToken(String column, String digest) {
            return Optional.empty();
        }

        public Optional<OgiriAccount> lock(String id) {
            return select("SELECT * FROM slice4_accounts WHERE id = ? FOR UPDATE", id);
        }

        public OgiriAccount create(Map<String, Object> columns) {
            throw new UnsupportedOperationException();
        }

        public OgiriAccount update(String id, Map<String, Object> changes) {
            if (changes.containsKey("encrypted_password"))
                jdbc.update(
                        "UPDATE slice4_accounts SET password_hash = ? WHERE id = ?",
                        changes.get("encrypted_password"),
                        id);
            return findById(id).orElseThrow();
        }

        public void delete(String id) {
            jdbc.update("DELETE FROM slice4_accounts WHERE id = ?", id);
        }
    }

    @Test
    void passwordChangeWorksWithoutOptionalDeviseColumns() throws Exception {
        jdbc.execute(
                "CREATE TABLE slice4_accounts (id VARCHAR(36) PRIMARY KEY, generation VARCHAR(36) NOT NULL, email VARCHAR(255) NOT NULL, password_hash VARCHAR(255) NOT NULL)");
        try {
            jdbc.update(
                    "INSERT INTO slice4_accounts VALUES (?, ?, ?, ?)",
                    "slice4",
                    "incarnation-1",
                    "typed@example.test",
                    new BCryptPasswordEncoder(4).encode("test-password"));
            var signedIn =
                    request(
                            "POST",
                            "/sign_in",
                            Map.of("email", "typed@example.test", "password", "test-password"),
                            null);
            assertEquals(200, signedIn.statusCode(), signedIn.body());
            var changed =
                    request(
                            "PUT",
                            "/password",
                            Map.of(
                                    "password",
                                    "changed-password",
                                    "password_confirmation",
                                    "changed-password"),
                            signedIn);
            assertEquals(200, changed.statusCode(), changed.body());
            assertTrue(
                    new BCryptPasswordEncoder()
                            .matches(
                                    "changed-password",
                                    jdbc.queryForObject(
                                            "SELECT password_hash FROM slice4_accounts WHERE id = ?",
                                            String.class,
                                            "slice4")));
            var oldPassword =
                    request(
                            "POST",
                            "/sign_in",
                            Map.of("email", "typed@example.test", "password", "test-password"),
                            null);
            assertEquals(401, oldPassword.statusCode(), oldPassword.body());
            var newPassword =
                    request(
                            "POST",
                            "/sign_in",
                            Map.of("email", "typed@example.test", "password", "changed-password"),
                            null);
            assertEquals(200, newPassword.statusCode(), newPassword.body());
        } finally {
            jdbc.execute("DROP TABLE slice4_accounts");
        }
    }

    private HttpResponse<String> request(
            String method, String path, Map<String, String> body, HttpResponse<String> auth)
            throws Exception {
        var request =
                HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/auth" + path))
                        .timeout(Duration.ofSeconds(10))
                        .header("Content-Type", "application/json");
        if (auth != null)
            for (String header : List.of("access-token", "client", "uid"))
                request.header(header, auth.headers().firstValue(header).orElseThrow());
        return http.send(
                request.method(
                                method,
                                HttpRequest.BodyPublishers.ofString(
                                        JsonMapper.builder().build().writeValueAsString(body)))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
    }
}
