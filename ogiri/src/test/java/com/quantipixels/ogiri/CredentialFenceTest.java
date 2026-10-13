// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.quantipixels.ogiri.account.OgiriAccount;
import com.quantipixels.ogiri.account.internal.DevisePasswordEncoder;
import com.quantipixels.ogiri.account.internal.JdbcDeviseAccountStore;
import com.quantipixels.ogiri.account.internal.OgiriSettings;
import com.quantipixels.ogiri.account.internal.SignInService;
import com.quantipixels.ogiri.internal.AuthTransactions;
import com.quantipixels.ogiri.internal.DtaFailure;
import com.quantipixels.ogiri.internal.SessionRepository;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;

@Tag("database")
class CredentialFenceTest {
    @org.junit.jupiter.api.BeforeAll
    static void sessionSchema() {
        var source =
                new DriverManagerDataSource(
                        System.getenv("OGIRI_TEST_JDBC_URL"),
                        System.getenv("OGIRI_TEST_JDBC_USER"),
                        System.getenv("OGIRI_TEST_JDBC_PASSWORD"));
        var jdbc = new JdbcTemplate(source);
        jdbc.execute("DROP TABLE IF EXISTS ogiri_sessions");
        jdbc.execute("DROP TABLE IF EXISTS ogiri_subject_locks");
        new ResourceDatabasePopulator(
                        new ClassPathResource(
                                "META-INF/ogiri/ogiri-"
                                        + System.getenv("OGIRI_TEST_DATABASE")
                                        + ".sql"))
                .execute(source);
    }

    @ParameterizedTest
    @ValueSource(strings = {"password", "reset", "delete", "lock", "unconfirmed"})
    void committedTransitionFencesAnAlreadyVerifiedSignin(String transition) throws Exception {
        var source =
                new DriverManagerDataSource(
                        System.getenv("OGIRI_TEST_JDBC_URL"),
                        System.getenv("OGIRI_TEST_JDBC_USER"),
                        System.getenv("OGIRI_TEST_JDBC_PASSWORD"));
        var jdbc = new JdbcTemplate(source);
        jdbc.setQueryTimeout(2);
        jdbc.execute("TRUNCATE ogiri_sessions");
        String engine = System.getenv("OGIRI_TEST_DATABASE");
        String schema =
                new ClassPathResource("META-INF/ogiri/users-" + engine + ".sql")
                        .getContentAsString(java.nio.charset.StandardCharsets.UTF_8)
                        .replace("users", "spring_fence_users");
        jdbc.execute("DROP TABLE IF EXISTS spring_fence_users");
        new ResourceDatabasePopulator(
                        new ByteArrayResource(
                                schema.getBytes(java.nio.charset.StandardCharsets.UTF_8)))
                .execute(source);
        var tx = new AuthTransactions(source);
        var accounts =
                new JdbcDeviseAccountStore(
                        tx, "spring_fence_users", columns -> java.util.List.of());
        var encoder = new DevisePasswordEncoder(4);
        var settings = settings();
        var sessions = new SessionRepository(tx, SessionPolicy.defaults());
        var activation =
                new com.quantipixels.ogiri.account.internal.ActivationService(
                        accounts,
                        tx,
                        sessions,
                        settings,
                        new com.quantipixels.ogiri.internal.MailDispatcher(
                                event -> {},
                                new com.quantipixels.ogiri.mail.OgiriMailer() {
                                    public void resetPassword(String address, String link) {
                                        throw new AssertionError("No recovery mail in fence drill");
                                    }

                                    public void confirmation(String address, String link) {
                                        throw new AssertionError(
                                                "No confirmation mail in fence drill");
                                    }

                                    public void unlock(String address, String link) {
                                        throw new AssertionError(
                                                "No threshold mail in fence drill");
                                    }
                                }),
                        new com.quantipixels.ogiri.internal.PublicLinks(
                                "https://accounts.example.test", "/auth", java.util.List.of()));
        var signIn = new SignInService(accounts, tx, sessions, settings, encoder, activation);
        OgiriAccount account =
                tx.write(
                        () ->
                                accounts.create(
                                        Map.of(
                                                "email",
                                                "fence@example.test",
                                                "uid",
                                                "fence@example.test",
                                                "encrypted_password",
                                                encoder.encode("old-password"),
                                                "confirmed_at",
                                                Instant.now(),
                                                "created_at",
                                                Instant.now(),
                                                "updated_at",
                                                Instant.now())));
        var executor = Executors.newSingleThreadExecutor();
        try {
            var future =
                    tx.write(
                            () -> {
                                tx.lock(signIn.subject(account));
                                assertEquals(
                                        account.id(),
                                        accounts.lock(account.id()).orElseThrow().id());
                                var pending =
                                        executor.submit(
                                                () ->
                                                        signIn.signIn(
                                                                account.email(), "old-password"));
                                // This lock SQL is executed only after bcrypt verification. Our
                                // transaction owns
                                // the admission row, so the observed SQL cannot pass before our
                                // commit.
                                String query =
                                        engine.equals("postgresql")
                                                ? "SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND (query LIKE 'SELECT lock_key FROM ogiri_subject_locks%' OR query LIKE 'INSERT INTO ogiri_subject_locks%')"
                                                : "SELECT count(*) FROM information_schema.PROCESSLIST WHERE DB=DATABASE() AND INFO LIKE 'INSERT INTO ogiri_subject_locks%'";
                                long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);
                                boolean waiting = false;
                                while (System.nanoTime() < deadline) {
                                    if (engine.equals("postgresql"))
                                        jdbc.execute("SELECT pg_stat_clear_snapshot()");
                                    if (jdbc.queryForObject(query, Integer.class) > 0) {
                                        waiting = true;
                                        break;
                                    }
                                    Thread.onSpinWait();
                                }
                                assertTrue(
                                        waiting,
                                        "Signin must be observed waiting on our admission lock after bcrypt");
                                switch (transition) {
                                    case "password", "reset" -> {
                                        var changed = new LinkedHashMap<String, Object>();
                                        changed.put(
                                                "encrypted_password",
                                                encoder.encode("new-password"));
                                        changed.put("reset_password_token", null);
                                        changed.put("reset_password_sent_at", null);
                                        changed.put("allow_password_change", false);
                                        accounts.update(account.id(), changed);
                                    }
                                    case "delete" -> accounts.delete(account.id());
                                    case "lock" ->
                                            accounts.update(
                                                    account.id(),
                                                    Map.of(
                                                            "locked_at",
                                                            Instant.ofEpochMilli(tx.now())));
                                    case "unconfirmed" -> {
                                        var changed = new LinkedHashMap<String, Object>();
                                        changed.put("confirmed_at", null);
                                        accounts.update(account.id(), changed);
                                    }
                                    default -> throw new AssertionError(transition);
                                }
                                return pending;
                            });
            var rejected =
                    assertThrows(
                            java.util.concurrent.ExecutionException.class,
                            () -> future.get(5, TimeUnit.SECONDS));
            var failure = (DtaFailure) rejected.getCause();
            assertEquals(401, failure.status());
            String reason =
                    switch (transition) {
                        case "lock" ->
                                "Your account has been locked due to an excessive number of unsuccessful sign in attempts.";
                        case "unconfirmed" ->
                                "A confirmation email was sent to your account at 'fence@example.test'. You must follow the instructions in the email before your account can be activated";
                        default -> SignInService.INVALID;
                    };
            assertEquals(
                    Map.of("success", false, "errors", java.util.List.of(reason)), failure.body());
            assertTrue(
                    sessions.list(signIn.subject(account)).isEmpty(),
                    "Stale credential verification must never issue a session");
        } finally {
            executor.shutdownNow();
            assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS));
            jdbc.execute("DROP TABLE spring_fence_users");
        }
    }

    private static OgiriSettings settings() throws Exception {
        var defaults = OgiriSettings.defaults();
        var components = OgiriSettings.class.getRecordComponents();
        Object[] values = new Object[components.length];
        Class<?>[] types = new Class<?>[components.length];
        for (int i = 0; i < components.length; i++) {
            types[i] = components[i].getType();
            values[i] = components[i].getAccessor().invoke(defaults);
            if (components[i].getName().equals("confirmable")
                    || components[i].getName().equals("lockable")) values[i] = true;
        }
        return OgiriSettings.class.getDeclaredConstructor(types).newInstance(values);
    }
}
