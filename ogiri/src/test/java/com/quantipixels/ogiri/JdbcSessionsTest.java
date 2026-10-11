// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri;

import static org.junit.jupiter.api.Assertions.*;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.SQLException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.*;
import org.junit.jupiter.api.*;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.datasource.DelegatingDataSource;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;

@org.junit.jupiter.api.Tag("database")
class JdbcSessionsTest {
    private static DriverManagerDataSource dataSource;
    private static final Subject OWNER = new Subject("users", "tenant-a", "user-42");
    private JdbcSessions sessions;

    @BeforeAll
    static void database() throws Exception {
        dataSource = source();
        sql("DROP TABLE IF EXISTS ogiri_sessions");
        sql("DROP TABLE IF EXISTS ogiri_subject_locks");
        String vendor = System.getenv("OGIRI_TEST_DATABASE");
        if (!java.util.Set.of("postgresql", "mysql").contains(vendor))
            throw new IllegalArgumentException("Set OGIRI_TEST_DATABASE");
        new ResourceDatabasePopulator(
                        new ClassPathResource("META-INF/ogiri/schema-" + vendor + ".sql"))
                .execute(dataSource);
    }

    private static DriverManagerDataSource source() {
        return new DriverManagerDataSource(
                java.util.Objects.requireNonNull(
                        System.getenv("OGIRI_TEST_JDBC_URL"), "Disposable database required"),
                System.getenv("OGIRI_TEST_JDBC_USER"),
                System.getenv("OGIRI_TEST_JDBC_PASSWORD"));
    }

    @BeforeEach
    void reset() throws Exception {
        sql("TRUNCATE ogiri_sessions");
        sessions = new JdbcSessions(dataSource);
    }

    @Test
    void issuanceRoundTripsWithoutPersistingOrPrintingTheCredential() throws Exception {
        var issued = sessions.issue(OWNER, "phone");
        assertEquals(43, issued.token().length());
        assertEquals(issued.session(), sessions.authenticate(issued.token()).orElseThrow());
        assertTrue(sessions.authenticate(issued.session().id().toString()).isEmpty());
        assertFalse(issued.toString().contains(issued.token()));
        assertFalse(issued.session().toString().contains(issued.token()));
        try (var connection = dataSource.getConnection();
                var statement = connection.createStatement();
                var rows =
                        statement.executeQuery(
                                "SELECT token_hash, octet_length(token_hash), expires_at - created_at FROM ogiri_sessions")) {
            assertTrue(rows.next());
            assertEquals(32, rows.getInt(2));
            assertArrayEquals(
                    java.security.MessageDigest.getInstance("SHA-256")
                            .digest(issued.token().getBytes(StandardCharsets.US_ASCII)),
                    rows.getBytes(1));
        }
        assertEquals(
                Duration.ofDays(14),
                Duration.between(issued.session().createdAt(), issued.session().expiresAt()));
    }

    @Test
    void malformedAndNonCanonicalCredentialsNeverBecomeDatabaseLookups() {
        var unavailable = new java.util.concurrent.atomic.AtomicBoolean(false);
        var faultable =
                new DelegatingDataSource(dataSource) {
                    @Override
                    public Connection getConnection() throws SQLException {
                        if (unavailable.get())
                            throw new SQLException("controlled unavailable store");
                        return super.getConnection();
                    }
                };
        var offline = new JdbcSessions(faultable);
        unavailable.set(true);
        for (String token :
                new String[] {
                    "",
                    "not-a-token",
                    "" + "A".repeat(42),
                    "" + "A".repeat(44),
                    "" + "A".repeat(42) + "B",
                    "" + "!".repeat(43),
                    "Bearer " + "A".repeat(43),
                    "x".repeat(100_000)
                }) {
            assertTrue(
                    offline.authenticate(token).isEmpty(),
                    "Malformed credential must fail before I/O");
        }
        assertTrue(offline.authenticate(null).isEmpty());
        assertThrows(SessionStoreException.class, () -> offline.authenticate("" + "A".repeat(43)));
    }

    @Test
    void authenticationDoesNotWriteOrSlideExpiryAndExpiredRowsCannotAuthenticate()
            throws Exception {
        var issued = sessions.issue(OWNER, "browser");
        String before = scalar("SELECT expires_at FROM ogiri_sessions");
        var readOnly =
                new DelegatingDataSource(dataSource) {
                    @Override
                    public Connection getConnection() throws SQLException {
                        Connection actual = super.getConnection();
                        return (Connection)
                                Proxy.newProxyInstance(
                                        Connection.class.getClassLoader(),
                                        new Class<?>[] {Connection.class},
                                        (proxy, method, args) -> {
                                            if (method.getName().equals("prepareStatement")
                                                    && !((String) args[0])
                                                            .stripLeading()
                                                            .startsWith("SELECT"))
                                                throw new AssertionError(
                                                        "Authentication attempted a non-read statement");
                                            try {
                                                return method.invoke(actual, args);
                                            } catch (InvocationTargetException failure) {
                                                throw failure.getCause();
                                            }
                                        });
                    }
                };
        var reader = new JdbcSessions(readOnly);
        for (int i = 0; i < 5; i++)
            assertEquals(issued.session(), reader.authenticate(issued.token()).orElseThrow());
        assertEquals(
                before,
                scalar("SELECT expires_at FROM ogiri_sessions"),
                "Read authentication must not create new row versions");
        sql("UPDATE ogiri_sessions SET created_at = 1, expires_at = 2");
        assertTrue(sessions.authenticate(issued.token()).isEmpty());
        assertTrue(sessions.list(OWNER).isEmpty());
    }

    @Test
    void managementUsesEveryIdentityComponentAndNeverTrustsTheSessionIdAlone() {
        var a = sessions.issue(OWNER, "a");
        for (Subject foreign :
                List.of(
                        new Subject("admins", "tenant-a", "user-42"),
                        new Subject("users", "tenant-b", "user-42"),
                        new Subject("users", "Tenant-a", "user-42"),
                        new Subject("users", "tenant-a", "USER-42"),
                        new Subject("users", "tenant-a ", "user-42"),
                        new Subject("users", "tenant-a", "other"),
                        new Subject("users", "", "user-42"))) {
            var b = sessions.issue(foreign, "b");
            assertEquals(List.of(b.session()), sessions.list(foreign));
            assertFalse(sessions.revoke(foreign, a.session().id()));
            assertEquals(1, sessions.revokeAll(foreign));
            assertTrue(sessions.authenticate(a.token()).isPresent());
        }
        var unusual = new Subject("users", "tenant:a", "x' OR '1'='1");
        var c = sessions.issue(unusual, "device");
        assertEquals(List.of(c.session()), sessions.list(unusual));
        assertEquals(List.of(a.session()), sessions.list(OWNER));
    }

    @Test
    void revocationIsImmediateIdempotentAndDoesNotBanFutureSignIns() {
        var first = sessions.issue(OWNER, "phone");
        var second = sessions.issue(OWNER, "laptop");
        assertTrue(sessions.revoke(OWNER, first.session().id()));
        assertFalse(sessions.revoke(OWNER, first.session().id()));
        assertTrue(sessions.authenticate(first.token()).isEmpty());
        assertTrue(sessions.authenticate(second.token()).isPresent());
        assertEquals(1, sessions.revokeAll(OWNER));
        assertEquals(0, sessions.revokeAll(OWNER));
        assertTrue(sessions.authenticate(second.token()).isEmpty());
        assertTrue(sessions.authenticate(sessions.issue(OWNER, "new login").token()).isPresent());
    }

    @Test
    void admissionEvictsEarliestExpiryAndRevocationFreesCapacity() {
        var limited = new JdbcSessions(dataSource, new SessionPolicy(Duration.ofHours(1), 1));
        var first = limited.issue(OWNER, "phone");
        var second = limited.issue(OWNER, "laptop");
        assertTrue(limited.authenticate(first.token()).isEmpty());
        assertEquals(List.of(second.session()), limited.list(OWNER));
        limited.revoke(OWNER, second.session().id());
        assertTrue(limited.authenticate(limited.issue(OWNER, "laptop").token()).isPresent());
    }

    @Test
    void concurrentFirstSignInsCannotExceedTheAccountLimit() throws Exception {
        ExecutorService workers = Executors.newFixedThreadPool(8);
        try {
            for (int round = 0; round < 4; round++) {
                var subject = new Subject("race", "", "account-" + round);
                var start = new CyclicBarrier(8);
                List<Future<Boolean>> results = new ArrayList<>();
                for (int i = 0; i < 8; i++) {
                    results.add(
                            workers.submit(
                                    () -> {
                                        start.await(5, TimeUnit.SECONDS);
                                        try {
                                            new JdbcSessions(
                                                            dataSource,
                                                            new SessionPolicy(
                                                                    Duration.ofHours(1), 2))
                                                    .issue(subject, Tokens.client());
                                            return true;
                                        } catch (SessionLimitException expected) {
                                            return false;
                                        }
                                    }));
                }
                int accepted = 0;
                for (var result : results) if (result.get(15, TimeUnit.SECONDS)) accepted++;
                assertEquals(8, accepted);
                assertEquals(2, sessions.list(subject).size());
            }
        } finally {
            workers.shutdownNow();
            assertTrue(workers.awaitTermination(10, TimeUnit.SECONDS));
        }
    }

    @Test
    void cleanupIsBoundedSkipsLockedRowsAndPreservesLiveSessions() throws Exception {
        for (int i = 0; i < 4; i++) sessions.issue(OWNER, Tokens.client());
        var live = sessions.issue(OWNER, "live");
        sql("UPDATE ogiri_sessions SET created_at = 1, expires_at = 2 WHERE client <> 'live'");
        try (Connection blocker = dataSource.getConnection()) {
            blocker.setAutoCommit(false);
            try (var statement = blocker.createStatement();
                    var rows =
                            statement.executeQuery(
                                    "SELECT id FROM ogiri_sessions WHERE expires_at = 2 ORDER BY expires_at, id LIMIT 1 FOR UPDATE")) {
                assertTrue(rows.next());
                UUID locked = UUID.fromString(rows.getString(1));
                assertEquals(2, sessions.cleanup(2));
                assertEquals(3, Integer.parseInt(scalar("SELECT count(*) FROM ogiri_sessions")));
                assertEquals(1, sessions.cleanup(10));
                assertEquals(
                        1,
                        Integer.parseInt(
                                scalar(
                                        "SELECT count(*) FROM ogiri_sessions WHERE id = '"
                                                + locked
                                                + "'")));
            }
            blocker.rollback();
        }
        assertEquals(1, sessions.cleanup(10));
        assertEquals(0, sessions.cleanup(10));
        assertEquals(List.of(live.session()), sessions.list(OWNER));
        assertTrue(sessions.authenticate(live.token()).isPresent());
    }

    @Test
    void failedCommitRollsBackAndNeverReturnsACredential() {
        DelegatingDataSource failing =
                new DelegatingDataSource(dataSource) {
                    @Override
                    public Connection getConnection() throws SQLException {
                        Connection actual = dataSource.getConnection();
                        return (Connection)
                                Proxy.newProxyInstance(
                                        Connection.class.getClassLoader(),
                                        new Class<?>[] {Connection.class},
                                        (proxy, method, args) -> {
                                            if (method.getName().equals("commit"))
                                                throw new SQLException(
                                                        "simulated pre-commit failure");
                                            try {
                                                return method.invoke(actual, args);
                                            } catch (InvocationTargetException failure) {
                                                throw failure.getCause();
                                            }
                                        });
                    }
                };
        assertThrows(
                SessionStoreException.class, () -> new JdbcSessions(failing).issue(OWNER, "phone"));
        assertTrue(sessions.list(OWNER).isEmpty());
        assertTrue(sessions.authenticate(sessions.issue(OWNER, "retry").token()).isPresent());
    }

    @Test
    void springTransactionsDoNotUndoCommittedSessionChanges() {
        var outer =
                new org.springframework.transaction.support.TransactionTemplate(
                        new org.springframework.jdbc.support.JdbcTransactionManager(dataSource));
        outer.setIsolationLevel(
                org.springframework.transaction.TransactionDefinition.ISOLATION_REPEATABLE_READ);
        var jdbc = new org.springframework.jdbc.core.JdbcTemplate(dataSource);
        var issued =
                outer.execute(
                        status -> {
                            jdbc.queryForObject(
                                    "SELECT count(*) FROM ogiri_sessions", Integer.class);
                            var fresh = sessions.issue(OWNER, "committed independently");
                            assertTrue(sessions.authenticate(fresh.token()).isPresent());
                            assertTrue(sessions.revoke(OWNER, fresh.session().id()));
                            assertTrue(sessions.authenticate(fresh.token()).isEmpty());
                            var survivor = sessions.issue(OWNER, "survives outer rollback");
                            status.setRollbackOnly();
                            return survivor;
                        });
        assertTrue(sessions.authenticate(issued.token()).isPresent());
        assertEquals(List.of(issued.session()), sessions.list(OWNER));
    }

    @Test
    void invalidResourceBoundsAreRejected() {
        assertThrows(IllegalArgumentException.class, () -> new SessionPolicy(Duration.ZERO, 1));
        assertThrows(
                IllegalArgumentException.class, () -> new SessionPolicy(Duration.ofDays(366), 1));
        assertThrows(
                IllegalArgumentException.class, () -> new SessionPolicy(Duration.ofDays(1), 0));
        assertThrows(IllegalArgumentException.class, () -> sessions.cleanup(10_001));
        assertThrows(IllegalArgumentException.class, () -> sessions.issue(OWNER, ""));
        assertThrows(IllegalArgumentException.class, () -> new Subject("users", "", "x\0y"));
        assertThrows(
                IllegalArgumentException.class,
                () -> new Subject("users", "", String.valueOf((char) 0xD800)));
    }

    @Test
    void authenticationRequiresTheDatabaseOnEveryRequest() {
        var issued = sessions.issue(OWNER, "phone");
        var offline = new java.util.concurrent.atomic.AtomicBoolean(false);
        var source =
                new DelegatingDataSource(dataSource) {
                    @Override
                    public Connection getConnection() throws SQLException {
                        if (offline.get()) throw new SQLException("controlled database outage");
                        return super.getConnection();
                    }
                };
        var reader = new JdbcSessions(source);
        assertEquals(issued.session(), reader.authenticate(issued.token()).orElseThrow());
        offline.set(true);
        assertThrows(SessionStoreException.class, () -> reader.authenticate(issued.token()));
    }

    private static void sql(String sql) throws SQLException {
        try (var connection = dataSource.getConnection();
                var statement = connection.createStatement()) {
            statement.execute(sql);
        }
    }

    private static String scalar(String sql) throws SQLException {
        try (var connection = dataSource.getConnection();
                var statement = connection.createStatement();
                var rows = statement.executeQuery(sql)) {
            rows.next();
            return rows.getString(1);
        }
    }
}
