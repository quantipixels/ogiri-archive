// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri;

import static org.junit.jupiter.api.Assertions.*;

import com.quantipixels.ogiri.internal.AuthTransactions;
import com.quantipixels.ogiri.internal.ClientRotation;
import com.quantipixels.ogiri.internal.SessionRepository;
import com.quantipixels.ogiri.internal.Tokens;
import java.time.Duration;
import java.util.ArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;

@Tag("database")
class RotationTest {
    AuthTransactions tx;
    SessionRepository sessions;
    ClientRotation rotation;
    Subject subject = new Subject("rotation", "", "1");

    @BeforeEach
    void schema() {
        var source =
                new DriverManagerDataSource(
                        System.getenv("OGIRI_TEST_JDBC_URL"),
                        System.getenv("OGIRI_TEST_JDBC_USER"),
                        System.getenv("OGIRI_TEST_JDBC_PASSWORD"));
        tx = new AuthTransactions(source);
        tx.jdbc().execute("DROP TABLE IF EXISTS ogiri_sessions");
        tx.jdbc().execute("DROP TABLE IF EXISTS ogiri_subject_locks");
        new ResourceDatabasePopulator(
                        new ClassPathResource(
                                "META-INF/ogiri/ogiri-"
                                        + System.getenv("OGIRI_TEST_DATABASE")
                                        + ".sql"))
                .execute(source);
        sessions = new SessionRepository(tx, SessionPolicy.defaults());
        rotation = new ClientRotation(tx);
    }

    ClientRotation.Result authenticate(String token) {
        return tx.write(
                () -> {
                    tx.lock(subject);
                    return rotation.authenticateLocked(
                                    subject,
                                    "client",
                                    token,
                                    Duration.ofSeconds(5),
                                    Duration.ofDays(14))
                            .orElseThrow();
                });
    }

    void age() {
        tx.jdbc().update("UPDATE ogiri_sessions SET rotated_at = 0");
    }

    @Test
    void concurrentVerifiedCurrentTokenRotatesOnceAndBatchesWaiters() throws Exception {
        var first = sessions.issue(subject, "client");
        age();
        int workers = 8;
        var ready = new CountDownLatch(workers);
        var go = new CountDownLatch(1);
        var executor = Executors.newFixedThreadPool(workers);
        try {
            var futures = new ArrayList<java.util.concurrent.Future<ClientRotation.Result>>();
            for (int i = 0; i < workers; i++)
                futures.add(
                        executor.submit(
                                () -> {
                                    ready.countDown();
                                    assertTrue(go.await(5, TimeUnit.SECONDS));
                                    return authenticate(first.token());
                                }));
            assertTrue(ready.await(5, TimeUnit.SECONDS));
            go.countDown();
            var results = new ArrayList<ClientRotation.Result>();
            for (var future : futures) results.add(future.get(10, TimeUnit.SECONDS));
            assertEquals(
                    1,
                    results.stream().filter(result -> !result.batch()).count(),
                    "A single locked rotation wins; the rest extend its batch buffer");
            var winner =
                    results.stream().filter(result -> !result.batch()).findFirst().orElseThrow();
            assertNotEquals(first.token(), winner.token());
            assertArrayEquals(
                    Tokens.digest(winner.token()),
                    tx.jdbc()
                            .queryForObject("SELECT token_hash FROM ogiri_sessions", byte[].class));
            assertArrayEquals(
                    Tokens.digest(first.token()),
                    tx.jdbc()
                            .queryForObject(
                                    "SELECT previous_token_hash FROM ogiri_sessions",
                                    byte[].class));
            assertEquals(1, sessions.list(subject).size());
            for (var result : results)
                if (result.batch()) assertEquals(first.token(), result.token());
        } finally {
            go.countDown();
            executor.shutdownNow();
            assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS));
        }
    }

    @Test
    void previousAndLastDigestsExpireWithBufferAndExpirySlides() {
        var first = sessions.issue(subject, "client");
        tx.jdbc().update("UPDATE ogiri_sessions SET expires_at = ?", tx.now() + 1000);
        age();
        var second = authenticate(first.token());
        assertFalse(second.batch());
        assertTrue(
                second.session().expiresAt().toEpochMilli()
                        > tx.now() + Duration.ofDays(13).toMillis());
        assertTrue(authenticate(first.token()).batch());
        age();
        var third = authenticate(second.token());
        assertFalse(third.batch());
        assertTrue(authenticate(first.token()).batch(), "last digest is valid within the batch");
        assertArrayEquals(
                Tokens.digest(first.token()),
                tx.jdbc()
                        .queryForObject(
                                "SELECT last_token_hash FROM ogiri_sessions", byte[].class));
        age();
        assertTrue(
                tx.write(
                                () -> {
                                    tx.lock(subject);
                                    return rotation.authenticateLocked(
                                            subject,
                                            "client",
                                            first.token(),
                                            Duration.ofSeconds(5),
                                            Duration.ofDays(14));
                                })
                        .isEmpty(),
                "last digest must fail outside the DB-clock buffer");
        assertTrue(
                tx.write(
                                () -> {
                                    tx.lock(subject);
                                    return rotation.authenticateLocked(
                                            subject,
                                            "client",
                                            second.token(),
                                            Duration.ofSeconds(5),
                                            Duration.ofDays(14));
                                })
                        .isEmpty(),
                "previous digest must fail outside the buffer");
        assertFalse(authenticate(third.token()).batch());
    }
}
