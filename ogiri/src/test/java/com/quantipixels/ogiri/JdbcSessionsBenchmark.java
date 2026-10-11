// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri;

import com.quantipixels.ogiri.internal.Tokens;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Opt-in measurement harness; not a timing-sensitive correctness test. Uses the disposable test DB.
 */
public final class JdbcSessionsBenchmark {
    public static void main(String[] args) throws Exception {
        String url = Objects.requireNonNull(System.getenv("OGIRI_TEST_JDBC_URL"));
        if (!url.contains("ogiri_test"))
            throw new IllegalArgumentException(
                    "Benchmark requires an ogiri_test disposable database");
        var config = new HikariConfig();
        config.setJdbcUrl(url);
        config.setUsername(System.getenv("OGIRI_TEST_JDBC_USER"));
        config.setPassword(System.getenv("OGIRI_TEST_JDBC_PASSWORD"));
        config.setMaximumPoolSize(8);
        config.setConnectionTimeout(3000);
        try (var source = new HikariDataSource(config)) {
            var jdbc = new JdbcTemplate(source);
            String realm = "benchmark-" + UUID.randomUUID();
            String token = Tokens.generate();
            try {
                long now = System.currentTimeMillis();
                List<Object[]> rows = new ArrayList<>();
                for (int i = 0; i < 10_000; i++)
                    rows.add(
                            new Object[] {
                                UUID.randomUUID().toString(),
                                realm,
                                "",
                                "user-" + i,
                                "benchmark",
                                now,
                                now + 3_600_000,
                                Tokens.digest(i == 0 ? token : Tokens.generate())
                            });
                jdbc.batchUpdate(
                        "INSERT INTO ogiri_sessions (id,realm,tenant_id,subject_id,client,created_at,expires_at,token_hash) VALUES (?,?,?,?,?,?,?,?)",
                        rows);
                var sessions = new com.quantipixels.ogiri.internal.SessionRepository(source);
                for (int i = 0; i < 1000; i++)
                    if (sessions.authenticate(token).isEmpty())
                        throw new AssertionError("Warmup failed");
                List<String> results = new ArrayList<>();
                for (int threads : new int[] {1, 8}) {
                    int perThread = 2000;
                    var executor = Executors.newFixedThreadPool(threads);
                    try {
                        var barrier = new CyclicBarrier(threads + 1);
                        List<Future<long[]>> futures = new ArrayList<>();
                        for (int t = 0; t < threads; t++)
                            futures.add(
                                    executor.submit(
                                            () -> {
                                                long[] elapsed = new long[perThread];
                                                barrier.await();
                                                for (int i = 0; i < perThread; i++) {
                                                    long start = System.nanoTime();
                                                    if (sessions.authenticate(token).isEmpty())
                                                        throw new AssertionError(
                                                                "Authentication failed");
                                                    elapsed[i] = System.nanoTime() - start;
                                                }
                                                return elapsed;
                                            }));
                        long start = System.nanoTime();
                        barrier.await();
                        long[] values = new long[threads * perThread];
                        int offset = 0;
                        for (var future : futures) {
                            long[] value = future.get(60, TimeUnit.SECONDS);
                            System.arraycopy(value, 0, values, offset, value.length);
                            offset += value.length;
                        }
                        double seconds = (System.nanoTime() - start) / 1e9;
                        Arrays.sort(values);
                        results.add(
                                String.format(
                                        Locale.ROOT,
                                        "{\"threads\":%d,\"samples\":%d,\"operationsPerSecond\":%.1f,\"p50Micros\":%.1f,\"p95Micros\":%.1f,\"p99Micros\":%.1f}",
                                        threads,
                                        values.length,
                                        values.length / seconds,
                                        values[values.length / 2] / 1000.0,
                                        values[(int) (values.length * .95)] / 1000.0,
                                        values[(int) (values.length * .99)] / 1000.0));
                    } finally {
                        executor.shutdownNow();
                        executor.awaitTermination(10, TimeUnit.SECONDS);
                    }
                }
                String database = System.getenv("OGIRI_TEST_DATABASE");
                String output =
                        "{\"database\":\""
                                + database
                                + "\",\"java\":\""
                                + System.getProperty("java.version")
                                + "\",\"rows\":10000,\"warmup\":1000,\"poolSize\":8,\"boundary\":\"local session lookup, excluding account directory and HTTP\",\"results\":["
                                + String.join(",", results)
                                + "]}";
                Path target = Path.of("target");
                Files.createDirectories(target);
                Files.writeString(target.resolve("benchmark-" + database + ".json"), output + "\n");
                System.out.println(output);
            } finally {
                jdbc.update("DELETE FROM ogiri_sessions WHERE realm = ?", realm);
            }
        }
    }
}
