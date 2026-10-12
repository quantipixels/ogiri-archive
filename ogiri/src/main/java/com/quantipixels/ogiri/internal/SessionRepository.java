// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Quanti Pixels
package com.quantipixels.ogiri.internal;

import com.quantipixels.ogiri.IssuedSession;
import com.quantipixels.ogiri.Session;
import com.quantipixels.ogiri.SessionPolicy;
import com.quantipixels.ogiri.Subject;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;
import javax.sql.DataSource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;

/**
 * Thread-safe PostgreSQL/MySQL session lifecycle using Spring JDBC and transaction management. Uses
 * the supplied native DataSource, never a transaction-aware or replica-routing proxy. Mutations
 * commit independently; reads suspend a caller transaction to avoid stale snapshots. SQL has a
 * five-second timeout. Pool acquisition and network timeouts are host configuration.
 */
public final class SessionRepository implements com.quantipixels.ogiri.JdbcSessions {
    private static final String COLUMNS =
            "id, realm, tenant_id, subject_id, client, created_at, expires_at";
    private static final String OWNER = "realm = ? AND tenant_id = ? AND subject_id = ?";
    private final JdbcTemplate jdbc;
    private final NamedParameterJdbcTemplate named;
    private final AuthTransactions transactions;
    private final SessionPolicy policy;

    public SessionRepository(DataSource source) {
        this(source, SessionPolicy.defaults());
    }

    public SessionRepository(DataSource source, SessionPolicy policy) {
        this(new AuthTransactions(source), policy);
    }

    public SessionRepository(
            DataSource source, SessionPolicy policy, PlatformTransactionManager manager) {
        this(new AuthTransactions(source, manager), policy);
    }

    public SessionRepository(AuthTransactions transactions, SessionPolicy policy) {
        this.transactions = Objects.requireNonNull(transactions);
        this.policy = Objects.requireNonNull(policy);
        this.jdbc = transactions.jdbc();
        this.named = new NamedParameterJdbcTemplate(jdbc);
    }

    /** Issue only after the caller has authenticated and authorized the full subject. */
    @Override
    public IssuedSession issue(Subject subject, String client) {
        Objects.requireNonNull(subject, "subject");
        if (client == null || client.isBlank() || client.length() > 64 || client.indexOf(0) >= 0)
            throw new IllegalArgumentException("client must contain 1 to 64 characters");
        return write(
                () -> {
                    transactions.lock(subject);
                    return issueLocked(subject, client);
                });
    }

    /** Participates in the coordinator's transaction after its subject/account locks. */
    public IssuedSession issueLocked(Subject subject, String client) {
        return issueLocked(subject, client, null);
    }

    /** Bind a DTA session to a particular account incarnation, under the account lock. */
    public IssuedSession issueLocked(Subject subject, String client, String generation) {
        if (generation != null) {
            jdbc.update(
                    "DELETE FROM ogiri_sessions WHERE "
                            + OWNER
                            + " AND (account_generation IS NULL OR account_generation <> ?)",
                    subject.realm(),
                    subject.tenantId(),
                    subject.subjectId(),
                    generation);
        }
        long now = transactions.now();
        jdbc.update(
                "DELETE FROM ogiri_sessions WHERE " + OWNER + " AND expires_at <= ?",
                subject.realm(),
                subject.tenantId(),
                subject.subjectId(),
                now);
        var existing =
                jdbc.query(
                        "SELECT "
                                + COLUMNS
                                + " FROM ogiri_sessions WHERE "
                                + OWNER
                                + " ORDER BY expires_at, created_at, id FOR UPDATE",
                        SessionRepository::row,
                        subject.realm(),
                        subject.tenantId(),
                        subject.subjectId());
        for (int i = 0; i <= existing.size() - policy.maximumSessions(); i++) {
            jdbc.update("DELETE FROM ogiri_sessions WHERE id = ?", existing.get(i).id().toString());
        }
        String token = Tokens.generate();
        var session =
                new Session(
                        UUID.randomUUID(),
                        subject,
                        client,
                        Instant.ofEpochMilli(now),
                        Instant.ofEpochMilli(Math.addExact(now, policy.lifetime().toMillis())));
        jdbc.update(
                "INSERT INTO ogiri_sessions ("
                        + COLUMNS
                        + ", token_hash, rotated_at, account_generation) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                session.id().toString(),
                subject.realm(),
                subject.tenantId(),
                subject.subjectId(),
                client,
                now,
                session.expiresAt().toEpochMilli(),
                Tokens.digest(token),
                now,
                generation);
        return new IssuedSession(session, token);
    }

    /** Always one scoped row lookup, including unknown-account sentinel lookups. */
    public Optional<Session> find(Subject subject, String client, String token) {
        byte[] candidate = Tokens.digest(token);
        return jdbc
                .query(
                        "SELECT "
                                + COLUMNS
                                + ", token_hash FROM ogiri_sessions WHERE "
                                + OWNER
                                + " AND client = ? AND expires_at > "
                                + nowSql(),
                        (rows, n) -> {
                            boolean matches =
                                    java.security.MessageDigest.isEqual(
                                            rows.getBytes("token_hash"),
                                            candidate == null ? new byte[32] : candidate);
                            return matches && candidate != null ? row(rows, n) : null;
                        },
                        subject.realm(),
                        subject.tenantId(),
                        subject.subjectId(),
                        client)
                .stream()
                .filter(Objects::nonNull)
                .findFirst();
    }

    /**
     * Candidate only: account binding and authoritative token validation follow under auth locks.
     */
    public Optional<Session> resolve(String realm, String client, String token, boolean rotating) {
        byte[] digest = Tokens.digest(token);
        if (digest == null || client.length() > 64) return Optional.empty();
        var matches =
                jdbc.query(
                        "SELECT "
                                + COLUMNS
                                + " FROM ogiri_sessions WHERE realm = ? AND tenant_id = '' AND client = ? AND "
                                + (rotating
                                        ? "(token_hash = ? OR previous_token_hash = ? OR last_token_hash = ?)"
                                        : "token_hash = ?"),
                        SessionRepository::row,
                        rotating
                                ? new Object[] {realm, client, digest, digest, digest}
                                : new Object[] {realm, client, digest});
        return matches.size() == 1 ? Optional.of(matches.get(0)) : Optional.empty();
    }

    public boolean boundTo(Subject subject, String client, String generation) {
        return jdbc
                .queryForList(
                        "SELECT account_generation FROM ogiri_sessions WHERE "
                                + OWNER
                                + " AND client = ?",
                        String.class,
                        subject.realm(),
                        subject.tenantId(),
                        subject.subjectId(),
                        client)
                .stream()
                .anyMatch(generation::equals);
    }

    private String nowSql() {
        return transactions.clockExpression();
    }

    /** One authoritative indexed read; revocation is visible on the next authentication. */
    @Override
    public Optional<Session> authenticate(String token) {
        byte[] digest = Tokens.digest(token);
        if (digest == null) return Optional.empty();
        return read(
                () ->
                        jdbc
                                .query(
                                        "SELECT "
                                                + COLUMNS
                                                + " FROM ogiri_sessions WHERE token_hash = ? AND expires_at > "
                                                + transactions.clockExpression(),
                                        SessionRepository::row,
                                        digest)
                                .stream()
                                .findFirst());
    }

    /** List live session metadata for an application-authorized complete subject. */
    @Override
    public List<Session> list(Subject subject) {
        Objects.requireNonNull(subject, "subject");
        return read(
                () ->
                        List.copyOf(
                                jdbc.query(
                                        "SELECT "
                                                + COLUMNS
                                                + " FROM ogiri_sessions WHERE "
                                                + OWNER
                                                + " AND expires_at > "
                                                + transactions.clockExpression()
                                                + " ORDER BY created_at, id",
                                        SessionRepository::row,
                                        subject.realm(),
                                        subject.tenantId(),
                                        subject.subjectId())));
    }

    /** Delete one owned session; foreign or absent identifiers return false. */
    @Override
    public boolean revoke(Subject subject, UUID id) {
        Objects.requireNonNull(subject, "subject");
        Objects.requireNonNull(id, "id");
        return write(
                () ->
                        jdbc.update(
                                        "DELETE FROM ogiri_sessions WHERE " + OWNER + " AND id = ?",
                                        subject.realm(),
                                        subject.tenantId(),
                                        subject.subjectId(),
                                        id.toString())
                                == 1);
    }

    /** Serialize with issuance and revoke existing sessions; this does not ban future login. */
    @Override
    public int revokeAll(Subject subject) {
        Objects.requireNonNull(subject, "subject");
        return write(
                () -> {
                    transactions.lock(subject);
                    return jdbc.update(
                            "DELETE FROM ogiri_sessions WHERE " + OWNER,
                            subject.realm(),
                            subject.tenantId(),
                            subject.subjectId());
                });
    }

    /**
     * Bounded cleanup, safe with concurrent workers. Expiry enforcement never waits for cleanup.
     */
    @Override
    public int cleanup(int batchSize) {
        if (batchSize < 1 || batchSize > 10_000)
            throw new IllegalArgumentException("batchSize must be between 1 and 10000");
        return write(
                () -> {
                    var ids =
                            jdbc.queryForList(
                                    "SELECT id FROM ogiri_sessions WHERE expires_at <= "
                                            + transactions.clockExpression()
                                            + " ORDER BY expires_at, id LIMIT ? FOR UPDATE SKIP LOCKED",
                                    String.class,
                                    batchSize);
                    return ids.isEmpty()
                            ? 0
                            : named.update(
                                    "DELETE FROM ogiri_sessions WHERE id IN (:ids)",
                                    Map.of("ids", ids));
                });
    }

    /** A uid change is a credential transition, even when authentication was a batch request. */
    public IssuedSession reissueLocked(Subject subject, UUID id) {
        var current =
                jdbc
                        .query(
                                "SELECT "
                                        + COLUMNS
                                        + " FROM ogiri_sessions WHERE "
                                        + OWNER
                                        + " AND id = ? AND expires_at > "
                                        + nowSql()
                                        + " FOR UPDATE",
                                SessionRepository::row,
                                subject.realm(),
                                subject.tenantId(),
                                subject.subjectId(),
                                id.toString())
                        .stream()
                        .findFirst();
        if (current.isEmpty()) return null;
        long now = transactions.now();
        String token = Tokens.generate();
        var previous = current.orElseThrow();
        var session =
                new Session(
                        previous.id(),
                        subject,
                        previous.client(),
                        previous.createdAt(),
                        Instant.ofEpochMilli(Math.addExact(now, policy.lifetime().toMillis())));
        jdbc.update(
                "UPDATE ogiri_sessions SET token_hash = ?, previous_token_hash = NULL, last_token_hash = NULL, rotated_at = ?, expires_at = ? WHERE id = ?",
                Tokens.digest(token),
                now,
                session.expiresAt().toEpochMilli(),
                id.toString());
        return new IssuedSession(session, token);
    }

    public boolean liveLocked(Subject subject, UUID id) {
        return id != null
                && !jdbc.queryForList(
                                "SELECT id FROM ogiri_sessions WHERE "
                                        + OWNER
                                        + " AND id = ? AND expires_at > "
                                        + nowSql(),
                                String.class,
                                subject.realm(),
                                subject.tenantId(),
                                subject.subjectId(),
                                id.toString())
                        .isEmpty();
    }

    public int revokeAllLocked(Subject subject) {
        return jdbc.update(
                "DELETE FROM ogiri_sessions WHERE " + OWNER,
                subject.realm(),
                subject.tenantId(),
                subject.subjectId());
    }

    public int keepNewestLocked(Subject subject) {
        var live =
                jdbc.query(
                        "SELECT "
                                + COLUMNS
                                + " FROM ogiri_sessions WHERE "
                                + OWNER
                                + " ORDER BY created_at DESC, id DESC FOR UPDATE",
                        SessionRepository::row,
                        subject.realm(),
                        subject.tenantId(),
                        subject.subjectId());
        int deleted = 0;
        for (int i = 1; i < live.size(); i++) {
            deleted +=
                    jdbc.update(
                            "DELETE FROM ogiri_sessions WHERE id = ?", live.get(i).id().toString());
        }
        return deleted;
    }

    private <T> T write(Supplier<T> operation) {
        return transactions.write(operation);
    }

    private <T> T read(Supplier<T> operation) {
        return transactions.read(operation);
    }

    private static Session row(ResultSet rows, int index) throws SQLException {
        return new Session(
                UUID.fromString(rows.getString("id")),
                new Subject(
                        rows.getString("realm"),
                        rows.getString("tenant_id"),
                        rows.getString("subject_id")),
                rows.getString("client"),
                Instant.ofEpochMilli(rows.getLong("created_at")),
                Instant.ofEpochMilli(rows.getLong("expires_at")));
    }
}
