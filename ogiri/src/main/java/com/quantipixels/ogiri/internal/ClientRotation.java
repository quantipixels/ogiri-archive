// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.internal;

import com.quantipixels.ogiri.Session;
import com.quantipixels.ogiri.Subject;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/** H5; caller owns subject and account locks before the client row lock. */
public final class ClientRotation {
    private final AuthTransactions transactions;

    public ClientRotation(AuthTransactions transactions) {
        this.transactions = transactions;
    }

    public record Result(Session session, String token, boolean batch) {
        @Override
        public String toString() {
            return "RotationResult[redacted]";
        }
    }

    private static final class Snapshot {
        private final Session session;
        private final byte[] current;
        private final byte[] previous;
        private final byte[] last;
        private final long rotated;

        private Snapshot(
                Session session, byte[] current, byte[] previous, byte[] last, long rotated) {
            this.session = session;
            this.current = current;
            this.previous = previous;
            this.last = last;
            this.rotated = rotated;
        }
    }

    public Optional<Result> authenticateLocked(
            Subject subject, String client, String token, Duration buffer, Duration lifespan) {
        var rows =
                transactions
                        .jdbc()
                        .query(
                                "SELECT id, created_at, expires_at, token_hash, previous_token_hash, last_token_hash, rotated_at FROM ogiri_sessions WHERE realm = ? AND tenant_id = ? AND subject_id = ? AND client = ? FOR UPDATE",
                                (row, index) ->
                                        new Snapshot(
                                                new Session(
                                                        UUID.fromString(row.getString("id")),
                                                        subject,
                                                        client,
                                                        Instant.ofEpochMilli(
                                                                row.getLong("created_at")),
                                                        Instant.ofEpochMilli(
                                                                row.getLong("expires_at"))),
                                                row.getBytes("token_hash"),
                                                row.getBytes("previous_token_hash"),
                                                row.getBytes("last_token_hash"),
                                                row.getLong("rotated_at")),
                                subject.realm(),
                                subject.tenantId(),
                                subject.subjectId(),
                                client);
        long now = transactions.now(); // Read after any client-row wait.
        if (rows.isEmpty()) return Optional.empty();
        var row = rows.get(0);
        byte[] digest = Tokens.digest(token);
        boolean batch = now < Math.addExact(row.rotated, buffer.toMillis());
        boolean current = same(row.current, digest);
        boolean previous = same(row.previous, digest);
        boolean last = same(row.last, digest);
        if (digest == null
                || row.session.expiresAt().toEpochMilli() <= now
                || !(current || ((previous || last) && batch))) return Optional.empty();
        if (batch) {
            transactions
                    .jdbc()
                    .update(
                            "UPDATE ogiri_sessions SET rotated_at = ? WHERE id = ?",
                            now,
                            row.session.id().toString());
            return Optional.of(new Result(row.session, token, true));
        }
        String next = Tokens.generate();
        long expiry = Math.addExact(now, lifespan.toMillis());
        transactions
                .jdbc()
                .update(
                        "UPDATE ogiri_sessions SET last_token_hash = previous_token_hash, previous_token_hash = token_hash, token_hash = ?, rotated_at = ?, expires_at = ? WHERE id = ?",
                        Tokens.digest(next),
                        now,
                        expiry,
                        row.session.id().toString());
        var session =
                new Session(
                        row.session.id(),
                        subject,
                        client,
                        row.session.createdAt(),
                        Instant.ofEpochMilli(expiry));
        return Optional.of(new Result(session, next, false));
    }

    private static boolean same(byte[] stored, byte[] candidate) {
        return MessageDigest.isEqual(
                stored == null ? new byte[32] : stored,
                candidate == null ? new byte[32] : candidate);
    }
}
