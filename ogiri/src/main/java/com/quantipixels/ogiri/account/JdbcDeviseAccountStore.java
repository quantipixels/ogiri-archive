// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.account;

import com.quantipixels.ogiri.AuthTransactions;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TimeZone;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.simple.SimpleJdbcInsert;

/** Default Devise-table adapter; table and extra columns are validated identifiers. */
public final class JdbcDeviseAccountStore implements AccountStore {
    private static final Set<String> TOKENS =
            Set.of("reset_password_token", "confirmation_token", "unlock_token");
    private final JdbcTemplate jdbc;
    private final String table;
    private final OgiriAuthorities authorities;

    public JdbcDeviseAccountStore(
            AuthTransactions transactions, String table, OgiriAuthorities authorities) {
        this.jdbc = transactions.jdbc();
        this.table = identifier(table);
        this.authorities = authorities;
    }

    private static String identifier(String value) {
        if (!value.matches("[A-Za-z_][A-Za-z0-9_]*")) {
            throw new IllegalArgumentException("Invalid account SQL identifier");
        }
        return value;
    }

    public static String normalize(String email) {
        return email.strip().toLowerCase(Locale.ROOT);
    }

    @Override
    public Optional<OgiriAccount> findByUid(String uid) {
        return select("uid = ?", uid);
    }

    @Override
    public Optional<OgiriAccount> findByEmail(String email) {
        return select("LOWER(TRIM(email)) = ? AND provider = 'email'", normalize(email));
    }

    @Override
    public Optional<OgiriAccount> findById(String id) {
        return select("id = ?", Long.valueOf(id));
    }

    @Override
    public Optional<OgiriAccount> lock(String id) {
        return select("id = ? FOR UPDATE", Long.valueOf(id));
    }

    @Override
    public Optional<OgiriAccount> findByToken(String column, String digest) {
        if (!TOKENS.contains(column)) {
            throw new IllegalArgumentException("Invalid token column");
        }
        return select(column + " = ?", digest);
    }

    private Optional<OgiriAccount> select(String where, Object value) {
        return jdbc.query("SELECT * FROM " + table + " WHERE " + where, this::row, value).stream()
                .findFirst();
    }

    private OgiriAccount row(ResultSet rows, int index) throws SQLException {
        var values = new LinkedHashMap<String, Object>();
        var metadata = rows.getMetaData();
        for (int i = 1; i <= metadata.getColumnCount(); i++) {
            Object value = rows.getObject(i);
            if (value instanceof Timestamp || value instanceof java.time.LocalDateTime) {
                value =
                        rows.getTimestamp(i, Calendar.getInstance(TimeZone.getTimeZone("UTC")))
                                .toInstant();
            }
            values.put(metadata.getColumnLabel(i), value);
        }
        return new OgiriAccount(
                values, authorities.map(java.util.Collections.unmodifiableMap(values)));
    }

    @Override
    public OgiriAccount create(Map<String, Object> columns) {
        var values = sqlValues(columns);
        Number id =
                new SimpleJdbcInsert(jdbc)
                        .withTableName(table)
                        .usingGeneratedKeyColumns("id")
                        .usingColumns(values.keySet().toArray(String[]::new))
                        .executeAndReturnKey(values);
        return findById(id.toString()).orElseThrow();
    }

    @Override
    public OgiriAccount update(String id, Map<String, Object> changes) {
        var values = sqlValues(changes);
        List<String> assignments = new ArrayList<>();
        List<Object> parameters = new ArrayList<>();
        values.forEach(
                (column, value) -> {
                    assignments.add(identifier(column) + " = ?");
                    parameters.add(value);
                });
        parameters.add(Long.valueOf(id));
        jdbc.update(
                "UPDATE " + table + " SET " + String.join(", ", assignments) + " WHERE id = ?",
                parameters.toArray());
        return findById(id).orElseThrow();
    }

    private static Map<String, Object> sqlValues(Map<String, Object> columns) {
        var result = new LinkedHashMap<String, Object>();
        columns.forEach(
                (key, value) ->
                        result.put(
                                identifier(key),
                                value instanceof Instant instant
                                        ? java.time.LocalDateTime.ofInstant(
                                                instant, java.time.ZoneOffset.UTC)
                                        : value));
        return result;
    }

    @Override
    public void delete(String id) {
        jdbc.update("DELETE FROM " + table + " WHERE id = ?", Long.valueOf(id));
    }
}
