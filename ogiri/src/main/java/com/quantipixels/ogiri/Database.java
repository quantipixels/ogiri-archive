// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Quanti Pixels
package com.quantipixels.ogiri;

import java.sql.SQLException;
import javax.sql.DataSource;

/**
 * SQL variation stays internal; unsupported vendors fail at startup rather than silently degrading.
 */
enum Database {
    POSTGRESQL(
            "FLOOR(EXTRACT(EPOCH FROM statement_timestamp()) * 1000)",
            "INSERT INTO ogiri_subject_locks (lock_key) VALUES (?) ON CONFLICT DO NOTHING"),
    MYSQL(
            "FLOOR(UNIX_TIMESTAMP(CURRENT_TIMESTAMP(3)) * 1000)",
            "INSERT INTO ogiri_subject_locks (lock_key) VALUES (?) ON DUPLICATE KEY UPDATE lock_key = lock_key");

    final String now;
    final String insertLock;

    Database(String now, String insertLock) {
        this.now = now;
        this.insertLock = insertLock;
    }

    static Database detect(DataSource source) {
        try (var connection = source.getConnection()) {
            var metadata = connection.getMetaData();
            return switch (metadata.getDatabaseProductName()) {
                case "PostgreSQL" -> POSTGRESQL;
                case "MySQL" -> {
                    if (metadata.getDatabaseMajorVersion() < 8)
                        throw new IllegalArgumentException("Ogiri requires MySQL 8 or newer");
                    yield MYSQL;
                }
                default ->
                        throw new IllegalArgumentException(
                                "Ogiri supports PostgreSQL and MySQL, not "
                                        + metadata.getDatabaseProductName());
            };
        } catch (SQLException failure) {
            throw new SessionStoreException(failure);
        }
    }
}
