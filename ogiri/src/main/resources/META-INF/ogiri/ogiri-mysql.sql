-- SPDX-License-Identifier: Apache-2.0
-- Ogiri session tables, protocol v2 (MySQL 8, InnoDB). Application-owned migration; libraries never run DDL.
CREATE TABLE ogiri_subject_locks (
    lock_key varbinary(32) PRIMARY KEY CHECK (octet_length(lock_key) = 32)
) ENGINE=InnoDB;
CREATE TABLE ogiri_sessions (
    id varchar(36) PRIMARY KEY,
    realm varchar(63) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin NOT NULL,
    tenant_id varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin NOT NULL,
    subject_id varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin NOT NULL,
    account_generation varchar(36) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin,
    client varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin NOT NULL,
    token_hash varbinary(32) NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    previous_token_hash varbinary(32) CHECK (octet_length(previous_token_hash) = 32),
    last_token_hash varbinary(32) CHECK (octet_length(last_token_hash) = 32),
    rotated_at bigint,
    created_at bigint NOT NULL,
    expires_at bigint NOT NULL,
    CONSTRAINT ogiri_expiry_after_creation CHECK (expires_at > created_at),
    CONSTRAINT ogiri_sessions_client UNIQUE (realm, tenant_id, subject_id, client)
) ENGINE=InnoDB;
CREATE INDEX ogiri_sessions_expiry ON ogiri_sessions (expires_at, id);
