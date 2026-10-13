-- SPDX-License-Identifier: Apache-2.0
-- Ogiri session tables, protocol v2 (PostgreSQL). Application-owned migration; libraries never run DDL.
CREATE TABLE ogiri_subject_locks (
    lock_key bytea PRIMARY KEY CHECK (octet_length(lock_key) = 32)
);
CREATE TABLE ogiri_sessions (
    id varchar(36) PRIMARY KEY,
    realm varchar(63) COLLATE "C" NOT NULL,
    tenant_id varchar(255) COLLATE "C" NOT NULL,
    subject_id varchar(255) COLLATE "C" NOT NULL,
    account_generation varchar(36) COLLATE "C",
    client varchar(64) COLLATE "C" NOT NULL,
    token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    previous_token_hash bytea CHECK (octet_length(previous_token_hash) = 32),
    last_token_hash bytea CHECK (octet_length(last_token_hash) = 32),
    rotated_at bigint,
    created_at bigint NOT NULL,
    expires_at bigint NOT NULL CHECK (expires_at > created_at),
    CONSTRAINT ogiri_sessions_client UNIQUE (realm, tenant_id, subject_id, client)
);
CREATE INDEX ogiri_sessions_expiry ON ogiri_sessions (expires_at, id);
CREATE INDEX ogiri_sessions_credential_lookup ON ogiri_sessions (realm, client);
