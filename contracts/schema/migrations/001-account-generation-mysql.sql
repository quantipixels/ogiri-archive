-- SPDX-License-Identifier: Apache-2.0
-- Apply while Ogiri writers are stopped. Repeat all three users steps for every account table.
-- Use ROW (MySQL 8.4 default) or MIXED binary logging for UUID backfills and future inserts.
-- Add nullable, backfill as row-logged DML, then enforce NOT NULL and default only new rows.
-- Existing sessions are deliberately invalidated; sign in again after this migration.
ALTER TABLE users ADD COLUMN ogiri_generation varchar(36) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin;
UPDATE users SET ogiri_generation = UUID();
ALTER TABLE users MODIFY COLUMN ogiri_generation varchar(36) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin NOT NULL DEFAULT (UUID());
ALTER TABLE ogiri_sessions ADD COLUMN account_generation varchar(36) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin;
DELETE FROM ogiri_sessions;
