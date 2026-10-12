-- SPDX-License-Identifier: Apache-2.0
-- Apply while Ogiri writers are stopped. Repeat the users ALTER for every account table.
-- Existing sessions are deliberately invalidated; sign in again after this migration.
ALTER TABLE users ADD COLUMN ogiri_generation varchar(36) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin NOT NULL DEFAULT (UUID());
ALTER TABLE ogiri_sessions ADD COLUMN account_generation varchar(36) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin;
DELETE FROM ogiri_sessions;
