-- SPDX-License-Identifier: Apache-2.0
-- Apply while Ogiri writers are stopped. Repeat the users ALTER for every account table.
-- Existing sessions are deliberately invalidated; sign in again after this migration.
ALTER TABLE users ADD COLUMN ogiri_generation varchar(36) COLLATE "C" NOT NULL DEFAULT gen_random_uuid()::text;
ALTER TABLE ogiri_sessions ADD COLUMN account_generation varchar(36) COLLATE "C";
DELETE FROM ogiri_sessions;
