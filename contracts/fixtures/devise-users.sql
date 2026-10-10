-- SPDX-License-Identifier: Apache-2.0
-- Development fixture for the sample apps and the parity suite. Apply after contracts/schema/users-<engine>.sql.
-- Works on PostgreSQL and MySQL 8. Every password is "test-password", hashed as Devise does (bcrypt $2a$).
-- role is a sample-app column (not part of DTA) used to demonstrate authorization.
ALTER TABLE users ADD COLUMN role varchar(32) NOT NULL DEFAULT 'user';
INSERT INTO users (provider, uid, email, encrypted_password, confirmed_at, role, failed_attempts, locked_at, created_at, updated_at) VALUES
    ('email', 'demo@example.com', 'demo@example.com', '$2a$10$dwxaxFO5KU5KIOZCktopVOPmw0Yo.f40/FJxVBkisK5/ToreCbuHK', CURRENT_TIMESTAMP, 'user', 0, NULL, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
    ('email', 'admin@example.com', 'admin@example.com', '$2a$10$dwxaxFO5KU5KIOZCktopVOPmw0Yo.f40/FJxVBkisK5/ToreCbuHK', CURRENT_TIMESTAMP, 'admin', 0, NULL, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
    ('email', 'locked@example.com', 'locked@example.com', '$2a$10$dwxaxFO5KU5KIOZCktopVOPmw0Yo.f40/FJxVBkisK5/ToreCbuHK', CURRENT_TIMESTAMP, 'user', 20, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
