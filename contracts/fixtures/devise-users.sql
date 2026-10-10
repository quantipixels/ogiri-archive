-- SPDX-License-Identifier: Apache-2.0
-- Development fixture only: a users table shaped like a DeviseTokenAuth install, for the sample apps.
-- Works on PostgreSQL and MySQL 8. Every account's password is "test-password", hashed the way Devise does (bcrypt $2a$).
DROP TABLE IF EXISTS users;
CREATE TABLE users (
    id bigint PRIMARY KEY,
    provider varchar(255) NOT NULL DEFAULT 'email',
    uid varchar(255) NOT NULL DEFAULT '',
    email varchar(255) NOT NULL UNIQUE,
    encrypted_password varchar(255) NOT NULL DEFAULT '',
    role varchar(32) NOT NULL DEFAULT 'user',
    locked_at timestamp NULL
);
INSERT INTO users (id, uid, email, encrypted_password, role, locked_at) VALUES
    (1, 'demo@example.com', 'demo@example.com', '$2a$10$dwxaxFO5KU5KIOZCktopVOPmw0Yo.f40/FJxVBkisK5/ToreCbuHK', 'user', NULL),
    (2, 'admin@example.com', 'admin@example.com', '$2a$10$dwxaxFO5KU5KIOZCktopVOPmw0Yo.f40/FJxVBkisK5/ToreCbuHK', 'admin', NULL),
    (3, 'locked@example.com', 'locked@example.com', '$2a$10$dwxaxFO5KU5KIOZCktopVOPmw0Yo.f40/FJxVBkisK5/ToreCbuHK', 'user', CURRENT_TIMESTAMP);
