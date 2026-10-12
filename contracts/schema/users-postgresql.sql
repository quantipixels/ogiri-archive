-- SPDX-License-Identifier: Apache-2.0
-- DeviseTokenAuth-compatible users table (postgresql), from DTA's install generator (b02076a) with the optional lockable columns.
-- New projects apply it; databases migrated from Rails already have it (the tokens column is ignored by Ogiri).
CREATE TABLE users (
    id bigserial PRIMARY KEY,
    ogiri_generation varchar(36) COLLATE "C" NOT NULL DEFAULT gen_random_uuid()::text,
    provider varchar(255) NOT NULL DEFAULT 'email',
    uid varchar(255) NOT NULL DEFAULT '',
    encrypted_password varchar(255) NOT NULL DEFAULT '',
    reset_password_token varchar(255),
    reset_password_sent_at timestamp,
    allow_password_change boolean DEFAULT false,
    remember_created_at timestamp,
    confirmation_token varchar(255),
    confirmed_at timestamp,
    confirmation_sent_at timestamp,
    unconfirmed_email varchar(255),
    failed_attempts integer NOT NULL DEFAULT 0,
    unlock_token varchar(255),
    locked_at timestamp,
    name varchar(255),
    nickname varchar(255),
    image varchar(255),
    email varchar(255),
    created_at timestamp NOT NULL,
    updated_at timestamp NOT NULL
);
CREATE UNIQUE INDEX index_users_on_email ON users (email);
CREATE UNIQUE INDEX index_users_on_uid_and_provider ON users (uid, provider);
CREATE UNIQUE INDEX index_users_on_reset_password_token ON users (reset_password_token);
CREATE UNIQUE INDEX index_users_on_confirmation_token ON users (confirmation_token);
CREATE UNIQUE INDEX index_users_on_unlock_token ON users (unlock_token);
