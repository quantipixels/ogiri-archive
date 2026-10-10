-- SPDX-License-Identifier: Apache-2.0
-- Development reset for sample apps and suites: drop the users table so users-<engine>.sql and devise-users.sql can be reapplied.
DROP TABLE IF EXISTS users;
