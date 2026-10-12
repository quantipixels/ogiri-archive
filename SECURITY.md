# Security

Report vulnerabilities through GitHub private vulnerability reporting for this repository. Do not publish live credentials. Automated proof is not a security certification; review Ogiri against your own threat model before production use.

## Supported versions

Ogiri targets Spring Boot 4.x, Java 17 or later, Jackson 3, PostgreSQL and MySQL 8.4 (InnoDB). Only the latest release receives fixes before 1.0.

## Credentials

- Access tokens are 32 random bytes from `SecureRandom`, encoded as unpadded base64url. Client ids are 16 random bytes. The database stores only SHA-256 digests of tokens, which is appropriate for high-entropy generated secrets, **not passwords**. A read-only database leak does not disclose usable tokens; database writes, process compromise, stolen plaintext tokens and heap dumps remain sensitive. There is no server-side pepper.
- Passwords use bcrypt, compatible with Devise hashes.
- Credentials travel in the devise_token_auth headers (`access-token`, `client`, `uid`, `expiry`, `token-type`), an `Authorization: Bearer` form of the same set, or, when cookie mode is enabled, an HttpOnly cookie. They are never accepted from query strings or form fields.
- Never log, serialise or put tokens in URLs or analytics. Ogiri's own logs and authentication events carry no tokens, passwords or client ids; events identify the account as `realm:uid`.

## Sessions

- Defaults: 14-day lifetime, at most 10 sessions (devices) per account; the soonest-expiring other session is evicted when the limit is reached. Both are configurable conveniences, not recommendations for every threat model.
- Rotation (`change-headers-on-each-request`) is **off by default**. When on, each authenticated request issues a new token; the previous token stays valid for the batch window (5 s by default) so parallel requests are not rejected. With rotation off, a stolen token stays usable until it expires or is revoked.
- Every request validates against the database; there is no session cache, so a storage outage fails closed (503) rather than accepting a previously seen session.
- Sign-out ends the current session. Password reset ends other sessions only when `remove-tokens-after-password-reset` is enabled; enable it unless you have a reason not to. An action on another account never clears the caller's own credential.
- Expired sessions are rejected at validation time. Deleting expired rows is an opt-in scheduled job (bounded batches, `SKIP LOCKED`, safe with several instances); it is housekeeping, not a security control.

## Working with the host's Spring Security

- Ogiri adds its rules to the host's security chain; it does not replace the host's CSRF configuration, session policy, request cache or CORS. The stateless defaults apply only to the fallback chain Ogiri supplies when the application defines none.
- Header- and Bearer-authenticated requests need no CSRF token. Requests authenticated by the Ogiri cookie require Spring's double-submit CSRF token on unsafe methods. The host's own CSRF protection keeps applying to everything else.
- A request carrying Ogiri credentials while the host session is already authenticated is rejected (401), so Ogiri headers cannot ride on a host login.
- CORS is enabled only if the application configures it.
- Use HTTPS. Cookies default to `Secure` and `SameSite=Lax`. Add rate limiting at the application or gateway; Ogiri's account locking (off by default; 20 attempts, unlock by email and/or after 1 hour) is not a substitute.

## Accounts

- Account status and authorities are loaded on each authenticated request. Re-enabling an account can restore its unrevoked, unexpired sessions.
- Configured permitted fields can never include password, token, confirmation, lock, tracking, provider or identity columns; such configuration fails at startup.
- Redirect targets for confirmation, password reset and unlock links must match the configured allow-list.
- Ogiri cannot atomically change account state it does not own. Bans, deletions and compromise recovery done outside Ogiri must also revoke the account's sessions.

## SQL, transactions and availability

- Apply the packaged schemas through your own migrations. MySQL requires InnoDB and the exact binary identity collation in the schema files. Timestamps use database statement time.
- Writes run in their own transactions (`REQUIRES_NEW`, `READ_COMMITTED`); reads suspend any outer transaction and must hit the primary, not a lagging replica. An outer transaction therefore needs a second connection.
- Per-account lock rows in `ogiri_subject_locks` serialise sign-in, rotation and revocation. Do not delete lock rows while the application runs.
- SQL statements time out after 5 seconds. Configure pool, socket and TLS timeouts separately. If a connection drops during commit the outcome is unknown: no credential is returned, but an orphaned session row may count toward the device limit. Do not blindly retry issuance.

## What the tests prove

Tests run against disposable PostgreSQL and MySQL databases with destructive fixtures, plus an HTTP conformance suite against a reference devise_token_auth server. Together with CodeQL and dependency scanning they cover different boundaries; none proves the absence of vulnerabilities, every race, or production capacity.
