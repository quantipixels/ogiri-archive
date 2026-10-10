# Ogiri protocol, version 1

Every Ogiri implementation (Spring Boot, FastAPI, Phoenix) follows this document. It shares one token format, one database schema and one HTTP API. A frontend written against one backend works against the others. Backends that share the session tables accept each other's sessions.

The executable form of this contract is [`conformance/`](conformance). An implementation conforms when that suite passes against its sample application.

## Tokens

- A token is `og1_` followed by 32 random bytes from a cryptographically secure generator, encoded as unpadded base64url (43 characters). Total length: 47 characters.
- Storage keeps only `SHA-256(token)`, computed over the full ASCII token including the `og1_` prefix (32 bytes). The token itself is never stored or logged.
- A presented token is malformed unless it is 47 characters, starts with `og1_`, and its remainder decodes as base64url to exactly 32 bytes that re-encode to the same text. Malformed tokens fail without a database query.
- Tokens are opaque. They carry no claims and are not JWTs. Every authenticated request reads the session row, so revocation applies to the next request.

## Identity

A session belongs to a subject: `realm` (matches `[a-z0-9][a-z0-9._-]{0,62}`, default `users`), `tenantId` (empty string means no tenant, never a wildcard) and `subjectId` (1–255 characters, no NUL). Comparison is exact and case-sensitive. The application owns its accounts: it verifies passwords and maps a login to a subject, and on every request it loads the current account (active or not, plus roles) from that subject.

## Database

The schema is [`ogiri/src/main/resources/META-INF/ogiri/schema-postgresql.sql`](../ogiri/src/main/resources/META-INF/ogiri/schema-postgresql.sql) (MySQL: `schema-mysql.sql`). The application applies it through its own migrations; libraries never run DDL. Timestamps are UTC epoch milliseconds from the **database** clock.

| Operation | Rule |
| --- | --- |
| Issue | One `READ COMMITTED` transaction: insert the subject's lock row if absent, `SELECT … FOR UPDATE` it, read the database time, count live sessions (`expires_at > now`). If the count is at least the maximum, fail with *limit*. Otherwise insert a row with a random UUID v4 `id`, `created_at = now`, `expires_at = now + lifetime`. |
| Authenticate | `SELECT … WHERE token_hash = ? AND expires_at > <database now>`. No writes. Expiry is fixed, not sliding. |
| List | Live sessions of one subject, ordered by `created_at, id`. |
| Revoke | Delete one session by `id` **and** owner. A foreign or missing id reports "not found". |
| Revoke all | Lock the subject row (as in Issue), then delete every session of the subject. |
| Cleanup | Bounded: select up to N expired ids `FOR UPDATE SKIP LOCKED`, delete them, same transaction. |

The lock key is `SHA-256("ogiri-session-admission-v1" ‖ len(realm) ‖ realm ‖ len(tenantId) ‖ tenantId ‖ len(subjectId) ‖ subjectId)`, where each part is UTF-8 and each length is a 4-byte big-endian byte count.

Session mutations commit independently of any surrounding application transaction. Reads must not reuse a stale snapshot of an outer transaction. Storage failures surface as errors (HTTP 503 at sign-in, 5xx elsewhere) and never as anonymous or successful authentication.

Defaults: lifetime 7 days (allowed: 1 second to 365 days), at most 10 live sessions per subject (allowed: 1–1000). Reaching the cap rejects the new sign-in; it never evicts another device.

## HTTP

The base path defaults to `/auth`. Responses from these endpoints carry `Cache-Control: no-store`.

### `POST {base}/sign-in`

The request must have `Content-Type: application/json` and `X-Requested-With: Ogiri`. The body is `{"username": …, "password": …, "client": …}`. `client` labels the device (for example `"iPhone"`). For Devise migrations `username` is the email address.

| Case | Status |
| --- | --- |
| Missing `X-Requested-With: Ogiri`, or not JSON | 403 |
| Field missing, blank, contains NUL, or too long (username 255, password 1024, client 255) | 400 |
| Wrong password, unknown or disabled account | 401, `application/problem+json` |
| Session limit reached | 409, `application/problem+json` |
| Session or account store unavailable | 503, `application/problem+json` |
| Success | 201, header `Authorization: Bearer og1_…`, body is the session JSON |

The token appears only in the `Authorization` response header, never in the body.

### Session JSON

```json
{"id":"c4b9fe18-7b0d-472e-a37a-2e8fddcf334c",
 "subject":{"realm":"users","tenantId":"","subjectId":"demo@example.com"},
 "client":"iPhone",
 "createdAt":"2026-10-10T21:05:40.349Z",
 "expiresAt":"2026-10-17T21:05:40.349Z"}
```

Timestamps are ISO-8601 UTC with a trailing `Z` and at most millisecond precision; implementations may omit a zero fraction. Clients parse them as ordinary ISO-8601.

### Authenticated requests

Send `Authorization: Bearer og1_…`. Only the header is accepted. Tokens in query strings, form bodies or cookies are ignored.

| Case | Status |
| --- | --- |
| No credentials on a protected route | 401, `WWW-Authenticate: Bearer…` |
| Malformed, unknown, expired or revoked token; account missing or disabled | 401, `WWW-Authenticate: Bearer error="invalid_token"…` |
| More than one `Authorization` header | 400 |
| Authenticated but the route needs a role the account lacks | 403 |
| Account store unavailable | 5xx, never 2xx |

| Endpoint | Success | Other |
| --- | --- | --- |
| `GET {base}/session` | 200, the current session JSON | |
| `GET {base}/sessions` | 200, array of this subject's live sessions | |
| `DELETE {base}/sessions/{id}` | 204 | 404 if not owned by this subject or missing; 400 if `id` is not a UUID |
| `DELETE {base}/sign-out` | 204, revokes the current session | |
| `DELETE {base}/sessions` | 204, revokes every session of this subject | |

Roles come from the account loaded on each request. A role change or account lock takes effect on the next request without signing out.

## Sample applications

Each sample in `examples/` uses the Devise-shaped [`fixtures/devise-users.sql`](fixtures/devise-users.sql) as its account directory, uses `subjectId = email`, and exposes:

- `GET /me`: 200 `text/plain`, body is the subject id.
- `GET /admin`: 200 for accounts with role `admin`, 403 otherwise.

## Migrating from DeviseTokenAuth

| DeviseTokenAuth | Ogiri |
| --- | --- |
| `POST /auth/sign_in` `{email, password}` | `POST /auth/sign-in` `{username: email, password, client}` plus `X-Requested-With: Ogiri` |
| Response headers `access-token`, `client`, `uid`, `expiry`, `token-type` | One header: `Authorization: Bearer og1_…` |
| Store all five headers and send them back on every request | Store the one header value and send it back |
| Token rotation on each request (`change_headers_on_each_request`) | None: fixed-lifetime token, immediate server-side revocation |
| `GET /auth/validate_token` | `GET /auth/session` |
| `DELETE /auth/sign_out` | `DELETE /auth/sign-out` |
| Tokens in `users.tokens` JSON column | `ogiri_sessions` table (the `tokens` column becomes unused) |
| `encrypted_password` (bcrypt `$2a$…`) | Verified as-is; no password reset needed |

Existing DeviseTokenAuth tokens cannot be converted (they are stored as bcrypt hashes of rotating secrets), so each user signs in once after the switch. Registration, password reset, confirmation and OmniAuth stay in the application. See the README's non-goals.
