# Ogiri protocol, version 2: DeviseTokenAuth parity

Status: ready (revision 3.4, 2026-10-11; 3.1 settles the batch-response `Authorization` value in H5 from the DTA oracle; 3.2 makes redirect-allowlist matching per URL part, D-A; 3.3 makes account views allowlists (D-V), aligns R6 password changes and unlock gating with Devise, and keeps paranoid responses independent of mail delivery (D-E); 3.4 keeps provider-issued `uid` values when an OAuth account's email changes, A7). Every Ogiri library (Spring Boot, FastAPI, Phoenix) implements this contract. It follows DeviseTokenAuth (DTA) at commit `b02076a` with Devise at `05811fb`, so existing DTA frontends keep working when a Rails backend is replaced. Deliberate differences are listed in [Differences from DTA](#differences-from-dta). The executable form is [`conformance/`](conformance): a library conforms when that suite passes against its sample application.

Each behaviour has an id (for example `S3`) that tickets, tests and reviews cite. Examples are normative unless marked *illustrative*. Lengths are counted in Unicode code points.

## 1. Terms

- **Account**: one row of the user table (§9). Identified on the wire by `uid` (for provider `email`, the email address; for any other provider, the provider-issued id, which never changes, A7).
- **Client**: one signed-in device. Each sign-in creates a client id; a client has one live access token.
- **Auth headers**: `access-token`, `client`, `uid`, `expiry`, `token-type`, plus `Authorization` (§2).
- **Base path**: where the library mounts, default `/auth`. Paths below are relative to it.
- **Redirect allowlist**: configured URL patterns that `redirect_url`, `confirm_success_url` and `auth_origin_url` must match. When the list is empty, any URL is allowed (DTA's default). Matching is per URL part, not on the raw string (difference D-A). The candidate is parsed first. It must be an absolute `http` or `https` URL with no userinfo (`user@`); otherwise it is not allowed. Its scheme must equal the pattern's. Its host is compared case-insensitively, and `*` there matches only hostname characters (letters, digits, `-`, `.`). Its port, with defaults filled in, must equal the pattern's, unless the pattern's port is `*`. The rest (path, query and fragment) is matched with `*` as any run of characters. So `https://*.example.com/*` allows `https://app.example.com/reset` and never `https://evil.test/#.example.com/`.
- **Paranoid mode**: Devise's `paranoid`; when on, responses never reveal whether an email exists. Default off.

## 2. Credentials (H)

- **H1 Token format.** `access-token` is 32 bytes from a cryptographically secure generator, encoded as unpadded base64url (43 characters). `client` is 16 random bytes, unpadded base64url (22 characters); a request `client` longer than 64 characters never authenticates. Storage keeps only `SHA-256(access-token)`; the raw token is never stored or logged.
- **H2 Request sources.** A request authenticates from, in order of precedence per field: the `access-token`, `client` and `uid` request headers; then `Authorization: Bearer <base64 of a JSON object with those three keys>` (standard base64, last whitespace-separated word, malformed → ignored). Query-string, form-body and cookie values are ignored (cookies only under §8 K1). A missing `client` means `default` (DTA).
- **H3 Validity.** A request is authenticated only if an account with that `uid` exists and is active (§9), and a live session for that account has that `client` and that access token. Expired sessions never authenticate; expiry is fixed unless rotation is on (H5). All three values are compared; a token alone, or a matching token with another account's `uid`, fails. Authentication runs the same queries whether or not the `uid` exists.
- **H4 Response headers.** Every authenticated response, and every response that issues a token, carries `access-token`, `client`, `uid`, `expiry` (Unix seconds, decimal string), `token-type: Bearer`, and `Authorization: Bearer <base64 JSON of those five>`. Responses also carry `Cache-Control: no-store` (difference D-H). A response that ends the session it authenticated with (S6, R10, D2 on the current client, D3) carries no auth headers, as DTA skips them after revocation. Browser clients read the headers only if CORS exposes them; each library offers a one-line way to expose them.
- **H5 Rotation.** Off by default (difference D-R). When off, H4 returns the presented token unchanged and nothing is written. When on (`change-headers-on-each-request`), as DTA does (`user.rb:105-179`, `set_user_by_token.rb:102-197`): a presented token is valid if it matches the client's current digest, its previous digest, or its last digest while `now < rotated_at + batch-request-buffer-throttle` (default 5 s). If `rotated_at` is within the buffer, the request is a batch request: nothing rotates, `rotated_at` is set to now, and the response carries `access-token: " "` and `expiry: " "` (one space) with the other H4 headers, while `Authorization` still encodes the presented token and the session's current expiry (DTA builds it in `extend_batch_buffer` before blanking the two headers, `set_user_by_token.rb`), so Bearer-reading clients never store a blank token. Otherwise the request rotates under the client's row lock: last ← previous, previous ← current, current ← a new token's digest, `rotated_at` ← now, `expires_at` ← now + `token-lifespan` (DTA's new token slides expiry); the new token is returned per H4. Times come from the database clock.
- **H6 Device cap.** At most `max-number-of-devices` (default 10) live clients per account. Issuing one more removes the client with the earliest expiry (DTA `clean_old_tokens`). Concurrent sign-ins never leave more than the cap.
- **H7 Lifetime.** `token-lifespan`, default 2 weeks.
- **H9 Public endpoints ignore credentials.** Sign-in, registration (R1), password reset request and link (P1, P3), confirmation (C1, C2) and unlock (U2, U3) behave the same whether the request carries no, stale or invalid auth headers; a stale header never turns a valid sign-in into 401.
- **H10 Separate identities.** An authenticated request's roles come only from the account its credentials resolve to (§9), never merged with an identity established earlier in the same request or from another mechanism.
- **H8 Protected routes.** A route the application protects returns 401 `{"errors":["You need to sign in or sign up before continuing."]}` when not authenticated, and 403 when authenticated without a required role. 403 body: `{"errors":["You are not authorized to access this resource."]}`. Store outages return 503 `{"success":false,"errors":["Authentication service unavailable."]}`, never 2xx or anonymous access; the same 503 body is used wherever this contract says 503.

## 3. Sessions (S)

| Id | Request | Result |
| --- | --- | --- |
| S1 | `POST /sign_in` with `email`, `password` (JSON or form) | 200 `{"data": <account, token view §9>}` and new auth headers (H4) for a new client; device cap applied (H6) |
| S2 | S1 with wrong password, unknown email, or missing field | 401 `{"success":false,"errors":["Invalid login credentials. Please try again."]}`. Unknown email takes about the same time as a wrong password |
| S3 | S1 for an unconfirmed account (§7, confirmable on) | 401 `{"success":false,"errors":["A confirmation email was sent to your account at '<email>'. You must follow the instructions in the email before your account can be activated"]}` In paranoid mode, the S2 body instead |
| S4 | S1 for a locked account | 401 `{"success":false,"errors":["Your account has been locked due to an excessive number of unsuccessful sign in attempts."]}` In paranoid mode, the S2 body instead |
| S5 | `GET /sign_in` | 405 `{"success":false,"errors":["Use POST /sign_in to sign in. GET is not supported."]}` |
| S6 | `DELETE /sign_out` authenticated | 200 `{"success":true}`; that client's token stops working on the next request; other clients unaffected |
| S7 | `DELETE /sign_out` not authenticated | 404 `{"success":false,"errors":["User was not found or was not logged in."]}` |
| S8 | Email matching | Email is trimmed and compared case-insensitively on every email-keyed request (Devise defaults) |

## 4. Token validation (V)

| Id | Request | Result |
| --- | --- | --- |
| V1 | `GET /validate_token` authenticated | 200 `{"success":true,"data": <account, token view>}` plus H4 headers |
| V2 | Not authenticated | 401 `{"success":false,"errors":["Invalid login credentials"]}` |

## 5. Registration (R)

| Id | Request | Result |
| --- | --- | --- |
| R1 | `POST /` with `email`, `password`, `password_confirmation`, optional permitted fields (§9), optional `confirm_success_url` | Account created with provider `email`, `uid` = normalized email. Confirmable off: 200 `{"status":"success","data": <account, full view>}` plus H4 headers (signed in). Confirmable on: 200 same body, no auth headers, confirmation email sent (§7) |
| R2 | R1 failing validation (email format, taken email, password length 6–128, confirmation mismatch) | 422 `{"status":"error","data": <submitted account, full view>,"errors":{"<field>":["<message>"],"full_messages":["<Field> <message>"]}}` |
| R3 | R1 with no permitted fields | 422 `{"success":false,"errors":["Please submit proper sign up data in request body."],"status":"error"}` |
| R4 | R1 with confirmable on and no `confirm_success_url` and no configured default | 422 `{"success":false,"errors":["Missing 'confirm_success_url' parameter."],"status":"error","data":…}` |
| R5 | R1 whose `confirm_success_url` fails the allowlist | 422 `{"success":false,"errors":["Redirect to '<url>' not allowed."],"status":"error","data":…}` |
| R6 | `PUT`/`PATCH /` authenticated with permitted account fields | 200 `{"status":"success","data": <account, full view>}`. `check-current-password-before-update` is `false` by default (DTA): no `current_password` needed. With `password`, changing `password` requires a correct `current_password`; with `attributes`, every update does. A supplied `current_password` is otherwise ignored. A password change here is the same transition as P4: under the account fence (A6) it re-verifies `current_password` against the locked row when one is required, clears `reset_password_token`, `reset_password_sent_at` and `allow_password_change`, and applies P6, as Devise (`clear_reset_password_token`) and DTA do on any password change |
| R7 | R6 failing validation or wrong `current_password` | 422 `{"status":"error","errors":{…, "full_messages":[…]}}` |
| R8 | R6 with no permitted fields | 422 `{"success":false,"errors":["Please submit proper account update data in request body."],"status":"error"}` |
| R9 | R6 / R10 not authenticated | 404 `{"success":false,"errors":["User not found."],"status":"error"}` / `["Unable to locate account for destruction."]` |
| R10 | `DELETE /` authenticated | 200 `{"status":"success","message":"Account with UID '<uid>' has been destroyed."}`; all of the account's sessions end |
| R11 | Email change with confirmable on and reconfirmable (default) | New address stored as `unconfirmed_email`, confirmation sent to it; `email`/`uid` change only after confirmation |

## 6. Passwords (P)

| Id | Request | Result |
| --- | --- | --- |
| P1 | `POST /password` with `email`, `redirect_url` | Reset token generated (valid `reset-password-within`, default 6 h), reset email sent (§7 E1). 200 `{"success":true,"message":"An email has been sent to '<email>' containing instructions for resetting your password."}`; paranoid: `"If your email address exists in our database, you will receive a password recovery link at your email address in a few minutes."` |
| P2 | P1 errors | No email: 401 `{"success":false,"errors":["You must provide an email address."]}`. No redirect URL and no default: 401 `["Missing redirect URL."]`. Disallowed URL: 422 `{"success":false,"errors":["Redirect to '<url>' not allowed."],"status":"error","data":null}`. Unknown email (not paranoid): 404 `["Unable to find user with email '<email>'."]`; paranoid: the P1 success body |
| P3 | `GET /password/edit?reset_password_token=…&redirect_url=…[&config=…]` | Valid token: sets `allow_password_change`, confirms an unconfirmed account, issues a new client, and redirects (302) to `redirect_url` with query `access-token`, `client`, `client_id`, `config`, `expiry`, `reset_password=true`, `token`, `uid` (and `reset_password_token`). With `require-client-password-reset-token`: no client issued; redirect carries only `reset_password_token`. Invalid or expired token: 404. Redirect allowlist applies |
| P4 | `PUT`/`PATCH /password` authenticated with `password`, `password_confirmation` (`current_password` is checked only when `check-current-password-before-update` is not `false` and `allow_password_change` is not set; otherwise ignored, where DTA raises 500 (difference D-B)) | 200 `{"success":true,"data": <account, full view>,"message":"Your password has been successfully updated."}`; clears `allow_password_change`. With `require-client-password-reset-token`, a valid `reset_password_token` replaces authentication |
| P5 | P4 errors | Not authenticated: 401 `{"success":false,"errors":["Unauthorized"]}`. Provider not `email`: 422 `["This account does not require a password. Sign in using your '<provider>' account instead."]`. Missing fields: 422 `["You must fill out the fields labeled 'Password' and 'Password confirmation'."]`. Validation: 422 `{"success":false,"errors":{…,"full_messages":[…]}}` |
| P6 | After a password change, with `remove-tokens-after-password-reset` | Every client except the most recently issued ends |

## 7. Confirmation, unlock and email (C, U, E)

Confirmable and lockable are off by default (DTA's generated model enables neither) and switched on per library configuration.

| Id | Request | Result |
| --- | --- | --- |
| C1 | `GET /confirmation?confirmation_token=…&redirect_url=…` | Valid: account confirmed, 302 to `redirect_url` with `account_confirmation_success=true` ; request credentials are ignored and never add auth parameters (H9 wins over DTA's signed-in branch, difference D-C). Invalid: 302 with `account_confirmation_success=false` when a redirect URL is known, else 404 |
| C2 | `POST /confirmation` with `email`, `redirect_url` | Resends instructions. 200 `{"success":true,"message":"An email has been sent to '<email>' containing instructions for confirming your account."}`; paranoid variant `"If your email address exists in our database, you will receive an email with instructions for how to confirm your email address in a few minutes."`. No email: 401 `["You must provide an email address."]`. Unknown (not paranoid): 404 `["Unable to find user with email '<email>'."]` |
| U1 | Lockable on | After `maximum-attempts` (default 20) consecutive failed sign-ins the account locks (S4). Unlock by email (U2/U3) and/or after `unlock-in` (default 1 h) per `unlock-strategy` (default both). A successful sign-in resets the count |
| U2 | `POST /unlock` with `email` | Sends unlock instructions. 200 `{"success":true,"message":"An email has been sent to '<email>' containing instructions for unlocking your account."}`; paranoid `"If your account exists, you will receive an email with instructions for how to unlock it in a few minutes."`. No email: 401 `["You must provide an email address."]`. Unknown (not paranoid): 404 `["Unable to find user with email '<email>'."]`. Instructions are sent only while the account is locked and `unlock-strategy` includes email (Devise `if_access_locked`); otherwise the response is the same and nothing is sent |
| U3 | `GET /unlock?unlock_token=…` | Valid only while the account is locked and `unlock-strategy` includes email. Valid: unlocks (clearing `unlock_token`, `locked_at` and `failed_attempts`), issues a client, 302 to `/` with `unlock=true` and the P3 auth query parameters. Invalid: 404 |
| E1 | Emails | Reset, confirmation and unlock emails go to the account's address (reconfirmation: the new address) and contain a link to P3, C1 or U3 respectively, carrying the raw one-time token plus `redirect_url` and `config` where given. Raw one-time tokens are stored only as digests. One-time tokens are 32 random bytes as unpadded base64url; their digest is the lowercase hex SHA-256 of the token text, stored in the DTA column (`reset_password_token`, `confirmation_token`, `unlock_token`), so any backend sharing the database accepts a link another issued. Mail is sent after the state change commits, through the platform's standard mail mechanism; the application can replace content or delivery. If delivery fails, the state change stays committed and the response is the 503 body (H8); a retry replaces the one-time token. In paranoid mode a delivery failure is logged and the response is the normal paranoid 200, so no response depends on whether the account exists (difference D-E) |

## 8. Optional DTA features (K, O, G)

- **K1 Cookie mode** (`cookie-enabled`, default off): sign-in and authenticated responses also set cookie `auth_cookie` (configurable name and attributes) holding the auth-header JSON, the `Authorization` response header is omitted, the cookie is accepted as a credential source (H2), and sign-out deletes it. Cookie attributes default to `HttpOnly`, `SameSite=Lax`, `Path=/`, and `Secure` outside local development. Unsafe requests authenticated by the cookie also require the standard double-submit CSRF token (`XSRF-TOKEN` cookie echoed in an `X-XSRF-TOKEN` header); header-authenticated requests never need it (difference D-K).
- **O1 OmniAuth**: `GET /:provider` starts the provider's flow; `GET|POST /:provider/callback` finds or creates the account by `provider` + provider `uid`, issues a client, and returns credentials to `auth_origin_url` (allowlisted) as query parameters with `blank=true`, or via the DTA new-window `postMessage` page when `omniauth_window_type=newWindow`; failure redirects with `message`. Each library uses its platform's standard OAuth client.
- **G1 Several account types**: a library can be mounted more than once (for example users at `/auth`, admins at `/admin_auth`) with separate tables or realms; credentials of one type never authenticate as another.

## 9. Accounts (A)

- **A1 Table.** The default store is the DTA users table: `provider` (default `email`), `uid`, `encrypted_password` (bcrypt), `email`, `name`, `nickname`, `image`, `reset_password_token`, `reset_password_sent_at`, `allow_password_change`, `confirmation_token`, `confirmed_at`, `confirmation_sent_at`, `unconfirmed_email`, optional lockable columns `failed_attempts`, `unlock_token`, `locked_at`, and timestamps. A migrated Rails database works unchanged; Ogiri ignores its `tokens` column. Applications may replace the store with their own user model through the library's extension point.
- **A2 Passwords.** bcrypt (`$2a$`, `$2b$`, `$2y$`) hashes verify unchanged; new hashes are plain bcrypt (no `{bcrypt}` prefix) readable by Devise, cost 12 by default; Devise `pepper` unsupported. As bcrypt-ruby does (`engine.rb:69`), the bcrypt input is the password's UTF-8 bytes truncated to 72 bytes, for hashing and verifying alike.
- **A6 Credential fence.** A sign-in issues a session only if the password it verified is still the account's password when the session is stored, and the account still exists and is active. A password change, reset, account deletion or lock that commits first makes a concurrent sign-in fail (S2/S4) instead of issuing a working session.
- **A3 Account views.** Views are allowlists (difference D-V). *Full view* (R, P responses): `id`, `provider`, `uid`, `email`, `name`, `nickname`, `image`, `allow_password_change`, `created_at`, `updated_at`, plus any column the application names as a view field. This is exactly what DTA returns for the A1 table. A column the application did not name never appears, whatever the table holds; `encrypted_password` and the one-time-token columns can never be named. *Token view* (S1, V1): the full view without `created_at` and `updated_at`. Keys are the column names (snake_case); timestamps are ISO-8601 UTC. Applications can add fields by naming them, or remove default ones.
- **A7 Identity.** `uid` follows `email` only when `provider` is `email`: whenever such an account's email is set or changes (R1, R6, C1 reconfirmation), `uid` becomes the new address. An account with any other provider keeps its provider-issued `uid` when its email changes, so O1 always finds it by `provider` + provider `uid` and no email edit can claim another identity's `uid` (DTA `sync_uid`, `email_provider?`).
- **A4 Active.** An account is active unless locked (§7 U1) or, with confirmable on, unconfirmed. Inactive accounts can't sign in and their existing tokens stop authenticating on the next request.
- **A5 Permitted fields.** Sign-up permits `email`, `password`, `password_confirmation` plus configured extra fields (DTA's `name`, `nickname`, `image` by default); account update additionally permits `current_password`. Unpermitted fields are ignored, never written.

## 10. Device management, an Ogiri addition (D)

| Id | Request | Result |
| --- | --- | --- |
| D1 | `GET /sessions` authenticated | 200 `{"success":true,"data":[{"client","created_at","expiry","current"}]}` for this account's live clients, oldest first |
| D2 | `DELETE /sessions/:client` authenticated | 200 `{"success":true}`; 404 `{"success":false,"errors":["Session not found."]}` if not this account's |
| D3 | `DELETE /sessions` authenticated | 200 `{"success":true}`; every client of the account ends, including the caller's |

## 11. Storage (T)

- **T1** Sessions live in the Ogiri session table, not in the users table. All implementations ship the same schema per database engine from [`schema/`](schema) (`ogiri-<engine>.sql` for sessions, `users-<engine>.sql` for the DTA users table), so one database serves several backends and a token issued by one is accepted by another.
- **T5** Session timestamps (`created_at`, `expires_at`, `rotated_at`) are UTC epoch milliseconds from the database clock; the `expiry` header is `expires_at` divided by 1000, rounded down. D3's "most recently issued" and P6's retained client are the greatest `(created_at, id)`.
- **T4** A session row's `subject_id` is the account's primary key as text, `realm` is the account type (default `users`, see G1), `tenant_id` is empty unless the application uses tenants, and `client` is the DTA client id. The access-token digest is SHA-256 of the token's ASCII text; the subject lock key (row in `ogiri_subject_locks`, locked `FOR UPDATE` to serialize issuance and revoke-all per account) is `SHA-256("ogiri-session-admission-v1" ‖ len(realm) ‖ realm ‖ len(tenant_id) ‖ tenant_id ‖ len(subject_id) ‖ subject_id)`, each part UTF-8 and each length a 4-byte big-endian byte count.
- **T2** Timestamps come from the database clock. Session writes commit independently of any surrounding application transaction; reads never use a stale snapshot. Libraries never run DDL at startup; applications apply the shipped migration.
- **T3** Revocation (sign-out, device removal, account deletion, lock) applies to the next request on every backend sharing the database.

## 12. Libraries (L)

- **L1** Each library is an installable package (Maven starter, PyPI package, Hex package) with release metadata. Adoption is: add the dependency, set configuration, apply the shipped migration, and (only if not using the DTA table) supply the account store.
- **L2** Each library uses its platform's standard mechanisms: Spring Boot auto-configuration, `@ConfigurationProperties`, Spring Security filters and `AuthenticationProvider`, application events and Spring Mail; FastAPI routers, dependencies and settings; Phoenix routers, plugs, behaviours, Ecto and Swoosh.
- **L3** Applications access the signed-in account in the platform's normal way (Spring `@AuthenticationPrincipal` / `Authentication`, a FastAPI dependency, `conn.assigns`), and protect routes and roles with the platform's normal tools (`@PreAuthorize`, dependencies, plugs).
- **L4** Every DTA setting named in this document is configurable under the platform's naming convention, with the DTA default.
- **L5** The sample application in `examples/` uses only the public API.

## 13. Differences from DTA

| Id | DTA | Ogiri | Why |
| --- | --- | --- | --- |
| D-R | Rotation on by default | Off by default (H5); one setting turns it on | Rotation costs a write per request and races under concurrency; immediate server-side revocation already limits a stolen token |
| D-Q | Credentials accepted from query and form parameters | Headers only (H2) | Tokens in URLs leak into logs, history and `Referer` |
| D-S | Tokens in `users.tokens` JSON, bcrypt | Separate session table, SHA-256 (T1) | Row locking for the device cap, cross-backend sharing; 256-bit random tokens need no slow hash |
| D-P | Devise `pepper` | Unsupported | Rarely set; check before migrating |
| D-T | 22-character access tokens (16 random bytes) | 43 characters (32 bytes, H1) | Stronger; clients treat tokens as opaque |
| D-H | `Cache-Control: max-age=0, private, must-revalidate` | `no-store` | Credentials in headers must never be cached |
| D-L | Tokens keep working after the account locks | Inactive accounts' tokens stop on the next request (A4) | Locking must take effect |
| D-B | Some malformed inputs crash with 500 (`Authorization` JSON `null`, `current_password` with the default setting, U3's relative redirect) | The documented error or behaviour instead | DTA bugs are not parity targets |
| D-C | Authenticated confirmation adds auth parameters to C1's redirect | Credentials ignored on C1 (H9) | Public endpoints never mix two identities |
| D-K | Cookie mode without CSRF protection | Double-submit CSRF for cookie-authenticated unsafe requests | Cookies are ambient credentials |
| D-M | In-flight reset/confirm/unlock links from Rails | Not carried over | Devise digests them with the Rails secret |
| D-A | Redirect allowlist globs match the raw URL string, so `https://*.example.com/*` also allows `https://evil.test/#.example.com/` and the redirect carries tokens there | Patterns match the parsed scheme, host and port, and `*` cannot leave the host (§1 Redirect allowlist) | The P3, C1 and O1 redirects carry credentials in the query; a raw-string glob makes any wildcard entry an open redirect |
| D-V | Account JSON is every column except a fixed list, so a column an app adds (an MFA secret, a role flag) is returned on sign-in and validation | Views are allowlists (A3); the A1 table renders identically | A reusable library cannot know which added columns are secret |
| D-E | Paranoid recovery returns 200 for unknown emails but a delivery error for known ones | In paranoid mode delivery failures are logged, and the response is unchanged (E1) | Otherwise a mail outage turns paranoid mode into an account-existence oracle |

## 14. Sample applications

Each sample uses the fixture [`fixtures/devise-users.sql`](fixtures/devise-users.sql), sends mail to the SMTP server given by `OGIRI_SMTP_HOST`/`OGIRI_SMTP_PORT` (the suite reads it through Mailpit's HTTP API), and exposes `GET /me` (200 `{"uid": …}` for a signed-in account, H8 otherwise) and `GET /admin` (role `admin`, else 403).

## Migrating from DeviseTokenAuth

Point the library at the existing database, apply the Ogiri session migration, and set the same DTA options the Rails app used. Frontends keep their DTA client library. Passwords verify unchanged; each user signs in once because DTA's stored tokens can't be converted (D-S).
