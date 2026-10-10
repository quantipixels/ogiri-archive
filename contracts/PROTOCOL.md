# Ogiri protocol, version 2: DeviseTokenAuth parity

Status: ready (revision 2.1, 2026-10-10). Every Ogiri library (Spring Boot, FastAPI, Phoenix) implements this contract. It follows DeviseTokenAuth (DTA) at commit `b02076a` with Devise at `05811fb`, so existing DTA frontends keep working when a Rails backend is replaced. Deliberate differences are listed in [Differences from DTA](#differences-from-dta). The executable form is [`conformance/`](conformance): a library conforms when that suite passes against its sample application.

Each behaviour has an id (for example `S3`) that tickets, tests and reviews cite. Examples are normative unless marked *illustrative*.

## 1. Terms

- **Account**: one row of the user table (§9). Identified on the wire by `uid` (for provider `email`, the email address).
- **Client**: one signed-in device. Each sign-in creates a client id; a client has one live access token.
- **Auth headers**: `access-token`, `client`, `uid`, `expiry`, `token-type`, plus `Authorization` (§2).
- **Base path**: where the library mounts, default `/auth`. Paths below are relative to it.
- **Redirect allowlist**: configured URL patterns that `redirect_url` and `confirm_success_url` must match; `*` matches any run of characters. When the list is empty, any URL is allowed (DTA's default).
- **Paranoid mode**: Devise's `paranoid`; when on, responses never reveal whether an email exists. Default off.

## 2. Credentials (H)

- **H1 Token format.** `access-token` is 32 bytes from a cryptographically secure generator, encoded as unpadded base64url (43 characters). `client` is 16 random bytes, unpadded base64url (22 characters); a request `client` longer than 64 characters never authenticates. Storage keeps only `SHA-256(access-token)`; the raw token is never stored or logged.
- **H2 Request sources.** A request authenticates from, in order of precedence per field: the `access-token`, `client` and `uid` request headers; then `Authorization: Bearer <base64 of a JSON object with those three keys>` (standard base64, last whitespace-separated word, malformed → ignored). Query-string, form-body and cookie values are ignored (cookies only under §8 K1). A missing `client` means `default` (DTA).
- **H3 Validity.** A request is authenticated only if an account with that `uid` exists and is active (§9), and a live session for that account has that `client` and that access token. Expired sessions never authenticate; expiry is fixed, not sliding. All three values are compared; a token alone, or a matching token with another account's `uid`, fails. Lookup time must not reveal whether a `uid` exists.
- **H4 Response headers.** Every authenticated response, and every response that issues a token, carries `access-token`, `client`, `uid`, `expiry` (Unix seconds, decimal string), `token-type: Bearer`, and `Authorization: Bearer <base64 JSON of those five>`. Responses also carry `Cache-Control: no-store`. Browser clients read them only if CORS exposes them; each library offers a one-line way to expose them.
- **H5 Rotation.** Off by default (difference D-R). When on (`change-headers-on-each-request`), each authenticated request issues a new access token for the client and returns it per H4; the previous token stays valid for `batch-request-buffer-throttle` (default 5 s) so concurrent requests from one client succeed; responses inside that window return the headers unchanged with blank `access-token` and `expiry`, as DTA does. When off, H4 returns the current token unchanged.
- **H6 Device cap.** At most `max-number-of-devices` (default 10) live clients per account. Issuing one more removes the client with the earliest expiry (DTA `clean_old_tokens`). Concurrent sign-ins never leave more than the cap.
- **H7 Lifetime.** `token-lifespan`, default 2 weeks.
- **H8 Protected routes.** A route the application protects returns 401 `{"errors":["You need to sign in or sign up before continuing."]}` when not authenticated, and 403 when authenticated without a required role. Store outages return 503, never 2xx or anonymous access.

## 3. Sessions (S)

| Id | Request | Result |
| --- | --- | --- |
| S1 | `POST /sign_in` with `email`, `password` (JSON or form) | 200 `{"data": <account, token view §9>}` and new auth headers (H4) for a new client; device cap applied (H6) |
| S2 | S1 with wrong password, unknown email, or missing field | 401 `{"success":false,"errors":["Invalid login credentials. Please try again."]}`. Unknown email takes about the same time as a wrong password |
| S3 | S1 for an unconfirmed account (§7, confirmable on) | 401 `{"success":false,"errors":["A confirmation email was sent to your account at '<email>'. You must follow the instructions in the email before your account can be activated"]}` |
| S4 | S1 for a locked account | 401 `{"success":false,"errors":["Your account has been locked due to an excessive number of unsuccessful sign in attempts."]}` |
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
| R6 | `PUT`/`PATCH /` authenticated with permitted account fields | 200 `{"status":"success","data": <account, full view>}`. Changing `password` requires `current_password` (and `password_confirmation`) unless the account is in a password-reset window (P3). With `check-current-password-before-update = attributes`, every update requires it |
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
| P4 | `PUT`/`PATCH /password` authenticated with `password`, `password_confirmation` (plus `current_password` unless `allow_password_change` is set) | 200 `{"success":true,"data": <account, full view>,"message":"Your password has been successfully updated."}`; clears `allow_password_change`. With `require-client-password-reset-token`, a valid `reset_password_token` replaces authentication |
| P5 | P4 errors | Not authenticated: 401 `{"success":false,"errors":["Unauthorized"]}`. Provider not `email`: 422 `["This account does not require a password. Sign in using your '<provider>' account instead."]`. Missing fields: 422 `["You must fill out the fields labeled 'Password' and 'Password confirmation'."]`. Validation: 422 `{"success":false,"errors":{…,"full_messages":[…]}}` |
| P6 | After a password change, with `remove-tokens-after-password-reset` | Every client except the most recently issued ends |

## 7. Confirmation, unlock and email (C, U, E)

Confirmable and lockable are off by default (DTA's generated model enables neither) and switched on per library configuration.

| Id | Request | Result |
| --- | --- | --- |
| C1 | `GET /confirmation?confirmation_token=…&redirect_url=…` | Valid: account confirmed, 302 to `redirect_url` with `account_confirmation_success=true` (plus auth query parameters as in P3 when the request was authenticated). Invalid: 302 with `account_confirmation_success=false` when a redirect URL is known, else 404 |
| C2 | `POST /confirmation` with `email`, `redirect_url` | Resends instructions. 200 `{"success":true,"message":"An email has been sent to '<email>' containing instructions for confirming your account."}`; paranoid variant `"If your email address exists in our database, you will receive an email with instructions for how to confirm your email address in a few minutes."`. No email: 401 `["You must provide an email address."]`. Unknown (not paranoid): 404 `["Unable to find user with email '<email>'."]` |
| U1 | Lockable on | After `maximum-attempts` (default 20) consecutive failed sign-ins the account locks (S4). Unlock by email (U2/U3) and/or after `unlock-in` (default 1 h) per `unlock-strategy` (default both). A successful sign-in resets the count |
| U2 | `POST /unlock` with `email` | Sends unlock instructions. 200 `{"success":true,"message":"An email has been sent to '<email>' containing instructions for unlocking your account."}`; paranoid `"If your account exists, you will receive an email with instructions for how to unlock it in a few minutes."`. No email: 401 `["You must provide an email address."]`. Unknown (not paranoid): 404 `["Unable to find user with email '<email>'."]` |
| U3 | `GET /unlock?unlock_token=…` | Valid: unlocks, issues a client, 302 to `/` with `unlock=true` and the P3 auth query parameters. Invalid: 404 |
| E1 | Emails | Reset, confirmation and unlock emails go to the account's address (reconfirmation: the new address) and contain a link to P3, C1 or U3 respectively, carrying the raw one-time token plus `redirect_url` and `config` where given. Raw one-time tokens are stored only as digests. Delivery uses the platform's standard mail mechanism; the application can replace the content or delivery |

## 8. Optional DTA features (K, O, G)

- **K1 Cookie mode** (`cookie-enabled`, default off): sign-in and authenticated responses also set cookie `auth_cookie` (configurable name and attributes) holding the auth-header JSON, the `Authorization` response header is omitted, the cookie is accepted as a credential source (H2), and sign-out deletes it.
- **O1 OmniAuth**: `GET /:provider` starts the provider's flow; `GET|POST /:provider/callback` finds or creates the account by `provider` + provider `uid`, issues a client, and returns credentials to `auth_origin_url` (allowlisted) as query parameters with `blank=true`, or via the DTA new-window `postMessage` page when `omniauth_window_type=newWindow`; failure redirects with `message`. Each library uses its platform's standard OAuth client.
- **G1 Several account types**: a library can be mounted more than once (for example users at `/auth`, admins at `/admin_auth`) with separate tables or realms; credentials of one type never authenticate as another.

## 9. Accounts (A)

- **A1 Table.** The default store is the DTA users table: `provider` (default `email`), `uid`, `encrypted_password` (bcrypt), `email`, `name`, `nickname`, `image`, `reset_password_token`, `reset_password_sent_at`, `allow_password_change`, `confirmation_token`, `confirmed_at`, `confirmation_sent_at`, `unconfirmed_email`, optional lockable columns `failed_attempts`, `unlock_token`, `locked_at`, and timestamps. A migrated Rails database works unchanged; Ogiri ignores its `tokens` column. Applications may replace the store with their own user model through the library's extension point.
- **A2 Passwords.** bcrypt (`$2a$`, `$2b$`, `$2y$`) hashes verify unchanged; new hashes are bcrypt readable by Devise (cost 12 by default; Devise `pepper` unsupported).
- **A3 Account views.** *Full view* (R, P responses): every column except `encrypted_password`, `reset_password_token`, `reset_password_sent_at`, `remember_created_at`, `sign_in_count`, `current_sign_in_at`, `last_sign_in_at`, `current_sign_in_ip`, `last_sign_in_ip`, `password_salt`, `confirmation_token`, `confirmed_at`, `confirmation_sent_at`, `remember_token`, `unconfirmed_email`, `failed_attempts`, `unlock_token`, `locked_at`, `tokens`. *Token view* (S1, V1): the full view without `created_at` and `updated_at`. Keys are the column names (snake_case); timestamps are ISO-8601 UTC. Applications can add or remove fields.
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
| D-M | In-flight reset/confirm/unlock links from Rails | Not carried over | Devise digests them with the Rails secret |

## 14. Sample applications

Each sample uses the fixture [`fixtures/devise-users.sql`](fixtures/devise-users.sql), sends mail to the SMTP server given by `OGIRI_SMTP_HOST`/`OGIRI_SMTP_PORT` (the suite reads it through Mailpit's HTTP API), and exposes `GET /me` (200 `{"uid": …}` for a signed-in account, H8 otherwise) and `GET /admin` (role `admin`, else 403).

## Migrating from DeviseTokenAuth

Point the library at the existing database, apply the Ogiri session migration, and set the same DTA options the Rails app used. Frontends keep their DTA client library. Passwords verify unchanged; each user signs in once because DTA's stored tokens can't be converted (D-S).
