# Ogiri Spring HTTP conformance suite

The suite asserts PROTOCOL rev 3.5 for the Ogiri Spring implementation and keeps the pinned Rails 8 + DTA `b02076a` + Devise `05811fb` wire behavior as the reference oracle. **Read [ORACLE.md](ORACLE.md)** for every round-1 disagreement and its rev-3 resolution. Deliberate differences have §13-labelled `ogiri_only` checks (skipped with `--reference`); native Rails expectations have `reference_only` checks (skipped on Ogiri). Adopted DTA behavior stays shared. Open contract questions are explicit skips, never fabricated expectations.

## Run the oracle

Run from the repository root. Each command builds the pinned image, starts fresh PostgreSQL and Mailpit, runs that profile against two Rails instances sharing its database, and removes the owned containers. No host Ruby is required.

```sh
contracts/conformance/run.sh --profile default --cross-backend
contracts/conformance/run.sh --profile strict --cross-backend
contracts/conformance/run.sh --profile reset-token --cross-backend
contracts/conformance/run.sh --profile rotation --cross-backend
contracts/conformance/run.sh --profile cookie --cross-backend
```

Use `--profile all` for all five. `--no-build` reuses the image; normal runs rebuild using Docker's cache. Output/JUnit and sample logs go to ignored `contracts/conformance/results/`. Do not commit that directory, `.venv`, `node_modules`, or caches.

Additional configuration branches:

```sh
contracts/conformance/run.sh --profile strict --cross-backend --setting OGIRI_PARANOID=false
contracts/conformance/run.sh --profile strict --cross-backend --setting OGIRI_DEFAULT_CONFIRM_SUCCESS_URL=https://client.example.test/confirm --setting OGIRI_DEFAULT_PASSWORD_RESET_URL=https://client.example.test/reset
```

## Run the Spring sample

Give the runner a **foreground** sample command; it supplies `PORT` and the env interface below, and stops the process group between profiles and on exit. Commands run from the repository root. No shell expansion of user-supplied commands is performed outside the explicitly requested shell command.

```sh
contracts/conformance/run.sh --profile all --sample-command 'mise exec java@temurin-17.0.17+10 -- python3 examples/spring-app/run.py'
contracts/conformance/run.sh --profile all --sample-command 'first sample start command' --peer-command 'second sample start command'
```

The second form is AC2: independently issued clients authenticate in both directions and sign-out revocation propagates across one database. `--cross-backend` alone starts a second Rails reference; two Spring instances use the sample and peer commands. Use `--reference` only for real DTA, never to hide failures in Ogiri.

For samples already running against a **disposable fixture database**:

```sh
uv run --project contracts/conformance pytest contracts/conformance --base-url http://localhost:APP_PORT --database-url postgresql://USER@localhost:DB_PORT/DATABASE --mailpit-url http://localhost:MAILPIT_PORT --profile default
```

Add `--peer-url` for AC2 and `--reference` for the oracle. Add `--setting OGIRI_NAME=value` when a running sample differs from the profile table. Tests reset the users and session tables and clear Mailpit before each test. Do not point this at a persistent/production database. The runner uses PostgreSQL 17; this version does not include a MySQL mutation adapter.

The sole read-only probe is `--read-only -k 'V2_invalid_validate or S5_get_signin'`; those two anonymous GET tests bypass database and mailbox fixtures. Other tests reject read-only mode. Empty database/mail URLs can be supplied for that probe.

## Sample env interface

All samples implement these variables; booleans are lowercase `true`/`false`, durations are integer seconds, and unset or empty default URLs mean no default.

| Variable | Baseline value / meaning |
| --- | --- |
| `OGIRI_DATABASE_URL` | PostgreSQL URL, supplied by runner |
| `OGIRI_SMTP_HOST` | SMTP hostname, supplied by runner |
| `OGIRI_SMTP_PORT` | SMTP port, supplied by runner |
| `PORT` | HTTP listen port, supplied by runner |
| `OGIRI_CHANGE_HEADERS_ON_EACH_REQUEST` | `false`; explicitly set for D-R |
| `OGIRI_MAX_NUMBER_OF_DEVICES` | `10` |
| `OGIRI_TOKEN_LIFESPAN_SECONDS` | `1209600` (two weeks) |
| `OGIRI_BATCH_REQUEST_BUFFER_THROTTLE_SECONDS` | `5` |
| `OGIRI_CONFIRMABLE` | `false` |
| `OGIRI_LOCKABLE` | `false` |
| `OGIRI_MAXIMUM_ATTEMPTS` | `20` |
| `OGIRI_UNLOCK_STRATEGY` | `both` (`email`, `time`, `both`, `none`) |
| `OGIRI_UNLOCK_IN_SECONDS` | `3600` |
| `OGIRI_PARANOID` | `false` |
| `OGIRI_REDIRECT_ALLOWLIST` | empty; comma-separated wildcard patterns |
| `OGIRI_DEFAULT_CONFIRM_SUCCESS_URL` | empty |
| `OGIRI_DEFAULT_PASSWORD_RESET_URL` | empty |
| `OGIRI_REMOVE_TOKENS_AFTER_PASSWORD_RESET` | `false` |
| `OGIRI_REQUIRE_CLIENT_PASSWORD_RESET_TOKEN` | `false` |
| `OGIRI_CHECK_CURRENT_PASSWORD_BEFORE_UPDATE` | `false` (`false`, `password`, `attributes`); native DTA default |
| `OGIRI_COOKIE_ENABLED` | `false` |
| `OGIRI_RESET_PASSWORD_WITHIN_SECONDS` | `21600` (six hours) |

`profiles.py` is the executable source of these values. The baseline includes every variable. Each profile applies only the following overrides:

| Profile | Overrides relative to baseline |
| --- | --- |
| `default` | none (rotation is explicitly off for D-R; confirmable/lockable off) |
| `strict` | `CONFIRMABLE=true`, `LOCKABLE=true`, `MAXIMUM_ATTEMPTS=3`, `UNLOCK_IN_SECONDS=30`, `PARANOID=true`, `REDIRECT_ALLOWLIST=https://*.example.test/*`, `REMOVE_TOKENS_AFTER_PASSWORD_RESET=true`, `CHECK_CURRENT_PASSWORD_BEFORE_UPDATE=attributes`, `MAX_NUMBER_OF_DEVICES=3` |
| `reset-token` | `REQUIRE_CLIENT_PASSWORD_RESET_TOKEN=true` |
| `rotation` | `CHANGE_HEADERS_ON_EACH_REQUEST=true` |
| `cookie` | `COOKIE_ENABLED=true` |

Override names in the table have the `OGIRI_` prefix. The Rails adapter maps seconds to Devise/DTA durations, the allowlist to DTA `redirect_whitelist`, and `attributes` to Ruby `:attributes`. Strict confirmable enables DTA's reconfirmation support. This configured oracle does not test DTA's unconfigured rotation default. The D-R check verifies the configured default profile; testing an implementation's unconfigured default needs launching it without that variable.

## Coverage and proof boundary

Names cite H1–H8, S1–S8, V1–V2, R1–R11, P1–P6, C1–C2, U1–U3, E1, K1, G1, A1–A5, D1–D3, T1–T5; O1 is an explicit skip. Every test applies to all profiles unless decorated with `profiles`. Reference skips identify §13 D-Q, D-R, D-S, D-T, D-H, D-L, D-B, D-C, D-K, D-M/E1, D-A, D-V and U2 unlocked-account gating, device APIs and T2/T5 storage semantics. D-P needs configuration/source review; there is no pepper setting in the HTTP sample interface. Configured redirect defaults are exercised by the second variant above. Visible S3/S4 and non-paranoid confirmation/unlock responses are exercised by the first variant. Optional AC2 skips only when no peer URL exists. H8's store-outage check needs the runner-owned database container; it stops/restarts only that container and restores readiness in `finally`.

HTTP assertions use the real response. Account views require exact A3 default column sets on Ogiri; the native reference additionally includes the fixture `role` column (D-V). IDs and creation timestamps are generated values, checked for type/UTC syntax. Tests do not reimplement the Rails controllers. Email links are read through Mailpit's HTTP API, recipients/config/redirect/token storage are checked (confirmation is raw in pinned Devise; Ogiri checks all three SHA-256 hex digests), and links are requested without following external redirects. U3's malformed DTA `Location` needs a raw httpx transport because httpx's high-level client rejects it even when redirects are disabled.

Expiry, reset windows, lock duration and device eviction change database timestamps. Only the batch-buffer test waits for real time; bounded container/database readiness waits are infrastructure checks. Oracle session expiry changes `users.tokens`; Ogiri expiry changes `ogiri_sessions`. Tests are sequential; do not use pytest-xdist against one database.

T1/T4 verify separate session storage, SHA-256 digest and subject lock key. T2 verifies visibility through independent connections and DB-clock plausibility. **HTTP alone does not prove independent commits inside a surrounding application transaction, absence of startup DDL, constant-time uid lookup, CSPRNG quality, or unknown-email timing equivalence.** Those require implementation/instrumented checks. AC2 verifies the real next-request sign-out case; it does not establish every possible concurrent transaction interleaving.

## Real JavaScript client (AC3)

`client.mjs` calls the published `vanilla-token-auth@1.0.6` methods `submitRegistration`, `submitLogin`, `validateToken`, and `signOut`; pytest runs Node and asserts the actual four HTTP requests and post-sign-out rejection. Strict follows the confirmation email first; cookie transport uses the actual auth cookie and echoes the real XSRF-TOKEN in X-XSRF-TOKEN for unsafe requests when supplied by Ogiri. Native Node Fetch supplies HTTP, the documented `httpWrapper` supplies header interception/cookie storage, and a small browser-facility adapter supplies local storage and timers. No authentication endpoint or auth library method is mocked.

Chosen because [DTA recommends vanilla-token-auth](https://github.com/lynndylanhurley/devise_token_auth#client-libraries) and [upstream documents Fetch/header interception and cookie transport](https://github.com/theblang/vanilla-token-auth#readme). It needs only `js-cookie`, avoiding the old Axios dependency in `devise-token-auth-client@0.0.55`. Version and integrity are pinned in `package-lock.json`; installation scripts are disabled. **Active current maintenance has not been established**: the latest npm release is from 2022. This is proven published-client interoperability, not a claim that the client is actively maintained in 2026.

## Static checks

```sh
uv run --project contracts/conformance ruff check contracts/conformance
uv run --project contracts/conformance ruff format --check contracts/conformance
uv run --project contracts/conformance pyright --project contracts/conformance
```

Ruff enables security (`S`), annotations, imports, bugbear, simplification and modern Python rules. Only necessary test-assert/public-fixture-credential and fixed local subprocess exceptions are scoped to tests/runner. Pyright uses strict mode. Dependencies are pytest/httpx and the small psycopg binary DB adapter; tooling is in the dev group.

Session mutation helpers use epoch milliseconds for Ogiri and seconds in reference users.tokens. T5 checks database-clock bounds and expiry-header flooring; P6 deliberately separates expiry ordering from (created_at, id), including a creation-time tie. D3 remains revoke-all pending the T5 wording correction. See ORACLE for C1/R11, R6 and cookie contract questions.

Rev 3.2/3.3 adds strict-profile D-A checks using `https://*.example.test/*`: deceptive fragment/query/userinfo redirects return the R5/P3 422 shape, while `https://app.example.test/reset` remains allowed. Default A3 views omit the fixture role unless explicitly configured; protected-route role checks still use that column. `PATCH /auth` clearing an earlier reset link and applying P6 is shared DTA proof. U2 sending no unlock mail for an unlocked account is Ogiri-only: pinned DTA sends mail anyway, with a separate reference observation. D-E's mail-outage response difference is documented in ORACLE; this round does not inject SMTP delivery failures.

The Ogiri cookie profile bootstraps sign-in and registration CSRF from `GET /auth/sign_in` before POST sign-in. Dedicated K1 negative tests disable that helper to prove missing tokens reject without creating a session; the reference profile keeps native DTA login behavior. H2/K1 cases also exercise malformed/non-string Bearer fields, partial named headers, full Bearer precedence and cross-realm cookie rejection.

Run a specific profile through the repository gate with `bash scripts/platform/parity.sh full --profile cookie --sample-command '<sample launcher>' --no-build` (use `strict` for the second profile). The runner creates uniquely named throwaway containers and cleans them; local HTTP cookie runs must configure the sample's Secure cookie policy for local development.

Rev 3.5 K1/D-K registration cases exercise JSON and HTML forms in both realms: missing CSRF returns the exact 403 body before any account/session insert; a valid echo issues the auth cookie. The published-client adapter bootstraps CSRF before registration. Cookie-mode batch responses leave the auth cookie unchanged.

Run the combined cookie/rotation regression explicitly in addition to the five profiles:

```sh
contracts/conformance/run.sh --profile cookie --sample-command '<sample launcher>' \
  --setting OGIRI_CHANGE_HEADERS_ON_EACH_REQUEST=true \
  -- -k test_K1_H5_late_batch_preserves_rotated_auth_cookie
```

That case skips when rotation is disabled; the explicit combined run must execute it.
