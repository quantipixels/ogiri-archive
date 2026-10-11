# Ogiri v2 HTTP parity suite

The expected wire behavior comes from real Rails 8 + DTA `b02076a` + Devise `05811fb`, with exact response keys/messages, headers and mail links. **Read [ORACLE.md](ORACLE.md) before changing a library to match a failing test:** several rev 2.1 contract claims disagree with DTA, including error cases that return 500. The contract is untouched. The suite follows the observed oracle for those cases; Ogiri's deliberate transport/storage differences and added device APIs have separate `ogiri_only` checks.

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

## Run another sample

Give the runner a **foreground** sample command; it supplies `PORT` and the env interface below, and stops the process group between profiles and on exit. Commands run from the repository root. No shell expansion of user-supplied commands is performed outside the explicitly requested shell command.

```sh
contracts/conformance/run.sh --profile all --sample-command 'your sample start command'
contracts/conformance/run.sh --profile all --sample-command 'first sample start command' --peer-command 'second sample start command'
```

The second form is AC2: independently issued clients authenticate in both directions and sign-out revocation propagates across one database. `--cross-backend` alone starts a second Rails reference; cross-language AC2 needs the two library commands. Use `--reference` only for real DTA, never to hide failures in Ogiri.

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
| `strict` | `CONFIRMABLE=true`, `LOCKABLE=true`, `MAXIMUM_ATTEMPTS=3`, `UNLOCK_IN_SECONDS=30`, `PARANOID=true`, `REDIRECT_ALLOWLIST=https://client.example.test/*`, `REMOVE_TOKENS_AFTER_PASSWORD_RESET=true`, `CHECK_CURRENT_PASSWORD_BEFORE_UPDATE=attributes`, `MAX_NUMBER_OF_DEVICES=3` |
| `reset-token` | `REQUIRE_CLIENT_PASSWORD_RESET_TOKEN=true` |
| `rotation` | `CHANGE_HEADERS_ON_EACH_REQUEST=true` |
| `cookie` | `COOKIE_ENABLED=true` |

Override names in the table have the `OGIRI_` prefix. The Rails adapter maps seconds to Devise/DTA durations, the allowlist to DTA `redirect_whitelist`, and `attributes` to Ruby `:attributes`. Strict confirmable enables DTA's reconfirmation support. This configured oracle does not test DTA's unconfigured rotation default. The D-R check verifies the configured default profile; testing an implementation's unconfigured default needs launching it without that variable.

## Coverage and proof boundary

Names cite H1–H8, S1–S8, V1–V2, R1–R11, P1–P6, C1–C2, U1–U3, E1, K1, G1, A1–A5, D1–D3, T1–T4; O1 is an explicit skip. Every test applies to all profiles unless decorated with `profiles`. Reference skips identify D-Q, D-R, D-S, the Ogiri device APIs, and T2 storage semantics. Configured redirect defaults are exercised by the second variant above. Visible S3/S4 and non-paranoid confirmation/unlock responses are exercised by the first variant. Optional AC2 skips only when no peer URL exists. H8's store-outage check needs the runner-owned database container; it stops/restarts only that container and restores readiness in `finally`.

HTTP assertions use the real response. Account views require exact column sets; IDs and creation timestamps are generated values, checked for type/UTC syntax. Tests do not reimplement the Rails controllers. Email links are read through Mailpit's HTTP API, recipients/config/redirect/token storage are checked (confirmation is raw in pinned Devise), and links are requested without following external redirects. U3's malformed DTA `Location` needs a raw httpx transport because httpx's high-level client rejects it even when redirects are disabled.

Expiry, reset windows, lock duration and device eviction change database timestamps. Only the batch-buffer test waits for real time; bounded container/database readiness waits are infrastructure checks. Oracle session expiry changes `users.tokens`; Ogiri expiry changes `ogiri_sessions`. Tests are sequential; do not use pytest-xdist against one database.

T1/T4 verify separate session storage, SHA-256 digest and subject lock key. T2 verifies visibility through independent connections and DB-clock plausibility. **HTTP alone does not prove independent commits inside a surrounding application transaction, absence of startup DDL, constant-time uid lookup, CSPRNG quality, or unknown-email timing equivalence.** Those require implementation/instrumented checks. AC2 verifies the real next-request sign-out case; it does not establish every possible concurrent transaction interleaving.

## Real JavaScript client (AC3)

`client.mjs` calls the published `vanilla-token-auth@1.0.6` methods `submitRegistration`, `submitLogin`, `validateToken`, and `signOut`; pytest runs Node and asserts the actual four HTTP requests and post-sign-out rejection. Strict follows the confirmation email first; cookie transport uses the actual DTA auth cookie. Native Node Fetch supplies HTTP, the documented `httpWrapper` supplies header interception/cookie storage, and a small browser-facility adapter supplies local storage and timers. No authentication endpoint or auth library method is mocked.

Chosen because [DTA recommends vanilla-token-auth](https://github.com/lynndylanhurley/devise_token_auth#client-libraries) and [upstream documents Fetch/header interception and cookie transport](https://github.com/theblang/vanilla-token-auth#readme). It needs only `js-cookie`, avoiding the old Axios dependency in `devise-token-auth-client@0.0.55`. Version and integrity are pinned in `package-lock.json`; installation scripts are disabled. **Active current maintenance has not been established**: the latest npm release is from 2022. This is proven published-client interoperability, not a claim that the client is actively maintained in 2026.

## Static checks

```sh
uv run --project contracts/conformance ruff check contracts/conformance
uv run --project contracts/conformance ruff format --check contracts/conformance
uv run --project contracts/conformance pyright contracts/conformance
```

Ruff enables security (`S`), annotations, imports, bugbear, simplification and modern Python rules. Only necessary test-assert/public-fixture-credential and fixed local subprocess exceptions are scoped to tests/runner. Pyright uses strict mode. Dependencies are pytest/httpx and the small psycopg binary DB adapter; tooling is in the dev group.
