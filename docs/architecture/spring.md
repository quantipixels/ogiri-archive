# Spring architecture

Ogiri provides database-backed opaque sessions and devise_token_auth account workflows for Spring Boot 4, Java 17+ and Jackson 3. PostgreSQL and MySQL 8.4 are the database targets. Applications own their account schema, migrations and authorization rules.

## Modules and public API

`ogiri` contains sessions, account workflows, mail and Spring Security integration without a Boot dependency. `ogiri-spring-boot-autoconfigure` binds properties and assembles the beans. The starter is a dependency-only JAR. `ogiri-bom` aligns the three library artifacts without importing build plugins or managing the host's Spring dependencies.

There are 18 declared public top-level types. Package names below share the prefix `com.quantipixels.ogiri`:

- Root: `Subject`, `Session`, `IssuedSession`, `SessionPolicy`, `JdbcSessions`, `SessionLimitException`, `SessionStoreException`.
- `account`: `AccountStore`, `OgiriAccount`, `OgiriAuthorities`.
- `security`: `OgiriAuthentication`, `OgiriConfigurer`, `OgiriRuntime`, `OgiriRealms`.
- `mail`: `OgiriMailer`.
- `spring`: `OgiriAutoConfiguration`, `OgiriProperties`, `OgiriRealmConfiguration`.

Other implementation types live in `internal` packages and are not supported integration APIs. Some public signatures still reference internal types; that does not make those types part of the declared API. The pre-1.0 package moves are listed in the [changelog](../../CHANGELOG.md).

## Accounts and session ownership

The default JDBC `AccountStore` uses a Devise-shaped account table. A custom store must participate in Ogiri's transaction on the same DataSource and supply an immutable `ogiri_generation` of 1–36 characters in each persisted `OgiriAccount`. Generate a fresh value whenever an account is replaced, even if its id is reused. The default schemas generate UUIDs. DTA sessions record the generation; authentication and account mutations check it. New issuance removes sessions from obsolete generations. Low-level `JdbcSessions` callers own their subject lifecycle.

Token authentication finds a realm-scoped session using the client and token digest, then loads the account by stable id and checks generation, exact uid, expiry and current account state. It does not select an account by uid alone. Directory lookup is `findByUid(uid, provider)`; the one-argument shorthand means `email`. A custom account snapshot with no provider value also means `email`; the default JDBC adapter still expects a provider column. No OAuth login flow is supplied.

For email-provider accounts, an email update also updates uid unless confirmation is pending. Other providers retain their uid. With rotation enabled, a uid-changing account update reissues the retained session credential even during a batch request, clears previous token digests and returns the new uid and token. With rotation disabled, the token remains and the response carries the updated uid.

`OgiriAccount` implements `UserDetails`; use it with `@AuthenticationPrincipal`. An `OgiriAuthorities` bean maps private account columns to Spring authorities. Wire views contain standard DTA resource fields plus `ogiri.account.columns`; extra columns are private by default. `ogiri.permitted-fields` separately controls extra writable attributes. Reserved identity, generation, password, token, confirmation, lock and tracking names are rejected at startup, case-insensitively.

## Schema and upgrades

Ogiri runs no startup DDL. Apply the packaged `META-INF/ogiri/ogiri-postgresql.sql` or `ogiri-mysql.sql` through application migrations. For a new account table, also apply `users-postgresql.sql` or `users-mysql.sql`. Use the supplied binary identity collations and InnoDB for MySQL. Existing email values must have Devise's normalized form.

For an existing pre-generation schema, stop every Ogiri writer. Apply `001-account-generation-<engine>.sql`, adapting the account-table steps for every realm, then `002-credential-lookup-<engine>.sql` from the [migration directory](../../contracts/schema/migrations/). Migration 001 deletes existing sessions; users must sign in again. Migration 002 adds the realm/client lookup index. For MySQL, use ROW or MIXED binary logging as directed by migration 001. Deploy the matching library before restarting writers. Fresh schemas already include these changes; do not apply the upgrade scripts to them. Do not reuse generation values for replacement accounts or restore account tables independently of session storage.

## Realms and bean selection

Root `ogiri.*` settings define the default `users` realm at `/auth`. Additional `ogiri.realms.<name>.*` settings inherit root properties and override individual values. One realm factory builds the root and additional workflow graphs. Each realm has its own account adapter, policy, authentication manager and endpoints; the session table is shared and ownership includes the realm.

Additional realms resolve these exact bean names:

- `<realm>OgiriAccountStore`: `AccountStore`.
- `<realm>OgiriMailer`: `OgiriMailer`.
- `<realm>OgiriPasswordEncoder`: `com.quantipixels.ogiri.account.internal.OgiriPasswords`.
- `<realm>OgiriAccountValidator`: `com.quantipixels.ogiri.account.internal.AccountValidator`.

Resolution uses the named bean, then the application's shared candidate (including `@Primary`), then the configured default. Declare realm-only beans with `@Bean(defaultCandidate = false)`. Generated root defaults do not count as shared application overrides: additional realms retain their own account table, bcrypt cost and mail-from setting. The validator fallback uses the root validator. Password and validator overrides depend on internal types and can change before 1.0.

Realm names and mounts must be distinct and mounts cannot overlap. Default JDBC realms need distinct account tables; explicit custom stores own that choice. Additional endpoint mappings reject paths already owned by another controller. Host paths outside the auth mounts resolve to the default realm. Use `OgiriConfigurer.ogiri(realms)` in a host chain; the single-runtime overload rejects configurations with additional realms.

## Spring Security and credentials

When the host defines no `SecurityFilterChain`, auto-configuration supplies a stateless chain with public auth workflows and authentication required elsewhere. An application chain must opt into `OgiriConfigurer` and choose its authorization rules. Ogiri composes with the host's CSRF, session policy and request cache. It does not configure CORS; the host can call `OgiriConfigurer.exposeHeaders(cors)` for browser access to credential headers. Ogiri's authentication manager is separate from host Basic authentication.

The converter reads named DTA headers before the base64-JSON Bearer fallback, field by field, then the auth cookie when enabled. Missing client defaults to `default`; query and form credentials are ignored. Public workflows ignore stale credentials. Invalid credentials continue anonymously; storage errors return 503. Ogiri credentials alongside an existing host identity are rejected with 401. Current authorities come from the account on each request.

Response credentials are planned during the workflow and written at response commitment without another database call. Header mode returns DTA headers and the complete Bearer header. Cookie mode also sets an HttpOnly auth cookie and omits the Bearer response header. Batch responses preserve the auth cookie. Sign-out and terminal revocation clear it.

Cookie mode uses Spring's double-submit protection: readable `XSRF-TOKEN` cookie and `X-XSRF-TOKEN` request header. A safe request bootstraps the cookie. Sign-in and registration that signs in require the pair even without an auth cookie. Unsafe requests require it when any selected credential field comes from the auth cookie. Complete header credentials need no Ogiri cookie CSRF on protected requests. Other host requests retain the host's CSRF policy.

Cookie defaults are Secure, SameSite=Lax and Path=/. Across cookie-enabled realms, use distinct auth-cookie names and the same cookie path. CSRF cookie/header names are shared; different paths can produce ambiguous duplicate CSRF cookies and 403 responses. Per-realm CSRF names are not supported.

## Transactions, passwords and mail

Auth writes use independent `REQUIRES_NEW`, `READ_COMMITTED` transactions. Reads suspend outer transactions and must use the primary database. The coordinator checks that the selected JDBC or JPA transaction manager uses the same DataSource. Multiple transaction managers require an explicitly supplied internal `AuthTransactions` bean. An outer transaction holding a connection needs spare pool capacity.

Lock order is subject admission row, account row, then client rows. Persistent subject-lock rows serialize issuance, rotation and revocation; keep them while writers run. Database time determines expiry. Sign-in verifies bcrypt outside the locks, then rechecks the account generation, active state and verified hash under locks. Rotation uses current/previous/last digests and the configured batch window. The default lifespan is 14 days, the device cap is 10 and rotation is off. At the cap, issuance evicts the soonest-expiring other session.

Passwords use Devise-compatible plain bcrypt, cost 12 by default, truncating UTF-8 input at 72 bytes. The unknown-account dummy uses the same encoder and cost. Recovery tokens are random and stored as SHA-256 digests. Password-reset session removal is controlled by `ogiri.remove-tokens-after-password-reset` and defaults to false.

Startup requires `ogiri.public-base-url` (or `spring.application.url`) and either `JavaMailSender` or `OgiriMailer`. Links use the configured public URL and mount paths, not the request Host. A nonempty redirect allow-list restricts targets; the empty default accepts any valid absolute HTTP(S) URL without userinfo. Mail is sent synchronously after commit; a non-paranoid delivery failure returns 503 while the state change remains committed. Paranoid recovery flows retain their normal response. There is no durable mail outbox.

## Operations and proof

SLF4J logs cover failed sign-ins, committed locks/unlocks and infrastructure failures. Logs omit account identifiers and credentials. Infrastructure diagnostics retain the outer exception type and stack while removing messages, causes and suppressed exceptions.

Spring Security events carry a string principal `realm:uid` with null credentials and details. Success uses the account uid; failure uses the trimmed, lowercased attempted uid. Password sign-ins publish success, bad-credentials, locked or disabled events after the transaction. Token authentication publishes success/bad-credentials through its dedicated manager. A successful token validation emits a success event, usually once per authenticated request; it is not necessarily a new sign-in. Applications can use `@EventListener`; these identities are personal data. The host's `AuthenticationEventPublisher` is used when supplied, otherwise Spring's default publisher is installed.

Cleanup is opt-in: set `ogiri.cleanup.interval=1h` at the root. Each fixed-delay run deletes at most `ogiri.cleanup.batch-size` expired sessions across all realms (default 1000; range 1–10000). The first run waits one interval, and shutdown stops the dedicated scheduler. Database time and `FOR UPDATE SKIP LOCKED` let instances share cleanup work. Live sessions and subject-lock rows remain. Authentication checks expiry even when cleanup is disabled or fails.

The sample uses a Boot parent, the Ogiri BOM and starter, and only declared public API in its main code. The build stages library artifacts into a worktree-local Maven cache and builds the sample outside the reactor. It does not need the Ogiri build parent as its application parent or install library artifacts into the shared Maven cache. The full gate includes database tests, the independent consumer, SBOM scanning and a release rehearsal; HTTP conformance has a separate gate. A build with `-DskipTests` proves compilation and static checks, not database or HTTP behavior.
