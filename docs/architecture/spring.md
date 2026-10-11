# Spring architecture

Ogiri implements `contracts/PROTOCOL.md` revision 3.3. The Spring decision selects a dedicated stateless DTA authentication mechanism and independently committed JDBC workflows. Java 17 is the runtime baseline; the compiler uses mise JDK 25 with release 17.

## Modules and ownership

* `ogiri`: session storage and transaction coordination, the account SPI and Devise JDBC implementation, account workflows, security converter/provider/filter/configurer, MVC endpoints, replaceable mail, commit events and observations. Features own their internal helpers; production code has no dependency on Boot.
* `ogiri-spring-boot-autoconfigure`: configuration properties, conditions, dependency validation and bean assembly only. It backs off on typed public seams and any application security chain.
* `ogiri-spring-boot-starter`: dependency-only starter; no implementation classes.
* `examples/spring-app`: public-API adoption, environment configuration, fixture role mapping and protected `/me` and `/admin` application endpoints.

## Adoption and extension points

Add `com.quantipixels.ogiri:ogiri-spring-boot-starter:0.0.1`, configure the application DataSource, and apply the packaged `META-INF/ogiri/ogiri-<engine>.sql` migration. Apply `users-<engine>.sql` only for a new application; existing Devise tables remain application-owned. Ogiri never runs DDL at startup.

The default `AccountStore` uses the DTA users table. Replace it for another model. An `OgiriAuthorities` bean maps account attributes to Spring authorities; the authenticated principal is `OgiriAccount implements UserDetails`. Applications use `@AuthenticationPrincipal OgiriAccount`, `Authentication` and `@PreAuthorize` normally. Replace `OgiriMailer` for content or delivery. Public events are published after commit with no secrets; Micrometer observations use bounded operation/outcome tags.

A host security chain opts in with `http.with(OgiriConfigurer.ogiri(realms), configurer -> {})`; without a host chain Boot assembles a stateless default. The configurer installs the DTA converter/provider/filter, request-attribute context repository, DTA error handlers and commit-time header writer. `OgiriConfigurer.exposeHeaders(cors)` exposes DTA headers for browser callers. Root `ogiri.*` settings configure the users realm; `ogiri.realms.<name>.*` inherits defaults for additional mounts. Endpoint registration can be disabled independently.

## Authentication and wire behavior

The converter reads each field from its named header before the base64 JSON Authorization fallback. Missing client becomes `default`. It ignores query/form values and accepts cookies only when enabled. The provider resolves uid, executes the same client-row lookup using a sentinel subject for an unknown account, compares digests in constant time and checks current account state. Each request gets a fresh SecurityContext; authorities never merge. Invalid credentials continue anonymously; infrastructure failure terminates with the contract 503 body. Public workflows ignore credentials.

A request attribute carries response credentials. A Spring HeaderWriter emits DTA headers, Authorization and no-store at response commitment without database work. Revocation clears the response plan. Cookie mode uses the standard CookieCsrfTokenRepository and double-submit requirement only for unsafe cookie-authenticated requests. Optional OAuth uses Spring OAuth2 Login and issues the same Ogiri sessions.

## Transactions, locks and clocks

One coordinator resolves and validates a JDBC or JPA transaction manager against the same DataSource. Every auth mutation runs REQUIRES_NEW at READ COMMITTED; reads suspend ambient transactions. Internal account and session operations participate in that one transaction. Lock order is subject admission row, account row, client rows. Stable admission rows use the contract length-prefixed SHA-256 key. DB time is read after waits, in epoch milliseconds.

Sign-in verifies bcrypt outside locks, then rereads account existence, active state and the exact verified hash under locks before inserting. Password/reset/delete/lock transitions use the same locks, making the A6 fence atomic. The cap evicts earliest expiry rather than rejecting. Rotation serializes the client row, follows revision 3 current/previous/last and sliding batch rules, and uses DB time. Cleanup deletes bounded expired batches with SKIP LOCKED; optional scheduling owns only its task.

## Accounts and mail

DevisePasswordEncoder hashes UTF-8 bytes truncated to 72 through Spring BCrypt's byte-array API, cost 12, plain bcrypt. PK text is the stored subject; normalized email is the wire uid. Explicit full/token projections remove A3 secret columns. Workflows permit only A5 fields, validate code-point length, and persist one-time SHA-256 hex digests. A transactional AFTER_COMMIT listener sends mail synchronously: delivery failure yields 503 while the state change remains committed.

## Proof and maintenance

Preserve and adapt real PostgreSQL/MySQL lock, DB-clock, independent-commit, bounded cleanup, JPA-host and one-connection-pool tests. Deterministic latches/barriers establish credential fences, rotation and cap races; no sleep clocks. Context-runner tests assert exact startup causes and typed backoff. Consumer tests drive JSON/form wire behavior through HTTP using installed project artifacts in an isolated Maven cache.

`scripts/platform/java.sh` owns fast/full/staged/fix gates: Spotless AOSP, Error Prone, NullAway/JSpecify, SpotBugs/FindSecBugs, PMD and Checkstyle. Each new analyzer must reject one seeded violation. Package byte-identical contract schemas and check drift. Manage Jackson 3.1.7 before Boot's BOM in library and sample; align Tomcat and BOM order, enforce Java/Maven versions, provide a scoped Maven wrapper. Full proof includes both engines, public-API consumer, SBOM/OSV and release rehearsal. Missing gates are failures. The shared v2 parity suite is integrated when delivered by the lead.

## Scope and proof limits

No JWT, v1 compatibility, resource-server dependency, automatic schema migration, pepper or durable outbox. The progress report records slice commits, executed proof, contract questions and all merged-review dispositions. Architecture describes the selected final structure; unimplemented or unverified mechanisms remain explicit in that report until completed.

## Registration checkpoint and adopter notes

Registration and account updates use Jakarta Bean Validation through Spring Validator. Account views allow only the DTA resource columns (id, provider, uid, email, name, nickname, image, allow_password_change, created_at, updated_at) plus explicitly configured `ogiri.account.columns`; SELECT * is used for the private credential snapshot, never as the wire projection. The sample opts into `role`. The store normalizes email on create/update and uses indexed `email = ?` lookup. Existing migrated addresses must already have Devise's normalized form, or be normalized by an application migration.

The default provider is assembled inside Ogiri's typed resolver and dedicated ProviderManager. The OgiriPasswords wrapper keeps its encoder out of Spring's global PasswordEncoder selection; host Basic authentication retains its own account store and encoder. Applications with multiple PlatformTransactionManager beans must explicitly wire the matching Ogiri coordinator; ambiguity fails startup. An application-owned SecurityFilterChain must opt into `http.with(OgiriConfigurer.ogiri(realms), configurer -> {})` and choose its endpoint authorization rules. Ogiri does not replace that chain.

Subject, session value records, the injectable JdbcSessions interface and OgiriRuntime are intentional public integration APIs. JdbcSessions exposes only independent issue/authenticate/list/revoke/revokeAll/cleanup operations. SessionRepository, AuthTransactions, Tokens and Database live under internal; atomic locked methods and the JDBC accessor are infrastructure wiring, not adopter APIs. DtaAuthenticationConverter and OgiriEndpoints live under their feature internal packages. ModuleBoundariesTest verifies feature cycles and internal exposure. MVC's current-identity helper is private. Rotation, lockout, confirmation and scheduled cleanup configuration that needs unfinished behavior fails startup until its implementation slice removes the respective guard.

## Password and mail checkpoint

P1-P6 share the subject/account/session coordinator. Recovery tokens are random 32-byte base64url values; the Devise column contains the lowercase SHA-256 hex digest. P3 sets the reset window and confirms the account; P4 and R6 consume it and apply the configured session-retention transition. Credential survival is computed before the mutation commits, so header planning never borrows a second connection after a JPA transaction.

Configure `ogiri.public-base-url` (fallback `spring.application.url`) independently of request Host and scheme. Links append the context, dispatcher servlet and Ogiri mount paths. Redirect allowlists compare parsed scheme, host, port and remaining path/query/fragment; host wildcards cannot match query, fragment or userinfo. The default JavaMailSender adapter uses `ogiri.mail.<kind>.subject` and `.body` MessageSource keys, with the link as body argument 0. Replace the three-method OgiriMailer bean for application delivery/content.

MailDispatcher publishes a redacted intent inside the transaction. Its synchronous AFTER_COMMIT listener records a delivery receipt. Failed non-paranoid delivery returns the contract 503 while the digest remains committed; paranoid delivery logs a fixed event kind and returns the same normal success body as an unknown account. Missing delivery infrastructure or public URL fails startup with an actionable cause. Consumer tests use an independent connection in the mail callback to prove committed visibility and use a forged Host over actual HTTP to prove the mounted configured link.

Migration timing policy: `ogiri.bcrypt-cost` defaults to 12; set it to the migrated database cost when needed. The dummy uses the same encoder instance and cost as new hashes. Unknown-email rejection performs the same cheap subject/account lock transaction through a sentinel owner. This reduces two identified differences; no complete timing-distribution claim is made.

Confirmation, reconfirmation and lockout are implemented: pending email changes leave email/uid intact until confirmation, failures count and lock under admission/account locks, and mail dispatch runs after commit. Non-paranoid delivery failure returns 503 with committed recovery state; paranoid P/C/U retain the normal 200 body. Unlock issuance and token consumption require a currently locked account and an email strategy. Five deterministic native lock-wait drills on both database engines prove that verified sign-in cannot cross a committed password/reset/delete/lock/unconfirmed transition; each asserts its exact rejection reason and zero sessions.

H5 rotation authenticates in the same admission/account/client lock order. DB time is read after the client wait; current/previous/last digests are compared in constant time. Initial issuance sets rotated_at, batch requests extend it, and only an out-of-buffer current token rotates and slides expiry. ResponseCredentials keeps full Bearer values separately from the single-space batch access-token/expiry headers. Request-only raw response credentials are transient on the Authentication object. Native database concurrency drills assert one winner across eight simultaneous requests and explicit previous/last expiry; the one-connection consumer asserts Bearer preservation and terminal-revocation suppression.

G1 mounts use `ogiri.realms.<name>.*`, inheriting every root policy through Boot Binder. Each mount owns its account adapter, workflow services, authentication manager and MVC handlers; session/lock ownership includes its distinct realm. Names, paths and enabled cookie scopes are validated for collisions at startup. A named `<realm>OgiriAccountStore` bean replaces an additional realm adapter. Host paths outside auth mounts use the default realm. Host chains inject `OgiriRealms` and use `OgiriConfigurer.ogiri(realms)` so every mount resolves through its own authentication manager. The single-runtime overload fails during chain configuration when additional realms exist. Signed-in-account workflow services compare the full session Subject (realm, tenant and subject id) with the account's expected Subject before touching their store; account mutation services require the Session alongside the account snapshot. Endpoints enforce ownership for validate_token, sessions and sign-out, which have no account workflow service check. Rejected credentials are unauthenticated under H3, so account update/delete retain R9's 404 and error bodies.

Additional JDBC realms must resolve to distinct account tables, including the root table. Reusing an inherited or explicitly duplicated table fails startup with the realm setting and named store bean needed to fix it. An explicit `<realm>OgiriAccountStore` bean owns that realm's storage choice and is exempt from table-property collision checks.

Ogiri's resolver bean is named and qualified `ogiriAuthenticationManagers`. A host AuthenticationManagerResolver does not replace it; adopters replacing Ogiri's resolver must use that bean name/qualifier. The dependency-only starter is a conventional JAR, and the installed-artifact consumer uses the README dependency verbatim.
