# Spring architecture

Ogiri implements `contracts/PROTOCOL.md` revision 3.0. The Spring decision selects a dedicated stateless DTA authentication mechanism and independently committed JDBC workflows. Java 17 is the runtime baseline; the compiler uses mise JDK 25 with release 17.

## Modules and ownership

* `ogiri`: session storage and transaction coordination, the account SPI and Devise JDBC implementation, account workflows, security converter/provider/filter/configurer, MVC endpoints, replaceable mail, commit events and observations. Features own their internal helpers; production code has no dependency on Boot.
* `ogiri-spring-boot-autoconfigure`: configuration properties, conditions, dependency validation and bean assembly only. It backs off on typed public seams and any application security chain.
* `ogiri-spring-boot-starter`: dependency-only starter; no implementation classes.
* `examples/spring-app`: public-API adoption, environment configuration, fixture role mapping and protected `/me` and `/admin` application endpoints.

## Adoption and extension points

Add `com.quantipixels.ogiri:ogiri-spring-boot-starter:0.0.1`, configure the application DataSource, and apply the packaged `META-INF/ogiri/ogiri-<engine>.sql` migration. Apply `users-<engine>.sql` only for a new application; existing Devise tables remain application-owned. Ogiri never runs DDL at startup.

The default `AccountStore` uses the DTA users table. Replace it for another model. An `OgiriAuthorities` bean maps account attributes to Spring authorities; the authenticated principal is `OgiriAccount implements UserDetails`. Applications use `@AuthenticationPrincipal OgiriAccount`, `Authentication` and `@PreAuthorize` normally. Replace `OgiriMailer` for content or delivery. Public events are published after commit with no secrets; Micrometer observations use bounded operation/outcome tags.

A host security chain opts in with `http.with(OgiriConfigurer.ogiri(runtime), configurer -> {})`; without a host chain Boot assembles a stateless default. The configurer installs the DTA converter/provider/filter, request-attribute context repository, DTA error handlers and commit-time header writer. `OgiriConfigurer.exposeHeaders(cors)` exposes DTA headers for browser callers. Root `ogiri.*` settings configure the users realm; `ogiri.realms.<name>.*` inherits defaults for additional mounts. Endpoint registration can be disabled independently.

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

The provider bean can participate in Spring's global AuthenticationManager assembly. Ogiri's filter uses its typed resolver and a dedicated ProviderManager. Applications with multiple PlatformTransactionManager beans must supply an AuthTransactions bean tied to the correct DataSource; ambiguity fails startup. An application-owned SecurityFilterChain must opt into `http.with(OgiriConfigurer.ogiri(runtime), configurer -> {})` and choose its endpoint authorization rules. Ogiri does not replace that chain.

Subject, session value records, JdbcSessions, AuthTransactions and OgiriRuntime are intentional public integration APIs for host transaction and custom-chain integration. The locked storage operations and JDBC accessor still need isolation behind internal implementation packages in the next API checkpoint. MVC's current-identity helper is private. Rotation, lockout, confirmation and scheduled cleanup configuration that needs unfinished behavior fails startup until its implementation slice removes the respective guard.
