# Ogiri 0.0.1

Ogiri provides opaque bearer sessions: no JWTs, no cookies, and immediate server-side revocation. Every authenticated request checks the stored session. Keep your accounts and authorization rules; Ogiri handles the session lifecycle.

## One protocol, three implementations

| Implementation | Location |
| --- | --- |
| Spring Boot | This repo's Maven modules: [`ogiri`](ogiri/) and [`ogiri-spring-boot-starter`](ogiri-spring-boot-starter/) |
| FastAPI | [`packages/python`](packages/python/README.md) (being built) |
| Phoenix | [`packages/elixir`](packages/elixir/README.md) (being built) |

All three follow the [shared protocol](contracts/PROTOCOL.md) and [HTTP conformance suite](contracts/conformance/check.py). The Spring modules support **Spring Boot 4.1 / Java 17+**, with **PostgreSQL and MySQL 8+**.

This is a new, unpublished prototype API and schema. Earlier v3/v4 credentials and database layouts are incompatible; use the application-owned migration and require existing users to sign in again.

## Install

```xml
<dependency>
  <groupId>com.quantipixels.ogiri</groupId>
  <artifactId>ogiri-spring-boot-starter</artifactId>
  <version>0.0.1</version>
</dependency>
```

Until published, run `mvn clean install` with a disposable database (see [CONTRIBUTING.md](CONTRIBUTING.md)). Add **one** database driver: `org.postgresql:postgresql` or `com.mysql:mysql-connector-j`. Your application's Spring Boot BOM manages its version. The starter includes Spring JDBC, the native OAuth2 resource-server pipeline, and Spring MVC; it does not require JPA, Redis or a Kotlin runtime.

Configure your ordinary `spring.datasource.*` settings, provision the schema, and set `ogiri.enabled=true`. Provide your existing `UserDetailsService`; no Ogiri user entity, session repository, authentication manager, filter or controller is needed for the default path:

```java
@Bean
UserDetailsService users(UserRepository repository) {
    return username -> repository.securityUser(username)
        .orElseThrow(() -> new UsernameNotFoundException("Unknown account"));
}
```

`UserRepository` and `securityUser` belong to your application. Return Spring `UserDetails`. The default adapter uses the immutable username as the stable account ID in realm `users`, with no tenant. For mutable usernames, opaque IDs or tenants, supply `OgiriAccounts`: `subject(Authentication)` resolves successful login to a stable full identity; `load(Subject)` loads current status/authorities from that identity. Never resolve an ID as a mutable login accidentally.

Spring's `AuthenticationConfiguration` builds password authentication from your normal services/providers; an application `AuthenticationManager` or `PasswordEncoder` wins. The default delegating encoder accepts algorithm-prefixed hashes (for example `{bcrypt}`) and unprefixed bcrypt hashes. No default users or passwords are created by Ogiri.

## Migrating from DeviseTokenAuth

See the [protocol's migration table](contracts/PROTOCOL.md#migrating-from-devisetokenauth) for endpoint, header and storage changes. Devise's `$2a$` bcrypt password hashes verify as-is with Ogiri's default encoder; no password reset is needed. Existing DeviseTokenAuth tokens cannot be converted, so users sign in once after the switch.

If Rails and Spring share the users table during migration, supply a plain `BCryptPasswordEncoder` bean so new hashes stay Rails-readable. Ogiri's default encoder writes `{bcrypt}`-prefixed hashes.

## Endpoints and defaults

With no application `SecurityFilterChain`, the starter supplies a stateless bearer chain. Only the configured JSON sign-in is public; other routes require authentication. Add method/route authorization for your business rules.

| Request | Outcome |
| --- | --- |
| `POST /auth/sign-in` | Authenticate JSON `username`, `password`, `client`; return session metadata and an `Authorization: Bearer ...` header |
| `GET /auth/session` | Current session metadata |
| `GET /auth/sessions` | List this account's live sessions |
| `DELETE /auth/sessions/{id}` | Revoke one owned session |
| `DELETE /auth/sign-out` | Revoke the current session |
| `DELETE /auth/sessions` | Revoke all current account sessions |

Send `Content-Type: application/json` and `X-Requested-With: Ogiri` on sign-in. That non-simple request is the only login CSRF exemption; other writes retain Spring's CSRF handling. Restrict CORS to trusted origins. Bearer credentials go in the Authorization header, never URLs, response JSON or logs. Native resource-server authentication plus duplicate-header rejection is packaged in the library, not copied from a demo.

```yaml
ogiri:
  lifetime: 7d
  maximum-sessions: 10
  realm: users
  base-path: /auth
  endpoints-enabled: true
  enabled: true
```

`ogiri.enabled=true` is required; the other settings above show defaults. Until enabled, Ogiri registers no session endpoints, storage beans or security chain and needs no Ogiri schema. The starter still adds Spring Security, JDBC and MVC to the classpath, so [Boot's normal auto-configuration](https://docs.spring.io/spring-boot/reference/web/spring-security.html) applies: it can secure an application without an existing chain, and JDBC still needs the application's DataSource configuration. Disabling Ogiri does not disable those Spring features.

Properties are bound and validated by Boot, with generated IDE metadata. Reaching the session cap rejects the new issuance; it does not evict another device. Expiry is fixed, not sliding. Session reads check current account status and authorities. Invalid credentials fail authentication; directory/storage outages remain failures, never fabricated anonymous success.

## Keep an existing security chain

Ogiri backs off completely from creating a chain when **any** application chain exists. Inject the reusable `OgiriSecurity` helper into whichever chains should accept Ogiri tokens:

```java
@Bean
SecurityFilterChain security(HttpSecurity http, OgiriSecurity ogiri) throws Exception {
    ogiri.configure(http); // Native bearer authentication, not authorization or global CSRF disable.
    return http
        .authorizeHttpRequests(routes -> routes
            .requestMatchers(ogiri.signInRequest()).permitAll()
            .anyRequest().authenticated())
        .csrf(csrf -> csrf.ignoringRequestMatchers(ogiri.signInRequest()))
        .build();
}
```

Retain your existing request matchers, other authentication methods, error-dispatch handling and CSRF policy. Add the sign-in permit/exemption only when you use the built-in login. The helper is reusable across multiple chains; it is not a mutable singleton configurer. `ogiri.endpoints-enabled=false` removes the controller, and `ogiri.enabled=false` disables all Ogiri auto-configuration. Business authorization remains yours. Built-in management accepts an Ogiri session, not an unrelated Basic/JWT principal.

If the host sets `spring.mvc.servlet.path`, the built-in endpoint and `ogiri.signInRequest()` use that servlet prefix together. Keep the same request matcher for the sign-in permit and CSRF exemption in application-owned chains.

## Runtime patch level

The tested Boot 4.1.1 consumer pins `tomcat.version=11.0.25` for CVE-2026-65905, CVE-2026-65182 and CVE-2026-68525. Your application's dependency management takes precedence over transitive versions: keep embedded Tomcat at 11.0.25 or a later compatible patched release. Remove this temporary override after upgrading to a Boot BOM that supplies the fixes. CI scans both resolved runtime graphs.

## Database ownership

Copy `META-INF/ogiri/schema-postgresql.sql` or `META-INF/ogiri/schema-mysql.sql` from the core JAR into an application-owned migration. Ogiri never reserves a Flyway version, runs DDL at startup, or modifies application tables. Spring Boot SQL initialization may be used explicitly in disposable development databases. Production migrations are application-owned.

Both engines use the same lifecycle, admission rules and contract suite. SQL variations are limited to timestamp expressions, lock-row insertion and DDL types. Schema timestamps are UTC epoch milliseconds. Identity uses exact, case-sensitive, non-padding comparisons, including on MySQL. MySQL tables must use InnoDB.

Two tables are required. `ogiri_sessions` holds hashes and metadata. `ogiri_subject_locks` provides stable row locks for admission and account-wide revocation. Lock rows retain one digest per identity; do not delete them while writers run, as that can split the serialization boundary. They contain no credential or direct identity text. This retained state is the explicit cost of portable session-cap enforcement, not a cache.

Use the authoritative primary and a normal underlying pool, not a transaction-aware or replica-routing proxy. Spring transaction management and `TransactionTemplate` own commit, rollback and resource restoration. Session mutations commit in independent `REQUIRES_NEW` transactions; reads suspend an outer JDBC or JPA transaction so a stale snapshot cannot restore revoked credentials. An outer transaction that already holds a connection needs spare pool capacity. Ordinary calls work with a one-connection pool. No automatic retry pretends to resolve an ambiguous commit.

The starter reuses the application transaction manager, including Spring JPA. With the core alone, pass the manager for the supplied DataSource to `new JdbcSessions(dataSource, policy, transactionManager)`. The two-argument constructor creates a JDBC manager and is intended for JDBC-only transaction contexts. Multiple data sources or managers require an explicitly selected `JdbcSessions` bean; do not select an unrelated manager.

Each authentication performs one indexed session read and no writes, followed by the current account lookup in the Spring adapter. Malformed credentials fail before query execution. Five-second SQL timeouts do not replace connection, socket or HTTP timeouts. Configure those through your pool/server. JDBC driver timeout units differ: PostgreSQL `socketTimeout` uses seconds; MySQL uses milliseconds. Do not share that numeric setting between drivers. Authentication expiry does not depend on cleanup.

Schedule `JdbcSessions.cleanup(batchSize)` in your existing jobs. It locks a bounded ID page with `SKIP LOCKED` and deletes it in the same transaction; concurrent workers need no leader lease. Limit job runtime and stop when fewer than a page is returned. Core-only callers can depend on `ogiri` and construct `JdbcSessions(dataSource, policy)` without Boot.

## Session freshness and caching decision

Every authentication queries the authoritative database and then loads current account status and authorities. Revocation is visible to the next authentication request after its database commit. A database outage fails authentication instead of accepting a previously observed session.

Ogiri 0.0.1 deliberately has no session lookup cache. Caching would make revocation stale across nodes, in-flight fills, direct SQL changes and cache outages. It also adds a second security-sensitive store and provider configuration to a prototype whose primary promise is immediate revocation. Applications may cache unrelated data through Spring Cache; that does not change Ogiri authentication. Revisit session caching only with an explicit consistency contract and measured need.

## Non-goals

Registration, password reset, confirmation, OmniAuth, MFA, and JWT/refresh-token flows stay in the application. Ordinary browser HttpSession applications should consider Spring Session JDBC; federated OAuth/OIDC should use an identity provider. See [SECURITY.md](SECURITY.md) for recovery coordination and token-lifetime trade-offs, and [PUBLISHING.md](PUBLISHING.md) for the opt-in Central release path.

The [independent example](examples/spring-app) consumes the actual installed artifacts. It exercises the opt-in default chain and existing multi-chain applications against both database engines. Production performance is not inferred from line counts; the opt-in benchmark measures a defined local storage workload.

Licensed under Apache-2.0.
