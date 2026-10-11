# Ogiri 0.0.1

Ogiri provides opaque bearer sessions: no JWTs and immediate server-side revocation, with optional cookie transport. Every authenticated request checks the stored session. Keep your accounts and authorization rules; Ogiri handles the session lifecycle.

## One protocol, three implementations

| Implementation | Location |
| --- | --- |
| Spring Boot | This repo's Maven modules: [`ogiri`](ogiri/) [`ogiri-spring-boot-autoconfigure`](ogiri-spring-boot-autoconfigure/), and [`ogiri-spring-boot-starter`](ogiri-spring-boot-starter/) |
| FastAPI | [`packages/python`](packages/python/README.md) (being built) |
| Phoenix | [`packages/elixir`](packages/elixir/README.md) (being built) |

All three follow the [shared protocol](contracts/PROTOCOL.md) and [HTTP conformance suite](contracts/conformance/check.py). The Spring modules support **Spring Boot 4.1 / Java 17+**, with **PostgreSQL and MySQL 8+**.

This is a new, unpublished prototype API and schema. Earlier v3/v4 credentials and database layouts are incompatible; use the application-owned migration and require existing users to sign in again.

The Spring prototype implements sign-in, sign-out, validation, devices, registration, password recovery, confirmation, lockout, rotation, account updates and deletion, and multiple account realms. Cookie mode uses HttpOnly auth cookies and double-submit CSRF for sign-in, registration that signs in, and unsafe cookie-authenticated requests. Scheduled cleanup remains unfinished and fails startup when enabled. See the [Spring architecture](docs/architecture/spring.md).

## Adopt the Spring library

```xml
<dependency>
  <groupId>com.quantipixels.ogiri</groupId>
  <artifactId>ogiri-spring-boot-starter</artifactId>
  <version>0.0.1</version>
</dependency>
```

The dependency-only starter is a conventional JAR. The prototype is not published yet. The repository's `bash scripts/platform/java.sh ci` builds the project and tests an independent consumer using an isolated artifact cache. It does not install third-party artifacts into your Maven cache. Add PostgreSQL or MySQL's JDBC driver to your application and configure `spring.datasource.*` normally. Runtime dependency versions in the sample and library manage Jackson 3.1.7 and Tomcat 11.0.26; an adopter's dependency management must also retain those patched versions.

Apply `META-INF/ogiri/ogiri-postgresql.sql` or `ogiri-mysql.sql` from the core JAR through an application-owned migration. For a new application, also apply the corresponding `users-<engine>.sql`. Existing Devise users tables can be retained; normalize migrated email values as Devise does. Ogiri ignores the old users.tokens column and never runs DDL at startup. Existing DTA session tokens require a new sign-in. Plain Devise bcrypt hashes verify unchanged; new hashes remain plain bcrypt, cost 12, with the bcrypt UTF-8 72-byte truncation rule.

The default `AccountStore` reads and writes the Devise-shaped users table. Replace that bean for your own account model. Map application roles through `OgiriAuthorities`:

```java
@Bean
OgiriAuthorities authorities() {
    return columns -> List.of(new SimpleGrantedAuthority(
        "ROLE_" + columns.get("role").toString().toUpperCase(Locale.ROOT)));
}
```

The authenticated principal is `OgiriAccount implements UserDetails`; use `@AuthenticationPrincipal OgiriAccount` and ordinary Spring method/route authorization. No UserDetailsService adapter is needed. Wire views contain only standard DTA resource fields plus explicitly configured `ogiri.account.columns`; for example `ogiri.account.columns=role`. Extra database columns are private by default. Additional permitted input fields are configured separately through `ogiri.permitted-fields` (defaults: name, nickname, image).

## HTTP credentials

Sign in with JSON or form fields **email** and **password**:

```sh
curl -i "$BASE_URL/auth/sign_in" \
  -H 'Content-Type: application/json' \
  --data '{"email":"demo@example.com","password":"test-password"}'
```

The response JSON is `{"data": <account>}`. Authentication credentials are in the response headers: **access-token**, **client**, **uid**, **expiry**, **token-type**. DTA clients store those values and send **access-token/client/uid** back on later requests:

```sh
curl -i "$BASE_URL/me" \
  -H "access-token: $ACCESS_TOKEN" -H "client: $CLIENT" -H "uid: $AUTH_UID"
```

`Authorization: Bearer <base64(JSON)>` is the alternative form: the JSON object contains access-token, client, uid, expiry and token-type. It is **not a JWT**. A non-cookie response already supplies this complete Authorization header, so it can be replayed directly. Named request headers take precedence per field. Query and form credentials are ignored. No X-Requested-With header is required. Authenticated responses use Cache-Control: no-store. Configure trusted CORS origins and call `OgiriConfigurer.exposeHeaders(cors)` to expose the authentication headers to browser clients.

| Request | Behavior |
| --- | --- |
| POST /auth/sign_in | Sign in; new client and authentication headers |
| DELETE /auth/sign_out | Revoke this client |
| GET /auth/validate_token | Validate credentials; return account token view |
| POST /auth | Register email/password/password_confirmation and permitted fields |
| PUT or PATCH /auth | Update permitted account fields |
| DELETE /auth | Delete account and revoke every client |
| GET /auth/sessions | List owned live clients |
| DELETE /auth/sessions/{client} | Revoke one owned client |
| DELETE /auth/sessions | Revoke every client |

Defaults are realm users, base path /auth, 14-day token lifespan, 10 devices, and rotation off. A full device cap evicts the earliest-expiring client. The default current-password check is false; a supplied current_password is ignored. Configure password or attributes to require it for the respective updates. See generated configuration metadata and the protocol for the remaining settings.

## An application-owned security chain

Without an application SecurityFilterChain, the starter supplies a stateless chain. With any application chain, it backs off; opt into Ogiri explicitly:

```java
@Bean
SecurityFilterChain security(HttpSecurity http, OgiriRealms realms) throws Exception {
    http.with(OgiriConfigurer.ogiri(realms), configurer -> {});
    return http.authorizeHttpRequests(routes -> routes
        .requestMatchers(request -> realms.endpointsEnabled(request)
            && OgiriConfigurer.publicWorkflow(request, realms.resolve(request).settings().basePath())).permitAll()
        .anyRequest().authenticated()).build();
}
```

The configurer installs the dedicated DTA converter/provider/filter, error handlers, request-attribute context and response header writer. Authorization remains the application's responsibility. Public auth workflows ignore stale or malformed credentials. Invalid credentials become anonymous; storage outages return the protocol 503 body. The default provider and password policy stay inside Ogiri's dedicated resolver and workflows, preserving host Basic authentication. Requests carrying both an existing identity and Ogiri credentials are rejected. Multiple PlatformTransactionManager beans require an explicitly selected AuthTransactions bean for Ogiri's DataSource. A mismatched JDBC or JPA resource fails startup.

Every authentication reads the primary database and current account state. Mutations commit independently of surrounding application transactions; reads suspend their snapshots. Ordinary calls support a one-connection pool; an outer transaction holding a connection needs spare capacity. Cleanup is bounded with SKIP LOCKED and does not determine authentication expiry.

See the [independent sample](examples/spring-app/README.md) for build, startup and HTTP exercises. FastAPI and Phoenix implementations live under [packages/python](packages/python/) and [packages/elixir](packages/elixir/). Licensed under Apache-2.0.

### Spring public API

Adopters use AccountStore, OgiriAccount, OgiriAuthorities, OgiriPasswords/DevisePasswordEncoder, OgiriMailer, the independent JdbcSessions interface and subject/session records, OgiriRuntime, OgiriRealms and OgiriConfigurer. Atomic JDBC workflow operations, token helpers, MVC endpoints and credential conversion are under internal packages. Configure `ogiri.public-base-url` (or `spring.application.url`) and JavaMailSender or an OgiriMailer bean for recovery. `ogiri.bcrypt-cost` defaults to 12 and also determines the unknown-account dummy cost.

### Spring account realms

Root `ogiri.*` configures the default users realm. Additional mounts inherit every root setting and override only named properties:

```properties
ogiri.realms.admins.base-path=/admin_auth
ogiri.realms.admins.account.table=admins
ogiri.realms.admins.max-number-of-devices=3
```

Apply an application-owned Devise-shaped admins table migration. Users and admins may share an email but never share sessions. Realm names and mounts must be distinct and non-overlapping. For a custom realm store, supply a bean named `adminsOgiriAccountStore` with `@Bean(defaultCandidate=false)` so it does not replace the default store. An application-owned chain uses `OgiriRealms` as above. Request authentication, response credentials and context caches are isolated by the runtime instance and chain. Email-provider uid follows an email edit; other providers keep their issued uid.
