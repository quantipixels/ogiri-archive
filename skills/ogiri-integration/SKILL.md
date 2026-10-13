---
name: ogiri-integration
description: Add Ogiri (database-backed opaque sessions with devise_token_auth-compatible endpoints) to an existing Spring Boot 4 application. Detects the build tool and database, adds the starter, sets the required ogiri.* properties, applies the packaged schema, wires account/mailer overrides, protects routes with Spring Security and proves sign-up/sign-in works. Use for "add Ogiri", "use devise_token_auth from Spring", "replace the Rails auth backend", or wiring Ogiri into a host SecurityFilterChain. For choosing an auth approach, use the auth-design skill instead.
---

# Integrate Ogiri

**Result:** the host app builds, starts, and a sign-up then sign-in round trip returns `access-token`, `client` and `uid` headers; protected routes return 401 without them.

**Not for:** deciding whether Ogiri is the right approach, roles or tenancy design. Use [auth-design](../auth-design/SKILL.md).

Sources of truth (read them instead of guessing): properties in `ogiri-spring-boot-autoconfigure/src/main/java/com/quantipixels/ogiri/spring/OgiriProperties.java`, schemas in `META-INF/ogiri/` of the `ogiri` JAR (also `contracts/schema/`), HTTP behaviour in `contracts/PROTOCOL.md`, a working host in `examples/spring-app/`.

## 1. Check the host

- Spring Boot 4.x, Java 17+, Jackson 3 (`tools.jackson.*`). Boot 3 or Jackson 2 (`com.fasterxml.jackson.databind`) is unsupported: stop and report.
- Build tool: `pom.xml` (Maven) or `build.gradle(.kts)` (Gradle). Database: the JDBC driver on the classpath and `spring.datasource.url`. Only PostgreSQL and MySQL 8.4 InnoDB are supported.
- Migration tool (Flyway, Liquibase, plain SQL) and whether a Devise-shaped account table already exists.
- Existing `SecurityFilterChain` beans, CSRF, CORS and `JavaMailSender` configuration.

## 2. Add the dependency

Group `com.quantipixels.ogiri`. Add `ogiri-spring-boot-starter`. If the build already imports BOMs, import `ogiri-bom` (type `pom`, scope `import`) and leave the starter unversioned; otherwise version the starter directly. Use the version from the repo's root `pom.xml`. Keep Boot's managed Jackson; the README lists the Jackson and Tomcat overrides that pick up security fixes.

## 3. Schema

Ogiri runs no DDL at startup. Add migrations in the host's own tool:
- always `ogiri-<engine>.sql` (sessions and lock tables);
- `users-<engine>.sql` only when there is no account table yet.

Mapping an existing table: it must have the Devise columns in `users-<engine>.sql`, including `ogiri_generation` (immutable, 1-36 chars, new value when an account is replaced), and MySQL identity columns must use the binary collations in those files. Upgrading an older Ogiri schema: `contracts/schema/migrations/001-*` then `002-*`; 001 deletes all sessions. Never apply them to a fresh schema.

## 4. Properties

```properties
ogiri.public-base-url=https://app.example.com   # required; absolute http(s); used for mail links
ogiri.account.table=users                       # default realm "users" at /auth
ogiri.redirect-allowlist=https://app.example.com # frontend URLs allowed in confirm/reset/unlock links
```

- Mail: startup fails without `spring.mail.*` (a `JavaMailSender`) or an `OgiriMailer` bean, even with confirmation off.
- Cookies: `ogiri.cookie-enabled=false` by default (header credentials). If enabled, keep `ogiri.cookie-secure=true` except for local HTTP; additional cookie realms need distinct `cookie-name` and the same `cookie-path`.
- Set `ogiri.redirect-allowlist` explicitly. An empty list accepts only URLs on the origin (scheme, host, port) of `ogiri.public-base-url`, so a frontend on another origin must be listed (`SECURITY.md`, PROTOCOL D-O).
- Consider `ogiri.remove-tokens-after-password-reset=true` and `ogiri.lockable=true`. Expose extra account fields with `ogiri.account.columns`, accept them on input with `ogiri.permitted-fields`.
- Extra realms: `ogiri.realms.<name>.base-path`, `.account.table`, and so on; distinct mounts and tables.

## 5. Overrides

Default realm: declare an ordinary bean of the type (`AccountStore`, `OgiriMailer`, `OgiriAuthorities`); the default is skipped. Additional realm `<realm>`: name it `<realm>OgiriAccountStore`, `<realm>OgiriMailer`, `<realm>OgiriPasswordEncoder` or `<realm>OgiriAccountValidator`, declared with `@Bean(defaultCandidate = false)` so it does not become the shared one. The last two use `*.internal` types and may break before 1.0. A custom `AccountStore` must use the same `DataSource` and transaction manager as Ogiri.

Map roles with an `OgiriAuthorities` bean (`attributes -> List<GrantedAuthority>`); inject the user with `@AuthenticationPrincipal OgiriAccount`.

## 6. Security chain

- No host `SecurityFilterChain`: the starter's fallback chain makes auth endpoints public and everything else authenticated. Done.
- Host chain exists: inject `OgiriRealms realms` and add `http.with(OgiriConfigurer.ogiri(realms), c -> {})`. In the host's `authorizeHttpRequests`, permit only the public workflows, before the host's own rules:

  ```java
  .requestMatchers(r -> OgiriConfigurer.publicWorkflow(r, "/auth")).permitAll()
  ```

  Do not `permitAll()` the whole `/auth/**` mount; `sign_out`, `validate_token`, `sessions` and account updates need authentication. Copy the full matcher (including `tokenResetWorkflow`, error dispatch and multiple realms) from `ogiriSecurityFilterChain` in `OgiriAutoConfiguration.java`. Use method security as normal.
- Browser across origins: configure CORS yourself and call `OgiriConfigurer.exposeHeaders(cors)`.

## 7. Verify

Start the app against a disposable database, then:

```sh
curl -si "$BASE_URL/auth" -H 'Content-Type: application/json' \
  --data '{"email":"a@example.com","password":"test-password","password_confirmation":"test-password"}'
curl -si "$BASE_URL/auth/sign_in" -H 'Content-Type: application/json' \
  --data '{"email":"a@example.com","password":"test-password"}'
curl -si "$BASE_URL/auth/validate_token" -H "access-token: $T" -H "client: $C" -H "uid: $U"
curl -si "$BASE_URL/<protected-route>"   # expect 401
```

Or write the same flow as a `@SpringBootTest` with `MockMvc` or `RestClient`. With `ogiri.confirmable=true` sign-up sends mail and does not sign in. In cookie mode, first `GET /auth/sign_in` (405 is fine) and echo the `XSRF-TOKEN` cookie as `X-XSRF-TOKEN`.

## Common mistakes

- **Disabling CSRF to make sign-in work.** `OgiriCsrfFilter`, installed by `OgiriConfigurer`, checks Ogiri's cookie requests and then skips the host filter for them. Leave the host's `csrf()` alone; header credentials never need a token. A 403 in cookie mode means the XSRF pair is missing.
- **Leaving the redirect allowlist unset** for confirmation, reset or unlock links.
- **Jackson 2 imports** or a Jackson 2 `ObjectMapper` bean for Ogiri payloads. Use Jackson 3.
- **Importing `com.quantipixels.ogiri.*.internal`.** Only the 18 public types listed in `docs/architecture/spring.md` are supported.
- **Using `OgiriConfigurer.ogiri(runtime)` with extra realms.** It throws; use `ogiri(realms)`.
- **Treating the Bearer header as a JWT.** It is base64 JSON of the DTA headers; validate through Ogiri, not a JWT decoder.
- **Revoking access outside Ogiri** (bans, deletes) without deleting the account's sessions.
