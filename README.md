# Ogiri

Ogiri adds database-backed opaque sessions and devise_token_auth (DTA) account endpoints to a Spring Boot application. Existing DTA frontends keep working. Every authenticated request checks the stored session and the current account. Your application keeps its account model and authorization rules.

Requirements: Spring Boot 4.x (built against 4.1.1), Java 17+, Jackson 3, PostgreSQL or MySQL 8.4 (InnoDB). Boot 3 and Jackson 2 are unsupported. Version `0.0.1` is an unpublished prototype; before 1.0, API and schema changes can break compatibility (see the [changelog](CHANGELOG.md)).

Coding agents: use the [ogiri-integration skill](skills/ogiri-integration/SKILL.md) to add Ogiri to an app, and [auth-design](skills/auth-design/SKILL.md) to plan auth first.

## 1. Add the dependency

Ogiri is not on Maven Central yet. Build it from a checkout with the tools in `mise.toml`:

```sh
mise exec -- bash scripts/platform/java.sh sample
```

This stages the artifacts in `target/java/consumer-cache` and writes `target/java/consumer-settings.xml`; pass that file with `mvn -s` from your application. It needs no database and does not touch your shared Maven cache.

In your application's POM (with `spring-boot-starter-parent` 4.1.1):

```xml
<properties>
  <jackson-bom.version>3.1.7</jackson-bom.version>
  <tomcat.version>11.0.26</tomcat.version>
</properties>
<dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>com.quantipixels.ogiri</groupId>
      <artifactId>ogiri-bom</artifactId>
      <version>0.0.1</version>
      <type>pom</type>
      <scope>import</scope>
    </dependency>
  </dependencies>
</dependencyManagement>
<dependencies>
  <dependency>
    <groupId>com.quantipixels.ogiri</groupId>
    <artifactId>ogiri-spring-boot-starter</artifactId>
  </dependency>
  <dependency>
    <groupId>org.postgresql</groupId>
    <artifactId>postgresql</artifactId>
    <scope>runtime</scope>
  </dependency>
</dependencies>
```

For MySQL use `com.mysql:mysql-connector-j`. The Jackson and Tomcat overrides pick up security fixes missing from Boot 4.1.1's defaults. The BOM aligns only Ogiri artifacts.

## 2. Create the tables

Ogiri runs no DDL at startup. Through your migration tool, apply from the `ogiri` JAR:

- `META-INF/ogiri/ogiri-postgresql.sql` (sessions and lock tables), always;
- `META-INF/ogiri/users-postgresql.sql` (a Devise-shaped account table), unless you already have one.

MySQL uses the `-mysql.sql` files. The same files are in [contracts/schema](contracts/schema/). An existing account table needs the columns in `users-<engine>.sql`, including `ogiri_generation`. To upgrade a schema from before account generations, see [Schema and upgrades](docs/architecture/spring.md#schema-and-upgrades).

For disposable local databases, `mise run db:up` starts PostgreSQL and MySQL with Docker (credentials and ports in `compose.yaml`).

## 3. Configure

```properties
spring.datasource.url=jdbc:postgresql://localhost:5432/app
spring.datasource.username=app
spring.datasource.password=secret
spring.mail.host=localhost
spring.mail.port=1025
ogiri.public-base-url=https://app.example.com
ogiri.redirect-allowlist=https://app.example.com
```

Startup needs `ogiri.public-base-url` (an absolute HTTP(S) URL used in mail links) and a mailer: either `spring.mail.*` or an `OgiriMailer` bean, even with confirmation off. Set `ogiri.redirect-allowlist` before using confirmation, password-reset or unlock links; [SECURITY.md](SECURITY.md) explains what an empty list accepts.

This gives one realm, `users`, mounted at `/auth` on table `users`. Common settings (all in [`OgiriProperties`](ogiri-spring-boot-autoconfigure/src/main/java/com/quantipixels/ogiri/spring/OgiriProperties.java)):

| Property | Default | Purpose |
|---|---|---|
| `ogiri.base-path` | `/auth` | Mount for the endpoints |
| `ogiri.account.table` | `users` | Account table for the default store |
| `ogiri.account.columns` | empty | Extra account columns returned in responses |
| `ogiri.permitted-fields` | `name,nickname,image` | Extra fields accepted on sign-up and update |
| `ogiri.token-lifespan` | `14d` | Session lifetime |
| `ogiri.max-number-of-devices` | `10` | Sessions per account; the soonest-expiring is evicted |
| `ogiri.change-headers-on-each-request` | `false` | Rotate the token on each request |
| `ogiri.confirmable` / `ogiri.lockable` | `false` | Email confirmation / lock after `maximum-attempts` (20) failures |
| `ogiri.remove-tokens-after-password-reset` | `false` | End other sessions after a reset |
| `ogiri.cookie-enabled` | `false` | Also issue an HttpOnly auth cookie |
| `ogiri.cookie-secure` | `true` | Set `false` only for local HTTP |
| `ogiri.cleanup.interval` | unset | Enable deleting expired sessions, e.g. `1h` |
| `ogiri.realms.<name>.*` | | Additional realms; inherit root settings |

## 4. Use the endpoints

Without your own `SecurityFilterChain`, the starter supplies a stateless chain: sign-up, sign-in, confirmation, unlock and password recovery are public, and everything else requires authentication.

| Method and path | Purpose |
|---|---|
| `POST /auth` | Sign up (signs in unless `confirmable`) |
| `PUT`/`PATCH /auth`, `DELETE /auth` | Update or delete the current account |
| `POST /auth/sign_in`, `DELETE /auth/sign_out` | Sign in, sign out |
| `GET /auth/validate_token` | Check credentials and return the account |
| `POST /auth/password`, `GET /auth/password/edit`, `PUT`/`PATCH /auth/password` | Password recovery and change |
| `GET`/`POST /auth/confirmation`, `GET`/`POST /auth/unlock` | Email confirmation and unlock |
| `GET /auth/sessions`, `DELETE /auth/sessions/{client}`, `DELETE /auth/sessions` | List and revoke the account's sessions |

[contracts/PROTOCOL.md](contracts/PROTOCOL.md) specifies every request and response.

```sh
curl -i "$BASE_URL/auth" -H 'Content-Type: application/json' \
  --data '{"email":"demo@example.com","password":"test-password","password_confirmation":"test-password"}'
curl -i "$BASE_URL/auth/sign_in" -H 'Content-Type: application/json' \
  --data '{"email":"demo@example.com","password":"test-password"}'
curl -i "$BASE_URL/auth/validate_token" \
  -H "access-token: $ACCESS_TOKEN" -H "client: $CLIENT" -H "uid: $AUTH_UID"
```

Responses carry `access-token`, `client`, `uid`, `expiry` and `token-type` headers, plus an `Authorization: Bearer` header that encodes the same set as base64 JSON (not a JWT). Send either form back. Credentials in query strings or form fields are ignored.

**Cookie mode** (`ogiri.cookie-enabled=true`): first send a safe request such as `GET /auth/sign_in` (a 405 is fine) and keep the `XSRF-TOKEN` cookie. Send it back with its value in `X-XSRF-TOKEN` on sign-in, sign-up and every unsafe cookie-authenticated request. Header credentials need no CSRF token. Ogiri's own CSRF filter does this check; do not disable your application's CSRF protection.

**Browsers on other origins:** configure CORS in your application and call `OgiriConfigurer.exposeHeaders(cors)` so the credential headers are readable.

## 5. Protect your routes and customize

Use Spring Security as usual. The principal is `OgiriAccount` (a `UserDetails`):

```java
@GetMapping("/me")
Map<String, String> me(@AuthenticationPrincipal OgiriAccount account) {
    return Map.of("uid", account.uid());
}
```

Map roles with an `OgiriAuthorities` bean. With your own `SecurityFilterChain`, add `http.with(OgiriConfigurer.ogiri(realms), c -> {})` and permit Ogiri's public workflows; see [Spring Security and credentials](docs/architecture/spring.md#spring-security-and-credentials).

To replace a part of the default realm, declare a bean of that type: `AccountStore` (your own account model), `OgiriMailer` (mail delivery). For an additional realm, name the bean after the realm:

| Bean name | Type |
|---|---|
| `<realm>OgiriAccountStore` | `com.quantipixels.ogiri.account.AccountStore` |
| `<realm>OgiriMailer` | `com.quantipixels.ogiri.mail.OgiriMailer` |
| `<realm>OgiriPasswordEncoder` | `com.quantipixels.ogiri.account.internal.OgiriPasswords` |
| `<realm>OgiriAccountValidator` | `com.quantipixels.ogiri.account.internal.AccountValidator` |

Declare realm-only beans with `@Bean(defaultCandidate = false)`. The last two use internal types that can change before 1.0. Only the 18 public types listed in the [architecture notes](docs/architecture/spring.md#modules-and-public-api) are supported; `*.internal` packages are not. A custom `AccountStore` must use Ogiri's `DataSource` and supply an immutable `ogiri_generation` for each account.

## More

- [Spring architecture](docs/architecture/spring.md): realms, bean resolution, transactions, cookies, events and operations.
- [Security](SECURITY.md): threat model, defaults and how to report vulnerabilities.
- [Sample application](examples/spring-app/README.md): a working host with roles, two realms and cookie mode.
- [Protocol](contracts/PROTOCOL.md): HTTP contract and differences from DTA.
- [Contributing](CONTRIBUTING.md) and [publishing](PUBLISHING.md).

Licensed under Apache-2.0.
