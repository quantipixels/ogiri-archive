# Ogiri

Ogiri provides database-backed opaque sessions and devise_token_auth account workflows for Spring Boot. Every authenticated request checks the stored session and current account. Applications keep their account model and authorization rules.

The baseline is Spring Boot 4.1.1, Java 17+, Jackson 3.1.7, PostgreSQL and MySQL 8.4 (InnoDB). Boot 3 and Jackson 2 are unsupported. The library builds with Java 21+; repository scripts select JDK 25 and run tests on Java 17. Check other Boot 4.x versions in your application.

The POM version is `0.0.1`; the project is an unpublished prototype. The instructions below build local artifacts and do not assume a Maven Central release. Before 1.0, API and schema changes can break compatibility; see the [changelog](CHANGELOG.md) and [security notes](SECURITY.md).

## Quickstart

### Build the library and independent sample

From a checkout, with the tools in `mise.toml` installed:

```sh
mise exec -- bash scripts/platform/java.sh fix
mise exec java@25.0.2 -- ./ogiri/mvnw --batch-mode --no-transfer-progress -o -DskipTests verify
mise exec -- bash scripts/platform/java.sh sample
```

These commands need no database. The offline verification needs a populated Maven cache; on a first build, omit `-o` to download dependencies. Tests are skipped here. The sample task stages the built artifacts in `target/java/consumer-cache`, writes `target/java/consumer-settings.xml`, and packages a separate Boot-parent application. It does not install Ogiri into your shared Maven cache.

### Add the BOM and starter

Start with a Java 17+ Spring Boot application using `spring-boot-starter-parent` 4.1.1. Add these sections to its POM:

```xml
<properties>
  <java.version>17</java.version>
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
<build>
  <plugins>
    <plugin>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-maven-plugin</artifactId>
    </plugin>
  </plugins>
</build>
```

For MySQL, replace the driver with `com.mysql:mysql-connector-j`. The BOM aligns only Ogiri artifacts. Boot 4.1.1 ships Jackson 3.1.5 and Tomcat 11.0.24, which have known advisories; the Jackson 3.1.7 and Tomcat 11.0.26 overrides pick up the fixes. Use the generated consumer settings when resolving these unpublished artifacts from another application.

### Apply the schema and configure one realm

Ogiri performs no startup DDL. Through your application's migration tool, apply `META-INF/ogiri/ogiri-postgresql.sql` from the core JAR and, for a new account table, `META-INF/ogiri/users-postgresql.sql`. MySQL uses the corresponding `-mysql.sql` files. The same schemas are available in the checkout's `contracts/schema` directory. Schema application needs a database.

For an existing pre-generation schema, stop all writers and apply [migrations](contracts/schema/migrations/) `001-account-generation-<engine>.sql` and `002-credential-lookup-<engine>.sql` in order. Adapt the account-table steps for every realm. Migration 001 invalidates all existing sessions; users must sign in again. Follow the MySQL script's binary-logging requirement. Deploy the matching library before restarting. Fresh schemas already contain these changes.

For disposable local PostgreSQL and MySQL, this command needs Docker and starts databases:

```sh
mise run db:up
```

The Compose credentials and default ports are in `compose.yaml`; override ports with `OGIRI_PG_PORT` and `OGIRI_MYSQL_PORT`. Compose starts databases but does not apply your application's migrations.

Put this in your application's `application.properties`, supplying the environment values for your database, SMTP server and public application URL:

```properties
spring.datasource.url=${OGIRI_JDBC_URL}
spring.datasource.username=${OGIRI_JDBC_USER}
spring.datasource.password=${OGIRI_JDBC_PASSWORD}
spring.mail.host=${OGIRI_SMTP_HOST}
spring.mail.port=${OGIRI_SMTP_PORT}
ogiri.public-base-url=${OGIRI_PUBLIC_BASE_URL}
ogiri.realm=users
ogiri.base-path=/auth
ogiri.account.table=users
ogiri.cookie-enabled=false
```

For PostgreSQL, `OGIRI_JDBC_URL` has the form `jdbc:postgresql://host:port/database`; for MySQL, `jdbc:mysql://host:port/database`. The public URL must be an absolute HTTP(S) URL. Mail delivery can instead be supplied by an `OgiriMailer` bean. Startup requires a public URL and a mail implementation even with confirmation disabled. Configure redirect allow-lists before using confirmation, recovery or unlock links.

This creates one realm. Without an application `SecurityFilterChain`, the starter supplies a stateless chain with public auth workflows and authentication required elsewhere. For an existing host chain, explicitly install `OgiriConfigurer.ogiri(realms)` and keep your application's authorization rules; see the [Spring architecture](docs/architecture/spring.md).

From your application directory, set `OGIRI_CONSUMER_SETTINGS` to the absolute path of the checkout's generated `target/java/consumer-settings.xml`. This command needs the migrated database and runtime environment above:

```sh
mvn -s "$OGIRI_CONSUMER_SETTINGS" spring-boot:run
```

### Register and use header credentials

The following commands need the running application and database. Set `BASE_URL` to its public URL. With confirmation and cookie mode at their defaults, registration signs in the new account:

```sh
curl -i "$BASE_URL/auth" \
  -H 'Content-Type: application/json' \
  --data '{"email":"demo@example.com","password":"test-password","password_confirmation":"test-password"}'
```

For an existing account:

```sh
curl -i "$BASE_URL/auth/sign_in" \
  -H 'Content-Type: application/json' \
  --data '{"email":"demo@example.com","password":"test-password"}'
```

The response contains `{"data": <account>}` and credential headers. Copy `access-token`, `client` and `uid` into `ACCESS_TOKEN`, `CLIENT` and `AUTH_UID`, then validate or sign out:

```sh
curl -i "$BASE_URL/auth/validate_token" \
  -H "access-token: $ACCESS_TOKEN" -H "client: $CLIENT" -H "uid: $AUTH_UID"
curl -i -X DELETE "$BASE_URL/auth/sign_out" \
  -H "access-token: $ACCESS_TOKEN" -H "client: $CLIENT" -H "uid: $AUTH_UID"
```

The complete response `Authorization` header can also be replayed. It is Bearer base64-encoded JSON containing the DTA credentials, not a JWT. Named headers take precedence per field; query and form credentials are ignored. Defaults are a 14-day lifetime, 10 sessions per account and rotation off. When enabling `ogiri.change-headers-on-each-request`, use a DTA client that handles rotation and batch responses.

### Cookie mode

Set `ogiri.cookie-enabled=true` for an HttpOnly auth cookie. It defaults to Secure, SameSite=Lax and Path=/. Use HTTPS; set `ogiri.cookie-secure=false` only for local HTTP development. Cookie mode omits the Bearer response header.

Before sign-in or registration that signs in, send a safe request such as `GET /auth/sign_in` and retain the `XSRF-TOKEN` cookie; that route may return 405 while setting the cookie. Send both that cookie and its value in `X-XSRF-TOKEN` on sign-in, registration that signs in, and unsafe cookie-authenticated requests. This is required even before the auth cookie exists. Complete header credentials need no Ogiri cookie CSRF on protected requests. Other host requests keep the host's CSRF policy.

For browser calls across origins, configure trusted CORS origins in your application and use `OgiriConfigurer.exposeHeaders(cors)` to expose credential headers. Ogiri does not configure CORS for you.

## Extend and operate

Use `com.quantipixels.ogiri.account.AccountStore` for a custom model. Every persisted `OgiriAccount` must provide immutable `ogiri_generation` (1–36 characters), with a fresh value when an account is replaced. A missing provider value in a custom account snapshot means `email`; the default JDBC table still needs its provider column. `findByUid(uid, provider)` is provider-aware, while the one-argument form means `email`.

`OgiriAccount` implements `UserDetails`; use `@AuthenticationPrincipal OgiriAccount`. Supply `OgiriAuthorities` to map roles. Wire fields are separate from authorities: expose extra fields through `ogiri.account.columns`, and permit extra input fields through `ogiri.permitted-fields`. Reserved identity, generation, password, token and account-state names cannot be permitted fields.

Additional realms use `ogiri.realms.<name>.*` and distinct mounts and account tables. Per-realm stores and mailers use `<realm>OgiriAccountStore` and `<realm>OgiriMailer`; see [bean selection and the 18-type public API](docs/architecture/spring.md). Types in `internal` packages are implementation details.

Spring Security events identify accounts as `realm:uid`, without credentials. Token validation emits success events too, so do not count each event as a new sign-in. Logs omit identities and secrets. Expiry is checked on every authentication; optional housekeeping is enabled with `ogiri.cleanup.interval=1h`, with a default batch size of 1000 shared across realms.

See the [independent sample](examples/spring-app/README.md) for database-backed exercises, the [protocol](contracts/PROTOCOL.md) for HTTP workflows, and the [auth-design skill](skills/auth-design/SKILL.md) for application planning. Licensed under Apache-2.0.
