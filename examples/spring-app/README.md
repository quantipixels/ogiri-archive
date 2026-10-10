# Independent Spring Boot consumer

The example uses a Devise-shaped `users` table from [`contracts/fixtures/devise-users.sql`](../../contracts/fixtures/devise-users.sql). Its `UserDetailsService` reads email, bcrypt password hash, role and lock status from that table. The example opts into Ogiri with `ogiri.enabled=true`; the starter supplies the session service, security integration and JSON endpoints.

The `demo` Spring profile drops and recreates the fixture's users table on every startup. **Use it only with a disposable database, never a real application database.** All three fixture accounts use password `test-password`:

| Username | Behavior |
| --- | --- |
| `demo@example.com` | User role |
| `admin@example.com` | Admin role; can access `/admin` |
| `locked@example.com` | Locked account; sign-in returns 401 |

Install the library from the repo root with `mvn -B -ntp clean install`, using the disposable test database settings in [CONTRIBUTING.md](../../CONTRIBUTING.md). Provision `META-INF/ogiri/schema-postgresql.sql` or `schema-mysql.sql` from the installed core JAR through your own migration; the demo profile initializes only the users fixture.

From the repo root, set your disposable database connection and run the sample:

```sh
export OGIRI_JDBC_URL=jdbc:postgresql://localhost:5432/ogiri_test
export OGIRI_JDBC_USER=ogiri
export OGIRI_JDBC_PASSWORD=ogiri
cd examples/spring-app
mvn spring-boot:run -Dspring-boot.run.profiles=demo
```

For MySQL add `-Pmysql` and use its JDBC URL; the example's PostgreSQL runtime dependency can be removed in a MySQL application. Run from `examples/spring-app` so the demo profile can locate the fixture.

Sign in with `POST /auth/sign-in`, JSON username `demo@example.com`, password `test-password` and a client label; include `Content-Type: application/json` and `X-Requested-With: Ogiri`. Use the returned Authorization header for `/me`, `/auth/session` and `/auth/sessions`. `/admin` demonstrates method-level role denial.

With the sample running, run the shared conformance suite from the repo root (adjust the URL for a custom server port):

```sh
python3 contracts/conformance/check.py --base-url http://localhost:8080
```

Expected result: `10 passed, 0 failed, 1 skipped`. The cross-backend check needs `--peer-url` and is skipped when no peer is supplied.

`ConsumerTest` verifies the default path with a one-connection pool. `ServletPathConsumerTest` verifies login with a context path, MVC servlet prefix and custom Ogiri base path. `HostChainTest` demonstrates two application-owned chains, a custom tenant/ID mapping, disabled endpoints, preserved CSRF and directory outages. Neither test assumes H2 represents a production database.

Configure driver-specific socket timeouts in the JDBC URL: PostgreSQL uses `socketTimeout=10` for ten seconds, while MySQL uses `socketTimeout=10000`. The common application properties intentionally do not set a driver-specific socket timeout. See [pgJDBC parameters](https://jdbc.postgresql.org/documentation/use/) and [Connector/J networking](https://dev.mysql.com/doc/connector-j/en/connector-j-connp-props-networking.html).
