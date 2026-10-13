# Spring Boot 4 consumer

This application consumes the public Ogiri starter API. The default Devise-table AccountStore owns auth behavior; the sample supplies only role mapping, configuration and protected GET /me and GET /admin routes. Set `OGIRI_ACCOUNT_VIEW_FIELDS=role` to expose role through `ogiri.account.columns`; the default wire view remains the protocol allowlist. The principal is OgiriAccount, with ordinary Spring method security; no UserDetailsService/securityUser adapter is required.

To add Ogiri to your own application, follow the [root README](../../README.md). This page covers running this sample.

## Build and test

The sample reads its datasource, mail and `ogiri.*` settings from environment variables; see `src/main/resources/application.properties`. Its `admins` realm needs a second account table.

For disposable databases from this checkout:

```sh
mise run db:up
mise exec -- bash scripts/platform/java.sh ci
mise run db:down
```

To isolate concurrent work, set `COMPOSE_PROJECT_NAME`, `OGIRI_PG_PORT` and
`OGIRI_MYSQL_PORT` for all three commands. Set `OGIRI_TEST_DATABASE=mysql` to
run the gate against MySQL. The gate builds the library, stages its artifacts
into `target/java/consumer-cache`, then builds this Boot-parent application
using that repository; no published release or `mvn install` is required.
Database tests create their disposable schema. For a normal external build,
resolve the Ogiri artifacts from your configured Maven repository and run
`mvn verify` in your application.

## Build and run through the conformance runner

From the repository root:

```sh
bash scripts/platform/java.sh check
bash scripts/platform/java.sh sample
contracts/conformance/run.sh --profile default \
  --sample-command 'mise exec java@temurin-17.0.17+10 -- python3 examples/spring-app/run.py' \
  -- -k 'test_S1_json_and_form_signin or test_R1_signup or test_R10_destroy_account_all_clients'
```

The runner supplies PORT, OGIRI_DATABASE_URL, SMTP and protocol settings, creates a disposable PostgreSQL/Mailpit fixture, starts the sample, exercises it and stops its process group and containers. `run.py` converts the runner's PostgreSQL URL into JDBC configuration and launches the packaged JAR. The selected tests exercise sign-in, registration and account deletion.

For a manually managed disposable database, apply the packaged ogiri/users schemas and the shared devise-users fixture, then set OGIRI_DATABASE_URL (PostgreSQL URL or JDBC URL), OGIRI_JDBC_USER/OGIRI_JDBC_PASSWORD when using JDBC, OGIRI_SMTP_HOST/OGIRI_SMTP_PORT and PORT. Start with `mise exec java@temurin-17.0.17+10 -- python3 examples/spring-app/run.py`. Stop that process when finished. Production schema migrations are application-owned; Ogiri performs no startup DDL.

The demo profile recreates disposable users/session fixtures. It must only be used on a throwaway database. `bash scripts/platform/java.sh ci` drives the installed-artifact consumer tests with OGIRI_TEST_DATABASE, OGIRI_TEST_JDBC_URL, OGIRI_TEST_JDBC_USER and OGIRI_TEST_JDBC_PASSWORD. Those tests also prove a one-connection pool and matching JPA host transactions.

## Try the HTTP flow

Fixture emails demo@example.com and admin@example.com both use password test-password. The default profile has lockout and confirmation off. Set BASE_URL to the running sample's HTTP URL:

```sh
curl -i "$BASE_URL/auth/sign_in" \
  -H 'Content-Type: application/json' \
  --data '{"email":"demo@example.com","password":"test-password"}'
```

Copy access-token, client and uid from the response headers and send them back:

```sh
curl -i "$BASE_URL/me" \
  -H "access-token: $ACCESS_TOKEN" -H "client: $CLIENT" -H "uid: $AUTH_UID"
curl -i -X DELETE "$BASE_URL/auth/sign_out" \
  -H "access-token: $ACCESS_TOKEN" -H "client: $CLIENT" -H "uid: $AUTH_UID"
```

/me returns `{"uid":"demo@example.com"}`; replaying the revoked credentials returns 401. /admin requires the admin role. /auth/validate_token validates the account and /auth/sessions lists clients.

DTA clients replay **access-token/client/uid**. **Authorization: Bearer base64(JSON)** is an alternative encoding of those credentials, not a JWT; the response provides a complete header ready to replay. No X-Requested-With header is required. Sign-in returns an account JSON object and credentials in headers, rather than session metadata in the body.

The sample implements the [runner environment interface](../../contracts/conformance/README.md#sample-env-interface). MySQL consumer proof uses its JDBC URL and `OGIRI_TEST_DATABASE=mysql`; the current conformance runner's database mutation adapter supports PostgreSQL. The sample uses Boot-managed Jackson and the Tomcat override documented above; the SBOM gate scans both library and consumer resolved graphs.

Account views use the protocol default allowlist. Set `OGIRI_ACCOUNT_VIEW_FIELDS=role` to expose the fixture role explicitly; authority mapping always reads it independently.

The additional `/admin_auth` mount reads the application-owned `admins` table and inherits root settings. The conformance runner provisions it; a manually managed database must apply that account-table migration too.

## Cookie mode

Set `OGIRI_COOKIE_ENABLED=true`; the sample uses distinct `auth_cookie` and `admin_auth_cookie` names for its realms. Auth cookies are HttpOnly, SameSite=Lax, Path=/ and Secure by default; set `OGIRI_COOKIE_SECURE=false` only for local HTTP development. Cookie mode omits the Authorization response header.

Before sign-in or registration that signs in (confirmable=false), call an existing safe route such as `GET /auth/sign_in` and read its `XSRF-TOKEN` cookie (the endpoint may return 405). Send that cookie and its value as `X-XSRF-TOKEN` on those requests and on unsafe cookie-authenticated requests. Sign-in and registration that signs in require CSRF even before an auth cookie exists. Batch responses leave the auth cookie unchanged. Complete named DTA headers or Bearer credentials select header authentication and require no cookie CSRF on protected requests. Sign-out and terminal session/account revocation clear the auth cookie.

Use the same cookie path (normally /) across cookie-enabled realms and distinct auth cookie names, as this sample does. XSRF-TOKEN/X-XSRF-TOKEN are shared across realms: differing paths can send duplicate XSRF-TOKEN cookies, and Spring taking the first while the browser echoes another causes 403. Per-realm CSRF names are not supported.
