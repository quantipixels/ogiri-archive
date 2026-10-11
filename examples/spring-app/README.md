# Spring Boot v2 consumer

This application consumes the public Ogiri starter API. The default Devise-table AccountStore owns auth behavior; the sample supplies only role mapping, configuration and protected GET /me and GET /admin routes. It exposes role through `ogiri.account.columns=role`. The principal is OgiriAccount, with ordinary Spring method security; no UserDetailsService/securityUser adapter is required.

## Build and run through the parity runner

From the repository root:

```sh
bash scripts/platform/java.sh check
bash scripts/platform/java.sh sample
contracts/conformance/run.sh --profile default \
  --sample-command 'mise exec java@temurin-17.0.17+10 -- python3 examples/spring-app/run.py' \
  -- -k 'test_S1_json_and_form_signin or test_R1_signup or test_R10_destroy_account_all_clients'
```

The runner supplies PORT, OGIRI_DATABASE_URL, SMTP and protocol settings, creates a disposable PostgreSQL/Mailpit fixture, starts the sample, exercises it and stops its process group and containers. `run.py` converts the runner's PostgreSQL URL into JDBC configuration and launches the packaged JAR. The selected tests exercise sign-in, registration and account deletion. Broader profiles become usable as their implementation checkpoints land.

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

The sample implements the [runner environment interface](../../contracts/conformance/README.md#sample-env-interface). MySQL consumer proof uses its JDBC URL and `OGIRI_TEST_DATABASE=mysql`; the current parity runner's database mutation adapter supports PostgreSQL. The library/sample manage Jackson 3.1.7 and Tomcat 11.0.25, and the SBOM gate scans both resolved graphs.
