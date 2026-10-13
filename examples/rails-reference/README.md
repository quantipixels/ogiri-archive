# Rails DTA oracle

A disposable Rails 8 API application, not an Ogiri implementation. The Docker image pins Ruby by image digest and locks Rails 8.0.5.1, Devise `05811fb8366edd08874111d0f6fb44543e1c91ef`, and DeviseTokenAuth `b02076a930f7d0a4a155e25feaa7a50b86dbc625`. Controllers and token handling come from the upstream gems without patches.

From the repository root:

```sh
examples/rails-reference/run.sh --profile all --cross-backend
```

This delegates to the parity runner, which builds the image, creates its own PostgreSQL and Mailpit containers on random host ports, applies the shared users schema, shared fixture and Ogiri schema, and adds Rails' nullable `tokens text` column. A separate `admins` table demonstrates a second DTA mapping at `/admin_auth`. Each profile receives a fresh database. All containers are removed in `finally`; unrelated containers are untouched. Dependencies: Docker, uv, Node/npm. See [the suite interface](../../contracts/conformance/README.md).

The model enables database_authenticatable, registerable, recoverable and validatable. `OGIRI_CONFIRMABLE` and `OGIRI_LOCKABLE` enable the optional modules; lockable defaults to email plus time (`both`). Confirmable also enables DTA `send_confirmation_email`, which installs its reconfirmation support, matching DTA's own `ConfirmableUser` test model. Without that DTA setting, email changes are immediate despite Devise's `reconfirmable=true`.

`/me` and `/admin` use DTA's normal controller authentication helper and the fixture role. Cookies/session middleware supports Devise/Warden; credentials still use DTA. CORS exposes the DTA headers. Rails open redirects are permitted so DTA's redirect allowlist remains the tested policy. Mail delivery is synchronous SMTP to the configured Mailpit. Raw password and token parameters are filtered from Rails logs. Fixed oracle secrets and trust authentication are only for these disposable containers.

The application reads the entire documented sample env interface. `PORT` controls Puma and mail-link URLs. The runner supplies host-visible ports and rewrites only database/SMTP hostnames for Docker's `host.docker.internal`. The app performs no schema creation at startup. Empty default URLs mean unset.
