# Changelog

All notable changes to Ogiri are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Before 1.0, minor versions may break compatibility; breaking changes are marked **Breaking**.

## [Unreleased]

### Added
- `ogiri-bom` for aligning Ogiri's modules; the starter now publishes Maven Central-valid sources and javadoc jars.
- `compose.yaml` and `mise run db:up` / `db:down` for local PostgreSQL and MySQL using the same pinned images as CI; ports are overridable with `OGIRI_PG_PORT` and `OGIRI_MYSQL_PORT`.
- Tag-triggered release workflow (`v*`), verified and signed; publishing stays inactive until Central and GPG secrets are configured.
- Spring Security authentication events (success, bad credentials, locked, disabled) identifying the account as `realm:uid`, with no credentials.
- Failure logging for storage errors, sign-in failures, locks and unlocks, without tokens, passwords or full emails.
- Opt-in scheduled cleanup of expired sessions in bounded batches, safe with several application instances.
- `skills/auth-design`: an agent skill that interviews you and writes an authentication and authorisation spec fitted to your repository.

### Changed
- **Breaking:** Ogiri now adds its rules to the host application's Spring Security chain instead of replacing them. The host's CSRF configuration, session policy, request cache and CORS are left as configured; stateless defaults apply only to the fallback chain Ogiri supplies when the application defines none. CORS is enabled only when the application configures it.
- Supported platform stated and tested: Spring Boot 4.x, Java 17+, Jackson 3, PostgreSQL and MySQL 8.4.

### Removed
- **Breaking:** the Phoenix (Elixir) and FastAPI (Python) ports and their tooling. Ogiri is a Spring Boot library; the Python HTTP conformance suite remains as a test of the Spring implementation.
- The unused Micrometer dependency.

### Fixed
- Changing another account's password no longer clears the caller's own cookie credential.
- Consumer test classes no longer share sessions through reused account ids.
- Changes under `ogiri-spring-boot-autoconfigure/` now trigger the Java CI lane and formatting checks.
