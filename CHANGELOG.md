# Changelog

All notable changes to Ogiri are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Before 1.0, minor versions may break compatibility; breaking changes are marked **Breaking**.

## [Unreleased]

### Added

- Account-generation binding for DTA sessions. Custom account stores must supply immutable `ogiri_generation`; replacing an account requires a fresh value.
- Provider-aware `AccountStore.findByUid(uid, provider)` and session-based credential resolution by stable account id. The one-argument lookup and custom account snapshots without a provider value use `email`.
- `ogiri-bom` for aligning Ogiri's modules; the dependency-only starter now packages sources and javadoc attachments.
- `compose.yaml` and `mise run db:up` / `db:down` for local PostgreSQL and MySQL using the same pinned images as CI; ports are overridable with `OGIRI_PG_PORT` and `OGIRI_MYSQL_PORT`.
- Tag-triggered release workflow (`v*`) with verification and release rehearsal; signing and publication stay inactive until Central and GPG secrets are configured.
- Spring Security authentication events (success, bad credentials, locked, disabled) identifying the account as `realm:uid`, with no credentials.
- Failure logging for storage errors, sign-in failures, locks and unlocks, without tokens, passwords or full emails.
- Opt-in scheduled cleanup of expired sessions in bounded batches, safe with several application instances.
- `skills/auth-design`: an agent skill that interviews you and writes an authentication and authorisation spec fitted to your repository.

### Changed

- **Breaking:** existing pre-generation schemas need migrations 001 and 002 for PostgreSQL or MySQL. Stop all writers, adapt migration 001 for every account table, and apply both before deploying and restarting. Migration 001 deletes existing sessions; users must sign in again. Fresh schemas already include both changes.
- One realm factory now assembles root and additional realms. Additional realms select named overrides, then application shared beans, then configured defaults. Supported names are `<realm>OgiriAccountStore`, `<realm>OgiriMailer`, `<realm>OgiriPasswordEncoder` and `<realm>OgiriAccountValidator`; the last two use internal types.
- The sample builds outside the reactor with a Boot parent, the Ogiri BOM and starter, using staged artifacts in a worktree-local cache.
- **Breaking:** the declared public API contains 18 top-level types. The following implementation types moved to `internal` packages before 1.0 (source compatibility changes, without changing the wire format):

- `com.quantipixels.ogiri.account.AccountChange` → `com.quantipixels.ogiri.account.internal.AccountChange`
- `com.quantipixels.ogiri.account.AccountInput` → `com.quantipixels.ogiri.account.internal.AccountInput`
- `com.quantipixels.ogiri.account.AccountValidator` → `com.quantipixels.ogiri.account.internal.AccountValidator`
- `com.quantipixels.ogiri.account.ActivationService` → `com.quantipixels.ogiri.account.internal.ActivationService`
- `com.quantipixels.ogiri.account.CodePointLength` → `com.quantipixels.ogiri.account.internal.CodePointLength`
- `com.quantipixels.ogiri.account.CodePointLengthValidator` → `com.quantipixels.ogiri.account.internal.CodePointLengthValidator`
- `com.quantipixels.ogiri.account.DevisePasswordEncoder` → `com.quantipixels.ogiri.account.internal.DevisePasswordEncoder`
- `com.quantipixels.ogiri.account.JdbcDeviseAccountStore` → `com.quantipixels.ogiri.account.internal.JdbcDeviseAccountStore`
- `com.quantipixels.ogiri.account.OgiriPasswords` → `com.quantipixels.ogiri.account.internal.OgiriPasswords`
- `com.quantipixels.ogiri.account.OgiriSettings` → `com.quantipixels.ogiri.account.internal.OgiriSettings`
- `com.quantipixels.ogiri.account.PasswordService` → `com.quantipixels.ogiri.account.internal.PasswordService`
- `com.quantipixels.ogiri.account.RegistrationService` → `com.quantipixels.ogiri.account.internal.RegistrationService`
- `com.quantipixels.ogiri.account.SignInService` → `com.quantipixels.ogiri.account.internal.SignInService`
- `com.quantipixels.ogiri.security.DtaAuthenticationToken` → `com.quantipixels.ogiri.security.internal.DtaAuthenticationToken`
- `com.quantipixels.ogiri.security.DtaCredential` → `com.quantipixels.ogiri.security.internal.DtaCredential`
- `com.quantipixels.ogiri.security.DtaErrors` → `com.quantipixels.ogiri.security.internal.DtaErrors`
- `com.quantipixels.ogiri.security.DtaHeaderWriter` → `com.quantipixels.ogiri.security.internal.DtaHeaderWriter`
- `com.quantipixels.ogiri.security.OgiriAuthenticationFilter` → `com.quantipixels.ogiri.security.internal.OgiriAuthenticationFilter`
- `com.quantipixels.ogiri.security.OgiriTokenAuthenticationProvider` → `com.quantipixels.ogiri.security.internal.OgiriTokenAuthenticationProvider`
- `com.quantipixels.ogiri.security.ResponseCredentials` → `com.quantipixels.ogiri.security.internal.ResponseCredentials`
- `com.quantipixels.ogiri.spring.OgiriSessionCleanup` → `com.quantipixels.ogiri.spring.internal.OgiriSessionCleanup`
- `com.quantipixels.ogiri.spring.RedactedAuthenticationEvents` → `com.quantipixels.ogiri.spring.internal.RedactedAuthenticationEvents`
- `com.quantipixels.ogiri.DtaFailure` → `com.quantipixels.ogiri.internal.DtaFailure`

- **Breaking:** Ogiri now adds its rules to the host application's Spring Security chain instead of replacing them. The host's CSRF configuration, session policy, request cache and CORS are left as configured; stateless defaults apply only to the fallback chain Ogiri supplies when the application defines none. CORS is enabled only when the application configures it.
- Supported platform stated and tested: Spring Boot 4.x, Java 17+, Jackson 3, PostgreSQL and MySQL 8.4.

### Removed

- **Breaking:** the Phoenix (Elixir) and FastAPI (Python) ports and their tooling. Ogiri is a Spring Boot library; the Python HTTP conformance suite remains as a test of the Spring implementation.
- The unused Micrometer dependency.

### Fixed

- A uid-changing account update reissues the retained credential when rotation is enabled, including batch requests, and clears old token digests. With rotation disabled, the token is retained and the response uses the new uid.
- Changing another account's password no longer clears the caller's own cookie credential.
- Consumer test classes no longer share sessions through reused account ids.
- Changes under `ogiri-spring-boot-autoconfigure/` now trigger the Java CI lane and formatting checks.
