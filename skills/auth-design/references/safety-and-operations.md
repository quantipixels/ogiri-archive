# Safety and operations (stages 7–8)

Each decision lists the options, when each fits, what it costs, and the default. Recommend from the repo facts; drop options the repo rules out. Mark every decision **in / out / later** where it is a feature.

## 7. Account safety

- Breached-password check (k-anonymity API).
- CAPTCHA or bot protection on sign-up, sign-in and reset after suspicious volume.
- Rate limits per IP and per account.
- New-device and credential-change notifications.
- Admin actions: force sign-out, disable account, reset 2FA (with step-up and audit).

## 8. Operations and compliance

- **Audit log:** sign-ins, failures, locks, credential changes, role changes, impersonation, exports; who, what, when, IP; retention period.
- **Mail and SMS:** sender, templates, localisation, delivery failures.
- **Cleanup:** expired sessions and tokens on a schedule.
- **Monitoring:** failed sign-in spikes, lockout rates, database errors on auth paths.
- **Migration:** import existing users and password hashes (verify old hash, rehash on next sign-in).
- **Privacy:** data export, deletion, consent and terms acceptance (with version), data residency.
- **Secrets:** signing keys, OAuth client secrets, rotation plan.
