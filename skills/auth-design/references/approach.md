# Approach (stage 0)

Each decision lists the options, when each fits, what it costs, and the default. Recommend from the repo facts; drop options the repo rules out. Mark every decision **in / out / later** where it is a feature.

## 0. Approach

| Option | Fits when | Costs |
|---|---|---|
| **Keep and harden existing auth** (check first) | The repo already has working auth: custom database-backed sessions, framework sessions or a provider | Inherits its limits; the spec lists only the gaps to close |
| **Opaque rotating tokens** (default) | Own API with SPA, mobile or CLI clients; need instant sign-out, device limit, session list | A database lookup per request |
| **Server sessions** (framework session cookie) | Server-rendered or same-site web only, one backend | Weak for mobile/CLI; CSRF to handle |
| **JWT access + refresh** | Several services must check tokens without calling the auth service; no shared database | Revocation is hard: short access lifetime, refresh rotation, denylist; key management; tokens grow with claims |
| **Managed provider** (Auth0, Clerk, Cognito, Supabase, Keycloak) | Need enterprise SSO, MFA or compliance fast; small team; no wish to run auth | Cost per user, lock-in, data with a third party, less control over flows |

Custom database-backed cookie sessions count as server sessions. Signals: existing working auth → keep and harden. One backend + mobile → opaque tokens. Server-rendered only → server sessions. Many services, no shared DB → JWT (say the revocation cost). Enterprise customers or regulated data and a small team → managed provider. Opaque tokens and server sessions can coexist (cookie for web, headers for mobile).
