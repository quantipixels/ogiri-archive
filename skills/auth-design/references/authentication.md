# Authentication (stages 1–5)

Each decision lists the options, when each fits, what it costs, and the default. Recommend from the repo facts; drop options the repo rules out. Mark every decision **in / out / later** where it is a feature.

## 1. Who signs in

- **Account types:** one, or several (users, admins, partners). Several types → separate tables and mounts, or one table with roles (prefer one table + roles unless the types share almost nothing).
- **Identity:** email (default), username, phone. Case-insensitive and trimmed.
- **Tenancy:** none; one organisation per user; many organisations per user (memberships). Decide now: it shapes authorisation.
- **Machines:** none; API keys or personal access tokens; service-to-service credentials (OAuth client credentials or mTLS).

## 2. Sign-in methods

| Method | Fits when | Costs |
|---|---|---|
| Password | Default for most apps | Reset flow, breach risk |
| Magic link / email code | Low-frequency use, consumer apps, no passwords wanted | Mail latency and deliverability; link-scanning by mail clients (use a confirm page) |
| SMS code | Phone-first markets | Cost, SIM-swap risk; avoid as the only factor for high value |
| OAuth (Google, Apple, GitHub, Microsoft) | Consumer or developer audiences | Account linking rules; Apple required on iOS if others offered |
| Passkeys (WebAuthn) | Modern apps wanting phishing-resistant sign-in | Device recovery story; still offer a fallback |
| Enterprise SSO (SAML / OIDC) | B2B selling to companies | Per-tenant configuration; often "later" or managed provider |

Second factor: none; authenticator app (TOTP, default when chosen); passkey as second factor; SMS or email code (weaker). Always with recovery codes. Required for admins at minimum in sensitive domains. **Step-up:** ask for the password or second factor again before sensitive actions (change email, password, 2FA, payouts, delete).

## 3. Account lifecycle

| Feature | Options and notes | Default |
|---|---|---|
| Registration | Open; invite-only; admin-created; domain-restricted | Open, unless B2B → invites |
| Validation | Identity format and uniqueness; password 8–128 chars, breached-password check | On |
| Confirmation | Required before sign-in; grace period; not required | Required when email is the identity and mail exists |
| Password reset | Link signs in via redirect; or link returns a reset token to the client app | Return a token for SPA/mobile; link valid 6 h |
| Password change | Needs current password | On |
| Email change | Reconfirm new address; notify old address | On |
| Locking | After N failures (5); unlock by email, by time (1 h), or both; warn on last attempt | Both, for sensitive domains; else rate limit only |
| Tracking | Sign-in count, current/last time and IP | On if admins need it |
| Account deletion | Hard delete; soft delete with grace period; anonymise | Soft delete + purge job when data is regulated |
| Disable / suspend | Admin can block sign-in without deleting | On if admins exist |
| Invitations | Single-use link, expiry, preset role and tenant | On for B2B |
| Lost access | Mail or SMS provider down, or mailbox or phone lost: recovery codes (sign in alone, or only as a second factor), mailbox replacement, written operator procedure | Recovery codes + operator procedure when one person holds all access |
| Account linking | Several sign-in methods on one account | On if OAuth + password |

## 4. Sessions

| Decision | Options | Default |
|---|---|---|
| Lifetime | Hours (sensitive) to weeks (consumer) | 2 weeks; 12 h for admin/sensitive |
| Inactivity timeout | None; minutes to hours | 30 min for sensitive domains, else none |
| Rotation | Off; on every request with a batch window | On for sensitive domains |
| Batch window | Seconds parallel requests may reuse the previous token | 5 s |
| Device limit | Unlimited; N (evict soonest-expiring other session) | 10 |
| Remember me | Usually unneeded with long sessions; or short default + opt-in long | Out, unless lifetime is short |
| Session list / revoke | Let users see and end devices | On |
| End sessions on credential change | Password, email, 2FA change | On |
| New-device alert | Email on sign-in from a new device | On for sensitive domains |

## 5. Clients

| Client | Transport | Notes |
|---|---|---|
| SPA on same site | HttpOnly cookie + CSRF | Never put tokens in localStorage |
| SPA on another site | Cookie with `SameSite=None; Secure` + CSRF, or headers | Prefer a same-site API subdomain |
| Mobile / desktop | Headers; store in Keychain / Keystore | — |
| CLI | Device-code flow or personal access token | — |
| Server-rendered | Session cookie | — |
| Third parties | OAuth authorisation server, or scoped API keys | Usually "later" |

Also decide: allowed CORS origins, allowed redirect URLs, header names, an `Authorization: Bearer` form.
