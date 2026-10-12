---
name: auth-design
description: Interview the user and produce a spec for an app's authentication and authorisation, fitted to the current repo. Compares approaches (opaque rotating tokens, server sessions, JWT, managed provider), sign-in methods, account lifecycle, sessions, clients, permission models and operations, recommending one option per decision from the repo's code, docs and domain. Use for "add auth", "sign in / sign up", "roles and permissions", "token auth", in any framework. Output is a spec, not code.
---

# Auth spec

**Result:** a spec in which every decision in the `references/` choice files is settled **in / out / later** with a reason and the repo fact behind it, plus the protocol, data model, rules and acceptance checks a builder needs.

**Not for:** building the code (that comes after, from the spec), or running an identity provider for other companies.

## Files

Each choice file lists decisions with options, trade-offs and the repo signals that pick one. Read each when its stage comes up:
- `references/approach.md`: stage 0.
- `references/authentication.md`: stages 1–5 (who signs in, methods, lifecycle, sessions, clients).
- `references/authorisation.md`: stage 6 (permission model, checks, tenancy).
- `references/safety-and-operations.md`: stages 7–8.
- `references/token-protocol.md`: pseudocode, settings and data model for opaque rotating tokens. Read it when stage 1 picks that approach.

## 1. Read before you ask

Read the repo and its docs. Note, with file references:
- framework, version, database, migration tool, existing security setup or auth;
- user model(s) and columns; how many kinds of account sign in;
- domain: what the product does, who uses it, what is sensitive (money, health, minors, admin power), any compliance named in docs;
- clients: browser SPA, server-rendered pages, mobile, CLI, third-party integrations, other services;
- tenancy: are there organisations, teams or workspaces; who owns which records;
- existing roles, admin flags, permission checks or ownership checks in the code;
- mailer, SMS, logging, rate limiting, background jobs, secrets handling.

Confirm each fact in the code before citing it; a doc saying something exists is not enough.

Show a short **What I learned** note and ask the user to correct it. Every recommendation later cites one of these facts.

## 2. Interview

Walk the stages in order: one round per stage with real decisions; stages that are only easy defaults share a round. For each decision:
1. say what the repo shows;
2. give the options that are realistic for this repo (drop ones the repo rules out, and say why);
3. recommend the least machinery that meets the need, with the trade-off the user accepts; once the user states a priority (such as "minimal"), it overrides the defaults in the choice files;
4. ask only when the repo can't decide it.

Stages: 0 approach → 1 who signs in → 2 sign-in methods → 3 account lifecycle → 4 sessions → 5 clients → 6 authorisation → 7 account safety → 8 operations and compliance.

Keep a short **Decided** list and add to it each round. Never re-ask a decided item and don't repeat the list in full; use tables only for open decisions. Group easy defaults into one confirm-all question; spend questions on the decisions that change the design. Use an interview skill if one is installed. Stop when every decision has an answer.

## 3. Rules the spec must state

Authentication:
- Credentials are random secrets stored hashed (SHA-256 for 32-byte random tokens; Argon2id or BCrypt for passwords). Compare in constant time. Never log secrets.
- Reset, confirmation, unlock, magic-link and invite tokens are single-use, hashed and expire.
- Look accounts up by normalised identity **and** provider. Link OAuth to an existing account by verified email only.
- Unknown account and wrong password take the same time and give the same answer; reset, unlock and magic-link requests answer the same whether or not the account exists.
- A session belongs to the account, not just an id; reject it if the account was deleted or the id reused.
- An action on another account never rotates, expires or clears the caller's own credential.
- Password change, reset, email change and 2FA change end the other sessions (when chosen) and notify the user.
- Redirect URLs come from an allow-list, for every flow.
- Cookies: `HttpOnly`, `Secure`, `SameSite`, with CSRF protection on unsafe methods. Add auth to the host's security setup; never replace its CSRF, CORS or session policy.
- Rate-limit sign-in, reset, resend, unlock, 2FA and magic-link endpoints.

Authorisation:
- Deny by default. Every endpoint and background job declares who may call it.
- Check permission on the server for every request, on the record, not just the route ("can edit *this* invoice").
- Tenant isolation: every query is scoped to the caller's tenant; a missing scope is a bug, and tests prove cross-tenant access fails.
- Permissions come from the server's data, never from client input or an unverified token claim.
- Roles and permission changes take effect on the next request (or state the delay).
- Privileged actions (role change, impersonation, export, delete) are logged with who, what, when and on whose behalf.

## 4. Write the spec

Use a spec-writing skill if one is installed, otherwise these headings. Cite the repo files each decision rests on.
1. Problem, users and **What I learned**.
2. Decisions: every decision from the choice files, with the chosen option, the reason and what was rejected.
3. Protocol and endpoints for the chosen approach, with headers and status codes.
4. Data model: accounts, sessions or tokens, and the authorisation tables (roles, memberships, grants) the chosen model needs.
5. Permission matrix: roles (or relations) × actions × resources, including tenant scope.
6. Rules: section 3, as they apply.
7. Acceptance checks: one per chosen feature, plus always:
   - an unknown account and a wrong password are indistinguishable;
   - a used or expired single-use link is rejected;
   - a disallowed redirect URL is rejected;
   - an action on another account leaves the caller signed in;
   - a user without permission gets 403 (or 404 to hide existence) on every protected action;
   - a user in tenant A can never read or change tenant B's data;
   - revoking a role or session takes effect within the stated delay;
   - plus the approach-specific checks in `references/token-protocol.md` when that approach is chosen.
8. Non-goals, "later" items and open questions.

## Done when

Every decision has an answer and a reason, every chosen feature has an acceptance check, the permission matrix is complete, and the user has confirmed the spec. Return the spec's path and a five-line summary: approach, features in, authorisation model, main risks, open questions.
