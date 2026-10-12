# Authorisation (stage 6)

Each decision lists the options, when each fits, what it costs, and the default. Recommend from the repo facts; drop options the repo rules out. Mark every decision **in / out / later** where it is a feature.

## 6. Authorisation

**Model:**

| Model | Fits when | Costs |
|---|---|---|
| Owner-only | Users touch only their own records | Breaks once sharing or teams appear |
| Roles (RBAC) (default) | A few fixed roles: member, admin, owner | Role explosion if rules depend on data |
| Roles per tenant | B2B: a user is admin in org A, member in org B | Membership table; every check needs the tenant |
| Attributes (ABAC) / policies | Rules depend on record fields ("editor of draft invoices under £1k") | Harder to audit; put policies in one place |
| Relationships (ReBAC, Zanzibar-style) | Sharing, folders, nested teams, Google-Docs-like access | Needs a relation store or service (OpenFGA, SpiceDB) |

**Decide also:**
- **Where checks live:** one policy layer (per-resource policy classes or a policy function) called from every endpoint and job; not scattered `if admin`.
- **Granularity:** per route, per action, per record, per field (hide salary, mask PII).
- **Tenant scoping:** automatic scope on every query (row-level security or a repository filter) vs manual; prefer automatic.
- **Super-admin and support access:** impersonation with audit, read-only support role, break-glass account.
- **Machine scopes:** API keys and tokens carry scopes (`invoices:read`) checked like permissions.
- **Delegation:** users granting access to others (sharing, inviting) and who may grant which role.
- **Visibility:** 403 vs 404 for records the caller may not see (404 hides existence).
- **Change latency:** permissions read per request (instant) vs cached (state the delay).

Output: a permission matrix (role or relation × action × resource) and the tenant rule.
