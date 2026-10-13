# Opaque rotating tokens

Use when stage 0 picks opaque tokens. A **session** is one `client` (device) for one account. The server stores only hashes.

## Endpoints (default mount `/auth`; one mount per account type)

| Feature | Endpoints |
|---|---|
| Sign in / out | `POST /sign_in`, `DELETE /sign_out` |
| Validate token | `GET /validate_token` (returns the account) |
| Registration | `POST /`, `PUT /`, `DELETE /` |
| Confirmation | `POST /confirmation` (resend), `GET /confirmation?confirmation_token=…&redirect_url=…` |
| Password reset | `POST /password`, `GET /password/edit?reset_password_token=…&redirect_url=…`, `PUT /password` |
| Unlock | `POST /unlock`, `GET /unlock?unlock_token=…` |
| OAuth | `GET /:provider`, `GET /:provider/callback` (tokens by redirect or postMessage) |
| Sessions | `GET /sessions`, `DELETE /sessions/:client` |

Headers: `access-token`, `token-type: Bearer`, `client`, `expiry`, `uid` (names configurable), or `Authorization: Bearer <base64 JSON of the same set>`, or an HttpOnly cookie carrying the same set.

## Pseudocode

```
sign_in(identity, password):
  account = find(normalise(identity), provider="email")
  if not account or locked(account) or disabled(account): fake_hash_check(); fail 401
  if not verify_password(account, password): record_failure(account); fail 401
  if confirmation_required and not confirmed(account) and grace_over(account): fail 401
                                                       # acceptable: only after a correct password
  if second_factor_enabled(account): return challenge  # issue a session only after the second factor
  reset_failures(account); track(account)
  client = random_id(); token = random_secret(32 bytes)
  store session(account_type, account_id, account_version, client, hash(token), expires_at=now+lifetime)
  enforce_device_limit(account)                        # evict soonest-expiring *other* sessions
  respond headers(access-token=token, client, uid, expiry, token-type="Bearer")

authenticate(request):
  uid, client, token = read Authorization, headers or cookie
  account = find(uid, provider)
  session = sessions[account_type, client]
  if not session or session.account_id != account.id
     or session.account_version != account.version
     or expired(session) or idle_too_long(session): 401
  if constant_time_eq(hash(token), session.token_hash): current = true
  elif within_batch_window(session) and constant_time_eq(hash(token), session.previous_hash): current = false
  else: 401
  if rotation and current and not within_batch_window(session):
      new = random_secret()
      rows = UPDATE sessions SET previous_hash=token_hash, token_hash=hash(new),
               rotated_at=now, expires_at=now+lifetime
             WHERE id=session.id AND token_hash=hash(token)   # check and write in one step
      if rows == 1: respond with new headers
      else: respond with the same token headers               # lost the race: batch request
  elif rotation: respond with the same token headers, expiry unchanged

sign_out: delete the current session only.
password reset or change: if configured, delete all other sessions; notify.
email change: reconfirm if configured; notify the old address; send the new uid in every credential response.
account deletion or disable: delete all sessions of that account.
```

## Data model

`sessions(id, account_type, account_id, account_version, client, token_hash, previous_hash, rotated_at, expires_at, created_at)` unique on `(account_type, client)`; add `last_used_at` if inactivity timeout or the session list is in, and `user_agent` if the session list is in.

## Extra acceptance checks

- A rotated token works once more inside the batch window, then fails.
- Parallel requests with the same token never yield two valid new tokens.
- The device limit evicts another session, never the current one.
- Password reset ends the other sessions when configured, never the current one.
- After an email change, every credential response (including batch responses) carries the new uid.
