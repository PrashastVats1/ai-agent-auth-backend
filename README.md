# AI Agent Auth — Backend

An identity and delegation layer for AI agents. FastAPI + Neon PostgreSQL + MonoCloud, running entirely on free tiers.

## The problem

When an AI agent acts on behalf of a user, the agent's identity disappears. Your API logs say *"Alice deleted the orders table"* — not *"Agent X did it on Alice's behalf, at 14:32, after Alice approved it."* There is no consent step, no audit trail that separates user actions from agent actions, and the agent silently inherits everything the user is allowed to do.

This backend fixes that with three things:

1. **Token exchange.** A user signs in and gets a MonoCloud JWT. The agent presents that JWT plus its own MonoCloud machine-to-machine (M2M) token, and the backend issues a short-lived delegation JWT that names *both* the user and the agent. The design is modelled on the token-exchange idea in [RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693); it does not implement that RFC's wire format.
2. **Consent.** Destructive scopes (`delete:`, `write:`, `admin:`) are never in a default token. The agent asks, the user approves or denies in a dashboard, and only an approved request can be redeemed for a token carrying that scope. Pending requests expire after 5 minutes.
3. **Policy enforcement.** Per-agent rules stored in the database: which endpoints, which HTTP methods, which hours (IST), which days. An agent with no policy is denied. Every allow and every rejection is written to an audit log, along with each consent request, approval, denial, expiry and token issuance.

The dashboard lives in the [frontend repo](https://github.com/PrashastVats1/ai-agent-auth-frontend).

## How it works

```
   Human                     Agent                          This backend
     │                         │                                  │
     │ sign in (MonoCloud)     │                                  │
     ├──► user JWT             │                                  │
     │                         │ client credentials (MonoCloud)   │
     │                         ├──► agent M2M JWT                 │
     │                         │                                  │
     │                         │ POST /auth/agent-token           │
     │                         │   user JWT + agent M2M JWT ─────►│ validate both via JWKS
     │                         │                                  │ agent M2M JWT belongs to client ID?
     │                         │                                  │ user owns this agent?
     │                         │                                  │ policy exists, and this time/day allowed?
     │                         │◄──── delegation JWT (read) ──────┤
     │                         │                                  │
     │                         │ DELETE /api/... (needs consent)  │
     │                         ├─ POST /consent/request ─────────►│ pending record
     │ approve in dashboard ◄──┼─ poll /consent/status every 4s ──┤
     ├─ POST /consent/approve ─┼─────────────────────────────────►│ approved
     │                         │ POST /auth/agent-token + consent_id
     │                         │◄──── delegation JWT (read + delete:orders)
     │                         ├─ DELETE /api/... ───────────────►│ scope + policy checked, logged
```

### Two kinds of JWT, never mixed

| | MonoCloud JWT | Delegation JWT |
|---|---|---|
| Issued by | MonoCloud (users and agent M2M clients) | This backend |
| Signed with | MonoCloud's RSA keys (RS256) | `JWT_SECRET` (HS256) |
| Validated by | `validate_monocloud_jwt()` in `services/monocloud.py` | `validate_agent_jwt()` in `services/delegation.py` |
| Used for | Dashboard API calls; proving identity to `/auth/agent-token` | Everything an agent does after the exchange |

MonoCloud's public keys are fetched from its JWKS endpoint and cached for 10 minutes, never hardcoded, so key rotation just works.

The delegation JWT payload:

```json
{
  "user_id": "…", "user_email": "alice@example.com",
  "agent_id": "…", "agent_name": "order-bot",
  "scopes": ["read", "delete:orders"],
  "token_type": "agent_delegation",
  "iat": 1700000000, "exp": 1700001800
}
```

It expires after 30 minutes.

### Consent

- `POST /consent/request` creates a `pending` record. Only `delete:`, `write:` and `admin:` scopes are accepted.
- The agent polls `GET /consent/status/{id}` **every 4 seconds** (not faster; see [free-tier notes](#free-tier-notes)), presenting its own M2M token. Only the agent the request was made for can read it. An expired request returns `410 Gone` rather than hanging.
- The user approves or denies via `POST /consent/approve`.
- The agent redeems an approval by calling `POST /auth/agent-token` again with `consent_id`. Each approval works **once**, and only within 5 minutes of being approved.
- Endpoints that need a scope use `Depends(require_scope("delete:orders"))`. See `DELETE /api/protected/orders` for a working example.

### Policy

One policy per agent, enforced in two places:

- **At token issuance** (`POST /auth/agent-token`): the agent must have a policy, and the current time and day must be allowed. Endpoint and method aren't known yet, so they can't be checked here.
- **On every request** (`enforce_policy` / `require_scope` in `middleware/policy_check.py`): endpoint, method, time and day.

**An agent with no policy is denied** (`rejected_no_policy`) until you create one in the dashboard.

| Field | Meaning |
|---|---|
| `allowed_endpoints` | Exact paths (`/api/orders`), or a prefix ending in `*` (`/api/orders/*` matches `/api/orders/123` but not `/api/orders`). Empty list = no restriction. |
| `allowed_methods` | e.g. `["GET", "POST"]`, normalised to uppercase. Empty = no restriction. |
| `time_window_start` / `time_window_end` | `HH:MM`, evaluated in IST (`Asia/Kolkata`), inclusive. Set both or neither. `22:00`–`06:00` crosses midnight. |
| `allowed_days` | Day names, `monday`…`sunday`. Empty = no restriction. |

A policy with every field empty is an explicit "allow everything". Policies are validated when saved, so bad input returns a `422` with the reason.

Every outcome is written to the audit log with one of these actions:

| Action | When |
|---|---|
| `allowed` | A request passed the policy check |
| `rejected_no_policy`, `rejected_endpoint`, `rejected_method`, `rejected_time_window`, `rejected_day` | A policy rule failed (at issuance or on a request) |
| `rejected_scope` | A request needed a scope the token doesn't carry |
| `consent_requested`, `consent_approved`, `consent_denied`, `consent_expired` | The consent lifecycle |
| `token_issued`, `token_issued_with_consent` | A delegation JWT was issued |
| `rejected_consent` | A consent couldn't be redeemed (pending, denied, used, stale or not yours) |

### Protecting your own endpoint

Any FastAPI route can require a delegation JWT and enforce the caller's policy:

```python
from fastapi import APIRouter, Depends
from middleware.policy_check import enforce_policy, require_scope

router = APIRouter()

@router.get("/api/orders")
def list_orders(claims: dict = Depends(enforce_policy)):
    # claims has user_id, user_email, agent_id, agent_name, scopes
    ...

@router.delete("/api/orders")
def delete_orders(claims: dict = Depends(require_scope("delete:orders"))):
    # only reachable with a token that carries delete:orders, i.e. after a user-approved consent
    ...
```

Both write to the audit log automatically. Remember to add the path to the agent's policy (or leave `allowed_endpoints` empty).

## API reference

Interactive docs are served at `/docs` when the app is running.

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /health` | none | Liveness check |
| `POST /api/users/sync` | MonoCloud user JWT | Create the user row on first login |
| `POST /auth/agent-token` | user JWT + agent M2M JWT in the body | Exchange for a delegation JWT (optionally redeem a `consent_id`) |
| `GET / POST /api/agents`, `DELETE /api/agents/{id}` | MonoCloud user JWT | Manage your agents |
| `GET / PUT / DELETE /api/policies/{agent_id}` | MonoCloud user JWT | Manage an agent's policy |
| `POST /consent/request` | MonoCloud user JWT | Create a pending consent for a destructive scope |
| `GET /consent/status/{id}` | agent M2M JWT | Agent polling; only for the agent the request belongs to |
| `GET /consent/pending` | MonoCloud user JWT | Dashboard list of pending requests |
| `POST /consent/approve` | MonoCloud user JWT | Approve or deny |
| `GET /api/audit` | MonoCloud user JWT | Audit log for your agents, newest first (`limit` ≤ 200, `offset`) |
| `GET /api/protected/orders` | delegation JWT | Demo: policy-protected endpoint |
| `DELETE /api/protected/orders` | delegation JWT with `delete:orders` | Demo: consent-gated endpoint |

User identity always comes from the validated token's `sub` claim, never from a request body.

## Local setup

**Prerequisites:** Python 3.12, a free [Neon](https://neon.tech) project, a free [MonoCloud](https://www.monocloud.com) project. No Docker needed.

### 1. Database

Open your Neon project's SQL editor and run [`schema.sql`](schema.sql). It creates `users`, `agents`, `policies`, `consent_requests` and `audit_logs`. It is safe to re-run. If you created the tables before consent redemption existed, the `ALTER TABLE` at the bottom adds the missing `consumed_at` column.

### 2. MonoCloud

Menu names in MonoCloud's dashboard may change, so check their docs for exact clicks. You need:

1. **One application for the human dashboard**: Authorization Code flow with PKCE. Add `http://localhost:5173/callback` as an allowed redirect URI (and your Vercel URL later). Also allow your app's origin as a post-logout redirect. Its client ID goes in the frontend's `VITE_MONOCLOUD_CLIENT_ID`.
2. **One M2M application per agent**: Client Credentials flow. The client ID is what you register in the dashboard as the agent's `monocloud_client_id`. The client secret stays with the agent and must never be committed.
3. **The issuer URL**: your tenant's base URL. The backend discovers the JWKS endpoint from `{issuer}/.well-known/openid-configuration`.
4. **The audience**: `MONOCLOUD_AUDIENCE` must equal the `aud` claim of **both** the user's access token and the agent's M2M token, because both are checked against it. If you're not sure what yours is, decode a real token and look:

   ```bash
   python3 -c "import sys,json,base64;p=sys.argv[1].split('.')[1];print(json.loads(base64.urlsafe_b64decode(p+'='*(-len(p)%4))).get('aud'))" "<access token>"
   ```

### 3. Run the backend

```bash
git clone https://github.com/PrashastVats1/ai-agent-auth-backend.git
cd ai-agent-auth-backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env        # then fill it in
uvicorn main:app --reload
```

The API is at <http://localhost:8000> and the docs at <http://localhost:8000/docs>.

| Variable | Description |
|---|---|
| `NEON_DATABASE_URL` | Connection string from Neon (keep `sslmode=require`) |
| `MONOCLOUD_ISSUER_URL` | Your MonoCloud tenant URL, e.g. `https://your-tenant.monocloud.com` |
| `MONOCLOUD_AUDIENCE` | Expected `aud` claim, see step 2.4 |
| `JWT_SECRET` | Secret for signing delegation JWTs. Generate one: `python3 -c "import secrets; print(secrets.token_urlsafe(48))"` |
| `CORS_ALLOWED_ORIGINS` | Comma-separated URLs of your deployed dashboard, e.g. `https://my-dashboard.vercel.app`. `http://localhost:5173` is always allowed. Only needed once you deploy. |

### 4. Try it with the demo agent

[`examples/agent_demo.py`](examples/agent_demo.py) plays the part of an agent end to end: it gets an M2M token, exchanges it for a read-only delegation JWT, tries a destructive call (expects 403), requests consent, polls every 4 seconds while you approve in the dashboard, redeems the approval, and retries the call (expects 200).

You need the [frontend](https://github.com/PrashastVats1/ai-agent-auth-frontend) running to approve the request, and an agent registered in it **with a policy** (agents without one are denied). A policy that allows `GET` and `DELETE` on `/api/protected/orders` works, and so does one with every field left empty. Then:

```bash
export MONOCLOUD_ISSUER_URL=https://your-tenant.monocloud.com
export AGENT_CLIENT_ID=<agent M2M client id>
export AGENT_CLIENT_SECRET=<agent M2M client secret>
export USER_JWT=<access token of the signed-in user>   # see the script's docstring for how to grab it
python3 examples/agent_demo.py
```

## Deploy to Render (free tier)

1. Create a new **Web Service** from this repo.
2. Build command: `pip install -r requirements.txt`. Start command: `uvicorn main:app --host 0.0.0.0 --port $PORT`. The Python version is pinned in `.python-version`.
3. Add the environment variables above in Render's dashboard.
4. Set `CORS_ALLOWED_ORIGINS` to your frontend's URL (comma-separated if there are several). `http://localhost:5173` is always allowed. Until you do this, browsers block the dashboard's requests (CORS).
5. Run `schema.sql` in Neon **before** the first deploy.

> **Render free tier sleeps after 15 minutes of inactivity.** The first request after that takes 30–50 seconds while the service wakes up. That is expected, not a bug. Worth knowing before a live demo: open `/health` a minute beforehand.

## Tests

```bash
pip install -r requirements-dev.txt
export TEST_DATABASE_URL=postgresql://user:password@localhost:5432/scratch   # a scratch database is safest
pytest
```

The suite runs against a real PostgreSQL, entirely inside a throwaway schema that it creates and drops, so it doesn't touch your other tables. Without `TEST_DATABASE_URL` the database tests are skipped. MonoCloud is never contacted: the tests sign real RS256 tokens with a throwaway key, so signature, issuer, audience and expiry are genuinely checked. CI runs the same suite on every push and pull request. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Free-tier notes

- **Neon connection limits.** One shared SQLAlchemy engine with `pool_size=5`, `max_overflow=2` and `pool_pre_ping=True` (Neon drops idle connections). Please don't raise these.
- **Polling interval.** Agents and the dashboard poll every 4 seconds. Polling every second burns through Neon's free-tier limits.
- **No background workers.** Consent expiry runs at poll time, so nothing extra needs to stay awake on Render.

## Project layout

```
main.py               app setup, CORS, router registration
database.py           SQLAlchemy engine, session, pool config
routers/              auth (token exchange), agents, policies, consent, audit, users, protected (demo)
middleware/           user_auth.py (dashboard user from a MonoCloud JWT),
                      policy_check.py (enforce_policy, require_scope for delegation JWTs)
services/             monocloud.py (JWKS + MonoCloud JWTs), delegation.py (our JWTs),
                      policy.py (policy rules), consent.py, audit.py
models/               tables.py (ORM), schemas.py (Pydantic)
tests/                pytest suite (needs TEST_DATABASE_URL for the database tests)
examples/             agent_demo.py
schema.sql            database schema and migration
```

## Known limitations

This is early-stage software. Before you rely on it:

- **A policy with empty lists allows everything for that field.** That's deliberate and documented, but it means a saved-but-blank policy is permissive. Only a *missing* policy is denied.
- **Endpoint matching is by exact path or trailing `*` prefix.** No regexes, no per-method path rules, and no path-parameter templates.
- **Time windows are IST only** and the day check uses the day the request is made, not the day the window started.
- **`consent_expired` is logged when someone next polls or lists consents**, not at the moment of expiry, because there's no background worker on Render's free tier.
- **The agent's M2M token is verified on each call, not bound to the delegation JWT.** A delegation JWT is a bearer token for its 30-minute life.
- **The tests never contact a live MonoCloud tenant.** They use a throwaway signing key, so they can't catch a mismatch with your tenant's real `aud` claim; run `examples/agent_demo.py` against your deployment to confirm that.

Issues and pull requests are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md). To report a vulnerability, see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
