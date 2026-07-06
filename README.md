# QuillAir Auth Server

Authentication backend for the QuillAir GCS app. Provides username/password
login with role-based access (`admin` / `operator`) using JWT access +
refresh tokens, backed by PostgreSQL for persistent storage.

This has been tested end-to-end against a live PostgreSQL instance:
register, login, refresh rotation, role enforcement, account disable,
validation errors, and - critically - **a full server restart with data
intact** (the scenario that caused account loss under the previous
SQLite-on-ephemeral-storage setup).

## Why Postgres instead of SQLite

The original version used SQLite, which stored its database as a local
file. On Render's free tier (and similar platforms), that file lives on
ephemeral storage - it's wiped on every restart, redeploy, or free-tier
spin-down/spin-up cycle. That caused accounts created between restarts to
silently disappear. Postgres, run as a separate managed service, persists
independently of the app server's lifecycle, which fixes this permanently.

## Quick start (local)

You'll need a local Postgres instance running, or any reachable Postgres
connection string.

```bash
npm install
cp .env.example .env
```

Edit `.env`:
- Generate two long random strings for `JWT_ACCESS_SECRET` and
  `JWT_REFRESH_SECRET`:
  ```bash
  node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
  ```
  Run it twice, paste each result into the respective `.env` field.
- Set `DATABASE_URL` to your Postgres connection string, e.g.
  `postgresql://user:password@localhost:5432/quillair_auth`
- Set `BOOTSTRAP_ADMIN_PASSWORD` to something real.

Then:

```bash
npm start
```

The server creates its schema and bootstrap admin automatically on first
run (and skips that step on every run after, once a user exists - this is
the part that's now safe across restarts). Visit
`http://localhost:3000/health` to confirm it's up.

## API

Unchanged from before - all bodies/responses are JSON. Send
`Authorization: Bearer <accessToken>` for any route marked "auth required."

| Method | Path | Auth required | Description |
|---|---|---|---|
| POST | `/auth/register` | no | Creates an `operator` account. Returns tokens. |
| POST | `/auth/login` | no | Returns `{ user, accessToken, refreshToken }`. |
| POST | `/auth/refresh` | no (needs refreshToken in body) | Rotates tokens. |
| POST | `/auth/logout` | yes | Revokes the supplied refresh token. |
| GET | `/auth/me` | yes | Returns the current user. |
| GET | `/auth/users` | yes, admin only | Lists all users. |
| POST | `/auth/users` | yes, admin only | Creates a user with any role. |
| PATCH | `/auth/users/:id` | yes, admin only | Updates `role` and/or `is_active`. |
| DELETE | `/auth/users/:id` | yes, admin only | Deletes a user. |

## Security notes

Unchanged from before:
- Passwords hashed with bcrypt (12 rounds).
- Refresh tokens stored hashed (SHA-256) in the DB.
- Refresh tokens rotate on every use; the old one is revoked immediately.
- `/auth/login` and `/auth/register` are rate-limited (20 requests / 15 min
  per IP).
- Self-registration always creates an `operator`.
- An admin can't demote or disable the last remaining active admin account.

## Deploying to Render with a free Postgres database

### Step 1: Create the Postgres instance

1. In the Render dashboard, click **New + → PostgreSQL**
2. Give it a name (e.g. `quillair-auth-db`)
3. Choose the **Free** plan
4. Same region as your web service, for speed and to avoid bandwidth charges
5. Create it, then wait for it to finish provisioning

### Step 2: Get the connection string

On the Postgres instance's page, find **Internal Database URL** (use this
one, not External, since your web service and database will be in the
same Render network - it's faster and doesn't count against bandwidth
limits). Copy it - it looks like:
```
postgresql://user:password@dpg-xxxxx-a/dbname
```

### Step 3: Update your web service's environment variables

In your existing `quillair-auth-server` web service on Render, go to
**Environment** and:
- **Remove** `DB_PATH` (no longer used)
- **Add** `DATABASE_URL` with the Internal Database URL from Step 2

### Step 4: Push this updated code and redeploy

```bash
git add .
git commit -m "Migrate from SQLite to PostgreSQL for persistent storage"
git push
```

Render will auto-redeploy (if auto-deploy is on) or you can trigger a
manual deploy. Watch the logs for:
```
Database schema ready (Postgres)
```

### Step 5: Verify persistence

After deploying, register a test user, then manually restart the web
service from the Render dashboard (Manual Deploy → or just wait for a
free-tier spin-down/spin-up cycle). Log in as that test user again - it
should still work. That confirms the fix.

### Note on Render's free Postgres tier

Render's free PostgreSQL instances expire after 90 days and are deleted
unless you upgrade to a paid plan or create a new one. This is fine to
start with, but mark your calendar - you'll need to migrate to a new free
instance (or a paid one) before the 90 days are up, or you'll hit this
same data-loss problem again from a different cause.

## Project layout

```
src/
  server.js            entry point - Express app, CORS, route mounting
  db/
    connection.js        Postgres connection pool + thin query-builder
                          compatibility shim
    init.js               schema creation + bootstrap admin (idempotent)
  middleware/
    auth.js               requireAuth / requireRole middleware
    rateLimiter.js         rate limit config for login/register
  routes/
    auth.js                register, login, refresh, logout, me
    users.js               admin-only user management
  utils/
    tokens.js              JWT sign/verify helpers, refresh token hashing
```
