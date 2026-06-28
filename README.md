# QuillAir Auth Server

Authentication backend for the QuillAir GCS app. Provides username/password
login with role-based access (`admin` / `operator`) using JWT access +
refresh tokens.

This has been tested end-to-end (register, login, refresh rotation, role
enforcement, account disable, validation errors) against an equivalent
in-memory setup. The only swap needed for that test was the SQLite driver,
to work around a sandboxed test environment that couldn't compile native
modules — the code shipped here is unchanged and uses the real
`better-sqlite3` / `bcrypt` packages, which install normally on any regular
machine or cloud host.

## Quick start (local)

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
- Set `BOOTSTRAP_ADMIN_PASSWORD` to something real — this becomes the first
  admin account's password on first run. Change it via the API after first
  login.

Then:

```bash
npm start
```

The server creates its SQLite database and bootstrap admin automatically on
first run. Visit `http://localhost:3000/health` to confirm it's up.

## API

All bodies/responses are JSON. Send `Authorization: Bearer <accessToken>`
for any route marked "auth required."

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

Example login:
```bash
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"yourpassword"}'
```

## Security notes

- Passwords are hashed with bcrypt (12 rounds).
- Refresh tokens are stored hashed (SHA-256) in the DB — a DB leak alone
  doesn't expose usable tokens.
- Refresh tokens rotate on every use; the old one is revoked immediately.
- `/auth/login` and `/auth/register` are rate-limited (20 requests / 15 min
  per IP) to slow brute-forcing.
- Self-registration always creates an `operator` — only an existing admin
  can create another admin account via `POST /auth/users`.
- An admin can't demote or disable the last remaining active admin account
  (prevents accidental lockout).

## Deploying to the cloud

This app is a stock Node/Express server with a local SQLite file, so it
runs on most "deploy from a Git repo" platforms with minimal config.

### Render / Railway / Fly.io (similar steps on each)

1. Push this folder to a GitHub repo (the `.gitignore` already excludes
   `node_modules`, `.env`, and the `data/` SQLite folder).
2. Create a new "Web Service" from that repo.
3. Build command: `npm install`
4. Start command: `npm start`
5. Add environment variables in the platform's dashboard (same keys as
   `.env.example`): `JWT_ACCESS_SECRET`, `JWT_REFRESH_SECRET`,
   `BOOTSTRAP_ADMIN_USERNAME`, `BOOTSTRAP_ADMIN_PASSWORD`,
   `ALLOWED_ORIGINS`, etc.
6. **Persistent disk**: SQLite needs a writable, persistent file. On
   Render, add a "Disk" mounted at e.g. `/data` and set `DB_PATH=/data/quillair_auth.db`
   in the environment variables. On Railway, add a Volume similarly. Fly.io
   uses "Volumes" the same way. Without this, the database resets every
   time the service restarts/redeploys.
7. Set `ALLOWED_ORIGINS` to your actual app's origin(s) once you know them,
   instead of `*`, to lock down CORS.
8. After first deploy, log in as the bootstrap admin and change the
   password immediately (there's no "change password" endpoint yet — for
   now use `PATCH /auth/users/:id` is role/active only; to rotate the
   password right now you'd re-create the account via `POST /auth/users`
   with a new admin, then delete the bootstrap one. A proper
   "change my password" endpoint is a natural next addition.)

### Moving off SQLite later

If you outgrow SQLite (e.g. need multiple server instances), swap
`src/db/connection.js` for a Postgres client (e.g. `pg`) — every other file
only calls `db.prepare(...).run/get/all(...)`, so you'd reimplement that
small interface against Postgres and nothing else changes.

## Project layout

```
src/
  server.js            entry point — Express app, CORS, route mounting
  db/
    connection.js       SQLite connection setup
    init.js              schema creation + bootstrap admin (idempotent)
  middleware/
    auth.js              requireAuth / requireRole middleware
    rateLimiter.js        rate limit config for login/register
  routes/
    auth.js               register, login, refresh, logout, me
    users.js               admin-only user management
  utils/
    tokens.js              JWT sign/verify helpers, refresh token hashing
```
