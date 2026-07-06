const db = require('./connection');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();

const BCRYPT_ROUNDS = 12;

async function createSchema() {
  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('admin', 'operator')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      is_active BOOLEAN NOT NULL DEFAULT true
    );

    CREATE TABLE IF NOT EXISTS refresh_tokens (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token_hash TEXT NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      revoked BOOLEAN NOT NULL DEFAULT false
    );

    CREATE TABLE IF NOT EXISTS devices (
      id TEXT PRIMARY KEY,
      device_id TEXT UNIQUE NOT NULL,
      device_name TEXT,
      platform TEXT,
      status TEXT NOT NULL DEFAULT 'pending'
        CHECK(status IN ('pending', 'approved', 'rejected')),
      requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      reviewed_at TIMESTAMPTZ,
      reviewed_by TEXT REFERENCES users(id) ON DELETE SET NULL,
      notes TEXT
    );

    CREATE TABLE IF NOT EXISTS device_accounts (
      id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      role TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(device_id, user_id),
      UNIQUE(device_id, role)
    );

    CREATE INDEX IF NOT EXISTS idx_refresh_user ON refresh_tokens(user_id);
    CREATE INDEX IF NOT EXISTS idx_refresh_hash ON refresh_tokens(token_hash);
    CREATE INDEX IF NOT EXISTS idx_device_id ON devices(device_id);
    CREATE INDEX IF NOT EXISTS idx_device_status ON devices(status);
    CREATE INDEX IF NOT EXISTS idx_device_accounts_device ON device_accounts(device_id);
  `);
}

async function bootstrapAdmin() {
  const countResult = await db.prepare('SELECT COUNT(*) as count FROM users').get();
  const userCount = parseInt(countResult.count, 10);

  if (userCount > 0) {
    console.log(`Found ${userCount} existing user(s) - skipping bootstrap admin creation.`);
    return;
  }

  const username = process.env.BOOTSTRAP_ADMIN_USERNAME || 'admin';
  const password = process.env.BOOTSTRAP_ADMIN_PASSWORD;

  if (!password || password === 'change_me_immediately') {
    console.warn('WARNING: BOOTSTRAP_ADMIN_PASSWORD is not set to a real value in .env');
  }

  const passwordHash = await bcrypt.hash(password || 'change_me_immediately', BCRYPT_ROUNDS);
  const id = uuidv4();

  await db.prepare(`
    INSERT INTO users (id, username, password_hash, role)
    VALUES (?, ?, ?, 'admin')
  `).run(id, username, passwordHash);

  console.log(`Bootstrap admin created: username="${username}"`);
}

async function init() {
  await createSchema();
  await bootstrapAdmin();
  console.log('Database schema ready (Postgres)');
}

if (require.main === module) {
  init()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('Database init failed:', err);
      process.exit(1);
    });
}

module.exports = { init };
