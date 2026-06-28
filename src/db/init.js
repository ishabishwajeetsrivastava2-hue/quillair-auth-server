// Run with: npm run init-db
// Creates tables if they don't exist, and creates a bootstrap admin account
// if the users table is empty. Safe to run multiple times.

const db = require('./connection');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();

const BCRYPT_ROUNDS = 12;

function createSchema() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('admin', 'operator')),
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      is_active INTEGER NOT NULL DEFAULT 1
    );

    CREATE TABLE IF NOT EXISTS refresh_tokens (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      token_hash TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      revoked INTEGER NOT NULL DEFAULT 0,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_refresh_user ON refresh_tokens(user_id);
    CREATE INDEX IF NOT EXISTS idx_refresh_hash ON refresh_tokens(token_hash);
  `);
}

function bootstrapAdmin() {
  const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get().count;

  if (userCount > 0) {
    console.log(`Found ${userCount} existing user(s) - skipping bootstrap admin creation.`);
    return;
  }

  const username = process.env.BOOTSTRAP_ADMIN_USERNAME || 'admin';
  const password = process.env.BOOTSTRAP_ADMIN_PASSWORD;

  if (!password || password === 'change_me_immediately') {
    console.warn('WARNING: BOOTSTRAP_ADMIN_PASSWORD is not set to a real value in .env');
    console.warn('Creating admin with the default password anyway - CHANGE IT IMMEDIATELY after first login.');
  }

  const passwordHash = bcrypt.hashSync(password || 'change_me_immediately', BCRYPT_ROUNDS);
  const id = uuidv4();

  db.prepare(`
    INSERT INTO users (id, username, password_hash, role)
    VALUES (?, ?, ?, 'admin')
  `).run(id, username, passwordHash);

  console.log(`Bootstrap admin created: username="${username}"`);
  console.log('Log in and change this password immediately.');
}

function init() {
  createSchema();
  bootstrapAdmin();
  console.log('Database initialized at', process.env.DB_PATH || './data/quillair_auth.db');
}

if (require.main === module) {
  init();
}

module.exports = { init };
