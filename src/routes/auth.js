const express = require('express');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const db = require('../db/connection');
const {
  signAccessToken,
  signRefreshToken,
  verifyRefreshToken,
  hashToken,
} = require('../utils/tokens');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();
const BCRYPT_ROUNDS = 12;
const USERNAME_RE = /^[a-zA-Z0-9_.-]{3,32}$/;

function refreshTtlMs() {
  const ttl = process.env.REFRESH_TOKEN_TTL || '30d';
  const match = ttl.match(/^(\d+)([smhd])$/);
  if (!match) return 30 * 24 * 60 * 60 * 1000;
  const value = parseInt(match[1], 10);
  const unit = match[2];
  const multipliers = { s: 1000, m: 60000, h: 3600000, d: 86400000 };
  return value * multipliers[unit];
}

function storeRefreshToken(userId, token) {
  const id = uuidv4();
  const tokenHash = hashToken(token);
  const expiresAt = new Date(Date.now() + refreshTtlMs()).toISOString();
  db.prepare(
    'INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, ?)'
  ).run(id, userId, tokenHash, expiresAt);
}

function isRefreshTokenValid(userId, token) {
  const tokenHash = hashToken(token);
  const row = db.prepare(
    'SELECT * FROM refresh_tokens WHERE user_id = ? AND token_hash = ? AND revoked = 0'
  ).get(userId, tokenHash);
  if (!row) return false;
  if (new Date(row.expires_at) < new Date()) return false;
  return true;
}

function revokeRefreshToken(userId, token) {
  const tokenHash = hashToken(token);
  db.prepare(
    'UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ? AND token_hash = ?'
  ).run(userId, tokenHash);
}

router.post('/register', async (req, res) => {
  const { username, password } = req.body || {};

  if (!username || !password) {
    return res.status(400).json({ error: 'username and password are required' });
  }
  if (!USERNAME_RE.test(username)) {
    return res.status(400).json({
      error: 'username must be 3-32 characters: letters, numbers, underscore, dot, hyphen',
    });
  }
  if (typeof password !== 'string' || password.length < 8) {
    return res.status(400).json({ error: 'password must be at least 8 characters' });
  }

  const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if (existing) {
    return res.status(409).json({ error: 'username already taken' });
  }

  const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
  const id = uuidv4();

  db.prepare(
    "INSERT INTO users (id, username, password_hash, role) VALUES (?, ?, ?, 'operator')"
  ).run(id, username, passwordHash);

  const user = { id, username, role: 'operator' };
  const accessToken = signAccessToken(user);
  const refreshToken = signRefreshToken(user);
  storeRefreshToken(user.id, refreshToken);

  res.status(201).json({
    user: { id: user.id, username: user.username, role: user.role },
    accessToken,
    refreshToken,
  });
});

router.post('/login', async (req, res) => {
  const { username, password } = req.body || {};

  if (!username || !password) {
    return res.status(400).json({ error: 'username and password are required' });
  }

  const row = db.prepare('SELECT * FROM users WHERE username = ?').get(username);

  const dummyHash = '$2b$12$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX';
  const passwordOk = await bcrypt.compare(password, row ? row.password_hash : dummyHash);

  if (!row || !passwordOk) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }
  if (!row.is_active) {
    return res.status(403).json({ error: 'Account is disabled' });
  }

  const user = { id: row.id, username: row.username, role: row.role };
  const accessToken = signAccessToken(user);
  const refreshToken = signRefreshToken(user);
  storeRefreshToken(user.id, refreshToken);

  res.json({
    user: { id: user.id, username: user.username, role: user.role },
    accessToken,
    refreshToken,
  });
});

router.post('/refresh', (req, res) => {
  const { refreshToken } = req.body || {};

  if (!refreshToken) {
    return res.status(400).json({ error: 'refreshToken is required' });
  }

  let payload;
  try {
    payload = verifyRefreshToken(refreshToken);
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired refresh token' });
  }

  if (payload.type !== 'refresh') {
    return res.status(401).json({ error: 'Invalid token type' });
  }

  if (!isRefreshTokenValid(payload.sub, refreshToken)) {
    return res.status(401).json({ error: 'Refresh token has been revoked or is unknown' });
  }

  const row = db.prepare('SELECT * FROM users WHERE id = ?').get(payload.sub);
  if (!row || !row.is_active) {
    return res.status(401).json({ error: 'User no longer exists or is disabled' });
  }

  revokeRefreshToken(payload.sub, refreshToken);
  const user = { id: row.id, username: row.username, role: row.role };
  const newAccessToken = signAccessToken(user);
  const newRefreshToken = signRefreshToken(user);
  storeRefreshToken(user.id, newRefreshToken);

  res.json({
    accessToken: newAccessToken,
    refreshToken: newRefreshToken,
  });
});

router.post('/logout', requireAuth, (req, res) => {
  const { refreshToken } = req.body || {};
  if (refreshToken) {
    revokeRefreshToken(req.user.sub, refreshToken);
  }
  res.json({ success: true });
});

router.get('/me', requireAuth, (req, res) => {
  const row = db.prepare(
    'SELECT id, username, role, created_at, is_active FROM users WHERE id = ?'
  ).get(req.user.sub);

  if (!row) {
    return res.status(404).json({ error: 'User not found' });
  }

  res.json({ user: row });
});

module.exports = router;
