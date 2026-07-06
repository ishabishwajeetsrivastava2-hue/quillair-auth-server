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

async function storeRefreshToken(userId, token) {
  const id = uuidv4();
  const tokenHash = hashToken(token);
  const expiresAt = new Date(Date.now() + refreshTtlMs()).toISOString();
  await db.prepare(
    'INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, ?)'
  ).run(id, userId, tokenHash, expiresAt);
}

async function isRefreshTokenValid(userId, token) {
  const tokenHash = hashToken(token);
  const row = await db.prepare(
    'SELECT * FROM refresh_tokens WHERE user_id = ? AND token_hash = ? AND revoked = false'
  ).get(userId, tokenHash);
  if (!row) return false;
  if (new Date(row.expires_at) < new Date()) return false;
  return true;
}

async function revokeRefreshToken(userId, token) {
  const tokenHash = hashToken(token);
  await db.prepare(
    'UPDATE refresh_tokens SET revoked = true WHERE user_id = ? AND token_hash = ?'
  ).run(userId, tokenHash);
}

// ─────────────────────────────────────────────────────────────────────────
// Device binding helpers
// ─────────────────────────────────────────────────────────────────────────

// Returns the device row if the deviceId is approved, null otherwise.
async function getApprovedDevice(deviceId) {
  if (!deviceId) return null;
  const device = await db.prepare(
    "SELECT * FROM devices WHERE device_id = ? AND status = 'approved'"
  ).get(deviceId);
  return device || null;
}

// Enforces the 2-account-per-device rule (max 1 admin + 1 operator).
// Returns an error string if adding this role would exceed the limit,
// null if it's fine to proceed.
async function checkDeviceAccountLimit(deviceId, newUserRole) {
  // Count how many accounts have logged in from this device.
  // We track this via a device_accounts join table implicitly by
  // checking refresh_tokens tied to users who have this device approved.
  // Simpler approach: a dedicated device_accounts table.
  const rows = await db.prepare(
    "SELECT role FROM device_accounts WHERE device_id = ?"
  ).all(deviceId);

  const roles = rows.map(r => r.role);
  if (roles.includes(newUserRole)) {
    return `This device already has a${newUserRole === 'admin' ? 'n' : ''} ${newUserRole} account registered.`;
  }
  if (roles.length >= 2) {
    return 'This device already has the maximum of 2 accounts (one admin + one operator).';
  }
  return null;
}

async function recordDeviceAccount(deviceId, userId, role) {
  const existing = await db.prepare(
    'SELECT id FROM device_accounts WHERE device_id = ? AND user_id = ?'
  ).get(deviceId, userId);
  if (existing) return; // Already recorded

  const id = uuidv4();
  await db.prepare(
    'INSERT INTO device_accounts (id, device_id, user_id, role) VALUES (?, ?, ?, ?)'
  ).run(id, deviceId, userId, role);
}

// ─────────────────────────────────────────────────────────────────────────
// POST /auth/register
// ─────────────────────────────────────────────────────────────────────────
router.post('/register', async (req, res) => {
  const { username, password, deviceId } = req.body || {};

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

  // Device check on registration too
  if (deviceId) {
    const device = await getApprovedDevice(deviceId);
    if (!device) {
      return res.status(403).json({
        error: 'device_not_approved',
        message: 'This device has not been approved. Request access first.',
      });
    }
  }

  const existing = await db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if (existing) {
    return res.status(409).json({ error: 'username already taken' });
  }

  const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
  const id = uuidv4();

  await db.prepare(
    "INSERT INTO users (id, username, password_hash, role) VALUES (?, ?, ?, 'operator')"
  ).run(id, username, passwordHash);

  const user = { id, username, role: 'operator' };

  if (deviceId) {
    const limitError = await checkDeviceAccountLimit(deviceId, 'operator');
    if (limitError) {
      // Roll back user creation
      await db.prepare('DELETE FROM users WHERE id = ?').run(id);
      return res.status(409).json({ error: limitError });
    }
    await recordDeviceAccount(deviceId, id, 'operator');
  }

  const accessToken = signAccessToken(user);
  const refreshToken = signRefreshToken(user);
  await storeRefreshToken(user.id, refreshToken);

  res.status(201).json({
    user: { id: user.id, username: user.username, role: user.role },
    accessToken,
    refreshToken,
  });
});

// ─────────────────────────────────────────────────────────────────────────
// POST /auth/login
// ─────────────────────────────────────────────────────────────────────────
router.post('/login', async (req, res) => {
  const { username, password, deviceId } = req.body || {};

  if (!username || !password) {
    return res.status(400).json({ error: 'username and password are required' });
  }

  // --- Device check FIRST (before credentials, to avoid timing leaks) ---
  if (!deviceId) {
    return res.status(400).json({
      error: 'device_id_required',
      message: 'deviceId is required for login.',
    });
  }

  const device = await getApprovedDevice(deviceId);
  if (!device) {
    // Check if pending or rejected or unregistered
    const anyDevice = await db.prepare(
      'SELECT status FROM devices WHERE device_id = ?'
    ).get(deviceId);

    if (!anyDevice) {
      return res.status(403).json({
        error: 'device_not_registered',
        message: 'This device is not registered. Use "Request Access" to submit for approval.',
      });
    }
    if (anyDevice.status === 'pending') {
      return res.status(403).json({
        error: 'device_pending',
        message: 'Your device is awaiting admin approval.',
      });
    }
    if (anyDevice.status === 'rejected') {
      return res.status(403).json({
        error: 'device_rejected',
        message: 'Your device registration was rejected. Contact your admin.',
      });
    }
  }

  // --- Credentials check ---
  const row = await db.prepare('SELECT * FROM users WHERE username = ?').get(username);

  const dummyHash = '$2b$12$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX';
  const passwordOk = await bcrypt.compare(password, row ? row.password_hash : dummyHash);

  if (!row || !passwordOk) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }
  if (!row.is_active) {
    return res.status(403).json({ error: 'Account is disabled' });
  }

  // --- Device account limit check ---
  const limitError = await checkDeviceAccountLimit(deviceId, row.role);
  if (limitError) {
    // Only block if this user isn't already recorded on this device
    const alreadyLinked = await db.prepare(
      'SELECT id FROM device_accounts WHERE device_id = ? AND user_id = ?'
    ).get(deviceId, row.id);
    if (!alreadyLinked) {
      return res.status(409).json({ error: limitError });
    }
  }

  // Record this user-device pairing if not already recorded
  await recordDeviceAccount(deviceId, row.id, row.role);

  const user = { id: row.id, username: row.username, role: row.role };
  const accessToken = signAccessToken(user);
  const refreshToken = signRefreshToken(user);
  await storeRefreshToken(user.id, refreshToken);

  res.json({
    user: { id: user.id, username: user.username, role: user.role },
    accessToken,
    refreshToken,
  });
});

// ─────────────────────────────────────────────────────────────────────────
// POST /auth/refresh
// ─────────────────────────────────────────────────────────────────────────
router.post('/refresh', async (req, res) => {
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

  const valid = await isRefreshTokenValid(payload.sub, refreshToken);
  if (!valid) {
    return res.status(401).json({ error: 'Refresh token has been revoked or is unknown' });
  }

  const row = await db.prepare('SELECT * FROM users WHERE id = ?').get(payload.sub);
  if (!row || !row.is_active) {
    return res.status(401).json({ error: 'User no longer exists or is disabled' });
  }

  await revokeRefreshToken(payload.sub, refreshToken);
  const user = { id: row.id, username: row.username, role: row.role };
  const newAccessToken = signAccessToken(user);
  const newRefreshToken = signRefreshToken(user);
  await storeRefreshToken(user.id, newRefreshToken);

  res.json({ accessToken: newAccessToken, refreshToken: newRefreshToken });
});

// ─────────────────────────────────────────────────────────────────────────
// POST /auth/logout
// ─────────────────────────────────────────────────────────────────────────
router.post('/logout', requireAuth, async (req, res) => {
  const { refreshToken } = req.body || {};
  if (refreshToken) {
    await revokeRefreshToken(req.user.sub, refreshToken);
  }
  res.json({ success: true });
});

// ─────────────────────────────────────────────────────────────────────────
// GET /auth/me
// ─────────────────────────────────────────────────────────────────────────
router.get('/me', requireAuth, async (req, res) => {
  const row = await db.prepare(
    'SELECT id, username, role, created_at, is_active FROM users WHERE id = ?'
  ).get(req.user.sub);

  if (!row) {
    return res.status(404).json({ error: 'User not found' });
  }

  res.json({ user: row });
});

module.exports = router;
