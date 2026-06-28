const express = require('express');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const db = require('../db/connection');
const { requireAuth, requireRole } = require('../middleware/auth');

const router = express.Router();
const BCRYPT_ROUNDS = 12;
const USERNAME_RE = /^[a-zA-Z0-9_.-]{3,32}$/;

router.use(requireAuth, requireRole('admin'));

router.get('/', (req, res) => {
  const users = db.prepare(
    'SELECT id, username, role, created_at, is_active FROM users ORDER BY created_at DESC'
  ).all();
  res.json({ users });
});

router.post('/', async (req, res) => {
  const { username, password, role } = req.body || {};

  if (!username || !password || !role) {
    return res.status(400).json({ error: 'username, password, and role are required' });
  }
  if (!USERNAME_RE.test(username)) {
    return res.status(400).json({ error: 'invalid username format' });
  }
  if (!['admin', 'operator'].includes(role)) {
    return res.status(400).json({ error: "role must be 'admin' or 'operator'" });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: 'password must be at least 8 characters' });
  }

  const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if (existing) {
    return res.status(409).json({ error: 'username already taken' });
  }

  const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
  const id = uuidv4();

  db.prepare(
    'INSERT INTO users (id, username, password_hash, role) VALUES (?, ?, ?, ?)'
  ).run(id, username, passwordHash, role);

  res.status(201).json({ user: { id, username, role } });
});

router.patch('/:id', (req, res) => {
  const { id } = req.params;
  const { role, is_active } = req.body || {};

  const existing = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  if (!existing) {
    return res.status(404).json({ error: 'User not found' });
  }

  if (id === req.user.sub && (role === 'operator' || is_active === false || is_active === 0)) {
    const adminCount = db.prepare(
      "SELECT COUNT(*) as count FROM users WHERE role = 'admin' AND is_active = 1"
    ).get().count;
    if (adminCount <= 1) {
      return res.status(400).json({
        error: 'Cannot demote or disable the last active admin account',
      });
    }
  }

  if (role !== undefined) {
    if (!['admin', 'operator'].includes(role)) {
      return res.status(400).json({ error: "role must be 'admin' or 'operator'" });
    }
    db.prepare('UPDATE users SET role = ? WHERE id = ?').run(role, id);
  }

  if (is_active !== undefined) {
    db.prepare('UPDATE users SET is_active = ? WHERE id = ?').run(is_active ? 1 : 0, id);
  }

  const updated = db.prepare(
    'SELECT id, username, role, created_at, is_active FROM users WHERE id = ?'
  ).get(id);

  res.json({ user: updated });
});

router.delete('/:id', (req, res) => {
  const { id } = req.params;

  if (id === req.user.sub) {
    return res.status(400).json({ error: 'Cannot delete your own account while logged in' });
  }

  const existing = db.prepare('SELECT id FROM users WHERE id = ?').get(id);
  if (!existing) {
    return res.status(404).json({ error: 'User not found' });
  }

  db.prepare('DELETE FROM users WHERE id = ?').run(id);
  res.json({ success: true });
});

module.exports = router;
