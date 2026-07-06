// Device registration and approval routes.
// Devices must be approved by an admin before any account on that device
// can log in. One approval covers all accounts on the device.
// A device can have at most 2 accounts: one admin + one operator.

const express = require('express');
const { v4: uuidv4 } = require('uuid');
const db = require('../db/connection');
const { requireAuth, requireRole } = require('../middleware/auth');

const router = express.Router();

// ─────────────────────────────────────────────────────────────────────────
// POST /auth/device/register
// Called when a user tries to log in from an unrecognised device.
// Submits the device for admin approval. No auth required (the user
// may not even have a valid token yet at this point).
// ─────────────────────────────────────────────────────────────────────────
router.post('/register', async (req, res) => {
  const { deviceId, deviceName, platform } = req.body || {};

  if (!deviceId) {
    return res.status(400).json({ error: 'deviceId is required' });
  }

  // Check if already exists
  const existing = await db.prepare(
    'SELECT * FROM devices WHERE device_id = ?'
  ).get(deviceId);

  if (existing) {
    // Return current status so Flutter can show the right UI
    return res.json({
      status: existing.status,
      message: existing.status === 'approved'
        ? 'Device already approved'
        : existing.status === 'rejected'
          ? 'Device registration was rejected. Contact your admin.'
          : 'Device registration already pending. Waiting for admin approval.',
    });
  }

  const id = uuidv4();
  await db.prepare(`
    INSERT INTO devices (id, device_id, device_name, platform)
    VALUES (?, ?, ?, ?)
  `).run(id, deviceId, deviceName || 'Unknown Device', platform || 'unknown');

  res.status(201).json({
    status: 'pending',
    message: 'Device registration submitted. Waiting for admin approval.',
  });
});

// ─────────────────────────────────────────────────────────────────────────
// GET /auth/device/status/:deviceId
// Check the current approval status of a device. No auth required.
// ─────────────────────────────────────────────────────────────────────────
router.get('/status/:deviceId', async (req, res) => {
  const { deviceId } = req.params;

  const device = await db.prepare(
    'SELECT status, device_name FROM devices WHERE device_id = ?'
  ).get(deviceId);

  if (!device) {
    return res.json({ status: 'unregistered' });
  }

  res.json({ status: device.status, deviceName: device.device_name });
});

// ─────────────────────────────────────────────────────────────────────────
// GET /auth/devices — admin only: list all devices
// ─────────────────────────────────────────────────────────────────────────
router.get('/', requireAuth, requireRole('admin'), async (req, res) => {
  const devices = await db.prepare(`
    SELECT
      d.id,
      d.device_id,
      d.device_name,
      d.platform,
      d.status,
      d.requested_at,
      d.reviewed_at,
      d.notes,
      u.username AS reviewed_by_username
    FROM devices d
    LEFT JOIN users u ON d.reviewed_by = u.id
    ORDER BY
      CASE d.status WHEN 'pending' THEN 0 WHEN 'approved' THEN 1 ELSE 2 END,
      d.requested_at DESC
  `).all();

  res.json({ devices });
});

// ─────────────────────────────────────────────────────────────────────────
// PATCH /auth/devices/:id — admin only: approve or reject a device
// ─────────────────────────────────────────────────────────────────────────
router.patch('/:id', requireAuth, requireRole('admin'), async (req, res) => {
  const { id } = req.params;
  const { status, notes } = req.body || {};

  if (!['approved', 'rejected'].includes(status)) {
    return res.status(400).json({ error: "status must be 'approved' or 'rejected'" });
  }

  const existing = await db.prepare('SELECT * FROM devices WHERE id = ?').get(id);
  if (!existing) {
    return res.status(404).json({ error: 'Device not found' });
  }

  await db.prepare(`
    UPDATE devices
    SET status = ?, reviewed_at = now(), reviewed_by = ?, notes = ?
    WHERE id = ?
  `).run(status, req.user.sub, notes || null, id);

  const updated = await db.prepare('SELECT * FROM devices WHERE id = ?').get(id);
  res.json({ device: updated });
});

// ─────────────────────────────────────────────────────────────────────────
// DELETE /auth/devices/:id — admin only: remove a device entirely
// (forces re-registration on next login attempt from that device)
// ─────────────────────────────────────────────────────────────────────────
router.delete('/:id', requireAuth, requireRole('admin'), async (req, res) => {
  const { id } = req.params;

  const existing = await db.prepare('SELECT * FROM devices WHERE id = ?').get(id);
  if (!existing) {
    return res.status(404).json({ error: 'Device not found' });
  }

  await db.prepare('DELETE FROM devices WHERE id = ?').run(id);
  res.json({ success: true });
});

module.exports = router;
