const express = require('express'), db = require('../db');
const router = express.Router();
router.get('/history', async (req, res) => res.json(await db.scans.list(req.user.id, 50)));
router.delete('/history', async (req, res) => { await db.scans.clear(req.user.id); res.json({ ok: true }); });
router.get('/stats', async (req, res) => res.json(await db.scans.stats(req.user.id)));
module.exports = router;
