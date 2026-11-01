const express = require('express'), cfg = require('../config'), db = require('../db'), sec = require('../security');
const router = express.Router(), COOKIE = 'cs_session', DAY = 864e5, fails = new Map();

const setCookie = (res, userId) => res.setHeader('Set-Cookie',
  `${COOKIE}=${sec.sign({ uid: userId, exp: Date.now() + 7 * DAY })}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${7 * 86400}${cfg.secureCookie ? '; Secure' : ''}`);

async function requireAuth(req, res, next) {
  const p = sec.verify(sec.parseCookies(req.headers.cookie)[COOKIE]), u = p && await db.users.byId(p.uid);
  if (!u) return res.status(401).json({ error: 'Sign in required.' });
  req.user = { id: u.id, username: u.username }; next();
}
const valid = (u, p) => /^[a-z0-9_]{3,24}$/.test(u || '') && typeof p === 'string' && p.length >= 8 && p.length <= 128;

router.post('/register', async (req, res) => {
  const username = String(req.body.username || '').toLowerCase().trim(), { password } = req.body;
  if (!valid(username, password)) return res.status(400).json({ error: 'Username: 3-24 letters, numbers or underscores. Password: at least 8 characters.' });
  if (await db.users.byName(username)) return res.status(409).json({ error: 'That username is taken.' });
  const u = await db.users.create(username, await sec.hashPassword(password));
  setCookie(res, u.id); res.status(201).json({ username: u.username });
});

router.post('/login', async (req, res) => {
  const username = String(req.body.username || '').toLowerCase().trim(), key = `${req.ip}|${username}`, f = fails.get(key);
  if (f && f.n >= 5 && Date.now() < f.until) return res.status(429).json({ error: 'Too many attempts. Try again in a few minutes.' });
  const u = await db.users.byName(username);
  const ok = u && typeof req.body.password === 'string' && await sec.verifyPassword(req.body.password, u.passHash);
  if (!ok) { const n = (f?.n || 0) + 1; fails.set(key, { n, until: Date.now() + 5 * 60e3 }); return res.status(401).json({ error: 'Wrong username or password.' }); }
  fails.delete(key); setCookie(res, u.id); res.json({ username: u.username });
});

router.post('/logout', (_q, res) => { res.setHeader('Set-Cookie', `${COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`); res.json({ ok: true }); });
router.get('/me', requireAuth, (req, res) => res.json({ username: req.user.username }));
module.exports = { router, requireAuth };
