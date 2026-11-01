// Pure crypto helpers (no framework imports, easy to unit test).
const crypto = require('crypto'), { promisify } = require('util'), cfg = require('./config');
const scrypt = promisify(crypto.scrypt);

async function hashPassword(pw) {
  const salt = crypto.randomBytes(16), h = await scrypt(pw, salt, 64);
  return `scrypt$${salt.toString('hex')}$${h.toString('hex')}`;
}
async function verifyPassword(pw, stored) {
  const [alg, s, h] = String(stored).split('$');
  if (alg !== 'scrypt' || !s || !h) return false;
  const exp = Buffer.from(h, 'hex'), got = await scrypt(pw, Buffer.from(s, 'hex'), exp.length);
  return got.length === exp.length && crypto.timingSafeEqual(got, exp);
}
const mac = (body, secret) => crypto.createHmac('sha256', secret).update(body).digest('base64url');
function sign(payload, secret = cfg.secret) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return `${body}.${mac(body, secret)}`;
}
function verify(token, secret = cfg.secret) {
  if (typeof token !== 'string') return null;
  const [body, sig] = token.split('.');
  if (!body || !sig) return null;
  const a = Buffer.from(sig), b = Buffer.from(mac(body, secret));
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try { const p = JSON.parse(Buffer.from(body, 'base64url').toString()); return p.exp && Date.now() > p.exp ? null : p; } catch { return null; }
}
function parseCookies(h = '') {
  return Object.fromEntries(h.split(';').map(p => p.trim()).filter(Boolean).map(p => { const i = p.indexOf('='); return [p.slice(0, i), decodeURIComponent(p.slice(i + 1))]; }));
}
module.exports = { hashPassword, verifyPassword, sign, verify, parseCookies };
