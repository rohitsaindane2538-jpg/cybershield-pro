// PostgreSQL backend (used when DATABASE_URL is set). Same interface as db/json.js.
const crypto = require('crypto'), cfg = require('../config');
let pool;
const uid = () => crypto.randomBytes(8).toString('hex');
const q = (text, params) => pool.query(text, params);

async function init() {
  const { Pool } = require('pg');
  const local = /localhost|127\.0\.0\.1|@postgres[:/]/.test(cfg.databaseUrl);
  pool = new Pool({ connectionString: cfg.databaseUrl, ssl: local || process.env.PGSSL === 'disable' ? false : { rejectUnauthorized: false }, max: 10 });
  await q(`CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, pass_hash TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now())`);
  await q(`CREATE TABLE IF NOT EXISTS scans (id TEXT PRIMARY KEY, uid TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, at TIMESTAMPTZ NOT NULL DEFAULT now(),
    kind TEXT NOT NULL, level TEXT, score INT, verdict TEXT, preview TEXT, summary TEXT, top JSONB NOT NULL DEFAULT '[]')`);
  await q('CREATE INDEX IF NOT EXISTS scans_uid_at ON scans (uid, at DESC)');
}
const toUser = r => r && { id: r.id, username: r.username, passHash: r.pass_hash, createdAt: r.created_at.toISOString() };
const toScan = r => ({ id: r.id, uid: r.uid, at: r.at.toISOString(), kind: r.kind, level: r.level, score: r.score, verdict: r.verdict, preview: r.preview, summary: r.summary, top: r.top });

const users = {
  async create(username, passHash) { const id = uid(); const r = await q('INSERT INTO users (id, username, pass_hash) VALUES ($1,$2,$3) RETURNING *', [id, username, passHash]); return toUser(r.rows[0]); },
  async byName(n) { return toUser((await q('SELECT * FROM users WHERE username = $1', [n])).rows[0]); },
  async byId(i) { return toUser((await q('SELECT * FROM users WHERE id = $1', [i])).rows[0]); }
};
const scans = {
  async add(userId, r) {
    const id = uid();
    const res = await q('INSERT INTO scans (id, uid, kind, level, score, verdict, preview, summary, top) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *',
      [id, userId, r.kind, r.level, r.score, r.verdict, r.preview, r.summary, JSON.stringify(r.top || [])]);
    await q('DELETE FROM scans WHERE uid = $1 AND id NOT IN (SELECT id FROM scans WHERE uid = $1 ORDER BY at DESC LIMIT 500)', [userId]);
    return toScan(res.rows[0]);
  },
  async list(userId, limit = 50) { return (await q('SELECT * FROM scans WHERE uid = $1 ORDER BY at DESC LIMIT $2', [userId, limit])).rows.map(toScan); },
  async clear(userId) { await q('DELETE FROM scans WHERE uid = $1', [userId]); },
  async stats(userId) {
    const [lv, kd, dy] = await Promise.all([
      q('SELECT level, count(*)::int AS n FROM scans WHERE uid = $1 GROUP BY level', [userId]),
      q('SELECT kind, count(*)::int AS n FROM scans WHERE uid = $1 GROUP BY kind', [userId]),
      q(`SELECT to_char(at AT TIME ZONE 'UTC','YYYY-MM-DD') AS day, count(*)::int AS n FROM scans WHERE uid = $1 AND at > now() - interval '7 days' GROUP BY 1`, [userId])]);
    const levels = { Low: 0, Medium: 0, High: 0, Critical: 0 }, byKind = {}, days = {};
    lv.rows.forEach(r => { if (r.level in levels) levels[r.level] = r.n; }); kd.rows.forEach(r => { byKind[r.kind] = r.n; });
    for (let i = 6; i >= 0; i--) days[new Date(Date.now() - i * 864e5).toISOString().slice(0, 10)] = 0;
    dy.rows.forEach(r => { if (r.day in days) days[r.day] = r.n; });
    return { total: Object.values(levels).reduce((a, b) => a + b, 0), levels, byKind, threats: levels.High + levels.Critical, days: Object.entries(days).map(([day, count]) => ({ day, count })) };
  }
};
module.exports = { init, users, scans, reset() {} };
