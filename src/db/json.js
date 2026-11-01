// Durable JSON store with atomic writes (temp file + rename). Swap for a real DB behind this same interface.
const fs = require('fs'), path = require('path'), crypto = require('crypto'), cfg = require('../config');
const file = () => path.join(cfg.dataDir, process.env.CS_DB || 'db.json');
let state = null;
const load = () => { if (state) return state; try { state = JSON.parse(fs.readFileSync(file(), 'utf8')); } catch { state = { users: [], scans: [] }; } return state; };
const flush = () => { const tmp = file() + '.tmp'; fs.writeFileSync(tmp, JSON.stringify(state)); fs.renameSync(tmp, file()); };
const uid = () => crypto.randomBytes(8).toString('hex');

const usersSync = {
  create(username, passHash) { const s = load(); const u = { id: uid(), username, passHash, createdAt: new Date().toISOString() }; s.users.push(u); flush(); return u; },
  byName: n => load().users.find(u => u.username === n),
  byId: i => load().users.find(u => u.id === i)
};
const scansSync = {
  add(userId, rec) {
    const s = load(); const r = { id: uid(), uid: userId, at: new Date().toISOString(), ...rec }; s.scans.push(r);
    const mine = s.scans.filter(x => x.uid === userId);
    if (mine.length > 500) { const drop = new Set(mine.slice(0, mine.length - 500).map(x => x.id)); s.scans = s.scans.filter(x => !drop.has(x.id)); }
    flush(); return r;
  },
  list: (userId, limit = 50) => load().scans.filter(x => x.uid === userId).slice(-limit).reverse(),
  clear(userId) { const s = load(); s.scans = s.scans.filter(x => x.uid !== userId); flush(); },
  stats(userId) {
    const mine = load().scans.filter(x => x.uid === userId);
    const levels = { Low: 0, Medium: 0, High: 0, Critical: 0 }, byKind = {}, days = {};
    for (let i = 6; i >= 0; i--) days[new Date(Date.now() - i * 864e5).toISOString().slice(0, 10)] = 0;
    mine.forEach(x => { if (levels[x.level] !== undefined) levels[x.level]++; byKind[x.kind] = (byKind[x.kind] || 0) + 1; const d = x.at.slice(0, 10); if (d in days) days[d]++; });
    return { total: mine.length, levels, byKind, threats: levels.High + levels.Critical, days: Object.entries(days).map(([day, count]) => ({ day, count })) };
  }
};
const reset = () => { state = { users: [], scans: [] }; };
// Async facade so JSON and PostgreSQL backends are interchangeable.
const asyncify = o => Object.fromEntries(Object.entries(o).map(([k, f]) => [k, async (...a) => f(...a)]));
module.exports = { init: async () => { load(); }, users: asyncify(usersSync), scans: asyncify(scansSync), reset };
