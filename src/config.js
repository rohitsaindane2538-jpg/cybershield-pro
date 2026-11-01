try { require('dotenv').config(); } catch { /* dotenv optional in tests */ }
const fs = require('fs'), path = require('path'), crypto = require('crypto');
const dataDir = path.join(__dirname, '..', 'data');
fs.mkdirSync(dataDir, { recursive: true });
let cached;
function sessionSecret() {
  if (process.env.SESSION_SECRET) return process.env.SESSION_SECRET;
  if (cached) return cached;
  const f = path.join(dataDir, '.secret');
  try { cached = fs.readFileSync(f, 'utf8').trim(); }
  catch { cached = crypto.randomBytes(32).toString('hex'); fs.writeFileSync(f, cached); }
  return cached;
}
module.exports = {
  dataDir,
  get port() { return Number(process.env.PORT) || 3000; },
  get apiKey() { return process.env.ANTHROPIC_API_KEY || ''; },
  get model() { return process.env.CLAUDE_MODEL || 'claude-sonnet-4-6'; },
  get vtKey() { return process.env.VIRUSTOTAL_API_KEY || ''; },
  get abuseKey() { return process.env.ABUSEIPDB_API_KEY || ''; },
  get databaseUrl() { return process.env.DATABASE_URL || ''; },
  get aiEnabled() { return !!this.apiKey; },
  get secret() { return sessionSecret(); },
  get secureCookie() { return process.env.NODE_ENV === 'production'; }
};
