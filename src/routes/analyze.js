const intel = require('../intel'), express = require('express'), H = require('../engines/heuristics'), ioc = require('../engines/ioc'), fileEngine = require('../engines/file'),
  { analyze } = require('../ai/analyze'), client = require('../ai/client'), cfg = require('../config'), db = require('../db'), log = require('../logger');
const router = express.Router();

const bad = (res, msg = 'Input is missing or too long.') => res.status(400).json({ error: msg });
const okStr = (v, max) => typeof v === 'string' && v.trim().length > 0 && v.length <= max;
const save = (req, r, preview) => db.scans.add(req.user.id, { kind: r.kind, level: r.level, score: r.risk_score, verdict: r.verdict, preview: preview.slice(0, 80).replace(/\s+/g, ' '), summary: r.summary, top: r.findings.slice(0, 3).map(f => f.title) });

function textTool(path, kind, key, max, scan, instruction, withIocs) {
  router.post(path, async (req, res) => {
    const input = req.body[key]; if (!okStr(input, max)) return bad(res);
    const r = await analyze({ kind, input, heur: scan(input), instruction });
    if (withIocs) r.iocs = ioc.extract(input);
    await save(req, r, input); res.json(r);
  });
}
textTool('/analyze/phishing', 'Message', 'text', 12000, H.scanPhishing, 'Analyze this email/SMS/chat message for phishing and social engineering. Name the manipulation tactics used.', true);
textTool('/analyze/url', 'Link', 'url', 2000, H.scanUrl, 'Assess this URL for phishing, typosquatting, brand impersonation and malware delivery using only its structure. You cannot browse it.', false);
textTool('/analyze/logs', 'Logs', 'logs', 50000, H.scanLogs, 'Triage these logs as an incident responder: attack types, attacker behavior, impact, and containment steps.', true);
textTool('/analyze/code', 'Code', 'code', 30000, H.scanCode, 'Audit this code for vulnerabilities (OWASP Top 10, CWE). Cite CWE IDs in finding titles and give a concrete fix per issue in recommended_actions.', false);

router.post('/analyze/file', async (req, res) => {
  const { name, data } = req.body;
  if (!okStr(name, 200) || !okStr(data, 2.2e6) || !/^[A-Za-z0-9+/=]+$/.test(data)) return bad(res, 'Upload a file under 1.5 MB.');
  const buf = Buffer.from(data, 'base64'); if (buf.length > 1.6e6) return bad(res, 'File is larger than 1.5 MB.');
  const f = fileEngine.inspect(buf, name.replace(/[\\/]/g, '_'));
  const summary = `File: ${f.meta.name}\nSize: ${f.meta.size} bytes\nDetected type: ${f.meta.type}\nEntropy: ${f.meta.entropy}\nSHA-256: ${f.meta.sha256}\nExtracted strings sample:\n${f.stringsText}`;
  const r = await analyze({ kind: 'File', input: summary, heur: f, instruction: 'Triage this file from its static metadata and extracted strings only (the file is never executed). Judge whether it looks like malware, a dropper, a malicious document, or benign.' });
  r.file = f.meta; r.iocs = ioc.extract(f.stringsText);
  if (intel.enabled()) {
    r.intel = await intel.lookupHash(f.meta.sha256).catch(() => null);
    if (r.intel?.verdict === 'Malicious') { r.risk_score = Math.max(r.risk_score, 90); r.level = H.level(r.risk_score); r.verdict = 'Malicious'; r.findings.unshift({ title: 'Known malicious file hash', detail: r.intel.summary, severity: 'Critical' }); }
  }
  await save(req, r, name); res.json(r);
});

// Passwords stay on the server; only numeric metrics reach the AI.
router.post('/password', async (req, res) => {
  const { password } = req.body; if (!okStr(password, 200)) return bad(res);
  const m = H.scanPassword(password);
  const out = { kind: 'Password', engine: 'heuristic', risk_score: m.score, level: H.level(m.score), bits: m.bits, crackTime: m.crackTime, length: m.length, flags: m.flags, tips: [] };
  if (cfg.aiEnabled) {
    try {
      const ai = await client.completeJSON('You are a credential-security coach. You receive only metrics about a password, never the password. Return {"tips":["3-4 short actions"],"passphrase_idea":"a method, not an actual password"}.', JSON.stringify(m), 500);
      out.tips = (ai.tips || []).slice(0, 5).map(t => String(t).slice(0, 200)); out.passphrase_idea = String(ai.passphrase_idea || '').slice(0, 300); out.engine = 'claude+heuristic';
    } catch (e) { log.error('password_ai_failed', { error: e.message }); }
  }
  await db.scans.add(req.user.id, { kind: 'Password', level: out.level, score: out.risk_score, verdict: m.crackTime, preview: `${m.length} characters`, summary: `Crack time ${m.crackTime}`, top: m.flags });
  res.json(out);
});

// Manual indicator lookup (IP, domain, URL or file hash) against live threat intelligence.
router.post('/intel', async (req, res) => {
  const { indicator } = req.body; if (!okStr(indicator, 2100)) return bad(res, 'Enter an indicator to look up.');
  try {
    const r = await intel.lookup(indicator), level = { Malicious: 'High', Suspicious: 'Medium' }[r.verdict] || 'Low';
    await db.scans.add(req.user.id, { kind: 'Intel', level, score: { Malicious: 90, Suspicious: 50 }[r.verdict] || 5, verdict: r.verdict, preview: r.indicator.slice(0, 80), summary: r.summary, top: [] });
    res.json({ ...r, level, keysConfigured: intel.enabled() });
  } catch (e) { bad(res, e.message); }
});
module.exports = router;
