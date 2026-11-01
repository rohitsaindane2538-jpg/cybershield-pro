const test = require('node:test'), assert = require('node:assert/strict');
process.env.CS_DB = 'test-db.json'; delete process.env.ANTHROPIC_API_KEY; process.env.SESSION_SECRET = 'test-secret';
const sec = require('../src/security'), db = require('../src/db'), ai = require('../src/ai/analyze'), agent = require('../src/ai/agent');

test('password hashing verifies and rejects', async () => {
  const h = await sec.hashPassword('hunter2hunter2');
  assert.ok(await sec.verifyPassword('hunter2hunter2', h)); assert.ok(!(await sec.verifyPassword('wrong-password', h))); assert.ok(!(await sec.verifyPassword('x', 'garbage')));
});
test('session tokens: valid, tampered, expired', () => {
  const t = sec.sign({ uid: 'a', exp: Date.now() + 1000 });
  assert.equal(sec.verify(t).uid, 'a'); assert.equal(sec.verify(t.slice(0, -2) + 'xx'), null);
  assert.equal(sec.verify(sec.sign({ uid: 'a', exp: Date.now() - 1 })), null); assert.equal(sec.verify(undefined), null);
});
test('cookie parser', () => assert.deepEqual(sec.parseCookies('a=1; cs_session=x.y'), { a: '1', cs_session: 'x.y' }));

test('db: users unique lookup, per-user scans, stats isolation', async () => {
  db.reset(); const a = await db.users.create('alice', 'h'), b = await db.users.create('bob', 'h');
  await db.scans.add(a.id, { kind: 'URL', level: 'High', score: 80 }); await db.scans.add(a.id, { kind: 'Logs', level: 'Low', score: 5 }); await db.scans.add(b.id, { kind: 'URL', level: 'Low', score: 1 });
  assert.equal((await db.users.byName('alice')).id, a.id); assert.equal((await db.scans.list(a.id)).length, 2);
  const s = await db.scans.stats(a.id); assert.equal(s.total, 2); assert.equal(s.threats, 1); assert.equal(s.days.length, 7);
  await db.scans.clear(a.id); assert.equal((await db.scans.list(a.id)).length, 0); assert.equal((await db.scans.list(b.id)).length, 1);
  assert.equal(db.kind, 'json');
  db.reset(); require('fs').rmSync(require('path').join(__dirname, '..', 'data', 'test-db.json'), { force: true });
});

test('AI output normalization rejects bad shapes and clamps values', () => {
  const n = ai.normalize({ verdict: 'Evil', risk_score: 999, findings: [{ title: 'x', severity: 'Nope' }, { detail: 'no title' }], mitre: ['T1110', 'T0000'], recommended_actions: 'bad' });
  assert.equal(n.verdict, null); assert.equal(n.risk_score, 100); assert.equal(n.findings.length, 1); assert.equal(n.findings[0].severity, 'Medium');
  assert.deepEqual(n.mitre.map(m => m.id), ['T1110']); assert.deepEqual(n.recommended_actions, []);
});
test('analyze falls back to rule engine when no AI key', async () => {
  const r = await ai.analyze({ kind: 'Message', input: 'verify your password urgent', heur: require('../src/engines/heuristics').scanPhishing('verify your password urgent'), instruction: 'x' });
  assert.equal(r.engine, 'heuristic'); assert.ok(r.risk_score > 0); assert.ok(Array.isArray(r.mitre));
});
test('offline agent investigates with tools and emits a final brief', async () => {
  const ev = []; await agent.runAgent({ task: 'Email said verify your password at http://185.220.101.4/pay urgent', uid: 'u', emit: e => ev.push(e) });
  assert.ok(ev.some(e => e.type === 'tool' && e.name === 'extract_iocs')); assert.ok(ev.some(e => e.name === 'scan_url'));
  const fin = ev.find(e => e.final); assert.match(fin.text, /## Summary/); assert.match(fin.text, /## Recommended actions/);
});
test('agent tools are well-formed for the Messages API', async () => {
  for (const t of agent.TOOLS) { assert.ok(t.name && t.description); assert.equal(t.input_schema.type, 'object'); }
  assert.deepEqual(await agent.runTool('lookup_mitre', { id: 't1110' }, {}), { id: 'T1110', name: 'Brute Force' });
});
