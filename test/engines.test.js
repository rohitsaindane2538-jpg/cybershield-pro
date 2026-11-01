const test = require('node:test'), assert = require('node:assert/strict');
const H = require('../src/engines/heuristics'), ioc = require('../src/engines/ioc'), file = require('../src/engines/file'), mitre = require('../src/engines/mitre');

test('phishing: obvious scam scores high, benign scores low', () => {
  assert.ok(H.scanPhishing('Dear customer verify your password at http://192.168.4.7/x urgent').score >= 60);
  assert.ok(H.scanPhishing('Lunch at 1pm tomorrow? The team is meeting near the office.').score < 10);
});
test('url: lookalike on abuse TLD is flagged; clean https is low', () => {
  assert.ok(H.scanUrl('http://secure-login-paypal.account-verify.xyz/u').score >= 50);
  assert.ok(H.scanUrl('https://example.com/docs').score < 10);
  assert.ok(H.scanUrl('not a url ://').score >= 50);
});
test('password: common password is weak, long passphrase is strong', () => {
  assert.ok(H.scanPassword('Password123').score >= 70);
  assert.equal(H.scanPassword('correct-horse-battery-staple-92!').score, 0);
});
test('logs: detects brute force and SQLi', () => {
  const logs = Array(6).fill('sshd: Failed password for root from 203.0.113.9').join('\n') + "\nGET /?q=1' OR 1=1--";
  const r = H.scanLogs(logs);
  assert.ok(r.flags.some(f => /brute force/i.test(f)) && r.flags.some(f => /sql/i.test(f)));
});
test('code: flags SQL concat, innerHTML, hard-coded secret', () => {
  const r = H.scanCode(`const q = "SELECT * FROM u WHERE n='" + x; el.innerHTML = y; const apiKey = "abcdef123456";`);
  assert.equal(r.flags.length, 3);
});
test('ioc: extracts and separates public vs private IPs', () => {
  const r = ioc.extract('From 203.0.113.9 and 10.0.0.5 visit http://evil.xyz/a mail bob@corp.com CVE-2024-12345 ' + 'a'.repeat(64));
  assert.deepEqual(r.ips, ['203.0.113.9']); assert.deepEqual(r.privateIps, ['10.0.0.5']);
  assert.equal(r.urls.length, 1); assert.equal(r.emails[0], 'bob@corp.com'); assert.equal(r.cves[0], 'CVE-2024-12345'); assert.equal(r.hashes[0].type, 'sha256');
});
test('file: PE disguised as image is high risk; plain text is low', () => {
  const pe = Buffer.concat([Buffer.from([0x4d, 0x5a]), Buffer.from('VirtualAlloc CreateRemoteThread powershell -enc AAAA')]);
  const bad = file.inspect(pe, 'invoice.jpg');
  assert.ok(bad.score >= 70); assert.match(bad.meta.type, /PE/); assert.equal(bad.meta.sha256.length, 64);
  assert.ok(file.inspect(Buffer.from('hello world, just notes'), 'notes.txt').score < 10);
});
test('file: entropy of random data is near 8, of repeated bytes is 0', () => {
  assert.ok(file.entropy(require('crypto').randomBytes(65536)) > 7.9); assert.equal(file.entropy(Buffer.alloc(100, 1)), 0);
});
test('mitre: validate drops hallucinated IDs and dedupes', () => {
  assert.deepEqual(mitre.validate(['T1566', 't1566', 'T9999', { id: 'T1110' }]).map(m => m.id), ['T1566', 'T1110']);
  assert.deepEqual(mitre.validate('nope'), []);
});
