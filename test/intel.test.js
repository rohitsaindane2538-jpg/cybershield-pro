const test = require('node:test'), assert = require('node:assert/strict');
delete process.env.VIRUSTOTAL_API_KEY; delete process.env.ABUSEIPDB_API_KEY;
const intel = require('../src/intel'), agent = require('../src/ai/agent');
const realFetch = globalThis.fetch;
test.afterEach(() => { globalThis.fetch = realFetch; delete process.env.VIRUSTOTAL_API_KEY; delete process.env.ABUSEIPDB_API_KEY; });

test('indicator type detection', () => {
  assert.equal(intel.detect('8.8.8.8'), 'ip'); assert.equal(intel.detect('Evil.Example.com'), 'domain'); assert.equal(intel.detect('https://a.io/x'), 'url');
  assert.equal(intel.detect('a'.repeat(64)), 'hash'); assert.equal(intel.detect('hello world'), null); assert.equal(intel.detect('999.1.1.1'), null);
});
test('verdict thresholds', () => {
  assert.equal(intel.verdictOf([{ available: false }]), 'Unknown');
  assert.equal(intel.verdictOf([{ available: true, malicious: 5 }]), 'Malicious'); assert.equal(intel.verdictOf([{ available: true, abuseScore: 80 }]), 'Malicious');
  assert.equal(intel.verdictOf([{ available: true, malicious: 1 }]), 'Suspicious'); assert.equal(intel.verdictOf([{ available: true, malicious: 0, abuseScore: 0 }]), 'Clean');
});
test('without API keys lookups degrade gracefully (no network call)', async () => {
  globalThis.fetch = () => { throw new Error('network must not be called'); };
  const r = await intel.lookupIp('8.8.4.4');
  assert.equal(r.verdict, 'Unknown'); assert.ok(r.results.every(x => x.available === false));
});
test('rejects malformed indicators before any request', async () => {
  await assert.rejects(intel.lookupIp('1.2.3'), /valid IPv4/); await assert.rejects(intel.lookupHash('xyz'), /hash/); await assert.rejects(intel.lookup('???'), /Enter an/);
});
test('VirusTotal response is parsed and the URL id is base64url encoded', async () => {
  process.env.VIRUSTOTAL_API_KEY = 'k'; let seen;
  globalThis.fetch = async (url, o) => { seen = { url, key: o.headers['x-apikey'] }; return { ok: true, status: 200, json: async () => ({ data: { attributes: { last_analysis_stats: { malicious: 7, suspicious: 1, harmless: 50, undetected: 12 }, reputation: -30 } } }) }; };
  const r = await intel.lookupUrl('http://bad.example.net/x?a=1');
  assert.equal(r.verdict, 'Malicious'); assert.equal(r.results[0].malicious, 7); assert.equal(r.results[0].total, 70); assert.equal(seen.key, 'k');
  assert.ok(seen.url.endsWith('/urls/' + Buffer.from('http://bad.example.net/x?a=1').toString('base64url')));
});
test('AbuseIPDB response is parsed; 404 on VirusTotal means not found', async () => {
  process.env.ABUSEIPDB_API_KEY = 'a'; process.env.VIRUSTOTAL_API_KEY = 'v';
  globalThis.fetch = async url => url.includes('abuseipdb') ? { ok: true, status: 200, json: async () => ({ data: { abuseConfidenceScore: 92, totalReports: 41, countryCode: 'RU', isp: 'ExampleNet' } }) } : { ok: false, status: 404 };
  const r = await intel.lookupIp('203.0.113.77');
  assert.equal(r.verdict, 'Malicious'); assert.match(r.summary, /92%/); assert.equal(r.results.find(x => x.source === 'VirusTotal').found, false);
});
test('rate limit and server errors are reported as unavailable, not thrown', async () => {
  process.env.VIRUSTOTAL_API_KEY = 'v'; globalThis.fetch = async () => ({ ok: false, status: 429 });
  const r = await intel.lookupDomain('rate-limited-example.com'); assert.equal(r.verdict, 'Unknown'); assert.match(r.summary, /rate limit/i);
});
test('agent exposes intel tools and rejects bad input safely', async () => {
  const names = agent.TOOLS.map(t => t.name); for (const n of ['lookup_ip_reputation', 'lookup_domain_reputation', 'lookup_url_reputation', 'lookup_file_hash']) assert.ok(names.includes(n));
  await assert.rejects(agent.runTool('lookup_ip_reputation', { ip: 'not-an-ip' }, {}), /valid IPv4/);
});
