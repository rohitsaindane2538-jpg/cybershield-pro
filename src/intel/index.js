// Live threat-intelligence lookups (VirusTotal, AbuseIPDB). Fixed hosts only; indicators are validated before use.
const cfg = require('../config'), metrics = require('../metrics'), log = require('../logger');
const RE = {
  ip: /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/,
  domain: /^(?=.{4,253}$)(?:[a-z0-9-]{1,63}\.)+[a-z]{2,24}$/i,
  hash: /^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i
};
const cache = new Map(), TTL = 3600e3, MAX = 300;
const unavailable = (source, why) => ({ available: false, source, summary: why || `${source} API key not configured` });

async function getJSON(url, headers) {
  const ctrl = new AbortController(), t = setTimeout(() => ctrl.abort(), 8000);
  try { return await fetch(url, { headers, signal: ctrl.signal }); } finally { clearTimeout(t); }
}
async function memo(key, fn) {
  const hit = cache.get(key); if (hit && Date.now() - hit.at < TTL) { metrics.inc('intel_cache_hits'); return hit.v; }
  const v = await fn(); if (v.available !== false) { if (cache.size >= MAX) cache.delete(cache.keys().next().value); cache.set(key, { at: Date.now(), v }); } return v;
}

async function virustotal(path) {
  if (!cfg.vtKey) return unavailable('VirusTotal');
  return memo('vt|' + path, async () => {
    try {
      const r = await getJSON('https://www.virustotal.com/api/v3/' + path, { 'x-apikey': cfg.vtKey });
      metrics.inc('intel_calls');
      if (r.status === 404) return { available: true, source: 'VirusTotal', found: false, malicious: 0, suspicious: 0, summary: 'Not previously seen by VirusTotal' };
      if (r.status === 429) return unavailable('VirusTotal', 'VirusTotal rate limit reached. Try again in a minute.');
      if (!r.ok) return unavailable('VirusTotal', `VirusTotal returned status ${r.status}`);
      const a = (await r.json()).data.attributes, st = a.last_analysis_stats || {}, total = Object.values(st).reduce((x, y) => x + y, 0);
      return { available: true, source: 'VirusTotal', found: true, malicious: st.malicious || 0, suspicious: st.suspicious || 0, harmless: st.harmless || 0, total, reputation: a.reputation ?? null,
        summary: `${st.malicious || 0} of ${total} security engines flag this as malicious, ${st.suspicious || 0} as suspicious` };
    } catch (e) { log.warn('intel_vt_failed', { error: e.message }); return unavailable('VirusTotal', 'VirusTotal lookup failed: ' + e.message); }
  });
}
async function abuseipdb(ip) {
  if (!cfg.abuseKey) return unavailable('AbuseIPDB');
  return memo('abuse|' + ip, async () => {
    try {
      const r = await getJSON(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`, { Key: cfg.abuseKey, Accept: 'application/json' });
      metrics.inc('intel_calls');
      if (r.status === 429) return unavailable('AbuseIPDB', 'AbuseIPDB rate limit reached.');
      if (!r.ok) return unavailable('AbuseIPDB', `AbuseIPDB returned status ${r.status}`);
      const d = (await r.json()).data;
      return { available: true, source: 'AbuseIPDB', found: true, abuseScore: d.abuseConfidenceScore, reports: d.totalReports, country: d.countryCode, isp: d.isp,
        summary: `Abuse confidence ${d.abuseConfidenceScore}%, ${d.totalReports} reports in 90 days (${d.countryCode || '??'}, ${d.isp || 'unknown ISP'})` };
    } catch (e) { log.warn('intel_abuse_failed', { error: e.message }); return unavailable('AbuseIPDB', 'AbuseIPDB lookup failed: ' + e.message); }
  });
}

function verdictOf(results) {
  const live = results.filter(r => r.available);
  if (!live.length) return 'Unknown';
  const mal = Math.max(0, ...live.map(r => r.malicious || 0)), abuse = Math.max(0, ...live.map(r => r.abuseScore || 0)), sus = Math.max(0, ...live.map(r => r.suspicious || 0));
  if (mal >= 3 || abuse >= 75) return 'Malicious';
  if (mal >= 1 || sus >= 2 || abuse >= 25) return 'Suspicious';
  return 'Clean';
}
const wrap = async (indicator, type, jobs) => {
  const results = await Promise.all(jobs); const verdict = verdictOf(results);
  return { indicator, type, verdict, results, summary: results.map(r => `${r.source}: ${r.summary}`).join(' | ') };
};

const lookupIp = ip => RE.ip.test(ip) ? wrap(ip, 'ip', [virustotal('ip_addresses/' + ip), abuseipdb(ip)]) : Promise.reject(new Error('Not a valid IPv4 address'));
const lookupDomain = d => RE.domain.test(d) ? wrap(d.toLowerCase(), 'domain', [virustotal('domains/' + d.toLowerCase())]) : Promise.reject(new Error('Not a valid domain'));
const lookupHash = h => RE.hash.test(h) ? wrap(h.toLowerCase(), 'hash', [virustotal('files/' + h.toLowerCase())]) : Promise.reject(new Error('Not a valid MD5, SHA-1 or SHA-256 hash'));
const lookupUrl = u => /^https?:\/\/\S{3,2000}$/i.test(u) ? wrap(u, 'url', [virustotal('urls/' + Buffer.from(u).toString('base64url'))]) : Promise.reject(new Error('Not a valid http(s) URL'));

function detect(x) { x = String(x || '').trim(); return RE.ip.test(x) ? 'ip' : RE.hash.test(x) ? 'hash' : /^https?:\/\//i.test(x) ? 'url' : RE.domain.test(x) ? 'domain' : null; }
async function lookup(indicator) {
  const x = String(indicator || '').trim(), t = detect(x);
  if (!t) throw new Error('Enter an IPv4 address, domain, URL or file hash (MD5, SHA-1, SHA-256).');
  return { ip: lookupIp, domain: lookupDomain, url: lookupUrl, hash: lookupHash }[t](x);
}
module.exports = { lookup, lookupIp, lookupDomain, lookupHash, lookupUrl, detect, verdictOf, enabled: () => !!(cfg.vtKey || cfg.abuseKey) };
