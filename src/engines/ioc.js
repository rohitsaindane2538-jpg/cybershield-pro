// Indicator-of-compromise extraction (offline, regex based).
const RE = {
  ipv4: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g,
  url: /\bhttps?:\/\/[^\s<>"')]+/gi,
  email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
  sha256: /\b[a-f0-9]{64}\b/gi, sha1: /\b[a-f0-9]{40}\b/gi, md5: /\b[a-f0-9]{32}\b/gi,
  cve: /\bCVE-\d{4}-\d{4,7}\b/gi,
  domain: /\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|xyz|top|ru|cn|info|biz|co|in|dev|app|click|tk|ml|gq|cf|zip|work)\b/gi
};
const uniq = (a, n = 25) => [...new Set(a)].slice(0, n);
const isPrivate = ip => /^(10\.|127\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|0\.)/.test(ip);
function extract(text = '') {
  const m = (re) => text.match(re) || [];
  const ips = uniq(m(RE.ipv4)), emails = uniq(m(RE.email)), urls = uniq(m(RE.url));
  const emailDomains = new Set(emails.map(e => e.split('@')[1].toLowerCase()));
  const domains = uniq(m(RE.domain).map(d => d.toLowerCase()).filter(d => !emailDomains.has(d)));
  const hashes = [...m(RE.sha256).map(v => ({ type: 'sha256', value: v })), ...m(RE.sha1).map(v => ({ type: 'sha1', value: v })), ...m(RE.md5).map(v => ({ type: 'md5', value: v }))].slice(0, 25);
  return { ips: ips.filter(i => !isPrivate(i)), privateIps: ips.filter(isPrivate), urls, domains, emails, hashes, cves: uniq(m(RE.cve).map(c => c.toUpperCase())) };
}
const count = i => Object.values(i).reduce((n, v) => n + v.length, 0);
module.exports = { extract, count, isPrivate };
