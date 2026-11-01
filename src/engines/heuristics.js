// Offline detection engines. They run on every scan and also serve as the fallback when no AI key is set.
const clamp = n => Math.max(0, Math.min(100, Math.round(n)));
const level = s => (s >= 75 ? 'Critical' : s >= 50 ? 'High' : s >= 25 ? 'Medium' : 'Low');

function scanPhishing(text) {
  const t = text.toLowerCase(), flags = [];
  const rules = [
    [/urgent|immediately|within 24 hours|account.*(suspended|locked|closed)|final notice/, 20, 'Urgency or threat language'],
    [/verify your|confirm your|update your (payment|billing|account|password)/, 20, 'Asks you to verify or update credentials'],
    [/password|otp|one[- ]time|cvv|ssn|pin\b/, 15, 'Requests sensitive data'],
    [/https?:\/\/\d{1,3}(\.\d{1,3}){3}/, 25, 'Link points to a raw IP address'],
    [/bit\.ly|tinyurl|t\.co|goo\.gl|cutt\.ly/, 12, 'Shortened link hides the destination'],
    [/gift card|crypto|wire transfer|lottery|winner|inheritance/, 18, 'Common scam payment or prize bait'],
    [/dear (customer|user|member|sir|madam)/, 8, 'Generic greeting'],
    [/\.(exe|scr|zip|js|vbs)\b/, 15, 'Risky attachment type mentioned']
  ];
  let score = 0;
  rules.forEach(([re, w, label]) => { if (re.test(t)) { score += w; flags.push(label); } });
  return { score: clamp(score), flags };
}

function scanUrl(raw) {
  const flags = []; let score = 0, u;
  try { u = new URL(/^https?:\/\//i.test(raw) ? raw : 'http://' + raw); } catch { return { score: 60, flags: ['Not a valid URL'] }; }
  const host = u.hostname;
  const add = (w, m) => { score += w; flags.push(m); };
  if (u.protocol !== 'https:') add(15, 'Not using HTTPS');
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) add(30, 'Host is a raw IP address');
  if (host.includes('xn--')) add(25, 'Punycode domain (possible lookalike characters)');
  if (host.split('.').length > 4) add(15, 'Excessive subdomains');
  if (host.split('-').length > 3) add(10, 'Many hyphens in domain');
  if (/\.(zip|top|xyz|click|gq|tk|ml|cf|work|country)$/.test(host)) add(18, 'High-abuse top-level domain');
  if (/(login|verify|secure|account|update|wallet|bank|paypal|apple|microsoft|google)/.test(host)) add(14, 'Brand or credential keyword inside domain');
  if (u.username || raw.includes('@')) add(20, 'Contains "@" or credentials in URL');
  if (raw.length > 90) add(8, 'Very long URL');
  return { score: clamp(score), flags };
}

function scanPassword(pw) {
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/\d/.test(pw)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) pool += 33;
  let bits = pw.length * Math.log2(pool || 1);
  const flags = [];
  const common = ['password', '123456', 'qwerty', 'letmein', 'admin', 'welcome', 'iloveyou', 'abc123', 'monkey'];
  if (common.some(c => pw.toLowerCase().includes(c))) { bits = Math.min(bits, 20); flags.push('Contains a very common password or word'); }
  if (/(.)\1{2,}/.test(pw)) { bits -= 10; flags.push('Repeated characters'); }
  if (/(0123|1234|2345|abcd|qwer)/i.test(pw)) { bits -= 10; flags.push('Keyboard or number sequence'); }
  if (pw.length < 12) flags.push('Shorter than 12 characters');
  bits = Math.max(0, bits);
  const secs = (Math.pow(2, bits) / 2) / 1e10; // offline GPU attack, 10B guesses/sec
  const fmt = s => s < 1 ? 'instantly' : s < 60 ? `${Math.round(s)} seconds` : s < 3600 ? `${Math.round(s / 60)} minutes` :
    s < 86400 ? `${Math.round(s / 3600)} hours` : s < 31536000 ? `${Math.round(s / 86400)} days` :
    s < 3.15e9 ? `${Math.round(s / 31536000)} years` : 'centuries';
  return { score: clamp(100 - bits * 100 / 90), bits: Math.round(bits), crackTime: fmt(secs), length: pw.length, flags };
}

function scanLogs(logs) {
  const lines = logs.split('\n').filter(Boolean), flags = [], ips = {};
  let failed = 0, score = 0;
  lines.forEach(l => {
    if (/failed|invalid user|authentication failure|denied|\b401\b|\b403\b/i.test(l)) {
      failed++; const ip = (l.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/) || [])[0]; if (ip) ips[ip] = (ips[ip] || 0) + 1;
    }
  });
  const brute = Object.entries(ips).filter(([, c]) => c >= 5);
  if (brute.length) { score += 40; flags.push(`Possible brute force from ${brute.map(([ip, c]) => `${ip} (${c}x)`).join(', ')}`); }
  if (/union\s+select|or\s+1=1|drop\s+table|sleep\(/i.test(logs)) { score += 35; flags.push('SQL injection patterns'); }
  if (/<script|onerror=|javascript:/i.test(logs)) { score += 25; flags.push('XSS payload patterns'); }
  if (/\.\.\/|\/etc\/passwd|cmd\.exe|powershell -enc/i.test(logs)) { score += 30; flags.push('Path traversal or command execution attempt'); }
  if (/nmap|sqlmap|nikto|masscan/i.test(logs)) { score += 20; flags.push('Known scanning tool signature'); }
  if (failed > 10) { score += 15; flags.push(`${failed} failed or denied events`); }
  return { score: clamp(score), flags, stats: { lines: lines.length, failed } };
}

function scanCode(code) {
  const flags = []; let score = 0;
  const rules = [
    [/eval\s*\(|new Function\(/, 20, 'Dynamic code execution (eval)'],
    [/(exec|system|popen|child_process|subprocess)[\s\S]{0,60}(\+|\$\{|%s|format)/, 25, 'Possible command injection'],
    [/(select|insert|update|delete)[^;\n]{0,80}("|'|`)\s*\+/i, 25, 'SQL built with string concatenation'],
    [/innerHTML\s*=|document\.write\(|dangerouslySetInnerHTML/, 15, 'Unsafe HTML injection sink'],
    [/(password|secret|api[_-]?key|token)\s*[:=]\s*["'][^"']{6,}/i, 25, 'Hard-coded secret'],
    [/md5|sha1\b/i, 10, 'Weak hash algorithm'],
    [/verify\s*=\s*False|rejectUnauthorized\s*:\s*false/, 15, 'TLS verification disabled'],
    [/pickle\.loads|yaml\.load\(|unserialize\(/, 20, 'Unsafe deserialization']
  ];
  rules.forEach(([re, w, m]) => { if (re.test(code)) { score += w; flags.push(m); } });
  return { score: clamp(score), flags };
}

module.exports = { scanPhishing, scanUrl, scanPassword, scanLogs, scanCode, level };
