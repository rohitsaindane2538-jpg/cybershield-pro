const $ = (s, r = document) => r.querySelector(s), $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const defang = s => String(s).replace(/\./g, '[.]').replace(/^http/i, 'hxxp');
const color = l => (l === 'Low' ? '#22e3c4' : l === 'Medium' ? '#ffb547' : '#ff4d8d');
let authMode = 'login';

// ---------- API layer ----------
async function api(url, opts = {}) {
  const r = await fetch(url, { ...opts, headers: { 'content-type': 'application/json' } });
  if (r.status === 401 && !url.includes('/auth/')) { showAuth(); throw new Error('Please sign in.'); }
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || 'Request failed');
  return j;
}
const post = (url, body) => api(url, { method: 'POST', body: JSON.stringify(body) });
async function stream(url, body, onEvent) {
  const r = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  if (r.status === 401) { showAuth(); throw new Error('Please sign in.'); }
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || 'Request failed');
  const rd = r.body.getReader(), dec = new TextDecoder(); let buf = '';
  for (;;) {
    const { done, value } = await rd.read(); if (done) break;
    buf += dec.decode(value, { stream: true }); let i;
    while ((i = buf.indexOf('\n\n')) >= 0) {
      const line = buf.slice(0, i).split('\n').find(l => l.startsWith('data:')); buf = buf.slice(i + 2);
      if (line) { try { onEvent(JSON.parse(line.slice(5))); } catch { /* ignore bad frame */ } }
    }
  }
}

// ---------- Auth ----------
function showAuth() { $('#auth').classList.add('show'); $('#au').focus(); }
function setAuthMode(m) {
  authMode = m; const reg = m === 'register';
  $('#authTitle').textContent = reg ? 'Create account' : 'Sign in'; $('#authGo').textContent = reg ? 'Create account' : 'Sign in';
  $('#authSw').textContent = reg ? 'I already have an account' : 'Create an account instead';
  $('#ap').autocomplete = reg ? 'new-password' : 'current-password'; $('#authErr').textContent = '';
}
$('#authSw').addEventListener('click', () => setAuthMode(authMode === 'login' ? 'register' : 'login'));
$('#authForm').addEventListener('submit', async e => {
  e.preventDefault();
  try { const u = await post('/api/auth/' + authMode, { username: $('#au').value, password: $('#ap').value }); $('#ap').value = ''; $('#auth').classList.remove('show'); boot(u.username); }
  catch (err) { $('#authErr').textContent = err.message; }
});
$('#logout').addEventListener('click', async () => { await post('/api/auth/logout', {}); location.reload(); });

// ---------- Navigation ----------
$$('.tab').forEach(b => b.addEventListener('click', () => {
  $$('.tab').forEach(x => x.classList.toggle('on', x === b));
  $$('.view').forEach(v => v.classList.toggle('on', v.id === b.dataset.tab));
  if (b.dataset.tab === 'dash') loadDash();
}));

// ---------- Rendering ----------
function gauge(score, level) {
  const R = 78, C = 2 * Math.PI * R, off = C * (1 - score / 100), col = color(level);
  return `<div class="gauge"><svg width="180" height="180" viewBox="0 0 180 180" role="img" aria-label="Risk ${score} of 100"><circle cx="90" cy="90" r="${R}" fill="none" stroke="rgba(255,255,255,.1)" stroke-width="12"/>
  <circle class="arc" cx="90" cy="90" r="${R}" fill="none" stroke="${col}" style="color:${col}" stroke-width="12" stroke-linecap="round" stroke-dasharray="${C}" stroke-dashoffset="${C}" data-off="${off}"/></svg>
  <div class="n"><b>${score}</b><span>${esc(level)} risk</span></div></div>`;
}
const animate = root => requestAnimationFrame(() => requestAnimationFrame(() => $$('.arc', root).forEach(a => a.style.strokeDashoffset = a.dataset.off)));
const chips = (arr, cls = '') => arr.map(x => `<span class="chip ${cls}">${esc(x)}</span>`).join('');

function iocBlock(i) {
  if (!i) return '';
  const groups = [['Public IPs', i.ips.map(defang)], ['Domains', i.domains.map(defang)], ['URLs', i.urls.map(defang)], ['Emails', i.emails.map(defang)], ['Hashes', i.hashes.map(h => `${h.type}: ${h.value}`)], ['CVEs', i.cves]];
  const html = groups.filter(([, a]) => a.length).map(([t, a]) => `<div class="sub">${t}</div><div class="chips">${chips(a)}</div>`).join('');
  return html ? `<h2 style="margin-top:16px">Indicators found</h2><p class="muted" style="margin:2px 0 0;font-size:12px">Defanged so they are safe to copy and share.</p>${html}` : '';
}
function fileBlock(f) {
  if (!f) return '';
  return `<dl class="kv"><dt>Name</dt><dd>${esc(f.name)}</dd><dt>Type</dt><dd>${esc(f.type)}</dd><dt>Size</dt><dd>${f.size} bytes</dd><dt>Entropy</dt><dd>${f.entropy} / 8</dd><dt>SHA-256</dt><dd>${esc(f.sha256)}</dd><dt>MD5</dt><dd>${esc(f.md5)}</dd></dl>`;
}
function intelBlock(i) {
  if (!i) return '';
  const rows = i.results.map(x => `<div class="find ${x.available ? (x.malicious >= 3 || x.abuseScore >= 75 ? 'Critical' : x.malicious >= 1 || x.abuseScore >= 25 ? 'Medium' : 'Low') : 'Medium'}"><b>${esc(x.source)}</b><span>${esc(x.summary)}</span></div>`).join('');
  return `<h2 style="margin-top:16px">Threat intelligence: ${esc(i.verdict)}</h2>${rows}`;
}
function renderResult(r) {
  const finds = (r.findings || []).map(f => `<div class="find ${esc(f.severity)}"><b>${esc(f.title)} <span class="pill ${esc(f.severity)}">${esc(f.severity)}</span></b><span>${esc(f.detail)}</span></div>`).join('') || '<p class="muted">No findings.</p>';
  const acts = (r.recommended_actions || []).map(a => `<li>${esc(a)}</li>`).join('');
  const mit = (r.mitre || []).length ? `<div class="sub">MITRE ATT&amp;CK</div><div class="chips">${(r.mitre).map(m => `<span class="chip t">${esc(m.id)} ${esc(m.name)}</span>`).join('')}</div>` : '';
  return `<div class="glass result">${gauge(r.risk_score, r.level)}<div>
  <div class="verdict"><h2>${esc(r.verdict)}</h2><span class="pill ${esc(r.level)}">${esc(r.level)}</span><span class="muted" style="margin:0;font-size:13px">${esc(r.confidence)}% confidence</span></div>
  <p>${esc(r.summary)}</p>${fileBlock(r.file)}${finds}${intelBlock(r.intel)}${mit}${acts ? `<h2 style="margin-top:14px">What to do</h2><ul class="acts">${acts}</ul>` : ''}${iocBlock(r.iocs)}
  <div class="engine">Engine: ${esc(r.engine)}${r.cached ? ' (cached)' : ''}${r.degraded ? ' (AI unavailable)' : ''}</div></div></div>`;
}
// Minimal safe markdown: escape first, then format headings, bold and bullets.
function md(t) {
  return esc(t).replace(/^## (.+)$/gm, '<h3>$1</h3>').replace(/^# (.+)$/gm, '<h3>$1</h3>').replace(/\*\*(.+?)\*\*/g, '<b>$1</b>')
    .replace(/^(?:- |\* )(.+)$/gm, '<li>$1</li>').replace(/(<li>.*<\/li>\n?)+/g, m => `<ul class="acts">${m}</ul>`).replace(/\n{2,}/g, '<br>');
}

// ---------- Scan tools ----------
$$('.tool').forEach(sec => {
  const input = $('textarea, input', sec), out = $('.out', sec), go = $('.go', sec);
  $$('.sample', sec).forEach(s => s.addEventListener('click', () => { input.value = s.dataset.s; }));
  go.addEventListener('click', async () => {
    if (!input.value.trim()) { out.innerHTML = '<p class="err">Enter something to scan first.</p>'; return; }
    go.disabled = true; const old = go.textContent; go.textContent = 'Analyzing…';
    try { out.innerHTML = renderResult(await post(sec.dataset.api, { [sec.dataset.key]: input.value })); animate(out); }
    catch (e) { out.innerHTML = `<p class="err">${esc(e.message)}</p>`; }
    go.disabled = false; go.textContent = old;
  });
});

// ---------- File inspector ----------
async function inspectFile(file) {
  const out = $('#fileOut');
  if (!file) return;
  if (file.size > 1.5e6) { out.innerHTML = '<p class="err">File is larger than 1.5 MB.</p>'; return; }
  out.innerHTML = '<p class="muted">Analyzing…</p>';
  const data = await new Promise((res, rej) => { const r = new FileReader(); r.onload = () => res(String(r.result).split(',')[1] || ''); r.onerror = () => rej(new Error('Could not read file')); r.readAsDataURL(file); });
  try { out.innerHTML = renderResult(await post('/api/analyze/file', { name: file.name, data })); animate(out); }
  catch (e) { out.innerHTML = `<p class="err">${esc(e.message)}</p>`; }
}
$('#fileIn').addEventListener('change', e => inspectFile(e.target.files[0]));
const drop = $('#drop');
['dragover', 'dragenter'].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.add('over'); }));
['dragleave', 'drop'].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.remove('over'); }));
drop.addEventListener('drop', e => inspectFile(e.dataTransfer.files[0]));

// ---------- Threat intel ----------
$('#intelSample').addEventListener('click', () => { $('#intelIn').value = '8.8.8.8'; });
$('#intelGo').addEventListener('click', async () => {
  const v = $('#intelIn').value.trim(), out = $('#intelOut'), b = $('#intelGo'); if (!v) return;
  b.disabled = true; b.textContent = 'Looking up…';
  try {
    const r = await post('/api/intel', { indicator: v });
    const note = r.keysConfigured ? '' : '<p class="muted">No intel API keys are set. Add VIRUSTOTAL_API_KEY and ABUSEIPDB_API_KEY to .env to get live results.</p>';
    out.innerHTML = `<div class="glass pad"><div class="verdict"><h2>${esc(r.verdict)}</h2><span class="pill ${esc(r.level)}">${esc(r.type)}</span></div><p class="muted" style="word-break:break-all">${esc(r.indicator)}</p>${intelBlock({ ...r, verdict: r.verdict })}${note}</div>`;
  } catch (e) { out.innerHTML = `<p class="err">${esc(e.message)}</p>`; }
  b.disabled = false; b.textContent = 'Look up';
});

// ---------- Password lab ----------
$('#pwGo').addEventListener('click', async () => {
  const pw = $('#pw').value, out = $('#pwOut'); if (!pw) return;
  try {
    const r = await post('/api/password', { password: pw }), lvl = r.level === 'Low' ? 'Strong' : r.level === 'Medium' ? 'Fair' : 'Weak';
    out.innerHTML = `<div class="glass result">${gauge(r.risk_score, r.level)}<div><div class="verdict"><h2>${lvl} password</h2></div>
    <p>About ${r.bits} bits of entropy. An offline attacker could crack it in <b>${esc(r.crackTime)}</b>.</p>${r.flags.map(f => `<div class="find"><b>${esc(f)}</b></div>`).join('')}
    ${r.tips.length ? `<h2 style="margin-top:14px">Coach tips</h2><ul class="acts">${r.tips.map(t => `<li>${esc(t)}</li>`).join('')}</ul>` : ''}${r.passphrase_idea ? `<p class="muted">${esc(r.passphrase_idea)}</p>` : ''}
    <div class="engine">Engine: ${esc(r.engine)}</div></div></div>`;
    animate(out); $('#pw').value = '';
  } catch (e) { out.innerHTML = `<p class="err">${esc(e.message)}</p>`; }
});

// ---------- SOC agent ----------
$('#agentSample').addEventListener('click', () => { $('#agentIn').value = `A finance employee received this email and says they clicked the link:\n\nSubject: URGENT invoice 4471\nDear customer, verify your payment details immediately at http://185.220.101.4/pay or your account will be suspended. Questions: billing@secure-paypal-help.xyz\n\nOur VPN logs show repeated failed logins for "admin" from 203.0.113.9 around the same time.`; });
$('#agentGo').addEventListener('click', async () => {
  const task = $('#agentIn').value.trim(), steps = $('#steps'), brief = $('#brief'), btn = $('#agentGo');
  if (!task) { brief.innerHTML = '<p class="err">Describe the case first.</p>'; return; }
  steps.innerHTML = ''; brief.innerHTML = ''; btn.disabled = true; btn.textContent = 'Investigating…';
  const addStep = (html) => { const d = document.createElement('div'); d.className = 'step'; d.innerHTML = html; steps.appendChild(d); return d; };
  try {
    await stream('/api/agent', { task }, ev => {
      if (ev.type === 'tool') addStep(`Running <b>${esc(ev.name)}</b> <span>${esc(Object.values(ev.input || {}).filter(Boolean).join(', '))}</span>`);
      else if (ev.type === 'result') { const last = steps.lastElementChild; if (last) last.innerHTML += `<br><span>Result: ${esc(ev.summary)}</span>`; }
      else if (ev.type === 'text') { if (ev.final) brief.innerHTML = `<div class="glass brief">${md(ev.text)}</div>`; else addStep(`<span>${esc(ev.text)}</span>`); }
      else if (ev.type === 'error') brief.innerHTML = `<p class="err">${esc(ev.error)}</p>`;
    });
  } catch (e) { brief.innerHTML = `<p class="err">${esc(e.message)}</p>`; }
  btn.disabled = false; btn.textContent = 'Investigate';
});

// ---------- Dashboard & report ----------
let reportMd = '';
async function loadDash() {
  try {
    const [s, h] = await Promise.all([api('/api/stats'), api('/api/history')]);
    $('#sTotal').textContent = s.total; $('#sThreat').textContent = s.threats; $('#sMed').textContent = s.levels.Medium; $('#sLow').textContent = s.levels.Low;
    const max = Math.max(1, ...s.days.map(d => d.count));
    $('#days').innerHTML = s.days.map(d => `<div><span>${d.count}</span><i style="height:${Math.round(d.count / max * 70)}px"></i>${new Date(d.day + 'T00:00').toLocaleDateString(undefined, { weekday: 'short' })}</div>`).join('');
    $('#hist').innerHTML = h.length ? h.slice(0, 15).map(x => `<div class="hrow"><b>${esc(x.kind)}</b><code>${esc(x.preview)}</code><span class="pill ${esc(x.level)}">${esc(x.level)} ${esc(x.score)}</span><small>${new Date(x.at).toLocaleTimeString()}</small></div>`).join('')
      : '<p class="muted">No scans yet. Pick a tool on the left to run your first one.</p>';
  } catch { /* auth overlay handles 401 */ }
}
$('#clearHist').addEventListener('click', async () => { await api('/api/history', { method: 'DELETE' }); loadDash(); });
$('#repGo').addEventListener('click', async () => {
  const b = $('#repGo'), out = $('#repOut'); b.disabled = true; b.textContent = 'Writing…';
  try { const r = await post('/api/report', {}); reportMd = r.markdown; out.hidden = false; out.textContent = reportMd; $('#repDl').hidden = false; }
  catch (e) { out.hidden = false; out.innerHTML = `<span class="err">${esc(e.message)}</span>`; }
  b.disabled = false; b.textContent = 'Generate report';
});
$('#repDl').addEventListener('click', () => {
  const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([reportMd], { type: 'text/markdown' })); a.download = 'cybershield-report.md'; a.click(); URL.revokeObjectURL(a.href);
});

// ---------- Streaming chat ----------
const history = [];
const addMsg = (who, text) => { const d = document.createElement('div'); d.className = 'm ' + who; d.textContent = text; $('#msgs').appendChild(d); d.scrollIntoView({ block: 'end' }); return d; };
$('#chatForm').addEventListener('submit', async e => {
  e.preventDefault(); const inp = $('#chatIn'), text = inp.value.trim(); if (!text) return;
  inp.value = ''; addMsg('me', text); history.push({ role: 'user', content: text });
  const bot = addMsg('bot', '…'); let full = '';
  try { await stream('/api/chat', { messages: history.slice(-20) }, ev => { if (ev.type === 'delta') { full += ev.text; bot.textContent = full; bot.scrollIntoView({ block: 'end' }); } else if (ev.type === 'error') { bot.textContent = ev.error; bot.classList.add('err'); } }); history.push({ role: 'assistant', content: full }); }
  catch (err) { bot.textContent = err.message; bot.classList.add('err'); }
});

// ---------- Boot ----------
function boot(name) { $('#who').textContent = name; loadDash(); }
(async () => {
  fetch('/api/status').then(r => r.json()).then(s => { const el = $('#status'); el.className = 'status glass-in ' + (s.ai ? 'on' : 'off'); el.textContent = s.ai ? 'Claude AI connected' : 'Offline mode: add API key'; });
  try { boot((await api('/api/auth/me')).username); } catch { showAuth(); }
})();
