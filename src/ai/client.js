// Anthropic Messages API client: timeouts, retry with backoff, SSE streaming, JSON helper.
const cfg = require('../config'), metrics = require('../metrics'), log = require('../logger');
const URL_ = 'https://api.anthropic.com/v1/messages';
const RETRY = new Set([408, 429, 500, 502, 503, 529]);
const sleep = ms => new Promise(r => setTimeout(r, ms));

async function send(body, { timeoutMs = 45000, retries = 2 } = {}) {
  for (let attempt = 0; ; attempt++) {
    const ctrl = new AbortController(), timer = setTimeout(() => ctrl.abort(), timeoutMs), t0 = Date.now();
    try {
      const res = await fetch(URL_, {
        method: 'POST', signal: ctrl.signal,
        headers: { 'content-type': 'application/json', 'x-api-key': cfg.apiKey, 'anthropic-version': '2023-06-01' },
        body: JSON.stringify({ model: cfg.model, ...body })
      });
      clearTimeout(timer);
      if (res.ok) { metrics.inc('ai_calls'); metrics.observe('ai_latency_ms', Date.now() - t0); return res; }
      if (RETRY.has(res.status) && attempt < retries) {
        const wait = Math.min((Number(res.headers.get('retry-after')) * 1000) || 500 * 2 ** attempt, 8000);
        log.warn('ai_retry', { status: res.status, attempt, wait }); await sleep(wait); continue;
      }
      const err = new Error(`Anthropic API ${res.status}`); err.status = res.status; err.detail = (await res.text()).slice(0, 300); throw err;
    } catch (e) {
      clearTimeout(timer);
      if (e.status) { metrics.inc('ai_errors'); throw e; }
      if (attempt < retries) { await sleep(500 * 2 ** attempt); continue; }
      metrics.inc('ai_errors'); throw e.name === 'AbortError' ? new Error('AI request timed out') : e;
    }
  }
}
const complete = async body => (await send(body)).json();
const textOf = data => data.content.filter(b => b.type === 'text').map(b => b.text).join('\n');

function parseJSON(text) {
  const clean = String(text).replace(/```json|```/g, '').trim();
  const s = clean.indexOf('{'), e = clean.lastIndexOf('}');
  if (s < 0 || e < s) throw new Error('Model returned no JSON');
  return JSON.parse(clean.slice(s, e + 1));
}
async function completeJSON(system, user, max_tokens = 1500) {
  const data = await complete({ system: system + '\nRespond with ONLY one valid JSON object. No prose, no markdown fences.', messages: [{ role: 'user', content: user }], max_tokens });
  return parseJSON(textOf(data));
}
async function* streamText(body) {
  const res = await send({ ...body, stream: true }); const dec = new TextDecoder(); let buf = '';
  for await (const chunk of res.body) {
    buf += dec.decode(chunk, { stream: true }); let i;
    while ((i = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, i).trim(); buf = buf.slice(i + 1);
      if (!line.startsWith('data:')) continue;
      try { const ev = JSON.parse(line.slice(5)); if (ev.type === 'content_block_delta' && ev.delta?.type === 'text_delta') yield ev.delta.text; } catch { /* partial frame */ }
    }
  }
}
module.exports = { complete, completeJSON, streamText, textOf, parseJSON };
