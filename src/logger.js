// Structured JSON logs: easy to ship to any log pipeline.
const out = (level, msg, meta = {}) => console.log(JSON.stringify({ t: new Date().toISOString(), level, msg, ...meta }));
module.exports = { info: (m, x) => out('info', m, x), warn: (m, x) => out('warn', m, x), error: (m, x) => out('error', m, x) };
