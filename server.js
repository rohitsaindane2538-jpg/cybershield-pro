const express = require('express'), helmet = require('helmet'), rateLimit = require('express-rate-limit'), crypto = require('crypto'), path = require('path');
const db = require('./src/db'), intel = require('./src/intel'), cfg = require('./src/config'), log = require('./src/logger'), metrics = require('./src/metrics');
require('./src/async-errors');
const { router: authRouter, requireAuth } = require('./src/routes/auth');

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', process.env.TRUST_PROXY ? 1 : false);
app.use(helmet({ contentSecurityPolicy: { directives: {
  defaultSrc: ["'self'"], styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'], fontSrc: ["'self'", 'https://fonts.gstatic.com'],
  scriptSrc: ["'self'"], connectSrc: ["'self'"], imgSrc: ["'self'", 'data:'], frameAncestors: ["'none'"] } } }));

// Request ID + structured access log + metrics
app.use((req, res, next) => {
  req.id = crypto.randomBytes(6).toString('hex'); res.setHeader('X-Request-Id', req.id); const t0 = Date.now();
  res.on('finish', () => { metrics.inc('http_requests'); if (req.path.startsWith('/api')) log.info('http', { id: req.id, method: req.method, path: req.path, status: res.statusCode, ms: Date.now() - t0, user: req.user?.username }); });
  next();
});
app.use(express.json({ limit: '3mb' }));

// CSRF defense in depth: SameSite=Strict cookie + same-origin check on writes
app.use('/api', (req, res, next) => {
  if (req.method !== 'GET' && req.headers.origin && new URL(req.headers.origin).host !== req.headers.host) return res.status(403).json({ error: 'Cross-origin request blocked.' });
  next();
});
app.use(express.static(path.join(__dirname, 'public')));

app.get('/healthz', (_q, res) => res.json({ ok: true }));
app.get('/metrics', (_q, res) => res.json(metrics.snapshot()));
app.get('/api/status', (_q, res) => res.json({ ai: cfg.aiEnabled, model: cfg.model, intel: intel.enabled(), db: db.kind }));

app.use('/api/auth', rateLimit({ windowMs: 60e3, max: 20, standardHeaders: true, legacyHeaders: false }), authRouter);
const perUser = rateLimit({ windowMs: 60e3, max: 30, keyGenerator: req => req.user.id, standardHeaders: true, legacyHeaders: false, message: { error: 'Rate limit reached. Wait a minute.' } });
app.use('/api', requireAuth, perUser, require('./src/routes/analyze'), require('./src/routes/ai'), require('./src/routes/user'));

app.use('/api', (_q, res) => res.status(404).json({ error: 'Not found.' }));
app.use((err, req, res, _next) => { // central error handler: never leak internals
  log.error('unhandled', { id: req.id, error: err.message });
  res.status(err.type === 'entity.too.large' ? 413 : 500).json({ error: err.type === 'entity.too.large' ? 'Payload too large.' : 'Internal error.', requestId: req.id });
});
process.on('unhandledRejection', e => log.error('unhandled_rejection', { error: String(e) }));

db.init().then(() => {
  const server = app.listen(cfg.port, () => log.info('listening', { url: `http://localhost:${cfg.port}`, ai: cfg.aiEnabled ? 'ON' : 'OFF (offline mode)', model: cfg.model, db: db.kind, intel: intel.enabled() }));
  for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => { log.info('shutdown', { sig }); server.close(() => process.exit(0)); });
}).catch(e => { log.error('startup_failed', { error: e.message }); process.exit(1); });
