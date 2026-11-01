// Express 4 ignores rejected promises from async handlers. This forwards them to the central error handler.
const Layer = require('express/lib/router/layer');
Layer.prototype.handle_request = function handle(req, res, next) {
  const fn = this.handle;
  if (fn.length > 3) return next();
  try { const p = fn(req, res, next); if (p && typeof p.catch === 'function') p.catch(next); } catch (err) { next(err); }
};
