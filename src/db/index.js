const cfg = require('../config');
const backend = cfg.databaseUrl ? require('./pg') : require('./json');
module.exports = { kind: cfg.databaseUrl ? 'postgres' : 'json', init: backend.init, users: backend.users, scans: backend.scans, reset: backend.reset };
