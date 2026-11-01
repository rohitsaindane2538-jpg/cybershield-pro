const c = {}, obs = {};
module.exports = {
  inc: (k, n = 1) => { c[k] = (c[k] || 0) + n; },
  observe: (k, v) => { const o = obs[k] || (obs[k] = { sum: 0, count: 0 }); o.sum += v; o.count++; },
  snapshot: () => ({ counters: { ...c }, averages: Object.fromEntries(Object.entries(obs).map(([k, o]) => [k, Math.round(o.sum / o.count)])), uptime_s: Math.round(process.uptime()) })
};
