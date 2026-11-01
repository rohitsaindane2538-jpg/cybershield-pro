# Architecture

```
Browser (vanilla JS, no inline scripts, strict CSP)
   |  cookie session, JSON + SSE
Express  server.js: helmet, request IDs, JSON logs, CSRF origin check, per-user rate limit, central error handler
   |-- routes/auth      scrypt + HMAC-signed cookie, login lockout
   |-- routes/analyze   text tools, file inspector, password
   |-- routes/ai        chat (stream), agent (SSE), report
   |-- routes/user      history, stats
   |
   |-- ai/analyze   rule pre-scan -> Claude JSON -> normalize/validate -> blend -> cache
   |-- ai/agent     tool-use loop (max 6 steps), offline fallback
   |-- ai/client    timeout, retry + backoff, SSE parsing
   |-- engines/     heuristics, ioc, file, mitre (pure functions, unit tested)
   |-- intel/       VirusTotal + AbuseIPDB lookups (validated inputs, fixed hosts, 8 s timeout, 1 h cache)
   `-- db/          async interface with two backends: JSON file (default) or PostgreSQL (DATABASE_URL)
```

## Key decisions
- **Hybrid detection.** Deterministic rules always run. They give instant results, an offline mode, and an anchor against AI error. The AI contributes reasoning and context; scores are blended 70/30.
- **Untrusted input handling.** User content is wrapped in `<untrusted_input>` tags with tag-breakout stripping, and the system prompt forbids following instructions inside it. The agent applies the same rule to tool output.
- **Output validation.** Every AI response is normalized: enums checked, scores clamped, text truncated, MITRE IDs validated against a local table so hallucinated IDs never reach the UI.
- **Privacy by design.** Passwords never leave the server process; the AI sees only entropy and length metrics. Files are analyzed in memory and not stored. IOCs are defanged in the UI.
- **Reliability.** 45 s timeout, 2 retries with exponential backoff honoring `retry-after`, graceful degradation to rule-engine results, 1 hour LRU cache of AI verdicts to cut cost and latency.
- **Observability.** One JSON log line per API request with request ID, `/metrics` counters (AI calls, errors, cache hits, average latency), `/healthz` for orchestrators.
- **Security controls.** HttpOnly + SameSite=Strict cookie (Secure in production), CSP without inline scripts, same-origin check on writes, scrypt hashing with timing-safe compare, login lockout, body size caps.

## Known limits and next steps
- The JSON store suits one server instance; use PostgreSQL for anything shared or deployed. The PostgreSQL backend is written against the same interface but is not covered by automated tests yet (add an integration test using the docker-compose database).
- Free intel API tiers are rate limited; rate-limit responses are shown as unavailable rather than failing the scan.
- No email verification or password reset; add before any public deployment.

## Threat intelligence safety
Indicators are validated (IPv4, domain, hash, http(s) URL) before use, requests go only to two fixed hosts, URL identifiers are base64url encoded, and the agent is told never to guess when a lookup is unavailable.
