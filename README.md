# CyberShield v2

AI-native security operations suite. Express backend, glassmorphism UI, Claude integration with an agentic investigator.

## Features
- **SOC agent**: Claude chooses tools (IOC extraction, URL/message/log scans, MITRE lookup, your scan history), gathers evidence in up to 6 steps, and writes an incident brief. Steps stream live to the UI. Works offline with a deterministic investigator.
- **Threat intel**: live VirusTotal and AbuseIPDB lookups for IPs, domains, URLs and file hashes. Available as its own tab, as agent tools, and automatically on uploaded files (a known-malicious hash raises the score to 90+).
- **Message scanner, link checker, log triage, code audit**: rule engine pre-scan + Claude structured analysis, blended 30/70, with confidence, MITRE ATT&CK mapping and extracted indicators (defanged).
- **File inspector**: SHA-256/SHA-1/MD5, real type from magic bytes, entropy, suspicious strings, masquerading checks, then AI triage. Never executes or stores the file.
- **Password lab**: strength computed server-side; only numeric metrics reach the AI.
- **AI advisor**: streaming chat (SSE).
- **Dashboard + reports**: 7-day activity, history, AI-written executive report you can download as Markdown.
- **Accounts**: scrypt password hashing, signed HttpOnly SameSite=Strict session cookie, login lockout, per-user data and rate limits.

## Windows setup
1. Install Node.js LTS (18 or newer) from https://nodejs.org. Reopen the terminal, check `node -v`.
2. Unzip, then in PowerShell: `cd cybershield-pro`
3. `npm install`
4. `npm test` (should show 17 passing)
5. `copy .env.example .env`, open `.env` in Notepad, paste your key after `ANTHROPIC_API_KEY=` (https://console.anthropic.com). Blank = offline mode.
6. `npm start`, then open http://localhost:3000 and create an account.

Free intel keys: sign up at virustotal.com (API key under your profile, about 4 lookups/minute) and abuseipdb.com (free tier has a daily limit). Both are optional.

PostgreSQL (optional): set `DATABASE_URL` in `.env` and tables are created on startup. Easiest local setup: `docker compose up --build` runs the app and a Postgres container together.

Docker alternative: `docker build -t cybershield .` then `docker run -p 3000:3000 --env-file .env cybershield`

## Configuration (.env)
| Variable | Purpose | Default |
|---|---|---|
| ANTHROPIC_API_KEY | Enables AI features | blank (offline) |
| CLAUDE_MODEL | Model name | claude-sonnet-4-6 |
| PORT | Server port | 3000 |
| VIRUSTOTAL_API_KEY | Live file, URL, domain and IP reputation | blank (intel off) |
| ABUSEIPDB_API_KEY | Live IP abuse reports | blank |
| DATABASE_URL | PostgreSQL connection string | blank (local JSON store) |
| SESSION_SECRET | Cookie signing key | auto-generated in data/.secret |

## API (all except auth/status need a session cookie)
| Method | Path | Purpose |
|---|---|---|
| POST | /api/auth/register, /login, /logout; GET /me | Accounts |
| POST | /api/analyze/{phishing,url,logs,code,file} | Hybrid analysis |
| POST | /api/intel | Threat-intel lookup (IP, domain, URL, hash) |
| POST | /api/password | Strength + coaching |
| POST | /api/agent (SSE) | Agentic investigation |
| POST | /api/chat (SSE) | Streaming advisor |
| POST | /api/report | Executive report (Markdown) |
| GET/DELETE | /api/history; GET /api/stats | User data |
| GET | /healthz, /metrics, /api/status | Ops |

See docs/ARCHITECTURE.md for design decisions.

## Deploy free on Render
1. Push this folder to a GitHub repository (do not commit `.env`).
2. On https://render.com choose New > Blueprint, pick your repository. `render.yaml` creates the web service and a PostgreSQL database and wires `DATABASE_URL` for you.
3. When asked, paste `ANTHROPIC_API_KEY` (and optionally `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`).
4. Open the `.onrender.com` URL once the deploy finishes. Check `/healthz` returns `{"ok":true}`.

Free-tier limits (sleeping services, database expiry) change over time, so check Render's pricing page before your demo. Open the site a few minutes early so the service is awake.
