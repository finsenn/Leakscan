# Leakscan — Repo Secret Scanner

Scans a public GitHub repository for leaked credentials — API keys, tokens,
private keys, connection strings — across committed files and git history, and
reports them masked. Clones are deleted as soon as the scan finishes.

- **`scan.py`** — the original CLI, scans a local folder before you push.
- **`backend/`** — FastAPI service wrapping the same engine.
- **`frontend/`** — Next.js UI.

## Detection

Two passes, each finding rated **high**, **medium**, or **low** confidence:

1. **Regex** (`backend/patterns.py`) — ~75 known credential formats. A
   provider-specific shape like `AKIA…` rates high; the generic keyword rules
   (`password = "…"`) rate medium. Card numbers are Luhn-validated and
   published test numbers are filtered out.
2. **Entropy** (`backend/entropy.py`) — Shannon entropy over whatever the regex
   pass did not claim, catching custom formats no pattern list covers. Rated
   low: a broad net that needs review. Thresholds are tunable in
   `EntropyConfig`, or via `LEAKSCAN_ENTROPY_*` environment variables.

## Local development

Backend (http://localhost:8000, docs at `/docs`):

```bash
cd backend && pip install -r requirements.txt && uvicorn main:app --reload
```

Frontend (http://localhost:3000):

```bash
cd frontend && npm install && npm run dev
```

Tests:

```bash
cd backend && python -m pytest
```

With `ALLOWED_ORIGINS` unset the API accepts requests from any localhost port,
so the frontend works regardless of which port `next dev` picks.

## Deployment

Deploy the **backend first**. `NEXT_PUBLIC_API_URL` is inlined into the
frontend bundle at *build* time, so the API URL must exist before Vercel
builds — otherwise the deployed site calls `localhost:8000` and needs a
redeploy to fix.

### 1. Backend → Render

Render Dashboard → **New** → **Blueprint** → select this repo. `render.yaml`
supplies the runtime, build and start commands, and health check. Note the
service URL it assigns (e.g. `https://leakscan-api.onrender.com`).

Free instances sleep when idle, so the first scan after a quiet period pays a
cold start of roughly 30–60 seconds.

### 2. Frontend → Vercel

Import the repo, then set:

| Setting | Value |
| --- | --- |
| Root Directory | `frontend` |
| `NEXT_PUBLIC_API_URL` | the Render URL from step 1, no trailing slash |

Root Directory must be set in the Vercel dashboard — it cannot be configured
from a file at the repo root.

### 3. Connect them

Back in Render, set `ALLOWED_ORIGINS` to the Vercel domain
(`https://your-app.vercel.app`) and redeploy.

This step is required. Unset, the API allows localhost only and the deployed
frontend fails with a CORS error. That is deliberate — an unconfigured
deployment fails closed rather than serving every origin on the internet. To
allow preview deployments too, pass a comma-separated list.

## Safety constraints

- Only public `github.com` repositories; the URL is validated before anything
  is cloned, and the repo is confirmed public and under 100 MB via the GitHub
  API first.
- Shallow clone (depth 50) with a 90-second timeout.
- Clones are removed in a `finally` block, and any orphaned by a killed process
  are swept on the next startup.
- Secrets are masked by the engine. Full secret values and scanned source code
  are never logged, stored, or returned.
