# Polyglot Security Orchestrator

A full-stack security audit tool that scans **GitHub repositories** for code issues, secrets, and vulnerable dependencies. You provide a repo URL and an API key; the app clones the repo, runs SAST (Semgrep), secret detection (Gitleaks), and dependency checks (npm/pip-audit), then returns a single report with findings and remediation.

**Built for:** Developers and security engineers who want a single dashboard to assess repository security. Suitable as a portfolio project demonstrating Java/Spring Boot, Vue, and integration of multiple security tools.

---

## What it does

| Capability | Description |
|------------|-------------|
| **Clone** | Clones the target public GitHub repo into a sandboxed directory. |
| **SAST** | Runs **Semgrep** (Docker or local) for static analysis across Java, JavaScript, Python, Bash, and more. |
| **Secrets** | Runs **Gitleaks** to detect API keys, passwords, and tokens. |
| **SCA** | Runs **npm audit** and **pip-audit** where `package.json` or `requirements.txt` exist. |
| **Report** | Produces a vulnerability score, affected files, and remediation steps. All tool outputs are normalized into a structured report and audit trail in the UI. |

The backend uses a ReAct-style workflow (think → act → observe) to orchestrate these steps; the Vue dashboard lets you run audits and inspect results.

---

## Tech stack

- **Backend:** Java 17+, Spring Boot 3.4, LangChain4j  
- **Frontend:** Vue 3, Vite, Tailwind CSS  
- **Tools:** Semgrep, Gitleaks, npm audit, pip-audit (via CLI or Docker)

---

## Requirements

- **JDK 17+**
- **Semgrep:** Docker (recommended), or [bundled binary](#semgrep-setup), or `pip install semgrep`
- **Gitleaks:** Docker (recommended; image `zricethezav/gitleaks:latest`) or [Gitleaks](https://github.com/gitleaks/gitleaks) on PATH
- **SCA:** npm and/or pip-audit when scanning Node/Python repos
- **API key:** OpenAI-compatible key for the orchestrator (sent per request via `X-API-Key`; not stored server-side)

---

## Semgrep setup

If you don’t use Docker, the app looks for Semgrep in this order:

1. **Docker** — `semgrep.docker.enabled: true` (default). Uses `semgrep/semgrep:latest`.
2. **Bundled** — Binary under `tools/semgrep` (see below).
3. **Local** — `semgrep.command` (e.g. `semgrep` or `python -m semgrep`).

**Bundled binary (one-time):**

Windows (PowerShell):

```powershell
.\scripts\setup-semgrep.ps1
```

Linux / macOS:

```bash
chmod +x scripts/setup-semgrep.sh
./scripts/setup-semgrep.sh
```

Or install Semgrep yourself ([semgrep.dev](https://semgrep.dev)); set `semgrep.command` if needed.

---

## Build and run

**Backend** (from repo root):

```bash
mvn spring-boot:run
```

**Frontend:**

```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:5173. Add your API key in **Settings**, then run an audit from the **Dashboard**. The dev server proxies `/api` to the backend (port 8080).

**Docker (backend only):**

```bash
mvn package -DskipTests
docker-compose up --build
```

Backend runs at http://localhost:8080. Run the frontend locally (`cd frontend && npm run dev`) and set `VITE_API_BASE=http://localhost:8080` if the backend is in Docker. **Do not** hardcode or pre-configure the API key: after the app is running, open the dashboard and add your API key in **Settings**; it is sent only in the request header and is never stored on the server.

---

## API

**POST /v1/audit**

- **Header:** `X-API-Key: <your-api-key>`
- **Body:** `{ "target": "https://github.com/org/repo" }` (GitHub repo URL only; strict `https://github.com/org/repo` or `.git` form)
- **Response:** `report` (vulnerabilityScore, affectedFiles, remediationSteps) and `auditSteps` (tool runs with optional `findings`).
- **Errors:** `401` / `400` / `429` return JSON `{ "error": "...", "code": "MISSING_API_KEY" | "MISSING_TARGET" | "INVALID_TARGET" | "RATE_LIMITED" }`.

---

## Tests

- **Backend:** `mvn test`
- **Frontend:** `cd frontend && npm run test` (Vitest; use `npm run test:watch` for watch mode)

---

## Configuration

| Property | Description |
|----------|-------------|
| `security.sandbox.base-path` | Sandbox for clones and scans (default: `/tmp/security-sandbox`) |
| `audit.rate-limit.max-per-minute` | Max audit requests per IP per window (default: `10`) |
| `audit.rate-limit.window-seconds` | Rate limit window in seconds (default: `60`) |
| `audit.clone-timeout-seconds` | Git clone timeout (default: `300`; min 60, max 600) |
| `semgrep.docker.enabled` | Use Docker for Semgrep (default: `true`) |
| `semgrep.docker.image` | Semgrep image (default: `semgrep/semgrep:latest`) |
| `semgrep.bundled-dir` | Dir for bundled Semgrep binary (default: `tools/semgrep`) |
| `semgrep.command` | Local Semgrep command when not using Docker/bundled |
| `gitleaks.docker.enabled` / `gitleaks.docker.image` | Gitleaks via Docker (default: `zricethezav/gitleaks:latest`) |
| `langchain4j.open-ai.chat-model.model-name` | Model for orchestration (default: `gpt-4o-mini`) |
| `cors.allowed-origins` | Allowed origins for the dashboard |
