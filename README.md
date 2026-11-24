# Bastion v2.1 — Pre-Ship Security & Anti-AI-Reverse-Engineering Release Gate

Bastion v2.1 is a production-hardened, local-first DevSecOps web application and CLI orchestrator that enforces a sequential 3-stage security and anti-reverse-engineering release gate against any local Git repository or build directory.

## What Is New in v2.1.0 (Production Hardening)

1. **Encrypted Secret Vault for BYOK API Keys (`vault.py`, `llm_providers.py`, `SettingsDrawer.tsx`):**
   - Zero plaintext API keys in SQLite (`data/bastion.db`). All persisted provider keys are encrypted with authenticated Fernet (`enc:fernet:v1:`) using a host-local master key outside the project at `~/.bastion/keys/vault.key` (`0600` on POSIX, current-user ACL on Windows).
   - Automatic startup migration encrypts any legacy plaintext entries and checkpoints/vacuums SQLite.
   - Strict environment variable precedence (`GEMINI_API_KEY`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `OLLAMA_BASE_URL`) overrides stored vault entries so CI/CD runners never touch local disk secrets.
   - `GET /api/settings/llm` returns only `configured`, `source` (`env` | `vault` | `none`), and `masked_key` (`sk-••••4f2a`). All loaded API keys are scrubbed from SSE log streams, exception tracebacks, and exported compliance certificates.

2. **Git-Diff Scoping, Token/Cost Budgeting & Live LLM Resilience (`gate2_cloudflare.py`, `cli.py`, `OverviewView.tsx`):**
   - Supports `diff` (default for PR/CI: changed files from `git diff --name-only <base>...HEAD` + local staged/untracked files + direct 1-hop local imports) and `full` repository scope modes.
   - Pre-flight token estimation and per-run budget caps (default `$1.50` / `120,000` input tokens). High-risk paths (auth, middleware, API routes, SQL/ORM, crypto, shell/subprocess handlers) are prioritized first; deferred or out-of-scope files are cleanly recorded in Cloudflare's `coverage-ledger.json` rather than crashing or overspending.
   - Hardened live LLM JSON extraction strips markdown fences/comments/trailing commas, performs a 1-shot strict schema-repair retry on malformed responses, and guarantees outputs validate against Cloudflare's `validate-findings.cjs` and `validate-coverage-ledger.cjs`.

3. **Post-BLA Smoke Verification Hook (`gate3_bla.py`, `ArtifactShieldView.tsx`, `cli.py`):**
   - Optional per-project `smoke_test_cmd` (or `--smoke-cmd "<cmd>"` on CLI) runs against the `.bla-hardened/` build inside an isolated working copy with sensitive environment variables stripped and a configurable timeout.
   - Failing smoke checks block Gate 3 (exit code `30`) and display an explicit warning guard before `--apply` promotion.

4. **Production `Dockerfile.cli` & Runnable GitHub Actions Workflow (`Dockerfile.cli`, `cicd.py`, `CicdModal.tsx`):**
   - Multi-stage, non-root `Dockerfile.cli` (UID `10001`) bundles Python 3.11 + `bastion` CLI, Node.js 22 LTS (`bla-agents` + Cloudflare validators), and MIT-licensed `gitleaks` as the default AGPL-clean Gate 1 scanner (`INSTALL_TRUFFLEHOG=false` by default).
   - **CI/CD Setup** exports dual-mode runnable `.github/workflows/bastion-gate.yml` templates (**Published Container** or **Self-Built `./Dockerfile.cli`**) with SARIF Code Scanning upload, Ed25519 certificate + public key artifact upload, and PR gating on exit codes `10`/`20`/`30`.

## Quick Start

### 1. Start Backend & Frontend

**Backend (port 8000):**
```powershell
cd backend
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

**Frontend (port 3000):**
```powershell
cd frontend
npm.cmd run dev
```

Open `http://localhost:3000`.

### 2. CLI Commands

```powershell
# Check installed external plugins, Cloudflare validators, vault status, and Ed25519 signing key fingerprint
.\backend\.venv\Scripts\bastion.exe doctor

# Run 3-stage release gate with diff scoping, budget cap, and post-BLA smoke verification (exit codes 0/10/20/30)
.\backend\.venv\Scripts\bastion.exe run .\sample-target --scanner auto --scope diff --base origin/main --max-budget-usd 1.50 --smoke-cmd "node dist/index.js" --sarif-out findings.sarif --cert-out release-cert.json

# Verify an Ed25519-signed Release Certificate for tampering or expiry
.\backend\.venv\Scripts\bastion.exe verify release-cert.json --pubkey "$env:USERPROFILE\.bastion\keys\ed25519_public.pem"

# Promote or roll back BLA hardened build outputs
.\backend\.venv\Scripts\bastion.exe bla-apply .\sample-target --intensity balanced
.\backend\.venv\Scripts\bastion.exe bla-restore .\sample-target
```

### 3. Production CLI Container (AGPL-Clean Default)

```bash
docker build -f Dockerfile.cli -t bastion-cli:2.1.0 .
docker run --rm -v "$(pwd):/workspace" -e GEMINI_API_KEY="$GEMINI_API_KEY" bastion-cli:2.1.0 run /workspace --scope diff --scanner gitleaks
```
