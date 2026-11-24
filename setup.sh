#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "==> Bastion Local-First DevSecOps Setup (macOS / Linux)"

# 1. TruffleHog
if ! command -v trufflehog >/dev/null 2>&1; then
  echo "[1/5] Installing TruffleHog..."
  mkdir -p "$HOME/.local/bin"
  curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b "$HOME/.local/bin"
  export PATH="$HOME/.local/bin:$PATH"
fi
echo "    TruffleHog ready: $(trufflehog --version 2>&1 || true)"

# 2. BLA (qybaihe/bla)
echo "[2/5] Installing BLA (bla-agents) globally via npm..."
npm install -g bla-agents
echo "    BLA ready: $(bla --version 2>&1 || true)"

# 3. Cloudflare Security Audit Skill
echo "[3/5] Installing Cloudflare Security Audit Skill..."
VENDOR_SKILL="$ROOT_DIR/vendor/security-audit-skill"
if [ ! -d "$VENDOR_SKILL" ]; then
  mkdir -p "$ROOT_DIR/vendor"
  git clone --depth 1 https://github.com/cloudflare/security-audit-skill.git "$VENDOR_SKILL"
fi
npx --yes skills add https://github.com/cloudflare/security-audit-skill --skill security-audit -y || true

# 4. Python Backend & Bastion CLI
echo "[4/5] Configuring FastAPI backend virtual environment..."
cd "$ROOT_DIR/backend"
if [ ! -d ".venv" ]; then
  python3 -m venv .venv
fi
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -r requirements.txt
.venv/bin/pip install --no-deps -e .

# 5. Next.js Frontend
echo "[5/5] Installing Next.js frontend dependencies..."
cd "$ROOT_DIR/frontend"
npm install --no-audit --no-fund

echo ""
echo "Setup complete. Start Bastion:"
echo "  Backend : cd backend && .venv/bin/uvicorn app.main:app --reload --port 8000"
echo "  Frontend: cd frontend && npm run dev"
echo "  CLI     : ./backend/.venv/bin/bastion doctor"
