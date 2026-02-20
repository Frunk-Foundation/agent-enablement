#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

echo "[bootstrap] Ensuring Homebrew tools are installed..."
brew install just aws-cdk node@22 gitleaks

echo "[bootstrap] Rebuilding local virtualenv..."
python3 -m venv --clear .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements-dev.txt

echo "[bootstrap] Installing repository git hooks..."
./scripts/install-git-hooks.sh

echo "[bootstrap] Done."
echo "[bootstrap] To prefer Node 22 for this shell session:"
echo "  export PATH=\"/opt/homebrew/opt/node@22/bin:\$PATH\""
