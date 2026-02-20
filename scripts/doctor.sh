#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

status=0

check_cmd() {
  local cmd="$1"
  if command -v "${cmd}" >/dev/null 2>&1; then
    printf "[ok] %s -> %s\n" "${cmd}" "$(command -v "${cmd}")"
  else
    printf "[missing] %s\n" "${cmd}"
    status=1
  fi
}

check_cmd python3
check_cmd aws
check_cmd jq
check_cmd just
check_cmd cdk
check_cmd gitleaks
check_cmd node
check_cmd npm
check_cmd npx

if [[ -x "/opt/homebrew/opt/node@22/bin/node" ]]; then
  node22_version="$(/opt/homebrew/opt/node@22/bin/node --version)"
  printf "[ok] node@22 available -> %s\n" "${node22_version}"
else
  printf "[warn] node@22 not found at /opt/homebrew/opt/node@22/bin/node\n"
  status=1
fi

if command -v node >/dev/null 2>&1; then
  node_version="$(node --version)"
  node_major="$(echo "${node_version}" | sed -E 's/^v([0-9]+).*/\1/')"
  if [[ "${node_major}" =~ ^(20|22|24)$ ]]; then
    printf "[ok] active node is CDK/jsii supported -> %s\n" "${node_version}"
  else
    printf "[warn] active node may be unsupported for CDK/jsii -> %s (prefer v22)\n" "${node_version}"
    status=1
  fi
fi

if [[ -x ".venv/bin/python" ]]; then
  printf "[ok] .venv python -> %s\n" "$(.venv/bin/python --version 2>&1)"
else
  printf "[missing] .venv/bin/python\n"
  status=1
fi

if [[ -x ".venv/bin/pip" ]]; then
  if .venv/bin/pip --version >/dev/null 2>&1; then
    printf "[ok] .venv pip entrypoint\n"
  else
    printf "[warn] .venv pip exists but failed\n"
    status=1
  fi
else
  printf "[missing] .venv/bin/pip\n"
  status=1
fi

if [[ -x ".venv/bin/python" ]]; then
  if .venv/bin/python - <<'PY' >/dev/null 2>&1
import importlib
mods = ["boto3", "typer", "rich", "dotenv", "pytest", "aws_cdk", "constructs"]
for m in mods:
    importlib.import_module(m)
PY
  then
    printf "[ok] required Python imports\n"
  else
    printf "[warn] one or more required Python imports failed\n"
    status=1
  fi
fi

if [[ "${status}" -ne 0 ]]; then
  echo
  echo "doctor found issues. Suggested fix:"
  echo "  ./scripts/bootstrap-local.sh"
  exit 1
fi

echo
echo "doctor passed."
