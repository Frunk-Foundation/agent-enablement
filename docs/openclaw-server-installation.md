# OpenClaw Server Installation: `agent_enablement` Skill + `enabler-mcp-cli`

## Goal
Install and enable `agent_enablement` on additional servers so OpenClaw agents use:
- `skills/enabler-mcp-cli/SKILL.md`
- `./enabler-mcp-cli`

No MCP server registration in `~/.openclaw/openclaw.json` is required for this flow.

## Required Host Paths
- Repo: `/home/openclaw/agent_enablement`
- OpenClaw config: `/home/openclaw/.openclaw/openclaw.json`
- OpenClaw env file: `/home/openclaw/.openclaw/.env`

## 1) Install or Update Repo
```bash
cd ~
if [ ! -d agent_enablement ]; then
  git clone https://github.com/Frunk-Foundation/agent-enablement.git agent_enablement
fi

cd ~/agent_enablement
git checkout main
git pull --ff-only origin main
```

## 2) Create Local Python Environment
```bash
cd ~/agent_enablement
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements.txt
```

## 3) Verify Required Artifacts
```bash
ls -la ~/agent_enablement/enabler-mcp-cli
ls -la ~/agent_enablement/skills/enabler-mcp-cli/SKILL.md
```

## 4) Ensure Obsolete Skills Are Not Present
These should be absent:
- `skills/files-basic-ops/SKILL.md`
- `skills/get-started/SKILL.md`
- `skills/messages-basic-ops/SKILL.md`
- `skills/shortlinks/SKILL.md`
- `skills/taskboard-basics/SKILL.md`
- `skills/ssm-key-access/SKILL.md`

Check:
```bash
cd ~/agent_enablement
for f in \
  skills/files-basic-ops/SKILL.md \
  skills/get-started/SKILL.md \
  skills/messages-basic-ops/SKILL.md \
  skills/shortlinks/SKILL.md \
  skills/taskboard-basics/SKILL.md \
  skills/ssm-key-access/SKILL.md; do
  if [ -e "$f" ]; then
    echo "STILL_PRESENT $f"
  else
    echo "REMOVED $f"
  fi
done
```

## 5) Configure OpenClaw Skill Lookup Path
Add the repo skills directory to `skills.load.extraDirs` in `~/.openclaw/openclaw.json`.

Target value:
```json
{
  "skills": {
    "load": {
      "extraDirs": [
        "/home/openclaw/agent_enablement/skills"
      ]
    }
  }
}
```

## 6) Configure Required `ENABLER_*` Variables
Set in `~/.openclaw/.env`:
- `ENABLER_CREDENTIALS_ENDPOINT`
- `ENABLER_API_KEY`
- `ENABLER_COGNITO_USERNAME`
- `ENABLER_COGNITO_PASSWORD`

Optional:
- `ENABLER_AGENT_ID`
- `ENABLER_SESSION_ROOT`

Set secure file mode:
```bash
chmod 600 ~/.openclaw/.env
```

## 7) Restart OpenClaw
```bash
sudo systemctl restart openclaw
```

## 8) Validate Runtime
```bash
~/agent_enablement/enabler-mcp-cli list
~/agent_enablement/enabler-mcp-cli inspect help
~/agent_enablement/enabler-mcp-cli call credentials.status
```

If unbound identity is expected, use delegation bootstrap:
- `credentials.exec` `action=delegation_request`
- approve from named authorized agent
- `credentials.exec` `action=delegation_redeem`

## 9) Smoke Checks
Run one runtime read action and one fileshare/help action:
```bash
~/agent_enablement/enabler-mcp-cli call taskboard.exec --action help
~/agent_enablement/enabler-mcp-cli call fileshare.exec --action help
```

## Acceptance Criteria
- `~/agent_enablement` is on latest `main`
- `enabler-mcp-cli` exists and runs
- `skills/enabler-mcp-cli/SKILL.md` exists
- `skills.load.extraDirs` includes `/home/openclaw/agent_enablement/skills`
- Required `ENABLER_*` vars are present in `~/.openclaw/.env`
- OpenClaw restarted after config/env changes
- CLI checks pass (`list`, `inspect`, `credentials.status`)
