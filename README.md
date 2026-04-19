# git-secret-scan-hook

`pre-push` secret scanner for Git. It inspects only the commits being pushed and blocks likely sensitive material before it reaches the remote.

## What It Detects

- Private key headers
- GitHub, OpenAI, Anthropic, Tavily, Slack, and Stripe tokens
- AWS Access Key IDs
- Alibaba Cloud AccessKey IDs
- Database URLs with embedded credentials
- High-entropy assignments such as `apiKey=...`, `token: ...`, `password=...`

The rule set is based on common patterns from GitHub Secret Scanning, gitleaks, and detect-secrets.

## Install

Clone the repo somewhere stable, then install the user-level hook:

```bash
git clone <your-remote-or-local-path> ~/code/git-secret-scan-hook
cd ~/code/git-secret-scan-hook
./scripts/install-user-hook.sh
```

The installer will:

- Set `git config --global core.hooksPath ~/.config/git/hooks`
- Install `~/.config/git/hooks/pre-push`
- Back up any existing global `pre-push` hook and chain it after the scan
- Remove the old copied `~/.config/git/hooks/secret-scan.js` if it exists

## Update

If the repo stays at the same path, updates are simple:

```bash
cd ~/code/git-secret-scan-hook
git pull
```

No reinstall is required for ordinary updates because the installed wrapper points back to this repo.

## Allowing Intentional Fixtures

If a line is intentionally kept as a test sample, add one of these markers on the same line:

- `secret-scan: allow`
- `pragma: allowlist secret`
- `gitleaks:allow`

To bypass the scan for a single push:

```bash
SKIP_SECRET_SCAN=1 git push
```
