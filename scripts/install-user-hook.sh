#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CONFIG_HOME="${XDG_CONFIG_HOME:-${HOME}/.config}"
HOOKS_DIR="${CONFIG_HOME}/git/hooks"
TARGET_HOOK="${HOOKS_DIR}/pre-push"
BACKUP_HOOK="${HOOKS_DIR}/pre-push.git-secret-scan-hook.backup"
LEGACY_COPY="${HOOKS_DIR}/secret-scan.js"
WRAPPER_MARKER="# managed by git-secret-scan-hook"
LEGACY_LOCAL_MARKER='exec node "${ROOT_DIR}/scripts/secret-scan.js" "$@"'

mkdir -p "${HOOKS_DIR}"

LEGACY_HOOK_PATH=""
if [[ -e "${TARGET_HOOK}" || -L "${TARGET_HOOK}" ]]; then
  if grep -qF "${WRAPPER_MARKER}" "${TARGET_HOOK}" 2>/dev/null; then
    if [[ -x "${BACKUP_HOOK}" ]]; then
      LEGACY_HOOK_PATH="${BACKUP_HOOK}"
    fi
  elif grep -qF "${LEGACY_LOCAL_MARKER}" "${TARGET_HOOK}" 2>/dev/null; then
    rm -f "${TARGET_HOOK}"
  else
    mv "${TARGET_HOOK}" "${BACKUP_HOOK}"
    LEGACY_HOOK_PATH="${BACKUP_HOOK}"
  fi
fi

HOOK_REPO_ESCAPED="$(printf "%q" "${REPO_ROOT}")"
LEGACY_HOOK_ESCAPED="$(printf "%q" "${LEGACY_HOOK_PATH}")"

cat > "${TARGET_HOOK}" <<EOF
#!/usr/bin/env bash
set -euo pipefail
${WRAPPER_MARKER}

HOOK_REPO=${HOOK_REPO_ESCAPED}
HOOK_SCRIPT="\${HOOK_REPO}/hooks/pre-push"
LEGACY_HOOK=${LEGACY_HOOK_ESCAPED}
STDIN_FILE="\$(mktemp "\${TMPDIR:-/tmp}/git-secret-scan-hook.XXXXXX")"

cleanup() {
  rm -f "\${STDIN_FILE}"
}

trap cleanup EXIT

if [[ ! -x "\${HOOK_SCRIPT}" ]]; then
  echo "git-secret-scan-hook is missing: \${HOOK_SCRIPT}" >&2
  exit 1
fi

cat > "\${STDIN_FILE}"
"\${HOOK_SCRIPT}" "\$@" < "\${STDIN_FILE}"
STATUS=\$?
if [[ \${STATUS} -ne 0 ]]; then
  exit \${STATUS}
fi

if [[ -n "\${LEGACY_HOOK}" && -x "\${LEGACY_HOOK}" ]]; then
  "\${LEGACY_HOOK}" "\$@" < "\${STDIN_FILE}"
fi
EOF

chmod +x "${TARGET_HOOK}" "${REPO_ROOT}/hooks/pre-push" "${REPO_ROOT}/scripts/install-user-hook.sh" "${REPO_ROOT}/scripts/secret-scan.js"
git config --global core.hooksPath "${HOOKS_DIR}"
rm -f "${LEGACY_COPY}"

echo "Installed git-secret-scan-hook"
echo "  repo: ${REPO_ROOT}"
echo "  hooks: ${HOOKS_DIR}"
if [[ -n "${LEGACY_HOOK_PATH}" ]]; then
  echo "  chained legacy hook: ${LEGACY_HOOK_PATH}"
fi
