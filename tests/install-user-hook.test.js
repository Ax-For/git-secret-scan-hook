const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync } = require("node:child_process");

const repoRoot = path.resolve(__dirname, "..");
const installScript = path.join(repoRoot, "scripts", "install-user-hook.sh");

function makeEnv(tempRoot) {
  const homeDir = path.join(tempRoot, "home");
  const configHome = path.join(tempRoot, "config");
  const globalGitConfig = path.join(tempRoot, "gitconfig");
  fs.mkdirSync(homeDir, { recursive: true });
  fs.mkdirSync(configHome, { recursive: true });

  return {
    ...process.env,
    HOME: homeDir,
    XDG_CONFIG_HOME: configHome,
    GIT_CONFIG_GLOBAL: globalGitConfig,
  };
}

test("install-user-hook writes global pre-push wrapper and git hooksPath", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "git-secret-scan-hook-"));
  const env = makeEnv(tempRoot);
  const hooksDir = path.join(env.XDG_CONFIG_HOME, "git", "hooks");
  const legacyCopy = path.join(hooksDir, "secret-scan.js");

  fs.mkdirSync(hooksDir, { recursive: true });
  fs.writeFileSync(legacyCopy, "legacy copy");

  execFileSync(installScript, { env, cwd: repoRoot, encoding: "utf8" });

  const configuredHooksPath = execFileSync("git", ["config", "--global", "--get", "core.hooksPath"], {
    env,
    cwd: repoRoot,
    encoding: "utf8",
  }).trim();
  const installedHook = path.join(hooksDir, "pre-push");
  const wrapper = fs.readFileSync(installedHook, "utf8");

  assert.equal(configuredHooksPath, hooksDir);
  assert.match(wrapper, /managed by git-secret-scan-hook/);
  assert.match(wrapper, new RegExp(repoRoot.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  assert.equal(fs.existsSync(legacyCopy), false);
});

test("install-user-hook preserves and chains an existing global pre-push hook", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "git-secret-scan-hook-"));
  const env = makeEnv(tempRoot);
  const hooksDir = path.join(env.XDG_CONFIG_HOME, "git", "hooks");
  const installedHook = path.join(hooksDir, "pre-push");
  const backupHook = path.join(hooksDir, "pre-push.git-secret-scan-hook.backup");
  const markerFile = path.join(tempRoot, "legacy-ran.txt");

  fs.mkdirSync(hooksDir, { recursive: true });
  fs.writeFileSync(installedHook, `#!/usr/bin/env bash\nset -euo pipefail\necho legacy >> "${markerFile}"\n`);
  fs.chmodSync(installedHook, 0o755);

  execFileSync(installScript, { env, cwd: repoRoot, encoding: "utf8" });

  assert.equal(fs.existsSync(backupHook), true);

  execFileSync(installedHook, ["origin", "git@example.com:repo.git"], {
    env: {
      ...env,
      SKIP_SECRET_SCAN: "1",
    },
    cwd: repoRoot,
    input: "",
    encoding: "utf8",
  });

  assert.equal(fs.readFileSync(markerFile, "utf8").trim(), "legacy");
});

test("install-user-hook replaces the old repo-local secret-scan hook without chaining it", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "git-secret-scan-hook-"));
  const env = makeEnv(tempRoot);
  const hooksDir = path.join(env.XDG_CONFIG_HOME, "git", "hooks");
  const installedHook = path.join(hooksDir, "pre-push");
  const backupHook = path.join(hooksDir, "pre-push.git-secret-scan-hook.backup");

  fs.mkdirSync(hooksDir, { recursive: true });
  fs.writeFileSync(
    installedHook,
    "#!/usr/bin/env bash\nset -euo pipefail\n\nROOT_DIR=\"$(git rev-parse --show-toplevel)\"\nexec node \"${ROOT_DIR}/scripts/secret-scan.js\" \"$@\"\n",
  );
  fs.chmodSync(installedHook, 0o755);

  execFileSync(installScript, { env, cwd: repoRoot, encoding: "utf8" });

  assert.equal(fs.existsSync(backupHook), false);

  execFileSync(installedHook, ["origin", "git@example.com:repo.git"], {
    env: {
      ...env,
      SKIP_SECRET_SCAN: "1",
    },
    cwd: repoRoot,
    input: "",
    encoding: "utf8",
  });
});
