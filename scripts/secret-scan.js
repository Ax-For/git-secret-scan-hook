#!/usr/bin/env node
"use strict";

const { execFileSync } = require("child_process");

const ZERO_SHA_PATTERN = /^0+$/;
const ALLOW_MARKERS = [
  "secret-scan: allow",
  "pragma: allowlist secret",
  "gitleaks:allow",
];
const GENERATED_FILE_PATTERN =
  /(^|\/)(dist|build|coverage|node_modules|vendor)\//i;
const GENERATED_FILE_SUFFIX_PATTERN =
  /\.(min\.js|map|lock|snap)$/i;

const EXPLICIT_RULES = [
  {
    id: "private-key",
    description: "Private key material",
    regex: /-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP|PRIVATE KEY|ENCRYPTED PRIVATE KEY)/,
  },
  {
    id: "github-token",
    description: "GitHub token",
    regex: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}\b|\bgithub_pat_[A-Za-z0-9_]{20,255}\b/,
  },
  {
    id: "openai-api-key",
    description: "OpenAI API key",
    regex: /\bsk-(?:proj-|svcacct-|live-)?[A-Za-z0-9_-]{20,}\b/,
  },
  {
    id: "anthropic-api-key",
    description: "Anthropic API key",
    regex: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/,
  },
  {
    id: "tavily-api-key",
    description: "Tavily API key",
    regex: /\btvly-[A-Za-z0-9_-]{20,}\b/,
  },
  {
    id: "aws-access-key-id",
    description: "AWS access key id",
    regex: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/,
  },
  {
    id: "alibaba-access-key-id",
    description: "Alibaba Cloud AccessKey ID",
    regex: /\b(?:LTAI[A-Za-z0-9]{12,64}|STS\.[A-Za-z0-9]{12,64})\b/,
  },
  {
    id: "slack-token",
    description: "Slack token",
    regex: /\bxox[baprs]-[A-Za-z0-9-]{10,255}\b/,
  },
  {
    id: "stripe-live-key",
    description: "Stripe live secret",
    regex: /\b(?:sk|rk)_live_[0-9a-zA-Z]{16,}\b/,
  },
  {
    id: "db-connection-string",
    description: "Database connection string with credentials",
    regex: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[^:\s/]+:[^@\s]+@/i,
  },
  {
    id: "http-auth-header",
    description: "HTTP authorization header with embedded credential",
    regex: /\bAuthorization:\s*(?:Basic\s+[A-Za-z0-9+/=]{12,}|Bearer\s+[A-Za-z0-9._-]{16,})/i,
  },
];

const GENERIC_SECRET_ASSIGNMENT_PATTERN =
  /(?:^|["'\s])([A-Za-z0-9_.-]{0,80}(?:api[_-]?key|token|secret|password|passwd|pwd|client[_-]?secret|access[_-]?key|private[_-]?key)[A-Za-z0-9_.-]{0,40})["']?\s*[:=]\s*(?:["'`])?([^\s"'`]{16,})(?:["'`])?/i;

function shannonEntropy(value) {
  if (!value) return 0;
  const counts = new Map();
  for (const char of value) counts.set(char, (counts.get(char) || 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const probability = count / value.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}

function isGeneratedFile(filePath) {
  return GENERATED_FILE_PATTERN.test(filePath) || GENERATED_FILE_SUFFIX_PATTERN.test(filePath);
}

function hasAllowMarker(text) {
  const lower = String(text || "").toLowerCase();
  return ALLOW_MARKERS.some((marker) => lower.includes(marker));
}

function looksPlaceholder(value) {
  if (!value) return true;
  if (/^(?:x+|X+|\*+|y+|Y+)$/.test(value)) return true;
  if (/^(?:your|example|sample|dummy|placeholder|changeme|replace-me|test)[-_a-z0-9]*$/i.test(value)) return true;
  return false;
}

function looksGenericSecretValue(value) {
  if (!value || value.length < 16) return false;
  if (looksPlaceholder(value)) return false;
  if (/^[a-f0-9]{32,64}$/i.test(value)) return false;
  if (/^[A-F0-9]{32,64}$/.test(value)) return false;

  const entropy = shannonEntropy(value);
  const hasLower = /[a-z]/.test(value);
  const hasUpper = /[A-Z]/.test(value);
  const hasDigit = /\d/.test(value);
  const hasSymbol = /[^A-Za-z0-9]/.test(value);
  const classCount = [hasLower, hasUpper, hasDigit, hasSymbol].filter(Boolean).length;

  return entropy >= 3.5 || (value.length >= 24 && classCount >= 3);
}

function findSensitiveMatches(text, context = {}) {
  const line = String(text || "");
  if (!line || hasAllowMarker(line)) return [];

  const findings = [];
  for (const rule of EXPLICIT_RULES) {
    const match = line.match(rule.regex);
    if (match) {
      findings.push({
        ruleId: rule.id,
        description: rule.description,
        match: match[0],
      });
    }
  }

  if (!isGeneratedFile(context.filePath || "")) {
    const genericMatch = line.match(GENERIC_SECRET_ASSIGNMENT_PATTERN);
    if (genericMatch) {
      const value = genericMatch[2] || "";
      const overlapsExplicitMatch = findings.some((finding) => finding.match === value || value.includes(finding.match) || finding.match.includes(value));
      if (looksGenericSecretValue(value) && !overlapsExplicitMatch) {
        findings.push({
          ruleId: "generic-secret-assignment",
          description: "High-entropy secret-looking assignment",
          match: value,
        });
      }
    }
  }

  return findings;
}

function parsePushRefs(stdinText) {
  return String(stdinText || "")
    .split(/\r?\n/)
    .filter(Boolean)
    .map((line) => {
      const [localRef, localSha, remoteRef, remoteSha] = line.trim().split(/\s+/);
      return { localRef, localSha, remoteRef, remoteSha };
    });
}

function extractAddedLines(patchText, commit = "") {
  const lines = String(patchText || "").split(/\r?\n/);
  const added = [];
  let filePath = "";
  let nextLineNumber = 0;

  for (const line of lines) {
    if (line.startsWith("+++ ")) {
      filePath = line.slice(4).replace(/^b\//, "");
      continue;
    }
    const hunk = line.match(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
    if (hunk) {
      nextLineNumber = Number(hunk[1]);
      continue;
    }
    if (!filePath || !nextLineNumber) continue;
    if (line.startsWith("+") && !line.startsWith("+++")) {
      added.push({
        commit,
        filePath,
        lineNumber: nextLineNumber,
        text: line.slice(1),
      });
      nextLineNumber += 1;
      continue;
    }
    if (line.startsWith(" ") && !line.startsWith(" @@")) {
      nextLineNumber += 1;
    }
  }

  return added;
}

function execGit(args) {
  return execFileSync("git", args, {
    encoding: "utf8",
    maxBuffer: 20 * 1024 * 1024,
  });
}

function isZeroSha(sha) {
  return ZERO_SHA_PATTERN.test(String(sha || ""));
}

function getCommitsForPush(refs, execGitImpl = execGit) {
  const commits = new Set();

  for (const ref of refs) {
    if (!ref || isZeroSha(ref.localSha)) continue;

    let revList = "";
    if (isZeroSha(ref.remoteSha)) {
      revList = execGitImpl(["rev-list", ref.localSha, "--not", "--remotes"]).trim();
      if (!revList) {
        revList = execGitImpl(["rev-list", ref.localSha]).trim();
      }
    } else {
      revList = execGitImpl(["rev-list", `${ref.remoteSha}..${ref.localSha}`]).trim();
    }

    for (const commit of revList.split(/\r?\n/).filter(Boolean)) {
      commits.add(commit);
    }
  }

  return [...commits];
}

function getAddedLinesForCommit(commit, execGitImpl = execGit) {
  const patch = execGitImpl([
    "show",
    "--format=",
    "--unified=0",
    "--no-color",
    "--no-ext-diff",
    "--find-renames",
    commit,
    "--",
  ]);
  return extractAddedLines(patch, commit);
}

function scanCommits(commits, execGitImpl = execGit) {
  const findings = [];
  for (const commit of commits) {
    const addedLines = getAddedLinesForCommit(commit, execGitImpl);
    for (const line of addedLines) {
      const matches = findSensitiveMatches(line.text, { filePath: line.filePath });
      for (const match of matches) {
        findings.push({
          commit: line.commit,
          filePath: line.filePath,
          lineNumber: line.lineNumber,
          line: line.text,
          ...match,
        });
      }
    }
  }
  return findings;
}

function formatFinding(finding) {
  const sample = finding.match.length > 80 ? `${finding.match.slice(0, 77)}...` : finding.match;
  return `- ${finding.ruleId} in ${finding.filePath}:${finding.lineNumber} (${finding.commit.slice(0, 8)})\n  ${sample}`;
}

function readStdin() {
  return new Promise((resolve) => {
    let input = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (chunk) => {
      input += chunk;
    });
    process.stdin.on("end", () => resolve(input));
    if (process.stdin.isTTY) resolve("");
  });
}

async function main() {
  if (process.env.SKIP_SECRET_SCAN === "1") return;

  const refs = parsePushRefs(await readStdin());
  if (!refs.length) return;

  const commits = getCommitsForPush(refs);
  if (!commits.length) return;

  const findings = scanCommits(commits);
  if (!findings.length) return;

  console.error("\nSecret scan blocked this push. Found likely sensitive content in commits being pushed:\n");
  for (const finding of findings) {
    console.error(formatFinding(finding));
  }
  console.error("\nIf a match is intentional, add `secret-scan: allow` to that line or re-run with `SKIP_SECRET_SCAN=1 git push`.");
  process.exitCode = 1;
}

module.exports = {
  EXPLICIT_RULES,
  extractAddedLines,
  findSensitiveMatches,
  formatFinding,
  getAddedLinesForCommit,
  getCommitsForPush,
  hasAllowMarker,
  isGeneratedFile,
  looksGenericSecretValue,
  parsePushRefs,
  scanCommits,
  shannonEntropy,
};

if (require.main === module) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exit(1);
  });
}
