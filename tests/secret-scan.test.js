const test = require("node:test");
const assert = require("node:assert/strict");

const {
  extractAddedLines,
  findSensitiveMatches,
  parsePushRefs,
} = require("../scripts/secret-scan");

test("parsePushRefs parses pre-push stdin records", () => {
  const refs = parsePushRefs([
    "refs/heads/main 1111111111111111111111111111111111111111 refs/heads/main 2222222222222222222222222222222222222222",
    "refs/heads/feature 3333333333333333333333333333333333333333 refs/heads/feature 0000000000000000000000000000000000000000",
  ].join("\n"));

  assert.deepEqual(refs, [
    {
      localRef: "refs/heads/main",
      localSha: "1111111111111111111111111111111111111111",
      remoteRef: "refs/heads/main",
      remoteSha: "2222222222222222222222222222222222222222",
    },
    {
      localRef: "refs/heads/feature",
      localSha: "3333333333333333333333333333333333333333",
      remoteRef: "refs/heads/feature",
      remoteSha: "0000000000000000000000000000000000000000",
    },
  ]);
});

test("extractAddedLines keeps file path and added line numbers", () => {
  const patch = [
    "diff --git a/server.js b/server.js",
    "--- a/server.js",
    "+++ b/server.js",
    "@@ -10,0 +11,2 @@",
    "+const token = \"sensitive-value\";",
    "+console.log(token);",
  ].join("\n");

  const lines = extractAddedLines(patch, "abc123");
  assert.deepEqual(lines, [
    {
      commit: "abc123",
      filePath: "server.js",
      lineNumber: 11,
      text: "const token = \"sensitive-value\";",
    },
    {
      commit: "abc123",
      filePath: "server.js",
      lineNumber: 12,
      text: "console.log(token);",
    },
  ]);
});

test("findSensitiveMatches catches provider tokens and private keys", () => {
  const github = findSensitiveMatches(`const token = "${`ghp_${"123456789012345678901234567890123456"}`}";`, {
    filePath: "server.js",
  });
  const openai = findSensitiveMatches(`OPENAI_API_KEY=${`sk-proj-${"abcdefghijklmnopqrstuvwxyz123456"}`}`, {
    filePath: ".env.example",
  });
  const alibaba = findSensitiveMatches(`ALIBABA_CLOUD_ACCESS_KEY_ID=${`LTAI${"1234567890abcdef1234567890"}`}`, {
    filePath: ".env",
  });
  const pemFindings = findSensitiveMatches(["-----BEGIN", "OPENSSH PRIVATE KEY-----"].join(" "), {
    filePath: "id_rsa",
  });

  assert.equal(github[0].ruleId, "github-token");
  assert.equal(openai[0].ruleId, "openai-api-key");
  assert.equal(alibaba[0].ruleId, "alibaba-access-key-id");
  assert.equal(alibaba.length, 1);
  assert.equal(pemFindings[0].ruleId, "private-key");
});

test("findSensitiveMatches catches generic high-entropy secret assignments", () => {
  const sampleKey = "A1b2C3d4E5f6G7h8" + "J9kLmNoPqRsTuVwX";
  const findings = findSensitiveMatches(`const apiKey = "${sampleKey}";`, {
    filePath: "server.js",
  });

  assert.equal(findings.length, 1);
  assert.equal(findings[0].ruleId, "generic-secret-assignment");
});

test("findSensitiveMatches honors inline allow markers and generated-file heuristics", () => {
  const sampleKey = "A1b2C3d4E5f6G7h8" + "J9kLmNoPqRsTuVwX";
  const allowlisted = findSensitiveMatches(
    `const apiKey = "${sampleKey}"; // secret-scan: allow`,
    { filePath: "tests/fixture.js" },
  );
  const generated = findSensitiveMatches(
    `const apiKey="${sampleKey}";`,
    { filePath: "dist/bundle.min.js" },
  );

  assert.deepEqual(allowlisted, []);
  assert.deepEqual(generated, []);
});
