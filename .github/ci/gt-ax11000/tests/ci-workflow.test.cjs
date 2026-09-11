"use strict";
// Exercise the checked-in job expression itself, not a separately copied
// policy. This expression uses the common JS/GitHub subset: strings, !=, ==, ||.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const os = require("node:os");
const { execFileSync } = require("node:child_process");
const { test } = require("node:test");
const workflow = fs.readFileSync(path.join(__dirname, "../../../workflows/build-gt-ax11000.yml"), "utf8");
function job(name) {
  const match = workflow.match(new RegExp(`^  ${name}:\\n([\\s\\S]*?)(?=^  [a-z][a-z-]*:|$(?![\\s\\S]))`, "m"));
  assert.ok(match, `job ${name} exists`);
  return match[1];
}
const expression = job("build").match(/^    if: (.+)$/m)?.[1];
assert.ok(expression, "firmware has an explicit event policy");
const checkName = job("build").match(/^    name: \$\{\{ (.+) \}\}$/m)?.[1];
assert.ok(checkName, "skipped push and required firmware checks have distinct names");
for (const [event, ref, expected] of [
  ["push", "refs/heads/main", true],
  ["push", "refs/heads/codex/gt-ax11000-parallel-dag-ci", false],
  ["push", "refs/heads/codex/rust-porting", false],
  ["push", "refs/heads/not-main", false],
  ["pull_request", "refs/pull/15/merge", true],
  ["workflow_dispatch", "refs/heads/codex/gt-ax11000-parallel-dag-ci", true],
  ["workflow_dispatch", "refs/heads/main", true],
  ["schedule", "refs/heads/main", true],
]) {
  test(`firmware ${event} ${ref}: ${expected}`, () => {
    assert.equal(vm.runInNewContext(expression, { github: { event_name: event, ref } }, { timeout: 100 }), expected);
    const name = vm.runInNewContext(checkName, { github: { event_name: event, ref } }, { timeout: 100 });
    if (expected) assert.equal(name, "Firmware");
    else assert.equal(name, "Firmware (PR or manual run required)");
  });
}
test("branch pushes still run all three inexpensive gates", () => {
  for (const name of ["rust", "security-overlay", "trial"]) {
    assert.doesNotMatch(job(name), /^    if:/m);
  }
  assert.match(workflow, /^      - codex\/gt-ax11000-parallel-dag-ci$/m);
});
test("firmware still depends on successful Rust and security checks", () => {
  assert.match(job("build"), /^    needs:\n      - rust\n      - security-overlay\n/m);
});
test("PR and push keep independent concurrency and exact event SHA", () => {
  assert.match(workflow, /group: gt-ax11000-\$\{\{ github\.ref \}\}/);
  assert.doesNotMatch(workflow, /pull_request_target|github\.head_ref|pull_request\.head\.sha/);
  for (const name of ["rust", "security-overlay", "trial", "build"]) {
    assert.match(job(name), /git -C overlay fetch --depth=1 --filter=blob:none origin "\$GITHUB_SHA"/);
    assert.match(job(name), /test "\$\(git -C overlay rev-parse HEAD\)" = "\$GITHUB_SHA"/);
  }
});
test("the Rust gate actually receives and tests the workflow file", () => {
  assert.match(job("rust"), /sparse-checkout set \.github\/ci\/gt-ax11000 \.github\/workflows/);
  assert.match(job("rust"), /node --test .*tests\/ci-workflow\.test\.cjs/);
});

const sync = fs.readFileSync(path.join(__dirname, "../../../workflows/sync-upstream.yml"), "utf8");
function scriptSection(start, end) {
  const body = sync.split(start)[1]?.split(end)[0];
  assert.ok(body, `sync section ${start} exists`);
  return body.split("\n").map(line => line.replace(/^          /, "")).join("\n");
}
for (const existing of [false, true]) {
  test(`sync configures the locked upstream (pre-existing remote: ${existing})`, () => {
    const temp = fs.mkdtempSync(path.join(os.tmpdir(), "gt-ci-remote-"));
    try {
      const repo = path.join(temp, "repo");
      execFileSync("git", ["init", "-q", repo]);
      if (existing) execFileSync("git", ["-C", repo, "remote", "add", "upstream", "https://example.invalid/wrong"]);
      const block = scriptSection("# BEGIN locked upstream remote (also executed by ci-workflow.test.cjs)", "# END locked upstream remote");
      const expected = "https://example.invalid/locked-upstream";
      // No network, credentials or router. Exercise the real shell twice.
      for (let attempt = 0; attempt < 2; attempt++) {
        execFileSync("bash", ["-euo", "pipefail", "-c", block], { cwd: temp, env: { ...process.env, upstream_repo: expected } });
        assert.equal(execFileSync("git", ["-C", repo, "remote", "get-url", "upstream"], { encoding: "utf8" }).trim(), expected);
      }
    } finally {
      fs.rmSync(temp, { recursive: true });
    }
  });
}
test("sync patch paths survive git -C into a separate source tree", () => {
  const block = scriptSection('overlay_root="$GITHUB_WORKSPACE/repo/.github/ci/gt-ax11000"', 'upstream_repo=$(python3');
  const workspace = "/tmp/a workspace";
  const result = execFileSync("bash", ["-euo", "pipefail", "-c", 'overlay_root="$GITHUB_WORKSPACE/repo/.github/ci/gt-ax11000"' + block + '\nprintf "%s\\n" "$lock" "$tool" "$patch_root"'], {
    encoding: "utf8", env: { ...process.env, GITHUB_WORKSPACE: workspace },
  }).trim().split("\n");
  assert.deepEqual(result, ["inputs.lock", "tools/input_lock.py", "patches"].map(p => workspace + "/repo/.github/ci/gt-ax11000/" + p));
  assert.match(sync, /git -C "\$source" apply --recount --check "\$patch_root\/\$patch_name"/);
});
