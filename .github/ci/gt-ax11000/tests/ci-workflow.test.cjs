"use strict";
// Exercise the checked-in job expression itself, not a separately copied
// policy. This expression uses the common JS/GitHub subset: strings, !=, ==, ||.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { test } = require("node:test");
const workflow = fs.readFileSync(path.join(__dirname, "../../../workflows/build-gt-ax11000.yml"), "utf8");
function job(name) {
  const match = workflow.match(new RegExp(`^  ${name}:\\n([\\s\\S]*?)(?=^  [a-z][a-z-]*:|$(?![\\s\\S]))`, "m"));
  assert.ok(match, `job ${name} exists`);
  return match[1];
}
const expression = job("build").match(/^    if: (.+)$/m)?.[1];
assert.ok(expression, "firmware has an explicit event policy");
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
