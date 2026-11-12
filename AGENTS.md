# HarnessGuard Agent Instructions

This file tells a coding agent how to work in this repo.

## Project

Eight Claude Code hooks, each a short shell script that needs only `bash`, `jq` and `python3`. Claude Code runs a PreToolUse hook before a tool call and a PostToolUse hook after it. A hook blocks the call only by exiting with code 2; exit 1 is a warning that lets the call through. The README's table says what each hook blocks.

- `hooks/`: the eight hooks.
- `tests/`: shell test files and the runner `run.sh`.
- `install.sh`: copies the hooks into `~/.claude/hooks` and prints the settings snippet.

## Verification

```bash
bash tests/run.sh
shellcheck -x -S warning hooks/*.sh tests/*.sh install.sh
```

`run.sh` prints `PASS: all test files` when every test passes. The egress tests put a stand-in `osascript` first on PATH, so running them never raises a real desktop alert.

## Rules

- A new block rule gets a test that fails when the rule is removed.
- Keep each hook readable in one sitting; no new runtime dependencies.
- egress-guard fails closed: a send whose destination it cannot read is blocked. readonly-scope-guard stays inert while its marker files are absent. Keep both behaviors when editing.
- Do not commit secrets, logs or local state files.
