#!/bin/bash
# Pre-Commit Quality Gate Hook
# Blocks git commit if tests, lint, or typecheck fail
# Runs on PreToolUse for Bash tool when command contains "git commit"

INPUT=$(cat)
COMMAND=$(echo "$INPUT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('tool_input',{}).get('command',''))" 2>/dev/null)

# Only intercept git commit commands
case "$COMMAND" in
  *"git commit"*)
    ;;
  *)
    exit 0  # Not a commit, allow
    ;;
esac

# Find project root from CWD or CLAUDE_PROJECT_DIR
PROJECT_ROOT="${CLAUDE_PROJECT_DIR:-$(pwd)}"
if [ ! -f "$PROJECT_ROOT/package.json" ]; then
  exit 0  # No package.json, skip checks
fi

cd "$PROJECT_ROOT"

ERRORS=""

# Run tests if test script exists
# Prefer the repo's own "test" script (vitest, jest, etc.) over Bun's native
# runner, since projects configure their own isolation / mocking / env there.
# Fall back to `bun test` only if no "test" script is declared.
HAS_TEST=$(python3 -c "import json; d=json.load(open('package.json')); print('yes' if 'test' in d.get('scripts',{}) else 'no')" 2>/dev/null)
if [ "$HAS_TEST" = "yes" ]; then
  TEST_OUTPUT=$(bun run test 2>&1)
  if [ $? -ne 0 ]; then
    ERRORS="${ERRORS}\n--- TEST FAILURES ---\n${TEST_OUTPUT}\n"
  fi
fi

# Run lint if lint script exists
HAS_LINT=$(python3 -c "import json; d=json.load(open('package.json')); print('yes' if 'lint' in d.get('scripts',{}) else 'no')" 2>/dev/null)
if [ "$HAS_LINT" = "yes" ]; then
  LINT_OUTPUT=$(bun run lint 2>&1)
  if [ $? -ne 0 ]; then
    ERRORS="${ERRORS}\n--- LINT FAILURES ---\n${LINT_OUTPUT}\n"
  fi
fi

# Run typecheck if typecheck script exists
HAS_TC=$(python3 -c "import json; d=json.load(open('package.json')); print('yes' if 'typecheck' in d.get('scripts',{}) else 'no')" 2>/dev/null)
if [ "$HAS_TC" = "yes" ]; then
  TC_OUTPUT=$(bun run typecheck 2>&1)
  if [ $? -ne 0 ]; then
    ERRORS="${ERRORS}\n--- TYPECHECK FAILURES ---\n${TC_OUTPUT}\n"
  fi
fi

if [ -n "$ERRORS" ]; then
  echo -e "Quality gate FAILED. Fix these before committing:\n${ERRORS}" >&2
  exit 2  # Block the commit
fi

exit 0
