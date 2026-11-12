#!/usr/bin/env bash
# Tests for no-console-log.sh and readonly-scope-guard.sh.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
HOOKS="$here/../hooks"
TMP="$(mktemp -d)"
LOCKED_DIR=""
cleanup() {
  if [ -n "${LOCKED_DIR}" ] && [ -d "${LOCKED_DIR}" ]; then
    chmod 700 "$LOCKED_DIR" || true
  fi
  /bin/rm -rf "$TMP"
}
trap cleanup EXIT
fail=0
pass() { echo "PASS $1"; }
bad() { echo "FAIL $1"; fail=1; }

# source: 11-12 pre-push review: no-console-log pasted the matched lines into a python3 -c
# triple-quoted literal, so a line holding three quotes ran its own Python inside the hook.
js="$TMP/app.js"
printf '%s\n' "console.log(1) ''' + str(__import__(\"os\").system(\"touch $TMP/pwned\")) + '''" > "$js"
out="$(printf '{"tool_input":{"file_path":"%s"}}' "$js" | bash "$HOOKS/no-console-log.sh" 2>&1)"; status=$?
if [ -e "$TMP/pwned" ]; then
  bad "a matched line cannot run code in the hook"
else
  pass "a matched line cannot run code in the hook"
fi
if [ "$status" -eq 0 ] && printf '%s' "$out" | python3 -c 'import json,sys; d=json.load(sys.stdin); m=d["hookSpecificOutput"]["additionalContext"]; sys.exit(0 if "console.log(1)" in m else 1)' 2>/dev/null; then
  pass "the warning is valid JSON that quotes the line"
else
  bad "the warning is valid JSON that quotes the line (status $status): ${out:0:200}"
fi

# source: 11-12 pre-push review: the read-only block message told the agent the command that
# switches read-only mode off, which a Bash call could then run past this Edit/Write hook.
mkdir -p "$TMP/fakehome/.claude/state"
printf '{"active":true,"reason":"audit"}' > "$TMP/fakehome/.claude/state/readonly.json"
msg="$(printf '{"tool_input":{"file_path":"/tmp/x.txt"}}' | HOME="$TMP/fakehome" bash "$HOOKS/readonly-scope-guard.sh" 2>&1)"; status=$?
if [ "$status" -eq 2 ]; then pass "read-only mode blocks a write with exit 2"; else bad "read-only mode blocks a write with exit 2 (got $status)"; fi
case "$msg" in
  *"rm ~"*|*"rm \$HOME"*|*"rm -"*|*"readonly.json"*|*".claude/state"*) bad "the block message does not name how to switch the mode off: $msg" ;;
  *) pass "the block message does not name how to switch the mode off" ;;
esac

# source: 11-12 review of c69dc2f, the quality gate failed open when it could not enter the project folder
# The hook sets PROJECT_ROOT from CLAUDE_PROJECT_DIR when that is set, else pwd.
LOCKED_DIR="$(mktemp -d "$TMP/locked.XXXXXX")"
printf '%s\n' '{"name":"quality-gate-fixture"}' > "$LOCKED_DIR/package.json"
chmod 000 "$LOCKED_DIR"
qg_out="$(printf '%s' '{"tool_input":{"command":"git commit -m x"}}' | CLAUDE_PROJECT_DIR="$LOCKED_DIR" bash "$HOOKS/pre-commit-quality-gate.sh" 2>&1)"
qg_status=$?
if [ "$qg_status" -eq 2 ] && printf '%s' "$qg_out" | grep -F -q -- "$LOCKED_DIR" && printf '%s' "$qg_out" | grep -F -q "blocked" && printf '%s' "$qg_out" | grep -F -q "could not run"; then
  pass "the quality gate blocks when it cannot enter the project folder"
else
  bad "the quality gate blocks when it cannot enter the project folder (status $qg_status): ${qg_out:0:300}"
fi

if [ "$fail" -ne 0 ]; then exit 1; fi
