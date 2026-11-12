#!/usr/bin/env bash
# Tests for no-console-log.sh and readonly-scope-guard.sh.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
HOOKS="$here/../hooks"
TMP="$(mktemp -d)"
trap '/bin/rm -rf "$TMP"' EXIT
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

if [ "$fail" -ne 0 ]; then exit 1; fi
