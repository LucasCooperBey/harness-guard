#!/bin/bash
# No console.log Warning Hook
# Non-blocking warning when console.log is found in production code
# Skips test files

INPUT=$(cat)
FILE_PATH=$(echo "$INPUT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('tool_input',{}).get('file_path',''))" 2>/dev/null)

# Only check TypeScript/JavaScript files
case "$FILE_PATH" in
  *.ts|*.tsx|*.js|*.jsx)
    ;;
  *)
    exit 0
    ;;
esac

# Skip test files
case "$FILE_PATH" in
  *.test.*|*.spec.*|*__tests__*)
    exit 0
    ;;
esac

if [ ! -f "$FILE_PATH" ]; then
  exit 0
fi

MATCHES=$(grep -n 'console\.log' "$FILE_PATH" | head -5)

if [ -n "$MATCHES" ]; then
  # Non-blocking: output as JSON additionalContext (exit 0, not exit 2).
  # The path and the matched lines reach Python as environment values, never as source text,
  # so a line in the file cannot run code here.
  FILE_PATH="$FILE_PATH" MATCHES="$MATCHES" python3 -c '
import json, os
msg = ("Found console.log in " + os.environ["FILE_PATH"] + ". Consider removing it before commit:\n"
       + os.environ["MATCHES"] + "\n\nUse a proper logger or remove debug statements.")
print(json.dumps({"hookSpecificOutput": {"hookEventName": "PostToolUse", "additionalContext": msg}}))
'
fi

exit 0
