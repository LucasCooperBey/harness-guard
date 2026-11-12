#!/bin/bash
# No `any` Type Enforcement Hook
# Blocks edits that introduce `: any` in TypeScript files
# Allows eslint-disable comments as escape hatch

INPUT=$(cat)
FILE_PATH=$(echo "$INPUT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('tool_input',{}).get('file_path',''))" 2>/dev/null)

# Only check TypeScript files
case "$FILE_PATH" in
  *.ts|*.tsx)
    ;;
  *)
    exit 0
    ;;
esac

# Skip test files
case "$FILE_PATH" in
  *.test.ts|*.test.tsx|*.spec.ts|*.spec.tsx)
    exit 0
    ;;
esac

if [ ! -f "$FILE_PATH" ]; then
  exit 0
fi

# Find `: any` that isn't disabled by eslint comment
MATCHES=$(grep -n ': any' "$FILE_PATH" | grep -v '// eslint-disable' | grep -v '// @ts-ignore' | grep -v '// any-ok' | head -10)

if [ -n "$MATCHES" ]; then
  echo "Found \`any\` type in ${FILE_PATH}. Use proper typing instead:" >&2
  echo "$MATCHES" >&2
  echo "" >&2
  echo "Use: unknown with type guards, generics, or specific types." >&2
  echo "Escape hatch: add '// any-ok' comment on the line if truly needed." >&2
  exit 2  # Block
fi

exit 0
