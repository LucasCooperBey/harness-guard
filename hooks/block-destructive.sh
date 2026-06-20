#!/bin/bash
# Block Destructive Commands Hook (PreToolUse on Bash)
# Catches dangerous operations before they execute. Exit 2 = block, Exit 0 = allow.

INPUT=$(cat)
COMMAND=$(echo "$INPUT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('tool_input',{}).get('command',''))" 2>/dev/null)

[[ -z "$COMMAND" ]] && exit 0

# ---- Optional: protect irreplaceable directories from deletion ----
# Set HARNESS_GUARD_PROTECT to a |-separated list of path fragments, e.g.
#   export HARNESS_GUARD_PROTECT="Irreplaceable-Backups|wedding-photos|master-recordings"
# Any rm/shred/unlink/trash touching a matching path is hard-blocked.
PROTECT="${HARNESS_GUARD_PROTECT:-}"
if [[ -n "$PROTECT" ]] && echo "$COMMAND" | grep -qE "$PROTECT"; then
  if echo "$COMMAND" | grep -qE '\brm\b|\bshred\b|\bunlink\b|\btrash\b'; then
    echo "BLOCKED: refusing to delete a protected path (matched HARNESS_GUARD_PROTECT). Do it by hand if you truly mean to." >&2
    exit 2
  fi
fi

# Block patterns (case-insensitive check)
case "$COMMAND" in
  *"rm -rf /"*|*"rm -rf ~"*|*"rm -rf \$HOME"*)
    echo "BLOCKED: Recursive delete of root or home directory" >&2
    exit 2
    ;;
  *"git push --force"*main*|*"git push -f"*main*|*"git push --force"*master*|*"git push -f"*master*)
    echo "BLOCKED: Force push to main/master. Use a feature branch." >&2
    exit 2
    ;;
  *"git reset --hard"*)
    echo "WARNING: git reset --hard detected. Proceeding but logging." >&2
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) DESTRUCTIVE: $COMMAND" >> "$HOME/.claude/hooks/destructive.log"
    exit 0
    ;;
  *"DROP TABLE"*|*"DROP DATABASE"*|*"TRUNCATE"*)
    echo "BLOCKED: Destructive SQL operation. Use a migration instead." >&2
    exit 2
    ;;
  *"curl "*"|"*"sh"*|*"curl "*"| "*"bash"*|*"wget "*"|"*"sh"*|*"wget "*"| "*"bash"*)
    echo "BLOCKED: Pipe-to-shell detected. Download and inspect scripts before running." >&2
    exit 2
    ;;
  *"eval "*)
    if echo "$COMMAND" | grep -q 'curl\|wget'; then
      echo "BLOCKED: eval with remote content is dangerous." >&2
      exit 2
    fi
    ;;
  *"chmod 777"*)
    echo "BLOCKED: chmod 777 makes files world-writable. Use specific permissions." >&2
    exit 2
    ;;
  *"launchctl load"*)
    if ! echo "$COMMAND" | grep -qE '(com\.apple\.|homebrew)'; then
      echo "WARNING: launchctl load of unknown plist. Logging." >&2
      echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) LAUNCHCTL: $COMMAND" >> "$HOME/.claude/hooks/destructive.log"
    fi
    ;;
  *"networksetup -set"*)
    echo "BLOCKED: Network configuration change. Run manually if intended." >&2
    exit 2
    ;;
  *"> /etc/"*|*"tee /etc/"*)
    echo "BLOCKED: Write to /etc detected. Run manually if intended." >&2
    exit 2
    ;;
esac

exit 0
