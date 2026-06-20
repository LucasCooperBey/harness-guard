#!/bin/bash
# Hook Integrity Verification
# Generates and verifies checksums of all hook scripts
# Run on SessionStart to detect tampering

HOOKS_DIR="$HOME/.claude/hooks"
INTEGRITY_FILE="$HOOKS_DIR/.integrity"

generate() {
  find "$HOOKS_DIR" -maxdepth 1 -type f \( -name "*.sh" -o -name "*.py" \) ! -name ".integrity" | sort | xargs shasum -a 256 > "$INTEGRITY_FILE"
  echo "Generated integrity checksums for $(wc -l < "$INTEGRITY_FILE" | tr -d ' ') hook files"
}

verify() {
  if [[ ! -f "$INTEGRITY_FILE" ]]; then
    echo "WARNING: No integrity file found. Run 'verify-integrity.sh generate' first." >&2
    return 1
  fi

  if shasum -a 256 --check "$INTEGRITY_FILE" --quiet 2>/dev/null; then
    exit 0
  else
    CHANGED=$(shasum -a 256 --check "$INTEGRITY_FILE" 2>&1 | grep -c "FAILED")
    echo "ALERT: $CHANGED hook file(s) have been modified since last baseline!" >&2
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) INTEGRITY_FAIL: $CHANGED files changed" >> "$HOOKS_DIR/destructive.log"
    shasum -a 256 --check "$INTEGRITY_FILE" 2>&1 | grep "FAILED" >&2
    exit 0  # Don't block session, just warn
  fi
}

case "${1:-verify}" in
  generate) generate ;;
  verify) verify ;;
  *) echo "Usage: $0 [generate|verify]" ;;
esac
