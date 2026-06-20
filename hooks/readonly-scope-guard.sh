#!/bin/bash
# Read-Only + Scope-Guard enforcement  (PreToolUse: Edit|Write|MultiEdit|NotebookEdit)
# Ports Dan Mercede's `readonly` + `scope-guard` skill CONTRACTS into a hard structural rail.
# Markers (ABSENT by default => hook is inert/safe):
#   ~/.claude/state/readonly.json    {"active":true,"reason":"..."}
#   ~/.claude/state/scope-guard.json {"active":true,"scope":"...","allowed":[...],"excluded":[...]}
# Manage markers via ~/.claude/scripts/readonly-mode.sh  and  ~/.claude/scripts/scope-guard.sh
# Exit 2 = DENY (stderr shown to the model). Exit 0 = allow.

STATE="$HOME/.claude/state"
RO="$STATE/readonly.json"
SG="$STATE/scope-guard.json"

# Fast path: neither marker present => nothing to enforce.
[ -f "$RO" ] || [ -f "$SG" ] || exit 0

INPUT=$(cat)

is_active() { [ -f "$1" ] && [ "$(jq -r '.active // false' "$1" 2>/dev/null)" = "true" ]; }

# ---- READ-ONLY MODE: deny ALL file writes ----
if is_active "$RO"; then
  REASON=$(jq -r '.reason // "read-only session"' "$RO" 2>/dev/null)
  echo "BLOCKED (read-only mode): file writes are denied this session — ${REASON}. Clear with: ~/.claude/scripts/readonly-mode.sh off" >&2
  exit 2
fi

# ---- SCOPE-GUARD: deny out-of-scope writes ----
if is_active "$SG"; then
  FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // .tool_input.notebook_path // empty' 2>/dev/null)
  [ -z "$FILE_PATH" ] && exit 0
  case "$FILE_PATH" in /*) ABS="$FILE_PATH" ;; *) ABS="$PWD/$FILE_PATH" ;; esac

  # target is under any of the glob/prefix entries fed on stdin (one per line)
  under_any() {
    local target="$1" g base
    while IFS= read -r g; do
      [ -z "$g" ] && continue
      base="${g%/\*\*}"; base="${base%/\*}"; base="${base%/}"
      [ -z "$base" ] && continue
      [ "$target" = "$base" ] && return 0
      case "$target" in "$base"/*) return 0 ;; esac
    done
    return 1
  }

  # excluded wins over allowed
  if jq -r '.excluded[]?' "$SG" 2>/dev/null | grep -q . && \
     under_any "$ABS" < <(jq -r '.excluded[]?' "$SG" 2>/dev/null); then
    echo "BLOCKED (scope-guard): ${ABS} is inside an EXCLUDED path (scope: $(jq -r '.scope // "?"' "$SG" 2>/dev/null)). Expand scope or edit by hand." >&2
    exit 2
  fi

  # if an allow-list is declared, target must fall inside it
  if jq -r '.allowed[]?' "$SG" 2>/dev/null | grep -q .; then
    if ! under_any "$ABS" < <(jq -r '.allowed[]?' "$SG" 2>/dev/null); then
      echo "BLOCKED (scope-guard): ${ABS} is OUTSIDE declared write scope [$(jq -r '.allowed | join(", ")' "$SG" 2>/dev/null)]. Expand scope or edit by hand." >&2
      exit 2
    fi
  fi
fi

exit 0
