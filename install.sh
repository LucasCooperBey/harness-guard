#!/usr/bin/env bash
# HarnessGuard installer — copies hooks into ~/.claude/hooks and prints the settings snippet.
set -euo pipefail

SRC="$(cd "$(dirname "$0")" && pwd)/hooks"
DEST="$HOME/.claude/hooks"

mkdir -p "$DEST"
echo "Installing HarnessGuard hooks → $DEST"
for f in "$SRC"/*.sh; do
  name="$(basename "$f")"
  if [[ -f "$DEST/$name" ]]; then
    echo "  • $name already exists — backing up to $name.bak"
    cp "$DEST/$name" "$DEST/$name.bak"
  fi
  cp "$f" "$DEST/$name"
  chmod +x "$DEST/$name"
  echo "  ✓ $name"
done

echo ""
echo "Setting hook-integrity baseline…"
"$DEST/verify-integrity.sh" generate || true

echo ""
echo "Done. Final step: merge the 'hooks' block from settings.example.json into:"
echo "    $HOME/.claude/settings.json"
echo "Then restart Claude Code. Read each hook first — they're short and they block tool calls."
