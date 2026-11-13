#!/usr/bin/env bash
# HarnessGuard installer: copies hooks into ~/.claude/hooks and prints the settings snippet.
set -euo pipefail

SRC="$(cd "$(dirname "$0")" && pwd)/hooks"
DEST="$HOME/.claude/hooks"

mkdir -p "$DEST"
echo "Installing HarnessGuard hooks → $DEST"
for f in "$SRC"/*.sh; do
  name="$(basename "$f")"
  if [[ -f "$DEST/$name" ]]; then
    echo "  • $name already exists, backing up to $name.bak"
    cp "$DEST/$name" "$DEST/$name.bak"
  fi
  cp "$f" "$DEST/$name"
  chmod +x "$DEST/$name"
  echo "  ✓ $name"
done

# Domain lines, counted the way the hook reads them: drop a trailing CR, trim spaces,
# and skip blanks and comments. Missing, or none of those lines, means it is still empty.
allowlist="$HOME/.claude/allowlist-domains.txt"
domain_lines=0
if [[ -f "$allowlist" ]]; then
  while IFS= read -r line || [[ -n "$line" ]]; do
    entry="${line%$'\r'}"
    entry="${entry#"${entry%%[![:space:]]*}"}"
    entry="${entry%"${entry##*[![:space:]]}"}"
    [[ -z "$entry" || "$entry" =~ ^# ]] && continue
    domain_lines=$((domain_lines + 1))
  done < "$allowlist"
fi
if [[ "$domain_lines" -eq 0 ]]; then
  echo 'egress-guard: ~/.claude/allowlist-domains.txt starts empty, so every send is blocked until you add the domains you send to.'
else
  domain_word=domains
  [[ "$domain_lines" -eq 1 ]] && domain_word=domain
  echo "egress-guard: the allow-list keeps its $domain_lines $domain_word."
fi

echo ""
echo "Setting hook-integrity baseline…"
"$DEST/verify-integrity.sh" generate || true

echo ""
echo "Done. Final step: merge the 'hooks' block from settings.example.json into:"
echo "    $HOME/.claude/settings.json"
echo "Then restart Claude Code. Read each hook first; they're short and they block tool calls."
