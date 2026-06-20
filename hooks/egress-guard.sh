#!/usr/bin/env bash
# egress-guard.sh — PreToolUse exfiltration + untrusted-fetch guard for Claude Code
#
# RISK MODEL:
#   The danger is data LEAVING the machine, NOT pages coming in. So:
#     SEND   tools (email / draft / notion-create / webhook) -> domain allow-list,
#            FAIL CLOSED (block if destination can't be read). This is the real exfil leg.
#     SEARCH tools (WebSearch / Exa / Apify search)          -> scan the QUERY for
#            secret-shaped text (exfil via query); block that, else allow + log.
#     FETCH  tools (WebFetch GET / Exa crawl / ref read url)  -> reading is inbound, so
#            do NOT domain-restrict (that just breaks research). Scan the URL for
#            secret-shaped text (exfil via GET querystring) + an optional blocklist.
#   Untrusted *content* is best handled downstream by a quarantine sub-agent that
#   fetches in an isolated context — not here.
#
# Wire in ~/.claude/settings.json PreToolUse. Matcher must include every guarded tool
# (see settings.example.json). Exit codes:  0 = allow  |  1 = block.

set -uo pipefail   # NOT -e: a jq miss must not abort the guard

ALLOWLIST="$HOME/.claude/allowlist-domains.txt"
BLOCKLIST="$HOME/.claude/blocklist-domains.txt"   # optional known-bad fetch domains (one/line)
LOG="$HOME/.claude/artifacts/logs/egress-guard.log"
mkdir -p "$(dirname "$LOG")"

# Credential / secret-shaped patterns. Conservative — real keys/paths, not normal prose.
SECRET_RE='(~/?\.ssh|/\.ssh/|id_rsa|id_ed25519|BEGIN [A-Z ]*PRIVATE KEY|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|xox[baprs]-[0-9A-Za-z-]{10,}|gh[pousr]_[0-9A-Za-z]{20,}|sk-[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{20,}|secret[_-]?(key|token)|password["'"'"' :=]{1,3}[^ ]|aws_secret|1password|op://)'

INPUT="$(cat 2>/dev/null || true)"
[[ -z "$INPUT" ]] && exit 0

TOOL_NAME="$(jq -r '.tool_name // empty' <<<"$INPUT" 2>/dev/null || echo "")"
[[ -z "$TOOL_NAME" ]] && exit 0

ts() { date -Iseconds; }
logline() { echo "$(ts) $*" >> "$LOG"; }

notify() { osascript -e "display notification \"$1\" with title \"Egress guard\" subtitle \"$2\" sound name \"Basso\"" 2>/dev/null || true; }

block() { # $1 = short reason (notify), $2 = detail for stderr/log
  notify "$TOOL_NAME blocked" "$1"
  logline "BLOCK tool=$TOOL_NAME reason=$1 detail=$2"
  cat >&2 <<EOF
BLOCKED by egress-guard: $1

Tool: $TOOL_NAME
$2

If this is legitimate:
  - SEND target: add the domain to $ALLOWLIST
  - FETCH/SEARCH flagged a secret-shaped string: re-issue without the credential in the URL/query,
    or route the fetch through an isolated quarantine sub-agent instead.
EOF
  exit 1
}

# ---- classify the tool ----------------------------------------------------------
CLASS=""
case "$TOOL_NAME" in
  *send_email|*Gmail__send*|*create_draft|*notion-create-pages|*notion-update-page|*slack*post*Message|*__webhook*)
    CLASS=send ;;
  WebSearch|*exa__web_search*|*exa__deep_researcher_start|*apify__search-actors|*apify__search-apify-docs)
    CLASS=search ;;
  WebFetch|*ref__ref_read_url|*exa__crawling_exa|*exa__company_research_exa|*apify__rag-web-browser|*apify__apify--rag-web-browser|*apify__call-actor)
    CLASS=fetch ;;
  *)
    exit 0 ;;  # not guarded
esac

# ---- pull candidate destination + query from many tool shapes -------------------
DEST="$(jq -r '
  .tool_input.url // .tool_input.to // .tool_input.recipient // .tool_input.email
  // .tool_input.params.url // (.tool_input.urls[0]? // empty)
  // .tool_input.input.url // (.tool_input.input.startUrls[0].url? // empty)
  // .tool_input.request.url // empty' <<<"$INPUT" 2>/dev/null || echo "")"

QUERY="$(jq -r '
  .tool_input.query // .tool_input.q // .tool_input.search // .tool_input.prompt
  // .tool_input.input.query // empty' <<<"$INPUT" 2>/dev/null || echo "")"

# ---- SEARCH: no destination domain; the leak risk is secrets inside the query ----
if [[ "$CLASS" == "search" ]]; then
  if [[ -n "$QUERY" ]] && grep -iqE "$SECRET_RE" <<<"$QUERY"; then
    block "search query contains secret-shaped text" "Query: ${QUERY:0:160}"
  fi
  logline "ALLOW tool=$TOOL_NAME class=search query=\"${QUERY:0:120}\""
  exit 0
fi

# ---- FETCH/SEND both need a destination ------------------------------------------
if [[ -z "$DEST" ]]; then
  if [[ "$CLASS" == "send" ]]; then
    block "could not read recipient of a SEND tool — failing closed" "tool_input had no to/recipient/email/url field"
  fi
  # fetch with no extractable url: can't scan it -> fail closed (better safe)
  block "could not read URL of a FETCH tool — failing closed" "tool_input had no url field"
fi

# Secret smuggled into the destination itself (exfil via GET querystring or mailto body)
if grep -iqE "$SECRET_RE" <<<"$DEST"; then
  block "destination carries secret-shaped text (possible exfiltration)" "Dest: ${DEST:0:200}"
fi

# Extract domain
if [[ "$DEST" == *@* && "$DEST" != *://* ]]; then
  DOMAIN="$(awk -F'@' '{print $NF}' <<<"$DEST" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')"
else
  DOMAIN="$(sed -E 's|^[a-zA-Z]+://||' <<<"$DEST" | cut -d'/' -f1 | cut -d'?' -f1 | cut -d':' -f1 | tr '[:upper:]' '[:lower:]')"
fi

# ---- FETCH: allow any domain (reading is inbound) unless on the optional blocklist ----
if [[ "$CLASS" == "fetch" ]]; then
  if [[ -f "$BLOCKLIST" ]]; then
    while IFS= read -r bad; do
      [[ "$bad" =~ ^# || -z "$bad" ]] && continue
      if [[ "$DOMAIN" == "$bad" || "$DOMAIN" == *".$bad" ]]; then
        block "fetch target is on the known-bad blocklist" "Domain: $DOMAIN"
      fi
    done < "$BLOCKLIST"
  fi
  logline "ALLOW tool=$TOOL_NAME class=fetch domain=$DOMAIN"
  exit 0
fi

# ---- SEND: enforce the domain allow-list (this is the real exfil channel) ---------
if [[ ! -f "$ALLOWLIST" ]]; then
  printf 'anthropic.com\nclaude.ai\nplatform.claude.com\ngmail.com\n' > "$ALLOWLIST"
fi
ALLOWED=0
while IFS= read -r line; do
  [[ "$line" =~ ^# || -z "$line" ]] && continue
  if [[ "$DOMAIN" == "$line" || "$DOMAIN" == *".$line" ]]; then ALLOWED=1; break; fi
done < "$ALLOWLIST"

if [[ "$ALLOWED" == "1" ]]; then
  logline "ALLOW tool=$TOOL_NAME class=send domain=$DOMAIN"
  exit 0
fi
block "SEND to a domain not on the allow-list" "Domain: $DOMAIN  Dest: ${DEST:0:160}"
