#!/usr/bin/env bash
# egress-guard.sh: PreToolUse exfiltration and untrusted-fetch guard for Claude Code
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
#   fetches in an isolated context, not here.
#
# Wire in ~/.claude/settings.json PreToolUse. Matcher must include every guarded tool
# (see settings.example.json).
# Exit codes: 0 = allow, 2 = block. Claude Code treats any other non-zero exit as a
# non-blocking error and runs the call, so a block must exit 2.
# No here-document or here-string: bash 3.2 writes them to a temp file, and on a full
# disk that write fails and the reads come back empty. Everything goes through pipes.
# Allow-list: ~/.claude/allowlist-domains.txt
#   Created as comments only when missing, so every SEND blocks until the owner adds a domain.
# Optional known-bad fetch domains: ~/.claude/blocklist-domains.txt

set -uo pipefail   # NOT -e: a jq miss must not abort the guard
# The C locale keeps [a-z] and tr to ASCII, so a host with any other letter fails the character checks.
export LC_ALL=C

ALLOWLIST="$HOME/.claude/allowlist-domains.txt"
BLOCKLIST="$HOME/.claude/blocklist-domains.txt"   # optional known-bad fetch domains (one/line)
LOG="$HOME/.claude/artifacts/logs/egress-guard.log"
mkdir -p "$(dirname "$LOG")" 2>/dev/null || true

# Credential / secret-shaped patterns. Conservative: real keys and paths, not normal prose.
SECRET_RE='(~/?\.ssh|/\.ssh/|id_rsa|id_ed25519|BEGIN [A-Z ]*PRIVATE KEY|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|xox[baprs]-[0-9A-Za-z-]{10,}|gh[pousr]_[0-9A-Za-z]{20,}|sk-[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{20,}|secret[_-]?(key|token)|password["'"'"' :=]{1,3}[^ ]|aws_secret|1password|op://)'

INPUT="$(cat 2>/dev/null || true)"

# Match with bash's own regex, never `printf | grep -q`: under pipefail, grep -q exits at the
# first match, printf dies of SIGPIPE on a payload past the 64 KB pipe buffer, and the pipeline
# reads as false, so a secret near the start of a long URL or query would pass.
# A match sets SECRET_HINT to its first four characters and its length, so a block can say what
# matched without printing the secret into the agent's context or the log.
SECRET_HINT=""
has_secret() {
  local rc
  shopt -s nocasematch
  [[ "$1" =~ $SECRET_RE ]]
  rc=$?
  shopt -u nocasematch
  if [[ "$rc" -eq 0 ]]; then
    SECRET_HINT="${BASH_REMATCH[0]:0:4}... (${#BASH_REMATCH[0]} characters, not shown)"
  fi
  return "$rc"
}

ts() { date -Iseconds; }
logline() { echo "$(ts) $*" >> "$LOG" 2>/dev/null || true; }

notify() { osascript -e "display notification \"$1\" with title \"Egress guard\" subtitle \"$2\" sound name \"Basso\"" 2>/dev/null || true; }

TOOL_NAME="unknown"
block() { # $1 = short reason (notify), $2 = detail for stderr/log
  notify "$TOOL_NAME blocked" "$1"
  logline "BLOCK tool=$TOOL_NAME reason=$1 detail=$2"
  printf '%s\n' "BLOCKED by egress-guard: $1" "" "Tool: $TOOL_NAME" "$2" "" \
    "If this is legitimate:" \
    "  - SEND target: add the domain to $ALLOWLIST" \
    "  - FETCH/SEARCH flagged a secret-shaped string: re-issue without the credential in the URL/query," \
    "    or route the fetch through an isolated quarantine sub-agent instead." >&2
  exit 2
}

# A missing allow-list is comments only. Redirections apply left to right, so stderr is
# dropped before the file is opened and a failed create prints nothing. An existing file
# is never rewritten.
ensure_allowlist() {
  [[ -f "$ALLOWLIST" ]] && return 0
  printf '%s\n' \
    '# Domains a SEND tool may reach.' \
    '# One domain per line. Subdomains of a listed domain are included.' \
    2>/dev/null > "$ALLOWLIST" || true
}

# One list entry: a carriage return and surrounding spaces dropped, lowercased. Sets ENTRY.
clean_entry() {
  ENTRY="${1%$'\r'}"
  ENTRY="${ENTRY#"${ENTRY%%[![:space:]]*}"}"
  ENTRY="${ENTRY%"${ENTRY##*[![:space:]]}"}"
  ENTRY="$(printf '%s' "$ENTRY" | tr '[:upper:]' '[:lower:]')"
}

# $1 is on list file $2: an exact match or a subdomain of a listed line. Comments and blank
# lines are skipped, and a last line with no newline still counts.
list_match() {
  local line
  [[ -r "$2" ]] || return 1
  while IFS= read -r line || [[ -n "$line" ]]; do
    clean_entry "$line"
    [[ "$ENTRY" =~ ^# || -z "$ENTRY" ]] && continue
    if [[ "$1" == "$ENTRY" || "$1" == *".$ENTRY" ]]; then
      return 0
    fi
  done < "$2"
  return 1
}

# The list file $1 holds at least one domain.
list_in_use() {
  local line
  [[ -r "$1" ]] || return 1
  while IFS= read -r line || [[ -n "$line" ]]; do
    clean_entry "$line"
    [[ "$ENTRY" =~ ^# || -z "$ENTRY" ]] && continue
    return 0
  done < "$1"
  return 1
}

domain_allowed() { list_match "$1" "$ALLOWLIST"; }

# Host from a URL. Caller secret-scans the raw destination first.
# Scheme is [A-Za-z][A-Za-z0-9+.-]*://. Authority runs to the first / ? # or backslash.
# SEND: a raw backslash blocks, and an authority that holds @ blocks. FETCH: the host is
# the authority after the last @. Then drop a trailing :port, lowercase, and remove one
# trailing dot. SEND also blocks a host outside [a-z0-9.-]. Sets DOMAIN.
host_from_url() {
  local url="$1" class="$2" rest auth host
  if [[ "$class" == "send" && "$url" == *\\* ]]; then
    block "URL contains a backslash, failing closed" "Dest: ${url:0:200}"
  fi
  rest="$url"
  if [[ "$url" =~ ^[A-Za-z][A-Za-z0-9+.-]*:// ]]; then
    rest="${url:${#BASH_REMATCH[0]}}"
  fi
  auth="${rest%%[/?#\\]*}"
  if [[ "$class" == "send" && "$auth" == *@* ]]; then
    block "URL carries user info, failing closed" "Dest: ${url:0:200}"
  fi
  if [[ "$class" == "fetch" ]]; then
    host="${auth##*@}"
  else
    host="$auth"
  fi
  if [[ "$host" =~ ^(.*):[0-9]+$ ]]; then
    host="${BASH_REMATCH[1]}"
  fi
  host="$(printf '%s' "$host" | tr '[:upper:]' '[:lower:]')"
  host="${host%.}"
  if [[ "$class" == "send" ]]; then
    if [[ ! "$host" =~ ^[a-z0-9.-]+$ ]]; then
      block "URL host has characters outside the allowed set, failing closed" "Host: $host"
    fi
  fi
  DOMAIN="$host"
}

# One JSON object per present, non-empty recipient field, at any depth of tool_input. A key is a
# recipient field when its name, in any case, is to, cc, bcc, recipient(s), email(s),
# address(es), or to, cc or bcc joined to one of those or to list (toRecipients, cc_addresses).
# Every string under that key is recipient text. from, sender and reply_to are not destinations.
recipient_fields() {
  jq -c '
    def as_text:
      if type == "string" then .
      elif type == "array" or type == "object" then [.. | strings] | join("\n")
      elif . == null then ""
      else tostring
      end;
    def is_nonempty:
      if . == null then false
      elif type == "string" then . != ""
      elif type == "array" or type == "object" then length > 0
      else true
      end;
    def rkey: ascii_downcase
      | test("^(to|cc|bcc|recipients?|emails?|address(es)?|(to|cc|bcc)_?(recipients?|address(es)?|emails?|list))$");
    def skipkey: ascii_downcase | test("^(from|sender|reply_?to)$");
    def fields:
      if type == "object" then
        to_entries[]
        | select(.key | skipkey | not)
        | if (.key | rkey) then (select(.value | is_nonempty) | {k: .key, t: (.value | as_text)})
          else (.value | fields) end
      elif type == "array" then .[] | fields
      else empty
      end;
    (.tool_input // {}) | fields
  '
}

# Every URL a tool call names, one per line: url, params.url, each urls entry, input.url, each
# input.startUrls url, request.url. A value that is not a string is printed as JSON text, so it
# reaches the host check and fails it.
all_urls() {
  jq -r '
    (.tool_input // {}) as $in
    | [($in.url?), ($in.params.url?), ($in.urls[]?), ($in.input.url?),
       ($in.input.startUrls[]?.url?), ($in.request.url?)]
    | map(select(. != null and . != "") | if type == "string" then . else tostring end)[]
  '
}

# Addresses are runs without whitespace, comma, semicolon, quote, or angle bracket that contain @.
# Every recipient address and every URL must be on the allow-list. A send with neither blocks.
guard_send() {
  local recs rec key text tokens tok found domain atless accepted="" urls u checked=0
  urls="$(printf '%s' "$INPUT" | all_urls 2>/dev/null)" || block "could not read the tool call, failing closed" "jq could not read the URL fields"
  if [[ -n "$urls" ]] && has_secret "$urls"; then
    block "destination carries secret-shaped text (possible exfiltration)" "Matched: $SECRET_HINT"
  fi
  recs="$(printf '%s' "$INPUT" | recipient_fields 2>/dev/null)" || block "could not read the tool call, failing closed" "jq could not parse recipients"
  ensure_allowlist
  while IFS= read -r rec || [[ -n "$rec" ]]; do
    [[ -z "$rec" ]] && continue
    key="$(printf '%s' "$rec" | jq -r '.k // empty')" || block "could not read a recipient, failing closed" "jq could not read a recipient field"
    text="$(printf '%s' "$rec" | jq -r '.t // empty')" || block "could not read a recipient, failing closed" "jq could not read a recipient field"
    if [[ -n "$text" ]] && has_secret "$text"; then
      block "destination carries secret-shaped text (possible exfiltration)" "Matched: $SECRET_HINT"
    fi
    tokens="$(printf '%s' "$text" | tr '[:space:],;"'"'"'<>' '\n')"
    found=0
    while IFS= read -r tok || [[ -n "$tok" ]]; do
      [[ -z "$tok" ]] && continue
      [[ "$tok" == *@* ]] || continue
      found=1
      atless="${tok//@/}"
      if [[ $(( ${#tok} - ${#atless} )) -gt 1 ]]; then
        block "recipient address has more than one @, failing closed" "Address: ${tok:0:160}"
      fi
      domain="${tok#*@}"
      domain="$(printf '%s' "$domain" | tr '[:upper:]' '[:lower:]')"
      domain="${domain%.}"
      if [[ ! "$domain" =~ ^[a-z0-9.-]+$ ]]; then
        block "recipient domain has characters outside the allowed set, failing closed" "Domain: $domain"
      fi
      if ! domain_allowed "$domain"; then
        block "SEND to a domain not on the allow-list" "Domain: $domain  Dest: ${tok:0:160}"
      fi
      accepted="${accepted:+$accepted }$domain"
      checked=$((checked + 1))
    done < <(printf '%s\n' "$tokens")
    if [[ "$found" -eq 0 ]]; then
      block "could not read a recipient, failing closed" "field ${key:-recipient} held no address"
    fi
  done < <(printf '%s\n' "$recs")
  # A send that names recipients and URLs reaches all of them, so every URL host is checked too.
  while IFS= read -r u || [[ -n "$u" ]]; do
    [[ -z "$u" ]] && continue
    host_from_url "$u" send
    if ! domain_allowed "$DOMAIN"; then
      block "SEND to a domain not on the allow-list" "Domain: $DOMAIN  Dest: ${u:0:160}"
    fi
    accepted="${accepted:+$accepted }$DOMAIN"
    checked=$((checked + 1))
  done < <(printf '%s\n' "$urls")
  if [[ "$checked" -eq 0 ]]; then
    block "could not read recipient of a SEND tool, failing closed" "tool_input had no recipient or URL field"
  fi
  logline "ALLOW tool=$TOOL_NAME class=send domain=$accepted"
  exit 0
}

# Empty stdin and a missing tool_name are unreadable payloads: fail closed.
if [[ -z "$INPUT" ]]; then
  block "empty hook payload, failing closed" "stdin was empty"
fi

# A payload this hook cannot read belongs to a guarded tool (the matcher sent it here).
if ! TOOL_NAME="$(printf '%s' "$INPUT" | jq -r '.tool_name // empty' 2>/dev/null)"; then
  TOOL_NAME="unknown"
  block "could not read the tool call, failing closed" "jq could not parse the hook payload"
fi
if [[ -z "$TOOL_NAME" ]]; then
  TOOL_NAME="unknown"
  block "hook payload has no tool_name, failing closed" "tool_name was empty"
fi

# ---- classify the tool ----------------------------------------------------------
# web_search and web_fetch are alternate names for the same search and fetch tools.
CLASS=""
case "$TOOL_NAME" in
  *send_email|*Gmail__send*|*create_draft|*notion-create-pages|*notion-update-page|*slack*post*Message|*__webhook*)
    CLASS=send ;;
  WebSearch|web_search|*exa__web_search*|*exa__deep_researcher_start|*apify__search-actors|*apify__search-apify-docs)
    CLASS=search ;;
  WebFetch|web_fetch|*ref__ref_read_url|*exa__crawling_exa|*exa__company_research_exa|*apify__rag-web-browser|*apify__apify--rag-web-browser|*apify__call-actor)
    CLASS=fetch ;;
  *)
    exit 0 ;;  # not guarded
esac

# ---- SEARCH: no destination domain; the leak risk is secrets in what the search sends ----
# Every string in tool_input is scanned, since every field goes to the search provider.
if [[ "$CLASS" == "search" ]]; then
  SEARCH_TEXT="$(printf '%s' "$INPUT" | jq -r '[(.tool_input // {}) | .. | strings] | join("\n")' 2>/dev/null)" || block "could not read the tool call, failing closed" "jq could not read the search fields"
  if [[ -n "$SEARCH_TEXT" ]] && has_secret "$SEARCH_TEXT"; then
    block "search query contains secret-shaped text" "Matched: $SECRET_HINT"
  fi
  QUERY="$(printf '%s' "$INPUT" | jq -r '
    .tool_input.query // .tool_input.q // .tool_input.search // .tool_input.prompt
    // .tool_input.input.query // empty' 2>/dev/null || echo "")"
  logline "ALLOW tool=$TOOL_NAME class=search query=\"${QUERY:0:120}\""
  exit 0
fi

# ---- SEND: every recipient and every URL ----------------------------------------
if [[ "$CLASS" == "send" ]]; then
  guard_send
fi

# ---- FETCH: secret scan of every URL, then each host against the optional blocklist ----
URLS="$(printf '%s' "$INPUT" | all_urls 2>/dev/null)" || block "could not read the tool call, failing closed" "jq could not read the URL fields"
if [[ -z "$URLS" ]]; then
  block "could not read URL of a FETCH tool, failing closed" "tool_input had no url field"
fi

if has_secret "$URLS"; then
  block "destination carries secret-shaped text (possible exfiltration)" "Matched: $SECRET_HINT"
fi

BLOCKLIST_ON=0
list_in_use "$BLOCKLIST" && BLOCKLIST_ON=1
FETCHED=""
while IFS= read -r u || [[ -n "$u" ]]; do
  [[ -z "$u" ]] && continue
  host_from_url "$u" fetch
  if [[ "$BLOCKLIST_ON" -eq 1 ]]; then
    # A percent escape or any other character outside a-z, 0-9, dot and hyphen could name a
    # blocklisted host in a form the comparison below would miss.
    if [[ ! "$DOMAIN" =~ ^[a-z0-9.-]+$ ]]; then
      block "fetch host has characters outside a-z, 0-9, dot and hyphen, so the blocklist cannot be checked" "Host: ${DOMAIN:0:160}"
    fi
    if list_match "$DOMAIN" "$BLOCKLIST"; then
      block "fetch target is on the known-bad blocklist" "Domain: $DOMAIN"
    fi
  fi
  FETCHED="${FETCHED:+$FETCHED }$DOMAIN"
done < <(printf '%s\n' "$URLS")
logline "ALLOW tool=$TOOL_NAME class=fetch domain=$FETCHED"
exit 0
