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
# Key shapes stay case-sensitive. sk- matches only when it does not continue a word: bash ERE
# has no lookbehind, so the left side is the start of the text or a non-alphanumeric character.
# Markers such as "password" are a second, case-insensitive pattern. That split keeps
# risk-based-security-assessment-guide and the phrase "password reset" from reading as secrets,
# while "password: hunter2hunter2" still matches.
SECRET_RE_CS='AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|xox[baprs]-[0-9A-Za-z-]{10,}|gh[pousr]_[0-9A-Za-z]{20,}|AIza[0-9A-Za-z_-]{20,}|(^|[^A-Za-z0-9])sk-[A-Za-z0-9_-]{20,}'
SECRET_RE_CI='(~/?\.ssh|/\.ssh/|id_rsa|id_ed25519|BEGIN [A-Z ]*PRIVATE KEY|secret[_-]?(key|token)|aws_secret|1password|op://|password['"'"'"]?[[:space:]]*[:=][[:space:]]*['"'"'"]?[^[:space:]'"'"'"]{4,})'

# Whole-value addresses. An address is the email shape, or Name <email> whose brackets hold
# that same shape. A body such as "see <file>" is not one.
ADDR_RE='^[^[:space:]@<>]+@[^[:space:]@<>]+$'
ANGLE_CAP='<([^<>]+)>$'
URL_RE='^[A-Za-z][A-Za-z0-9+.-]*://[^[:space:]]+$'
# Not anchored: a token may sit inside a display name, a list, or another field.
ADDR_TOKEN_RE='[^][[:space:],;<>"()]*@[^][[:space:],;<>"()]*'

INPUT="$(cat 2>/dev/null || true)"
DEST_JSON=""

# Match with bash's own regex, never `printf | grep -q`: under pipefail, grep -q exits at the
# first match, printf dies of SIGPIPE on a payload past the 64 KB pipe buffer, and the pipeline
# reads as false, so a secret near the start of a long URL or query would pass.
# A match sets SECRET_HINT to its first four characters and its length, so a block can say what
# matched without printing the secret into the agent's context or the log.
# A regex compile error (rc 2) counts as a match. Returning that rc unchanged would read as
# "no secret" and the call would pass.
SECRET_HINT=""
has_secret() {
  local rc
  SECRET_HINT=""
  shopt -u nocasematch
  [[ "$1" =~ $SECRET_RE_CS ]]
  rc=$?
  if [[ "$rc" -eq 0 ]]; then
    SECRET_HINT="${BASH_REMATCH[0]:0:4}... (${#BASH_REMATCH[0]} characters, not shown)"
    return 0
  fi
  if [[ "$rc" -eq 2 ]]; then
    SECRET_HINT="the secret pattern could not be evaluated"
    return 0
  fi
  shopt -s nocasematch
  [[ "$1" =~ $SECRET_RE_CI ]]
  rc=$?
  shopt -u nocasematch
  if [[ "$rc" -eq 0 ]]; then
    SECRET_HINT="${BASH_REMATCH[0]:0:4}... (${#BASH_REMATCH[0]} characters, not shown)"
    return 0
  fi
  if [[ "$rc" -eq 2 ]]; then
    SECRET_HINT="the secret pattern could not be evaluated"
    return 0
  fi
  return 1
}

ts() { date -Iseconds; }
logline() { echo "$(ts) $*" >> "$LOG" 2>/dev/null || true; }

# Arguments, never the script source. A tool name that closes a string must not become code.
notify() {
  osascript -e 'on run argv' \
    -e 'display notification (item 1 of argv) with title "Egress guard" subtitle (item 2 of argv) sound name "Basso"' \
    -e 'end run' "$1" "$2" 2>/dev/null || true
}

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

# A URL for a block message: the user info before the last @ in the authority becomes ***, so a
# password written into a URL before its host never reaches stderr or the egress log. The scheme
# is optional, and the redaction runs on the whole value before it is cut to 200 characters.
# source: 11-12 review, the user-info block printed the whole URL, password included
# source: 11-12 review of a121d06, a cut before the redaction could leave the start of a long password
# Everything up to the last @ is hidden, so a password holding an unencoded / ? or # is hidden
# too; an @ in a path hides a little more than needed, which a block message can afford.
# source: 11-12 review of aeb448c, a URL password holding a slash was kept
redact_userinfo() {
  local u="$1" re='^([A-Za-z][A-Za-z0-9+.-]*://)?.*@(.*)$' out
  if [[ "$u" =~ $re ]]; then
    out="${BASH_REMATCH[1]}***@${BASH_REMATCH[2]}"
  else
    out="$u"
  fi
  printf '%s' "${out:0:200}"
}

# An address token for a block message: only ***@ and what follows the last @ is shown. The
# token comes from a tokenizer that splits on ; and , so the part before the @ can be the tail
# of a URL password, and the domain is what the allow-list decides on.
# source: 11-12 security review of a121d06, an address-shaped token could carry a URL password
# source: 11-12 security review of aeb448c, a URL password holding ; showed its tail
shown_addr() {
  local a="***@${1##*@}"
  printf '%s' "${a:0:160}"
}

# A host or domain for a block message, with everything after its first : hidden. A
# URL whose password holds a slash has no @ in its authority, so the host read from it is
# the user name, a colon and the start of the password.
# source: 11-12 stub run of aeb448c, the host-character block printed the password
shown_host() {
  local h="$1"
  case "$h" in
    *:*) h="${h%%:*}:***" ;;
  esac
  printf '%s' "${h:0:160}"
}

# Host from a URL. Caller secret-scans the raw destination first.
# Scheme is [A-Za-z][A-Za-z0-9+.-]*://. Authority runs to the first / ? # or backslash.
# SEND: a raw backslash blocks, and an authority that holds @ blocks. FETCH: the host is
# the authority after the last @. Then drop a trailing :port, lowercase, and remove one
# trailing dot. SEND also blocks a host outside [a-z0-9.-]. Sets DOMAIN.
host_from_url() {
  local url="$1" class="$2" rest auth host
  if [[ "$class" == "send" && "$url" == *\\* ]]; then
    block "URL contains a backslash, failing closed" "Dest: $(redact_userinfo "$url")"
  fi
  rest="$url"
  if [[ "$url" =~ ^[A-Za-z][A-Za-z0-9+.-]*:// ]]; then
    rest="${url:${#BASH_REMATCH[0]}}"
  fi
  auth="${rest%%[/?#\\]*}"
  if [[ "$class" == "send" && "$auth" == *@* ]]; then
    block "URL carries user info, failing closed" "Dest: $(redact_userinfo "$url")"
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
      block "URL host has characters outside the allowed set, failing closed" "Host: $(shown_host "$host")"
    fi
  fi
  DOMAIN="$host"
}

trim_space() {
  local s="$1"
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf '%s' "$s"
}

# Double-quoted display names are removed before splitting. A comma inside the quotes belongs
# to the name, so "A, Person" <a@allowed.example> stays one address. A quote preceded by a
# backslash stays inside the name, so "Bob \" Smith" <a@allowed.example> stays one address.
# Single quotes stay, so an apostrophe in an address is not treated as a quote.
strip_double_quotes() {
  local s="$1" out="" i=0 c len prev
  len=${#s}
  prev=""
  while [ "$i" -lt "$len" ]; do
    c="${s:$i:1}"
    if [ "$c" = '"' ] && [ "$prev" != '\' ]; then
      i=$((i + 1))
      prev=""
      while [ "$i" -lt "$len" ]; do
        c="${s:$i:1}"
        if [ "$c" = '"' ] && [ "$prev" != '\' ]; then
          i=$((i + 1))
          prev=""
          break
        fi
        prev="$c"
        i=$((i + 1))
      done
    else
      out="${out}${c}"
      prev="$c"
      i=$((i + 1))
    fi
  done
  printf '%s' "$out"
}

# How many double quotes are not preceded by a backslash.
unescaped_quotes() {
  local s="$1" i=0 c prev n
  prev=""
  n=0
  while [ "$i" -lt "${#s}" ]; do
    c="${s:$i:1}"
    if [ "$c" = '"' ] && [ "$prev" != '\' ]; then
      n=$((n + 1))
    fi
    prev="$c"
    i=$((i + 1))
  done
  printf '%s' "$n"
}

# $1 address, $2 field name. Exactly one @, then the same domain rules as before.
accept_address() {
  local addr="$1" key="$2" atless domain count
  atless="${addr//@/}"
  count=$(( ${#addr} - ${#atless} ))
  if [[ "$count" -gt 1 ]]; then
    block "recipient address has more than one @, failing closed" "Address: $(shown_addr "$addr")"
  fi
  if [[ "$count" -ne 1 ]]; then
    block "could not read a recipient, failing closed" "field ${key:-recipient} held no address"
  fi
  domain="${addr#*@}"
  domain="$(printf '%s' "$domain" | tr '[:upper:]' '[:lower:]')"
  domain="${domain%.}"
  if [[ ! "$domain" =~ ^[a-z0-9.-]+$ ]]; then
    block "recipient domain has characters outside the allowed set, failing closed" "Domain: $(shown_host "$domain")"
  fi
  if ! domain_allowed "$domain"; then
    block "SEND to a domain not on the allow-list" "Domain: $domain  Dest: $(shown_addr "$addr")"
  fi
  accepted="${accepted:+$accepted }$domain"
  checked=$((checked + 1))
}

# Address-shaped tokens in $1, each checked with accept_address. grep status 0 or 1 means the
# scan finished. Any other status means it did not run, so the call fails closed.
# source: 11-12 review of 6e5d69b, grep -oE with || true turned a scan error into no tokens
accept_tokens_in() {
  local raw="$1" key="$2" token rc found
  found="$(printf '%s\n' "$raw" | grep -aoE "$ADDR_TOKEN_RE")"
  rc=$?
  if [[ "$rc" -gt 1 ]]; then
    block "could not read a recipient, failing closed" "the address scan could not run"
  fi
  while IFS= read -r token || [[ -n "$token" ]]; do
    [[ -z "$token" ]] && continue
    accept_address "$token" "$key"
  done < <(printf '%s\n' "$found")
}

# Split a recipient string on comma, semicolon and newline. Empty entries are skipped.
# anything <addr> yields addr. One token with no whitespace is the address. Anything else blocks.
consume_recipient_text() {
  local raw="$1" key="$2" stripped entries entry addr found=0 qcount
  # Every address-shaped token in the raw value must pass, wherever it sits: inside quotes, before
  # the brackets or in a second pair of brackets. A mail tool may read any of them as the address,
  # so the structured parse below is a second check, never the only one.
  # source: 11-12 security review of 7afb44f, "x@evil.example" <a@allowed.example> passed
  # A quote preceded by a backslash is the character ", not a delimiter.
  # source: 11-12 review of 6e5d69b, "Bob \" Smith" <a@allowed.example> was blocked
  qcount="$(unescaped_quotes "$raw")"
  if (( qcount % 2 )); then
    block "could not read a recipient, failing closed" "field ${key:-recipient} has an unbalanced double quote"
  fi
  accept_tokens_in "$raw" "$key"
  stripped="$(strip_double_quotes "$raw")"
  entries="$(printf '%s' "$stripped" | tr $',;\n' '\n')"
  while IFS= read -r entry || [[ -n "$entry" ]]; do
    entry="$(trim_space "$entry")"
    [[ -z "$entry" ]] && continue
    if [[ "$entry" =~ $ANGLE_CAP ]]; then
      addr="${BASH_REMATCH[1]}"
      addr="$(trim_space "$addr")"
      # The display name before the brackets holds no bracket of its own: one address per entry.
      if [[ "${entry%<*}" == *[\<\>]* ]]; then
        block "could not read a recipient, failing closed" "field ${key:-recipient} held an entry that is not one address"
      fi
    elif [[ "$entry" != *[[:space:]]* ]]; then
      addr="$entry"
    else
      block "could not read a recipient, failing closed" "field ${key:-recipient} held an entry that is not one address"
    fi
    found=1
    accept_address "$addr" "$key"
  done < <(printf '%s\n' "$entries")
  if [[ "$found" -eq 0 ]]; then
    block "could not read a recipient, failing closed" "field ${key:-recipient} held no address"
  fi
}

# True when every comma or semicolon entry is an address. A string that is entirely a URL is a
# URL destination, not a recipient. The text inside <brackets> must itself be an address, so
# prose such as "see <file>" is not a destination.
whole_is_addresses() {
  local raw="$1" trimmed entries entry n=0 inside
  trimmed="$(trim_space "$raw")"
  if [[ -z "$trimmed" || "$trimmed" =~ $URL_RE ]]; then
    return 1
  fi
  entries="$(printf '%s' "$raw" | tr $',;' '\n')"
  while IFS= read -r entry || [[ -n "$entry" ]]; do
    entry="$(trim_space "$entry")"
    [[ -z "$entry" ]] && continue
    n=$((n + 1))
    if [[ "$entry" =~ $ADDR_RE ]]; then
      continue
    fi
    if [[ "$entry" =~ $ANGLE_CAP ]]; then
      inside="${BASH_REMATCH[1]}"
      inside="$(trim_space "$inside")"
      if [[ "$inside" =~ $ADDR_RE ]]; then
        continue
      fi
    fi
    return 1
  done < <(printf '%s\n' "$entries")
  [[ "$n" -gt 0 ]]
}

# One JSON object for tool_input. ctrl is decided here, on the decoded string, before the shell
# can split a URL on a newline. A string that starts with a scheme and :// and holds a control
# character counts, even when a tab or a newline means it is not a whole URL.
# Recipient keys keep the previous name rule. Subtrees named from, sender, reply_to or replyTo
# are ignored there. Name, displayName, display_name and label leaves inside a recipient value
# are ignored by that parse. Any other string that is entirely a URL is a destination too.
# addrs is a third list: every string leaf except those subtrees and except the prose fields
# subject, body, text, content, message, html and description. The shell checks each leaf for
# address-shaped tokens, so a name or an unlisted field is not a way around the allow-list.
# A string directly under an id field (inReplyTo, references, messageId, threadId, attachments,
# filename, file_path, path), or in an array there, is skipped except for each @host: in it,
# whose host is checked like an address domain. An object under an id field is walked as usual.
# The control-character rule reads every string leaf except the prose fields, from and sender
# included.
collect_destinations() {
  DEST_JSON="$(printf '%s' "$INPUT" | jq -c '
    def skipkey: ascii_downcase | test("^(from|sender|reply_?to)$");
    def rkey: ascii_downcase
      | test("^(to|cc|bcc|recipients?|emails?|address(es)?|(to|cc|bcc)_?(recipients?|address(es)?|emails?|list))$");
    def namekey: ascii_downcase | test("^(name|displayname|display_name|label)$");
    def prosekey: ascii_downcase | test("^(subject|body|text|content|message|html|description)$");
    # Message ids, thread ids and attachment names can hold an @ and are never destinations.
    # source: 11-12 review of a121d06, an inReplyTo Message-ID and img@2x.png blocked a reply
    def idkey: ascii_downcase | test("^(in_?reply_?to|references|message_?id|thread_?id|attachments?|file_?name|file_?path|path)$");
    def scheme_start:
      if type != "string" then false
      else test("^[A-Za-z][A-Za-z0-9+.-]*://")
      end;
    # source: 11-12 security review of aeb448c, a path of user@evil:/x was never checked
    # Every @host: in the string counts, wherever it sits, so a leading space or a second @
    # cannot hide one. The host is checked as id@host.
    # source: 11-12 security review of 318e887, " deploy@evil:/x" and "a@b@evil:/x" were skipped
    def scp_addr:
      match("@(?<h>[^@:]*):"; "g") | .captures[0].string
      | sub("^[[:space:]]+"; "") | sub("[[:space:]]+$"; "") | "id@" + .;
    def walk_addr($prose):
      # source: 11-12 security review of aeb448c, an object under attachments was skipped whole
      def id_addr:
        if type == "object" then walk_addr(false)
        elif type == "array" then .[] | id_addr
        elif type == "string" then scp_addr
        else empty
        end;
      if type == "object" then
        to_entries[]
        | select(.key | skipkey | not)
        | if (.key | idkey) then .value | id_addr
          else (.key | prosekey) as $p | .value | walk_addr($p)
          end
      elif type == "array" then
        if $prose then .[] | if type == "object" or type == "array" then walk_addr(false) else empty end
        else .[] | walk_addr(false)
        end
      elif type == "string" then
        if $prose or . == "" then empty else .
        end
      else empty
      end;
    def is_nonempty:
      if . == null then false
      elif type == "string" then . != ""
      elif type == "array" or type == "object" then length > 0
      else true
      end;
    def trimspace:
      sub("^[[:space:]]+"; "") | sub("[[:space:]]+$"; "");
    def looks_like_url:
      if type != "string" then false
      else trimspace | test("^[A-Za-z][A-Za-z0-9+.-]*://\\S+$")
      end;
    def has_ctrl:
      if type != "string" then false
      else any(explode[]?; . < 32 or . == 127)
      end;
    def recip_leaves:
      if type == "string" then select(. != "")
      elif type == "array" then .[] | recip_leaves
      elif type == "object" then
        to_entries[] | select(.key | namekey | not) | .value | recip_leaves
      elif . == null then empty
      else tostring
      end;
    def walk_recips:
      if type == "object" then
        to_entries[]
        | select(.key | skipkey | not)
        | if ((.key | rkey) and (.value | is_nonempty)) then
            {k: .key, t: (.value | recip_leaves)}
          else .value | walk_recips
          end
      elif type == "array" then .[] | walk_recips
      else empty
      end;
    def walk_strays:
      def id_strays:
        if type == "object" then walk_strays
        elif type == "array" then .[] | id_strays
        else empty
        end;
      if type == "object" then
        to_entries[]
        | select(.key | skipkey | not)
        | if (.key | rkey) then empty
          elif (.key | idkey) then .value | id_strays
          else .value | walk_strays
          end
      elif type == "array" then .[] | walk_strays
      elif type == "string" then select(looks_like_url | not)
      else empty
      end;
    # Every string leaf except prose, for the control-character rule.
    # source: 11-12 security review of aeb448c, a tab in a URL under from was no longer refused
    def walk_ctrl($prose):
      if type == "object" then
        to_entries[] | (.key | prosekey) as $p | .value | walk_ctrl($p)
      elif type == "array" then
        if $prose then .[] | if type == "object" or type == "array" then walk_ctrl(false) else empty end
        else .[] | walk_ctrl(false)
        end
      elif type == "string" then
        if $prose then empty else . end
      else empty
      end;
    def walk_urls:
      if type == "object" then
        to_entries[]
        | select(.key | skipkey | not)
        | .value | walk_urls
      elif type == "array" then .[] | walk_urls
      elif type == "string" then select(looks_like_url)
      else empty
      end;
    (.tool_input // {}) as $in
    | [ $in | walk_recips ] as $recips
    | [ $in | walk_strays ] as $strays
    | [ $in | walk_urls ] as $whole
    | [ ($in.url?), ($in.params.url?), ($in.urls[]?), ($in.input.url?),
        ($in.input.startUrls[]?.url?), ($in.request.url?) ]
      | map(select(. != null and . != "") | if type == "string" then . else tostring end) as $known
    | [ $known[], ($whole[] | trimspace) ] | map(select(. != "")) | unique as $urls
    | [ $known[], $whole[] ] as $raws
    | [ $in | walk_addr(false) ] as $addrs
    | {
        ctrl: (any($raws[]; has_ctrl) or any($in | walk_ctrl(false); scheme_start and has_ctrl)),
        urls: $urls,
        recips: $recips,
        strays: $strays,
        addrs: $addrs
      }
  ' 2>/dev/null)" || return 1
}

# The flag was computed in jq. Do not print the URL itself: a newline in it would split the line.
refuse_control_urls() {
  local ctrl
  ctrl="$(printf '%s' "$DEST_JSON" | jq -r '.ctrl' 2>/dev/null)" || block "could not read the tool call, failing closed" "jq could not read the URL fields"
  if [[ "$ctrl" == "true" ]]; then
    block "URL holds a control character, failing closed" "a URL contains a control character"
  fi
}

# Every recipient address and every URL must be on the allow-list. A send with neither blocks.
guard_send() {
  local recs rec key text stray_lines stray_json stray urls u addr_text checked_before accepted_before accepted="" checked=0
  collect_destinations || block "could not read the tool call, failing closed" "jq could not read the tool call"
  refuse_control_urls
  urls="$(printf '%s' "$DEST_JSON" | jq -r '.urls[]' 2>/dev/null)" || block "could not read the tool call, failing closed" "jq could not read the URL fields"
  if [[ -n "$urls" ]] && has_secret "$urls"; then
    block "destination carries secret-shaped text (possible exfiltration)" "Matched: $SECRET_HINT"
  fi
  recs="$(printf '%s' "$DEST_JSON" | jq -c '.recips[]' 2>/dev/null)" || block "could not read the tool call, failing closed" "jq could not parse recipients"
  ensure_allowlist
  if [[ -n "$recs" ]]; then
    while IFS= read -r rec || [[ -n "$rec" ]]; do
      [[ -z "$rec" ]] && continue
      key="$(printf '%s' "$rec" | jq -r '.k // empty')" || block "could not read a recipient, failing closed" "jq could not read a recipient field"
      text="$(printf '%s' "$rec" | jq -r '.t // empty')" || block "could not read a recipient, failing closed" "jq could not read a recipient field"
      [[ -z "$text" ]] && continue
      if has_secret "$text"; then
        block "destination carries secret-shaped text (possible exfiltration)" "Matched: $SECRET_HINT"
      fi
      consume_recipient_text "$text" "$key"
    done < <(printf '%s\n' "$recs")
  fi
  stray_lines="$(printf '%s' "$DEST_JSON" | jq -c '.strays[]' 2>/dev/null)" || block "could not read the tool call, failing closed" "jq could not read a string field"
  if [[ -n "$stray_lines" ]]; then
    while IFS= read -r stray_json || [[ -n "$stray_json" ]]; do
      [[ -z "$stray_json" ]] && continue
      stray="$(printf '%s' "$stray_json" | jq -r '.' 2>/dev/null)" || block "could not read the tool call, failing closed" "jq could not read a string field"
      if whole_is_addresses "$stray"; then
        if has_secret "$stray"; then
          block "destination carries secret-shaped text (possible exfiltration)" "Matched: $SECRET_HINT"
        fi
        consume_recipient_text "$stray" "value"
      fi
    done < <(printf '%s\n' "$stray_lines")
  fi
  # A send that names recipients and URLs reaches all of them, so every URL host is checked too.
  while IFS= read -r u || [[ -n "$u" ]]; do
    [[ -z "$u" ]] && continue
    host_from_url "$u" send
    if ! domain_allowed "$DOMAIN"; then
      block "SEND to a domain not on the allow-list" "Domain: $DOMAIN  Dest: $(redact_userinfo "$u")"
    fi
    accepted="${accepted:+$accepted }$DOMAIN"
    checked=$((checked + 1))
  done < <(printf '%s\n' "$urls")
  # Third check, after the URL host rules so a userinfo URL still reports that block.
  # Every string leaf except the prose fields and the from/sender/reply_to/replyTo subtrees.
  # source: 11-12 review of 6e5d69b, an address in name or in an unlisted field was not a destination
  # One jq call and one scan for all leaves: a token holds no whitespace, so joining the leaves
  # with newlines cannot make a token across two of them. It only refuses; an allowed address
  # found here does not count as a recipient, so a SEND still needs a recipient field or a URL.
  # source: 11-12 review of a121d06, an allowed address in a stray field passed the no-recipient check
  addr_text="$(printf '%s' "$DEST_JSON" | jq -r '.addrs | join("\n")' 2>/dev/null)" || block "could not read the tool call, failing closed" "jq could not read a string field"
  if [[ -n "$addr_text" ]]; then
    checked_before="$checked"
    accepted_before="$accepted"
    accept_tokens_in "$addr_text" "value"
    checked="$checked_before"
    accepted="$accepted_before"
  fi
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
# Known URL fields plus any string that is entirely a URL. Control characters block first.
collect_destinations || block "could not read the tool call, failing closed" "jq could not read the URL fields"
refuse_control_urls
URLS="$(printf '%s' "$DEST_JSON" | jq -r '.urls[]' 2>/dev/null)" || block "could not read the tool call, failing closed" "jq could not read the URL fields"
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
