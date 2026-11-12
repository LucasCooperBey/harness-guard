#!/usr/bin/env bash
# egress-guard refuses with exit 2, the only code Claude Code treats as a block, and holds on a
# full disk and for the lowercase web_fetch and web_search tool names.
# source: 11-12 audit: public egress-guard exited 1, so Claude Code ran every call it meant to block
# source: 2026-09-30 review: printf | grep -q under pipefail let a secret near the start of a payload over 64 KB pass
# source: 2026-09-29: here-documents made bash 3.2 write a temp file, so on a full disk the reads came back empty
# EGRESS_GUARD_HOOK overrides the hook under test.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
HOOK="${EGRESS_GUARD_HOOK:-$ROOT/hooks/egress-guard.sh}"
have_sandbox=0
if command -v sandbox-exec >/dev/null 2>&1; then
  have_sandbox=1
else
  echo "SKIP full-disk checks: sandbox-exec not found (macOS only)"
fi
DENY='(version 1)(allow default)(deny file-write-create)'
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/fakehome/.claude/artifacts/logs"
# A real allow-list, so the off-list send is refused by the list and not by a missing file.
printf 'allowed.example\n' > "$TMP/fakehome/.claude/allowlist-domains.txt"
# bad.example is the fetch blocklist entry used by the userinfo host check. Other fixture hosts are not on it.
printf 'bad.example\n' > "$TMP/fakehome/.claude/blocklist-domains.txt"
# A stand-in osascript, so each planted block records its alert here instead of posting a real
# desktop notification with a sound. The count file exists first: the full-disk runs may append
# but not create.
# source: 11-12 12:15 to 12:27 PST, a build lane's repeated runs of this suite put bursts of 13 real
# "Egress guard ... blocked" alerts with the Basso sound on the screen of the person at the Mac
mkdir -p "$TMP/bin"
: > "$TMP/notified"
printf '#!/bin/sh\necho x >> "%s"\n' "$TMP/notified" > "$TMP/bin/osascript"
chmod +x "$TMP/bin/osascript"
# The secret-shaped probes are assembled here so no literal credential shape sits in this file.
AWS="$(printf '%s' 'AK' 'IA' 'ABCD' 'EFGH' 'IJKL' 'MNOP')"
GHP="$(printf '%s' 'gh' 'p_' 'abcdefghijklmnopqrstuvwxyz0123')"
# 70 KB of padding on a line after the secret: grep -q exits at the first matching line, and past
# the 64 KB pipe buffer printf dies of SIGPIPE, which pipefail read as no match.
PAD70="$(head -c 70000 /dev/zero | tr '\0' 'a')"
PAD100="$(head -c 100000 /dev/zero | tr '\0' 'a')"

payload() {  # tool_name, then a jq object for tool_input
  jq -cn --arg t "$1" --argjson i "$2" '{tool_name: $t, tool_input: $i}'
}

fails=0
# A block must add exactly one stand-in alert, and an allow must add none. CHECK_HOME overrides
# the temp home. CHECK_OUT, when set, must appear in the hook's output.
check() {  # want label payload [runner...]
  local want="$1" label="$2" body="$3" out status before after delta home
  shift 3
  home="${CHECK_HOME:-$TMP/fakehome}"
  before="$(wc -l < "$TMP/notified" | tr -d ' ')"
  set +e
  out="$(printf '%s' "$body" | HOME="$home" PATH="$TMP/bin:$PATH" "$@" "$HOOK" 2>&1)"
  status=$?
  set -e
  after="$(wc -l < "$TMP/notified" | tr -d ' ')"
  delta=$((after - before))
  if [ "$status" -ne "$want" ]; then
    echo "FAIL (got $status want $want) $label: $(printf '%s' "$out" | head -3)"
    fails=$((fails + 1))
    return 0
  fi
  if printf '%s' "$out" | grep -q "cannot create temp file"; then
    echo "FAIL (a temp file was needed) $label"
    fails=$((fails + 1))
    return 0
  fi
  if [ "$want" -eq 2 ] && [ "$delta" -ne 1 ]; then
    echo "FAIL $label: expected 1 alert, got $delta"
    fails=$((fails + 1))
    return 0
  fi
  if [ "$want" -eq 0 ] && [ "$delta" -ne 0 ]; then
    echo "FAIL $label: expected 0 alerts, got $delta"
    fails=$((fails + 1))
    return 0
  fi
  if [ -n "${CHECK_OUT:-}" ]; then
    if ! printf '%s' "$out" | grep -F -q -- "$CHECK_OUT"; then
      echo "FAIL $label: output did not contain: $CHECK_OUT"
      fails=$((fails + 1))
      return 0
    fi
  fi
  if [ -n "${CHECK_NOT_OUT:-}" ]; then
    if printf '%s' "$out" | grep -F -q -- "$CHECK_NOT_OUT"; then
      echo "FAIL $label: output contained text it must not show"
      fails=$((fails + 1))
      return 0
    fi
  fi
  echo "PASS ($status) $label"
}

secret_fetch="$(payload WebFetch "{\"url\": \"https://example.com/?k=$AWS\", \"prompt\": \"x\"}")"
plain_fetch="$(payload WebFetch '{"url": "https://example.com/docs", "prompt": "x"}')"
secret_search="$(payload WebSearch "{\"query\": \"token $GHP\"}")"
plain_search="$(payload WebSearch '{"query": "bash here-string temp file"}')"
send_out="$(payload mcp__claude_ai_Gmail__send_email '{"to": "someone@not-on-the-list.example", "subject": "x"}')"
alt_fetch="$(payload web_fetch "{\"url\": \"https://example.com/?k=$AWS\"}")"
alt_search="$(payload web_search "{\"query\": \"token $GHP\"}")"
no_url="$(payload WebFetch '{"prompt": "x"}')"
send_ok="$(payload mcp__claude_ai_Gmail__send_email '{"to": "someone@allowed.example", "subject": "x"}')"
long_fetch="$(payload WebFetch "{\"url\": \"https://example.com/?k=$AWS\\n$PAD70\", \"prompt\": \"x\"}")"
long_search="$(payload WebSearch "{\"query\": \"token $GHP\\n$PAD70\"}")"
long100="$(payload WebFetch "{\"url\": \"https://x/?k=${AWS}${PAD100}\", \"prompt\": \"x\"}")"

# source: 11-12 audit: public egress-guard exited 1, so Claude Code ran every call it meant to block
check 2 "a fetch whose URL carries a secret is blocked with exit 2" "$secret_fetch" bash
check 0 "a plain fetch is allowed" "$plain_fetch" bash
check 2 "a search whose query carries a secret is blocked" "$secret_search" bash
check 0 "a plain search is allowed" "$plain_search" bash
check 2 "a send to a domain off the allow-list is blocked" "$send_out" bash
check 2 "web_fetch with a secret in the URL is blocked" "$alt_fetch" bash
check 2 "web_search with a secret in the query is blocked" "$alt_search" bash
check 2 "a fetch with no URL is blocked" "$no_url" bash
check 2 "a payload jq cannot read is blocked" '{"tool_name": "WebFetch", "tool_input": ' bash
if [ "$have_sandbox" -eq 1 ]; then
  check 2 "full disk, bash 3.2: a fetch whose URL carries a secret is blocked" "$secret_fetch" sandbox-exec -p "$DENY" /bin/bash
  check 0 "full disk, bash 3.2: a plain fetch is allowed" "$plain_fetch" sandbox-exec -p "$DENY" /bin/bash
  check 2 "full disk, bash 3.2: a send off the allow-list is blocked" "$send_out" sandbox-exec -p "$DENY" /bin/bash
fi
check 0 "a send to an allow-listed domain is allowed" "$send_ok" bash
check 2 "a 70 KB fetch URL with a secret near the start is blocked" "$long_fetch" bash
check 2 "a 70 KB search query with a secret near the start is blocked" "$long_search" bash
if [ "$have_sandbox" -eq 1 ]; then
  check 2 "full disk, bash 3.2: a 70 KB fetch URL with a secret near the start is blocked" "$long_fetch" sandbox-exec -p "$DENY" /bin/bash
fi

# source: 2026-09-30 review: a secret in the first 100 bytes of a 100 KB payload passed because grep -q closed the pipe and printf took SIGPIPE under pipefail
place="$(printf '%s' "$long100" | S="$AWS" python3 -c 'import os,sys
b=sys.stdin.buffer.read()
i=b.find(os.environ["S"].encode())
sys.stdout.write("%d %d\n" % (i, len(b)))')"
off="${place%% *}"
size="${place##* }"
if [ "$off" -ge 100 ] || [ "$off" -lt 0 ] || [ "$size" -lt 100000 ]; then
  echo "FAIL secret is not in the first 100 bytes of a 100 KB payload (off=$off size=$size)"
  fails=$((fails + 1))
else
  echo "PASS placement off=$off size=$size"
fi
check 2 "a 100 KB payload with a secret in the first 100 bytes is blocked" "$long100" bash

# source: 11-12 review: a comma-separated SEND read only the domain after the last @, so an off-list address before an allowed one passed
comma_to="$(payload mcp__claude_ai_Gmail__send_email '{"to": "x@evil.example, y@allowed.example", "subject": "x"}')"
CHECK_OUT='Domain: evil.example' check 2 "a comma-separated to with an off-list address is blocked" "$comma_to" bash

# source: 11-12 review: a semicolon-separated SEND read only the domain after the last @, so an off-list address before an allowed one passed
semi_to="$(payload mcp__claude_ai_Gmail__send_email '{"to": "x@evil.example; y@allowed.example", "subject": "x"}')"
CHECK_OUT='Domain: evil.example' check 2 "a semicolon-separated to with an off-list address is blocked" "$semi_to" bash

# source: 11-12 review: to as an array was read as JSON text, so an off-list address in the array was not checked as its own recipient
to_array="$(payload mcp__claude_ai_Gmail__send_email '{"to": ["y@allowed.example", "x@evil.example"], "subject": "x"}')"
CHECK_OUT='Domain: evil.example' check 2 "a to array with an off-list address is blocked" "$to_array" bash

# source: 11-12 review: cc was never read, so an off-list address only in cc passed when to was allow-listed
cc_bad="$(payload mcp__claude_ai_Gmail__send_email '{"to": "a@allowed.example", "cc": "x@evil.example", "subject": "x"}')"
CHECK_OUT='Domain: evil.example' check 2 "an off-list address only in cc is blocked" "$cc_bad" bash

# source: 11-12 review: bcc was never read, so an off-list address only in bcc passed when to was allow-listed
bcc_bad="$(payload mcp__claude_ai_Gmail__send_email '{"to": "a@allowed.example", "bcc": "x@evil.example", "subject": "x"}')"
CHECK_OUT='Domain: evil.example' check 2 "an off-list address only in bcc is blocked" "$bcc_bad" bash

# source: 11-12 review: a recipient of the form Name <addr> kept the trailing bracket, so a listed address was not recognized
named_ok="$(payload mcp__claude_ai_Gmail__send_email '{"to": "Name <a@allowed.example>", "subject": "x"}')"
check 0 "Name <a@allowed.example> alone is allowed" "$named_ok" bash

# source: 11-12 review: every address in to and cc is checked, and the send is allowed when each domain is listed
multi_ok="$(payload mcp__claude_ai_Gmail__send_email '{"to": "a@allowed.example, b@allowed.example", "cc": "c@allowed.example", "subject": "x"}')"
check 0 "two allow-listed addresses in to plus one in cc are allowed" "$multi_ok" bash

# source: 11-12 review: an address with more than one @ was reduced to the text after the last @ and could pass the allow-list
two_at="$(payload mcp__claude_ai_Gmail__send_email '{"to": "a@b@allowed.example", "subject": "x"}')"
check 2 "an address with two @ is blocked" "$two_at" bash

# source: 11-12 review: a webhook URL was cut at the first colon, so https://allowed.example:x@evil.example/hook read as allowed.example
webhook_user="$(payload mcp__example__webhook '{"url": "https://allowed.example:x@evil.example/hook"}')"
CHECK_OUT='URL carries user info, failing closed' check 2 "webhook URL https://allowed.example:x@evil.example/hook is blocked" "$webhook_user" bash

# source: 11-12 review: a webhook whose host is on the allow-list is a SEND and is allowed
webhook_ok="$(payload mcp__example__webhook '{"url": "https://allowed.example/hook"}')"
check 0 "webhook URL https://allowed.example/hook is allowed" "$webhook_ok" bash

# source: 11-12 review: a backslash in a webhook authority ends the authority, so the host before it must not pass the allow-list
webhook_bs="$(payload mcp__example__webhook '{"url": "https://allowed.example\\evil.example/hook"}')"
CHECK_OUT='URL contains a backslash, failing closed' check 2 "a webhook URL with a backslash in the authority is blocked" "$webhook_bs" bash

# source: 11-12 architect review of round A: with a recipient field present, the url host was never checked
both_bad="$(payload mcp__example__webhook '{"to": "a@allowed.example", "url": "https://evil.example/hook"}')"
CHECK_OUT='Domain: evil.example' check 2 "an allow-listed to with an off-list url is blocked" "$both_bad" bash

# source: 11-12 review: a fetch host is the authority after the last @, so a blocklisted host behind userinfo was missed
fetch_user="$(payload WebFetch '{"url": "https://good.example@bad.example/", "prompt": "x"}')"
CHECK_OUT='Domain: bad.example' check 2 "FETCH https://good.example@bad.example/ is blocked when bad.example is blocklisted" "$fetch_user" bash

# source: 11-12 review: empty stdin exited 0 while every other unreadable payload is blocked
CHECK_OUT='empty hook payload, failing closed' check 2 "empty stdin is blocked" "" bash

# source: 11-12 review: a payload with an empty tool_name exited 0 while every other unreadable payload is blocked
CHECK_OUT='hook payload has no tool_name, failing closed' check 2 "a payload with no tool_name is blocked" '{}' bash

# source: 11-12 review: a missing allow-list was created containing gmail.com, so a send to any Gmail address passed
FRESH="$(mktemp -d "$TMP/noallow.XXXXXX")"
gmail_send="$(payload mcp__claude_ai_Gmail__send_email '{"to": "someone@gmail.com", "subject": "x"}')"
CHECK_HOME="$FRESH" CHECK_OUT='Domain: gmail.com' check 2 "a send to someone@gmail.com with no allow-list is blocked" "$gmail_send" bash
alist="$FRESH/.claude/allowlist-domains.txt"
if [ ! -f "$alist" ]; then
  echo "FAIL a send to someone@gmail.com with no allow-list: allow-list file was not written"
  fails=$((fails + 1))
elif grep -vE '^[[:space:]]*(#|$)' "$alist" | grep -q .; then
  echo "FAIL a send to someone@gmail.com with no allow-list: allow-list has a non-comment line"
  fails=$((fails + 1))
elif ! grep -q '^#' "$alist"; then
  echo "FAIL a send to someone@gmail.com with no allow-list: allow-list has no comment line"
  fails=$((fails + 1))
else
  echo "PASS a missing allow-list is comments and blank lines only"
fi

# source: 11-12 security review of round A: a SEND read only the first URL field, so an off-list URL in a later field was never checked
multi_url="$(payload mcp__example__webhook '{"url": "https://allowed.example/hook", "request": {"url": "https://evil.example/hook"}}')"
CHECK_OUT='Domain: evil.example' check 2 "a webhook with an allow-listed url and an off-list request.url is blocked" "$multi_url" bash
urls_second="$(payload mcp__example__webhook '{"urls": ["https://allowed.example/a", "https://evil.example/b"]}')"
CHECK_OUT='Domain: evil.example' check 2 "a webhook whose second urls entry is off the list is blocked" "$urls_second" bash
urls_ok="$(payload mcp__example__webhook '{"urls": ["https://allowed.example/a", "https://hooks.allowed.example/b"]}')"
check 0 "a webhook whose urls are all allow-listed is allowed" "$urls_ok" bash

# source: 11-12 security review of round A: recipient fields were matched by exact lowercase name at the top level only
cap_to="$(payload mcp__claude_ai_Gmail__send_email '{"To": "x@evil.example", "subject": "x"}')"
CHECK_OUT='Domain: evil.example' check 2 "a capitalized To with an off-list address is blocked" "$cap_to" bash
graph_to="$(payload mcp__example__send_email '{"message": {"toRecipients": [{"emailAddress": {"address": "x@evil.example"}}]}}')"
CHECK_OUT='Domain: evil.example' check 2 "a nested toRecipients address off the list is blocked" "$graph_to" bash
nested_cc="$(payload mcp__claude_ai_Gmail__send_email '{"to": "a@allowed.example", "message": {"cc": "x@evil.example"}}')"
CHECK_OUT='Domain: evil.example' check 2 "an allow-listed to with an off-list nested cc is blocked" "$nested_cc" bash
graph_ok="$(payload mcp__example__send_email '{"message": {"toRecipients": [{"emailAddress": {"address": "a@allowed.example", "name": "A"}}]}, "from": {"email": "me@sender.example"}, "body": "write to x@evil.example"}')"
check 0 "an allow-listed nested recipient is allowed, and the sender and body are not recipients" "$graph_ok" bash

# source: 11-12 pre-push review of round A: the last allow-list line was skipped when the file had no trailing newline
NONL="$(mktemp -d "$TMP/nonl.XXXXXX")"
mkdir -p "$NONL/.claude"
printf '# sends\nallowed.example' > "$NONL/.claude/allowlist-domains.txt"
CHECK_HOME="$NONL" check 0 "an allow-list whose last line has no newline still allows that domain" "$send_ok" bash
CRLF="$(mktemp -d "$TMP/crlf.XXXXXX")"
mkdir -p "$CRLF/.claude"
printf 'Allowed.Example \r\n' > "$CRLF/.claude/allowlist-domains.txt"
CHECK_HOME="$CRLF" check 0 "an allow-list line with capitals, a trailing space and CRLF still allows that domain" "$send_ok" bash

# source: 11-12 pre-push review of round A: a fetch read only urls[0], so a secret or a blocklisted host in a later URL passed
crawl_bad="$(payload mcp__exa__crawling_exa '{"urls": ["https://example.com/a", "https://bad.example/b"]}')"
CHECK_OUT='Domain: bad.example' check 2 "a crawl whose second URL is blocklisted is blocked" "$crawl_bad" bash
crawl_secret="$(payload mcp__exa__crawling_exa "{\"urls\": [\"https://example.com/a\", \"https://example.com/?k=$AWS\"]}")"
check 2 "a crawl whose second URL carries a secret is blocked" "$crawl_secret" bash
crawl_ok="$(payload mcp__exa__crawling_exa '{"urls": ["https://example.com/a", "https://example.org/b"]}')"
check 0 "a crawl of two plain URLs is allowed" "$crawl_ok" bash

# source: 11-12 security review of round A: a fetch host had no character check, so bad%2eexample was compared to the blocklist as written and missed bad.example
fetch_pct="$(payload WebFetch '{"url": "https://bad%2eexample/", "prompt": "x"}')"
check 2 "a fetch host with a percent escape is blocked while a blocklist is in use" "$fetch_pct" bash
NOBL="$(mktemp -d "$TMP/nobl.XXXXXX")"
mkdir -p "$NOBL/.claude"
CHECK_HOME="$NOBL" check 0 "the same fetch is allowed when there is no blocklist" "$fetch_pct" bash

# source: 11-12 pre-push review of round A: a secret block printed the first 200 characters of the destination, so the secret reached the agent and the log
CHECK_NOT_OUT="$AWS" check 2 "a secret block does not print the secret" "$secret_fetch" bash
CHECK_NOT_OUT="$GHP" check 2 "a search secret block does not print the secret" "$secret_search" bash
secret_send="$(payload mcp__example__webhook "{\"url\": \"https://allowed.example/?k=$AWS\"}")"
CHECK_NOT_OUT="$AWS" check 2 "a send secret block does not print the secret" "$secret_send" bash
egress_log="$TMP/fakehome/.claude/artifacts/logs/egress-guard.log"
if [ -f "$egress_log" ] && { grep -F -q -- "$AWS" "$egress_log" || grep -F -q -- "$GHP" "$egress_log"; }; then
  echo "FAIL the egress log holds a secret from a blocked call"
  fails=$((fails + 1))
else
  echo "PASS the egress log holds no secret from a blocked call"
fi

[ "$fails" -eq 0 ] || { echo "$fails failed"; exit 1; }
echo "PASS egress-guard"
