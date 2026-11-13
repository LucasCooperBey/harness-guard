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
# osa-args records each -e script and each plain argument on its own labeled line.
# The count file stays one line per alert. Both files exist first: full-disk runs may append
# but not create.
: > "$TMP/osa-args"
{
  printf '%s\n' '#!/bin/sh'
  printf '%s\n' "echo x >> '$TMP/notified'"
  printf '%s\n' "detail='$TMP/osa-args'"
  printf '%s\n' 'expect=0'
  printf '%s\n' 'while [ $# -gt 0 ]; do'
  printf '%s\n' '  if [ "$expect" -eq 1 ]; then'
  printf '%s\n' '    printf "%s\n" "script:$1" >> "$detail"'
  printf '%s\n' '    expect=0'
  printf '%s\n' '  elif [ "$1" = "-e" ]; then'
  printf '%s\n' '    expect=1'
  printf '%s\n' '  else'
  printf '%s\n' '    printf "%s\n" "arg:$1" >> "$detail"'
  printf '%s\n' '  fi'
  printf '%s\n' '  shift'
  printf '%s\n' 'done'
  printf '%s\n' 'exit 0'
} > "$TMP/bin/osascript"
chmod +x "$TMP/bin/osascript"
# The secret-shaped probes are assembled here so no literal credential shape sits in this file.
AWS="$(printf '%s' 'AK' 'IA' 'ABCD' 'EFGH' 'IJKL' 'MNOP')"
GHP="$(printf '%s' 'gh' 'p_' 'abcdefghijklmnopqrstuvwxyz0123')"
# sk- plus 24 characters. Pieces, so the key shape is not one literal in this file.
SK="$(printf '%s' 'sk' '-' 'abcdefghij' 'klmnopqrst' 'uvwx')"
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

# source: 11-12 review, the user-info block printed the whole URL, so a password reached stderr and the log
# The URL is built from parts so secret scanners do not read this file as holding a credential.
pw_url="https://bob"; pw_url="$pw_url:Hunter2Pass"; pw_url="$pw_url@allowed.example/hook"
webhook_pw="$(payload mcp__example__webhook "{\"url\": \"$pw_url\"}")"
CHECK_OUT='https://***@allowed.example/hook' check 2 "a webhook URL with a password shows the user info as ***" "$webhook_pw" bash
# The log folder exists first, so the log check below reads a real BLOCK line.
pw_log="$TMP/fakehome/.claude/artifacts/logs/egress-guard.log"
mkdir -p "$(dirname "$pw_log")"
pw_out="$(printf '%s' "$webhook_pw" | HOME="$TMP/fakehome" PATH="$TMP/bin:$PATH" bash "$HOOK" 2>&1)" || true
if ! printf '%s' "$pw_out" | grep -F -q 'Hunter2Pass' && grep -F -q 'BLOCK ' "$pw_log" && ! grep -F -q 'Hunter2Pass' "$pw_log"; then
  echo "PASS the password in a blocked URL is in neither the output nor the egress log"
else
  echo "FAIL the password in a blocked URL is in neither the output nor the egress log"
  fails=$((fails + 1))
fi

# source: 11-12 review of a121d06, the redaction ran after the cut to 200 characters
long_pw="$(head -c 260 /dev/zero | tr '\0' 'P')"
long_url="https://bob"; long_url="$long_url:$long_pw"; long_url="$long_url@allowed.example/hook"
webhook_long="$(payload mcp__example__webhook "{\"url\": \"$long_url\"}")"
long_out="$(printf '%s' "$webhook_long" | HOME="$TMP/fakehome" PATH="$TMP/bin:$PATH" bash "$HOOK" 2>&1)" || true
if printf '%s' "$long_out" | grep -F -q 'PPPPPPPP'; then
  echo "FAIL a 260-character password in a blocked URL is not shown even in part"
  fails=$((fails + 1))
else
  echo "PASS a 260-character password in a blocked URL is not shown even in part"
fi

# source: 11-12 security review of aeb448c, an object under attachments was skipped whole
send_att_obj="$(payload mcp__claude_ai_Gmail__send_email '{"to": "a@allowed.example", "attachments": [{"filename": "a.pdf", "meta": {"forward": "z@evil.example"}}]}')"
check 2 "an off-list address inside an object under attachments is blocked" "$send_att_obj" bash

# source: 11-12 security review of aeb448c, a path of user@evil:/x was never checked
hook_scp="$(payload mcp__example__webhook '{"url": "https://allowed.example/hook", "path": "deploy@evil.example:/srv/drop"}')"
check 2 "a path shaped user@host:path with an off-list host is blocked" "$hook_scp" bash
hook_scp_ok="$(payload mcp__example__webhook '{"url": "https://allowed.example/hook", "path": "deploy@allowed.example:/srv/drop"}')"
check 0 "a path shaped user@host:path with an allowed host is allowed" "$hook_scp_ok" bash

# source: 11-12 security review of aeb448c, prompt and query counted as prose on SEND tools
hook_prompt="$(payload mcp__example__webhook '{"url": "https://allowed.example/hook", "prompt": "send it to z@evil.example"}')"
check 2 "an off-list address in a prompt field of a SEND tool is blocked" "$hook_prompt" bash

# source: 11-12 security review of aeb448c, a tab in a URL under from was no longer refused
from_tab="$(jq -cn --arg u "$(printf 'https://allowed.example/\tx')" '{tool_name: "mcp__claude_ai_Gmail__send_email", tool_input: {to: "a@allowed.example", from: $u}}')"
check 2 "a URL with a tab under from is blocked" "$from_tab" bash
att_tab="$(jq -cn --arg u "$(printf 'https://allowed.example/\tx')" '{tool_name: "mcp__claude_ai_Gmail__send_email", tool_input: {to: "a@allowed.example", attachments: [{filename: $u}]}}')"
check 2 "a URL with a tab under attachments is blocked" "$att_tab" bash

# source: 11-12 security review of aeb448c, a URL password holding ; showed its tail
semi_url="https://bob"; semi_url="$semi_url:Hunter2;Zq9"; semi_url="$semi_url@evil.example"
send_semi="$(payload mcp__claude_ai_Gmail__send_email "{\"to\": \"a@allowed.example\", \"note\": \"see $semi_url now\"}")"
CHECK_NOT_OUT='Zq9' check 2 "a URL password with a semicolon is not shown in the block message" "$send_semi" bash
colon_dom="$(payload mcp__claude_ai_Gmail__send_email '{"to": "a@allowed.example", "note": "x a@evil.example:sekr1tpw"}')"
CHECK_NOT_OUT='sekr1tpw' check 2 "a recipient domain holding a colon is not shown past the colon" "$colon_dom" bash

# source: 11-12 review of aeb448c, a password holding an unencoded / kept its text in the message
slash_url="https://bob"; slash_url="$slash_url:Hunter2/Pass"; slash_url="$slash_url@allowed.example/hook"
webhook_slash="$(payload mcp__example__webhook "{\"url\": \"$slash_url\"}")"
slash_out="$(printf '%s' "$webhook_slash" | HOME="$TMP/fakehome" PATH="$TMP/bin:$PATH" bash "$HOOK" 2>&1)" || true
if printf '%s' "$slash_out" | grep -i -F -q 'Hunter2'; then
  echo "FAIL a password with a slash in a blocked URL is not shown"
  fails=$((fails + 1))
else
  echo "PASS a password with a slash in a blocked URL is not shown"
fi

# source: 11-12 review of aeb448c, a stray-field domain reached the ALLOW log line as a recipient
stray_log_home="$TMP/straylog"
mkdir -p "$stray_log_home/.claude/artifacts/logs"
cp "$TMP/fakehome/.claude/allowlist-domains.txt" "$stray_log_home/.claude/allowlist-domains.txt"
printf 'other.example\n' >> "$stray_log_home/.claude/allowlist-domains.txt"
send_stray_log="$(payload mcp__claude_ai_Gmail__send_email '{"to": "a@allowed.example", "note": "ask b@other.example"}')"
CHECK_HOME="$stray_log_home" check 0 "an allowed address in a stray field does not block" "$send_stray_log" bash
if grep -F 'ALLOW' "$stray_log_home/.claude/artifacts/logs/egress-guard.log" | grep -F -q 'other.example'; then
  echo "FAIL the ALLOW log line names only recipient domains"
  fails=$((fails + 1))
else
  echo "PASS the ALLOW log line names only recipient domains"
fi

# source: 11-12 security review of a121d06, an address-shaped token could carry a URL password
tok_url="https://bob"; tok_url="$tok_url:Hunter2Pass"; tok_url="$tok_url@evil.example"
send_tok="$(payload mcp__claude_ai_Gmail__send_email "{\"to\": \"a@allowed.example\", \"note\": \"see $tok_url\"}")"
CHECK_OUT='***@evil.example' check 2 "a URL password in an unlisted field is blocked and shown as ***" "$send_tok" bash
tok_out="$(printf '%s' "$send_tok" | HOME="$TMP/fakehome" PATH="$TMP/bin:$PATH" bash "$HOOK" 2>&1)" || true
if printf '%s' "$tok_out" | grep -F -q 'Hunter2Pass'; then
  echo "FAIL the password in an address-shaped token is not shown"
  fails=$((fails + 1))
else
  echo "PASS the password in an address-shaped token is not shown"
fi

# source: 11-12 review of a121d06, an inReplyTo Message-ID and img@2x.png blocked a reply
send_reply="$(payload mcp__claude_ai_Gmail__send_email '{"to": "a@allowed.example", "subject": "Re: x", "body": "thanks", "threadId": "18c2f", "inReplyTo": "<CAF1x@mail.gmail.com>", "references": "<a1@mail.gmail.com> <b2@mail.gmail.com>", "attachments": [{"filename": "img@2x.png", "path": "/tmp/img@2x.png"}]}')"
check 0 "a reply with Message-IDs and an img@2x.png attachment is allowed" "$send_reply" bash

# source: 11-12 review of a121d06, a body that starts with a link and a new line was refused
send_link_body="$(jq -cn '{tool_name: "mcp__claude_ai_Gmail__send_email", tool_input: {to: "a@allowed.example", subject: "PR", body: "https://github.com/x/y/pull/1\n\nPlease review."}}')"
check 0 "a body that starts with a link and a new line is allowed" "$send_link_body" bash

# source: 11-12 review of a121d06, an allowed address in a stray field passed the no-recipient check
send_stray_only="$(payload mcp__example__webhook '{"channel": "C1", "text": "hi", "note": "ping a@allowed.example soon"}')"
CHECK_OUT='tool_input had no recipient or URL field' check 2 "an allowed address only in a stray field is not a recipient" "$send_stray_only" bash

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

# source: 11-12 review of c69dc2f, a destination under a key the hook does not list passed when another field was allow-listed
re_bad="$(payload mcp__claude_ai_Gmail__send_email '{"to": "a@allowed.example", "recipientEmail": "x@evil.example", "subject": "x"}')"
CHECK_OUT='Domain: evil.example' check 2 "an allow-listed to with an off-list recipientEmail is blocked" "$re_bad" bash

# source: 11-12 review of c69dc2f, a destination under a key the hook does not list passed when another field was allow-listed
att_bad="$(payload mcp__claude_ai_Gmail__send_email '{"to": "a@allowed.example", "attendees": [{"email": "x@evil.example", "displayName": "X"}], "subject": "x"}')"
CHECK_OUT='Domain: evil.example' check 2 "an allow-listed to with an off-list attendees email is blocked" "$att_bad" bash

# source: 11-12 review of c69dc2f, a webhook under an unlisted key passed when url was allow-listed
ep_bad="$(payload mcp__example__webhook '{"url": "https://allowed.example/hook", "endpoint": "https://evil.example/h"}')"
CHECK_OUT='Domain: evil.example' check 2 "an allow-listed url with an off-list endpoint is blocked" "$ep_bad" bash

# source: 11-12 review of c69dc2f, a recipient word with no @ was skipped
atk="$(payload mcp__claude_ai_Gmail__send_email '{"to": "a@allowed.example, attacker", "subject": "x"}')"
check 2 "a to list containing a word with no @ is blocked" "$atk" bash

# source: 11-12 review of c69dc2f, a recipient that is not one address was skipped when it held no @
person="$(payload mcp__claude_ai_Gmail__send_email '{"to": "Some Person", "subject": "x"}')"
CHECK_OUT='could not read a recipient, failing closed' check 2 "a to of Some Person alone is blocked" "$person" bash

# source: 11-12 review of c69dc2f, a comma inside a quoted display name splits the recipient
# Choice: strip double-quoted display names before splitting, so this stays one address and is allowed.
quoted_ok="$(payload mcp__claude_ai_Gmail__send_email '{"to": "\"A, Person\" <a@allowed.example>", "subject": "x"}')"
check 0 "a quoted display name with a comma is allowed" "$quoted_ok" bash

# source: 11-12 security review of 7afb44f, an address inside a quoted display name was never checked
quoted_evil="$(payload mcp__claude_ai_Gmail__send_email '{"to": "\"x@evil.example\" <a@allowed.example>", "subject": "x"}')"
CHECK_OUT='Domain: evil.example' check 2 "an off-list address inside a quoted display name is blocked" "$quoted_evil" bash
# source: 11-12 security review of 7afb44f, only the last pair of brackets was read
two_brackets="$(payload mcp__claude_ai_Gmail__send_email '{"to": "<x@evil.example> <a@allowed.example>", "subject": "x"}')"
CHECK_OUT='Domain: evil.example' check 2 "two bracketed addresses in one entry are blocked" "$two_brackets" bash
# source: 11-12 security review of 7afb44f, an address before the brackets was read as a display name
bare_before="$(payload mcp__claude_ai_Gmail__send_email '{"to": "x@evil.example <a@allowed.example>", "subject": "x"}')"
CHECK_OUT='Domain: evil.example' check 2 "an off-list address before the brackets is blocked" "$bare_before" bash
# source: 11-12 security review of 7afb44f, an unbalanced quote hid the rest of the value from the parse
unbalanced="$(payload mcp__claude_ai_Gmail__send_email '{"to": "\"a@allowed.example <a@allowed.example>", "subject": "x"}')"
CHECK_OUT='unbalanced double quote' check 2 "an unbalanced double quote in a recipient is blocked" "$unbalanced" bash
# source: 11-12 security review of 7afb44f, the same rule under a field name the hook does not list
stray_quoted="$(payload mcp__claude_ai_Gmail__send_email '{"to": "a@allowed.example", "recipientEmail": "\"x@evil.example\" <a@allowed.example>", "subject": "x"}')"
CHECK_OUT='Domain: evil.example' check 2 "an off-list quoted address under an unlisted field is blocked" "$stray_quoted" bash

# source: 11-12 review of c69dc2f, prose that only mentions an address was not a destination and must stay allowed
prose="$(payload mcp__claude_ai_Gmail__send_email '{"to": "a@allowed.example", "body": "write to x@evil.example or @channel", "subject": "x"}')"
check 0 "a body that mentions an address is not a destination" "$prose" bash

# source: 11-12 review of c69dc2f, a plain-string startUrls entry was dropped
su="$(payload mcp__apify__rag-web-browser '{"input": {"startUrls": ["https://bad.example/"]}}')"
CHECK_OUT='Domain: bad.example' check 2 "a fetch startUrls string on the blocklist is blocked" "$su" bash

# source: 11-12 review of c69dc2f, a URL holding a control character was split before the check
nl_url="$(payload mcp__example__webhook '{"url": "https://allowed.example\n.evil.example/"}')"
CHECK_OUT='URL holds a control character, failing closed' check 2 "a webhook URL with a newline is blocked" "$nl_url" bash

# source: 11-12 review of c69dc2f, a URL holding a control character was split before the check
tab_input="$(jq -cn --arg u "$(printf 'https://example.com/\tpage')" '{url:$u, prompt:"x"}')"
tab_fetch="$(payload WebFetch "$tab_input")"
CHECK_OUT='URL holds a control character, failing closed' check 2 "a fetch URL holding a tab is blocked" "$tab_fetch" bash

# source: 11-12 review of c69dc2f, the secret pattern matched sk- inside ordinary words
slug="$(payload WebSearch '{"query": "risk-based-security-assessment-guide checklist"}')"
check 0 "a search for risk-based-security-assessment-guide is allowed" "$slug" bash

# source: 11-12 review of c69dc2f, the secret pattern matched the phrase password reset
pwreset="$(payload WebSearch '{"query": "how to handle a password reset email"}')"
check 0 "a search about a password reset email is allowed" "$pwreset" bash

# source: 11-12 review of c69dc2f, a password assignment is still secret-shaped
pwset="$(payload WebSearch '{"query": "password: hunter2hunter2"}')"
CHECK_NOT_OUT='hunter2hunter2' check 2 "a search query with a password assignment is blocked" "$pwset" bash

# source: 11-12 review of c69dc2f, an sk- key shape preceded by a space must still block
sk_search="$(payload WebSearch "{\"query\": \"prefix $SK\"}")"
CHECK_NOT_OUT="$SK" check 2 "a search query with an sk- key shape preceded by a space is blocked" "$sk_search" bash

# source: 11-12 review of c69dc2f, notify pasted the tool name into the AppleScript source
INJECT='x"; do shell script "touch INJECTED"; "send_email'
inject_body="$(payload "$INJECT" '{"to": "someone@not-on-the-list.example", "subject": "x"}')"
inject_preexisted=0
if [ -e INJECTED ]; then
  inject_preexisted=1
fi
before_detail="$(wc -l < "$TMP/osa-args" | tr -d ' ')"
check 2 "a tool name that breaks out of an AppleScript string is blocked" "$inject_body" bash
detail_new="$(tail -n +"$((before_detail + 1))" "$TMP/osa-args")"
scripts="$(printf '%s\n' "$detail_new" | grep '^script:' || true)"
args="$(printf '%s\n' "$detail_new" | grep '^arg:' || true)"
if [ -z "$scripts" ]; then
  echo "FAIL osascript -e scripts were not recorded"
  fails=$((fails + 1))
elif printf '%s\n' "$scripts" | grep -F -q 'touch INJECTED'; then
  echo "FAIL tool name was inside an -e script"
  fails=$((fails + 1))
elif ! printf '%s\n' "$args" | grep -F -q 'touch INJECTED'; then
  echo "FAIL tool name did not reach osascript as an argument"
  fails=$((fails + 1))
elif [ "$inject_preexisted" -eq 0 ] && [ -e INJECTED ]; then
  echo "FAIL injected command created INJECTED"
  rm -f INJECTED
  fails=$((fails + 1))
else
  echo "PASS tool name reached osascript only as an argument"
fi

# source: 11-12 review of 6e5d69b, a quoted display name with a comma under an unlisted field was not read as addresses
contact_bad="$(payload mcp__claude_ai_Gmail__send_email '{"to": "a@allowed.example", "contact": "\"Smith, Bob\" <x@evil.example>"}')"
CHECK_OUT='Domain: evil.example' check 2 "an off-list address under contact is blocked" "$contact_bad" bash

# source: 11-12 review of 6e5d69b, an address in a name field inside a recipient was not checked
name_bad="$(payload mcp__claude_ai_Gmail__send_email '{"to": [{"name": "x@evil.example", "email": "a@allowed.example"}]}')"
CHECK_OUT='Domain: evil.example' check 2 "an off-list address in a recipient name is blocked" "$name_bad" bash

# source: 11-12 review of 6e5d69b, a backslash-escaped quote was counted, so a balanced recipient was blocked
escaped_quote="$(payload mcp__claude_ai_Gmail__send_email '{"to": "\"Bob \\\" Smith\" <a@allowed.example>", "subject": "x"}')"
check 0 "a display name with an escaped quote is allowed" "$escaped_quote" bash

# source: 11-12 review of 6e5d69b, prose fields that mention an address must stay allowed
prose_fields="$(payload mcp__claude_ai_Gmail__send_email '{"to": "a@allowed.example", "subject": "write to x@evil.example", "body": "or y@evil.example"}')"
check 0 "subject and body that mention addresses are not destinations" "$prose_fields" bash

# source: 11-12 review of 6e5d69b, a tab in a URL under an unlisted field was neither a URL nor an address
target_tab="$(payload mcp__example__webhook '{"url": "https://allowed.example/h", "target": "https://evil.example/\tx"}')"
CHECK_OUT='control character' check 2 "a webhook target URL with a tab is blocked" "$target_tab" bash

# source: 11-12 review of 6e5d69b, a newline in a FETCH URL under an unlisted field was never checked
note_nl="$(payload WebFetch '{"url": "https://allowed.example/", "note": "https://evil.example/\nx"}')"
CHECK_OUT='control character' check 2 "a fetch note URL with a newline is blocked" "$note_nl" bash

# source: 11-12 review of 6e5d69b, a grep error during the address scan yielded no tokens and the send passed
{
  printf '%s\n' '#!/bin/sh'
  printf '%s\n' 'for a in "$@"; do'
  printf '%s\n' '  if [ "$a" = "-aoE" ]; then'
  printf '%s\n' '    exit 2'
  printf '%s\n' '  fi'
  printf '%s\n' 'done'
  printf '%s\n' 'exec /usr/bin/grep "$@"'
} > "$TMP/bin/grep"
chmod +x "$TMP/bin/grep"
grep_fail="$(payload mcp__claude_ai_Gmail__send_email '{"to": "a@allowed.example", "subject": "x"}')"
CHECK_OUT='the address scan could not run' check 2 "a grep error during the address scan blocks the send" "$grep_fail" bash
rm -f "$TMP/bin/grep"

# source: 11-12 review of 6e5d69b, install.sh said the allow-list starts empty on a reinstall that keeps domains
inst_home="$(mktemp -d "$TMP/inst.XXXXXX")"
inst_out="$(HOME="$inst_home" bash "$ROOT/install.sh" 2>&1)"
if printf '%s' "$inst_out" | grep -F -q 'allowlist-domains.txt starts empty'; then
  echo "PASS install.sh with no allow-list says it starts empty"
else
  echo "FAIL install.sh with no allow-list says it starts empty"
  fails=$((fails + 1))
fi
mkdir -p "$inst_home/.claude"
printf 'allowed.example\n' > "$inst_home/.claude/allowlist-domains.txt"
inst_out="$(HOME="$inst_home" bash "$ROOT/install.sh" 2>&1)"
if printf '%s' "$inst_out" | grep -F -q 'keeps its 1 domain.'; then
  echo "PASS install.sh with one saved domain says the allow-list keeps its 1 domain"
else
  echo "FAIL install.sh with one saved domain says the allow-list keeps its 1 domain"
  fails=$((fails + 1))
fi

[ "$fails" -eq 0 ] || { echo "$fails failed"; exit 1; }
echo "PASS egress-guard"
