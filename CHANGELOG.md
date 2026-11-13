# Changelog

## 2026-11-12, fifth release

- An object under an id or attachment field is read again, so an off-list address in `attachments[].meta` blocks. Only the strings there are skipped, and a string shaped `user@host:path` counts as `user@host`, so a path of `deploy@evil.example:/srv` blocks.
- `prompt` and `query` are destinations again on a SEND tool. The fourth release counted them as prose, which let an off-list address through in a webhook's `prompt`.
- The control-character rule reads every string except the prose fields again, `from`, `sender` and the id fields included. The fourth release had narrowed it to the fields the address scan reads.
- Block messages show an address as `***@` and its domain, and a host or domain holding a `:` only up to the colon. The fourth release still showed part of a password written with `;` or `/` in it, and a URL whose password held a `/` printed the password as part of the host.
- An allowed address found only in an unlisted field no longer reaches the ALLOW log line as a recipient domain.

## 2026-11-12, fourth release

- A reply is no longer blocked by its message ids or attachment names. `inReplyTo`, `references`, `messageId`, `threadId`, `attachments`, `filename` and `path` are not read as destinations. The second and third releases read `<id@mail.gmail.com>` and `img@2x.png` as off-list addresses and blocked the send.
- The control-character rule skips the prose fields, so a body that opens with a link and a new line is allowed. `prompt` and `query` count as prose.
- An allowed address that appears only in a field the hook does not list does not count as a recipient, so a SEND with no recipient field and no URL is still blocked.
- Block messages show `***` for user info in a URL or in an address-shaped token, and the redaction runs before the message is cut to length.
- The address scan reads every string with one `jq` call and one `grep`, instead of one pair per string.

## 2026-11-12, third release

- `egress-guard.sh` checks every address-shaped token in a SEND at any field and depth, including `name`, `displayName`, `display_name` and `label` inside a recipient, and a field the hook does not list as a recipient field (`contact`, `headers.Bcc`). Strings under `from`, `sender`, `reply_to` and `replyTo`, and the prose fields `subject`, `body`, `text`, `content`, `message`, `html` and `description`, are not destinations.
- A string that starts with a scheme and `://` and holds a control character blocks a SEND or a FETCH, including under a field that is not a URL field, where a tab or a newline meant it was not read as a URL.
- A double quote preceded by a backslash does not count as a quote delimiter, so `"Bob \" Smith" <a@allowed.example>` is one address and is allowed.
- The hook blocks when the address scan cannot run. A grep error used to look like a value with no address in it.
- A blocked URL is shown with its user info replaced by `***`, so a password written into a URL before its host never reaches the block message or the egress log.
- `install.sh` says the allow-list starts empty only when `~/.claude/allowlist-domains.txt` is missing or has no domain line. Otherwise it says how many domains the allow-list keeps.
- The quality gate's cannot-enter test is skipped when the tests run as root, where `chmod 000` does not stop `cd`.

## 2026-11-12, second release

- `egress-guard.sh` treats any string in a SEND call that is wholly an email address, a list of addresses or a URL as a destination, at any depth and under any field name, so fields such as `recipientEmail`, `attendees` and `endpoint` are checked. A body that mentions an address is still not a destination.
- Each entry in a recipient field must be a bare address or `Name <address>`. An entry with no address, as in `a@allowed.example, attacker`, blocks the send, and so does an entry with a second pair of brackets or a value with an unbalanced double quote. A quoted display name that holds a comma, such as `"A, Person" <a@allowed.example>`, stays one address.
- Every address-shaped token in a recipient value must be on the allow-list, wherever it sits: inside a quoted display name, before the brackets or in the brackets. A mail tool may read any of them as the address. A build of this release published earlier the same day read only the bracketed address, so `"x@evil.example" <a@allowed.example>` passed; it was replaced within the hour.
- A URL that holds a control character, such as a newline or a tab, blocks the call.
- The secret scan has a case-sensitive part for key shapes (`AKIA`, `ghp_`, and `sk-` after a character that is not a letter or digit) and a case-insensitive part for words. `password` matches only when `:` or `=` follows it, so a search about a password reset is allowed. A pattern that cannot be evaluated counts as a match.
- The desktop alert passes the tool name to `osascript` as an argument instead of pasting it into AppleScript source, so a tool name cannot break out of the string.
- `pre-commit-quality-gate.sh` blocks the commit with exit 2 when it cannot enter the project folder. The first release let the commit through with a warning.
- `install.sh` says that the allow-list starts empty, so every send is blocked until you add the domains you send to.

## 2026-11-12

- `egress-guard.sh` blocks with exit 2. Earlier copies exited 1, which Claude Code treats as a non-blocking error, so the tool call still ran.
- `egress-guard.sh` matches secret-shaped text with bash `[[ =~ ]]` instead of `printf | grep -q`. Under `pipefail`, `grep -q` exits at the first match and `printf` dies with SIGPIPE, so a secret near the start of a payload over 64 KB was allowed.
- `egress-guard.sh` checks every recipient of a SEND: `to`, `cc`, `bcc`, `recipient`, `recipients` and `email`, as a string, a comma or semicolon list, or an array. One address off the allow-list blocks the send. Before this, only the text after the last `@` of one field was read, so `x@evil.example, y@allowed.example` passed and `bcc` was never read.
- `egress-guard.sh` reads a URL's host after the scheme and before the first `/`, `?`, `#` or backslash. A SEND URL that carries user info (`https://allowed.example:x@evil.example/hook`) or a backslash is blocked. A SEND that has both recipients and a URL must pass on both.
- `egress-guard.sh` checks every URL a call names: `url`, `params.url`, each `urls` entry, `input.url`, each `input.startUrls` URL and `request.url`. A SEND checks each against the allow-list, and a FETCH runs each through the secret scan and the blocklist. It used to read only the first one it found.
- `egress-guard.sh` finds recipient fields at any depth and in any case, such as `To`, `message.cc`, `toRecipients` and `cc_addresses`. `from`, `sender` and `reply_to` are not read as destinations, and a body that mentions an address is not a recipient.
- `egress-guard.sh` reads the allow-list and the blocklist with case, spaces and carriage returns ignored, and keeps a last line that has no newline.
- While the blocklist holds a domain, a FETCH host with a character outside a-z, 0-9, dot and hyphen is blocked, since a percent escape such as `bad%2eexample` could name a blocklisted host. With no blocklist, fetches stay open. The hook runs in the C locale, so these checks are ASCII only.
- A block for secret-shaped text shows the first four characters and the length of the match. It used to print up to 200 characters of the destination, which put the secret in the agent's context and the log.
- SEARCH scans every string the call sends, not only the query field.
- `egress-guard.sh` writes a missing allow-list as comments only, so every send is blocked until you add a domain. Earlier copies wrote a default list that allowed gmail.com.
- `egress-guard.sh` blocks an empty hook payload and a payload with no tool name, like every other input it cannot read.
- `egress-guard.sh` reads through pipes only. Here-documents and here-strings made bash 3.2 write a temp file, and on a full disk those reads came back empty.
- Tests are in `tests/` and run with `bash tests/run.sh`. The egress tests use a stand-in `osascript`, so they never raise a real desktop alert.
- `readonly-scope-guard.sh` tells the agent to stop and ask you when read-only mode blocks a write. It no longer prints the command that turns the mode off, which an agent could run itself.
- `pre-commit-quality-gate.sh` skips its checks when it cannot enter the project folder, instead of running them in the wrong folder, and prints a line saying the checks did not run.
- `no-console-log.sh` hands the file path and the matched lines to Python as environment values. They used to be pasted into the Python source, so a line such as `console.log('''); import os; ...` could run code inside the hook.
- `AGENTS.md` lists the real test and lint commands.
- `block-destructive.sh` drops two pipe-to-shell patterns that an earlier pattern on the same line already covered, so they could never match. Its behavior is unchanged.
- `README.md` says that only exit 2 blocks a call, lists what `egress-guard.sh` reads, and shows a blocked send in an Example section. The destructive-command scanner update follows in a later release.
