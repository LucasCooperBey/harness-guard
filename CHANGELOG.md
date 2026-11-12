# Changelog

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
- `README.md` says that only exit 2 blocks a call and lists what `egress-guard.sh` reads. The destructive-command scanner update follows in a later release.
