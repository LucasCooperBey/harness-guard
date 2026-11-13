# HarnessGuard

Eight Claude Code hooks that guard an autonomous coding agent. They cover exfiltration, destructive commands, write scope, and code quality. Each one is a small shell script. The only dependencies are `jq` and `python3`.

These are PreToolUse and PostToolUse hooks. Claude Code runs them before or after a tool call. A hook blocks only with exit code 2. Any other exit, including exit 1, is a non-blocking error, and Claude Code still runs the tool call. Exit 0 allows the call. The hooks do not use the network, do not send telemetry, and do not contain secrets. They read the tool payload on stdin and decide allow or block.

## Why

An agent with shell, web, and file access can leak a credential, delete the wrong directory, force-push `main`, or weaken a linter so an error disappears. These hooks refuse those calls before they run.

## The hooks

| Hook | Event | What it blocks |
|---|---|---|
| **egress-guard.sh** | PreToolUse (web/email/fetch) | Data leaving the machine. SEND tools must target a domain on the allow-list, and a destination the hook cannot read is blocked. SEARCH and FETCH stay open for reading, and are blocked when the query or URL carries secret-shaped text (keys, `op://`, private keys). |
| **block-destructive.sh** | PreToolUse (Bash) | `rm -rf /` or `~`, force-push to main/master, `DROP TABLE`/`TRUNCATE`, pipe-to-shell (`curl ... \| bash`), `chmod 777`, writes to `/etc`. Optional `HARNESS_GUARD_PROTECT` env to fence irreplaceable dirs. |
| **readonly-scope-guard.sh** | PreToolUse (Edit/Write) | Out-of-scope writes. Two modes via marker files: **read-only** (deny all writes) and **scope-guard** (writes must fall inside a declared allow-list, minus an exclude-list). Inert when no marker is present. |
| **config-protection.sh** | PreToolUse (Edit/Write) | Edits that weaken tooling: ESLint/Biome/Prettier/Ruff configs, or relaxing `tsconfig` strict flags (`strict:false`, `noImplicitAny:false`, `skipLibCheck:true`). Override with `ECC_ALLOW_CONFIG_EDIT=1`. |
| **no-any-types.sh** | PostToolUse (Edit/Write) | `: any` introduced into TypeScript (skips tests). Escape hatch: `// any-ok`. |
| **no-console-log.sh** | PostToolUse (Edit/Write) | Non-blocking warning on `console.log` in prod TS/JS. |
| **pre-commit-quality-gate.sh** | PreToolUse (Bash) | `git commit` when the repo's own `test` / `lint` / `typecheck` scripts fail. |
| **verify-integrity.sh** | manual / SessionStart | SHA-256 baselines every hook file and warns on tampering. Run `verify-integrity.sh generate` once to set the baseline. |

## Install

```bash
git clone https://github.com/LucasCooperBey/harness-guard.git
cd harness-guard
./install.sh
```

Then merge the `hooks` block from [`settings.example.json`](./settings.example.json) into `~/.claude/settings.json`. Restart Claude Code.

### Customize

- Allow-list for outbound sends: `~/.claude/allowlist-domains.txt` (one domain per line; a line that starts with `#` is a comment). The hook creates it on first use holding comments only, so every send is blocked until you add the domains you send to, for example `example.com`. A domain also allows its subdomains.
- Protect directories from deletion: `export HARNESS_GUARD_PROTECT="my-backups|wedding-photos"`.
- Known-bad fetch domains: `~/.claude/blocklist-domains.txt`, one per line. While it holds a domain, a fetch whose host has a character outside a-z, 0-9, dot and hyphen is blocked too, since an escaped name could hide a listed domain.
- The hooks are plain bash. Read them. Delete any you do not want.

### What egress-guard reads

- Recipients come from fields named `to`, `cc`, `bcc`, `recipient(s)`, `email(s)` or `address(es)`, or `to`, `cc` or `bcc` joined to one of those (`toRecipients`, `cc_addresses`), at any depth and in any case. Any other string in the call that is wholly an address or a list of addresses counts too, whatever its field is called (`recipientEmail`, `attendees`). Each entry must be a bare address or `Name <address>`, and every address must be on the allow-list. Every address-shaped token in any other string is checked the same way, including a token in `name`, `displayName`, `display_name` or `label`, and a token under a field the hook does not list. Strings under `from`, `sender`, `reply_to` and `replyTo` are not destinations, and neither are the fields `subject`, `body`, `text`, `content`, `message`, `html`, `description`, `prompt` and `query`, so a body that mentions an address stays prose. Message and thread ids and attachment names (`inReplyTo`, `references`, `messageId`, `threadId`, `attachments`, `filename`, `path`) can hold an `@` and are not destinations either, so a reply to a thread is not blocked.
- URLs come from `url`, `params.url`, each `urls` entry, `input.url`, each `input.startUrls` URL and `request.url`, plus any other string in the call that is wholly a URL (`endpoint`). A SEND needs every URL host on the allow-list. A FETCH checks every URL for secrets and against the blocklist. A string that starts with a scheme and `://` and holds a newline, a tab or another control character is blocked, including under a field that is not a URL field. Prose fields are the exception, so a body that opens with a link and goes on to a new line is allowed. A blocked URL is shown with its user info replaced by `***`.
- A SEND tool with no recipient field and no URL is blocked, because the hook cannot tell where it goes. Slack posts and Notion pages are in that group. If you trust a tool like that, take it out of the egress-guard matcher in `settings.json`.
- A tool that names its destination only in a shape the hook does not recognize is read as having no destination, so it is blocked. The hook cannot know every tool's schema, so it fails closed instead of guessing.

## Example

With the hooks installed and an allow-list that does not hold `not-on-your-list.example`, an agent's Gmail send to that domain stops before it runs. This is what the hook printed from a fresh clone on 2026-11-12 (the allow-list path is shortened). The block message lists both kinds of fix, whichever rule fired:

```text
BLOCKED by egress-guard: SEND to a domain not on the allow-list

Tool: mcp__claude_ai_Gmail__send_email
Domain: not-on-your-list.example  Dest: someone@not-on-your-list.example

If this is legitimate:
  - SEND target: add the domain to ~/.claude/allowlist-domains.txt
  - FETCH/SEARCH flagged a secret-shaped string: re-issue without the credential in the URL/query,
    or route the fetch through an isolated quarantine sub-agent instead.
```

The hook exits 2, so Claude Code does not run the send and shows the agent this message. Add `example.com` to the allow-list and a send to `someone@example.com` goes through, with a line in `~/.claude/artifacts/logs/egress-guard.log`.

## Updating from an earlier copy

Earlier copies of `egress-guard.sh` exited 1 and only warned, so Claude Code still ran the call. Re-run `install.sh` or copy the hook again.

## Design principles

1. **Fail closed on the exfil leg.** If `egress-guard` cannot read where a SEND is going, it blocks.
2. **Leave the inbound path open.** Fetching and reading pages is allowed. Only secrets leaving in a URL or query are stopped.
3. **Inert until armed.** `readonly-scope-guard` does nothing unless you drop a marker file.
4. **A hook blocks only with exit 2.** Exit 1 does not block the tool call.

## Tests

```bash
bash tests/run.sh
```

## License

MIT. See [LICENSE](./LICENSE). Built by [LucasCooperBey](https://github.com/LucasCooperBey).

Made by Lucas Cooper-Bey for 100 Doors, one free tool a day: https://sandiegoaistudio.com/season
If you like seeing how other builders guard their agents, San Diego AI Studio runs Sharathon, where people show their own setups: https://www.skool.com/sandiegoaistudio
