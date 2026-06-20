# HarnessGuard

**Eight drop-in [Claude Code](https://claude.com/claude-code) hooks that make an autonomous coding agent safe to leave running.** Guardrails for exfiltration, destructive commands, write-scope, and code quality — each one a small, auditable shell script with zero dependencies beyond `jq` + `python3` (already on most dev machines).

These are PreToolUse / PostToolUse hooks: Claude Code runs them *before* (or after) a tool call and a non-zero exit **blocks the call**. No network, no telemetry, no secrets — they read the tool payload on stdin and decide allow/block.

## Why

An agent with shell + web + file access can, in a single bad turn, leak a credential, `rm -rf` the wrong directory, force-push `main`, or weaken your linter to make an error "go away." HarnessGuard closes those holes structurally — the agent *cannot* do the dangerous thing, regardless of what a prompt (or a prompt injection) tells it to do.

## The hooks

| Hook | Event | What it blocks |
|---|---|---|
| **egress-guard.sh** | PreToolUse (web/email/fetch) | Data exfiltration. SEND tools → domain allow-list (fail-closed). SEARCH/FETCH → blocks secret-shaped strings (keys, `op://`, private keys) smuggled into a query/URL. Reading pages stays open so research isn't broken. |
| **block-destructive.sh** | PreToolUse (Bash) | `rm -rf /` or `~`, force-push to main/master, `DROP TABLE`/`TRUNCATE`, pipe-to-shell (`curl … \| bash`), `chmod 777`, writes to `/etc`. Optional `HARNESS_GUARD_PROTECT` env to fence irreplaceable dirs. |
| **readonly-scope-guard.sh** | PreToolUse (Edit/Write) | Out-of-scope writes. Two modes via marker files: **read-only** (deny all writes) and **scope-guard** (writes must fall inside a declared allow-list, minus an exclude-list). Inert when no marker is present. |
| **config-protection.sh** | PreToolUse (Edit/Write) | Edits that weaken tooling: ESLint/Biome/Prettier/Ruff configs, or relaxing `tsconfig` strict flags (`strict:false`, `noImplicitAny:false`, `skipLibCheck:true`). Override with `ECC_ALLOW_CONFIG_EDIT=1`. |
| **no-any-types.sh** | PostToolUse (Edit/Write) | `: any` introduced into TypeScript (skips tests). Escape hatch: `// any-ok`. |
| **no-console-log.sh** | PostToolUse (Edit/Write) | Non-blocking warning on `console.log` in prod TS/JS. |
| **pre-commit-quality-gate.sh** | PreToolUse (Bash) | `git commit` when the repo's own `test` / `lint` / `typecheck` scripts fail. |
| **verify-integrity.sh** | manual / SessionStart | SHA-256 baselines every hook file and warns on tampering. Run `verify-integrity.sh generate` once to set the baseline. |

## Install

```bash
git clone https://github.com/Lucface/harness-guard.git
cd harness-guard
./install.sh          # copies hooks to ~/.claude/hooks and prints the settings snippet
```

Then merge the `hooks` block from [`settings.example.json`](./settings.example.json) into your `~/.claude/settings.json`. Restart Claude Code. That's it.

### Customize

- **Allow-list** for outbound sends: `~/.claude/allowlist-domains.txt` (one domain per line; auto-created with sensible defaults).
- **Protect dirs** from deletion: `export HARNESS_GUARD_PROTECT="my-backups|wedding-photos"`.
- Hooks are plain bash — read them, they're short. Delete any you don't want.

## Design principles

1. **Fail closed on the exfil leg.** If `egress-guard` can't read where a SEND is going, it blocks.
2. **Don't break the inbound path.** Fetching/reading pages is allowed — only *secrets leaving* are stopped — so research and browsing still work.
3. **Inert until armed.** `readonly-scope-guard` does nothing unless you drop a marker file, so it never surprises you.
4. **Structural, not advisory.** A blocked tool call is blocked. The agent can't talk its way past a non-zero exit.

## License

MIT — see [LICENSE](./LICENSE). Built by [@Lucface](https://github.com/Lucface). PRs welcome.
