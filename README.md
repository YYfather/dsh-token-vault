# @yyfather/dsh-token-vault

**Secure credential vault for DeepSeek Harness** · 凭证库插件

Store your GitHub / npm / API tokens in DSH's own credential store (`ctx.credentials` → `~/.credentials.yaml`). **Secrets never leave the host** — no plaintext file, no model context, no browser round-trip. The agent uses tokens through `vault_run` which injects them into a child-process environment only; `vault_show` (the single disclosure path) requires an explicit `confirm: true`.

> 设置 → 凭证库 录入一次，之后所有 GitHub/npm 操作由 Host 侧代持。

## Tools (agent-facing)

| Tool | Purpose |
| --- | --- |
| `vault_list` | List stored token names only (never values) |
| `vault_has` | Check one token's presence |
| `vault_set` | Store/update a token (value never echoed) |
| `vault_remove` | Delete a token |
| `vault_import` | Import from `gh auth token` (source: gh) or `~/.npmrc` (source: npm) |
| `vault_run` | Run `gh/npm/npx/node/git` with the token injected via env (github/gh → `GH_TOKEN`, npm/node → `NPM_TOKEN`, `env_name` overrides); output contains no secrets |
| `vault_show` | Reveal one token (**requires `confirm: true`**, only on explicit user request) |

## Install

```sh
dsh plugin --profile desktop add @yyfather/dsh-token-vault
```

The package declares `dsh.bundle.patch` so it mounts automatically; restart DSH Desktop to activate. Then manage it from **设置 → 市场 → 已安装** (enable / update / uninstall), or paste tokens in **设置 → 凭证库**.

## Security design

- Storage: DSH credential record space (`dsh-token-vault/<name>`, atomic `modifyRecord`) — no new plaintext files.
- Usage: `vault_run` places the token in the child environment only; stdout/stderr/logs never contain it.
- Disclosure: `vault_show` is the only leak path and demands `confirm: true`; usage rules advise rotating after use.
- Prompt section `token-vault-usage` injected automatically: the agent must never print or persist tokens.

## Structure

- `lib/index.js` — host: `ctx.tools.register` for 7 vault tools; `webServer` routes `/vault/status|set|remove|import`; `systemPrompt.section` usage rules
- `lib/client.js` — browser `__ModuleLoader__` bundle: Settings → 凭证库 (add / import / delete, values never displayed)
- `cordis.patch.yml` — bundle mount patch
- `package.json` — market-format compliant (strict `inject`, full `exports` incl. `./client` and `./cordis.patch.yml`)

## License

MIT © YYfather
