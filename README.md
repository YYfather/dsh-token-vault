# @yyfather/dsh-token-vault

**Secure credential vault for DeepSeek Harness** · 凭证库插件

Store API keys, tokens, accounts and SSH keys in DSH's own credential store (`ctx.credentials` → `~/.credentials.yaml`). **Encrypted at rest with Windows DPAPI**, never in model context, never in the browser. The agent uses them through `vault_run`, which injects one field into a child-process environment only; `vault_show` (the single disclosure path) requires an explicit `confirm: true`.

> 设置 → 凭证库 录入一次，之后 GitHub / npm / 任意 REST API 调用由 Host 侧代持。

## Credential model

Every credential has **four fields**:

| 字段 | 说明 |
| --- | --- |
| 名称 | free-form, Chinese allowed, 1–64 chars, no `/` |
| 类型 | preset type id (see below) or `custom` |
| 凭证字段 | one or more key/value values; preset types enforce their own keys |
| 备注 | free text, shown in `vault_list` |

Preset types (field keys):

| id | 名称 | 字段 |
| --- | --- | --- |
| `api-key` | API Key | `key` |
| `token` | 访问令牌 | `token` |
| `username-password` | 用户名密码 | `username`, `password` |
| `github` | GitHub Token | `token` |
| `npm` | npm Token | `token` |
| `database` | 数据库 | `host`, `port`(opt), `username`, `password`, `database`(opt) |
| `smtp` | 邮箱 / SMTP | `host`, `port`(opt), `username`, `password` |
| `ssh-key` | SSH 私钥 | `privateKey`, `passphrase`(opt) |
| `custom` | 自定义 | user-defined labels (Chinese allowed) |

## Tools (agent-facing)

| Tool | Purpose |
| --- | --- |
| `vault_list` | names + type + remark + field labels + env var (never values) |
| `vault_has` | check one name's presence |
| `vault_set` | store/update a credential (values never echoed) |
| `vault_remove` | delete a credential |
| `vault_import` | import from `gh auth token` or `~/.npmrc` |
| `vault_run` | run `gh/npm/npx/node/git/curl` with one field injected; `%TOKEN%` in args is substituted host-side and scrubbed from output |
| `vault_show` | reveal all fields (**requires `confirm: true`**) |

Environment variable resolution for `vault_run`: explicit `env_name` → stored `env` → `github/gh` → `GH_TOKEN`, `npm/node` → `NPM_TOKEN`, ASCII name → `TOKEN_<NAME>`; non-ASCII names need an explicit `env_name`.

## Install

```sh
dsh plugin --profile desktop add @yyfather/dsh-token-vault
```

The package declares `dsh.bundle.patch` so it mounts automatically; restart DSH Desktop to activate. Then manage it from **设置 → 市场 → 已安装** (enable / update / uninstall), or paste credentials in **设置 → 凭证库**.

## Editing credentials

Open **Settings → Credential vault** and click **编辑** on a saved row. The form is prefilled with the
name, type, remark and environment-variable name; secret fields stay blank.

| Input | Effect |
| --- | --- |
| non-empty value | overwrites that field |
| empty string | keeps the stored value |
| field omitted | deletes that field (delete a row to drop a custom field) |

The same semantics apply to the agent tool `vault_set`: calling it with an existing name updates the
credential instead of replacing every field. The name cannot be renamed in place — create the new name
and delete the old one.

```sh
# update only the remark; the token stays untouched
curl -s localhost:PORT/vault/set -H 'content-type: application/json' \
  -d '{"name":"npm","type":"npm","fields":{"token":""},"remark":"rotated 2026-11"}'
```

## Security design

- **At rest — encrypted**: every record payload is encrypted with Windows DPAPI (`CurrentUser`) before it reaches DSH's credential store, and written as `{ v: 3, enc: "dpapi", data: <base64> }`. The ciphertext is bound to this Windows account on this machine: a copied `.credentials.yaml`, a backup or a disk image decrypts to nothing, while the same user gets it back with no password prompt. PowerShell's `ProtectedData` is the bridge; the plaintext travels over **stdin**, never argv, so it stays out of process lists.
- **What encryption does not do**: a process already running as you can call DPAPI itself, so this removes plaintext at rest — not same-user access. Non-secret metadata (name / type / remark / field names / env var) stays readable; that is what lets listing work without decryption.
- **Metadata vs values**: `vault_list` and the Settings page never decrypt — they read name, type, remark, field names and the env var only.
- **Legacy records** written before encryption are read as-is, then re-encrypted in place the first time they are listed or used.
- **Usage**: `vault_run` places one field in the child environment only; stdout/stderr are scrubbed of secret-marked field values before they reach the model.
- **Disclosure**: `vault_show` is the only leak path and demands `confirm: true`.
- **Prompt section** `token-vault-usage` injected automatically: the agent must never print or persist secret values.

Platform note: encryption uses DPAPI, so it is Windows-only. On other platforms the plugin refuses to store (`DPAPI 加密仅支持 Windows`) rather than silently falling back to plaintext.

## Structure

- `lib/index.js` — host: type registry, `ctx.tools.register` for 7 vault tools, `webServer` routes `/vault/types|status|set|remove|import`, `systemPrompt.section` usage rules
- `lib/client.js` — browser `__ModuleLoader__` bundle: Settings → 凭证库 (name / type / fields / remark, add / import / delete, values never displayed)
- `cordis.patch.yml` — bundle mount patch
- `package.json` — market-format compliant (strict `inject`, full `exports` incl. `./client` and `./cordis.patch.yml`)

## License

MIT © YYfather
