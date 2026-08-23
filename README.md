# @yyfather/dsh-token-vault

DeepSeek Harness **凭证库插件**：把 GitHub / npm 等令牌安全地保存在 DSH 凭证库（`ctx.credentials` → `~/.credentials.yaml`），**明文永不进入模型上下文与浏览器端**；代理通过 `vault_run` 直接以注入环境变量的方式调用 gh / npm / npx / node / git。

> 再也不用把 token 贴进对话：设置 → 凭证库 录入一次，之后所有操作由 Host 侧代持。

## 工具（代理可用）

| 工具 | 说明 |
| --- | --- |
| `vault_list` | 列出已保存令牌名（不含值） |
| `vault_has` | 检查某个令牌是否存在 |
| `vault_set` | 保存/更新令牌（值不回显） |
| `vault_remove` | 删除令牌 |
| `vault_import` | 从 `gh auth token`（source: gh）或 `~/.npmrc`（source: npm）导入 |
| `vault_run` | 运行 `gh/npm/npx/node/git`，令牌注入环境变量（默认 github/gh → `GH_TOKEN`，npm/node → `NPM_TOKEN`，可用 `env_name` 覆盖），输出不含任何秘密 |
| `vault_show` | 明文查看（**必须 confirm: true**；仅当用户明确要求时） |

## 安装（本地）

```sh
dsh plugin --profile desktop add @yyfather/dsh-token-vault
```

或本地路径：`dsh plugin --profile desktop add "file:E:/studywork/DSHwork/plugins/token-vault/dsh-token-vault"`

带 `dsh.bundle.patch` 的包安装后自动挂载，重启 DSH Desktop 生效。

## 安全设计

- 存储：DSH 凭证库记录空间（`dsh-token-vault/<name>`，`modifyRecord` 原子读改写），不新增明文文件。
- 使用：`vault_run` 只把令牌放进子进程环境变量，stdout/stderr 与日志天然不含令牌。
- 展示：`vault_show` 是唯一泄露点，且要求 `confirm: true`（用户明确要求）；规则提示用后轮换。
- 注入提示词段 `token-vault-usage`：禁止代理打印/转述令牌、禁止写入工作区文件。

## 结构

- `lib/index.js` — host：`ctx.tools.register` 注册 7 个 vault 工具；`webServer` 提供 `/vault/status|set|remove|import`；`systemPrompt.section` 注入使用规则
- `lib/client.js` — 浏览器端 `__ModuleLoader__` bundle：设置 → 凭证库（录入/导入/删除，值不回显）
- `cordis.patch.yml` — bundle 挂载补丁

## License

MIT © YYfather
