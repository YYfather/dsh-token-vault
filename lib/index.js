/**
 * @yyfather/dsh-token-vault — host half.
 *
 * A Cordis plugin (loaded as a profile row, see cordis.patch.yml) that keeps
 * the user's tokens (GitHub, npm, ...) in DSH's own credential store
 * (ctx.credentials → ~/.credentials.yaml), and lets the agent USE them
 * without the secrets ever entering model context or client UI.
 *
 * Responsibilities:
 *   1. Register vault_* tools:
 *        vault_list    — names + status only (never values)
 *        vault_has     — one name's presence
 *        vault_set     — store/update one token (value never echoed)
 *        vault_remove  — delete one token
 *        vault_import  — import from `gh auth token` (source: gh) or ~/.npmrc (source: npm)
 *        vault_run     — run gh/npm/npx/node/git with the token injected as env var
 *        vault_show    — reveal one token (ONLY with confirm: true, i.e. explicit user request)
 *   2. Inject usage rules as a systemPrompt section (token-vault-usage).
 *   3. Serve same-origin management routes for the Settings page:
 *        GET  /vault/status   → { tokens: [{name, configured}], supports }
 *        POST /vault/set      → { name, value, description? }
 *        POST /vault/remove   → { name }
 *        POST /vault/import   → { source: 'gh' | 'npm' }
 *
 * Storage is the host credentials service record space, keyed
 * `dsh-token-vault/<name>` — the same encrypted, locked store the DSH
 * authorization stack uses; no plaintext file is written by this plugin.
 */

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

const SCOPE = 'dsh-token-vault';
const NAME_PATTERN = /^[a-z][a-z0-9-]*$/;
const RUNNABLE = new Set(['gh', 'npm', 'npx', 'node', 'git']);
const DEFAULT_ENV = { github: 'GH_TOKEN', gh: 'GH_TOKEN', npm: 'NPM_TOKEN', node: 'NPM_TOKEN' };
const OUTPUT_CAP = 20000;

const execFileAsync = promisify(execFile);

// ---------------------------------------------------------------------------
// Usage rules — injected into the system prompt so the agent follows the
// discipline automatically (never echo tokens; prefer vault_run).
// ---------------------------------------------------------------------------
const USAGE_RULES = `令牌库使用规则（@yyfather/dsh-token-vault）：
1. 令牌（GitHub/npm/API Key）安全保存在 DSH 凭证库中，明文永远不出 Host；列表/状态只返回名称，绝不返回令牌值。
2. 需要用令牌执行操作时，必须优先用 vault_run（如 vault_run gh repo create ... / vault_run npm publish）——令牌只注入子进程环境变量（GH_TOKEN/NPM_TOKEN），不会进入对话或日志。
3. 禁止：把令牌值打印/贴进回复、把令牌写入工作区文件、把 vault_show 的结果转述给用户。
4. 仅当用户明确要求"查看/展示"某个令牌时，才调用 vault_show(name, confirm: true)；调用后提醒用户该值已泄露到对话，用完可在 设置 → 凭证库 变更。
5. 命名规则：令牌名用小写连字符（github / npm / gh / npmjs...）；token 内容只在 设置 → 凭证库 或 vault_set 中录入。
6. environment 变量名映射：github/gh → GH_TOKEN，npm/node → NPM_TOKEN；vault_run 的 env_name 可覆盖。
7. 命令白名单：gh / npm / npx / node / git（参数任意，无 shell 注入面）。`;

// ---------------------------------------------------------------------------
// Credentials helpers
// ---------------------------------------------------------------------------

function isValidName(name) {
  return typeof name === 'string' && NAME_PATTERN.test(name);
}

function recordKey(name) {
  return SCOPE + '/' + name;
}

function stripKeyPrefix(key) {
  return String(key).slice(SCOPE.length + 1);
}

// ---------------------------------------------------------------------------
// Import sources (host-side reads, no secret returned through the wire)
// ---------------------------------------------------------------------------

async function importFromGh() {
  const { stdout } = await execFileAsync('gh', ['auth', 'token'], { windowsHide: true, maxBuffer: 1024 * 1024 });
  const token = String(stdout).trim();
  if (!token) throw new Error('gh 未登录或令牌为空');
  return token;
}

async function importFromNpm() {
  const rcPath = path.join(os.homedir(), '.npmrc');
  let rc = '';
  try { rc = fs.readFileSync(rcPath, 'utf8'); } catch { /* absent */ }
  const m = rc.match(/^\s*\/\/registry\.npmjs\.org\/:_authToken\s*=\s*(\S+)\s*$/m);
  if (!m) throw new Error('~/.npmrc 中未找到 registry.npmjs.org 的 _authToken');
  return m[1].trim();
}

// ---------------------------------------------------------------------------
// HTTP route helpers
// ---------------------------------------------------------------------------

function sendJson(res, status, data) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(data));
}

function readJsonBody(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let done = false;
    req.on('data', (chunk) => {
      if (done) return;
      size += chunk.length;
      if (size > limit) { done = true; reject(new Error('body too large')); req.destroy(); return; }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (done) return;
      done = true;
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')); } catch { reject(new Error('invalid JSON body')); }
    });
    req.on('error', (err) => { if (!done) { done = true; reject(err); } });
  });
}

// ---------------------------------------------------------------------------
// Tool definitions (raw JSON schema)
// ---------------------------------------------------------------------------

const OUTPUT_SCHEMA = {
  type: 'object',
  properties: { ok: { type: 'boolean' }, text: { type: 'string' } },
  required: ['ok', 'text'],
};

function toolDef(name, description, parameters, run) {
  return {
    name,
    description,
    parameters,
    output: {
      schema: OUTPUT_SCHEMA,
      render(args, value) {
        const text = (value && typeof value === 'object' && typeof value.text === 'string') ? value.text : String(value);
        return [{ type: 'text', text }];
      },
    },
    timeoutMs: 120000,
    async execute(args, exec) {
      try {
        return await run(args || {}, exec && exec.signal);
      } catch (err) {
        return { ok: false, text: 'vault: ' + String((err && err.message) || err) };
      }
    },
  };
}

function buildTools(store) {
  return [
    toolDef('vault_list', '列出凭证库中已保存的令牌名称与状态（不返回任何令牌值）。无参数。', {
      type: 'object',
      properties: {},
    }, async () => {
      const names = await store.names();
      if (names.length === 0) return { ok: true, text: '凭证库为空（可在 设置 → 凭证库 或 vault_set 添加）' };
      return { ok: true, text: '已保存令牌：\n- ' + names.join('\n- ') };
    }),
    toolDef('vault_has', '检查凭证库中是否存在指定令牌。参数：name 令牌名（小写连字符，如 github / npm）。', {
      type: 'object',
      properties: { name: { type: 'string', description: '令牌名（小写连字符）' } },
      required: ['name'],
    }, async (args) => {
      const { name } = args;
      if (!isValidName(name)) return { ok: false, text: '非法令牌名: ' + String(name) + '（需匹配 ^[a-z][a-z0-9-]*$）' };
      const has = await store.has(name);
      return { ok: true, text: has ? ('已保存: ' + name) : ('未保存: ' + name) };
    }),
    toolDef('vault_set', '保存/更新一个令牌（值只在 Host 侧存储，绝不回显）。参数：name 令牌名（小写连字符），value 令牌值，description 可选备注。', {
      type: 'object',
      properties: {
        name: { type: 'string', description: '令牌名（小写连字符，如 github / npm）' },
        value: { type: 'string', description: '令牌值（不回显）' },
        description: { type: 'string', description: '可选备注' },
      },
      required: ['name', 'value'],
    }, async (args) => {
      const { name, value, description } = args;
      if (!isValidName(name)) return { ok: false, text: '非法令牌名: ' + String(name) + '（需匹配 ^[a-z][a-z0-9-]*$）' };
      if (typeof value !== 'string' || !value.trim()) return { ok: false, text: '令牌值不能为空' };
      await store.set(name, value.trim(), { description });
      return { ok: true, text: '已保存: ' + name + '（长度 ' + String(value.trim().length) + '）' };
    }),
    toolDef('vault_remove', '删除一个令牌。参数：name 令牌名。', {
      type: 'object',
      properties: { name: { type: 'string', description: '令牌名' } },
      required: ['name'],
    }, async (args) => {
      const { name } = args;
      if (!isValidName(name)) return { ok: false, text: '非法令牌名: ' + String(name) };
      await store.remove(name);
      return { ok: true, text: '已删除: ' + name };
    }),
    toolDef('vault_import', '从现有认证源导入令牌到凭证库（值不回显）。参数：source gh（读取 gh auth token）或 npm（读取 ~/.npmrc 的 registry.npmjs.org _authToken），name 可选（默认 github / npm）。', {
      type: 'object',
      properties: {
        source: { type: 'string', enum: ['gh', 'npm'], description: '导入来源：gh = GitHub CLI 密钥环；npm = ~/.npmrc' },
        name: { type: 'string', description: '可选目标名，默认 github / npm' },
      },
      required: ['source'],
    }, async (args) => {
      const src = args.source;
      const name = args.name || (src === 'gh' ? 'github' : 'npm');
      if (!isValidName(name)) return { ok: false, text: '非法令牌名: ' + String(name) };
      const value = src === 'gh' ? await importFromGh() : await importFromNpm();
      await store.set(name, value, { description: 'imported from ' + src });
      return { ok: true, text: '已从 ' + src + ' 导入并保存: ' + name };
    }),
    toolDef('vault_run', '用凭证库中的令牌执行命令（令牌只注入子进程环境变量，绝不出现在输出/日志）。参数：name 令牌名，command 命令（gh/npm/npx/node/git），args 参数数组(可选)，env_name 环境变量名(可选，默认 github→GH_TOKEN、npm/node→NPM_TOKEN)。', {
      type: 'object',
      properties: {
        name: { type: 'string', description: '令牌名（如 github / npm）' },
        command: { type: 'string', description: '命令：gh / npm / npx / node / git' },
        args: { type: 'array', items: { type: 'string' }, description: '命令参数数组' },
        env_name: { type: 'string', description: '可选环境变量名，覆盖默认映射' },
      },
      required: ['name', 'command'],
    }, async (args, signal) => {
      const { name, command, args: cmdArgs, env_name: envName } = args;
      if (!isValidName(name)) return { ok: false, text: '非法令牌名: ' + String(name) };
      if (!RUNNABLE.has(command)) return { ok: false, text: '命令不在白名单: ' + String(command) + '（允许 gh/npm/npx/node/git）' };
      const token = await store.get(name);
      if (!token) return { ok: false, text: '未找到令牌: ' + name + '（可用 vault_set 或 vault_import 添加）' };
      const effectiveEnv = envName || DEFAULT_ENV[name] || DEFAULT_ENV[command] || 'TOKEN_' + name.toUpperCase();
      try {
        const { stdout, stderr } = await execFileAsync(command, Array.isArray(cmdArgs) ? cmdArgs : [], {
          env: { ...process.env, [effectiveEnv]: token },
          windowsHide: true,
          maxBuffer: 8 * 1024 * 1024,
        });
        const out = String(stdout || '').slice(0, OUTPUT_CAP);
        const err = String(stderr || '').slice(0, OUTPUT_CAP);
        const parts = [];
        if (out) parts.push(out.trimEnd());
        if (err) parts.push('[stderr]\n' + err.trimEnd());
        if (!parts.length) parts.push('(无输出)');
        return { ok: true, text: '$ ' + command + ' ' + (cmdArgs || []).join(' ') + '\n' + parts.join('\n') };
      } catch (err) {
        const code = err && err.code;
        const std = String((err && err.stdout) || '') + String((err && err.stderr) || '');
        return { ok: false, text: '命令退出码 ' + String(code) + ': ' + String(std || (err && err.message) || '未知错误').slice(0, OUTPUT_CAP) };
      }
    }),
    toolDef('vault_show', '显示一个令牌的明文（仅当用户明确要求时使用；必须传 confirm: true，否则拒绝；令牌将出现在对话中，用完建议轮换）。', {
      type: 'object',
      properties: {
        name: { type: 'string', description: '令牌名' },
        confirm: { type: 'boolean', description: '确认展示明文，必须为 true' },
      },
      required: ['name', 'confirm'],
    }, async (args) => {
      const { name, confirm } = args;
      if (confirm !== true) return { ok: false, text: '请在确认后传 confirm: true 才展示明文' };
      if (!isValidName(name)) return { ok: false, text: '非法令牌名: ' + String(name) };
      const token = await store.get(name);
      if (!token) return { ok: false, text: '未找到令牌: ' + name };
      return { ok: true, text: '令牌 ' + name + ' 明文：' + token + '\n⚠ 该值已出现在对话中，使用后建议在 设置 → 凭证库 变更。' };
    }),
  ];
}

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

const inject = ['tools', 'credentials'];

async function apply(ctx) {
  const disposers = [];
  const credentials = ctx.credentials;
  const webServer = ctx.get('webServer');
  const systemPrompt = ctx.get('systemPrompt');

  const store = {
    async names() {
      const entries = await credentials.listRecords();
      return entries
        .map((e) => String(e.key))
        .filter((k) => k.startsWith(SCOPE + '/'))
        .map(stripKeyPrefix)
        .sort();
    },
    async has(name) {
      const info = await credentials.describeRecord(recordKey(name));
      return !!(info && info.configured);
    },
    async get(name) {
      const rec = await credentials.readRecord(recordKey(name));
      if (!rec || rec.kind !== 'api-key' || !rec.key) return undefined;
      return rec.key;
    },
    async set(name, value, meta) {
      await credentials.modifyRecord(recordKey(name), async (current) => ({
        kind: 'api-key',
        key: value,
        env: meta && meta.description ? { description: meta.description } : (current && current.kind === 'api-key' ? current.env : undefined),
      }));
    },
    async remove(name) {
      await credentials.deleteRecord(recordKey(name));
    },
  };

  for (const def of buildTools(store)) {
    disposers.push(ctx.tools.register(def));
  }

  if (systemPrompt !== undefined) {
    disposers.push(systemPrompt.section({ name: 'token-vault-usage', order: 550, text: USAGE_RULES }));
  }

  if (webServer !== undefined) {
    disposers.push(webServer.register({
      kind: 'exact',
      path: '/vault/status',
      async handler(req, res) {
        try {
          const tokens = [];
          for (const name of await store.names()) tokens.push({ name, configured: true });
          sendJson(res, 200, { ok: true, tokens });
        } catch (err) {
          sendJson(res, 500, { ok: false, error: String((err && err.message) || err) });
        }
      },
    }));
    disposers.push(webServer.register({
      kind: 'exact',
      path: '/vault/set',
      async handler(req, res) {
        try {
          if (req.method !== 'POST') return sendJson(res, 405, { ok: false, error: 'POST only' });
          const a = await readJsonBody(req, 1024 * 1024);
          if (!isValidName(a.name)) return sendJson(res, 400, { ok: false, error: '非法令牌名（需匹配 ^[a-z][a-z0-9-]*$）' });
          if (typeof a.value !== 'string' || !a.value.trim()) return sendJson(res, 400, { ok: false, error: '令牌值不能为空' });
          await store.set(a.name, a.value.trim(), { description: a.description });
          sendJson(res, 200, { ok: true, name: a.name });
        } catch (err) {
          sendJson(res, 400, { ok: false, error: String((err && err.message) || err) });
        }
      },
    }));
    disposers.push(webServer.register({
      kind: 'exact',
      path: '/vault/remove',
      async handler(req, res) {
        try {
          if (req.method !== 'POST') return sendJson(res, 405, { ok: false, error: 'POST only' });
          const a = await readJsonBody(req, 1024 * 1024);
          if (!isValidName(a.name)) return sendJson(res, 400, { ok: false, error: '非法令牌名' });
          await store.remove(a.name);
          sendJson(res, 200, { ok: true, name: a.name });
        } catch (err) {
          sendJson(res, 400, { ok: false, error: String((err && err.message) || err) });
        }
      },
    }));
    disposers.push(webServer.register({
      kind: 'exact',
      path: '/vault/import',
      async handler(req, res) {
        try {
          if (req.method !== 'POST') return sendJson(res, 405, { ok: false, error: 'POST only' });
          const a = await readJsonBody(req, 1024 * 1024);
          const value = a.source === 'npm' ? await importFromNpm() : await importFromGh();
          const name = a.name || (a.source === 'npm' ? 'npm' : 'github');
          await store.set(name, value, { description: 'imported from ' + String(a.source) });
          sendJson(res, 200, { ok: true, name });
        } catch (err) {
          sendJson(res, 400, { ok: false, error: String((err && err.message) || err) });
        }
      },
    }));
  }

  return () => {
    for (const d of disposers) { try { d(); } catch { /* ignore */ } }
  };
}

export default { inject, apply };
