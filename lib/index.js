/**
 * @yyfather/dsh-token-vault — host half.
 *
 * A Cordis plugin (loaded as a profile row, see cordis.patch.yml) that keeps
 * the user's credentials (API keys, tokens, accounts, SSH keys, ...) in DSH's
 * own credential store (ctx.credentials → ~/.credentials.yaml), and lets the
 * agent USE them without the secrets ever entering model context or client UI.
 *
 * [local patch] Generalised credential model — every credential carries four
 * fields: name（名称）, type（类型）, credential fields（凭证字段, one or more
 * values）, remark（备注）. Types are a preset registry (api-key / token /
 * username-password / github / npm / database / smtp / ssh-key) plus `custom`.
 *
 * Responsibilities:
 *   1. Register vault_* tools:
 *        vault_list    — names + type + remark + field labels (never values)
 *        vault_has     — one name's presence
 *        vault_set     — store/update a credential (values never echoed)
 *        vault_remove  — delete one credential
 *        vault_import  — import from `gh auth token` or ~/.npmrc
 *        vault_run     — run gh/npm/npx/node/git/curl with one field injected
 *        vault_show    — reveal one credential (ONLY with confirm: true)
 *   2. Inject usage rules as a systemPrompt section (token-vault-usage).
 *   3. Serve same-origin management routes for the Settings page:
 *        GET  /vault/status   → { tokens: [{name, type, remark, env, fields}] }
 *        GET  /vault/types    → preset type registry
 *        POST /vault/set      → { name, type, fields, remark?, env? }
 *        POST /vault/remove   → { name }
 *        POST /vault/import   → { source: 'gh' | 'npm' }
 *
 * Storage is the host credentials service record space, keyed
 * `dsh-token-vault/<name>` — the same encrypted, locked store the DSH
 * authorization stack uses; no plaintext file is written by this plugin.
 * Record shape: key = JSON { v: 2, type, fields: { <fieldKey>: <value> } },
 * env = { remark, variable }. Legacy records (a bare token string) are read
 * as type `token` with a single `token` field.
 */

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';

const SCOPE = 'dsh-token-vault';
const SCHEMA_VERSION = 2;
// Names are free-form so Chinese / mixed-language labels work.
// Rules: starts with a letter or digit, then 0-63 of letters/digits/space/_/./-.
// "/" stays forbidden because it separates the credential record key.
const NAME_PATTERN = /^[\p{L}\p{N}][\p{L}\p{N} _.\-]{0,63}$/u;
const FIELD_KEY_PATTERN = /^[\p{L}\p{N}][\p{L}\p{N} _.\-]{0,31}$/u;
const NAME_HINT = '名称 1-64 字符，以文字或数字开头，可含空格 _ . - 和各语言文字（如 github、数据库-生产密码）';
const ENV_NAME_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/;
const RUNNABLE = new Set(['gh', 'npm', 'npx', 'node', 'git', 'curl']);
const DEFAULT_ENV = { github: 'GH_TOKEN', gh: 'GH_TOKEN', npm: 'NPM_TOKEN', node: 'NPM_TOKEN' };
const TOKEN_PLACEHOLDER = '%TOKEN%';
const OUTPUT_CAP = 20000;

// ---------------------------------------------------------------------------
// Credential type registry. `primary` is the field injected by vault_run when
// no explicit field is given; `optional` fields may be left empty.
// ---------------------------------------------------------------------------
const CRED_TYPES = {
  'api-key': {
    label: 'API Key',
    fields: [{ key: 'key', label: '密钥', secret: true }],
    primary: 'key',
  },
  token: {
    label: '访问令牌',
    fields: [{ key: 'token', label: '令牌', secret: true }],
    primary: 'token',
  },
  'username-password': {
    label: '用户名密码',
    fields: [{ key: 'username', label: '用户名' }, { key: 'password', label: '密码', secret: true }],
    primary: 'password',
  },
  github: {
    label: 'GitHub Token',
    fields: [{ key: 'token', label: '令牌', secret: true }],
    primary: 'token',
  },
  npm: {
    label: 'npm Token',
    fields: [{ key: 'token', label: '令牌', secret: true }],
    primary: 'token',
  },
  database: {
    label: '数据库',
    fields: [
      { key: 'host', label: '主机' },
      { key: 'port', label: '端口', optional: true },
      { key: 'username', label: '用户名' },
      { key: 'password', label: '密码', secret: true },
      { key: 'database', label: '库名', optional: true },
    ],
    primary: 'password',
  },
  smtp: {
    label: '邮箱 / SMTP',
    fields: [
      { key: 'host', label: '服务器' },
      { key: 'port', label: '端口', optional: true },
      { key: 'username', label: '用户名' },
      { key: 'password', label: '密码', secret: true },
    ],
    primary: 'password',
  },
  'ssh-key': {
    label: 'SSH 私钥',
    fields: [{ key: 'privateKey', label: '私钥', secret: true }, { key: 'passphrase', label: '口令', optional: true, secret: true }],
    primary: 'privateKey',
  },
  custom: {
    label: '自定义',
    fields: [],
    primary: undefined,
  },
};

function typeSpec(type) {
  return CRED_TYPES[type] || CRED_TYPES.custom;
}

function typeLabel(type) {
  return typeSpec(type).label;
}

function fieldLabel(type, key) {
  const spec = typeSpec(type);
  const found = spec.fields.find((f) => f.key === key);
  return found ? found.label : key;
}

const execFileAsync = promisify(execFile);

// ---------------------------------------------------------------------------
// [local patch] Windows command resolution
//
// On Windows `npm` / `npx` are .cmd shims. `execFile('npm')` fails with ENOENT
// (CreateProcess only auto-appends .exe), and Node refuses to exec .cmd/.bat
// without a shell (CVE-2024-27980) — a shell would be the only way to reach the
// shim, which reintroduces argv quoting/injection risk. Instead we locate the
// real node.exe plus npm's JS entry point and run that: no shell, argv verbatim.
//
// process.execPath is NOT node.exe here (the host runs inside DSH's bundled
// runtime), so the lookup must go through PATH.
// ---------------------------------------------------------------------------

function findOnPath(file) {
  const dirs = String(process.env.PATH || '').split(path.delimiter).filter(Boolean);
  const hasExt = path.extname(file) !== '';
  const exts = process.platform === 'win32'
    ? String(process.env.PATHEXT || '.COM;.EXE;.BAT;.CMD').split(';').filter(Boolean)
    : [];
  const names = hasExt ? [file] : [file, ...exts.map((ext) => file + ext.toLowerCase()), ...exts.map((ext) => file + ext)];
  for (const dir of dirs) {
    for (const name of names) {
      const full = path.join(dir, name);
      try { if (fs.statSync(full).isFile()) return full; } catch { /* next */ }
    }
  }
  return undefined;
}

function isFile(file) {
  try { return fs.statSync(file).isFile(); } catch { return false; }
}

function resolveCommand(command) {
  if (process.platform !== 'win32') return { file: command, argvPrefix: [] };
  if (command === 'npm' || command === 'npx') {
    const nodeExe = findOnPath('node.exe')
      || (path.basename(process.execPath).toLowerCase() === 'node.exe' ? process.execPath : undefined);
    const shim = findOnPath(command + '.cmd');
    const cli = [
      nodeExe && path.join(path.dirname(nodeExe), 'node_modules', 'npm', 'bin', command + '-cli.js'),
      shim && path.join(path.dirname(shim), 'node_modules', 'npm', 'bin', command + '-cli.js'),
    ].find((candidate) => candidate && isFile(candidate));
    if (cli && nodeExe) return { file: nodeExe, argvPrefix: [cli] };
  }
  return { file: command, argvPrefix: [] };
}

function redactSecrets(text, secrets) {
  let out = String(text || '');
  if (!out) return out;
  const list = (Array.isArray(secrets) ? secrets : [secrets])
    .filter((s) => typeof s === 'string' && s.length >= 3)
    .sort((a, b) => b.length - a.length);
  for (const secret of list) out = out.split(secret).join('***');
  return out;
}

// ---------------------------------------------------------------------------
// Usage rules — injected into the system prompt so the agent follows the
// discipline automatically (never echo secrets; prefer vault_run).
// NOTE: systemPrompt sections are interpolated as templates, so this text must
// never contain double-brace placeholders.
// ---------------------------------------------------------------------------
const USAGE_RULES = `凭证库使用规则（@yyfather/dsh-token-vault）：
1. 凭证（API Key / 令牌 / 密码 / 账号）保存在 DSH 凭证库，明文不出 Host；列表只返回名称、类型、备注、字段名，绝不返回字段值。
2. 每条凭证四个字段：名称、类型、凭证字段（可多个值）、备注。类型：API Key / 访问令牌 / 用户名密码 / GitHub Token / npm Token / 数据库 / 邮箱 SMTP / SSH 私钥 / 自定义。
3. 需要用凭证执行操作时优先 vault_run：按名称取一个字段注入环境变量；参数里的 %TOKEN% 会被替换成该字段明文，输出中的明文自动抹成 ***。
4. 禁止把字段值打印/贴进回复，禁止把字段值写入工作区文件。
5. vault_show 仅在用户明确要求时调用，必须传 confirm: true；调用后提醒该值已泄露到对话、用完请轮换。
6. 名称与自定义字段名支持中文；名称 1-64 字符，不能含 "/"。
7. 环境变量名：vault_set 的 env 参数优先；否则 github/gh → GH_TOKEN、npm/node → NPM_TOKEN、纯 ASCII 名称 → TOKEN_<NAME>；中文名必须显式传 env_name。
8. 命令白名单：gh / npm / npx / node / git / curl（execFile 直跑，不开 shell，无字符串拼接）。
9. 调用 REST API：vault_run name=<名称> command=curl args=["-s","-H","Authorization: Bearer %TOKEN%","https://…"]。
10. 多字段凭证（如用户名密码）用 field 参数指定取哪个字段，缺省取该类型的主字段（密码 / 私钥 / 令牌）。`;

// ---------------------------------------------------------------------------
// Credentials helpers
// ---------------------------------------------------------------------------

function isValidName(name) {
  return typeof name === 'string' && NAME_PATTERN.test(name);
}

function recordKey(name) {
  // The credentials service only accepts record-key segments matching
  // /^[a-z][a-z0-9-]*$/, so Chinese / mixed-case names are mapped to a stable
  // slug. The human name is kept in the record metadata (env.name) for display.
  // Pure slug names (github, npm) map to themselves, so old records still match.
  return SCOPE + '/' + keySlug(name);
}

function keySlug(name) {
  if (/^[a-z][a-z0-9-]*$/.test(name)) return name;
  return 'u-' + crypto.createHash('sha256').update(String(name), 'utf8').digest('hex').slice(0, 16);
}


function normalizeFields(type, input) {
  const spec = typeSpec(type);
  const fields = {};
  for (const [rawKey, rawValue] of Object.entries(input || {})) {
    const key = String(rawKey).trim();
    if (!key) continue;
    if (!FIELD_KEY_PATTERN.test(key)) throw new Error('字段名不合法: ' + key + '（1-32 字符，不能含 "/"）');
    const value = typeof rawValue === 'string' ? rawValue : (rawValue === undefined || rawValue === null ? '' : String(rawValue));
    if (!value) continue;
    fields[key] = value;
  }
  if (type !== 'custom') {
    const allowed = new Set(spec.fields.map((f) => f.key));
    const unknown = Object.keys(fields).filter((k) => !allowed.has(k));
    if (unknown.length) {
      throw new Error('类型「' + spec.label + '」不支持字段: ' + unknown.join('、') + '（可用: ' + [...allowed].join('、') + '）');
    }
    const missing = spec.fields.filter((f) => !f.optional && !fields[f.key]).map((f) => f.label);
    if (missing.length) throw new Error('缺少必填字段: ' + missing.join('、'));
    if (!Object.keys(fields).length) throw new Error('凭证字段不能为空');
  } else if (!Object.keys(fields).length) {
    throw new Error('自定义类型至少需要一个非空字段');
  }
  return fields;
}

function packRecord(cred) {
  return JSON.stringify({ v: SCHEMA_VERSION, type: cred.type, fields: cred.fields });
}

function unpackRecord(rec) {
  const meta = (rec && rec.env) || {};
  const raw = rec && rec.key;
  let parsed;
  try { parsed = raw ? JSON.parse(raw) : null; } catch { parsed = null; }
  if (parsed && parsed.v === SCHEMA_VERSION && parsed.fields && typeof parsed.fields === 'object') {
    return {
      type: parsed.type || 'custom',
      fields: parsed.fields,
      remark: meta.remark || '',
      variable: meta.variable || '',
      legacy: false,
    };
  }
  // Legacy record: the whole value was one token string.
  return {
    type: 'token',
    fields: raw ? { token: String(raw) } : {},
    remark: meta.remark || meta.description || '',
    variable: meta.variable || '',
    legacy: true,
  };
}

function pickField(cred, wanted) {
  if (!cred) return undefined;
  const spec = typeSpec(cred.type);
  const key = wanted || spec.primary || Object.keys(cred.fields)[0];
  if (!key || !(key in cred.fields)) return undefined;
  return { key, value: cred.fields[key] };
}

function summarizeFields(cred) {
  return Object.keys(cred.fields || {}).map((k) => fieldLabel(cred.type, k));
}

// Only secret-marked fields are scrubbed from command output: redacting host /
// port / username too would mangle ordinary output (e.g. a username "app"
// hitting the word "application"). `custom` has no schema, so all its fields
// count as secret.
function secretValues(cred) {
  const spec = typeSpec(cred.type);
  const keys = Object.keys(cred.fields || {});
  const picked = cred.type === 'custom'
    ? keys
    : keys.filter((k) => {
      const field = spec.fields.find((f) => f.key === k);
      return !!(field && field.secret);
    });
  return picked.map((k) => cred.fields[k]).filter(Boolean);
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
    toolDef('vault_list', '列出凭证库中的凭证（名称 / 类型 / 备注 / 字段名 / 环境变量名，绝不返回字段值）。无参数。', {
      type: 'object',
      properties: {},
    }, async () => {
      const names = await store.names();
      if (names.length === 0) return { ok: true, text: '凭证库为空（可在 设置 → 凭证库 或 vault_set 添加）' };
      const lines = [];
      for (const name of names) {
        const cred = await store.read(name);
        if (!cred) continue;
        const bits = [typeLabel(cred.type)];
        if (cred.remark) bits.push(cred.remark);
        if (cred.variable) bits.push('env=' + cred.variable);
        if (Object.keys(cred.fields).length) bits.push('字段: ' + summarizeFields(cred).join('/'));
        lines.push('- ' + name + '（' + bits.join('；') + '）');
      }
      return { ok: true, text: '已保存 ' + lines.length + ' 条：\n' + lines.join('\n') };
    }),
    toolDef('vault_has', '检查凭证库中是否存在指定名称。参数：name 名称（支持中文）。', {
      type: 'object',
      properties: { name: { type: 'string', description: '名称（如 github / 数据库-生产密码）' } },
      required: ['name'],
    }, async (args) => {
      const { name } = args;
      if (!isValidName(name)) return { ok: false, text: '非法名称: ' + String(name) + '（' + NAME_HINT + '）' };
      const has = await store.has(name);
      return { ok: true, text: has ? ('已保存: ' + name) : ('未保存: ' + name) };
    }),
    toolDef('vault_set', '保存/更新一条凭证（值只在 Host 侧存储，绝不回显）。四个字段：name 名称，type 类型，fields 凭证字段（键值对象），remark 备注。type 见 vault_list 说明或 设置 → 凭证库；旧调用可只传 value 存单值。', {
      type: 'object',
      properties: {
        name: { type: 'string', description: '名称，支持中文（如 github / 数据库-生产密码）' },
        type: { type: 'string', description: '类型 id：api-key / token / username-password / github / npm / database / smtp / ssh-key / custom' },
        fields: { type: 'object', description: '凭证字段，键值对象；preset 类型的键必须与类型定义一致（如 database 用 host/port/username/password/database）' },
        value: { type: 'string', description: '兼容写法：只存单值时用它，等价于 fields 里的主字段' },
        remark: { type: 'string', description: '备注（会显示在 vault_list）' },
        env: { type: 'string', description: '可选：固定注入的环境变量名（ASCII，如 OPENAI_API_KEY）' },
      },
      required: ['name'],
    }, async (args) => {
      const { name, remark, env } = args;
      if (!isValidName(name)) return { ok: false, text: '非法名称: ' + String(name) + '（' + NAME_HINT + '）' };
      const existing = await store.read(name);
      const type = args.type || (existing && existing.type) || 'token';
      if (!CRED_TYPES[type]) {
        return { ok: false, text: '未知类型: ' + String(type) + '（可用: ' + Object.keys(CRED_TYPES).join(' / ') + '）' };
      }
      let rawFields = args.fields;
      if ((!rawFields || !Object.keys(rawFields).length) && typeof args.value === 'string' && args.value.trim()) {
        rawFields = { [typeSpec(type).primary || 'key']: args.value.trim() };
      }
      let fields;
      try { fields = normalizeFields(type, rawFields); } catch (err) { return { ok: false, text: String((err && err.message) || err) }; }
      if (env !== undefined && env !== null && env !== '' && !ENV_NAME_PATTERN.test(String(env))) {
        return { ok: false, text: '非法环境变量名: ' + String(env) + '（需 [A-Za-z_][A-Za-z0-9_]*）' };
      }
      await store.write(name, { type, fields, remark: remark !== undefined ? String(remark) : (existing ? existing.remark : ''), variable: env !== undefined ? String(env) : (existing ? existing.variable : '') });
      const bits = [typeLabel(type), Object.keys(fields).length + ' 个字段'];
      if (env) bits.push('env=' + env);
      return { ok: true, text: '已保存: ' + name + '（' + bits.join('，') + '）' };
    }),
    toolDef('vault_remove', '删除一条凭证。参数：name 名称。', {
      type: 'object',
      properties: { name: { type: 'string', description: '名称' } },
      required: ['name'],
    }, async (args) => {
      const { name } = args;
      if (!isValidName(name)) return { ok: false, text: '非法名称: ' + String(name) + '（' + NAME_HINT + '）' };
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
      if (!isValidName(name)) return { ok: false, text: '非法名称: ' + String(name) + '（' + NAME_HINT + '）' };
      const value = src === 'gh' ? await importFromGh() : await importFromNpm();
      const type = src === 'gh' ? 'github' : 'npm';
      await store.write(name, { type, fields: { token: value }, remark: 'imported from ' + src, variable: '' });
      return { ok: true, text: '已从 ' + src + ' 导入并保存: ' + name + '（' + typeLabel(type) + '）' };
    }),
    toolDef('vault_run', '用凭证里的某个字段执行命令（字段值只注入子进程环境变量或替换 %TOKEN%，绝不出现在输出/日志）。参数：name 名称，command 命令（gh/npm/npx/node/git/curl），args 参数数组（可含 %TOKEN%），field 取哪个字段（可选），env_name 环境变量名（可选）。', {
      type: 'object',
      properties: {
        name: { type: 'string', description: '凭证名称（如 github / openai-key）' },
        command: { type: 'string', description: '命令：gh / npm / npx / node / git / curl' },
        args: { type: 'array', items: { type: 'string' }, description: '命令参数数组；元素里的 %TOKEN% 会被替换为所选字段的明文' },
        field: { type: 'string', description: '可选：取哪个字段（如 password / token / key）；缺省取该类型主字段' },
        env_name: { type: 'string', description: '可选环境变量名，覆盖默认推导（中文名必填）' },
      },
      required: ['name', 'command'],
    }, async (args, signal) => {
      const { name, command, args: cmdArgs, field, env_name: envName } = args;
      if (!isValidName(name)) return { ok: false, text: '非法名称: ' + String(name) + '（' + NAME_HINT + '）' };
      if (!RUNNABLE.has(command)) return { ok: false, text: '命令不在白名单: ' + String(command) + '（允许 gh/npm/npx/node/git/curl）' };
      const cred = await store.read(name);
      if (!cred) return { ok: false, text: '未找到凭证: ' + name + '（可用 vault_set 或 vault_import 添加）' };
      const picked = pickField(cred, field);
      if (!picked) {
        return { ok: false, text: '凭证「' + name + '」没有字段 ' + String(field || typeSpec(cred.type).primary) + '；可用字段: ' + (Object.keys(cred.fields).join(' / ') || '（无）') };
      }
      const token = picked.value;
      const effectiveEnv = envName || cred.variable || DEFAULT_ENV[name]
        || (/^[A-Za-z0-9_-]+$/.test(name) ? 'TOKEN_' + name.replace(/-/g, '_').toUpperCase() : undefined);
      if (!effectiveEnv) {
        return { ok: false, text: '名称「' + name + '」不是 ASCII，无法推导环境变量名：请传 env_name，或先用 vault_set 的 env 参数固定变量名（如 env="MY_KEY"）。' };
      }
      const target = resolveCommand(command);
      const rawArgs = (Array.isArray(cmdArgs) ? cmdArgs : []).map((a) => String(a));
      const argv = [...target.argvPrefix, ...rawArgs.map((a) => a.split(TOKEN_PLACEHOLDER).join(token))];
      const allSecrets = secretValues(cred);
      try {
        const { stdout, stderr } = await execFileAsync(target.file, argv, {
          env: { ...process.env, [effectiveEnv]: token },
          windowsHide: true,
          maxBuffer: 8 * 1024 * 1024,
        });
        const out = redactSecrets(String(stdout || '').slice(0, OUTPUT_CAP), allSecrets);
        const err = redactSecrets(String(stderr || '').slice(0, OUTPUT_CAP), allSecrets);
        const parts = [];
        if (out) parts.push(out.trimEnd());
        if (err) parts.push('[stderr]\n' + err.trimEnd());
        if (!parts.length) parts.push('(无输出)');
        const head = redactSecrets('$ ' + command + ' ' + rawArgs.join(' '), allSecrets);
        return { ok: true, text: head + '\n[字段 ' + picked.key + ' → ' + effectiveEnv + ']\n' + parts.join('\n') };
      } catch (err) {
        const code = err && err.code;
        const hint = code === 'ENOENT'
          ? '\n（未找到可执行文件 ' + target.file + '；Windows 下 npm/npx 需经由 node + npm-cli.js 启动）'
          : '';
        const std = redactSecrets(String((err && err.stdout) || '') + String((err && err.stderr) || ''), allSecrets);
        const body = redactSecrets(String(std || (err && err.message) || '未知错误').slice(0, OUTPUT_CAP), allSecrets);
        return { ok: false, text: '命令退出码 ' + String(code) + ': ' + body + hint };
      }
    }),
    toolDef('vault_show', '显示一条凭证的全部字段明文（仅当用户明确要求时使用；必须传 confirm: true，否则拒绝；明文将出现在对话中，用完建议轮换）。', {
      type: 'object',
      properties: {
        name: { type: 'string', description: '名称' },
        confirm: { type: 'boolean', description: '确认展示明文，必须为 true' },
      },
      required: ['name', 'confirm'],
    }, async (args) => {
      const { name, confirm } = args;
      if (confirm !== true) return { ok: false, text: '请在确认后传 confirm: true 才展示明文' };
      if (!isValidName(name)) return { ok: false, text: '非法名称: ' + String(name) + '（' + NAME_HINT + '）' };
      const cred = await store.read(name);
      if (!cred) return { ok: false, text: '未找到凭证: ' + name };
      const rows = Object.keys(cred.fields).map((k) => '  ' + fieldLabel(cred.type, k) + ': ' + cred.fields[k]);
      return {
        ok: true,
        text: name + '（' + typeLabel(cred.type) + '）' + (cred.remark ? ' 备注: ' + cred.remark : '') + '\n' + rows.join('\n')
          + '\n⚠ 该值已出现在对话中，使用后建议在 设置 → 凭证库 变更。',
      };
    }),
  ];
}

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

export const inject = ['tools', 'credentials', 'webServer', 'systemPrompt'];

export async function apply(ctx) {
  const disposers = [];
  const credentials = ctx.credentials;
  const webServer = ctx.webServer;
  const systemPrompt = ctx.systemPrompt;

  const store = {
    async names() {
      const entries = await credentials.listRecords();
      const out = [];
      for (const entry of entries) {
        const key = String(entry.key);
        if (!key.startsWith(SCOPE + '/')) continue;
        const slug = key.slice(SCOPE.length + 1);
        let display = slug;
        try {
          const rec = await credentials.readRecord(key);
          if (rec && rec.env && rec.env.name) display = String(rec.env.name);
        } catch { /* unreadable record: still show the slug so it can be removed */ }
        out.push(display);
      }
      return [...new Set(out)].sort();
    },
    async has(name) {
      const info = await credentials.describeRecord(recordKey(name));
      return !!(info && info.configured);
    },
    async read(name) {
      const rec = await credentials.readRecord(recordKey(name));
      if (!rec || rec.kind !== 'api-key' || !rec.key) return undefined;
      return { ...unpackRecord(rec), name: (rec.env && rec.env.name) || name };
    },
    async write(name, cred) {
      await credentials.modifyRecord(recordKey(name), async (current) => {
        const previous = (current && current.kind === 'api-key' && current.env) || {};
        const env = { ...previous };
        env.name = name;
        env.remark = cred.remark || '';
        if (cred.variable) env.variable = cred.variable;
        else delete env.variable;
        delete env.description;
        return { kind: 'api-key', key: packRecord(cred), env };
      });
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
      path: '/vault/types',
      async handler(req, res) {
        try {
          const types = Object.entries(CRED_TYPES).map(([id, spec]) => ({ id, label: spec.label, primary: spec.primary || null, fields: spec.fields }));
          sendJson(res, 200, { ok: true, types });
        } catch (err) {
          sendJson(res, 500, { ok: false, error: String((err && err.message) || err) });
        }
      },
    }));
    disposers.push(webServer.register({
      kind: 'exact',
      path: '/vault/status',
      async handler(req, res) {
        try {
          const tokens = [];
          for (const name of await store.names()) {
            const cred = await store.read(name);
            if (!cred) continue;
            tokens.push({
              name,
              type: cred.type,
              typeLabel: typeLabel(cred.type),
              remark: cred.remark || '',
              env: cred.variable || '',
              fields: Object.keys(cred.fields).map((k) => ({ key: k, label: fieldLabel(cred.type, k) })),
              legacy: !!cred.legacy,
            });
          }
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
          if (!isValidName(a.name)) return sendJson(res, 400, { ok: false, error: '非法名称（' + NAME_HINT + '）' });
          const existing = await store.read(a.name);
          const type = a.type || (existing && existing.type) || 'token';
          if (!CRED_TYPES[type]) return sendJson(res, 400, { ok: false, error: '未知类型: ' + String(type) });
          let rawFields = a.fields;
          if ((!rawFields || !Object.keys(rawFields).length) && typeof a.value === 'string' && a.value.trim()) {
            rawFields = { [typeSpec(type).primary || 'key']: a.value.trim() };
          }
          const fields = normalizeFields(type, rawFields);
          if (a.env && !ENV_NAME_PATTERN.test(String(a.env))) return sendJson(res, 400, { ok: false, error: '非法环境变量名（需 [A-Za-z_][A-Za-z0-9_]*）' });
          await store.write(a.name, {
            type,
            fields,
            remark: a.remark !== undefined ? String(a.remark) : (existing ? existing.remark : ''),
            variable: a.env !== undefined ? String(a.env) : (existing ? existing.variable : ''),
          });
          sendJson(res, 200, { ok: true, name: a.name, type });
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
          if (!isValidName(a.name)) return sendJson(res, 400, { ok: false, error: '非法名称' });
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
          const type = a.source === 'npm' ? 'npm' : 'github';
          await store.write(name, { type, fields: { token: value }, remark: 'imported from ' + String(a.source), variable: '' });
          sendJson(res, 200, { ok: true, name, type });
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

