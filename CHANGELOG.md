# Changelog

## 1.0.5 — 2026-11-14

- **Edit existing credentials in place** (Settings → Credential vault → 编辑): the form prefills name,
  type, remark and env name; secret fields stay blank.
  Semantics: non-empty value overwrites, empty string keeps the stored value, an omitted field is
  deleted (delete a row to drop a custom field).
- `vault_set` follows the same merge semantics, so a partial update no longer wipes other fields.
- `POST /vault/set` now merges for existing names and returns `created` so the UI can say 新建/已更新.
- Changing a credential's type while editing requires re-entering its fields (old values are dropped).

### Performance

- DPAPI now runs through a persistent PowerShell worker instead of spawning
  `powershell.exe` per call. On this machine each spawn costs ~13 s (security software
  scanning), so a save took 17-29 s; after the first call (~10 s, worker startup) writes
  settle at ~0.1-0.2 s.

## 1.0.4 — 2026-11-14

- Four-field credential model (name / type / credential fields / remark), preset type registry.
- DPAPI-encrypted record payloads at rest; legacy plaintext records auto-migrate on read.
- `%TOKEN%` substitution in `vault_run` arguments, plus `curl` in the command whitelist.
- Bundle metadata: named exports, locale (en/zh), icon, packed file list.

## 1.0.3 — 2026-08-24

- Market metadata (homepage/bugs) and bilingual README.
