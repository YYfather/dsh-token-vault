window.__ModuleLoader__.load({
	id: "@yyfather/dsh-token-vault",
	factory: (require) => {
		var module = { exports: {} };
		var exports = module.exports;

		const React = require("react");

		// Same-origin routes (host profile plugin registers them):
		// GET  /vault/types    → { ok, types: [{ id, label, primary, fields: [{ key, label, optional }] }] }
		// GET  /vault/status   → { ok, tokens: [{ name, type, typeLabel, remark, env, fields: [{key,label}] }] }
		// POST /vault/set      → { name, type, fields, remark?, env? }
		// POST /vault/remove   → { name }
		// POST /vault/import   → { source: 'gh' | 'npm' }
		function statusUrl() { return "/vault/status"; }
		function typesUrl() { return "/vault/types"; }
		function setUrl() { return "/vault/set"; }
		function removeUrl() { return "/vault/remove"; }
		function importUrl() { return "/vault/import"; }

		function postJson(url, body) {
			return fetch(url, {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify(body || {})
			}).then(function (r) { return r.json(); });
		}

		const FALLBACK_TYPES = [
			{ id: "api-key", label: "API Key", primary: "key", fields: [{ key: "key", label: "密钥" }] },
			{ id: "token", label: "访问令牌", primary: "token", fields: [{ key: "token", label: "令牌" }] },
			{ id: "username-password", label: "用户名密码", primary: "password", fields: [{ key: "username", label: "用户名" }, { key: "password", label: "密码" }] },
			{ id: "github", label: "GitHub Token", primary: "token", fields: [{ key: "token", label: "令牌" }] },
			{ id: "npm", label: "npm Token", primary: "token", fields: [{ key: "token", label: "令牌" }] },
			{ id: "database", label: "数据库", primary: "password", fields: [{ key: "host", label: "主机" }, { key: "port", label: "端口", optional: true }, { key: "username", label: "用户名" }, { key: "password", label: "密码" }, { key: "database", label: "库名", optional: true }] },
			{ id: "smtp", label: "邮箱 / SMTP", primary: "password", fields: [{ key: "host", label: "服务器" }, { key: "port", label: "端口", optional: true }, { key: "username", label: "用户名" }, { key: "password", label: "密码" }] },
			{ id: "ssh-key", label: "SSH 私钥", primary: "privateKey", fields: [{ key: "privateKey", label: "私钥" }, { key: "passphrase", label: "口令", optional: true }] },
			{ id: "custom", label: "自定义", primary: null, fields: [] }
		];

		function VaultSection() {
			var st = {
				tokens: React.useState(null),
				types: React.useState(FALLBACK_TYPES),
				loading: React.useState(true),
				name: React.useState(""),
				type: React.useState("token"),
				fields: React.useState({}),
				remark: React.useState(""),
				env: React.useState(""),
				customRows: React.useState([{ k: "", v: "" }]),
				busy: React.useState(false),
				msg: React.useState("")
			};
			var tokens = st.tokens[0], setTokens = st.tokens[1];
			var types = st.types[0], setTypes = st.types[1];
			var loading = st.loading[0], setLoading = st.loading[1];
			var name = st.name[0], setName = st.name[1];
			var type = st.type[0], setType = st.type[1];
			var fields = st.fields[0], setFields = st.fields[1];
			var remark = st.remark[0], setRemark = st.remark[1];
			var env = st.env[0], setEnv = st.env[1];
			var customRows = st.customRows[0], setCustomRows = st.customRows[1];
			var busy = st.busy[0], setBusy = st.busy[1];
			var msg = st.msg[0], setMsg = st.msg[1];

			var spec = (types || []).filter(function (t) { return t.id === type; })[0] || { id: "custom", label: "自定义", fields: [] };

			function refresh() {
				return fetch(statusUrl())
					.then(function (r) { return r.json(); })
					.then(function (r) { setTokens(r && r.ok ? r.tokens : []); setLoading(false); })
					.catch(function () { setTokens([]); setLoading(false); });
			}

			React.useEffect(function () {
				refresh();
				fetch(typesUrl())
					.then(function (r) { return r.json(); })
					.then(function (r) { if (r && r.ok && r.types && r.types.length) setTypes(r.types); })
					.catch(function () {});
			}, []);

			function onTypeChange(next) {
				setType(next);
				setFields({});
				setMsg("");
			}

			function setField(key, value) {
				var next = Object.assign({}, fields);
				next[key] = value;
				setFields(next);
			}

			function setRow(i, part, value) {
				var next = customRows.slice();
				next[i] = Object.assign({}, next[i]);
				next[i][part] = value;
				setCustomRows(next);
			}

			function collectFields() {
				if (type !== "custom") return fields;
				var out = {};
				(customRows || []).forEach(function (row) {
					var k = String(row.k || "").trim();
					if (k && row.v) out[k] = row.v;
				});
				return out;
			}

			function onSave() {
				setBusy(true); setMsg("");
				postJson(setUrl(), {
					name: name.trim(),
					type: type,
					fields: collectFields(),
					remark: remark.trim() || undefined,
					env: env.trim() || undefined
				})
					.then(function (r) {
						if (r && r.ok) { setMsg("✔ 已保存 " + r.name); setName(""); setFields({}); setRemark(""); setEnv(""); setCustomRows([{ k: "", v: "" }]); }
						else setMsg("保存失败: " + ((r && r.error) || "未知错误"));
						return refresh();
					})
					.catch(function (e) { setMsg("保存失败: " + String((e && e.message) || e)); })
					.finally(function () { setBusy(false); });
			}

			function onRemove(n) {
				setBusy(true); setMsg("");
				postJson(removeUrl(), { name: n })
					.then(function (r) {
						if (r && r.ok) setMsg("✔ 已删除 " + n);
						else setMsg("删除失败: " + ((r && r.error) || "未知错误"));
						return refresh();
					})
					.catch(function (e) { setMsg("删除失败: " + String((e && e.message) || e)); })
					.finally(function () { setBusy(false); });
			}

			function onImport(source) {
				setBusy(true); setMsg("");
				postJson(importUrl(), { source: source })
					.then(function (r) {
						if (r && r.ok) setMsg("✔ 已导入并保存 " + r.name);
						else setMsg("导入失败: " + ((r && r.error) || "未知错误"));
						return refresh();
					})
					.catch(function (e) { setMsg("导入失败: " + String((e && e.message) || e)); })
					.finally(function () { setBusy(false); });
			}

			var inputStyle = { width: "100%", boxSizing: "border-box", padding: "7px 9px", borderRadius: 6, border: "1px solid rgba(128,128,128,0.35)", background: "transparent", color: "inherit" };
			var labelStyle = { display: "block", fontSize: 12, opacity: 0.8, marginBottom: 4 };
			var btn = { padding: "7px 14px", borderRadius: 6, border: "none", background: "rgba(128,128,128,0.18)", color: "inherit", cursor: busy ? "wait" : "pointer", fontSize: 13 };
			var ghost = Object.assign({}, btn, { background: "transparent", border: "1px solid rgba(128,128,128,0.4)" });

			var fieldNodes = [];
			if (type === "custom") {
				(customRows || []).forEach(function (row, i) {
					fieldNodes.push(React.createElement("div", { key: "row" + i, style: { display: "flex", gap: 8, marginBottom: 6 } },
						React.createElement("input", { value: row.k, placeholder: "字段名（如 用户名）", style: inputStyle, onChange: function (e) { setRow(i, "k", e.target.value); } }),
						React.createElement("input", { value: row.v, placeholder: "值", type: "password", style: inputStyle, onChange: function (e) { setRow(i, "v", e.target.value); } }),
						React.createElement("button", {
							onClick: function () { setCustomRows(customRows.filter(function (_, j) { return j !== i; })); },
							style: Object.assign({}, ghost, { padding: "6px 10px" })
						}, "删除")
					));
				});
				fieldNodes.push(React.createElement("button", {
					onClick: function () { setCustomRows(customRows.concat([{ k: "", v: "" }])); },
					style: Object.assign({}, ghost, { padding: "5px 10px", fontSize: 12 })
				}, "＋ 添加字段"));
			} else {
				(spec.fields || []).forEach(function (f) {
					fieldNodes.push(React.createElement("div", { key: f.key, style: { margin: "8px 0" } },
						React.createElement("label", { style: labelStyle }, f.label + (f.optional ? "（可选）" : "")),
						React.createElement("input", {
							value: fields[f.key] || "",
							type: (f.key === "password" || f.key === "passphrase" || f.key === "privateKey") ? "password" : "text",
							style: inputStyle,
							onChange: function (e) { setField(f.key, e.target.value); }
						})
					));
				});
			}

			return React.createElement("div", { style: { maxWidth: 640, padding: "4px 0" } },
				React.createElement("div", { style: { fontSize: 16, fontWeight: 600, margin: "0 0 4px" } }, "凭证库"),
				React.createElement("div", { style: { fontSize: 12, opacity: 0.7, marginBottom: 10 } }, "每条凭证四栏：名称、类型、凭证字段、备注。明文不出 Host、不进对话；代理用 vault_run 调用（gh / npm / npx / node / git / curl，参数可用 %TOKEN%）。"),
				React.createElement("div", { style: { display: "flex", gap: 10, flexWrap: "wrap" } },
					React.createElement("div", { style: { flex: "1 1 220px" } },
						React.createElement("label", { style: labelStyle }, "名称（支持中文）"),
						React.createElement("input", { value: name, placeholder: "如 openai-key / 数据库-生产密码", style: inputStyle, onChange: function (e) { setName(e.target.value); } })
					),
					React.createElement("div", { style: { flex: "1 1 200px" } },
						React.createElement("label", { style: labelStyle }, "类型"),
						React.createElement("select", { value: type, style: inputStyle, onChange: function (e) { onTypeChange(e.target.value); } },
							(types || []).map(function (t) { return React.createElement("option", { key: t.id, value: t.id }, t.label); })
						)
					)
				),
				React.createElement("div", { style: { margin: "12px 0 4px", fontSize: 13, fontWeight: 600 } }, "凭证字段"),
				React.createElement("div", null, fieldNodes),
				React.createElement("div", { style: { display: "flex", gap: 10, flexWrap: "wrap", marginTop: 8 } },
					React.createElement("div", { style: { flex: "1 1 240px" } },
						React.createElement("label", { style: labelStyle }, "备注"),
						React.createElement("input", { value: remark, placeholder: "用途说明", style: inputStyle, onChange: function (e) { setRemark(e.target.value); } })
					),
					React.createElement("div", { style: { flex: "1 1 200px" } },
						React.createElement("label", { style: labelStyle }, "环境变量名（可选，仅 ASCII）"),
						React.createElement("input", { value: env, placeholder: "如 OPENAI_API_KEY", style: inputStyle, onChange: function (e) { setEnv(e.target.value); } })
					)
				),
				React.createElement("div", { style: { display: "flex", gap: 8, alignItems: "center", marginTop: 12, flexWrap: "wrap" } },
					React.createElement("button", { onClick: onSave, disabled: busy, style: btn }, busy ? "处理中…" : "保存凭证"),
					React.createElement("button", { onClick: function () { onImport("gh"); }, disabled: busy, style: ghost }, "从 gh 导入"),
					React.createElement("button", { onClick: function () { onImport("npm"); }, disabled: busy, style: ghost }, "从 npmrc 导入"),
					msg ? React.createElement("span", { style: { fontSize: 12, opacity: 0.85 } }, msg) : null
				),
				React.createElement("div", { style: { marginTop: 18 } },
					React.createElement("div", { style: { fontSize: 13, fontWeight: 600, marginBottom: 6 } }, "已保存"),
					loading ? React.createElement("div", { style: { fontSize: 12, opacity: 0.6 } }, "加载中…")
						: (tokens && tokens.length === 0)
							? React.createElement("div", { style: { fontSize: 12, opacity: 0.6 } }, "（空）")
							: React.createElement("div", null,
									(tokens || []).map(function (t) {
										var bits = [t.typeLabel || t.type];
										if (t.remark) bits.push(t.remark);
										if (t.env) bits.push("env=" + t.env);
										if (t.fields && t.fields.length) bits.push(t.fields.map(function (f) { return f.label; }).join("/"));
										return React.createElement("div", { key: t.name, style: { display: "flex", alignItems: "center", gap: 8, padding: "5px 8px", borderRadius: 6, background: "rgba(128,128,128,0.08)", marginBottom: 6 } },
											React.createElement("span", { style: { fontSize: 13, fontWeight: 500 } }, t.name),
											React.createElement("span", { style: { fontSize: 11, opacity: 0.6 } }, bits.join(" · ")),
											t.legacy ? React.createElement("span", { style: { fontSize: 10, opacity: 0.5 } }, "旧格式") : null,
											React.createElement("span", { style: { flex: 1 } }),
											React.createElement("button", { onClick: function () { onRemove(t.name); }, disabled: busy, style: { padding: "2px 10px", borderRadius: 6, border: "1px solid rgba(128,128,128,0.4)", background: "transparent", color: "inherit", fontSize: 12, cursor: busy ? "wait" : "pointer" } }, "删除")
										);
									})
								)
				)
			);
		}

		var inject = ["slots"];

		function apply(ctx) {
			if (ctx.slots) {
				ctx.slots.inject("settings.section", function () {
					return ctx.slots.register(
						{ name: "settings.section", id: "token-vault", order: 35, label: "凭证库" },
						function () { return React.createElement(VaultSection); }
					);
				});
				ctx.slots.inject("settings.plugin.item", function () {
					return ctx.slots.register(
						{ name: "settings.plugin.item", key: "@yyfather/dsh-token-vault" },
						function () {
							return React.createElement("div", { style: { padding: "4px 0" } },
								React.createElement("div", { style: { fontSize: 14, fontWeight: 600 } }, "dsh-token-vault"),
								React.createElement("div", { style: { fontSize: 12, opacity: 0.75, marginTop: 4 } }, "凭证库：名称 / 类型 / 凭证字段 / 备注四栏管理，类型含 API Key、令牌、用户名密码、数据库、SMTP、SSH 私钥与自定义；代理用 vault_run 调用（%TOKEN% 占位），明文不出 Host。点击 设置 → 凭证库 管理。")
							);
						}
					);
				});
			}
		}

		exports.apply = apply;
		exports.inject = inject;
		return module.exports;
	},
});
