window.__ModuleLoader__.load({
	id: "@yyfather/dsh-token-vault",
	factory: (require) => {
		var module = { exports: {} };
		var exports = module.exports;

		const React = require("react");

		// Same-origin routes (host profile plugin registers them):
		// GET  /vault/status   → { ok, tokens: [{name, configured}] }
		// POST /vault/set      → { name, value, description? }
		// POST /vault/remove   → { name }
		// POST /vault/import   → { source: 'gh' | 'npm' }
		function statusUrl() { return "/vault/status"; }
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

		function VaultSection() {
			var states = {
				tokens: React.useState(null),
				loading: React.useState(true),
				name: React.useState(""),
				value: React.useState(""),
				description: React.useState(""),
				busy: React.useState(false),
				msg: React.useState("")
			};
			var tokens = states.tokens[0], setTokens = states.tokens[1];
			var loading = states.loading[0], setLoading = states.loading[1];
			var name = states.name[0], setName = states.name[1];
			var value = states.value[0], setValue = states.value[1];
			var description = states.description[0], setDescription = states.description[1];
			var busy = states.busy[0], setBusy = states.busy[1];
			var msg = states.msg[0], setMsg = states.msg[1];

			function refresh() {
				return fetch(statusUrl())
					.then(function (r) { return r.json(); })
					.then(function (r) { setTokens(r && r.ok ? r.tokens : []); setLoading(false); })
					.catch(function () { setTokens([]); setLoading(false); });
			}

			React.useEffect(function () { refresh(); }, []);

			function onSave() {
				setBusy(true); setMsg("");
				postJson(setUrl(), { name: name.trim(), value: value, description: description.trim() || undefined })
					.then(function (r) {
						if (r && r.ok) { setMsg("✔ 已保存 " + r.name); setName(""); setValue(""); setDescription(""); }
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

			return React.createElement("div", { style: { maxWidth: 600, padding: "4px 0" } },
				React.createElement("div", { style: { fontSize: 16, fontWeight: 600, margin: "0 0 4px" } }, "凭证库"),
				React.createElement("div", { style: { fontSize: 12, opacity: 0.7, marginBottom: 10 } }, "GitHub / npm 等令牌安全保存在 DSH 凭证库（明文不出 Host，也不进对话）。代理通过 vault_run 直接调用，支持 github / npm / npx / node / git。"),
				React.createElement("div", { style: { margin: "10px 0" } },
					React.createElement("label", { style: labelStyle }, "令牌名"),
					React.createElement("input", { value: name, placeholder: "如 github / npm / gh", style: inputStyle, onChange: function (e) { setName(e.target.value); } })
				),
				React.createElement("div", { style: { margin: "10px 0" } },
					React.createElement("label", { style: labelStyle }, "令牌值（不会回显）"),
					React.createElement("input", { value: value, type: "password", placeholder: "粘贴令牌", style: inputStyle, onChange: function (e) { setValue(e.target.value); } })
				),
				React.createElement("div", { style: { margin: "10px 0" } },
					React.createElement("label", { style: labelStyle }, "备注（可选）"),
					React.createElement("input", { value: description, placeholder: "", style: inputStyle, onChange: function (e) { setDescription(e.target.value); } })
				),
				React.createElement("div", { style: { display: "flex", gap: 8, alignItems: "center", marginTop: 10, flexWrap: "wrap" } },
					React.createElement("button", { onClick: onSave, disabled: busy, style: btn }, busy ? "处理中…" : "保存令牌"),
					React.createElement("button", { onClick: function () { onImport("gh"); }, disabled: busy, style: ghost }, "从 gh 导入"),
					React.createElement("button", { onClick: function () { onImport("npm"); }, disabled: busy, style: ghost }, "从 npmrc 导入"),
					msg ? React.createElement("span", { style: { fontSize: 12, opacity: 0.85 } }, msg) : null
				),
				React.createElement("div", { style: { marginTop: 16 } },
					React.createElement("div", { style: { fontSize: 13, fontWeight: 600, marginBottom: 6 } }, "已保存"),
					loading ? React.createElement("div", { style: { fontSize: 12, opacity: 0.6 } }, "加载中…")
						: (tokens && tokens.length === 0)
							? React.createElement("div", { style: { fontSize: 12, opacity: 0.6 } }, "（空）")
							: React.createElement("div", null,
									(tokens || []).map(function (t) {
										return React.createElement("div", { key: t.name, style: { display: "flex", alignItems: "center", gap: 8, padding: "5px 8px", borderRadius: 6, background: "rgba(128,128,128,0.08)", marginBottom: 6 } },
											React.createElement("span", { style: { fontFamily: "monospace", fontSize: 13 } }, t.name),
											React.createElement("span", { style: { fontSize: 11, opacity: 0.6 } }, "已配置"),
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
			}
		}

		exports.apply = apply;
		exports.inject = inject;
		return module.exports;
	},
});
