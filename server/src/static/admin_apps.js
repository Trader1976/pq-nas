(() => {
    function tr(key, vars = null, fallback = "") {
        try {
            if (window.PQNAS_I18N && typeof window.PQNAS_I18N.t === "function") {
                return window.PQNAS_I18N.t(key, vars, fallback || key);
            }
        } catch (_) {}
        return fallback || key;
    }

    function applyStaticI18n() {
        try {
            if (window.PQNAS_I18N && typeof window.PQNAS_I18N.apply === "function") {
                window.PQNAS_I18N.apply(document);
            }
        } catch (_) {}
    }

    function launchLabel(v) {
        const s = String(v || "auto");
        if (s === "auto") return tr("admin.apps.auto", null, "Auto");
        if (s === "embedded") return tr("admin.apps.embedded", null, "Embedded");
        if (s === "detached") return tr("admin.apps.detached", null, "Detached");
        return s;
    }

    function windowLabel(v) {
        const s = String(v || "auto");
        if (s === "auto") return tr("admin.apps.auto", null, "Auto");
        if (s === "small") return tr("admin.apps.small", null, "Small");
        if (s === "normal") return tr("admin.apps.normal", null, "Normal");
        if (s === "large") return tr("admin.apps.large", null, "Large");
        if (s === "full") return tr("admin.apps.full", null, "Full");
        return s;
    }

    const stateBadge = document.getElementById("stateBadge");
    const statusLine = document.getElementById("statusLine");
    const refreshBtn = document.getElementById("refreshBtn");
    const installedList = document.getElementById("installedList");

    const zipFile = document.getElementById("zipFile");
    const zipPickBtn = document.getElementById("zipPickBtn");
    const zipPickName = document.getElementById("zipPickName");
    const installBtn = document.getElementById("installBtn");
    const installOut = document.getElementById("installOut");
    const installAdminOnly = document.getElementById("installAdminOnly");
    let launchPolicyByAppId = {};
    let lastInstalledItems = [];

    function setBadge(kind, text){
        stateBadge.className = `badge ${kind}`;
        stateBadge.textContent = text;
    }

    function esc(s){ return String(s ?? "").replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }

    function updateZipPickName() {
        if (!zipPickName) return;

        const f = zipFile && zipFile.files && zipFile.files[0]
            ? zipFile.files[0]
            : null;

        zipPickName.textContent = f
            ? tr("admin.apps.selected_file", { name: f.name }, `Selected: ${f.name}`)
            : tr("admin.apps.no_file_selected", null, "No file selected");
    }


    function policyForApp(appId){
        const p = launchPolicyByAppId && launchPolicyByAppId[appId];
        return {
            default_launch: (p && p.default_launch) || "auto",
            window_profile: (p && p.window_profile) || "auto",
            allow_user_override: !!(p && p.allow_user_override),
            admin_only: !!(p && p.admin_only)
        };
    }

    async function saveLaunchPolicy(id, policy){
        const r = await fetch("/api/v4/apps/launch_policy", {
            method: "POST",
            credentials: "include",
            headers: {"Content-Type":"application/json"},
            body: JSON.stringify({
                id,
                default_launch: policy.default_launch,
                window_profile: policy.window_profile,
                allow_user_override: !!policy.allow_user_override,
                admin_only: !!policy.admin_only
            })
        });

        const j = await r.json().catch(() => null);
        if (!r.ok || !j || !j.ok) {
            throw new Error((j && (j.message || j.error))
                ? `${j.error || ""} ${j.message || ""}`.trim()
                : tr("admin.apps.save_failed_http", { status: r.status }, `save failed (${r.status})`));
        }
        return j;
    }


    function injectAdminAppsConfirmCss() {
        if (document.getElementById("adminAppsConfirmCss")) return;

        const style = document.createElement("style");
        style.id = "adminAppsConfirmCss";
        style.textContent = `
.adminAppsConfirmBackdrop{
    position:fixed;
    inset:0;
    z-index:100000;
    display:flex;
    align-items:center;
    justify-content:center;
    padding:18px;
    background:rgba(0,0,0,0.55);
    backdrop-filter:blur(6px);
    -webkit-backdrop-filter:blur(6px);
}

.adminAppsConfirmCard{
    width:min(640px, calc(100vw - 24px));
    max-height:min(84vh, 900px);
    display:flex;
    flex-direction:column;
    overflow:hidden;
    border:1px solid var(--border2, rgba(120,120,120,0.45));
    border-radius:18px;
    background:linear-gradient(180deg, var(--panel2, #f8f8f8), var(--panel, #eeeeee));
    box-shadow:0 18px 70px rgba(0,0,0,0.42);
    color:var(--fg, #111);
}

.adminAppsConfirmHead{
    padding:14px 16px;
    border-bottom:1px solid var(--border2, rgba(120,120,120,0.35));
    background:rgba(0,0,0,0.08);
}

.adminAppsConfirmTitle{
    font-weight:950;
    letter-spacing:.2px;
    font-size:16px;
}

.adminAppsConfirmSub{
    margin-top:4px;
    font-size:12px;
    color:var(--fg-dim, rgba(0,0,0,0.65));
}

.adminAppsConfirmBody{
    padding:16px;
    display:grid;
    grid-template-columns:130px minmax(0, 1fr);
    gap:10px 14px;
    overflow:auto;
    min-height:0;
}

.adminAppsConfirmKey{
    color:var(--fg-dim, rgba(0,0,0,0.68));
    font-weight:850;
}

.adminAppsConfirmValue{
    color:var(--fg, #111);
    overflow-wrap:anywhere;
    white-space:pre-wrap;
}

.adminAppsConfirmValue.mono{
    font-family:var(--mono, ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace);
    font-size:12px;
}

.adminAppsConfirmNote{
    grid-column:1 / -1;
    padding:10px 12px;
    border:1px solid rgba(var(--fail-rgb, 180,40,40),0.35);
    border-radius:14px;
    background:rgba(var(--fail-rgb, 180,40,40),0.10);
    color:var(--fg, #111);
    font-weight:850;
}

.adminAppsConfirmFoot{
    display:flex;
    align-items:center;
    gap:12px;
    padding:12px 16px;
    border-top:1px solid var(--border2, rgba(120,120,120,0.35));
    background:rgba(0,0,0,0.08);
}

.adminAppsConfirmBtn{
    border:1px solid var(--border2, rgba(120,120,120,0.45));
    border-radius:14px;
    padding:9px 14px;
    font:inherit;
    font-weight:850;
    color:var(--fg, #111);
    background:linear-gradient(180deg, rgba(255,255,255,0.20), rgba(0,0,0,0.04));
    cursor:pointer;
}

.adminAppsConfirmBtn:hover{
    filter:brightness(1.05);
}

.adminAppsConfirmBtn.secondary{
    opacity:.90;
}

.adminAppsConfirmBtn.danger{
    border-color:rgba(var(--fail-rgb, 180,40,40),0.48);
    background:rgba(var(--fail-rgb, 180,40,40),0.14);
    color:var(--fg, #111);
}

html[data-theme="bright"] .adminAppsConfirmBackdrop{
    background:rgba(0,0,0,0.30);
}

html[data-theme="bright"] .adminAppsConfirmCard{
    background:linear-gradient(180deg, #ffffff, #f2f4f7) !important;
    border-color:rgba(70,80,95,0.32) !important;
    color:#111827 !important;
    box-shadow:0 22px 80px rgba(0,0,0,0.28) !important;
}

html[data-theme="bright"] .adminAppsConfirmHead,
html[data-theme="bright"] .adminAppsConfirmFoot{
    background:rgba(15,23,42,0.045) !important;
    border-color:rgba(70,80,95,0.22) !important;
}

html[data-theme="bright"] .adminAppsConfirmTitle,
html[data-theme="bright"] .adminAppsConfirmValue,
html[data-theme="bright"] .adminAppsConfirmBtn{
    color:#111827 !important;
}

html[data-theme="bright"] .adminAppsConfirmSub,
html[data-theme="bright"] .adminAppsConfirmKey{
    color:rgba(17,24,39,0.68) !important;
}

html[data-theme="bright"] .adminAppsConfirmNote{
    background:rgba(180,40,40,0.10) !important;
    border-color:rgba(180,40,40,0.30) !important;
    color:#111827 !important;
}

html[data-theme="bright"] .adminAppsConfirmBtn.secondary{
    background:linear-gradient(180deg, #ffffff, #e8ebef) !important;
}

html[data-theme="bright"] .adminAppsConfirmBtn.danger{
    background:rgba(180,40,40,0.14) !important;
    border-color:rgba(180,40,40,0.38) !important;
    color:#111827 !important;
}

html[data-theme="win_classic"] .adminAppsConfirmBackdrop{
    background:rgba(0,0,0,0.38);
}
`;
        document.head.appendChild(style);
    }

    function openAdminAppsConfirmModal(opts = {}) {
        injectAdminAppsConfirmCss();

        return new Promise((resolve) => {
            const options = opts || {};

            const modal = document.createElement("div");
            modal.className = "adminAppsConfirmBackdrop";
            modal.setAttribute("role", "dialog");
            modal.setAttribute("aria-modal", "true");

            const card = document.createElement("div");
            card.className = "adminAppsConfirmCard";

            const head = document.createElement("div");
            head.className = "adminAppsConfirmHead";

            const title = document.createElement("div");
            title.className = "adminAppsConfirmTitle";
            title.textContent = options.title || tr("admin.apps.confirm_action", null, "Confirm action");

            const sub = document.createElement("div");
            sub.className = "adminAppsConfirmSub";
            sub.textContent = options.subtitle || "";

            head.appendChild(title);
            if (sub.textContent) head.appendChild(sub);

            const body = document.createElement("div");
            body.className = "adminAppsConfirmBody";

            const rows = Array.isArray(options.rows) ? options.rows : [];
            for (const row of rows) {
                const k = document.createElement("div");
                k.className = "adminAppsConfirmKey";
                k.textContent = String(row.label || "");

                const v = document.createElement("div");
                v.className = row.mono ? "adminAppsConfirmValue mono" : "adminAppsConfirmValue";
                v.textContent = String(row.value || "");

                body.appendChild(k);
                body.appendChild(v);
            }

            if (options.note) {
                const note = document.createElement("div");
                note.className = "adminAppsConfirmNote";
                note.textContent = String(options.note || "");
                body.appendChild(note);
            }

            const foot = document.createElement("div");
            foot.className = "adminAppsConfirmFoot";

            const spacer = document.createElement("div");
            spacer.style.flex = "1 1 auto";

            const cancelBtn = document.createElement("button");
            cancelBtn.type = "button";
            cancelBtn.className = "adminAppsConfirmBtn secondary";
            cancelBtn.textContent = options.cancelText || tr("admin.apps.cancel", null, "Cancel");

            const okBtn = document.createElement("button");
            okBtn.type = "button";
            okBtn.className = options.danger ? "adminAppsConfirmBtn danger" : "adminAppsConfirmBtn";
            okBtn.textContent = options.confirmText || tr("admin.apps.ok", null, "OK");

            foot.appendChild(spacer);
            foot.appendChild(cancelBtn);
            foot.appendChild(okBtn);

            card.appendChild(head);
            card.appendChild(body);
            card.appendChild(foot);
            modal.appendChild(card);
            document.body.appendChild(modal);

            const finish = (value) => {
                document.removeEventListener("keydown", onKey, true);
                modal.remove();
                resolve(!!value);
            };

            const onKey = (ev) => {
                if (ev.key === "Escape") {
                    ev.preventDefault();
                    ev.stopPropagation();
                    finish(false);
                    return;
                }

                if (ev.key === "Enter") {
                    ev.preventDefault();
                    ev.stopPropagation();
                    finish(true);
                }
            };

            document.addEventListener("keydown", onKey, true);

            modal.addEventListener("click", (ev) => {
                if (ev.target === modal) finish(false);
            });

            cancelBtn.addEventListener("click", () => finish(false));
            okBtn.addEventListener("click", () => finish(true));

            window.setTimeout(() => {
                if (options.danger) cancelBtn.focus();
                else okBtn.focus();
            }, 0);
        });
    }

    function renderInstalled(items){
        installedList.innerHTML = "";
        if (!items.length) {
            installedList.innerHTML = `<div class="mono muted">${esc(tr("admin.apps.no_installed", null, "(no installed apps)"))}</div>`;
            return;
        }

        // sort stable: id then version
        items = items.slice().sort((a,b) => {
            const ai = String(a.id||"");
            const bi = String(b.id||"");
            if (ai !== bi) return ai.localeCompare(bi);
            return String(a.version||"").localeCompare(String(b.version||""));
        });

        for (const it of items) {
            const row = document.createElement("div");
            row.className = "item";

            const left = document.createElement("div");
            left.className = "left";

            const name = document.createElement("div");
            name.className = "name";
            name.textContent = `${it.id} • ${it.version}`;

            const meta = document.createElement("div");
            meta.className = "meta mono";
            meta.textContent = `${it.has_manifest ? tr("admin.apps.manifest", null, "manifest") : tr("admin.apps.no_manifest", null, "no-manifest")} · ${it.root || ""}`;

            left.appendChild(name);
            left.appendChild(meta);

            const pol = policyForApp(it.id);

            const launchMeta = document.createElement("div");
            launchMeta.className = "meta";
            launchMeta.textContent =
                `${tr("admin.apps.launch", null, "Launch")}: ${launchLabel(pol.default_launch)} · ` +
                `${tr("admin.apps.window", null, "Window")}: ${windowLabel(pol.window_profile)} · ` +
                `${tr("admin.apps.user_override", null, "User override")}: ${pol.allow_user_override ? tr("admin.apps.yes", null, "yes") : tr("admin.apps.no", null, "no")} · ` +
                `${tr("admin.apps.visibility", null, "Visibility")}: ${pol.admin_only ? tr("admin.apps.admin_only", null, "admin only") : tr("admin.apps.all_users", null, "all users")}`;

            left.appendChild(launchMeta);

            const right = document.createElement("div");
            right.className = "appPolicyRight";

            const policyGrid = document.createElement("div");
            policyGrid.className = "policyGrid";

            const launchField = document.createElement("div");
            launchField.className = "policyField";
            launchField.innerHTML = `
    <label class="policyLbl">${esc(tr("admin.apps.default_launch", null, "Default launch"))}</label>
    <select class="policySel">
        <option value="auto">${esc(tr("admin.apps.auto", null, "Auto"))}</option>
        <option value="embedded">${esc(tr("admin.apps.embedded", null, "Embedded"))}</option>
        <option value="detached">${esc(tr("admin.apps.detached", null, "Detached"))}</option>
    </select>
`;

            const windowField = document.createElement("div");
            windowField.className = "policyField";
            windowField.innerHTML = `
    <label class="policyLbl">${esc(tr("admin.apps.window_profile", null, "Window profile"))}</label>
    <select class="policySel">
        <option value="auto">${esc(tr("admin.apps.auto", null, "Auto"))}</option>
        <option value="small">${esc(tr("admin.apps.small", null, "Small"))}</option>
        <option value="normal">${esc(tr("admin.apps.normal", null, "Normal"))}</option>
        <option value="large">${esc(tr("admin.apps.large", null, "Large"))}</option>
        <option value="full">${esc(tr("admin.apps.full", null, "Full"))}</option>
    </select>
`;

            const overrideField = document.createElement("div");
            overrideField.className = "policyField";
            overrideField.innerHTML = `
    <label class="policyLbl">${esc(tr("admin.apps.user_override", null, "User override"))}</label>
    <label class="policyChk">
        <input type="checkbox" />
        <span>${esc(tr("admin.apps.allow_user_override", null, "Allow user override"))}</span>
    </label>
`;
            const visibilityField = document.createElement("div");
            visibilityField.className = "policyField";
            visibilityField.innerHTML = `
    <label class="policyLbl">${esc(tr("admin.apps.visibility", null, "Visibility"))}</label>
    <label class="policyChk">
        <input type="checkbox" />
        <span>${esc(tr("admin.apps.admin_only", null, "Admin only"))}</span>
    </label>
`;
            const launchSel = launchField.querySelector("select");
            const windowSel = windowField.querySelector("select");
            const overrideChk = overrideField.querySelector("input");
            const adminOnlyChk = visibilityField.querySelector("input");

            launchSel.value = pol.default_launch;
            windowSel.value = pol.window_profile;
            overrideChk.checked = !!pol.allow_user_override;
            adminOnlyChk.checked = !!pol.admin_only;

            policyGrid.appendChild(launchField);
            policyGrid.appendChild(windowField);
            policyGrid.appendChild(overrideField);
            policyGrid.appendChild(visibilityField);

            const actions = document.createElement("div");
            actions.className = "row";

            const saveBtn = document.createElement("button");
            saveBtn.className = "btn secondary";
            saveBtn.type = "button";
            saveBtn.textContent = tr("admin.apps.save_launch_policy", null, "Save launch policy");
            saveBtn.addEventListener("click", async () => {
                try {
                    saveBtn.disabled = true;
                    setBadge("warn", tr("admin.apps.saving", null, "saving…"));
                    statusLine.textContent = tr("admin.apps.saving_policy", { id: it.id }, `Saving launch policy for ${it.id}…`);

                    await saveLaunchPolicy(it.id, {
                        default_launch: launchSel.value,
                        window_profile: windowSel.value,
                        allow_user_override: overrideChk.checked,
                        admin_only: adminOnlyChk.checked
                    });

                    await load();
                    setBadge("ok", tr("admin.apps.ready", null, "ready"));
                    statusLine.textContent = tr("admin.apps.saved_policy", { id: it.id }, `Saved launch policy for ${it.id}`);
                } catch (e) {
                    setBadge("err", tr("admin.apps.error", null, "error"));
                    statusLine.textContent = String(e && e.message ? e.message : e);
                    alert(String(e && e.message ? e.message : e));
                } finally {
                    saveBtn.disabled = false;
                }
            });

            const openBtn = document.createElement("a");
            openBtn.className = "btn secondary";
            openBtn.textContent = tr("admin.apps.open", null, "Open");
            openBtn.href = `/apps/${encodeURIComponent(it.id)}/${encodeURIComponent(it.version)}/www/index.html`;
            openBtn.target = "_blank";
            openBtn.rel = "noopener";

            const btn = document.createElement("button");
            btn.className = "btn danger";
            btn.type = "button";
            btn.textContent = tr("admin.apps.uninstall", null, "Uninstall");
            btn.addEventListener("click", async () => {
                const ok = await openAdminAppsConfirmModal({
                    title: tr("admin.apps.uninstall_title", null, "Uninstall app?"),
                    subtitle: tr("admin.apps.uninstall_sub", null, "This removes the installed app package from this server."),
                    rows: [
                        { label: tr("admin.apps.app", null, "App"), value: String(it.id || ""), mono: true },
                        { label: tr("admin.apps.version", null, "Version"), value: String(it.version || ""), mono: true },
                        { label: tr("admin.apps.path", null, "Path"), value: String(it.root || ""), mono: true },
                    ],
                    note: tr("admin.apps.uninstall_note", null, "This removes the installed app files and registration for this version. User data stored elsewhere is not intentionally deleted."),
                    confirmText: tr("admin.apps.uninstall", null, "Uninstall"),
                    cancelText: tr("admin.apps.cancel", null, "Cancel"),
                    danger: true,
                });
                if (!ok) return;

                try {
                    setBadge("warn", tr("admin.apps.working", null, "working…"));
                    statusLine.textContent = tr("admin.apps.uninstalling", { id: it.id, version: it.version }, `Uninstalling ${it.id} ${it.version}…`);

                    const r = await fetch("/api/v4/apps/uninstall", {
                        method: "POST",
                        credentials: "include",
                        headers: {"Content-Type":"application/json"},
                        body: JSON.stringify({ id: it.id, version: it.version })
                    });
                    const j = await r.json().catch(() => null);
                    if (!r.ok || !j || !j.ok) {
                        setBadge("err", tr("admin.apps.error", null, "error"));
                        statusLine.textContent = (j && (j.message || j.error))
                            ? tr("admin.apps.uninstall_failed", { error: `${j.error || ""} ${j.message || ""}`.trim() }, `Uninstall failed: ${`${j.error || ""} ${j.message || ""}`.trim()}`)
                            : tr("admin.apps.uninstall_failed_http", { status: r.status }, `Uninstall failed: HTTP ${r.status}`);
                        return;
                    }

                    await load();
                } catch (e) {
                    setBadge("err", tr("admin.apps.network", null, "network"));
                    statusLine.textContent = tr("admin.apps.network_error", null, "Network error") + ": " + String(e && e.message ? e.message : e);
                }
            });

            actions.appendChild(saveBtn);
            actions.appendChild(openBtn);
            actions.appendChild(btn);

            right.appendChild(policyGrid);
            right.appendChild(actions);

            row.appendChild(left);
            row.appendChild(right);
            installedList.appendChild(row);
        }
    }

    async function load(){
        try {
            setBadge("warn", tr("admin.apps.loading", null, "loading…"));
            statusLine.textContent = tr("admin.apps.loading_api", null, "Loading /api/v4/apps…");

            const r = await fetch("/api/v4/apps", { credentials: "include", cache: "no-store" });
            const j = await r.json().catch(() => null);

            if (!r.ok || !j || !j.ok) {
                setBadge("err", tr("admin.apps.error", null, "error"));
                statusLine.textContent = tr("admin.apps.load_failed_http", { status: r.status }, `Load failed: HTTP ${r.status}`);
                return;
            }

            const installed = Array.isArray(j.installed) ? j.installed : [];
            launchPolicyByAppId = (j.launch_policy_by_app_id && typeof j.launch_policy_by_app_id === "object")
                ? j.launch_policy_by_app_id
                : {};

            setBadge("ok", tr("admin.apps.ready", null, "ready"));
            statusLine.textContent = tr("admin.apps.installed_count", { count: installed.length }, `Installed: ${installed.length}`);
            lastInstalledItems = installed;
            renderInstalled(installed);
        } catch (e) {
            setBadge("err", tr("admin.apps.network", null, "network"));
            statusLine.textContent = tr("admin.apps.network_error", null, "Network error");
            installedList.innerHTML = `<div class="mono">${esc(String(e && e.stack ? e.stack : e))}</div>`;
        }
    }

    async function install(){
        installOut.textContent = "";
        const f = zipFile?.files?.[0];
        if (!f) {
            installOut.textContent = tr("admin.apps.choose_zip", null, "Choose a .zip file first.");
            return;
        }

        try {
            setBadge("warn", tr("admin.apps.uploading", null, "uploading…"));
            statusLine.textContent = tr("admin.apps.uploading_file", { name: f.name, size: f.size }, `Uploading ${f.name} (${f.size} bytes)…`);

            const r = await fetch("/api/v4/apps/upload_install", {
                method: "POST",
                credentials: "include",
                headers: {
                    "Content-Type": "application/zip",
                    "X-PQNAS-Filename": f.name,
                    "X-PQNAS-Admin-Only": installAdminOnly && installAdminOnly.checked ? "1" : "0"
                },
                body: f
            });


            const j = await r.json().catch(() => null);
            if (!r.ok || !j || !j.ok) {
                setBadge("err", tr("admin.apps.error", null, "error"));
                statusLine.textContent = tr("admin.apps.install_failed_http", { status: r.status }, `Install failed: HTTP ${r.status}`);
                installOut.textContent = (j && (j.message || j.error))
                    ? `${j.error || ""} ${j.message || ""}`.trim()
                    : tr("admin.apps.bad_response", null, "bad response");
                return;
            }

            setBadge("ok", tr("admin.apps.installed", null, "installed"));
            statusLine.textContent = tr("admin.apps.installed_app", { id: j.id, version: j.version }, `Installed ${j.id} ${j.version}`);
            installOut.textContent = JSON.stringify(j, null, 2);

            zipFile.value = "";
            updateZipPickName();
            if (installAdminOnly) installAdminOnly.checked = false;
            await load();
        } catch (e) {
            setBadge("err", tr("admin.apps.network", null, "network"));
            statusLine.textContent = tr("admin.apps.network_error", null, "Network error");
            installOut.textContent = String(e && e.stack ? e.stack : e);
        }
    }

    refreshBtn?.addEventListener("click", load);
    zipPickBtn?.addEventListener("click", () => zipFile?.click());
    zipFile?.addEventListener("change", updateZipPickName);
    installBtn?.addEventListener("click", install);

    window.addEventListener("pqnas-language-changed", () => {
        applyStaticI18n();
        updateZipPickName();
        renderInstalled(lastInstalledItems || []);
    });

    applyStaticI18n();
    updateZipPickName();
    load();
})();
