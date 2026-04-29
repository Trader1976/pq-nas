(() => {
    const stateBadge = document.getElementById("stateBadge");
    const statusLine = document.getElementById("statusLine");
    const refreshBtn = document.getElementById("refreshBtn");
    const installedList = document.getElementById("installedList");

    const zipFile = document.getElementById("zipFile");
    const installBtn = document.getElementById("installBtn");
    const installOut = document.getElementById("installOut");
    const installAdminOnly = document.getElementById("installAdminOnly");
    let launchPolicyByAppId = {};

    function setBadge(kind, text){
        stateBadge.className = `badge ${kind}`;
        stateBadge.textContent = text;
    }

    function esc(s){ return String(s ?? "").replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }

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
                : `save failed (${r.status})`);
        }
        return j;
    }

    function renderInstalled(items){
        installedList.innerHTML = "";
        if (!items.length) {
            installedList.innerHTML = `<div class="mono muted">(no installed apps)</div>`;
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
            meta.textContent = `${it.has_manifest ? "manifest" : "no-manifest"} · ${it.root || ""}`;

            left.appendChild(name);
            left.appendChild(meta);

            const pol = policyForApp(it.id);

            const launchMeta = document.createElement("div");
            launchMeta.className = "meta";
            launchMeta.textContent =
                `Launch: ${pol.default_launch} · Window: ${pol.window_profile} · User override: ${pol.allow_user_override ? "yes" : "no"} · Visibility: ${pol.admin_only ? "admin only" : "all users"}`;

            left.appendChild(launchMeta);

            const right = document.createElement("div");
            right.className = "appPolicyRight";

            const policyGrid = document.createElement("div");
            policyGrid.className = "policyGrid";

            const launchField = document.createElement("div");
            launchField.className = "policyField";
            launchField.innerHTML = `
    <label class="policyLbl">Default launch</label>
    <select class="policySel">
        <option value="auto">Auto</option>
        <option value="embedded">Embedded</option>
        <option value="detached">Detached</option>
    </select>
`;

            const windowField = document.createElement("div");
            windowField.className = "policyField";
            windowField.innerHTML = `
    <label class="policyLbl">Window profile</label>
    <select class="policySel">
        <option value="auto">Auto</option>
        <option value="small">Small</option>
        <option value="normal">Normal</option>
        <option value="large">Large</option>
        <option value="full">Full</option>
    </select>
`;

            const overrideField = document.createElement("div");
            overrideField.className = "policyField";
            overrideField.innerHTML = `
    <label class="policyLbl">User override</label>
    <label class="policyChk">
        <input type="checkbox" />
        <span>Allow user override</span>
    </label>
`;
            const visibilityField = document.createElement("div");
            visibilityField.className = "policyField";
            visibilityField.innerHTML = `
    <label class="policyLbl">Visibility</label>
    <label class="policyChk">
        <input type="checkbox" />
        <span>Admin only</span>
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
            saveBtn.textContent = "Save launch policy";
            saveBtn.addEventListener("click", async () => {
                try {
                    saveBtn.disabled = true;
                    setBadge("warn", "saving…");
                    statusLine.textContent = `Saving launch policy for ${it.id}…`;

                    await saveLaunchPolicy(it.id, {
                        default_launch: launchSel.value,
                        window_profile: windowSel.value,
                        allow_user_override: overrideChk.checked,
                        admin_only: adminOnlyChk.checked
                    });

                    await load();
                    setBadge("ok", "ready");
                    statusLine.textContent = `Saved launch policy for ${it.id}`;
                } catch (e) {
                    setBadge("err", "error");
                    statusLine.textContent = String(e && e.message ? e.message : e);
                    alert(String(e && e.message ? e.message : e));
                } finally {
                    saveBtn.disabled = false;
                }
            });

            const openBtn = document.createElement("a");
            openBtn.className = "btn secondary";
            openBtn.textContent = "Open";
            openBtn.href = `/apps/${encodeURIComponent(it.id)}/${encodeURIComponent(it.version)}/www/index.html`;
            openBtn.target = "_blank";
            openBtn.rel = "noopener";

            const btn = document.createElement("button");
            btn.className = "btn danger";
            btn.type = "button";
            btn.textContent = "Uninstall";
            btn.addEventListener("click", async () => {
                if (!confirm(`Uninstall ${it.id} ${it.version}?`)) return;
                try {
                    setBadge("warn", "working…");
                    statusLine.textContent = "Uninstalling…";

                    const r = await fetch("/api/v4/apps/uninstall", {
                        method: "POST",
                        credentials: "include",
                        headers: {"Content-Type":"application/json"},
                        body: JSON.stringify({ id: it.id, version: it.version })
                    });
                    const j = await r.json().catch(() => null);
                    if (!r.ok || !j || !j.ok) {
                        setBadge("err", "error");
                        statusLine.textContent = `Uninstall failed: HTTP ${r.status}`;
                        alert((j && (j.message || j.error)) ? `${j.error||""} ${j.message||""}`.trim() : "bad response");
                        return;
                    }

                    await load();
                } catch (e) {
                    setBadge("err", "network");
                    statusLine.textContent = "Network error";
                    alert(String(e && e.stack ? e.stack : e));
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
            setBadge("warn", "loading…");
            statusLine.textContent = "Loading /api/v4/apps…";

            const r = await fetch("/api/v4/apps", { credentials: "include", cache: "no-store" });
            const j = await r.json().catch(() => null);

            if (!r.ok || !j || !j.ok) {
                setBadge("err", "error");
                statusLine.textContent = `Load failed: HTTP ${r.status}`;
                return;
            }

            const installed = Array.isArray(j.installed) ? j.installed : [];
            launchPolicyByAppId = (j.launch_policy_by_app_id && typeof j.launch_policy_by_app_id === "object")
                ? j.launch_policy_by_app_id
                : {};

            setBadge("ok", "ready");
            statusLine.textContent = `Installed: ${installed.length}`;
            renderInstalled(installed);
        } catch (e) {
            setBadge("err", "network");
            statusLine.textContent = "Network error";
            installedList.innerHTML = `<div class="mono">${esc(String(e && e.stack ? e.stack : e))}</div>`;
        }
    }

    async function install(){
        installOut.textContent = "";
        const f = zipFile?.files?.[0];
        if (!f) {
            installOut.textContent = "Choose a .zip file first.";
            return;
        }

        try {
            setBadge("warn", "uploading…");
            statusLine.textContent = `Uploading ${f.name} (${f.size} bytes)…`;

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
                setBadge("err", "error");
                statusLine.textContent = `Install failed: HTTP ${r.status}`;
                installOut.textContent = (j && (j.message || j.error))
                    ? `${j.error || ""} ${j.message || ""}`.trim()
                    : "bad response";
                return;
            }

            setBadge("ok", "installed");
            statusLine.textContent = `Installed ${j.id} ${j.version}`;
            installOut.textContent = JSON.stringify(j, null, 2);

            zipFile.value = "";
            if (installAdminOnly) installAdminOnly.checked = false;
            await load();
        } catch (e) {
            setBadge("err", "network");
            statusLine.textContent = "Network error";
            installOut.textContent = String(e && e.stack ? e.stack : e);
        }
    }

    refreshBtn?.addEventListener("click", load);
    installBtn?.addEventListener("click", install);

    load();
})();
