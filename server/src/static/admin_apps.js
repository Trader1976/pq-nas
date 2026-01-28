(() => {
    const stateBadge = document.getElementById("stateBadge");
    const statusLine = document.getElementById("statusLine");
    const refreshBtn = document.getElementById("refreshBtn");
    const installedList = document.getElementById("installedList");

    const zipFile = document.getElementById("zipFile");
    const installBtn = document.getElementById("installBtn");
    const installOut = document.getElementById("installOut");

    function setBadge(kind, text){
        stateBadge.className = `badge ${kind}`;
        stateBadge.textContent = text;
    }

    function esc(s){ return String(s ?? "").replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }

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

            const actions = document.createElement("div");
            actions.className = "row";

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

            actions.appendChild(btn);

            row.appendChild(left);
            row.appendChild(actions);
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
                    "X-PQNAS-Filename": f.name
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
