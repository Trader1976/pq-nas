(function () {
    const $ = (id) => document.getElementById(id);

    const statusPill = $("statusPill");
    const persistedVal = $("persistedVal");
    const runtimeVal = $("runtimeVal");
    const levelSelect = $("levelSelect");
    const btnSave = $("btnSave");
    const btnReload = $("btnReload");

    const toast = $("toast");
    const toastTitle = $("toastTitle");
    const toastMsg = $("toastMsg");

    function setPill(kind, text) {
        statusPill.className = "pill " + (kind || "");
        statusPill.innerHTML = `<span class="k">Status:</span> <span class="v">${escapeHtml(text)}</span>`;
    }

    function showToast(kind, title, msg) {
        toast.className = "toast show " + (kind || "");
        toastTitle.textContent = title;
        toastMsg.textContent = msg || "";
        window.clearTimeout(showToast._t);
        showToast._t = window.setTimeout(() => {
            toast.className = "toast";
        }, 2400);
    }

    function escapeHtml(s) {
        return String(s ?? "")
            .replaceAll("&", "&amp;")
            .replaceAll("<", "&lt;")
            .replaceAll(">", "&gt;")
            .replaceAll('"', "&quot;")
            .replaceAll("'", "&#39;");
    }

    async function apiGet() {
        const r = await fetch("/api/v4/admin/settings", { cache: "no-store" });
        if (!r.ok) throw new Error(`GET /api/v4/admin/settings failed (${r.status})`);
        return await r.json();
    }

    async function apiPost(level) {
        const r = await fetch("/api/v4/admin/settings", {
            method: "POST",
            cache: "no-store",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ audit_min_level: level }),
        });
        const j = await r.json().catch(() => null);
        if (!r.ok || !j || j.ok !== true) {
            const msg = (j && (j.message || j.error)) ? `${j.message || j.error}` : `HTTP ${r.status}`;
            throw new Error(msg);
        }
        return j;
    }

    function setOptions(allowed, selected) {
        levelSelect.innerHTML = "";
        for (const lvl of allowed) {
            const opt = document.createElement("option");
            opt.value = lvl;
            opt.textContent = lvl;
            if (lvl === selected) opt.selected = true;
            levelSelect.appendChild(opt);
        }
    }

    async function refresh() {
        setPill("", "loading…");
        try {
            const j = await apiGet();

            const allowed = Array.isArray(j.allowed) ? j.allowed : ["SECURITY", "ADMIN", "INFO", "DEBUG"];
            const persisted = j.audit_min_level || "ADMIN";
            const runtime = j.audit_min_level_runtime || persisted;

            persistedVal.textContent = persisted;
            runtimeVal.textContent = runtime;

            // Prefer selecting persisted value (what will survive restart)
            setOptions(allowed, persisted);

            setPill("ok", "ready");
        } catch (e) {
            console.error(e);
            setPill("fail", "error");
            showToast("fail", "Failed to load settings", String(e.message || e));
        }
    }

    btnReload.addEventListener("click", (ev) => {
        ev.preventDefault();
        refresh();
    });

    btnSave.addEventListener("click", async (ev) => {
        ev.preventDefault();
        const lvl = levelSelect.value;
        btnSave.disabled = true;
        setPill("", "saving…");
        try {
            await apiPost(lvl);
            showToast("ok", "Saved", `audit_min_level = ${lvl}`);
            await refresh();
        } catch (e) {
            console.error(e);
            showToast("fail", "Save failed", String(e.message || e));
            setPill("fail", "error");
        } finally {
            btnSave.disabled = false;
        }
    });

    // init
    refresh();
})();
