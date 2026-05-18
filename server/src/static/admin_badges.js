// server/src/static/admin_badges.js
(() => {
    let lastRole = null;

    function tr(key, vars, fallback) {
        const api = window.PQNAS_I18N;
        if (api && typeof api.t === "function") {
            return api.t(key, vars || null, fallback);
        }
        return String(fallback ?? key);
    }

    // -----------------------------
    // Small helper (non-throwing)
    // -----------------------------
    async function tryGetJson(path) {
        try {
            const r = await fetch(path, { credentials: "include", headers: { "Accept": "application/json" }, cache: "no-store" });
            const j = await r.json().catch(() => null);
            return { ok: r.ok, j };
        } catch {
            return { ok: false, j: null };
        }
    }

    // ============================================================
    // A) Role badge updater (#roleBadge)
    // ============================================================
    function setRoleBadge(role) {
        const badge = document.getElementById("roleBadge");
        if (!badge) return;

        role = String(role || "").toLowerCase();
        lastRole = role;

        if (role === "admin") {
            badge.textContent = tr("admin.badges.role.admin", null, "role: admin");
            badge.className = "badge admin";
        } else if (role === "user") {
            badge.textContent = tr("admin.badges.role.user", null, "role: user");
            badge.className = "badge user";
        } else {
            badge.textContent = tr("admin.badges.role.unknown", null, "role: ?");
            badge.className = "badge unknown";
        }
    }

    async function refreshRoleOnce() {
        const { ok, j } = await tryGetJson("/api/v4/me");
        if (!ok || !j || !j.ok) return setRoleBadge(null);
        setRoleBadge(j.role);
    }

    // ============================================================
    // B) Approvals nav “!” badge updater (your existing logic)
    // ============================================================
    function ensureNavAlertBadge(el) {
        if (!el) return null;
        let b = el.querySelector(".navAlertBadge");
        if (b) return b;

        b = document.createElement("span");
        b.className = "navAlertBadge";
        b.textContent = "!";
        b.title = tr("admin.badges.pending_approvals", null, "Pending approvals");
        el.appendChild(b);
        return b;
    }

    function findApprovalsNav() {
        return document.querySelector('.nav a.navbtn[href="/admin/approvals"]');
    }

    async function refreshApprovalsOnce() {
        const approvalsBtn = findApprovalsNav();
        if (!approvalsBtn) return;

        const badge = ensureNavAlertBadge(approvalsBtn);

        let pending = 0;
        try {
            const r = await fetch("/api/v4/admin/users", {
                credentials: "include",
                headers: { "Accept": "application/json" },
                cache: "no-store"
            });
            const j = await r.json().catch(() => ({}));
            if (!r.ok || !j.ok) return;

            const users = Array.isArray(j.users) ? j.users : [];
            pending = users.filter(u => String(u.status || "").toLowerCase() !== "enabled").length;
        } catch {
            return;
        }

        const on = pending > 0;
        approvalsBtn.classList.toggle("needs-attn", on);

        if (badge) {
            badge.style.display = on ? "inline-flex" : "none";
            badge.textContent = "!";
            badge.title = on
                ? tr("admin.badges.pending_count", { pending, count: pending }, `Pending approvals: ${pending}`)
                : tr("admin.badges.no_pending", null, "No pending approvals");
        }
    }

    // ============================================================
    // Start
    // ============================================================
    async function start() {
        // run once
        await refreshRoleOnce();
        await refreshApprovalsOnce();

        // role can be cheap (only /me)
        setInterval(refreshRoleOnce, 15000);

        // approvals poll as you had
        setInterval(refreshApprovalsOnce, 10000);
    }

    window.addEventListener("pqnas-language-changed", () => {
        setRoleBadge(lastRole);
        refreshApprovalsOnce();
    });

    window.addEventListener("load", start);
})();
