// server/src/static/admin_badges.js
(() => {
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
        if (role === "admin") {
            badge.textContent = "role: admin";
            badge.className = "badge admin";
        } else if (role === "user") {
            badge.textContent = "role: user";
            badge.className = "badge user";
        } else {
            badge.textContent = "role: ?";
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
        b.title = "Pending approvals";
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
            badge.title = on ? `Pending approvals: ${pending}` : "No pending approvals";
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

    window.addEventListener("load", start);
})();
