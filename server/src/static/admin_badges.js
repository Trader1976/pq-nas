(() => {
    async function apiGet(path) {
        const r = await fetch(path, { headers: { "Accept": "application/json" }, cache: "no-store" });
        const j = await r.json().catch(() => ({}));
        if (!r.ok || !j.ok) throw new Error(j.message || j.error || ("HTTP " + r.status));
        return j;
    }

    function ensureBadge(el) {
        if (!el) return null;

        // Reuse one badge element if already present
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
        // Works across all your admin pages because the sidebar links are consistent.
        // It finds the first nav button that points to /admin/approvals.
        return document.querySelector('.nav a.navbtn[href="/admin/approvals"]');
    }

    async function refreshOnce() {
        const approvalsBtn = findApprovalsNav();
        if (!approvalsBtn) return;

        const badge = ensureBadge(approvalsBtn);

        // If we can’t load users, fail silent (don’t break UI)
        let pending = 0;
        try {
            const j = await apiGet("/api/v4/admin/users");
            const users = Array.isArray(j.users) ? j.users : [];
            pending = users.filter(u => String(u.status || "").toLowerCase() !== "enabled").length;
        } catch {
            // keep previous state
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

    async function start() {
        // initial
        await refreshOnce();

        // poll (don’t hammer; /app already polls /me every 2s)
        setInterval(refreshOnce, 10000);
    }

    window.addEventListener("load", start);
})();
