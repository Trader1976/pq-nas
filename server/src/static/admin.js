(async () => {
    const status = document.getElementById("status");
    const pre = document.getElementById("me");
    const badge = document.getElementById("roleBadge");

    function setBadge(role) {
        if (!badge) return;
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

    try {
        const r = await fetch("/api/v4/me", { credentials: "include", cache: "no-store" });
        const ct = (r.headers.get("content-type") || "").toLowerCase();
        const txt = await r.text();

        if (status) status.textContent = `HTTP ${r.status}${ct ? ` · ${ct.split(";")[0]}` : ""}`;

        // Prefer JSON when possible, but don’t die if it’s HTML/plaintext
        let j = null;
        if (ct.includes("application/json")) {
            try { j = JSON.parse(txt); } catch (_) { /* fall through */ }
        } else {
            // Sometimes servers still return JSON without content-type
            try { j = JSON.parse(txt); } catch (_) { /* ignore */ }
        }

        if (j) {
            if (pre) pre.textContent = JSON.stringify(j, null, 2);
            setBadge(j.role);
            return;
        }

        // Non-JSON body (or invalid JSON) -> show raw body (trimmed)
        setBadge(null);
        if (pre) pre.textContent = txt.length > 4000 ? (txt.slice(0, 4000) + "\n…(truncated)…") : txt;
    } catch (e) {
        if (status) status.textContent = "Failed to load /api/v4/me";
        if (pre) pre.textContent = String(e && e.stack ? e.stack : e);
        setBadge(null);
    }
})();
