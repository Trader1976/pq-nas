(async () => {
    const status = document.getElementById("status");
    const pre = document.getElementById("me");
    const badge = document.getElementById("roleBadge");

    try {
        const r = await fetch("/api/v4/me", { credentials: "include" });
        const txt = await r.text();
        status.textContent = `HTTP ${r.status}`;

        const j = JSON.parse(txt);
        pre.textContent = JSON.stringify(j, null, 2);

        if (j.role === "admin") {
            badge.textContent = "role: admin";
            badge.className = "badge admin";
        } else if (j.role === "user") {
            badge.textContent = "role: user";
            badge.className = "badge user";
        } else {
            badge.textContent = "role: ?";
            badge.className = "badge unknown";
        }
    } catch (e) {
        status.textContent = "Failed to load /api/v4/me";
        pre.textContent = String(e);
    }
})();
