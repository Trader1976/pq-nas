(() => {
    const out = document.getElementById("out");
    const adminBlock = document.getElementById("admin_block");

    // New UI elements (from the updated app.html)
    const badge = document.getElementById("stateBadge");
    const statusLine = document.getElementById("statusLine");
    const refreshBtn = document.getElementById("refreshBtn");
    const adminHomeBtn = document.getElementById("adminHomeBtn");

    const stateDisabled = document.getElementById("state_disabled");
    const stateUnauth = document.getElementById("state_unauth");

    function show(el, on) {
        if (!el) return;
        el.style.display = on ? "" : "none";
    }

    function setBadge(kind, text) {
        if (!badge) return;
        badge.className = `badge ${kind}`;
        badge.textContent = text;
    }

    async function loadMe() {
        show(stateDisabled, false);
        show(stateUnauth, false);

        try {
            const r = await fetch("/api/v4/me", { credentials: "include", cache: "no-store" });
            const ct = (r.headers.get("content-type") || "").toLowerCase();
            const txt = await r.text();

            if (statusLine) statusLine.textContent = `GET /api/v4/me → HTTP ${r.status}`;

            // Try parse JSON even if ct is wrong
            let j = null;
            try { j = JSON.parse(txt); } catch {}

            if (j) {
                if (out) out.textContent = JSON.stringify(j, null, 2);

                const role = j.role || "?";
                const ok = !!j.ok;

                const isAdmin = ok && role === "admin";
                show(adminBlock, isAdmin);
                show(adminHomeBtn, isAdmin);

                if (!r.ok || !ok) {
                    const err = String(j.error || "").toLowerCase();
                    const msg = String(j.message || "");

                    if (r.status === 403 || err.includes("disabled") || msg.toLowerCase().includes("disabled")) {
                        setBadge("warn", "waiting for admin");
                        show(stateDisabled, true);
                    } else if (r.status === 401 || err.includes("unauthorized") || msg.toLowerCase().includes("unauthorized")) {
                        setBadge("warn", "not signed in");
                        show(stateUnauth, true);
                    } else {
                        setBadge("err", "error");
                    }
                    return;
                }

                setBadge("ok", `signed in · ${role}`);
                return;
            }

            // Non-JSON body
            show(adminBlock, false);
            show(adminHomeBtn, false);
            setBadge("err", "unexpected response");

            if (out) {
                const body = txt.length > 4000 ? (txt.slice(0, 4000) + "\n…(truncated)…") : txt;
                out.textContent = `${r.status}${ct ? " · " + ct.split(";")[0] : ""}\n\n${body}`;
            }
        } catch (e) {
            show(adminBlock, false);
            show(adminHomeBtn, false);
            setBadge("err", "network error");
            if (statusLine) statusLine.textContent = "Failed to load /api/v4/me";
            if (out) out.textContent = String(e && e.stack ? e.stack : e);
        }
    }

    if (refreshBtn) refreshBtn.addEventListener("click", loadMe);

    loadMe();
    // Makes "waiting for approval" feel alive
    setInterval(loadMe, 2000);
})();
