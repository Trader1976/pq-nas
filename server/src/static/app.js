(() => {
    const out = document.getElementById("out");

    const badge = document.getElementById("stateBadge");
    const statusLine = document.getElementById("statusLine");
    const refreshBtn = document.getElementById("refreshBtn");

    const stateDisabled = document.getElementById("state_disabled");
    const stateUnauth = document.getElementById("state_unauth");

    const navHome = document.getElementById("nav_home");
    const navFiles = document.getElementById("nav_files");
    const navLogs = document.getElementById("nav_logs");

    const navAdmin = document.getElementById("nav_admin");
    const navUsers = document.getElementById("nav_users");
    const navAudit = document.getElementById("nav_audit");
    const navSettings = document.getElementById("nav_settings");

    const navLogin = document.getElementById("nav_login");
    const navLogout = document.getElementById("nav_logout");

    const wsTitle = document.getElementById("wsTitle");
    const wsSubtitle = document.getElementById("wsSubtitle");
    const mainPaneTitle = document.getElementById("mainPaneTitle");
    const homeBlurb = document.getElementById("homeBlurb");

    const inspectorPane = document.getElementById("inspectorPane");
    const toggleInspectorBtn = document.getElementById("toggleInspectorBtn");

    function show(el, on) {
        if (!el) return;
        el.style.display = on ? "" : "none";
    }

    function setBadge(kind, text) {
        if (!badge) return;
        badge.className = `badge ${kind}`;
        badge.textContent = text;
    }

    function setActiveNav(activeId) {
        const ids = ["nav_home", "nav_files", "nav_logs"];
        for (const id of ids) {
            const b = document.getElementById(id);
            if (!b) continue;
            b.classList.toggle("active", id === activeId);
        }
    }

    function setWorkspace(view) {
        // This is UI-only for now. We don't invent backend calls.
        if (view === "home") {
            setActiveNav("nav_home");
            if (wsTitle) wsTitle.textContent = "Home";
            if (wsSubtitle) wsSubtitle.textContent = "Session, role, and access status";
            if (mainPaneTitle) mainPaneTitle.textContent = "Workspace";
            if (homeBlurb) {
                homeBlurb.innerHTML =
                    `This is the PQ-NAS desktop shell. The large pane will later host the file manager, apps, and tools.
           Use the left menu to switch views. Admin links appear only when your role is <b>admin</b>.`;
                show(homeBlurb, true);
            }
            return;
        }

        if (view === "files") {
            setActiveNav("nav_files");
            if (wsTitle) wsTitle.textContent = "Files";
            if (wsSubtitle) wsSubtitle.textContent = "File manager (placeholder UI)";
            if (mainPaneTitle) mainPaneTitle.textContent = "File Manager";
            if (homeBlurb) {
                homeBlurb.innerHTML =
                    `File manager UI will be rendered here later (server-backed).`;
                show(homeBlurb, true);
            }
            return;
        }

        if (view === "logs") {
            setActiveNav("nav_logs");
            if (wsTitle) wsTitle.textContent = "Logs";
            if (wsSubtitle) wsSubtitle.textContent = "Viewer (placeholder UI)";
            if (mainPaneTitle) mainPaneTitle.textContent = "Logs";
            if (homeBlurb) {
                homeBlurb.innerHTML =
                    `Log viewer UI will be rendered here later (audit and system logs).`;
                show(homeBlurb, true);
            }
        }
    }

    async function loadMe() {
        show(stateDisabled, false);
        show(stateUnauth, false);

        try {
            const r = await fetch("/api/v4/me", { credentials: "include", cache: "no-store" });
            const ct = (r.headers.get("content-type") || "").toLowerCase();
            const txt = await r.text();

            if (statusLine) statusLine.textContent = `GET /api/v4/me → HTTP ${r.status}`;

            let j = null;
            try { j = JSON.parse(txt); } catch {}

            if (j) {
                if (out) out.textContent = JSON.stringify(j, null, 2);

                const role = j.role || "?";
                const ok = !!j.ok;

                const isAdmin = ok && role === "admin";

                // show admin-only links
                show(navAdmin, isAdmin);
                show(navUsers, isAdmin);
                show(navAudit, isAdmin);
                show(navSettings, isAdmin);

                // signed-in vs not-signed-in nav
                show(navLogin, !ok);
                // Logout stays visible but is just a link to "/" for now

                if (!r.ok || !ok) {
                    const err = String(j.error || "").toLowerCase();
                    const msg = String(j.message || "");

                    if (r.status === 403 || err.includes("disabled") || msg.toLowerCase().includes("disabled")) {
                        setBadge("warn", "waiting for admin");
                        show(stateDisabled, true);
                    } else if (r.status === 401 || err.includes("unauthorized") || msg.toLowerCase().includes("unauthorized")) {
                        setBadge("warn", "not signed in");
                        show(stateUnauth, true);
                        show(navLogin, true);
                    } else {
                        setBadge("err", "error");
                    }
                    return;
                }

                setBadge("ok", `signed in · ${role}`);
                return;
            }

            // Non-JSON body
            show(navAdmin, false);
            show(navUsers, false);
            show(navAudit, false);
            show(navSettings, false);
            show(navLogin, true);

            setBadge("err", "unexpected response");

            if (out) {
                const body = txt.length > 4000 ? (txt.slice(0, 4000) + "\n…(truncated)…") : txt;
                out.textContent = `${r.status}${ct ? " · " + ct.split(";")[0] : ""}\n\n${body}`;
            }
        } catch (e) {
            show(navAdmin, false);
            show(navUsers, false);
            show(navAudit, false);
            show(navSettings, false);
            show(navLogin, true);

            setBadge("err", "network error");
            if (statusLine) statusLine.textContent = "Failed to load /api/v4/me";
            if (out) out.textContent = String(e && e.stack ? e.stack : e);
        }
    }

    if (refreshBtn) refreshBtn.addEventListener("click", loadMe);

    if (toggleInspectorBtn && inspectorPane) {
        toggleInspectorBtn.addEventListener("click", () => {
            const hidden = inspectorPane.style.display === "none";
            inspectorPane.style.display = hidden ? "" : "none";
            toggleInspectorBtn.textContent = hidden ? "Hide inspector" : "Show inspector";
        });
    }

    if (navHome) navHome.addEventListener("click", () => setWorkspace("home"));
    if (navFiles) navFiles.addEventListener("click", () => setWorkspace("files"));
    if (navLogs) navLogs.addEventListener("click", () => setWorkspace("logs"));

    // Default view
    setWorkspace("home");

    // Load status immediately, then refresh periodically (keeps "waiting for admin" alive)
    loadMe();
    setInterval(loadMe, 2000);
})();
