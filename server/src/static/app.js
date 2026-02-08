(() => {
    const out = document.getElementById("out");

    const badge = document.getElementById("stateBadge");
    const statusLine = document.getElementById("statusLine");
    const refreshBtn = document.getElementById("refreshBtn");

    const stateDisabled = document.getElementById("state_disabled");
    const stateUnauth = document.getElementById("state_unauth");

    const navHome = document.getElementById("nav_home");

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
    const contentGrid = document.getElementById("contentGrid");

    const appsList = document.getElementById("appsList");

    // app state
    let installedApps = [];     // [{id, version, has_manifest, root}, ...]
    let currentView = "home";   // "home" or "app:<id>@<ver>"
    let currentApp = null;      // {id, version} or null
    let lastAppsKey = "";
    let authed = false;

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
        const ids = ["nav_home"];
        for (const id of ids) {
            const b = document.getElementById(id);
            if (!b) continue;
            b.classList.toggle("active", id === activeId);
        }
    }

    function clearAppsList(){
        if (!appsList) return;
        appsList.innerHTML = "";
    }

    function addAppNavButton(appId, label, href){
        if (!appsList) return;

        const a = document.createElement("a");
        a.className = "navbtn";
        a.href = href; // we will preventDefault and render iframe
        a.dataset.appid = appId;

        const left = document.createElement("span");
        left.textContent = label;

        const k = document.createElement("span");
        k.className = "k";
        k.textContent = "▶";

        a.appendChild(left);
        a.appendChild(k);

        a.addEventListener("click", (ev) => {
            ev.preventDefault();
            openAppById(appId);
        });

        appsList.appendChild(a);
    }

    function setActiveApp(appId){
        if (!appsList) return;
        for (const el of appsList.querySelectorAll(".navbtn")){
            el.classList.toggle("active", el.dataset.appid === appId);
        }
    }

    function renderHome(){
        currentView = "home";
        currentApp = null;

        setActiveNav("nav_home");
        setActiveApp(""); // clears app highlight

        if (wsTitle) wsTitle.textContent = "Home";
        if (wsSubtitle) wsSubtitle.textContent = "Session, role, and access status";
        if (mainPaneTitle) mainPaneTitle.textContent = "Workspace";

        // ✅ remove "embedded app" styling when leaving an app
        if (homeBlurb) {
            const mainPane = homeBlurb.closest(".pane");
            if (mainPane) mainPane.classList.remove("appHost");
            homeBlurb.classList.remove("appHostBlurb");
        }

        if (homeBlurb) {
            homeBlurb.innerHTML =
                `This is the PQ-NAS desktop shell. The large pane hosts apps and tools.
             Installed apps appear in the left menu. Admin links appear only when your role is <b>admin</b>.`;
            show(homeBlurb, true);
        }
    }

    function renderApp(app){
        // app = {id, version}
        currentView = `app:${app.id}@${app.version}`;
        currentApp = { id: app.id, version: app.version };

        setActiveNav(""); // Home not active
        setActiveApp(app.id);

        if (wsTitle) wsTitle.textContent = app.id;
        if (wsSubtitle) wsSubtitle.textContent = "App (embedded)";
        if (mainPaneTitle) mainPaneTitle.textContent = app.id;

        if (!homeBlurb) return;

        // mark main pane + blurb as app host mode (for tighter padding)
        const mainPane = homeBlurb.closest(".pane");
        if (mainPane) mainPane.classList.add("appHost");
        homeBlurb.classList.add("appHostBlurb");

        homeBlurb.innerHTML = "";

        const info = document.createElement("div");
        info.className = "appHostInfo mono";
        info.innerHTML = `<b>APP ACTIVE ✅</b> — loading <span class="mono">${app.id} ${app.version}</span>`;

        const frame = document.createElement("iframe");
        frame.className = "appFrame";
        frame.src = `/apps/${encodeURIComponent(app.id)}/${encodeURIComponent(app.version)}/www/index.html`;

       // homeBlurb.appendChild(info);

        const frameWrap = document.createElement("div");
        frameWrap.className = "appFrameWrap";
        frameWrap.appendChild(frame);


        homeBlurb.appendChild(frameWrap);
        show(homeBlurb, true);
    }

    function openAppById(appId){
        const a = installedApps.find(x => x.id === appId);
        if (!a) {
            // fallback to home
            renderHome();
            return;
        }
        renderApp({ id: a.id, version: a.version });
    }

    async function loadApps(){
        if (!appsList) return;

        try {
            const r = await fetch("/api/v4/apps", { credentials: "include", cache: "no-store" });
            const j = await r.json().catch(() => null);
            if (!r.ok || !j || !j.ok) return;

            const installed = Array.isArray(j.installed) ? j.installed : [];
            const usable = installed.filter(x => x && x.id && x.version && x.has_manifest);

            // stable order: id then version
            usable.sort((a,b) => {
                const ai = String(a.id||"");
                const bi = String(b.id||"");
                if (ai !== bi) return ai.localeCompare(bi);
                return String(a.version||"").localeCompare(String(b.version||""));
            });

            const key = JSON.stringify(usable.map(x => [x.id, x.version]));
            if (key === lastAppsKey) return;
            lastAppsKey = key;

            installedApps = usable;

            clearAppsList();
            for (const a of usable) {
                // label = id for now (we can later fetch manifest.json to show "name")
                const label = a.id;
                const href = `/apps/${encodeURIComponent(a.id)}/${encodeURIComponent(a.version)}/www/index.html`;
                addAppNavButton(a.id, label, href);
            }

            // keep current view alive if app still exists; otherwise go home
            if (currentApp) {
                const still = installedApps.find(x => x.id === currentApp.id);
                if (!still) renderHome();
                else setActiveApp(currentApp.id);
            }
        } catch {
            // ignore (no UI spam)
        }
    }

    async function loadMe() {
        authed = false;
        show(stateDisabled, false);
        show(stateUnauth, false);

        try {
            const r = await fetch("/api/v4/me", { credentials: "include", cache: "no-store" });
            const ct = (r.headers.get("content-type") || "").toLowerCase();
            const txt = await r.text();

            if (statusLine) statusLine.textContent = "PQ-NAS v1.0";

            let j = null;
            try { j = JSON.parse(txt); } catch {}

            if (j) {
                if (out) out.textContent = JSON.stringify(j, null, 2);

                const role = j.role || "?";
                const ok = !!j.ok;
                authed = ok && r.ok;

                const isAdmin = ok && role === "admin";

                // show admin-only links
                show(navAdmin, isAdmin);
                show(navUsers, isAdmin);
                show(navAudit, isAdmin);
                show(navSettings, isAdmin);

                // signed-in vs not-signed-in nav
                show(navLogin, !ok);

                if (!r.ok || !ok) {
                    authed = false;
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

                const st = String(j.storage_state || "unallocated");
                setBadge("ok", `signed in · ${role} · storage: ${st}`);

                // update installed apps list (only when signed in ok)
                loadApps();

                return;
            }

            // Non-JSON body
            authed = false;
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
            authed = false;
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

    if (refreshBtn) refreshBtn.addEventListener("click", () => {
        loadMe();
        loadApps();
    });

    function setInspectorHidden(hidden) {
        if (!inspectorPane || !toggleInspectorBtn) return;
        inspectorPane.style.display = hidden ? "none" : "";
        if (contentGrid) contentGrid.classList.toggle("noInspector", hidden);
        toggleInspectorBtn.textContent = hidden ? "Show inspector" : "Hide inspector";
        try { localStorage.setItem("pqnas_hide_inspector", hidden ? "1" : "0"); } catch {}
    }

    // default: hidden (or last saved choice)
    (() => {
        let hide = true;
        try {
            const v = localStorage.getItem("pqnas_hide_inspector");
            if (v === "0") hide = false;
        } catch {}
        setInspectorHidden(hide);
    })();

    if (toggleInspectorBtn && inspectorPane) {
        toggleInspectorBtn.addEventListener("click", () => {
            const hidden = inspectorPane.style.display === "none";
            setInspectorHidden(!hidden);
        });
    }

    if (navHome) navHome.addEventListener("click", () => renderHome());

    // Default view
    renderHome();

// Load once immediately
    loadMe();

// Refresh auth state when tab comes back / user focuses
    document.addEventListener("visibilitychange", () => {
        if (!document.hidden) loadMe();
    });
    window.addEventListener("focus", () => loadMe());

// Slow refresh (only to keep UI honest; not a heartbeat)
    setInterval(() => { if (authed) loadMe(); }, 30000);

// Apps list can be even slower
    setInterval(() => { if (authed) loadApps(); }, 60000);

})();
