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
    let installedApps = [];     // [{id, ver, name?, title?, ...}, ...]
    let meFpHex = "";           // fingerprint_hex from /api/v4/me (for desktop layout storage)


    // desktop state (icon layout + manifests)

    const manifestCache = new Map(); // key: "id@ver" -> parsed manifest json
    let desktopLayout = null;        // loaded from localStorage
    const DESKTOP_GRID_X = 80;
    const DESKTOP_GRID_Y = 88;
    let desktopSelectedKey = "";     // currently selected icon key

    let currentView = "home";   // "home" or "app:<id>@<ver>"
    let currentApp = null;      // {id, ver} or null
    let lastAppsKey = "";
    let authed = false;
    let isAdmin = false;

    // small UI state
    let versionShown = false;

    function show(el, on) {
        if (!el) return;
        el.style.display = on ? "" : "none";
    }

    function setBadge(kind, text) {
        if (!badge) return;

        const t = (text || "").trim();

        // Hide badge completely when no text
        if (!t) {
            badge.style.display = "none";
            badge.textContent = "";
            return;
        }

        // Show badge when there is content
        badge.style.display = "";
        badge.className = `badge ${kind}`;
        badge.textContent = t;
    }

    function setWsSubtitleSafe(txt) {
        // Don’t override app subtitle while an app is open.
        if (currentApp) return;
        if (wsSubtitle) wsSubtitle.textContent = txt;
    }

    function setActiveNav(activeId) {
        const ids = ["nav_home"];
        for (const id of ids) {
            const b = document.getElementById(id);
            if (!b) continue;
            b.classList.toggle("active", id === activeId);
        }
    }

    function clearAppsList() {
        if (!appsList) return;
        appsList.innerHTML = "";
    }

    function addAppNavButton(appId, label, href) {
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

    function setActiveApp(appId) {
        if (!appsList) return;
        for (const el of appsList.querySelectorAll(".navbtn")) {
            el.classList.toggle("active", el.dataset.appid === appId);
        }
    }
    function currentThemeName() {
        // Try data-theme set by your theme system, then localStorage, then default
        const dt = (document.documentElement.getAttribute("data-theme") || "").trim();
        if (dt) return dt;
        try {
            const v = (localStorage.getItem("pqnas_theme") || "").trim();
            if (v) return v;
        } catch {}
        return "dark";
    }

    function desktopStorageKey() {
        const fp = meFpHex ? meFpHex : "anon";
        const theme = currentThemeName();
        return `pqnas_desktop_layout_v1::${fp}::${theme}`;
    }

    function bindDesktopSurfaceOnce() {
        const surface = getDesktopSurface();
        if (!surface) return;
        if (surface.dataset.bound === "1") return;
        surface.dataset.bound = "1";

        surface.addEventListener("pointerdown", (ev) => {
            if (ev.target === surface) setSelectedIcon("");
        });

        // Optional: prevent text selection drag inside surface
        surface.addEventListener("dragstart", (ev) => ev.preventDefault());
    }

    function loadDesktopLayout() {
        const k = desktopStorageKey();
        try {
            const raw = localStorage.getItem(k);
            desktopLayout = raw ? JSON.parse(raw) : { items: {} };
        } catch {
            desktopLayout = { items: {} };
        }
        if (!desktopLayout || typeof desktopLayout !== "object") desktopLayout = { items: {} };
        if (!desktopLayout.items || typeof desktopLayout.items !== "object") desktopLayout.items = {};
        return desktopLayout;
    }

    function saveDesktopLayout() {
        const k = desktopStorageKey();
        try { localStorage.setItem(k, JSON.stringify(desktopLayout || { items: {} })); } catch {}
    }

    function getDesktopSurface() {
        return document.getElementById("desktopSurface");
    }

    async function fetchManifest(id, ver) {
        const key = `${id}@${ver}`;
        if (manifestCache.has(key)) return manifestCache.get(key);

        // Try the served manifest at app root
        const url = `/apps/${encodeURIComponent(id)}/${encodeURIComponent(ver)}/manifest.json`;
        try {
            const r = await fetch(url, { credentials: "include", cache: "no-store" });
            const j = await r.json().catch(() => null);
            if (r.ok && j && typeof j === "object") {
                manifestCache.set(key, j);
                return j;
            }
        } catch {}
        manifestCache.set(key, null);
        return null;
    }

    function resolveIconUrl(app, mani) {
        const base = `/apps/${encodeURIComponent(app.id)}/${encodeURIComponent(app.ver)}/`;
        const bust = `?v=${encodeURIComponent(app.ver || "")}`;

        const withBust = (rel) => (base + rel + bust);

        if (mani && mani.icons && typeof mani.icons === "object") {
            const theme = currentThemeName();

            if (mani.icons[theme]) return withBust(mani.icons[theme]);

            const map = {
                "cpunk": "cpunk_orange",
                "orange": "cpunk_orange",
                "win": "win_classic",
                "classic": "win_classic"
            };
            if (map[theme] && mani.icons[map[theme]]) return withBust(mani.icons[map[theme]]);

            if (mani.icons.default) return withBust(mani.icons.default);

            const first = Object.values(mani.icons)[0];
            if (first) return withBust(first);
        }

        return base + "www/icon.png" + bust;
    }




    function clamp(n, a, b) { return Math.max(a, Math.min(b, n)); }

    function layoutKeyFor(app) {
        return `${app.id}@${app.ver}`;
    }
    function snapToGrid(x, y) {

        return {
            x: Math.round(x / DESKTOP_GRID_X) * DESKTOP_GRID_X,
            y: Math.round(y / DESKTOP_GRID_Y) * DESKTOP_GRID_Y
        };
    }

    function ensureDefaultLayout(surface, apps) {
        if (!desktopLayout) loadDesktopLayout();
        if (!surface) return;

        const rect = surface.getBoundingClientRect();
        const pad = 14;
        const colW = DESKTOP_GRID_X;
        const rowH = DESKTOP_GRID_Y;


        let i = 0;
        for (const app of apps) {
            const k = layoutKeyFor(app);
            if (desktopLayout.items[k]) continue;

            const col = (i % 5);
            const row = Math.floor(i / 5);
            const x = pad + col * colW;
            const y = pad + row * rowH;

            desktopLayout.items[k] = { x, y };
            i++;
        }
        saveDesktopLayout();
    }

    function setSelectedIcon(key) {
        desktopSelectedKey = key || "";
        const surface = getDesktopSurface();
        if (!surface) return;
        for (const el of surface.querySelectorAll(".desktopIcon")) {
            el.classList.toggle("selected", el.dataset.key === desktopSelectedKey);
        }
    }

    function attachDrag(iconEl, app) {
        const surface = getDesktopSurface();
        if (!surface) return;

        let dragging = false;
        let startX = 0, startY = 0;
        let baseX = 0, baseY = 0;

        const key = layoutKeyFor(app);

        const onMove = (ev) => {
            if (!dragging) return;
            ev.preventDefault();

            const dx = ev.clientX - startX;
            const dy = ev.clientY - startY;

            const rect = surface.getBoundingClientRect();
            const iconW = iconEl.offsetWidth || 92;
            const iconH = iconEl.offsetHeight || 92;

            let nx = baseX + dx;
            let ny = baseY + dy;

            // clamp within surface
            nx = clamp(nx, 6, Math.max(6, rect.width - iconW - 6));
            ny = clamp(ny, 6, Math.max(6, rect.height - iconH - 6));

            const snapped = snapToGrid(nx, ny);

            iconEl.style.left = `${snapped.x}px`;
            iconEl.style.top = `${snapped.y}px`;

            if (!desktopLayout) loadDesktopLayout();
            desktopLayout.items[key] = snapped;

        };

        const onUp = (ev) => {
            if (!dragging) return;
            dragging = false;
            iconEl.releasePointerCapture(ev.pointerId);
            saveDesktopLayout();
        };

        iconEl.addEventListener("pointerdown", (ev) => {
            // Only left click / primary
            if (ev.button !== 0) return;

            // Don’t start drag on double-click (browser will send second click quickly)
            setSelectedIcon(key);

            dragging = true;
            iconEl.setPointerCapture(ev.pointerId);

            const left = parseFloat(iconEl.style.left || "0") || 0;
            const top = parseFloat(iconEl.style.top || "0") || 0;

            startX = ev.clientX;
            startY = ev.clientY;
            baseX = left;
            baseY = top;

            ev.preventDefault();
        });

        iconEl.addEventListener("pointermove", onMove);
        iconEl.addEventListener("pointerup", onUp);
        iconEl.addEventListener("pointercancel", onUp);
    }

    async function renderDesktopIcons() {
        const surface = getDesktopSurface();
        if (!surface) return;

        // Only render on home view
        if (currentView !== "home") return;

        surface.innerHTML = "";
        if (!authed) return;
        bindDesktopSurfaceOnce();

        // We show installed apps as icons
        const apps = installedApps.slice();

        loadDesktopLayout();
        ensureDefaultLayout(surface, apps);

        for (const app of apps) {
            const key = layoutKeyFor(app);
            const pos = (desktopLayout && desktopLayout.items && desktopLayout.items[key]) || { x: 16, y: 16 };

            const el = document.createElement("div");
            el.className = "desktopIcon";
            el.dataset.key = key;
            el.style.left = `${pos.x}px`;
            el.style.top = `${pos.y}px`;

            const img = document.createElement("img");
            img.alt = (app.name || app.title || app.id || "App");
            img.draggable = false;

            // load icon from manifest (async)
            const mani = await fetchManifest(app.id, app.ver);
            img.src = resolveIconUrl(app, mani);

            const label = document.createElement("div");
            label.className = "label";
            label.textContent = app.name || app.title || app.id;

            const sub = document.createElement("div");
            sub.className = "sub";
            sub.textContent = app.ver;

            el.appendChild(img);
            el.appendChild(label);
            el.appendChild(sub);

            // single click selects
            el.addEventListener("click", (ev) => {
                ev.preventDefault();
                setSelectedIcon(key);
            });

            // double click opens
            el.addEventListener("dblclick", (ev) => {
                ev.preventDefault();
                openAppById(app.id);
            });

            attachDrag(el, app);

            surface.appendChild(el);
        }

        setSelectedIcon(desktopSelectedKey);
    }
    function renderHome() {
        currentView = "home";
        currentApp = null;

        setActiveNav("nav_home");
        setActiveApp(""); // clears app highlight

        if (wsTitle) wsTitle.textContent = "Home";
        setWsSubtitleSafe("Session, role, and access status");
        if (mainPaneTitle) mainPaneTitle.textContent = "Workspace";

        // remove "embedded app" styling when leaving an app
        if (homeBlurb) {
            const mainPane = homeBlurb.closest(".pane");
            if (mainPane) mainPane.classList.remove("appHost");
            homeBlurb.classList.remove("appHostBlurb");
        }

        if (homeBlurb) {
            show(homeBlurb, true);

            // IMPORTANT: renderApp() overwrote homeBlurb.innerHTML with the iframe.
            // So when returning Home, rebuild the desktop DOM if it’s missing.
            let surface = document.getElementById("desktopSurface");
            if (!surface) {
                homeBlurb.innerHTML = `
                <div id="desktopHint" style="margin-bottom:10px;">
                    Drag icons to arrange your desktop. Double-click an icon to open the app.
                </div>
                <div id="desktopSurface" class="desktopSurface" aria-label="Desktop"></div>
            `;
            } else {
                const hint = document.getElementById("desktopHint");
                if (hint) hint.textContent = "Drag icons to arrange your desktop. Double-click an icon to open the app.";
            }
        }

        // Render desktop icons on Home
        renderDesktopIcons();
    }

    function renderApp(app) {
        // app = {id, ver, name?}
        currentView = `app:${app.id}@${app.ver}`;
        currentApp = { id: app.id, ver: app.ver };

        const appLabel = app.name || app.id;

        setActiveNav(""); // Home not active
        setActiveApp(app.id);

        if (wsTitle) wsTitle.textContent = appLabel;
        if (wsSubtitle) wsSubtitle.textContent = "App (embedded)";
        if (mainPaneTitle) mainPaneTitle.textContent = appLabel;

        if (!homeBlurb) return;

        const mainPane = homeBlurb.closest(".pane");
        if (mainPane) mainPane.classList.add("appHost");
        homeBlurb.classList.add("appHostBlurb");

        homeBlurb.innerHTML = "";

        const frame = document.createElement("iframe");
        frame.className = "appFrame";
        frame.src = `/apps/${encodeURIComponent(app.id)}/${encodeURIComponent(app.ver)}/www/index.html`;

        const frameWrap = document.createElement("div");
        frameWrap.className = "appFrameWrap";
        frameWrap.appendChild(frame);

        homeBlurb.appendChild(frameWrap);
        show(homeBlurb, true);
    }


    function openAppById(appId) {
        const matches = installedApps.filter(x => x.id === appId);
        const a = matches.length ? matches[matches.length - 1] : null;

        if (!a) {
            renderHome();
            return;
        }
        renderApp({ id: a.id, ver: a.ver, name: a.name || a.title });


    }
    async function loadApps() {
        if (!appsList) return;

        try {
            const r = await fetch("/api/v4/apps/list", { credentials: "include", cache: "no-store" });
            const j = await r.json().catch(() => null);
            if (!r.ok || !j || !j.ok) return;

            const installed = Array.isArray(j.installed) ? j.installed : [];

            // server uses: {id, ver, name?, title? ...}
            let usable = installed.filter(x => x && x.id && x.ver);

            // Admin-only apps (UI visibility)
            if (!isAdmin) usable = usable.filter(x => x.id !== "snapshotmgr");

            // stable order: id then ver
            usable.sort((a, b) => {
                const ai = String(a.id || "");
                const bi = String(b.id || "");
                if (ai !== bi) return ai.localeCompare(bi);
                return String(a.ver || "").localeCompare(String(b.ver || ""));
            });

            // include name/title so UI updates when only name changes
            const key = JSON.stringify(usable.map(x => [x.id, x.ver, x.name || x.title || ""]));
            if (key === lastAppsKey) return;
            lastAppsKey = key;

            installedApps = usable;
            // If we're on Home, refresh desktop icons too
            if (currentView === "home") renderDesktopIcons();

            clearAppsList();
            for (const a of usable) {
                const label = a.name || a.title || a.id; // name from manifest.json

                const href = `/apps/${encodeURIComponent(a.id)}/${encodeURIComponent(a.ver)}/www/index.html`;
                addAppNavButton(a.id, label, href);
            }

            // keep current view alive if app still exists and is allowed; otherwise go home
            if (currentApp) {
                if (!isAdmin && currentApp.id === "snapshotmgr") {
                    renderHome();
                } else {
                    const still = installedApps.find(x => x.id === currentApp.id);
                    if (!still) {
                        renderHome();
                    } else {
                        // refresh titles + keep highlight (uses name/title)
                        renderApp({ id: still.id, ver: still.ver, name: still.name || still.title });
                    }
                }
            }
        } catch {
            // ignore
        }
    }


        async function loadMe() {
            authed = false;
            isAdmin = false;
            show(stateDisabled, false);
            show(stateUnauth, false);

            try {
                const r = await fetch("/api/v4/me", { credentials: "include", cache: "no-store" });
                const ct = (r.headers.get("content-type") || "").toLowerCase();
                const txt = await r.text();

                let j = null;
                try { j = JSON.parse(txt); } catch {}

                if (j) {
                    if (out) out.textContent = JSON.stringify(j, null, 2);
                    meFpHex = String(j.fingerprint_hex || "");

                    const role = j.role || "?";
                    const ok = !!j.ok;
                    authed = ok && r.ok;

                    // show version once (don’t stomp useful status text every refresh)
                    if (!versionShown && statusLine) {
                        statusLine.textContent = "PQ-NAS v1.0";
                        versionShown = true;
                    }

                    isAdmin = ok && role === "admin";

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
                            setWsSubtitleSafe("Waiting for admin approval");
                            setBadge("warn", "waiting for admin");
                            show(stateDisabled, true);
                        } else if (r.status === 401 || err.includes("unauthorized") || msg.toLowerCase().includes("unauthorized")) {
                            setWsSubtitleSafe("Not signed in");
                            setBadge("warn", "not signed in");
                            show(stateUnauth, true);
                            show(navLogin, true);
                        } else {
                            setWsSubtitleSafe(`Error (${r.status || "?"})`);
                            setBadge("err", "error");
                        }
                        return;
                    }

                    const st = String(j.storage_state || "unallocated");
                    setBadge("ok", "");
                    setWsSubtitleSafe(`Signed in · ${role} · storage: ${st}`);

                    // Update installed apps list (only when signed in ok)
                    // NOTE: don't await; keep UI snappy and avoid blocking auth render
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

                setWsSubtitleSafe("Unexpected response from /api/v4/me");
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

                setWsSubtitleSafe("Network error");
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
