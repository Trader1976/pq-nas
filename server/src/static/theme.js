(() => {
    const THEMES = new Set(["dark", "bright", "cpunk_orange"]);
    const KEY = "pqnas_theme";

    function normalizeTheme(t) {
        t = String(t || "").trim();
        if (THEMES.has(t)) return t;
        return "dark";
    }

    function applyTheme(t) {
        const theme = normalizeTheme(t);
        document.documentElement.setAttribute("data-theme", theme);
        try { localStorage.setItem(KEY, theme); } catch (_) {}
        return theme;
    }

    async function fetchThemeFromServer() {
        // This endpoint requires admin cookie; for non-admin pages it may 401/403.
        // We silently ignore failures and use localStorage/default.
        try {
            const r = await fetch("/api/v4/admin/settings", { cache: "no-store" });
            if (!r.ok) return null;
            const text = await r.text().catch(() => "");
            let j = null;
            try { j = text ? JSON.parse(text) : null; } catch (_) {}
            if (!j || j.ok !== true) return null;
            if (!j.ui_theme) return null;
            return normalizeTheme(j.ui_theme);
        } catch (_) {
            return null;
        }
    }

    function loadLocal() {
        try { return normalizeTheme(localStorage.getItem(KEY)); } catch (_) { return "dark"; }
    }

    // Expose for admin_settings.js to apply instantly after saving.
    window.pqnasSetTheme = (t) => applyTheme(t);

    // 1) Apply local immediately (fast)
    applyTheme(loadLocal());

    // 2) Then try server (authoritative for admin pages)
    fetchThemeFromServer().then((serverTheme) => {
        if (serverTheme) applyTheme(serverTheme);
    });

    // 3) Cross-tab sync
    window.addEventListener("storage", (e) => {
        if (e && e.key === KEY) applyTheme(e.newValue);
    });
})();
