(() => {
    "use strict";

    function loadScript(src) {
        return new Promise((resolve, reject) => {
            const s = document.createElement("script");
            s.src = src;
            s.async = true;
            s.onload = () => resolve();
            s.onerror = () => reject(new Error("Failed to load " + src));
            document.head.appendChild(s);
        });
    }

    function normMode(x) {
        x = String(x || "").trim().toLowerCase();
        if (x === "v5" || x === "v4" || x === "auto") return x;
        return "v4";
    }

    async function fetchMode() {
        try {
            const r = await fetch("/api/public/auth_mode", { cache: "no-store" });
            if (!r.ok) return "v4";
            const j = await r.json().catch(() => ({}));
            return normMode(j && j.auth_mode);
        } catch {
            return "v4";
        }
    }

    async function main() {
        const mode = await fetchMode();

        if (mode === "v4") {
            await loadScript("/static/pqnas_v4.js");
            return;
        }

        if (mode === "v5") {
            // v5 not implemented yet: fall back safely if missing
            try {
                await loadScript("/static/pqnas_v5.js");
            } catch {
                await loadScript("/static/pqnas_v4.js");
            }
            return;
        }

        // auto: try v5 first, fallback to v4
        try {
            await loadScript("/static/pqnas_v5.js");
        } catch {
            await loadScript("/static/pqnas_v4.js");
        }
    }

    main().catch((e) => {
        console.error(e);
        // last resort fallback
        loadScript("/static/pqnas_v4.js").catch(() => {});
    });
})();
