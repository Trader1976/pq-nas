(() => {
    "use strict";

    const STORAGE_KEY = "pqnas_neonwave_favorites_v1";

    const el = (id) => document.getElementById(id);

    let favoritesBtn = null;
    let listEl = null;

    function loadFavorites() {
        try {
            const raw = localStorage.getItem(STORAGE_KEY);
            const arr = raw ? JSON.parse(raw) : [];
            if (!Array.isArray(arr)) return [];
            return arr
                .filter((x) => x && x.path)
                .map((x) => ({
                    name: String(x.name || x.path.split("/").pop() || "Track"),
                    path: String(x.path),
                    cover: String(x.cover || "")
                }));
        } catch {
            return [];
        }
    }

    function saveFavorites(items) {
        try {
            localStorage.setItem(STORAGE_KEY, JSON.stringify(items));
        } catch {
            // Ignore private-mode/storage failures.
        }
    }

    function favMap() {
        const m = new Map();
        for (const f of loadFavorites()) {
            m.set(f.path, f);
        }
        return m;
    }

    function isFavorite(path) {
        return favMap().has(path);
    }

    function setFavorite(track, enabled) {
        const m = favMap();

        if (enabled) {
            m.set(track.path, {
                name: track.name || track.path.split("/").pop() || "Track",
                path: track.path,
                cover: track.cover || ""
            });
        } else {
            m.delete(track.path);
        }

        saveFavorites(Array.from(m.values()));
        updateFavoritesButton();
    }

    function updateFavoritesButton() {
        if (!favoritesBtn) return;
        const n = loadFavorites().length;
        favoritesBtn.textContent = n > 0 ? `Favorites ${n}` : "Favorites";
    }

    function makeStar(track) {
        const btn = document.createElement("button");
        btn.className = "favBtn";
        btn.type = "button";
        btn.title = "Add/remove favorite";

        const paint = () => {
            const on = isFavorite(track.path);
            btn.classList.toggle("active", on);
            btn.textContent = on ? "★" : "☆";
            btn.setAttribute("aria-pressed", on ? "true" : "false");
        };

        btn.addEventListener("click", (ev) => {
            ev.preventDefault();
            ev.stopPropagation();

            setFavorite(track, !isFavorite(track.path));
            paint();

            if (window.PQNAS_NEONWAVE_SEARCH &&
                typeof window.PQNAS_NEONWAVE_SEARCH.apply === "function") {
                window.PQNAS_NEONWAVE_SEARCH.apply();
            }
        });

        paint();
        return btn;
    }

    function decorate() {
        if (!listEl) listEl = el("list");
        if (!listEl) return;

        const rows = Array.from(listEl.children).filter((n) =>
            n && n.classList && n.classList.contains("item")
        );

        for (const row of rows) {
            if (row.dataset.nwFavoriteDecorated === "1") continue;
            if (row.dataset.nwAudio !== "1") continue;

            const path = row.dataset.nwPath || "";
            if (!path) continue;

            const track = {
                name: row.dataset.nwName || path.split("/").pop() || "Track",
                path,
                cover: row.dataset.nwCover || ""
            };

            const actions = row.querySelector(".itemActions");
            if (!actions) continue;

            actions.insertBefore(makeStar(track), actions.firstChild);
            row.dataset.nwFavoriteDecorated = "1";
        }

        updateFavoritesButton();
    }

    function showFavorites() {
        const api = window.PQNAS_NEONWAVE_APP;
        const favs = loadFavorites();

        if (!api || typeof api.showFavorites !== "function") {
            alert("NeonWave is still loading. Try again in a moment.");
            return;
        }

        api.showFavorites(favs);
    }

    function init() {
        favoritesBtn = el("favoritesBtn");
        listEl = el("list");

        favoritesBtn?.addEventListener("click", showFavorites);

        if (listEl) {
            const observer = new MutationObserver(() => decorate());
            observer.observe(listEl, { childList: true });
        }

        updateFavoritesButton();
        decorate();

        window.PQNAS_NEONWAVE_FAVORITES = {
            decorate,
            list: loadFavorites,
            isFavorite,
            setFavorite
        };
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init, { once: true });
    } else {
        init();
    }
})();