(() => {
    "use strict";

    const STORAGE_KEY = "pqnas_neonwave_playlists_v1";

    const el = (id) => document.getElementById(id);

    const nameInput = el("playlistName");
    const saveBtn = el("playlistSaveBtn");
    const listEl = el("playlistList");

    if (!listEl) return;

    function api() {
        return window.NEONWAVE_APP_API || null;
    }

    function status(msg) {
        const s = el("statusLine");
        if (s) s.textContent = msg;
    }

    function makeId() {
        return "pl_" + Date.now().toString(36) + "_" + Math.random().toString(36).slice(2, 8);
    }

    function cleanTrack(t) {
        const path = String(t && t.path ? t.path : "").trim();
        if (!path) return null;

        return {
            name: String(t.name || path.split("/").pop() || path),
            path,
            cover: String(t.cover || "")
        };
    }

    function loadPlaylists() {
        try {
            const raw = localStorage.getItem(STORAGE_KEY);
            if (!raw) return [];

            const arr = JSON.parse(raw);
            if (!Array.isArray(arr)) return [];

            return arr.map((pl) => {
                const tracks = Array.isArray(pl.tracks)
                    ? pl.tracks.map(cleanTrack).filter(Boolean)
                    : [];

                return {
                    id: String(pl.id || makeId()),
                    name: String(pl.name || "Untitled playlist"),
                    created_at: Number(pl.created_at || Date.now()),
                    tracks
                };
            }).filter((pl) => pl.tracks.length);
        } catch {
            return [];
        }
    }

    function savePlaylists(arr) {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(arr));
    }

    function formatDate(ts) {
        try {
            return new Date(ts).toLocaleDateString(undefined, {
                year: "numeric",
                month: "short",
                day: "numeric"
            });
        } catch {
            return "";
        }
    }

    function renderPlaylists() {
        const playlists = loadPlaylists();

        listEl.innerHTML = "";

        if (!playlists.length) {
            const empty = document.createElement("div");
            empty.className = "empty playlistEmpty";
            empty.textContent = "No saved playlists yet.";
            listEl.appendChild(empty);
            return;
        }

        for (const pl of playlists) {
            const row = document.createElement("div");
            row.className = "playlistItem";

            const left = document.createElement("div");
            left.className = "playlistInfo";

            const title = document.createElement("div");
            title.className = "playlistName";
            title.textContent = pl.name;

            const meta = document.createElement("div");
            meta.className = "playlistMeta";
            meta.textContent = `${pl.tracks.length} track${pl.tracks.length === 1 ? "" : "s"} · ${formatDate(pl.created_at)}`;

            left.appendChild(title);
            left.appendChild(meta);

            const actions = document.createElement("div");
            actions.className = "playlistActions";

            const play = document.createElement("button");
            play.className = "pillBtn small";
            play.type = "button";
            play.textContent = "Play";
            play.addEventListener("click", () => {
                const a = api();
                if (!a || typeof a.setQueue !== "function") {
                    status("Playlist API not ready. Reload NeonWave.");
                    return;
                }

                a.setQueue(pl.tracks, true);
                status(`Playing playlist: ${pl.name}`);
            });

            const add = document.createElement("button");
            add.className = "pillBtn small";
            add.type = "button";
            add.textContent = "Add";
            add.addEventListener("click", () => {
                const a = api();
                if (!a || typeof a.addToQueueMany !== "function") {
                    status("Playlist API not ready. Reload NeonWave.");
                    return;
                }

                a.addToQueueMany(pl.tracks, false);
                status(`Added playlist to queue: ${pl.name}`);
            });

            const del = document.createElement("button");
            del.className = "pillBtn small dangerMini";
            del.type = "button";
            del.textContent = "Delete";
            del.addEventListener("click", () => {
                if (!confirm(`Delete playlist "${pl.name}"?`)) return;

                const next = loadPlaylists().filter((x) => x.id !== pl.id);
                savePlaylists(next);
                renderPlaylists();
                status(`Deleted playlist: ${pl.name}`);
            });

            actions.appendChild(play);
            actions.appendChild(add);
            actions.appendChild(del);

            row.appendChild(left);
            row.appendChild(actions);
            listEl.appendChild(row);
        }
    }

    saveBtn?.addEventListener("click", () => {
        const a = api();
        if (!a || typeof a.getQueue !== "function") {
            status("Playlist API not ready. Reload NeonWave.");
            return;
        }

        const queue = a.getQueue().map(cleanTrack).filter(Boolean);
        if (!queue.length) {
            status("Queue is empty. Add or play tracks before saving a playlist.");
            return;
        }

        const fallbackName = `Playlist ${new Date().toLocaleDateString()}`;
        const name = String(nameInput?.value || "").trim() || fallbackName;

        const playlists = loadPlaylists();
        playlists.unshift({
            id: makeId(),
            name,
            created_at: Date.now(),
            tracks: queue
        });

        savePlaylists(playlists.slice(0, 100));

        if (nameInput) nameInput.value = "";
        renderPlaylists();
        status(`Saved playlist: ${name}`);
    });

    renderPlaylists();
})();
