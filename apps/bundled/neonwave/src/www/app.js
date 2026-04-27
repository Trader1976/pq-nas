(() => {
    "use strict";

    const AUDIO_EXTS = new Set([
        "mp3", "wav", "flac", "m4a", "aac", "ogg", "oga", "opus",
        "aif", "aiff", "alac", "wma"
    ]);

    const IMAGE_EXTS = new Set(["jpg", "jpeg", "png", "webp"]);

    const COVER_FILE_NAMES = [
        "cover.jpg", "cover.jpeg", "cover.png", "cover.webp",
        "folder.jpg", "folder.jpeg", "folder.png", "folder.webp",
        "front.jpg", "front.jpeg", "front.png", "front.webp",
        "album.jpg", "album.jpeg", "album.png", "album.webp",
        "artwork.jpg", "artwork.jpeg", "artwork.png", "artwork.webp",
        "albumart.jpg", "albumart.jpeg", "albumart.png", "albumart.webp",
        "album_art.jpg", "album_art.jpeg", "album_art.png", "album_art.webp"
    ];
    const EQ_STORAGE_KEY = "pqnas_neonwave_eq_v1";
    const PLAYLIST_STORAGE_KEY = "pqnas_neonwave_playlists_v1";
    const VIZ_STORAGE_KEY = "pqnas_neonwave_viz_v1";

    const EQ_BANDS = [
        { label: "60", freq: 60, type: "lowshelf", q: 0.8 },
        { label: "170", freq: 170, type: "peaking", q: 1.0 },
        { label: "350", freq: 350, type: "peaking", q: 1.0 },
        { label: "1k", freq: 1000, type: "peaking", q: 1.0 },
        { label: "3.5k", freq: 3500, type: "peaking", q: 1.0 },
        { label: "10k", freq: 10000, type: "highshelf", q: 0.8 }
    ];

    const EQ_PRESETS = {
        Flat: [0, 0, 0, 0, 0, 0],
        Rock: [5, 3, -2, -1, 3, 5],
        Metal: [4, 2, 0, 2, 4, 6],
        Bass: [7, 5, 2, 0, -1, -2],
        Vocal: [-2, -1, 1, 4, 3, -1],
        Night: [-4, -3, -2, -1, -2, -5]
    };
    const COVER_NAME_RANK = new Map(COVER_FILE_NAMES.map((name, idx) => [name, idx]));

    const state = {
        path: "/",
        mode: "folder",
        items: [],
        scannedTracks: [],
        queue: [],
        currentIndex: -1,
        sourceCandidates: [],
        sourceIndex: 0,
        scanning: false,
        repeatMode: "off",
        shuffle: false,
        playlists: [],
        activePlaylistId: "",
        coverByDir: Object.create(null),
        coverCheckedDirs: new Set(),
        eq: {
            ctx: null,
            source: null,
            filters: [],
            values: null,
            enabled: true
        },
        viz: {
            analyser: null,
            freqData: null,
            timeData: null,
            raf: 0,
            style: "bars"
        }
    };

    const el = (id) => document.getElementById(id);

    const listEl = el("list");
    const pathLine = el("pathLine");
    const statusLine = el("statusLine");
    const refreshBtn = el("refreshBtn");
    const upBtn = el("upBtn");
    const scanBtn = el("scanBtn");
    const musicFolderBtn = el("musicFolderBtn");
    const audioOnlyToggle = el("audioOnlyToggle");

    const audio = el("audio");
    const nowCover = el("nowCover");
    const nowTitle = el("nowTitle");
    const nowSub = el("nowSub");
    const queueList = el("queueList");
    const clearQueueBtn = el("clearQueueBtn");
    const prevBtn = el("prevBtn");
    const nextBtn = el("nextBtn");
    const shuffleToggle = el("shuffleToggle");
    const repeatBtn = el("repeatBtn");
    const playlistSelect = el("playlistSelect");
    const playlistNameInput = el("playlistNameInput");
    const playlistNewBtn = el("playlistNewBtn");
    const playlistSaveQueueBtn = el("playlistSaveQueueBtn");
    const playlistLoadBtn = el("playlistLoadBtn");
    const playlistDeleteBtn = el("playlistDeleteBtn");
    const playlistStatus = el("playlistStatus");
    const eqEnabled = el("eqEnabled");
    const eqPreset = el("eqPreset");
    const eqGrid = el("eqGrid");
    const eqResetBtn = el("eqResetBtn");
    const vizStyle = el("vizStyle");
    const vizCanvas = el("vizCanvas");

    function esc(s) {
        return String(s ?? "").replace(/[&<>"']/g, (c) => ({
            "&": "&amp;",
            "<": "&lt;",
            ">": "&gt;",
            '"': "&quot;",
            "'": "&#39;"
        }[c]));
    }

    function setStatus(msg) {
        statusLine.textContent = msg;
    }

    function normPath(p) {
        p = String(p || "/").trim();
        if (!p) return "/";
        if (!p.startsWith("/")) p = "/" + p;
        p = p.replace(/\/+/g, "/");
        return p || "/";
    }

    function apiPath(p) {
        p = normPath(p);
        if (p === "/") return "";
        return p.replace(/^\/+/, "");
    }

    function parentPath(p) {
        p = normPath(p);
        if (p === "/") return "/";
        const x = p.replace(/\/+$/, "");
        const idx = x.lastIndexOf("/");
        return idx <= 0 ? "/" : x.slice(0, idx);
    }

    function childPath(base, name) {
        base = normPath(base);
        name = String(name || "").replace(/^\/+/, "");
        if (base === "/") return "/" + name;
        return base.replace(/\/+$/, "") + "/" + name;
    }

    function extOf(name) {
        const s = String(name || "");
        const i = s.lastIndexOf(".");
        return i >= 0 ? s.slice(i + 1).toLowerCase() : "";
    }

    function isDir(it) {
        const t = String(it?.type || it?.kind || "").toLowerCase();
        return t === "dir" || t === "folder" || it?.is_dir === true || it?.directory === true;
    }

    function itemName(it) {
        return String(it?.name || it?.filename || it?.base || "");
    }

    function resolveItemPath(base, it) {
        const raw = it?.path || it?.full_path || it?.relpath;
        const name = itemName(it);

        if (!raw) return childPath(base, name);

        const r = String(raw).trim();
        if (!r) return childPath(base, name);

        // Absolute app/user path from server.
        if (r.startsWith("/")) return normPath(r);

        // Some APIs return root-relative paths without leading slash:
        // "Music/Album/Front.jpg"
        const clean = r.replace(/^\/+/, "");
        const baseClean = apiPath(base);

        if (baseClean && (clean === baseClean || clean.startsWith(baseClean + "/"))) {
            return normPath(clean);
        }

        // Some APIs return only the entry name:
        // "Front.jpg", "01 Track.mp3"
        return childPath(base, clean);
    }

    function itemPath(it) {
        return resolveItemPath(state.path, it);
    }

    function isAudioItem(it) {
        if (isDir(it)) return false;
        return AUDIO_EXTS.has(extOf(itemName(it) || itemPath(it)));
    }

    function itemPathFromBase(base, it) {
        return resolveItemPath(base, it);
    }

    function isImageItem(it) {
        if (isDir(it)) return false;
        return IMAGE_EXTS.has(extOf(itemName(it) || itemPath(it)));
    }

    function fileMediaUrl(path, endpoint = "download") {
        const p = encodeURIComponent(apiPath(path));
        return `/api/v4/files/${endpoint}?path=${p}`;
    }

    function coverForDir(dirPath) {
        return state.coverByDir[normPath(dirPath)] || "";
    }

    function setCoverNode(node, coverPath, fallbackText) {
        node.classList.remove("hasCover");
        node.replaceChildren();

        if (!coverPath) {
            node.textContent = fallbackText;
            return;
        }

        // Important:
        // /api/v4/files/download and /api/v4/files/raw can return 404 for normal user files.
        // /api/v4/files/get is the same endpoint that already works for audio playback.
        const urls = [
            fileMediaUrl(coverPath, "get"),
            fileMediaUrl(coverPath, "download"),
            fileMediaUrl(coverPath, "raw")
        ];

        let idx = 0;

        const img = document.createElement("img");
        img.alt = "";
        img.loading = "lazy";
        img.decoding = "async";

        img.addEventListener("error", () => {
            idx++;
            if (idx < urls.length) {
                img.src = urls[idx];
                return;
            }

            node.replaceChildren();
            node.textContent = fallbackText;
            node.classList.remove("hasCover");
        });

        img.addEventListener("load", () => {
            node.classList.add("hasCover");
        });

        node.classList.add("hasCover");
        node.appendChild(img);
        img.src = urls[idx];
    }

    function rememberCoverFromItems(dirPath, items) {
        const dir = normPath(dirPath);
        state.coverCheckedDirs.add(dir);

        let best = "";
        let bestRank = Number.POSITIVE_INFINITY;
        let firstImage = "";

        for (const it of items || []) {
            if (!isImageItem(it)) continue;

            const name = itemName(it);
            const lower = name.toLowerCase();
            const p = itemPathFromBase(dir, it);

            if (!firstImage) firstImage = p;

            if (COVER_NAME_RANK.has(lower)) {
                const rank = COVER_NAME_RANK.get(lower);
                if (rank < bestRank) {
                    bestRank = rank;
                    best = p;
                }
            }
        }

        const cover = best || firstImage;
        if (cover) state.coverByDir[dir] = cover;
        return cover;
    }

    async function prefetchVisibleFolderCovers() {
        if (state.mode !== "folder") return;

        const basePath = state.path;
        const rows = filteredFolderItems()
            .filter((it) => isDir(it))
            .map((it) => itemPath(it))
            .slice(0, 40);

        let changed = false;

        for (const dir of rows) {
            const cleanDir = normPath(dir);
            if (state.coverCheckedDirs.has(cleanDir)) continue;

            try {
                const j = await fetchJson(`/api/v4/files/list?path=${encodeURIComponent(apiPath(cleanDir))}`);
                const cover = rememberCoverFromItems(cleanDir, extractItems(j));
                if (cover) changed = true;
            } catch {
                state.coverCheckedDirs.add(cleanDir);
            }
        }

        if (changed && state.mode === "folder" && state.path === basePath) {
            renderList();
        }
    }
    function fileSizeText(n) {
        n = Number(n);
        if (!Number.isFinite(n) || n < 0) return "";
        const units = ["B", "KB", "MB", "GB", "TB"];
        let u = 0;
        while (n >= 1024 && u < units.length - 1) {
            n /= 1024;
            u++;
        }
        return `${n.toFixed(u === 0 ? 0 : 1)} ${units[u]}`;
    }

    async function fetchJson(url) {
        const r = await fetch(url, {
            credentials: "include",
            cache: "no-store",
            headers: { "Accept": "application/json" }
        });

        const txt = await r.text();
        let j = null;
        try {
            j = txt ? JSON.parse(txt) : null;
        } catch {
            j = null;
        }

        if (!r.ok || !j) {
            const msg = j && (j.message || j.error)
                ? `${j.error || ""} ${j.message || ""}`.trim()
                : `HTTP ${r.status}`;
            throw new Error(msg);
        }

        if (j.ok === false) {
            throw new Error(j.message || j.error || "request failed");
        }

        return j;
    }

    function extractItems(j) {
        if (Array.isArray(j.items)) return j.items;
        if (Array.isArray(j.entries)) return j.entries;
        if (Array.isArray(j.files)) return j.files;
        return [];
    }

    async function loadPath(path) {
        state.mode = "folder";
        state.path = normPath(path);
        pathLine.textContent = state.path;
        setStatus("Loading music library…");
        listEl.innerHTML = "";

        try {
            const j = await fetchJson(`/api/v4/files/list?path=${encodeURIComponent(apiPath(state.path))}`);
            state.items = extractItems(j);
            rememberCoverFromItems(state.path, state.items);
            renderList();
            setStatus("Ready.");
            prefetchVisibleFolderCovers().catch(() => {});
        } catch (e) {
            state.items = [];
            renderList();
            setStatus(`Load failed: ${String(e && e.message ? e.message : e)}`);
        }
    }

    function filteredFolderItems() {
        const audioOnly = !!audioOnlyToggle.checked;
        return state.items.filter((it) => {
            if (isDir(it)) return true;
            if (!audioOnly) return true;
            return isAudioItem(it);
        });
    }

    function renderList() {
        if (state.mode === "folder") rememberCoverFromItems(state.path, state.items);

        pathLine.textContent = state.mode === "scan"
            ? `Scan: ${state.path}`
            : state.path;

        const rows = state.mode === "scan"
            ? state.scannedTracks.map((t) => ({ ...t, __scanTrack: true }))
            : filteredFolderItems();

        listEl.innerHTML = "";

        if (!rows.length) {
            listEl.innerHTML = `<div class="empty">${
                state.mode === "scan"
                    ? "No audio files found."
                    : "No items to show."
            }</div>`;
            return;
        }

        for (const it of rows) {
            const dir = isDir(it);
            const audioFile = it.__scanTrack || isAudioItem(it);
            const name = it.__scanTrack ? it.name : itemName(it);
            const path = it.__scanTrack ? it.path : itemPath(it);
            const size = fileSizeText(it.size || it.size_bytes || it.bytes);
            const imageFile = !dir && isImageItem(it);
            const coverPath = it.__scanTrack
                ? (it.cover || "")
                : (
                    dir
                        ? coverForDir(path)
                        : (
                            audioFile
                                ? coverForDir(parentPath(path))
                                : (imageFile ? path : "")
                        )
                );

            const row = document.createElement("div");
            row.className = "item";
            row.dataset.path = path || "";
            row.dataset.name = name || "";
            row.dataset.kind = audioFile ? "audio" : (dir ? "folder" : (imageFile ? "image" : "file"));
            if (audioFile) {
                row.dataset.nwAudio = "1";
                row.dataset.nwName = name || "";
                row.dataset.nwPath = path || "";
                row.dataset.nwCover = coverPath || "";
            }
            const icon = document.createElement("div");
            icon.className = "itemIcon";
            setCoverNode(icon, coverPath, dir ? "📁" : (audioFile ? "♪" : (imageFile ? "▣" : "·")));

            const mid = document.createElement("div");
            mid.innerHTML = `
                <div class="itemName">${esc(name || path)}</div>
                <div class="itemMeta">${esc(dir ? "folder" : (audioFile ? "audio" : (imageFile ? "cover image" : "file")))}${size ? " · " + esc(size) : ""}${it.__scanTrack ? " · " + esc(path) : ""}</div>
            `;

            const actions = document.createElement("div");
            actions.className = "itemActions";

            if (dir) {
                const open = document.createElement("button");
                open.className = "pillBtn small";
                open.type = "button";
                open.textContent = "Open";
                open.addEventListener("click", () => loadPath(path));
                actions.appendChild(open);
            } else if (audioFile) {
                const play = document.createElement("button");
                play.className = "pillBtn small";
                play.type = "button";
                play.textContent = "Play";
                play.addEventListener("click", () => playTrack({ name, path, cover: coverPath }));

                const queue = document.createElement("button");
                queue.className = "pillBtn small";
                queue.type = "button";
                queue.textContent = "Queue";
                queue.addEventListener("click", () => addToQueue({ name, path, cover: coverPath }));

                const playlist = document.createElement("button");
                playlist.className = "pillBtn small";
                playlist.type = "button";
                playlist.textContent = "Playlist";
                playlist.title = "Add to selected playlist";
                playlist.addEventListener("click", () => addToSelectedPlaylist({ name, path, cover: coverPath }));

                actions.appendChild(play);
                actions.appendChild(queue);
                actions.appendChild(playlist);
            }

            row.appendChild(icon);
            row.appendChild(mid);
            row.appendChild(actions);
            listEl.appendChild(row);
        }
    
        if (state.mode === "folder") {
            window.setTimeout(() => {
                prefetchVisibleFolderCovers().catch(() => {});
            }, 0);
        }
        if (window.PQNAS_NEONWAVE_FAVORITES &&
            typeof window.PQNAS_NEONWAVE_FAVORITES.decorate === "function") {
            window.PQNAS_NEONWAVE_FAVORITES.decorate();
        }
}


    function setPlaylistStatus(msg) {
        if (playlistStatus) playlistStatus.textContent = msg;
    }

    function makePlaylistId() {
        return "pl_" + Date.now().toString(36) + "_" + Math.random().toString(36).slice(2, 8);
    }

    function cleanTrackForPlaylist(track) {
        const cleanPath = normPath(track?.path || "");
        return {
            name: String(track?.name || cleanPath.split("/").pop() || "Track"),
            path: cleanPath,
            cover: track?.cover || coverForDir(parentPath(cleanPath)) || ""
        };
    }

    function loadPlaylistsFromStorage() {
        state.playlists = [];
        state.activePlaylistId = "";

        try {
            const raw = localStorage.getItem(PLAYLIST_STORAGE_KEY);
            if (!raw) return;

            const j = JSON.parse(raw);
            const lists = Array.isArray(j.playlists) ? j.playlists : [];

            state.playlists = lists
                .filter((p) => p && typeof p.name === "string")
                .map((p) => ({
                    id: String(p.id || makePlaylistId()),
                    name: String(p.name || "Playlist").slice(0, 80),
                    tracks: Array.isArray(p.tracks)
                        ? p.tracks
                            .filter((t) => t && t.path)
                            .map(cleanTrackForPlaylist)
                        : []
                }));

            state.activePlaylistId = String(j.activePlaylistId || "");
        } catch {
            state.playlists = [];
            state.activePlaylistId = "";
        }
    }

    function savePlaylistsToStorage() {
        try {
            localStorage.setItem(PLAYLIST_STORAGE_KEY, JSON.stringify({
                activePlaylistId: state.activePlaylistId || "",
                playlists: state.playlists || []
            }));
        } catch {
            setPlaylistStatus("Could not save playlists. Browser storage may be full or blocked.");
        }
    }

    function selectedPlaylist() {
        const id = playlistSelect ? playlistSelect.value : state.activePlaylistId;
        return (state.playlists || []).find((p) => p.id === id) || null;
    }

    function renderPlaylists() {
        if (!playlistSelect) return;

        playlistSelect.innerHTML = "";

        if (!state.playlists.length) {
            const opt = document.createElement("option");
            opt.value = "";
            opt.textContent = "(no playlists)";
            playlistSelect.appendChild(opt);
            state.activePlaylistId = "";
            if (playlistNameInput) playlistNameInput.value = "";
            setPlaylistStatus("Create a playlist, then save queue or add tracks.");
            return;
        }

        state.playlists.sort((a, b) => String(a.name).localeCompare(String(b.name)));

        let activeOk = false;
        for (const p of state.playlists) {
            const opt = document.createElement("option");
            opt.value = p.id;
            opt.textContent = `${p.name} (${p.tracks.length})`;
            playlistSelect.appendChild(opt);
            if (p.id === state.activePlaylistId) activeOk = true;
        }

        if (!activeOk) state.activePlaylistId = state.playlists[0].id;
        playlistSelect.value = state.activePlaylistId;

        const p = selectedPlaylist();
        if (playlistNameInput) playlistNameInput.value = p ? p.name : "";
        if (p) setPlaylistStatus(`${p.name}: ${p.tracks.length} track${p.tracks.length === 1 ? "" : "s"}.`);
    }

    function createPlaylist(name) {
        const cleanName = String(name || "").trim().slice(0, 80) || `Playlist ${state.playlists.length + 1}`;
        const p = {
            id: makePlaylistId(),
            name: cleanName,
            tracks: []
        };

        state.playlists.push(p);
        state.activePlaylistId = p.id;
        savePlaylistsToStorage();
        renderPlaylists();
        setPlaylistStatus(`Created playlist: ${cleanName}`);
        return p;
    }

    function saveCurrentQueueToPlaylist() {
        let p = selectedPlaylist();

        const typed = playlistNameInput ? playlistNameInput.value.trim() : "";
        if (!p) {
            p = createPlaylist(typed || "My playlist");
        }

        if (typed) p.name = typed.slice(0, 80);
        p.tracks = state.queue.map(cleanTrackForPlaylist);

        state.activePlaylistId = p.id;
        savePlaylistsToStorage();
        renderPlaylists();
        setPlaylistStatus(`Saved ${p.tracks.length} track${p.tracks.length === 1 ? "" : "s"} to ${p.name}.`);
    }

    function loadSelectedPlaylistToQueue() {
        const p = selectedPlaylist();
        if (!p) {
            setPlaylistStatus("No playlist selected.");
            return;
        }

        state.queue = p.tracks.map(cleanTrackForPlaylist);
        state.currentIndex = -1;
        renderQueue();

        if (state.queue.length) {
            playQueueIndex(0);
        } else {
            setPlaylistStatus(`${p.name} is empty.`);
        }

        setPlaylistStatus(`Loaded ${p.name}: ${p.tracks.length} track${p.tracks.length === 1 ? "" : "s"}.`);
    }

    function deleteSelectedPlaylist() {
        const p = selectedPlaylist();
        if (!p) {
            setPlaylistStatus("No playlist selected.");
            return;
        }

        if (!confirm(`Delete playlist "${p.name}"?`)) return;

        state.playlists = state.playlists.filter((x) => x.id !== p.id);
        state.activePlaylistId = state.playlists[0]?.id || "";
        savePlaylistsToStorage();
        renderPlaylists();
        setPlaylistStatus(`Deleted playlist: ${p.name}`);
    }

    function addToSelectedPlaylist(track) {
        let p = selectedPlaylist();

        if (!p) {
            const name = prompt("Playlist name?", "My playlist");
            if (name === null) return;
            p = createPlaylist(name);
        }

        const clean = cleanTrackForPlaylist(track);

        if (!clean.path || clean.path === "/") {
            setPlaylistStatus("Could not add track: missing path.");
            return;
        }

        const already = p.tracks.some((t) => normPath(t.path) === clean.path);
        if (!already) p.tracks.push(clean);

        state.activePlaylistId = p.id;
        savePlaylistsToStorage();
        renderPlaylists();

        setPlaylistStatus(already
            ? `Already in ${p.name}: ${clean.name}`
            : `Added to ${p.name}: ${clean.name}`);
    }

    function audioUrlCandidates(path) {
        const p = encodeURIComponent(apiPath(path));
        return [
            `/api/v4/files/get?path=${p}`,
            `/api/v4/files/download?path=${p}`,
            `/api/v4/files/raw?path=${p}`
        ];
    }

    function addToQueue(track) {
        const cleanPath = normPath(track.path);
        state.queue.push({
            name: track.name || cleanPath.split("/").pop(),
            path: cleanPath,
            cover: track.cover || coverForDir(parentPath(cleanPath)) || ""
        });
        renderQueue();

        if (state.currentIndex < 0) {
            playQueueIndex(0);
        }
    }

    function playTrack(track) {
        const cleanPath = normPath(track.path);
        const clean = {
            name: track.name || cleanPath.split("/").pop(),
            path: cleanPath,
            cover: track.cover || coverForDir(parentPath(cleanPath)) || ""
        };

        state.queue = [clean];
        renderQueue();
        playQueueIndex(0);
    }
    function clampDb(v) {
        v = Number(v);
        if (!Number.isFinite(v)) return 0;
        return Math.max(-12, Math.min(12, Math.round(v)));
    }

    function dbText(v) {
        v = clampDb(v);
        return `${v > 0 ? "+" : ""}${v} dB`;
    }

    function defaultEqValues() {
        return EQ_BANDS.map(() => 0);
    }

    function loadEqSettings() {
        const out = {
            enabled: true,
            values: defaultEqValues()
        };

        try {
            const raw = localStorage.getItem(EQ_STORAGE_KEY);
            if (!raw) return out;

            const j = JSON.parse(raw);
            if (typeof j.enabled === "boolean") out.enabled = j.enabled;

            if (Array.isArray(j.values) && j.values.length === EQ_BANDS.length) {
                out.values = j.values.map(clampDb);
            }
        } catch {
            // keep defaults
        }

        return out;
    }

    function saveEqSettings() {
        try {
            localStorage.setItem(EQ_STORAGE_KEY, JSON.stringify({
                enabled: eqEnabled ? !!eqEnabled.checked : state.eq.enabled,
                values: state.eq.values || defaultEqValues()
            }));
        } catch {
            // ignore storage failure
        }
    }

    function disconnectNode(node) {
        try {
            if (node) node.disconnect();
        } catch {
            // already disconnected
        }
    }

    function connectEqGraph() {
        if (!state.eq.source || !state.eq.ctx) return;

        disconnectNode(state.eq.source);
        for (const f of state.eq.filters) disconnectNode(f);
        disconnectNode(state.viz.analyser);

        const analyser = state.viz.analyser || state.eq.ctx.createAnalyser();

        state.viz.analyser = analyser;
        analyser.fftSize = 2048;
        analyser.smoothingTimeConstant = 0.84;

        if (!state.viz.freqData || state.viz.freqData.length !== analyser.frequencyBinCount) {
            state.viz.freqData = new Uint8Array(analyser.frequencyBinCount);
        }

        if (!state.viz.timeData || state.viz.timeData.length !== analyser.fftSize) {
            state.viz.timeData = new Uint8Array(analyser.fftSize);
        }

        const enabled = eqEnabled ? !!eqEnabled.checked : state.eq.enabled;
        state.eq.enabled = enabled;

        let tail = state.eq.source;

        if (enabled && state.eq.filters.length) {
            for (const f of state.eq.filters) {
                tail.connect(f);
                tail = f;
            }
        }

        tail.connect(analyser);
        analyser.connect(state.eq.ctx.destination);
    }

    function applyEqValues(values, syncSliders = true) {
        state.eq.values = values.map(clampDb);

        if (state.eq.ctx && state.eq.filters.length) {
            for (let i = 0; i < state.eq.filters.length; i++) {
                const f = state.eq.filters[i];
                const v = state.eq.values[i] || 0;
                f.gain.setTargetAtTime(v, state.eq.ctx.currentTime, 0.015);
            }
        }

        if (syncSliders && eqGrid) {
            eqGrid.querySelectorAll("input[data-eq-index]").forEach((slider) => {
                const idx = Number(slider.dataset.eqIndex);
                const v = state.eq.values[idx] || 0;
                slider.value = String(v);

                const val = slider.parentElement?.querySelector(".eqBandValue");
                if (val) val.textContent = dbText(v);
            });
        }
    }

    function ensureEqGraph() {
        if (!audio) return false;
        if (state.eq.ctx && state.eq.source) return true;

        const AudioCtx = window.AudioContext || window.webkitAudioContext;
        if (!AudioCtx) {
            setStatus("Equalizer is not supported by this browser.");
            return false;
        }

        try {
            const ctx = new AudioCtx();
            const source = ctx.createMediaElementSource(audio);

            const values = state.eq.values || defaultEqValues();
            const filters = EQ_BANDS.map((band, idx) => {
                const f = ctx.createBiquadFilter();
                f.type = band.type;
                f.frequency.value = band.freq;
                f.Q.value = band.q || 1.0;
                f.gain.value = values[idx] || 0;
                return f;
            });

            const analyser = ctx.createAnalyser();
            analyser.fftSize = 2048;
            analyser.smoothingTimeConstant = 0.84;

            state.eq.ctx = ctx;
            state.eq.source = source;
            state.eq.filters = filters;

            state.viz.analyser = analyser;
            state.viz.freqData = new Uint8Array(analyser.frequencyBinCount);
            state.viz.timeData = new Uint8Array(analyser.fftSize);

            connectEqGraph();
            applyEqValues(values, false);
            return true;
        } catch (e) {
            setStatus(`Equalizer failed: ${String(e && e.message ? e.message : e)}`);
            return false;
        }
    }

    async function resumeEqContext() {
        if (!ensureEqGraph()) return;

        if (state.eq.ctx && state.eq.ctx.state === "suspended") {
            try {
                await state.eq.ctx.resume();
            } catch {
                // browser may require another user gesture
            }
        }
    }

    function renderEqControls() {
        if (!eqGrid) return;

        const saved = loadEqSettings();
        state.eq.values = saved.values.slice();
        state.eq.enabled = saved.enabled;

        if (eqEnabled) eqEnabled.checked = saved.enabled;

        if (eqPreset) {
            eqPreset.innerHTML = `<option value="custom">Custom</option>`;
            for (const name of Object.keys(EQ_PRESETS)) {
                const opt = document.createElement("option");
                opt.value = name;
                opt.textContent = name;
                eqPreset.appendChild(opt);
            }
            eqPreset.value = "custom";
        }

        eqGrid.innerHTML = "";

        EQ_BANDS.forEach((band, idx) => {
            const wrap = document.createElement("div");
            wrap.className = "eqBand";

            const label = document.createElement("div");
            label.className = "eqBandLabel";
            label.textContent = band.label;

            const slider = document.createElement("input");
            slider.className = "eqSlider";
            slider.type = "range";
            slider.min = "-12";
            slider.max = "12";
            slider.step = "1";
            slider.value = String(state.eq.values[idx] || 0);
            slider.dataset.eqIndex = String(idx);
            slider.title = `${band.label} Hz`;

            const value = document.createElement("div");
            value.className = "eqBandValue";
            value.textContent = dbText(state.eq.values[idx] || 0);

            slider.addEventListener("input", () => {
                const v = clampDb(slider.value);
                state.eq.values[idx] = v;
                value.textContent = dbText(v);

                if (eqPreset) eqPreset.value = "custom";

                if (state.eq.ctx && state.eq.filters[idx]) {
                    state.eq.filters[idx].gain.setTargetAtTime(v, state.eq.ctx.currentTime, 0.015);
                }

                saveEqSettings();
            });

            wrap.appendChild(label);
            wrap.appendChild(slider);
            wrap.appendChild(value);
            eqGrid.appendChild(wrap);
        });

        applyEqValues(state.eq.values, true);
    }
    function loadVizSettings() {
        try {
            const raw = localStorage.getItem(VIZ_STORAGE_KEY);
            if (!raw) return "bars";

            const j = JSON.parse(raw);
            const style = String(j.style || "bars");

            if (["bars", "wave", "rings", "off"].includes(style)) return style;
        } catch {
            // keep default
        }

        return "bars";
    }

    function saveVizSettings() {
        try {
            localStorage.setItem(VIZ_STORAGE_KEY, JSON.stringify({
                style: state.viz.style || "bars"
            }));
        } catch {
            // ignore storage failure
        }
    }

    function canvasCssColor(name, fallback) {
        try {
            const cs = getComputedStyle(document.documentElement);
            const v = cs.getPropertyValue(name).trim();
            return v || fallback;
        } catch {
            return fallback;
        }
    }

    function prepareVizCanvas() {
        if (!vizCanvas) return null;

        const rect = vizCanvas.getBoundingClientRect();
        const w = Math.max(1, Math.floor(rect.width || 320));
        const h = Math.max(1, Math.floor(rect.height || 132));
        const dpr = Math.max(1, Math.min(2, window.devicePixelRatio || 1));

        const needW = Math.floor(w * dpr);
        const needH = Math.floor(h * dpr);

        if (vizCanvas.width !== needW || vizCanvas.height !== needH) {
            vizCanvas.width = needW;
            vizCanvas.height = needH;
        }

        const ctx = vizCanvas.getContext("2d");
        if (!ctx) return null;

        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

        return { ctx, w, h };
    }

    function clearVisualizerCanvas(text = "Choose a track") {
        const c = prepareVizCanvas();
        if (!c) return;

        const { ctx, w, h } = c;
        const info = canvasCssColor("--info", "#00e5ff");
        const fgDim = canvasCssColor("--fg-dim", "#8aa");

        ctx.clearRect(0, 0, w, h);

        ctx.globalAlpha = 0.22;
        ctx.strokeStyle = info;
        ctx.lineWidth = 1;

        for (let x = 16; x < w; x += 28) {
            ctx.beginPath();
            ctx.moveTo(x, 12);
            ctx.lineTo(x, h - 12);
            ctx.stroke();
        }

        ctx.globalAlpha = 1;
        ctx.fillStyle = fgDim;
        ctx.font = "12px ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace";
        ctx.textAlign = "center";
        ctx.fillText(text, w / 2, h / 2 + 4);
    }

    function drawBars(c, data) {
        const { ctx, w, h } = c;
        const info = canvasCssColor("--info", "#00e5ff");

        ctx.clearRect(0, 0, w, h);

        const bars = 48;
        const gap = 2;
        const barW = Math.max(2, (w - gap * (bars - 1)) / bars);

        ctx.shadowColor = info;
        ctx.shadowBlur = 12;

        for (let i = 0; i < bars; i++) {
            const idx = Math.floor((i / bars) * data.length * 0.72);
            const v = data[idx] / 255;
            const bh = Math.max(3, v * (h - 18));
            const x = i * (barW + gap);
            const y = h - bh - 8;

            const grad = ctx.createLinearGradient(0, y, 0, h);
            grad.addColorStop(0, "rgba(255,255,255,0.92)");
            grad.addColorStop(0.25, info);
            grad.addColorStop(1, "rgba(0,229,255,0.12)");

            ctx.fillStyle = grad;
            ctx.fillRect(x, y, barW, bh);
        }

        ctx.shadowBlur = 0;
    }

    function drawWave(c, data) {
        const { ctx, w, h } = c;
        const info = canvasCssColor("--info", "#00e5ff");

        ctx.clearRect(0, 0, w, h);

        ctx.lineWidth = 2;
        ctx.strokeStyle = info;
        ctx.shadowColor = info;
        ctx.shadowBlur = 14;
        ctx.beginPath();

        for (let i = 0; i < data.length; i++) {
            const x = (i / (data.length - 1)) * w;
            const y = (data[i] / 255) * h;

            if (i === 0) ctx.moveTo(x, y);
            else ctx.lineTo(x, y);
        }

        ctx.stroke();
        ctx.shadowBlur = 0;
    }

    function drawRings(c, data) {
        const { ctx, w, h } = c;
        const info = canvasCssColor("--info", "#00e5ff");

        ctx.clearRect(0, 0, w, h);

        let sum = 0;
        const max = Math.min(120, data.length);

        for (let i = 0; i < max; i++) sum += data[i];

        const bass = max ? sum / max / 255 : 0;
        const cx = w / 2;
        const cy = h / 2;
        const base = Math.min(w, h) * 0.16;
        const pulse = bass * Math.min(w, h) * 0.22;

        ctx.strokeStyle = info;
        ctx.shadowColor = info;
        ctx.shadowBlur = 18;

        for (let i = 0; i < 4; i++) {
            ctx.globalAlpha = Math.max(0.12, 0.56 - i * 0.12);
            ctx.lineWidth = 2;
            ctx.beginPath();
            ctx.arc(cx, cy, base + pulse + i * 17, 0, Math.PI * 2);
            ctx.stroke();
        }

        ctx.globalAlpha = 1;
        ctx.shadowBlur = 0;

        ctx.fillStyle = "rgba(0,229,255,0.12)";
        ctx.beginPath();
        ctx.arc(cx, cy, base * 0.55 + pulse * 0.35, 0, Math.PI * 2);
        ctx.fill();
    }

    function visualizerFrame() {
        state.viz.raf = 0;

        if (!vizCanvas) return;

        const style = state.viz.style || "bars";

        if (style === "off") {
            clearVisualizerCanvas("Visualizer off");
            return;
        }

        if (!state.viz.analyser || !audio || audio.paused || audio.ended) {
            clearVisualizerCanvas("Waiting for audio");
            return;
        }

        const c = prepareVizCanvas();
        if (!c) return;

        if (style === "wave") {
            state.viz.analyser.getByteTimeDomainData(state.viz.timeData);
            drawWave(c, state.viz.timeData);
        } else if (style === "rings") {
            state.viz.analyser.getByteFrequencyData(state.viz.freqData);
            drawRings(c, state.viz.freqData);
        } else {
            state.viz.analyser.getByteFrequencyData(state.viz.freqData);
            drawBars(c, state.viz.freqData);
        }

        state.viz.raf = window.requestAnimationFrame(visualizerFrame);
    }

    function startVisualizer() {
        if (!vizCanvas) return;

        if ((state.viz.style || "bars") === "off") {
            stopVisualizer("Visualizer off");
            return;
        }

        ensureEqGraph();

        if (state.viz.raf) return;
        state.viz.raf = window.requestAnimationFrame(visualizerFrame);
    }

    function stopVisualizer(text = "Choose a track") {
        if (state.viz.raf) {
            window.cancelAnimationFrame(state.viz.raf);
            state.viz.raf = 0;
        }

        clearVisualizerCanvas(text);
    }

    function initVisualizerControls() {
        state.viz.style = loadVizSettings();

        if (vizStyle) {
            vizStyle.value = state.viz.style;
            vizStyle.addEventListener("change", () => {
                state.viz.style = vizStyle.value || "bars";
                saveVizSettings();

                if (state.viz.style === "off") {
                    stopVisualizer("Visualizer off");
                } else if (audio && !audio.paused && !audio.ended) {
                    startVisualizer();
                } else {
                    clearVisualizerCanvas("Choose a track");
                }
            });
        }

        clearVisualizerCanvas(state.viz.style === "off" ? "Visualizer off" : "Choose a track");
    }
    function playQueueIndex(idx) {
        if (idx < 0 || idx >= state.queue.length) return;

        state.currentIndex = idx;
        const t = state.queue[idx];

        try {
            window.dispatchEvent(new CustomEvent("neonwave:trackchange", {
                detail: {
                    name: t.name || String(t.path || "").split("/").pop() || "Track",
                    path: t.path || "",
                    cover: t.cover || coverForDir(parentPath(t.path || "/")) || ""
                }
            }));
        } catch {
            // History/extension hooks are best-effort only.
        }

        nowTitle.textContent = t.name;
        nowSub.textContent = t.path;
        setCoverNode(nowCover, t.cover || coverForDir(parentPath(t.path)), "♪");

        state.sourceCandidates = audioUrlCandidates(t.path);
        state.sourceIndex = 0;

        ensureEqGraph();
        resumeEqContext();

        audio.src = state.sourceCandidates[state.sourceIndex];
        startVisualizer();
        audio.play().catch(() => {
            setStatus("Click play in the browser audio controls to start playback.");
        });

        renderQueue();
    }

    function renderQueue() {
        queueList.innerHTML = "";

        if (!state.queue.length) {
            queueList.innerHTML = `<div class="empty">Queue is empty.</div>`;
            return;
        }

        state.queue.forEach((t, idx) => {
            const div = document.createElement("div");
            div.className = `queueItem ${idx === state.currentIndex ? "active" : ""}`;
            div.innerHTML = `
                <div class="queueName">${esc(t.name)}</div>
                <div class="queuePath">${esc(t.path)}</div>
            `;
            div.addEventListener("click", () => playQueueIndex(idx));
            queueList.appendChild(div);
        });
    }

    async function scanAudio(root) {
        if (state.scanning) return;

        state.scanning = true;
        scanBtn.disabled = true;

        const start = normPath(root || state.path || "/");
        state.mode = "scan";
        state.path = start;
        state.scannedTracks = [];
        pathLine.textContent = `Scan: ${start}`;
        listEl.innerHTML = "";
        setStatus(`Scanning audio under ${start}…`);

        const dirs = [start];
        const seenDirs = new Set([start]);
        let scannedDirs = 0;
        let stopReason = "";

        const MAX_DIRS = 700;
        const MAX_TRACKS = 3000;

        try {
            while (dirs.length) {
                const dir = dirs.shift();
                scannedDirs++;

                if (scannedDirs > MAX_DIRS) {
                    stopReason = `Stopped at ${MAX_DIRS} folders.`;
                    break;
                }

                const j = await fetchJson(`/api/v4/files/list?path=${encodeURIComponent(apiPath(dir))}`);
                const items = extractItems(j);
                const folderCover = rememberCoverFromItems(dir, items);

                for (const it of items) {
                    const p = itemPathFromBase(dir, it);

                    if (isDir(it)) {
                        const childDir = normPath(p);
                        if (!seenDirs.has(childDir)) {
                            seenDirs.add(childDir);
                            dirs.push(childDir);
                        }
                        continue;
                    }

                    if (!isAudioItem(it)) continue;

                    state.scannedTracks.push({
                        name: itemName(it) || p.split("/").pop(),
                        path: p,
                        size: it.size || it.size_bytes || it.bytes || 0,
                        cover: folderCover || coverForDir(parentPath(p)) || ""
                    });

                    if (state.scannedTracks.length >= MAX_TRACKS) {
                        stopReason = `Stopped at ${MAX_TRACKS} audio files.`;
                        dirs.length = 0;
                        break;
                    }
                }

                if (scannedDirs % 15 === 0) {
                    renderList();
                    setStatus(`Scanning… ${scannedDirs} folders, ${state.scannedTracks.length} audio files`);
                    await new Promise((resolve) => setTimeout(resolve, 0));
                }
            }

            renderList();
            setStatus(`Scan ready: ${state.scannedTracks.length} audio files. ${stopReason}`.trim());
        } catch (e) {
            renderList();
            setStatus(`Scan failed: ${String(e && e.message ? e.message : e)}`);
        } finally {
            state.scanning = false;
            scanBtn.disabled = false;
        }
    }

    function randomNextIndex() {
        if (state.queue.length <= 1) return state.currentIndex;
        let next = state.currentIndex;
        for (let guard = 0; guard < 12 && next === state.currentIndex; guard++) {
            next = Math.floor(Math.random() * state.queue.length);
        }
        return next;
    }

    function playPreviousTrack() {
        if (!state.queue.length) return;

        if (audio && audio.currentTime > 4) {
            audio.currentTime = 0;
            return;
        }

        const idx = state.currentIndex > 0
            ? state.currentIndex - 1
            : state.queue.length - 1;

        playQueueIndex(idx);
    }

    function playNextTrack(manual = false) {
        if (!state.queue.length) return;

        if (state.repeatMode === "one" && !manual) {
            audio.currentTime = 0;
            audio.play().catch(() => {});
            return;
        }

        if (state.shuffle) {
            playQueueIndex(randomNextIndex());
            return;
        }

        if (state.currentIndex + 1 < state.queue.length) {
            playQueueIndex(state.currentIndex + 1);
            return;
        }

        if (state.repeatMode === "all") {
            playQueueIndex(0);
        }
    }

    function cycleRepeatMode() {
        const modes = ["off", "all", "one"];
        const cur = modes.indexOf(state.repeatMode);
        state.repeatMode = modes[(cur + 1) % modes.length];

        if (repeatBtn) {
            repeatBtn.dataset.mode = state.repeatMode;
            repeatBtn.textContent = `Repeat: ${state.repeatMode}`;
            repeatBtn.classList.toggle("isActive", state.repeatMode !== "off");
        }
    }

    audio.addEventListener("ended", () => {
        playNextTrack(false);
    });

    prevBtn?.addEventListener("click", playPreviousTrack);

    nextBtn?.addEventListener("click", () => {
        playNextTrack(true);
    });

    shuffleToggle?.addEventListener("change", () => {
        state.shuffle = !!shuffleToggle.checked;
    });

    repeatBtn?.addEventListener("click", cycleRepeatMode);
    renderEqControls();
    initVisualizerControls();

    eqEnabled?.addEventListener("change", () => {
        state.eq.enabled = !!eqEnabled.checked;
        ensureEqGraph();
        connectEqGraph();
        saveEqSettings();
    });

    eqPreset?.addEventListener("change", () => {
        const name = eqPreset.value;
        if (!EQ_PRESETS[name]) return;

        applyEqValues(EQ_PRESETS[name].slice(), true);
        saveEqSettings();
    });

    eqResetBtn?.addEventListener("click", () => {
        if (eqPreset) eqPreset.value = "Flat";
        applyEqValues(EQ_PRESETS.Flat.slice(), true);
        saveEqSettings();
    });

    audio?.addEventListener("play", () => {
        resumeEqContext();
        startVisualizer();
    });
    audio?.addEventListener("pause", () => {
        if (!audio.ended) stopVisualizer("Paused");
    });
    audio.addEventListener("error", () => {
        if (!state.sourceCandidates.length) return;

        if (state.sourceIndex + 1 < state.sourceCandidates.length) {
            state.sourceIndex++;
            audio.src = state.sourceCandidates[state.sourceIndex];
            audio.play().catch(() => {});
            return;
        }

        const t = state.queue[state.currentIndex];
        setStatus(`Playback failed: ${t ? t.path : "unknown file"}`);
    });

    refreshBtn?.addEventListener("click", () => {
        if (state.mode === "scan") scanAudio(state.path);
        else loadPath(state.path);
    });

    upBtn?.addEventListener("click", () => {
        if (state.mode === "scan") {
            state.mode = "folder";
            loadPath(state.path);
            return;
        }
        if (state.path === "/") return;
        loadPath(parentPath(state.path));
    });

    musicFolderBtn?.addEventListener("click", () => {
        loadPath("/Music");
    });

    scanBtn?.addEventListener("click", () => {
        scanAudio(state.path || "/");
    });

    audioOnlyToggle?.addEventListener("change", () => {
        if (state.mode === "folder") renderList();
    });

    clearQueueBtn?.addEventListener("click", () => {
        state.queue = [];
        state.currentIndex = -1;
        audio.pause();
        audio.removeAttribute("src");
        audio.load();
        nowTitle.textContent = "Nothing playing";
        nowSub.textContent = "Choose an audio file";
        renderQueue();
    });


    loadPlaylistsFromStorage();
    renderPlaylists();

    playlistSelect?.addEventListener("change", () => {
        state.activePlaylistId = playlistSelect.value || "";
        const p = selectedPlaylist();
        if (playlistNameInput) playlistNameInput.value = p ? p.name : "";
        savePlaylistsToStorage();
        renderPlaylists();
    });

    playlistNameInput?.addEventListener("change", () => {
        const p = selectedPlaylist();
        if (!p) return;

        const clean = playlistNameInput.value.trim().slice(0, 80);
        if (!clean) {
            playlistNameInput.value = p.name;
            return;
        }

        p.name = clean;
        savePlaylistsToStorage();
        renderPlaylists();
    });

    playlistNewBtn?.addEventListener("click", () => {
        const name = playlistNameInput?.value?.trim() || prompt("Playlist name?", "My playlist");
        if (name === null) return;
        createPlaylist(name);
    });

    playlistSaveQueueBtn?.addEventListener("click", saveCurrentQueueToPlaylist);
    playlistLoadBtn?.addEventListener("click", loadSelectedPlaylistToQueue);
    playlistDeleteBtn?.addEventListener("click", deleteSelectedPlaylist);


    function neonwavePublicTrack(track) {
        const cleanPath = normPath(track && track.path ? track.path : "");
        if (!cleanPath || cleanPath === "/") return null;

        return {
            name: String(track.name || cleanPath.split("/").pop() || cleanPath),
            path: cleanPath,
            cover: String(track.cover || coverForDir(parentPath(cleanPath)) || "")
        };
    }

    window.NEONWAVE_APP_API = {
        getQueue() {
            return state.queue.map(neonwavePublicTrack).filter(Boolean);
        },

        setQueue(tracks, autoplay = true) {
            const clean = Array.isArray(tracks)
                ? tracks.map(neonwavePublicTrack).filter(Boolean)
                : [];

            state.queue = clean;
            state.currentIndex = -1;
            renderQueue();

            if (autoplay && state.queue.length) {
                playQueueIndex(0);
            }
        },

        addToQueueMany(tracks, autoplay = false) {
            const clean = Array.isArray(tracks)
                ? tracks.map(neonwavePublicTrack).filter(Boolean)
                : [];

            if (!clean.length) return;

            const shouldAutoplay = autoplay && state.currentIndex < 0 && state.queue.length === 0;
            state.queue.push(...clean);
            renderQueue();

            if (shouldAutoplay) {
                playQueueIndex(0);
            }
        }
    };

    window.PQNAS_NEONWAVE_APP = {
        scanCurrent() {
            return scanAudio(state.path || "/");
        },
        getCurrentTrack() {
            if (state.currentIndex < 0 || state.currentIndex >= state.queue.length) return null;
            return neonwavePublicTrack(state.queue[state.currentIndex]);
        },
        showFavorites(tracks) {
            state.mode = "scan";
            state.path = "Favorites";
            state.scannedTracks = Array.isArray(tracks)
                ? tracks.map((t) => ({
                    name: t.name || String(t.path || "").split("/").pop() || "Track",
                    path: normPath(t.path || "/"),
                    cover: t.cover || coverForDir(parentPath(t.path || "/")) || ""
                })).filter((t) => t.path && t.path !== "/")
                : [];

            renderList();
            setStatus(`Favorites: ${state.scannedTracks.length} tracks.`);
        },
        scanPath(path) {
            return scanAudio(path || state.path || "/");
        },

        currentPath() {
            return state.path || "/";
        },

        currentMode() {
            return state.mode || "folder";
        },

        loadPath(path) {
            return loadPath(path || "/");
        }
    };

    renderQueue();
    loadPath("/");
})();
