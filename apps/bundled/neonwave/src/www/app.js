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
        coverByDir: Object.create(null),
        coverCheckedDirs: new Set()
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
    
        if (changed) renderList();
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

                actions.appendChild(play);
                actions.appendChild(queue);
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

    function playQueueIndex(idx) {
        if (idx < 0 || idx >= state.queue.length) return;

        state.currentIndex = idx;
        const t = state.queue[idx];

        nowTitle.textContent = t.name;
        nowSub.textContent = t.path;
        setCoverNode(nowCover, t.cover || coverForDir(parentPath(t.path)), "♪");

        state.sourceCandidates = audioUrlCandidates(t.path);
        state.sourceIndex = 0;
        audio.src = state.sourceCandidates[state.sourceIndex];
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

    audio.addEventListener("ended", () => {
        if (state.currentIndex + 1 < state.queue.length) {
            playQueueIndex(state.currentIndex + 1);
        }
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

    renderQueue();
    loadPath("/");
})();
