(() => {
    "use strict";
    window.PQNAS_PHOTOGALLERY = window.PQNAS_PHOTOGALLERY || {};
    const el = (id) => document.getElementById(id);

    try {
        if (window.self !== window.top) document.body.classList.add("embedded");
    } catch (_) {
        document.body.classList.add("embedded");
    }

    const titleLine = el("titleLine");
    const pathLine = el("pathLine");
    const badge = el("badge");
    const statusEl = el("status");
    const footerStats = el("footerStats");
    const filterInput = el("filterInput");
    const ratingFilter = el("ratingFilter");
    const thumbSizeSelect = el("thumbSizeSelect");
    const refreshBtn = el("refreshBtn");
    const upBtn = el("upBtn");
    const gridEl = el("grid");
    const ctxMenu = el("ctxMenu");

    const gridWrap = el("gridWrap");

    const downloadSelBtn = el("downloadSelBtn");
    const deleteSelBtn = el("deleteSelBtn");
    const clearSelBtn = el("clearSelBtn");
    const selCount = el("selCount");

    const metaModal = el("metaModal");
    const metaClose = el("metaClose");
    const metaPath = el("metaPath");
    const metaStars = el("metaStars");
    const metaTags = el("metaTags");
    const metaNotes = el("metaNotes");
    const metaInfo = el("metaInfo");
    const metaStatus = el("metaStatus");
    const metaSaveBtn = el("metaSaveBtn");
    const metaApplySelWrap = el("metaApplySelWrap");
    const metaApplySelChk = el("metaApplySelChk");
    const metaApplySelText = el("metaApplySelText");

    const previewModal = el("previewModal");
    const previewCard = el("previewCard");
    const previewHead = el("previewHead");
    const previewPath = el("previewPath");
    const previewInfo = el("previewInfo");
    const previewImg = el("previewImg");
    const previewBody = previewCard ? previewCard.querySelector(".previewBody") : null;

    const previewPrevBtn = el("previewPrevBtn");
    const previewNextBtn = el("previewNextBtn");
    const previewFitBtn = el("previewFitBtn");
    const previewActualBtn = el("previewActualBtn");
    const previewMetaBtn = el("previewMetaBtn");
    const previewClose = el("previewClose");
    const previewShareBtn = el("previewShareBtn");
    const previewFullscreenBtn = el("previewFullscreenBtn");

    const metaCard = el("metaCard");
    const metaHead = el("metaHead");

    const gridBtn = el("gridBtn");
    const mapBtn = el("mapBtn");
    const mapWrap = el("mapWrap");
    const mapCanvas = el("mapCanvas");

    const panelEl = document.querySelector(".panel");

    let metaSaveInFlight = false;
    let suppressBrowserSaveUntil = 0;
    let selectedRelPaths = new Set();
    let selectionAnchorRelPath = "";
    let searchSeq = 0;
    let filterTimer = 0;


    const RATING_FILTER_KEY = "pqnas_photogallery_rating_filter_v1";

    const THUMB_SIZE_KEY = "pqnas_photogallery_thumb_size_v1";

    const state = {
        curPath: "",
        items: [],
        filter: "",
        ratingFilter: -1, // -1 = all, 0 = unrated, 1..5 = exact stars
        thumbSize: 160,
        viewMode: "grid",
        editingPath: "",
        editingRating: 0,
        previewPath: "",
        previewMode: "fit",
        previewZoom: 1,
        activeTilePath: "",
        searchItems: [],
        searchBasePath: "",
        searchLoaded: false,
        searchLoading: false,
        treeStats: {
            basePath: "",
            loaded: false,
            loading: false,
            dirs: 0,
            files: 0,
            fileBytes: 0,
            seq: 0
        }
    };

    const dragState = {
        active: false,
        startX: 0,
        startY: 0,
        cardLeft: 0,
        cardTop: 0,
        moved: false
    };

    const metaDragState = {
        active: false,
        startX: 0,
        startY: 0,
        cardLeft: 0,
        cardTop: 0
    };

    const previewPanState = {
        active: false,
        startX: 0,
        startY: 0,
        scrollLeft: 0,
        scrollTop: 0,
        moved: false
    };

    const mapRuntime = {
        leafletPromise: null,
        map: null,
        markersLayer: null,
        tileLayer: null
    };

    function loadRatingFilterPref() {
        try {
            const raw = Number(localStorage.getItem(RATING_FILTER_KEY) || "-1");
            if (raw >= -1 && raw <= 5) {
                state.ratingFilter = raw;
            }
        } catch (_) {
            state.ratingFilter = -1;
        }

        if (ratingFilter) {
            ratingFilter.value = String(state.ratingFilter);
        }
    }

    function saveRatingFilterPref() {
        try {
            localStorage.setItem(RATING_FILTER_KEY, String(state.ratingFilter));
        } catch (_) {}
    }
    function applyThumbSizeUi() {
        const size = Number(state.thumbSize || 160);

        if (gridEl) {
            gridEl.style.setProperty("--pg-tile-min", `${size}px`);
            gridEl.style.setProperty("--pg-thumb-height", `${Math.round(size * 0.82)}px`);
        }

        if (thumbSizeSelect) {
            thumbSizeSelect.value = String(size);
        }
    }


    function loadThumbSizePref() {
        try {
            const raw = Number(localStorage.getItem(THUMB_SIZE_KEY) || "160");
            if ([120, 160, 220, 300].includes(raw)) {
                state.thumbSize = raw;
            } else {
                state.thumbSize = 160;
            }
        } catch (_) {
            state.thumbSize = 160;
        }

        applyThumbSizeUi();
    }

    function saveThumbSizePref() {
        try {
            localStorage.setItem(THUMB_SIZE_KEY, String(state.thumbSize));
        } catch (_) {}
    }
    function setBadge(kind, text) {
        if (!badge) return;
        badge.className = `badge ${kind}`;
        badge.textContent = text;
    }

    function setStatus(text) {
        if (statusEl) statusEl.textContent = String(text || "");
    }

    function joinPath(base, name) {
        if (!base) return String(name || "");
        return `${base}/${name || ""}`;
    }

    function parentPath(p) {
        p = String(p || "");
        if (!p) return "";
        const i = p.lastIndexOf("/");
        return i < 0 ? "" : p.slice(0, i);
    }
    function normalizeRelPath(p) {
        p = String(p || "").replace(/\\/g, "/").trim();
        p = p.replace(/^\/+/, "").replace(/\/+$/, "");

        if (!p) return "";

        const parts = [];
        for (const part of p.split("/")) {
            if (!part || part === ".") continue;
            if (part === "..") {
                if (parts.length) parts.pop();
                continue;
            }
            parts.push(part);
        }

        return parts.join("/");
    }

    function setCurrentPath(nextPath, reason = "") {
        const prev = String(state.curPath || "");
        const norm = normalizeRelPath(nextPath);

        console.debug("[photogallery path]", {
            reason,
            prev,
            next: String(nextPath || ""),
            normalized: norm
        });

        state.curPath = norm;
        return state.curPath;
    }
    function currentRelPathFor(item) {
        if (!item) return "";
        if (item.rel_path) return String(item.rel_path);
        if (item.path) return String(item.path);
        if (item.base_path) return joinPath(String(item.base_path || ""), item.name || "");
        return joinPath(state.curPath, item.name);
    }

    function fmtSize(n) {
        const u = ["B", "KiB", "MiB", "GiB", "TiB"];
        let v = Number(n || 0);
        let i = 0;
        while (v >= 1024 && i < u.length - 1) {
            v /= 1024;
            i++;
        }
        return i === 0 ? `${v | 0} ${u[i]}` : `${v.toFixed(1)} ${u[i]}`;
    }

    function fmtTime(unix) {
        const n = Number(unix || 0);
        if (!Number.isFinite(n) || n <= 0) return "";
        const d = new Date(n * 1000);
        const pad = (x) => String(x).padStart(2, "0");
        return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
    }

    function shorten(s, n) {
        s = String(s || "");
        return s.length <= n ? s : s.slice(0, Math.max(0, n - 1)) + "…";
    }
    function fileExtLower(name) {
        const s = String(name || "");
        const i = s.lastIndexOf(".");
        return i >= 0 ? s.slice(i + 1).toLowerCase() : "";
    }

    function isRawName(name) {
        return [
            "cr2", "cr3", "nef", "arw", "raf", "dng", "rw2", "orf"
        ].includes(fileExtLower(name));
    }

    function renderRawGlyph() {
        const wrap = document.createElement("div");
        wrap.className = "rawGlyph";
        wrap.innerHTML = `
      <div style="
        display:flex;
        flex-direction:column;
        align-items:center;
        justify-content:center;
        gap:8px;
        width:100%;
        height:100%;
        padding:16px;
        text-align:center;
      ">
        <div style="
          font-size:34px;
          font-weight:900;
          opacity:.92;
          letter-spacing:.04em;
        ">RAW</div>
        <div style="
          font-size:12px;
          opacity:.72;
          font-family:var(--mono);
        ">Original camera file</div>
      </div>`;
        return wrap;
    }
    function escapeAttr(s) {
        return String(s || "").replace(/"/g, "&quot;");
    }

    function fileGetUrl(relPath) {
        return `/api/v4/files/get?path=${encodeURIComponent(relPath || "")}`;
    }

    function galleryThumbUrl(relPath, size = 320, mtimeUnix = 0) {
        const qs = new URLSearchParams();
        qs.set("path", relPath || "");
        qs.set("size", String(size));
        if (mtimeUnix) qs.set("v", String(mtimeUnix));
        return `/api/v4/gallery/thumb?${qs.toString()}`;
    }

    function galleryListUrl(relPath) {
        if (!relPath) return "/api/v4/gallery/list";
        return `/api/v4/gallery/list?path=${encodeURIComponent(relPath)}`;
    }

    async function fetchJson(url, opts = {}) {
        const r = await fetch(url, {
            credentials: "include",
            cache: "no-store",
            ...opts
        });
        const j = await r.json().catch(() => null);
        if (!r.ok || !j || !j.ok) {
            const msg = j && (j.message || j.error)
                ? `${j.error || ""} ${j.message || ""}`.trim()
                : `HTTP ${r.status}`;
            throw new Error(msg || `HTTP ${r.status}`);
        }
        return j;
    }

    async function galleryMetaGet(relPath) {
        return fetchJson("/api/v4/gallery/meta/get", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Accept": "application/json"
            },
            body: JSON.stringify({ path: relPath })
        });
    }

    async function galleryMetaSet(relPath, payload) {
        return fetchJson("/api/v4/gallery/meta/set", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Accept": "application/json"
            },
            body: JSON.stringify({
                path: relPath,
                ...payload
            })
        });
    }
    function closeContextMenu() {
        if (!ctxMenu) return;
        ctxMenu.classList.remove("show");
        ctxMenu.setAttribute("aria-hidden", "true");
        ctxMenu.innerHTML = "";
    }

    function clamp(n, lo, hi) {
        return Math.max(lo, Math.min(hi, n));
    }

    function placeContextMenu(x, y) {
        if (!ctxMenu) return;

        ctxMenu.style.left = "0px";
        ctxMenu.style.top = "0px";
        ctxMenu.classList.add("show");

        const rect = ctxMenu.getBoundingClientRect();
        const pad = 8;

        const nx = clamp(x, pad, window.innerWidth - rect.width - pad);
        const ny = clamp(y, pad, window.innerHeight - rect.height - pad);

        ctxMenu.style.left = `${nx}px`;
        ctxMenu.style.top = `${ny}px`;
        ctxMenu.setAttribute("aria-hidden", "false");
    }

    function menuItem(label, onClick, opts = {}) {
        const b = document.createElement("button");
        b.type = "button";
        b.className = `ctxItem${opts.danger ? " danger" : ""}`;
        b.textContent = label;
        b.addEventListener("click", () => {
            closeContextMenu();
            onClick();
        });
        return b;
    }

    function menuSep() {
        const d = document.createElement("div");
        d.className = "ctxSep";
        return d;
    }

    async function renameImage(item) {
        if (!item || item.type !== "file") return;

        const oldRel = currentRelPathFor(item);
        const oldName = String(item.name || "");
        const newName = prompt("Rename image to:", oldName);

        if (!newName) return;
        if (newName === oldName) return;

        if (newName.includes("/") || newName.includes("\\")) {
            alert("Name cannot contain '/' or '\\'.");
            return;
        }

        const base = parentPath(oldRel);
        const newRel = base ? `${base}/${newName}` : newName;

        setBadge("warn", "working…");
        setStatus(`Renaming ${oldName}…`);

        try {
            const r = await fetch(
                `/api/v4/files/move?from=${encodeURIComponent(oldRel)}&to=${encodeURIComponent(newRel)}`,
                {
                    method: "POST",
                    credentials: "include",
                    cache: "no-store"
                }
            );

            const j = await r.json().catch(() => null);
            if (!r.ok || !j || !j.ok) {
                const msg = j && (j.message || j.error)
                    ? `${j.error || ""} ${j.message || ""}`.trim()
                    : `HTTP ${r.status}`;
                throw new Error(msg || `HTTP ${r.status}`);
            }

            if (state.previewPath === oldRel) {
                closePreviewModal();
            }
            if (state.editingPath === oldRel) {
                closeMetaModal();
            }

            setBadge("ok", "ready");
            setStatus(`Renamed: ${oldName} → ${newName}`);
            await load(true);
        } catch (e) {
            setBadge("err", "error");
            setStatus(`Rename failed: ${String(e && e.message ? e.message : e)}`);
        }
    }

    async function deleteImage(item) {
        if (!item || item.type !== "file") return;

        const rel = currentRelPathFor(item);
        const ok = confirm(`Move image to trash?\n\n${rel}\n\nYou can restore it later from Trash.`);
        if (!ok) return;

        setBadge("warn", "working…");
        setStatus(`Moving ${item.name} to trash…`);

        try {
            const r = await fetch(
                `/api/v4/files/delete?path=${encodeURIComponent(rel)}`,
                {
                    method: "POST",
                    credentials: "include",
                    cache: "no-store"
                }
            );

            const j = await r.json().catch(() => null);
            if (!r.ok || !j || !j.ok) {
                const msg = j && (j.message || j.error)
                    ? `${j.error || ""} ${j.message || ""}`.trim()
                    : `HTTP ${r.status}`;
                throw new Error(msg || `HTTP ${r.status}`);
            }

            if (state.previewPath === rel) {
                closePreviewModal();
            }
            if (state.editingPath === rel) {
                closeMetaModal();
            }

            setBadge("ok", "ready");
            setStatus(`Moved to trash: ${item.name}`);
            await load(true);
        } catch (e) {
            setBadge("err", "error");
            setStatus(`Move to trash failed: ${String(e && e.message ? e.message : e)}`);
        }
    }
    async function renameFolder(item) {
        if (!item || item.type !== "dir") return;

        const oldRel = currentRelPathFor(item);
        const oldName = String(item.name || "");
        const newName = prompt("Rename folder to:", oldName);

        if (!newName) return;
        if (newName === oldName) return;

        if (newName.includes("/") || newName.includes("\\")) {
            alert("Name cannot contain '/' or '\\'.");
            return;
        }

        const base = parentPath(oldRel);
        const newRel = base ? `${base}/${newName}` : newName;

        setBadge("warn", "working…");
        setStatus(`Renaming folder ${oldName}…`);

        try {
            const r = await fetch(
                `/api/v4/files/move?from=${encodeURIComponent(oldRel)}&to=${encodeURIComponent(newRel)}`,
                {
                    method: "POST",
                    credentials: "include",
                    cache: "no-store"
                }
            );

            const j = await r.json().catch(() => null);
            if (!r.ok || !j || !j.ok) {
                const msg = j && (j.message || j.error)
                    ? `${j.error || ""} ${j.message || ""}`.trim()
                    : `HTTP ${r.status}`;
                throw new Error(msg || `HTTP ${r.status}`);
            }

            setBadge("ok", "ready");
            setStatus(`Renamed folder: ${oldName} → ${newName}`);
            await load(true);
        } catch (e) {
            setBadge("err", "error");
            setStatus(`Folder rename failed: ${String(e && e.message ? e.message : e)}`);
        }
    }

    async function deleteFolder(item) {
        if (!item || item.type !== "dir") return;

        const rel = currentRelPathFor(item);
        const ok = confirm(`Move folder to trash?\n\n${rel}\n\nThis moves the folder and its contents to Trash. You can restore it later.`);
        if (!ok) return;

        setBadge("warn", "working…");
        setStatus(`Moving folder ${item.name} to trash…`);

        try {
            const r = await fetch(
                `/api/v4/files/delete?path=${encodeURIComponent(rel)}`,
                {
                    method: "POST",
                    credentials: "include",
                    cache: "no-store"
                }
            );

            const j = await r.json().catch(() => null);
            if (!r.ok || !j || !j.ok) {
                const msg = j && (j.message || j.error)
                    ? `${j.error || ""} ${j.message || ""}`.trim()
                    : `HTTP ${r.status}`;
                throw new Error(msg || `HTTP ${r.status}`);
            }

            setBadge("ok", "ready");
            setStatus(`Moved folder to trash: ${item.name}`);
            await load(true);
        } catch (e) {
            setBadge("err", "error");
            setStatus(`Folder move to trash failed: ${String(e && e.message ? e.message : e)}`);
        }
    }
    async function createFolder(basePath = state.curPath) {
        const shownBase = basePath ? `/${basePath}` : "/";
        const name = prompt(`New folder name in ${shownBase}:`, "New Folder");
        if (!name) return;

        if (name.includes("/") || name.includes("\\")) {
            alert("Folder name cannot contain '/' or '\\'.");
            return;
        }

        const rel = basePath ? `${basePath}/${name}` : name;

        setBadge("warn", "working…");
        setStatus(`Creating folder ${name}…`);

        try {
            const r = await fetch(
                `/api/v4/files/mkdir?path=${encodeURIComponent(rel)}`,
                {
                    method: "POST",
                    credentials: "include",
                    cache: "no-store"
                }
            );

            const j = await r.json().catch(() => null);
            if (!r.ok || !j || !j.ok) {
                const msg = j && (j.message || j.error)
                    ? `${j.error || ""} ${j.message || ""}`.trim()
                    : `HTTP ${r.status}`;
                throw new Error(msg || `HTTP ${r.status}`);
            }

            setBadge("ok", "ready");
            setStatus(`Created folder: ${name}`);
            await load(true);
        } catch (e) {
            setBadge("err", "error");
            setStatus(`Create folder failed: ${String(e && e.message ? e.message : e)}`);
        }
    }
    function openSelectionContextMenu(x, y) {
        if (!ctxMenu) return;

        const count = selectedRelPaths.size;
        if (!count) return;

        const imageTargets = selectedImageRelPaths();

        ctxMenu.innerHTML = "";

        if (imageTargets.length) {
            ctxMenu.appendChild(menuItem("Edit metadata for selected photos…", () => {
                const preferred =
                    state.activeTilePath && imageTargets.includes(state.activeTilePath)
                        ? state.activeTilePath
                        : imageTargets[0];

                openMetaFor(preferred);
            }));
            ctxMenu.appendChild(menuSep());
        }

        ctxMenu.appendChild(menuItem("Download selected", () => downloadSelectionZip()));
        ctxMenu.appendChild(menuItem("Export selected with metadata…", () => exportSelectionZip()));
        ctxMenu.appendChild(menuSep());
        ctxMenu.appendChild(menuItem("Clear selection", () => {
            clearSelection();
            setStatus("Selection cleared.");
        }));
        ctxMenu.appendChild(menuItem("Move selected to trash…", () => deleteSelection(), { danger: true }));

        placeContextMenu(x, y);
    }
    function openFolderContextMenu(x, y, item) {
        if (!ctxMenu || !item || item.type !== "dir") return;

        ctxMenu.innerHTML = "";
        ctxMenu.appendChild(menuItem("Open", () => {
            setCurrentPath(currentRelPathFor(item), "folder-context-open");
            load();
        }));
        ctxMenu.appendChild(menuItem("New folder here…", () => {
            createFolder(currentRelPathFor(item));
        }));
        ctxMenu.appendChild(menuItem("Download zip", () => downloadSingleFolderZip(item)));
        ctxMenu.appendChild(menuItem("Export with metadata…", () => exportSingleItemZip(item)));
        ctxMenu.appendChild(menuSep());
        ctxMenu.appendChild(menuItem("Rename…", () => renameFolder(item)));
        ctxMenu.appendChild(menuItem("Move to trash…", () => deleteFolder(item), { danger: true }));

        placeContextMenu(x, y);
    }
    function openBackgroundContextMenu(x, y) {
        if (!ctxMenu) return;

        ctxMenu.innerHTML = "";

        ctxMenu.appendChild(menuItem("Upload files…", () => {
            if (window.PQNAS_PHOTOGALLERY?.upload?.pickFiles) {
                window.PQNAS_PHOTOGALLERY.upload.pickFiles();
                return;
            }
            if (window.PQNAS_PHOTOGALLERY_UPLOAD?.pickFiles) {
                window.PQNAS_PHOTOGALLERY_UPLOAD.pickFiles();
                return;
            }
            setBadge("err", "error");
            setStatus("Upload module not loaded.");
        }));

        ctxMenu.appendChild(menuItem("Upload folder…", () => {
            if (window.PQNAS_PHOTOGALLERY?.upload?.pickFolder) {
                window.PQNAS_PHOTOGALLERY.upload.pickFolder();
                return;
            }
            if (window.PQNAS_PHOTOGALLERY_UPLOAD?.pickFolder) {
                window.PQNAS_PHOTOGALLERY_UPLOAD.pickFolder();
                return;
            }
            setBadge("err", "error");
            setStatus("Upload module not loaded.");
        }));

        ctxMenu.appendChild(menuSep());

        ctxMenu.appendChild(menuItem("New folder…", () => {
            createFolder(state.curPath);
        }));

        if (state.curPath) {
            ctxMenu.appendChild(menuItem("Up", () => {
                setCurrentPath(parentPath(state.curPath), "background-context-up");
                clearSelection();
                load();
            }));
        }

        ctxMenu.appendChild(menuSep());
        ctxMenu.appendChild(menuItem("Refresh", () => load(true)));

        placeContextMenu(x, y);
    }
    function openImageContextMenu(x, y, item) {
        if (!ctxMenu || !item || item.type !== "file") return;

        const rel = currentRelPathFor(item);
        const shareLabel =
            window.PQNAS_PHOTOGALLERY_SHARES?.menuLabelForRelPath(rel, "file") ||
            "Share link…";

        ctxMenu.innerHTML = "";
        ctxMenu.appendChild(menuItem("Open preview", () => openPreviewFor(item)));
        ctxMenu.appendChild(menuItem("Edit metadata…", () => openMetaFor(item)));
        ctxMenu.appendChild(menuItem("Download", () => downloadSingleImage(item)));
        ctxMenu.appendChild(menuItem("Export with metadata…", () => exportSingleItemZip(item)));
        ctxMenu.appendChild(menuItem(shareLabel, () => {
            window.PQNAS_PHOTOGALLERY_SHARES?.openForItem(item);
        }));
        ctxMenu.appendChild(menuSep());
        ctxMenu.appendChild(menuItem("Rename…", () => renameImage(item)));
        ctxMenu.appendChild(menuItem("Move to trash…", () => deleteImage(item), { danger: true }));

        placeContextMenu(x, y);
    }
    function placeMetaCentered() {
        if (!metaCard) return;
        metaCard.style.transform = "translateX(-50%)";
        metaCard.style.left = "50%";
        metaCard.style.top = "110px";
    }

    function clampMetaIntoViewport() {
        if (!metaCard) return;

        const rect = metaCard.getBoundingClientRect();
        const pad = 8;

        let left = rect.left;
        let top = rect.top;

        const maxLeft = Math.max(pad, window.innerWidth - rect.width - pad);
        const maxTop = Math.max(pad, window.innerHeight - rect.height - pad);

        left = clamp(left, pad, maxLeft);
        top = clamp(top, pad, maxTop);

        metaCard.style.transform = "none";
        metaCard.style.left = `${left}px`;
        metaCard.style.top = `${top}px`;
    }
    function updateSelectionUi() {
        const count = selectedRelPaths.size;

        if (selCount) {
            selCount.textContent = `${count} selected`;
            selCount.style.display = count > 0 ? "" : "none";
        }

        if (downloadSelBtn) downloadSelBtn.disabled = count === 0;
        if (deleteSelBtn) deleteSelBtn.disabled = count === 0;
        if (clearSelBtn) clearSelBtn.disabled = count === 0;

        refreshMetaApplySelectionUi();
        refreshFooterStats();
    }
    function clearSelectionDom() {
        if (!gridEl) return;
        for (const el of gridEl.querySelectorAll(".tile")) {
            el.classList.remove("sel");
        }
    }

    function applySelectionToDom() {
        if (!gridEl) return;
        for (const el of gridEl.querySelectorAll(".tile")) {
            const rel = String(el.dataset.relPath || "");
            el.classList.toggle("sel", selectedRelPaths.has(rel));
        }
        updateSelectionUi();
    }

    function visibleRelPathsInOrder() {
        if (!gridEl) return [];
        return Array.from(gridEl.querySelectorAll(".tile"))
            .map((el) => String(el.dataset.relPath || ""))
            .filter(Boolean);
    }

    function clearSelection() {
        selectedRelPaths.clear();
        selectionAnchorRelPath = "";
        state.activeTilePath = "";
        clearSelectionDom();
        updateTileSelection();
        updateSelectionUi();
    }

    function setSingleSelection(relPath, opts = {}) {
        if (!relPath) return;
        selectedRelPaths = new Set([relPath]);
        selectionAnchorRelPath = relPath;
        applySelectionToDom();
        setActiveTileRelPath(relPath, {
            scroll: opts.scroll === true,
            focus: opts.focus === true
        });
    }

    function toggleSelection(relPath) {
        if (!relPath) return;
        if (selectedRelPaths.has(relPath)) selectedRelPaths.delete(relPath);
        else selectedRelPaths.add(relPath);
        applySelectionToDom();
        setActiveTileRelPath(relPath, {
            scroll: false,
            focus: false
        });
    }
    function ensureSelected(relPath) {
        if (!relPath) return;
        if (!selectedRelPaths.has(relPath)) {
            setSingleSelection(relPath);
        }
    }

    function selectRange(fromRelPath, toRelPath, additive) {
        const keys = visibleRelPathsInOrder();
        const a = keys.indexOf(String(fromRelPath || ""));
        const b = keys.indexOf(String(toRelPath || ""));

        if (a < 0 || b < 0) {
            setSingleSelection(String(toRelPath || fromRelPath || ""));
            selectionAnchorRelPath = String(toRelPath || fromRelPath || "");
            return;
        }

        const lo = Math.min(a, b);
        const hi = Math.max(a, b);

        const next = additive ? new Set(selectedRelPaths) : new Set();
        for (let i = lo; i <= hi; i++) {
            if (keys[i]) next.add(keys[i]);
        }

        selectedRelPaths = next;
        selectionAnchorRelPath = String(toRelPath || "");
        applySelectionToDom();
        setActiveTileRelPath(String(toRelPath || ""), {
            scroll: false,
            focus: false
        });
    }

    function selectedRelPathsList() {
        return Array.from(selectedRelPaths).sort((a, b) => String(a).localeCompare(String(b)));
    }
    function selectedImageRelPaths() {
        if (!gridEl) return [];

        return Array.from(gridEl.querySelectorAll(".tile[data-item-type='file']"))
            .map((tile) => String(tile.dataset.relPath || ""))
            .filter((rel) => rel && selectedRelPaths.has(rel))
            .sort((a, b) => String(a).localeCompare(String(b)));
    }

    function resetTreeStats() {
        state.treeStats = {
            basePath: "",
            loaded: false,
            loading: false,
            dirs: 0,
            files: 0,
            fileBytes: 0,
            seq: (state.treeStats?.seq || 0) + 1
        };
    }


async function ensureTreeStats(force = false) {
    const root = String(state.curPath || "");
    const currentSeq = (state.treeStats?.seq || 0) + 1;

    if (!force &&
        state.treeStats.loaded &&
        !state.treeStats.loading &&
        state.treeStats.basePath === root) {
        return state.treeStats;
    }

    state.treeStats = {
        basePath: root,
        loaded: false,
        loading: true,
        dirs: 0,
        files: 0,
        fileBytes: 0,
        seq: currentSeq
    };

    async function walk(path) {
        if (!state.treeStats || state.treeStats.seq !== currentSeq) return;

        const j = await fetchJson(galleryListUrl(path));
        const items = Array.isArray(j.items) ? j.items : [];

        for (const it of items) {
            if (it.type === "dir") {
                state.treeStats.dirs++;
            } else if (it.type === "file") {
                state.treeStats.files++;
                state.treeStats.fileBytes += Number(it.size_bytes || 0) || 0;
            }
        }

        for (const it of items) {
            if (it.type === "dir") {
                await walk(joinPath(path, it.name));
            }
        }
    }

    await walk(root);

    if (state.treeStats && state.treeStats.seq === currentSeq) {
        state.treeStats.loading = false;
        state.treeStats.loaded = true;
    }

    return state.treeStats;
}
    function visibleItemsSummary() {
        const items = filteredItems();

        let dirs = 0;
        let files = 0;
        let fileBytes = 0;

        for (const it of items) {
            if (it.type === "dir") {
                dirs++;
            } else if (it.type === "file") {
                files++;
                fileBytes += Number(it.size_bytes || 0) || 0;
            }
        }

        return {
            items: items.length,
            dirs,
            files,
            fileBytes
        };
    }

    function selectedItemsSummary() {
        const all = [...state.items, ...state.searchItems];
        const seen = new Set();

        let items = 0;
        let dirs = 0;
        let files = 0;
        let fileBytes = 0;

        for (const it of all) {
            const rel = currentRelPathFor(it);
            if (!rel || seen.has(rel) || !selectedRelPaths.has(rel)) continue;
            seen.add(rel);

            items++;
            if (it.type === "dir") {
                dirs++;
            } else if (it.type === "file") {
                files++;
                fileBytes += Number(it.size_bytes || 0) || 0;
            }
        }

        return { items, dirs, files, fileBytes };
    }

    function refreshFooterStats() {
        if (!footerStats) return;

        const vis = visibleItemsSummary();
        const tree = state.treeStats || {
            loaded: false,
            loading: false,
            dirs: 0,
            files: 0,
            fileBytes: 0
        };

        const parts = [];

        parts.push(`Here: ${vis.items}`);
        parts.push(`Folders: ${vis.dirs}`);
        parts.push(`Files: ${vis.files}`);
        parts.push(`Size: ${fmtSize(vis.fileBytes)}`);

        if (tree.loading) {
            parts.push(`Tree: loading…`);
        } else if (tree.loaded) {
            parts.push(`Tree folders: ${tree.dirs}`);
            parts.push(`Tree files: ${tree.files}`);
            parts.push(`Tree size: ${fmtSize(tree.fileBytes)}`);
        }

        const sel = selectedItemsSummary();
        let html = parts
            .map((p) => `${p}`)
            .join(` <span class="footerStatsDimSep">•</span> `);

        if (sel.items > 0) {
            html += ` <span class="footerStatsDimSep">•</span> <span class="footerStatsSel">Selected: ${sel.items} • ${fmtSize(sel.fileBytes)}</span>`;
        }

        footerStats.innerHTML = html;
    }
    function refreshMetaApplySelectionUi() {
        if (!metaApplySelWrap || !metaApplySelChk || !metaApplySelText) return;

        const selectedImages = selectedImageRelPaths();
        const show =
            !!state.editingPath &&
            selectedImages.length > 1 &&
            selectedImages.includes(state.editingPath);

        metaApplySelWrap.style.display = show ? "" : "none";

        if (!show) {
            metaApplySelChk.checked = false;
            metaApplySelText.textContent = "Apply to selected photos";
            metaApplySelWrap.style.background = "";
            metaApplySelWrap.style.border = "";
            metaApplySelWrap.style.borderRadius = "";
            metaApplySelWrap.style.padding = "";
            return;
        }

        metaApplySelText.textContent =
            `Apply to ${selectedImages.length} selected photo${selectedImages.length === 1 ? "" : "s"}`;

        if (metaApplySelChk.checked) {
            metaApplySelWrap.style.background = "rgba(255, 215, 0, 0.18)";
            metaApplySelWrap.style.border = "1px solid rgba(255, 215, 0, 0.45)";
        } else {
            metaApplySelWrap.style.background = "rgba(255, 215, 0, 0.10)";
            metaApplySelWrap.style.border = "1px solid rgba(255, 215, 0, 0.28)";
        }

        metaApplySelWrap.style.borderRadius = "10px";
        metaApplySelWrap.style.padding = "10px 12px";
    }
    function getZipFilenameFromResponse(r, fallback = "gallery-selection.zip") {
        const cd = r.headers.get("Content-Disposition") || "";

        let m = cd.match(/filename\*=UTF-8''([^;]+)/i);
        if (m && m[1]) {
            try { return decodeURIComponent(m[1]); } catch (_) {}
        }

        m = cd.match(/filename="?([^"]+)"?/i);
        if (m && m[1]) return m[1];

        return fallback;
    }
    function triggerBlobDownload(blob, filename) {
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = filename || "download";
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1500);
    }

    function triggerDirectFileDownload(relPath, filename) {
        const a = document.createElement("a");
        a.href = fileGetUrl(relPath);
        a.download = filename || "";
        document.body.appendChild(a);
        a.click();
        a.remove();
    }

    async function fetchSelectionArchive(url, body, fallbackName, busyText, doneText) {
        setBadge("warn", "zip…");
        setStatus(busyText);

        try {
            const r = await fetch(url, {
                method: "POST",
                credentials: "include",
                cache: "no-store",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(body)
            });

            if (!r.ok) {
                const t = await r.text().catch(() => "");
                throw new Error(`HTTP ${r.status}${t ? " — " + t : ""}`);
            }

            const blob = await r.blob();
            triggerBlobDownload(blob, getZipFilenameFromResponse(r, fallbackName));

            setBadge("ok", "ready");
            setStatus(doneText);
        } catch (e) {
            setBadge("err", "error");
            setStatus(`Download failed: ${String(e && e.message ? e.message : e)}`);
        }
    }

    function selectedBasePath() {
        return state.curPath || "";
    }

    async function exportSelectionZip() {
        const paths = selectedRelPathsList();
        if (!paths.length) {
            setStatus("Nothing selected.");
            return;
        }

        await fetchSelectionArchive(
            "/api/v4/gallery/export_sel_zip",
            { paths, base: selectedBasePath() },
            "gallery-export.zip",
            `Preparing export (${paths.length} item${paths.length === 1 ? "" : "s"})…`,
            `Export ready (${paths.length} item${paths.length === 1 ? "" : "s"}).`
        );
    }

    function downloadSingleImage(item) {
        const rel = currentRelPathFor(item);
        triggerDirectFileDownload(rel, item.name || "image");
        setBadge("ok", "ready");
        setStatus(`Download started: ${item.name || rel}`);
    }

    async function downloadSingleFolderZip(item) {
        const rel = currentRelPathFor(item);
        await fetchSelectionArchive(
            "/api/v4/files/zip_sel",
            { paths: [rel], base: parentPath(rel) || "" },
            `${item.name || "folder"}.zip`,
            `Preparing zip for ${item.name || rel}…`,
            `Download ready: ${item.name || rel}`
        );
    }

    async function exportSingleItemZip(item) {
        const rel = currentRelPathFor(item);
        await fetchSelectionArchive(
            "/api/v4/gallery/export_sel_zip",
            { paths: [rel], base: parentPath(rel) || "" },
            "gallery-export.zip",
            `Preparing export for ${item.name || rel}…`,
            `Export ready: ${item.name || rel}`
        );
    }
    async function downloadSelectionZip() {
        const paths = selectedRelPathsList();
        if (!paths.length) {
            setStatus("Nothing selected.");
            return;
        }

        await fetchSelectionArchive(
            "/api/v4/files/zip_sel",
            { paths, base: selectedBasePath() },
            "selection.zip",
            `Preparing zip (${paths.length} item${paths.length === 1 ? "" : "s"})…`,
            `Download ready (${paths.length} item${paths.length === 1 ? "" : "s"}).`
        );
    }

    async function deleteSelection() {
        const paths = selectedRelPathsList();
        if (!paths.length) {
            setStatus("Nothing selected.");
            return;
        }

        const ok = confirm(
            `Move ${paths.length} selected item(s) to trash?\n\nYou can restore them later from Trash.`
        );
        if (!ok) return;

        setBadge("warn", "working…");
        setStatus(`Moving ${paths.length} item(s) to trash…`);

        let done = 0;
        const failed = [];

        for (const rel of paths) {
            try {
                const r = await fetch(
                    `/api/v4/files/delete?path=${encodeURIComponent(rel)}`,
                    {
                        method: "POST",
                        credentials: "include",
                        cache: "no-store"
                    }
                );

                const j = await r.json().catch(() => null);
                if (!r.ok || !j || !j.ok) {
                    const msg = j && (j.message || j.error)
                        ? `${j.error || ""} ${j.message || ""}`.trim()
                        : `HTTP ${r.status}`;
                    throw new Error(msg || `HTTP ${r.status}`);
                }

                done++;

                if (state.previewPath === rel) closePreviewModal();
                if (state.editingPath === rel) closeMetaModal();
            } catch (e) {
                failed.push(`${rel}: ${String(e && e.message ? e.message : e)}`);
            }
        }

        clearSelection();
        await load(true);

        if (failed.length) {
            setBadge("warn", "partial");
            setStatus(`Moved to trash ${done}/${paths.length}. Failed: ${failed.length}`);
            console.warn("Photo Gallery deleteSelection failures:", failed);
        } else {
            setBadge("ok", "ready");
            setStatus(`Moved to trash ${done} item(s).`);
        }
    }
    const marquee = document.createElement("div");
    marquee.style.position = "absolute";
    marquee.style.border = "1px solid rgba(var(--fg-rgb),0.45)";
    marquee.style.background = "rgba(var(--fg-rgb),0.12)";
    marquee.style.borderRadius = "10px";
    marquee.style.pointerEvents = "none";
    marquee.style.display = "none";
    marquee.style.zIndex = "9999";
    document.body.appendChild(marquee);

    let marqueeOn = false;
    let marqueeStartX = 0;
    let marqueeStartY = 0;
    let marqueeBaseSelection = null;

    function tileRects() {
        if (!gridEl) return [];
        const out = [];
        for (const tileEl of gridEl.querySelectorAll(".tile")) {
            out.push({
                relPath: String(tileEl.dataset.relPath || ""),
                rect: tileEl.getBoundingClientRect()
            });
        }
        return out;
    }

    function rectIntersects(a, b) {
        return !(a.right < b.left || a.left > b.right || a.bottom < b.top || a.top > b.bottom);
    }

    function endMarquee() {
        if (!marqueeOn) return;
        marqueeOn = false;
        marquee.style.display = "none";
        marqueeBaseSelection = null;
    }

    gridWrap?.addEventListener("pointerdown", (e) => {
        if (e.button !== 0) return;
        if (e.target && e.target.closest && e.target.closest(".tile")) return;
        if (ctxMenu && ctxMenu.classList.contains("show")) return;

        marqueeOn = true;
        marqueeStartX = e.clientX;
        marqueeStartY = e.clientY;
        marqueeBaseSelection = (e.ctrlKey || e.metaKey) ? new Set(selectedRelPaths) : null;

        if (!marqueeBaseSelection) clearSelection();

        marquee.style.left = `${marqueeStartX}px`;
        marquee.style.top = `${marqueeStartY}px`;
        marquee.style.width = "0px";
        marquee.style.height = "0px";
        marquee.style.display = "block";

        try { gridWrap.setPointerCapture(e.pointerId); } catch (_) {}
        e.preventDefault();
    });

    gridWrap?.addEventListener("pointermove", (e) => {
        if (!marqueeOn) return;

        const x = e.clientX;
        const y = e.clientY;

        const left = Math.min(marqueeStartX, x);
        const top = Math.min(marqueeStartY, y);
        const right = Math.max(marqueeStartX, x);
        const bottom = Math.max(marqueeStartY, y);

        marquee.style.left = `${left}px`;
        marquee.style.top = `${top}px`;
        marquee.style.width = `${right - left}px`;
        marquee.style.height = `${bottom - top}px`;

        const selRect = { left, top, right, bottom };
        const rects = tileRects();
        const next = marqueeBaseSelection ? new Set(marqueeBaseSelection) : new Set();

        for (const t of rects) {
            if (t.relPath && rectIntersects(selRect, t.rect)) {
                next.add(t.relPath);
            }
        }

        selectedRelPaths = next;
        applySelectionToDom();
    });

    gridWrap?.addEventListener("pointerup", endMarquee);

    panelEl?.addEventListener("contextmenu", (e) => {
        const target = e.target;

        if (!target || !(target instanceof Element)) return;

        // Let tile-specific handlers keep control.
        if (target.closest(".tile")) return;

        // Do not hijack native menu inside editable controls.
        if (target.closest("input, textarea, select")) return;

        // Do not interfere with modals.
        if (target.closest(".modal.show")) return;

        e.preventDefault();
        e.stopPropagation();

        if (selectedRelPaths.size > 0) {
            openSelectionContextMenu(e.clientX, e.clientY);
        } else {
            openBackgroundContextMenu(e.clientX, e.clientY);
        }
    }, true);

    gridWrap?.addEventListener("pointercancel", endMarquee);
    function renderBreadcrumb() {
        if (!pathLine) return;
        pathLine.replaceChildren();

        const root = document.createElement("span");
        root.className = "crumb";
        root.textContent = "/";
        root.title = "Go to root";
        root.addEventListener("click", () => {
            setCurrentPath("", "breadcrumb-root");
            clearSelection();
            load();
        });
        pathLine.appendChild(root);

        if (!state.curPath) {
            root.classList.add("active");
            return;
        }

        const parts = String(state.curPath).split("/").filter(Boolean);
        let acc = "";

        for (let i = 0; i < parts.length; i++) {
            const sep = document.createElement("span");
            sep.className = "crumbSep";
            sep.textContent = "›";
            pathLine.appendChild(sep);

            const name = parts[i];
            acc = acc ? `${acc}/${name}` : name;

            const crumb = document.createElement("span");
            crumb.className = "crumb";
            if (i === parts.length - 1) crumb.classList.add("active");
            crumb.title = "/" + acc;

            const txt = document.createElement("span");
            txt.className = "crumbText";
            txt.textContent = name;
            crumb.appendChild(txt);

            if (i !== parts.length - 1) {
                const target = acc;
                crumb.addEventListener("click", () => {
                    setCurrentPath(target, "breadcrumb-click");
                    clearSelection();
                    load();
                });
            }

            pathLine.appendChild(crumb);
        }
    }

    function sortItems(items) {
        return items.slice().sort((a, b) => {
            if (a.type !== b.type) return a.type === "dir" ? -1 : 1;
            return String(a.name || "").localeCompare(String(b.name || ""));
        });
    }

    function isSearchMode() {
        const hasText = !!String(state.filter || "").trim();
        const rf = Number(state.ratingFilter);
        const hasRating = Number.isFinite(rf) && rf >= 0;
        return hasText || hasRating;
    }

    function invalidateSearchCache() {
        searchSeq++;
        state.searchItems = [];
        state.searchBasePath = "";
        state.searchLoaded = false;
        state.searchLoading = false;
    }

    function groupPathForItem(item) {
        return parentPath(currentRelPathFor(item));
    }

    function sortSearchItems(items) {
        return items.slice().sort((a, b) => {
            const ap = groupPathForItem(a);
            const bp = groupPathForItem(b);
            const byPath = String(ap).localeCompare(String(bp));
            if (byPath) return byPath;
            return String(a.name || "").localeCompare(String(b.name || ""));
        });
    }

    async function ensureRecursiveSearchItems(force = false) {
        const root = String(state.curPath || "");

        if (!force && state.searchLoaded && state.searchBasePath === root) {
            state.searchLoading = false;
            return state.searchItems;
        }

        const mySeq = ++searchSeq;
        state.searchLoading = true;
        state.searchLoaded = false;
        state.searchBasePath = root;
        state.searchItems = [];

        const out = [];
        let scannedFolders = 0;

        async function walk(path) {
            if (mySeq !== searchSeq) throw new Error("__stale_search__");

            scannedFolders++;
            setStatus(`Searching /${path || ""} … folders: ${scannedFolders}, photos: ${out.length}`);

            const j = await fetchJson(galleryListUrl(path));
            const items = sortItems(Array.isArray(j.items) ? j.items : []);

            for (const it of items) {
                const rel = joinPath(path, it.name);
                if (it.type === "file") {
                    out.push({
                        ...it,
                        rel_path: rel,
                        base_path: path
                    });
                }
            }

            for (const it of items) {
                if (it.type === "dir") {
                    await walk(joinPath(path, it.name));
                }
            }
        }

        try {
            await walk(root);

            if (mySeq !== searchSeq) throw new Error("__stale_search__");

            state.searchItems = out;
            state.searchLoaded = true;
            return out;
        } finally {
            if (mySeq === searchSeq) {
                state.searchLoading = false;
            }
        }
    }

    function makeSearchGroupHeader(folderPath, count, first) {
        const head = document.createElement("div");
        head.className = "searchGroupHead";
        head.style.gridColumn = "1 / -1";
        head.style.display = "flex";
        head.style.justifyContent = "space-between";
        head.style.alignItems = "baseline";
        head.style.gap = "12px";
        head.style.padding = first ? "0 2px 10px" : "14px 2px 10px";
        head.style.margin = first ? "0 0 4px" : "10px 0 4px";
        head.style.borderTop = first ? "none" : "1px solid rgba(var(--fg-rgb),0.16)";

        const left = document.createElement("div");
        left.style.fontWeight = "600";
        left.style.opacity = "0.95";
        left.textContent = "/" + (folderPath || "");

        const right = document.createElement("div");
        right.style.fontSize = "12px";
        right.style.opacity = "0.72";
        right.textContent = `${count} photo${count === 1 ? "" : "s"}`;

        head.appendChild(left);
        head.appendChild(right);
        return head;
    }

    function updateViewStatus() {
        const rf = Number(state.ratingFilter);
        const ratingTxt =
            rf < 0 ? "" :
                (rf === 0 ? " • unrated only" : ` • ${rf}★ only`);
        const textTxt =
            state.filter ? ` • filter: ${state.filter}` : "";

        const items = filteredItems();
        if (state.viewMode === "map") {
            const gpsCount = mapItems().length;
            const textTxt =
                state.filter ? ` • filter: ${state.filter}` : "";
            const rf = Number(state.ratingFilter);
            const ratingTxt =
                rf < 0 ? "" :
                    (rf === 0 ? " • unrated only" : ` • ${rf}★ only`);

            setStatus(`Map: ${gpsCount} GPS photo${gpsCount === 1 ? "" : "s"} under /${state.curPath || ""}${ratingTxt}${textTxt}`);
            return;
        }
        if (isSearchMode()) {
            const pathCount = new Set(items.map((it) => groupPathForItem(it))).size;
            const scopeTxt = ` under /${state.curPath || ""}`;
            setStatus(
                `Found ${items.length} photo${items.length === 1 ? "" : "s"} in ${pathCount} path${pathCount === 1 ? "" : "s"}${scopeTxt}${ratingTxt}${textTxt}`
            );
            return;
        }

        setStatus(`Items: ${items.length}${ratingTxt}${textTxt}`);
    }

    async function refreshVisibleView(forceSearch = false) {
        try {
            if (isSearchMode()) {
                const needSearch =
                    forceSearch ||
                    !state.searchLoaded ||
                    state.searchBasePath !== state.curPath;

                if (needSearch) {
                    state.searchLoading = true;
                    renderGrid();
                    setBadge("warn", "search…");
                    setStatus("Searching subfolders…");
                    await ensureRecursiveSearchItems(forceSearch);
                }
            } else {
                state.searchLoading = false;
            }

            renderGrid();
            window.dispatchEvent(new CustomEvent("photogallery:view-updated"));
            setBadge("ok", "ready");
            updateViewStatus();
        } catch (e) {
            const msg = String(e && e.message ? e.message : e);
            if (msg === "__stale_search__") return;

            state.searchLoading = false;
            renderGrid();
            setBadge("err", "error");
            setStatus(`Search failed: ${msg}`);
        }
    }

    function filteredItems() {
        const q = String(state.filter || "").trim().toLowerCase();
        const rating = Number(state.ratingFilter);

        const baseItems = isSearchMode()
            ? sortSearchItems(state.searchItems)
            : sortItems(state.items);

        return baseItems.filter((it) => {
            if (Number.isFinite(rating) && rating >= 0) {
                if (it.type !== "file") return false;
                const stars = Number(it.rating || 0) || 0;
                if (stars !== rating) return false;
            }

            if (!q) return true;

            if (it.type !== "file") return false;

            const hay = [
                it.name || "",
                groupPathForItem(it),
                Array.isArray(it.keywords) ? it.keywords.join(" ") : (it.tags_text || ""),
                it.description || it.notes_text || ""
            ].join(" ").toLowerCase();

            return hay.includes(q);
        });
    }
    function displayItems() {
        const items = filteredItems();

        if (!window.PQNAS_PHOTOGALLERY?.bursts?.buildDisplayItems) {
            return items.map((item) => ({ kind: "item", item }));
        }

        return window.PQNAS_PHOTOGALLERY.bursts.buildDisplayItems(items);
    }
    function normalizeGalleryMeta(meta) {
        const imageRating =
            meta && meta.imageRating != null
                ? Number(meta.imageRating || 0) || 0
                : Number(meta && meta.rating || 0) || 0;

        const keywords = Array.isArray(meta && meta.keywords)
            ? meta.keywords.map(v => String(v || "").trim()).filter(Boolean)
            : String(meta && meta.tags_text || "")
                .split(",")
                .map(v => v.trim())
                .filter(Boolean);

        const description =
            meta && meta.description && typeof meta.description === "object"
                ? String(meta.description["x-default"] || "")
                : String(meta && meta.notes_text || "");

        return {
            imageRating,
            keywords,
            description
        };
    }
    function applyMetaToItem(it, meta) {
        if (!it) return;

        const { imageRating, keywords, description } = normalizeGalleryMeta(meta);

        it.rating = imageRating;
        it.keywords = keywords.slice();
        it.description = description;

        // Keep old compatibility fields alive for now.
        it.tags_text = keywords.join(", ");
        it.notes_text = description;

        if (meta && meta.size_bytes != null) it.size_bytes = Number(meta.size_bytes || 0);
        if (meta && meta.mtime_epoch != null) it.mtime_unix = Number(meta.mtime_epoch || 0);
    }

    function applyMetaToCaches(rel, meta) {
        for (const it of state.items) {
            if (currentRelPathFor(it) === rel) applyMetaToItem(it, meta);
        }
        for (const it of state.searchItems) {
            if (currentRelPathFor(it) === rel) applyMetaToItem(it, meta);
        }
    }

    function filteredImageItems() {
        return filteredItems().filter((it) => it.type === "file");
    }
    function isTypingTarget(target) {
        if (!target || !(target instanceof Element)) return false;
        return !!target.closest("input, textarea, select, button, [contenteditable='true']");
    }

    function getRenderedTiles() {
        return gridEl ? Array.from(gridEl.querySelectorAll(".tile")) : [];
    }

    function findTileByRelPath(relPath) {
        return getRenderedTiles().find((tile) => tile.dataset.relPath === relPath) || null;
    }

    function updateTileSelection() {
        for (const tile of getRenderedTiles()) {
            const active = !!state.activeTilePath && tile.dataset.relPath === state.activeTilePath;
            tile.classList.toggle("kbdActive", active);
            tile.tabIndex = active ? 0 : -1;
            tile.setAttribute("aria-selected", active ? "true" : "false");
        }
    }

    function setActiveTileRelPath(relPath, opts = {}) {
        const scroll = opts.scroll !== false;
        const focus = opts.focus === true;

        state.activeTilePath = String(relPath || "");

        const tile = findTileByRelPath(state.activeTilePath);
        updateTileSelection();

        if (!tile) return null;

        if (scroll) {
            tile.scrollIntoView({
                block: "nearest",
                inline: "nearest"
            });
        }

        if (focus) {
            try {
                tile.focus({ preventScroll: true });
            } catch (_) {
                try { tile.focus(); } catch (_) {}
            }
        }

        return tile;
    }

    function ensureActiveTile() {
        const tiles = getRenderedTiles();
        if (!tiles.length) {
            state.activeTilePath = "";
            return null;
        }

        const existing = findTileByRelPath(state.activeTilePath);
        if (existing) {
            updateTileSelection();
            return existing;
        }

        return setActiveTileRelPath(tiles[0].dataset.relPath || "", {
            scroll: false,
            focus: false
        });
    }

    function moveLinear(delta) {
        const tiles = getRenderedTiles();
        if (!tiles.length) return;

        const current = ensureActiveTile();
        const idx = Math.max(0, tiles.indexOf(current));
        const nextIdx = clamp(idx + delta, 0, tiles.length - 1);
        const nextRel = tiles[nextIdx].dataset.relPath || "";

        setSingleSelection(nextRel, {
            scroll: true,
            focus: true
        });
    }

    function buildTileRows() {
        const tiles = getRenderedTiles().map((tile) => {
            const rect = tile.getBoundingClientRect();
            return {
                tile,
                relPath: tile.dataset.relPath || "",
                left: rect.left,
                top: rect.top,
                width: rect.width,
                height: rect.height,
                centerX: rect.left + rect.width / 2
            };
        });

        tiles.sort((a, b) => {
            const dy = a.top - b.top;
            if (Math.abs(dy) > 24) return dy;
            return a.left - b.left;
        });

        const rows = [];
        for (const entry of tiles) {
            const lastRow = rows[rows.length - 1];
            if (!lastRow || Math.abs(entry.top - lastRow[0].top) > 24) {
                rows.push([entry]);
            } else {
                lastRow.push(entry);
            }
        }

        return rows;
    }

    function getActiveRowPos(rows) {
        for (let r = 0; r < rows.length; r++) {
            for (let c = 0; c < rows[r].length; c++) {
                if (rows[r][c].relPath === state.activeTilePath) {
                    return { row: r, col: c, entry: rows[r][c] };
                }
            }
        }

        if (rows.length && rows[0].length) {
            return { row: 0, col: 0, entry: rows[0][0] };
        }

        return null;
    }

    function closestIndexByX(row, targetX) {
        let bestIdx = 0;
        let bestDist = Infinity;

        for (let i = 0; i < row.length; i++) {
            const d = Math.abs(row[i].centerX - targetX);
            if (d < bestDist) {
                bestDist = d;
                bestIdx = i;
            }
        }

        return bestIdx;
    }

    function moveVertical(deltaRows) {
        const rows = buildTileRows();
        const pos = getActiveRowPos(rows);
        if (!pos) return;

        const targetRow = clamp(pos.row + deltaRows, 0, rows.length - 1);
        if (targetRow === pos.row) return;

        const targetCol = closestIndexByX(rows[targetRow], pos.entry.centerX);
        const nextRel = rows[targetRow][targetCol].relPath;

        setSingleSelection(nextRel, {
            scroll: true,
            focus: true
        });
    }

    function moveByPage(deltaPages) {
        const rows = buildTileRows();
        const pos = getActiveRowPos(rows);
        if (!pos) return;

        const viewportH = gridEl ? gridEl.clientHeight : window.innerHeight;
        const rowHeight = Math.max(1, pos.entry.height);
        const stepRows = Math.max(1, Math.floor(viewportH / rowHeight) - 1);

        const targetRow = clamp(pos.row + (deltaPages * stepRows), 0, rows.length - 1);
        const targetCol = closestIndexByX(rows[targetRow], pos.entry.centerX);
        const nextRel = rows[targetRow][targetCol].relPath;

        setSingleSelection(nextRel, {
            scroll: true,
            focus: true
        });
    }

    function activateSelectedTile() {
        const tile = ensureActiveTile();
        if (!tile) return;
        tile.click();
    }
    function openSelectedTileMetadata() {
        const tile = ensureActiveTile();
        if (!tile) return;

        if ((tile.dataset.itemType || "") !== "file") {
            return;
        }

        const relPath = tile.dataset.relPath || "";
        if (!relPath) return;

        openMetaFor(relPath);
    }
    function currentPreviewIndex() {
        const items = filteredImageItems();
        const idx = items.findIndex((it) => currentRelPathFor(it) === state.previewPath);
        return { items, idx };
    }

    function updatePreviewNav() {
        const { items, idx } = currentPreviewIndex();
        const hasMany = items.length > 1;
        if (previewPrevBtn) previewPrevBtn.disabled = !hasMany || idx < 0;
        if (previewNextBtn) previewNextBtn.disabled = !hasMany || idx < 0;
        if (previewMetaBtn) previewMetaBtn.disabled = idx < 0;
    }
    function clampPreviewZoom(z) {
        return clamp(Number(z || 1), 0.05, 8);
    }

    function computeFitZoom() {
        if (!previewImg || !previewBody || !previewImg.naturalWidth || !previewImg.naturalHeight) {
            return 1;
        }

        const fitX = previewBody.clientWidth / previewImg.naturalWidth;
        const fitY = previewBody.clientHeight / previewImg.naturalHeight;
        return Math.min(1, fitX, fitY);
    }

    function currentPreviewZoom() {
        return state.previewMode === "fit"
            ? computeFitZoom()
            : clampPreviewZoom(state.previewZoom || 1);
    }

    function setPreviewScrollableMode(on) {
        if (!previewBody) return;

        previewBody.style.display = on ? "block" : "flex";
        previewBody.style.alignItems = on ? "flex-start" : "center";
        previewBody.style.justifyContent = on ? "flex-start" : "center";
    }

    function updatePreviewInfoText() {
        if (!previewInfo || !previewImg || !previewImg.naturalWidth || !previewImg.naturalHeight) return;

        const { items, idx } = currentPreviewIndex();
        const pos = (idx >= 0 && items.length > 1) ? ` • ${idx + 1} / ${items.length}` : "";
        const pct = Math.round(currentPreviewZoom() * 100);

        previewInfo.textContent = `${previewImg.naturalWidth} × ${previewImg.naturalHeight} • ${pct}%${pos}`;
    }

    function isPreviewFullscreen() {
        return !!previewModal && document.fullscreenElement === previewModal;
    }

    async function enterPreviewFullscreen() {
        if (!previewModal) return;

        previewModal.classList.add("previewFullscreen");

        try {
            await previewModal.requestFullscreen();
        } catch (_) {
            previewModal.classList.remove("previewFullscreen");
        }
    }

    async function exitPreviewFullscreen() {
        if (!isPreviewFullscreen()) return;

        try {
            await document.exitFullscreen();
        } catch (_) {}
    }

    async function togglePreviewFullscreen() {
        if (isPreviewFullscreen()) {
            await exitPreviewFullscreen();
        } else {
            await enterPreviewFullscreen();
        }
    }

    function syncPreviewFullscreenUi() {
        const on = isPreviewFullscreen();

        if (!on && previewModal) {
            previewModal.classList.remove("previewFullscreen");
        }

        if (previewFullscreenBtn) {
            previewFullscreenBtn.textContent = on ? "Windowed" : "Fullscreen";
            previewFullscreenBtn.title = on ? "Exit fullscreen" : "Enter fullscreen";
        }
    }

    function isPreviewPannable() {
        if (!previewBody || !previewImg || !previewImg.naturalWidth || !previewImg.naturalHeight) {
            return false;
        }

        return currentPreviewZoom() > computeFitZoom() + 0.01;
    }

    function updatePreviewPanCursor() {
        if (!previewBody) return;

        if (previewPanState.active) {
            previewBody.style.cursor = "grabbing";
        } else if (isPreviewPannable()) {
            previewBody.style.cursor = "grab";
        } else {
            previewBody.style.cursor = "";
        }
    }

    function applyPreviewZoom(nextZoom, opts = {}) {
        if (!previewImg || !previewBody || !previewImg.naturalWidth || !previewImg.naturalHeight) return;

        const fitZoom = computeFitZoom();
        const zoom = clampPreviewZoom(nextZoom);

        if (opts.snapToFit !== false && Math.abs(zoom - fitZoom) < 0.02) {
            applyPreviewFitMode();
            return;
        }

        const bodyRect = previewBody.getBoundingClientRect();
        const oldRect = previewImg.getBoundingClientRect();
        const oldWidth = oldRect.width || (previewImg.naturalWidth * currentPreviewZoom());
        const oldHeight = oldRect.height || (previewImg.naturalHeight * currentPreviewZoom());

        const clientX = Number.isFinite(opts.clientX)
            ? opts.clientX
            : (bodyRect.left + bodyRect.width / 2);

        const clientY = Number.isFinite(opts.clientY)
            ? opts.clientY
            : (bodyRect.top + bodyRect.height / 2);

        const offsetX = previewBody.scrollLeft + (clientX - bodyRect.left);
        const offsetY = previewBody.scrollTop + (clientY - bodyRect.top);

        const relX = oldWidth > 0 ? (offsetX / oldWidth) : 0.5;
        const relY = oldHeight > 0 ? (offsetY / oldHeight) : 0.5;

        state.previewMode = "zoom";
        state.previewZoom = zoom;

        setPreviewScrollableMode(true);

        previewImg.style.maxWidth = "none";
        previewImg.style.maxHeight = "none";
        previewImg.style.width = `${Math.max(1, Math.round(previewImg.naturalWidth * zoom))}px`;
        previewImg.style.height = `${Math.max(1, Math.round(previewImg.naturalHeight * zoom))}px`;

        requestAnimationFrame(() => {
            const newRect = previewImg.getBoundingClientRect();
            const newWidth = newRect.width || (previewImg.naturalWidth * zoom);
            const newHeight = newRect.height || (previewImg.naturalHeight * zoom);

            previewBody.scrollLeft = Math.max(0, relX * newWidth - (clientX - bodyRect.left));
            previewBody.scrollTop = Math.max(0, relY * newHeight - (clientY - bodyRect.top));

            updatePreviewInfoText();
            updatePreviewPanCursor();
        });
    }
    function applyPreviewFitMode() {
        if (!previewImg) return;

        state.previewMode = "fit";
        state.previewZoom = computeFitZoom();

        setPreviewScrollableMode(false);

        if (previewBody) {
            previewBody.scrollLeft = 0;
            previewBody.scrollTop = 0;
        }

        previewImg.style.width = "auto";
        previewImg.style.height = "auto";
        previewImg.style.maxWidth = "100%";
        previewImg.style.maxHeight = "100%";

        updatePreviewInfoText();
        updatePreviewPanCursor();
    }

    function applyPreviewActualMode() {
        applyPreviewZoom(1, { snapToFit: false });
    }

    function openPreviewByIndex(nextIdx) {
        const { items } = currentPreviewIndex();
        if (!items.length) return;
        const len = items.length;
        const idx = ((nextIdx % len) + len) % len;
        openPreviewFor(items[idx]);
    }

    function openPreviewFor(item) {
        if (!item || item.type !== "file") return;

        const rel = currentRelPathFor(item);
        state.previewPath = rel;

        if (previewPath) previewPath.textContent = "/" + rel;
        if (previewInfo) previewInfo.textContent = "Loading…";

        if (previewImg) {
            previewImg.alt = item.name || "image";

            previewImg.onload = () => {
                applyPreviewFitMode();
                updatePreviewNav();
                syncPreviewFullscreenUi();
            };

            previewImg.onerror = () => {
                if (previewInfo) previewInfo.textContent = "Failed to load preview";
            };
            previewImg.draggable = false;
            previewImg.src = fileGetUrl(rel);
        }

        const wasAlreadyOpen = !!(previewModal && previewModal.classList.contains("show"));

        if (!wasAlreadyOpen) {
            placePreviewCentered();
        }

        openPreviewModal();
        updatePreviewNav();

        window.dispatchEvent(new CustomEvent("photogallery:preview-open", {
            detail: { relPath: rel }
        }));
    }

    function openPreviewModal() {
        if (!previewModal) return;
        previewModal.classList.add("show");
        previewModal.setAttribute("aria-hidden", "false");
    }

    function closePreviewModal() {
        if (!previewModal) return;

        if (isPreviewFullscreen()) {
            document.exitFullscreen().catch(() => {});
        }

        previewModal.classList.remove("previewFullscreen");
        const oldRel = state.previewPath;

        previewModal.classList.remove("show");
        previewModal.setAttribute("aria-hidden", "true");
        state.previewPath = "";

        state.previewMode = "fit";
        state.previewZoom = 1;

        if (previewBody) {
            previewBody.scrollLeft = 0;
            previewBody.scrollTop = 0;
        }

        if (previewImg) {
            previewImg.removeAttribute("src");
            previewImg.alt = "";
        }

        previewPanState.active = false;
        previewPanState.moved = false;
        updatePreviewPanCursor();

        window.dispatchEvent(new CustomEvent("photogallery:preview-close", {
            detail: { relPath: oldRel }
        }));
    }

    function placePreviewCentered() {
        if (!previewCard) return;
        previewCard.style.transform = "translateX(-50%)";
        previewCard.style.left = "50%";
        previewCard.style.top = "80px";
    }


    function clampPreviewIntoViewport() {
        if (!previewCard) return;

        const rect = previewCard.getBoundingClientRect();
        const pad = 8;

        let left = rect.left;
        let top = rect.top;

        const maxLeft = Math.max(pad, window.innerWidth - rect.width - pad);
        const maxTop = Math.max(pad, window.innerHeight - rect.height - pad);

        left = clamp(left, pad, maxLeft);
        top = clamp(top, pad, maxTop);

        previewCard.style.transform = "none";
        previewCard.style.left = `${left}px`;
        previewCard.style.top = `${top}px`;
    }

    function renderFolderGlyph() {
        const wrap = document.createElement("div");
        wrap.className = "folderGlyph";
        wrap.innerHTML = `
      <svg viewBox="0 0 64 64" width="72" height="72" aria-hidden="true">
        <path d="M8 18h16l5 6h27v22c0 4.4-3.6 8-8 8H16c-4.4 0-8-3.6-8-8V26c0-4.4 3.6-8 8-8z"
              fill="currentColor" opacity="0.18"></path>
        <path d="M8 20c0-4.4 3.6-8 8-8h13l5 6h14c4.4 0 8 3.6 8 8v4H8v-10z"
              fill="currentColor" opacity="0.34"></path>
        <rect x="8" y="22" width="48" height="30" rx="8" fill="none" stroke="currentColor" stroke-width="3"></rect>
      </svg>`;
        return wrap;
    }

    function buildStars(current, onPick) {
        const row = document.createDocumentFragment();
        for (let i = 1; i <= 5; i++) {
            const b = document.createElement("button");
            b.type = "button";
            b.className = `starBtn${i <= current ? " on" : ""}`;
            b.textContent = "★";
            b.title = `${i} star${i === 1 ? "" : "s"}`;
            b.addEventListener("click", (e) => {
                e.preventDefault();
                e.stopPropagation();
                onPick(i);
            });
            row.appendChild(b);
        }
        return row;
    }

    function updateMetaStars() {
        if (!metaStars) return;
        metaStars.innerHTML = "";
        metaStars.appendChild(buildStars(state.editingRating, (i) => {
            state.editingRating = i;
            updateMetaStars();
        }));
        const clearBtn = document.createElement("button");
        clearBtn.type = "button";
        clearBtn.className = "btn secondary";
        clearBtn.style.marginLeft = "8px";
        clearBtn.textContent = "Clear";
        clearBtn.addEventListener("click", () => {
            state.editingRating = 0;
            updateMetaStars();
        });
        metaStars.appendChild(clearBtn);
    }

    function openMetaModal() {
        if (!metaModal) return;
        placeMetaCentered();
        metaModal.classList.add("show");
        metaModal.setAttribute("aria-hidden", "false");
    }

    function closeMetaModal() {
        if (!metaModal) return;
        metaModal.classList.remove("show");
        metaModal.setAttribute("aria-hidden", "true");
        state.editingPath = "";
        suppressBrowserSaveUntil = Date.now() + 700;
    }

    async function openMetaFor(itemOrPath) {
        const rel = typeof itemOrPath === "string"
            ? itemOrPath
            : currentRelPathFor(itemOrPath);

        state.editingPath = rel;
        window.PQNAS_PHOTOGALLERY_EMBEDDED_META?.reset(rel);
        state.editingRating = 0;

        if (metaPath) metaPath.textContent = "/" + rel;
        if (metaTags) metaTags.value = "";
        if (metaNotes) metaNotes.value = "";
        if (metaInfo) metaInfo.textContent = "Loading…";
        if (metaStatus) metaStatus.textContent = "Loading…";
        const selectedImagesNow = selectedImageRelPaths();
        if (metaApplySelChk) {
            metaApplySelChk.checked =
                selectedImagesNow.length > 1 && selectedImagesNow.includes(rel);
        }
        updateMetaStars();
        refreshMetaApplySelectionUi();
        openMetaModal();

        window.dispatchEvent(new CustomEvent("photogallery:meta-open", {
            detail: { relPath: rel }
        }));

        try {
            const j = await galleryMetaGet(rel);
            const meta = j.meta || {};
            const { imageRating, keywords, description } = normalizeGalleryMeta(meta);

            state.editingRating = imageRating;
            if (metaTags) metaTags.value = keywords.join(", ");
            if (metaNotes) metaNotes.value = description;

            const sizeBytes =
                j.file && j.file.size_bytes != null
                    ? Number(j.file.size_bytes || 0)
                    : Number(meta.size_bytes || 0);

            const mtimeEpoch =
                j.file && j.file.mtime_epoch != null
                    ? Number(j.file.mtime_epoch || 0)
                    : Number(meta.mtime_epoch || 0);

            if (metaInfo) {
                metaInfo.textContent =
                    `${fmtSize(sizeBytes)} • ${fmtTime(mtimeEpoch) || "unknown time"}`;
            }

            if (metaStatus) metaStatus.textContent = "Ready.";
            updateMetaStars();
        } catch (e) {
            if (metaInfo) metaInfo.textContent = "Could not load metadata";
            if (metaStatus) metaStatus.textContent = `Error: ${String(e && e.message ? e.message : e)}`;
        }
    }

    async function saveMeta() {
        if (!state.editingPath || metaSaveInFlight) return;

        const rel = state.editingPath;
        const applyToSelection =
            !!(metaApplySelWrap && metaApplySelChk && metaApplySelChk.checked);

        let targets = applyToSelection ? selectedImageRelPaths() : [rel];

        if (!targets.includes(rel)) {
            targets = [rel, ...targets];
        }

        targets = Array.from(new Set(targets));

        const payload = {
            meta: {
                description: {
                    "x-default": String(metaNotes ? metaNotes.value : "").trim()
                },
                keywords: String(metaTags ? metaTags.value : "")
                    .split(",")
                    .map(s => s.trim())
                    .filter(Boolean),
                imageRating: Number(state.editingRating || 0)
            }
        };

        metaSaveInFlight = true;
        suppressBrowserSaveUntil = Date.now() + 1500;

        if (metaSaveBtn) {
            metaSaveBtn.disabled = true;
            metaSaveBtn.textContent = "Saving…";
        }
        if (metaStatus) {
            metaStatus.textContent =
                targets.length > 1
                    ? `Saving to ${targets.length} photos…`
                    : "Saving…";
        }

        let done = 0;
        const failed = [];

        try {
            for (const targetRel of targets) {
                try {
                    const j = await galleryMetaSet(targetRel, payload);
                    const meta = j.meta || {};
                    applyMetaToCaches(targetRel, meta);
                    done++;
                } catch (e) {
                    failed.push(`${targetRel}: ${String(e && e.message ? e.message : e)}`);
                }
            }

            renderGrid();
            window.dispatchEvent(new CustomEvent("photogallery:view-updated"));

            if (failed.length) {
                if (metaStatus) {
                    metaStatus.textContent = `Saved ${done}/${targets.length}. Failed: ${failed.length}`;
                }
                setBadge("warn", "partial");
                setStatus(`Metadata saved to ${done}/${targets.length} photo${targets.length === 1 ? "" : "s"}.`);
                console.warn("Photo Gallery saveMeta partial failures:", failed);
                return;
            }

            if (metaStatus) metaStatus.textContent = "Saved.";
            setBadge("ok", "ready");

            if (targets.length > 1) {
                setStatus(`Saved metadata to ${targets.length} photos.`);
            } else {
                setStatus(`Saved metadata: ${rel}`);
            }

            suppressBrowserSaveUntil = Date.now() + 1500;
            closeMetaModal();
        } catch (e) {
            if (metaStatus) {
                metaStatus.textContent = `Save failed: ${String(e && e.message ? e.message : e)}`;
            }
            setBadge("err", "error");
        } finally {
            metaSaveInFlight = false;
            if (metaSaveBtn) {
                metaSaveBtn.disabled = false;
                metaSaveBtn.textContent = "Save";
            }
        }
    }

    async function quickRate(item, rating) {
        const rel = currentRelPathFor(item);
        try {
            const j = await galleryMetaSet(rel, {
                meta: {
                    imageRating: Number(rating || 0)
                }
            });

            const meta = j.meta || {};
            const { imageRating } = normalizeGalleryMeta(meta);

            applyMetaToCaches(rel, meta);
            renderGrid();
            window.dispatchEvent(new CustomEvent("photogallery:view-updated"));
            setBadge("ok", "ready");
            setStatus(`Rated ${item.name}: ${imageRating}/5`);
        } catch (e) {
            setBadge("err", "error");
            setStatus(`Rating failed: ${String(e && e.message ? e.message : e)}`);
        }
    }

    function makeTile(item) {
        const tile = document.createElement("div");
        tile.className = "tile";
        tile.dataset.relPath = currentRelPathFor(item);
        tile.dataset.itemType = item.type;

        tile.tabIndex = -1;
        tile.setAttribute("role", "button");
        tile.setAttribute("aria-selected", "false");

        const thumbWrap = document.createElement("div");
        thumbWrap.className = "thumbWrap";

        if (item.type === "dir") {
            thumbWrap.appendChild(renderFolderGlyph());
        } else {
            const rel = currentRelPathFor(item);
            const capture = item && item._pg_capture;
            const rawOnly = isRawName(item.name || "") && !(capture && capture.pair_kind === "raw+jpeg");

            if (rawOnly) {
                thumbWrap.appendChild(renderRawGlyph());
            } else {
                const img = document.createElement("img");
                img.className = "thumb";
                img.loading = "lazy";
                img.decoding = "async";
                img.alt = item.name || "image";

                const reqThumbSize = Math.max(160, Number(state.thumbSize || 160) * 2);
                img.src = galleryThumbUrl(rel, reqThumbSize, item.mtime_unix || 0);
                img.onerror = () => {
                    img.onerror = null;
                    img.src = fileGetUrl(rel);
                };

                thumbWrap.appendChild(img);
            }

            if (capture && capture.pair_kind === "raw+jpeg") {
                const pairBadge = document.createElement("div");
                pairBadge.className = "pgPairBadge";
                pairBadge.textContent = "RAW+JPG";
                thumbWrap.appendChild(pairBadge);
            }
        }

        const tools = document.createElement("div");
        tools.className = "tileTools";

        if (item.type === "file") {
            const metaBtn = document.createElement("button");
            metaBtn.type = "button";
            metaBtn.className = "miniBtn";
            metaBtn.title = "Edit metadata";
            metaBtn.textContent = "✎";
            metaBtn.addEventListener("click", (e) => {
                e.preventDefault();
                e.stopPropagation();
                openMetaFor(item);
            });
            tools.appendChild(metaBtn);
        }

        thumbWrap.appendChild(tools);

        const body = document.createElement("div");
        body.className = "tileBody";

        const name = document.createElement("div");
        name.className = "name";
        name.textContent = item.name || "(unnamed)";

        const meta = document.createElement("div");
        meta.className = "meta";

        const left = document.createElement("span");
        left.textContent = item.type === "dir" ? "dir" : fmtSize(item.size_bytes || 0);

        const right = document.createElement("span");
        right.textContent = fmtTime(item.mtime_unix || 0);

        meta.appendChild(left);
        meta.appendChild(right);

        body.appendChild(name);
        body.appendChild(meta);

        if (item.type === "file") {
            const stars = document.createElement("div");
            stars.className = "starRow";
            stars.appendChild(buildStars(Number(item.rating || 0) || 0, (i) => quickRate(item, i)));
            body.appendChild(stars);

            const tagLine = document.createElement("div");
            tagLine.className = "tagLine";

            const tagPreview =
                Array.isArray(item.keywords) && item.keywords.length
                    ? item.keywords.join(", ")
                    : (item.tags_text || "");

            tagLine.textContent = tagPreview ? shorten(tagPreview, 60) : "No metadata";
            body.appendChild(tagLine);
        } else {
            const tagLine = document.createElement("div");
            tagLine.className = "tagLine";
            tagLine.textContent = "Open folder";
            body.appendChild(tagLine);
        }

        tile.appendChild(thumbWrap);
        tile.appendChild(body);
        tile.addEventListener("contextmenu", (e) => {
            e.preventDefault();
            e.stopPropagation();

            const rel = tile.dataset.relPath || "";
            if (!rel) return;

            setActiveTileRelPath(rel, { scroll: false, focus: false });

            if (selectedRelPaths.size > 1) {
                if (!selectedRelPaths.has(rel)) {
                    setSingleSelection(rel);
                    selectionAnchorRelPath = rel;
                }
            } else {
                ensureSelected(rel);
                selectionAnchorRelPath = rel;
            }

            if (selectedRelPaths.size > 1 && selectedRelPaths.has(rel)) {
                openSelectionContextMenu(e.clientX, e.clientY);
            } else if (item.type === "file") {
                openImageContextMenu(e.clientX, e.clientY, item);
            } else if (item.type === "dir") {
                openFolderContextMenu(e.clientX, e.clientY, item);
            }
        });

        tile.addEventListener("dblclick", () => {
            if (item.type === "dir") {
                setCurrentPath(currentRelPathFor(item), "folder-dblclick");
                clearSelection();
                load();
            } else {
                openPreviewFor(item);
            }
        });

        tile.addEventListener("click", (e) => {
            if (marqueeOn) return;

            const rel = tile.dataset.relPath || "";
            if (!rel) return;

            const additive = (e.ctrlKey || e.metaKey);

            if (e.shiftKey) {
                const anchor =
                    selectionAnchorRelPath ||
                    (selectedRelPaths.size ? Array.from(selectedRelPaths)[0] : rel);
                selectRange(anchor, rel, additive);
                return;
            }

            if (additive) {
                toggleSelection(rel);
                if (selectedRelPaths.has(rel)) selectionAnchorRelPath = rel;
            } else {
                setSingleSelection(rel);
                selectionAnchorRelPath = rel;
            }
        });

        return tile;
    }
    function makeBurstBlock(burst) {
        const wrap = document.createElement("div");
        wrap.className = burst.expanded ? "pgBurst pgBurstExpanded" : "pgBurst";
        wrap.dataset.burstKey = burst.key;

        const coverTile = makeTile(burst.cover);
        coverTile.classList.add("pgBurstCoverTile");

        const thumbWrap = coverTile.querySelector(".thumbWrap");
        if (thumbWrap) {
            const burstCount = Array.isArray(burst.items) ? burst.items.length : 0;

            const hasRawPair =
                Array.isArray(burst.captures) &&
                burst.captures.some((cap) => cap && cap.pair_kind === "raw+jpeg");

            const compactExpandedCover =
                burst.expanded &&
                Number(state.thumbSize || 160) <= 120 &&
                hasRawPair;

            if (!compactExpandedCover) {
                const badge = document.createElement("div");
                badge.className = "pgBurstBadge";
                badge.innerHTML = `
            <span class="pgBurstBadgeLong">Burst ${burstCount}</span>
            <span class="pgBurstBadgeShort" style="display:none;">${hasRawPair ? `RAW B${burstCount}` : `B${burstCount}`}</span>
        `;
                thumbWrap.appendChild(badge);
            }

            if (hasRawPair) {
                const pairBadge = document.createElement("div");
                pairBadge.className = "pgPairBadge";
                pairBadge.innerHTML = `
            <span class="pgPairBadgeLong">RAW+JPG</span>
            <span class="pgPairBadgeShort" style="display:none;">RAW</span>
        `;
                thumbWrap.appendChild(pairBadge);
            }

            const toggleBtn = document.createElement("button");
            toggleBtn.type = "button";
            toggleBtn.className = "pgBurstToggle";
            toggleBtn.title = burst.expanded ? "Hide burst" : "Show burst";
            toggleBtn.setAttribute("aria-label", burst.expanded ? "Hide burst" : "Show burst");
            toggleBtn.innerHTML = `
        <span class="pgBurstToggleText">${burst.expanded ? "Hide" : "Show"}</span>
        <span class="pgBurstToggleIcon" aria-hidden="true" style="display:none;">${burst.expanded ? "−" : "+"}</span>
    `;
            toggleBtn.addEventListener("click", (e) => {
                e.preventDefault();
                e.stopPropagation();
                window.PQNAS_PHOTOGALLERY?.bursts?.toggleExpanded(burst.key);
                renderGrid();
                window.dispatchEvent(new CustomEvent("photogallery:view-updated"));
            });
            thumbWrap.appendChild(toggleBtn);
        }

        wrap.appendChild(coverTile);

        if (burst.expanded) {
            const itemsWrap = document.createElement("div");
            itemsWrap.className = "pgBurstItems";

            burst.items.forEach((it, idx) => {
                if (idx === burst.coverIdx) return;
                itemsWrap.appendChild(makeTile(it));
            });

            wrap.appendChild(itemsWrap);
        }

        return wrap;
    }
    function mapItems() {
        return filteredItems().filter((it) =>
            it &&
            it.type === "file" &&
            it.has_gps &&
            it.gps_latitude != null &&
            it.gps_longitude != null
        );
    }

    function applyViewModeUi() {
        const mapOn = state.viewMode === "map";

        gridWrap?.classList.toggle("hidden", mapOn);
        mapWrap?.classList.toggle("hidden", !mapOn);

        gridBtn?.classList.toggle("active", !mapOn);
        mapBtn?.classList.toggle("active", mapOn);
    }

    function setViewMode(mode) {
        state.viewMode = mode === "map" ? "map" : "grid";

        if (state.viewMode !== "map") {
            window.PQNAS_PHOTOGALLERY?.map?.destroyMap?.();
        }

        renderGrid();
        updateViewStatus();

        if (state.viewMode === "map") {
            window.setTimeout(() => {
                try {
                    window.PQNAS_PHOTOGALLERY?.map?.runtime?.map?.invalidateSize?.();
                } catch (_) {}
            }, 0);
        }
    }

    function renderMap() {
        if (!mapCanvas) return;

        if (isSearchMode() && state.searchLoading && !state.searchLoaded) {
            mapCanvas.replaceChildren();

            const loading = document.createElement("div");
            loading.className = "emptyState";
            loading.innerHTML = `
            <div class="h">Searching subfolders…</div>
            <div class="p">Scanning the current folder and all deeper folders for photos with GPS coordinates.</div>
        `;
            mapCanvas.appendChild(loading);
            refreshFooterStats();
            return;
        }

        const items = mapItems();

        window.PQNAS_PHOTOGALLERY?.map?.render(mapCanvas, items, {
            currentRelPathFor,
            fmtTime,
            openPreviewFor,
            refreshFooterStats
        });
    }

    function escapeHtml(s) {
        return String(s || "")
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#39;");
    }

    function destroyLeafletMap() {
        if (mapRuntime.map) {
            try { mapRuntime.map.remove(); } catch (_) {}
        }
        mapRuntime.map = null;
        mapRuntime.markersLayer = null;
        mapRuntime.tileLayer = null;
    }

    function ensureLeafletLoaded() {
        if (window.L) return Promise.resolve(window.L);
        if (mapRuntime.leafletPromise) return mapRuntime.leafletPromise;

        mapRuntime.leafletPromise = new Promise((resolve, reject) => {
            const cssHref = "./leaflet.css";
            const jsSrc = "./leaflet.js";

            const hasCss = Array.from(document.querySelectorAll('link[rel="stylesheet"]'))
                .some((el) => (el.getAttribute("href") || "") === cssHref);

            if (!hasCss) {
                const link = document.createElement("link");
                link.rel = "stylesheet";
                link.href = cssHref;
                document.head.appendChild(link);
            }

            const existingScript = Array.from(document.querySelectorAll("script"))
                .find((el) => (el.getAttribute("src") || "") === jsSrc);

            if (window.L) {
                resolve(window.L);
                return;
            }

            if (existingScript) {
                existingScript.addEventListener("load", () => resolve(window.L), { once: true });
                existingScript.addEventListener("error", () => reject(new Error("Failed to load Leaflet script")), { once: true });
                return;
            }

            const script = document.createElement("script");
            script.src = jsSrc;
            script.async = true;
            script.onload = () => {
                if (window.L) resolve(window.L);
                else reject(new Error("Leaflet loaded but window.L is missing"));
            };
            script.onerror = () => reject(new Error("Failed to load Leaflet script"));
            document.head.appendChild(script);
        });

        return mapRuntime.leafletPromise;
    }

    function buildMapSideList(items, markerByPath) {
        const list = document.createElement("div");
        list.className = "mapPhotoList";

        for (const item of items) {
            const rel = currentRelPathFor(item);

            const btn = document.createElement("button");
            btn.type = "button";
            btn.className = "mapPhotoBtn";

            const main = document.createElement("div");
            main.className = "mapPhotoMain";

            const name = document.createElement("div");
            name.className = "mapPhotoName";
            name.textContent = item.name || "(unnamed)";

            const path = document.createElement("div");
            path.className = "mapPhotoPath";
            path.textContent = "/" + rel;

            const coord = document.createElement("div");
            coord.className = "mapPhotoCoord";
            coord.textContent = `${Number(item.gps_latitude).toFixed(6)}, ${Number(item.gps_longitude).toFixed(6)}`;

            const time = document.createElement("div");
            time.className = "mapPhotoTime";
            time.textContent = fmtTime(item.capture_time_unix || 0) || "no capture time";

            main.appendChild(name);
            main.appendChild(path);
            main.appendChild(coord);
            main.appendChild(time);

            btn.appendChild(main);

            btn.addEventListener("click", () => {
                const marker = markerByPath.get(rel);
                if (marker && mapRuntime.map) {
                    mapRuntime.map.setView(marker.getLatLng(), Math.max(mapRuntime.map.getZoom(), 13), { animate: true });
                    marker.openPopup();
                }
                openPreviewFor(item);
            });

            list.appendChild(btn);
        }

        return list;
    }

    function renderGrid() {
        applyViewModeUi();

        if (state.viewMode === "map") {
            renderMap();
            return;
        }

        renderGridBody();
    }

    function renderGridBody() {
        if (!gridEl) return;
        gridEl.replaceChildren();

        if (isSearchMode() && state.searchLoading && !state.searchLoaded) {
            state.activeTilePath = "";
            const loading = document.createElement("div");
            loading.className = "emptyState";
            loading.innerHTML = `
            <div class="h">Searching subfolders…</div>
            <div class="p">Scanning the current folder and all deeper folders for matching photos.</div>
        `;
            gridEl.appendChild(loading);
            refreshFooterStats();
            return;
        }

        const items = filteredItems();

        if (!items.length) {
            state.activeTilePath = "";

            const empty = document.createElement("div");
            empty.className = "emptyState";

            if (isSearchMode()) {
                empty.innerHTML = `
        <div class="h">No matching photos</div>
        <div class="p">No photos matched the current search or rating filter in this folder or its subfolders.</div>
    `;
            } else {
                empty.innerHTML = `
        <div class="h">Nothing to show</div>
        <div class="p">This folder has no subfolders or supported images that match the current filter.</div>
    `;
            }

            gridEl.appendChild(empty);
            refreshFooterStats();
            return;
        }

        if (isSearchMode()) {
            const groups = new Map();

            for (const item of items) {
                const key = groupPathForItem(item);
                if (!groups.has(key)) groups.set(key, []);
                groups.get(key).push(item);
            }

            let first = true;
            for (const [folderPath, groupItems] of groups) {
                gridEl.appendChild(makeSearchGroupHeader(folderPath, groupItems.length, first));
                const displayGroupItems =
                    window.PQNAS_PHOTOGALLERY?.bursts?.buildDisplayItems
                        ? window.PQNAS_PHOTOGALLERY.bursts.buildDisplayItems(groupItems)
                        : groupItems.map((item) => ({ kind: "item", item }));

                for (const entry of displayGroupItems) {
                    if (entry.kind === "burst") gridEl.appendChild(makeBurstBlock(entry.burst));
                    else gridEl.appendChild(makeTile(entry.item));
                }
                first = false;
            }
        } else {
            const entries = displayItems();
            for (const entry of entries) {
                if (entry.kind === "burst") gridEl.appendChild(makeBurstBlock(entry.burst));
                else gridEl.appendChild(makeTile(entry.item));
            }
        }

        applySelectionToDom();
        ensureActiveTile();
        refreshFooterStats();
    }

    async function load(forceSearch = false) {
        closeContextMenu();
        setBadge("warn", "loading…");
        setStatus("Loading gallery…");

        try {
            const j = await fetchJson(galleryListUrl(state.curPath));
            state.items = Array.isArray(j.items) ? j.items.slice() : [];
            if (state.treeStats.basePath !== state.curPath) {
                resetTreeStats();
            }
            refreshFooterStats();

            ensureTreeStats(forceSearch)
                .then(() => refreshFooterStats())
                .catch(() => refreshFooterStats());
            renderBreadcrumb();

            if (forceSearch || state.searchBasePath !== state.curPath) {
                invalidateSearchCache();
            }

            await refreshVisibleView(forceSearch);
        } catch (e) {
            const msg = String(e && e.message ? e.message : e);
            if (msg === "__stale_search__") return;

            renderBreadcrumb();
            if (gridEl) {
                gridEl.innerHTML = `
                <div class="emptyState">
                    <div class="h">Load failed</div>
                    <div class="p">${msg}</div>
                </div>
            `;
            }


            if (msg.includes("not_found") || msg.includes("directory not found")) {
                const cur = normalizeRelPath(state.curPath);
                const parent = parentPath(cur);

                if (cur && parent !== cur) {
                    console.warn("[photogallery] path not found, falling back to parent", { cur, parent });
                    setCurrentPath(parent, "load-fallback-parent");
                    try {
                        await load(forceSearch);
                        return;
                    } catch (_) {}
                }
            }
            setBadge("err", "error");
            setStatus(`Load failed: ${msg}`);
        }
    }

    refreshBtn?.addEventListener("click", () => load(true));

    upBtn?.addEventListener("click", () => {
        setCurrentPath(parentPath(state.curPath), "up-button");
        clearSelection();
        load();
    });
    gridBtn?.addEventListener("click", () => {
        setViewMode("grid");
    });

    mapBtn?.addEventListener("click", () => {
        setViewMode("map");
    });
    filterInput?.addEventListener("input", () => {
        state.filter = String(filterInput.value || "");

        window.clearTimeout(filterTimer);

        if (isSearchMode() && (!state.searchLoaded || state.searchBasePath !== state.curPath)) {
            state.searchLoading = true;
            renderGrid();
            setBadge("warn", "search…");
            setStatus("Searching subfolders…");

            filterTimer = window.setTimeout(() => {
                refreshVisibleView(false);
            }, 180);
            return;
        }

        refreshVisibleView(false);
    });

    ratingFilter?.addEventListener("change", () => {
        state.ratingFilter = Number(ratingFilter.value || "-1");
        saveRatingFilterPref();
        refreshVisibleView(false);
    });

    thumbSizeSelect?.addEventListener("change", () => {
        state.thumbSize = Number(thumbSizeSelect.value || "160");
        applyThumbSizeUi();
        saveThumbSizePref();
        renderGrid();
        window.dispatchEvent(new CustomEvent("photogallery:view-updated"));

        const count = filteredItems().length;
        const rf = Number(state.ratingFilter);
        const ratingTxt =
            rf < 0 ? "" :
                (rf === 0 ? " • unrated only" : ` • ${rf}★ only`);
        const textTxt =
            state.filter ? ` • filter: ${state.filter}` : "";

        setStatus(`Items: ${count}${ratingTxt}${textTxt} • thumbs: ${state.thumbSize}px`);
    });

    metaClose?.addEventListener("click", closeMetaModal);
    metaModal?.addEventListener("click", (e) => {
        if (e.target === metaModal) closeMetaModal();
    });
    metaSaveBtn?.addEventListener("click", saveMeta);
    metaApplySelChk?.addEventListener("change", refreshMetaApplySelectionUi);
    previewClose?.addEventListener("click", closePreviewModal);
    previewModal?.addEventListener("click", (e) => {
        if (dragState.moved) {
            dragState.moved = false;
            return;
        }
        if (e.target === previewModal) closePreviewModal();
    });

    previewFitBtn?.addEventListener("click", applyPreviewFitMode);
    previewActualBtn?.addEventListener("click", applyPreviewActualMode);
    previewMetaBtn?.addEventListener("click", () => {
        const rel = state.previewPath;
        if (rel) openMetaFor(rel);
    });

    previewFullscreenBtn?.addEventListener("click", async () => {
        await togglePreviewFullscreen();
    });

    previewPrevBtn?.addEventListener("click", () => {
        const { idx } = currentPreviewIndex();
        if (idx >= 0) openPreviewByIndex(idx - 1);
    });

    previewNextBtn?.addEventListener("click", () => {
        const { idx } = currentPreviewIndex();
        if (idx >= 0) openPreviewByIndex(idx + 1);
    });

    previewBody?.addEventListener("wheel", (e) => {
        if (!previewModal || !previewModal.classList.contains("show")) return;
        if (!previewImg || !previewImg.naturalWidth || !previewImg.naturalHeight) return;

        e.preventDefault();
        e.stopPropagation();

        const baseZoom = currentPreviewZoom();
        const factor = Math.exp(-e.deltaY * 0.0015);

        applyPreviewZoom(baseZoom * factor, {
            clientX: e.clientX,
            clientY: e.clientY,
            snapToFit: true
        });
    }, { passive: false });

    previewImg?.addEventListener("dblclick", async (e) => {
        e.preventDefault();
        e.stopPropagation();

        if (isPreviewFullscreen()) {
            await exitPreviewFullscreen();
        } else {
            await enterPreviewFullscreen();
        }
    });

    previewBody?.addEventListener("pointerdown", (e) => {
        if (e.button !== 0) return;
        if (!previewModal || !previewModal.classList.contains("show")) return;
        if (!isPreviewPannable()) return;

        previewPanState.active = true;
        previewPanState.startX = e.clientX;
        previewPanState.startY = e.clientY;
        previewPanState.scrollLeft = previewBody.scrollLeft;
        previewPanState.scrollTop = previewBody.scrollTop;
        previewPanState.moved = false;

        updatePreviewPanCursor();

        try { previewBody.setPointerCapture(e.pointerId); } catch (_) {}
        e.preventDefault();
    });

    previewBody?.addEventListener("pointermove", (e) => {
        if (!previewPanState.active || !previewBody) return;

        const dx = e.clientX - previewPanState.startX;
        const dy = e.clientY - previewPanState.startY;

        if (Math.abs(dx) > 2 || Math.abs(dy) > 2) {
            previewPanState.moved = true;
        }

        previewBody.scrollLeft = previewPanState.scrollLeft - dx;
        previewBody.scrollTop = previewPanState.scrollTop - dy;

        e.preventDefault();
    });

    function endPreviewPan() {
        if (!previewPanState.active) return;
        previewPanState.active = false;
        updatePreviewPanCursor();
    }

    previewBody?.addEventListener("pointerup", endPreviewPan);
    previewBody?.addEventListener("pointercancel", endPreviewPan);
    previewBody?.addEventListener("lostpointercapture", endPreviewPan);
    downloadSelBtn?.addEventListener("click", downloadSelectionZip);
    deleteSelBtn?.addEventListener("click", deleteSelection);
    clearSelBtn?.addEventListener("click", () => {
        clearSelection();
        setStatus("Selection cleared.");
    });


    previewHead?.addEventListener("pointerdown", (e) => {
        if (!previewCard) return;
        if (e.target && e.target.closest && e.target.closest("button")) return;

        const rect = previewCard.getBoundingClientRect();
        dragState.active = true;
        dragState.startX = e.clientX;
        dragState.startY = e.clientY;
        dragState.cardLeft = rect.left;
        dragState.cardTop = rect.top;
        dragState.moved = false;

        previewCard.style.transform = "none";
        previewCard.style.left = `${rect.left}px`;
        previewCard.style.top = `${rect.top}px`;

        try { previewHead.setPointerCapture(e.pointerId); } catch (_) {}
        e.preventDefault();
    });

    previewHead?.addEventListener("pointermove", (e) => {
        if (!dragState.active || !previewCard) return;

        const dx = e.clientX - dragState.startX;
        const dy = e.clientY - dragState.startY;

        if (Math.abs(dx) > 2 || Math.abs(dy) > 2) dragState.moved = true;

        const rect = previewCard.getBoundingClientRect();
        const pad = 8;

        const nextLeft = clamp(
            dragState.cardLeft + dx,
            pad,
            Math.max(pad, window.innerWidth - rect.width - pad)
        );

        const nextTop = clamp(
            dragState.cardTop + dy,
            pad,
            Math.max(pad, window.innerHeight - rect.height - pad)
        );

        previewCard.style.left = `${nextLeft}px`;
        previewCard.style.top = `${nextTop}px`;
    });

    function endDrag() {
        dragState.active = false;
    }

    previewHead?.addEventListener("pointerup", endDrag);
    previewHead?.addEventListener("pointercancel", endDrag);

    metaHead?.addEventListener("pointerdown", (e) => {
        if (!metaCard) return;
        if (e.target && e.target.closest && e.target.closest("button")) return;

        const rect = metaCard.getBoundingClientRect();

        metaDragState.active = true;
        metaDragState.startX = e.clientX;
        metaDragState.startY = e.clientY;
        metaDragState.cardLeft = rect.left;
        metaDragState.cardTop = rect.top;

        metaCard.style.transform = "none";
        metaCard.style.left = `${rect.left}px`;
        metaCard.style.top = `${rect.top}px`;

        try { metaHead.setPointerCapture(e.pointerId); } catch (_) {}
        e.preventDefault();
    });

    metaHead?.addEventListener("pointermove", (e) => {
        if (!metaDragState.active || !metaCard) return;

        const dx = e.clientX - metaDragState.startX;
        const dy = e.clientY - metaDragState.startY;

        const rect = metaCard.getBoundingClientRect();
        const pad = 8;

        const nextLeft = clamp(
            metaDragState.cardLeft + dx,
            pad,
            Math.max(pad, window.innerWidth - rect.width - pad)
        );

        const nextTop = clamp(
            metaDragState.cardTop + dy,
            pad,
            Math.max(pad, window.innerHeight - rect.height - pad)
        );

        metaCard.style.left = `${nextLeft}px`;
        metaCard.style.top = `${nextTop}px`;
    });

    function endMetaDrag() {
        metaDragState.active = false;
    }

    metaHead?.addEventListener("pointerup", endMetaDrag);
    metaHead?.addEventListener("pointercancel", endMetaDrag);

    window.addEventListener("resize", () => {
        if (previewModal && previewModal.classList.contains("show")) {
            clampPreviewIntoViewport();
        }
        if (metaModal && metaModal.classList.contains("show")) {
            clampMetaIntoViewport();
        }
    });
    document.addEventListener("click", (e) => {
        if (!ctxMenu || !ctxMenu.classList.contains("show")) return;
        if (e.target === ctxMenu || ctxMenu.contains(e.target)) return;
        closeContextMenu();
    });
    document.addEventListener("keydown", (e) => {
        const previewOpen = !!(previewModal && previewModal.classList.contains("show"));
        const metaOpen = !!(metaModal && metaModal.classList.contains("show"));

        // Save hotkey handler lives elsewhere; don't interfere with typing.
        if (metaOpen) {
            if (e.key === "Escape") {
                e.preventDefault();
                closeMetaModal();
                return;
            }

            if (e.code === "Space" && !isTypingTarget(e.target)) {
                e.preventDefault();
                e.stopPropagation();
                closeMetaModal();
            }
            return;
        }

        if (previewOpen) {
            if (e.key === "Escape") {
                e.preventDefault();
                closePreviewModal();
                return;
            }

            if (e.key === "ArrowLeft") {
                e.preventDefault();
                const { idx } = currentPreviewIndex();
                if (idx >= 0) openPreviewByIndex(idx - 1);
                return;
            }

            if (e.key === "ArrowRight") {
                e.preventDefault();
                const { idx } = currentPreviewIndex();
                if (idx >= 0) openPreviewByIndex(idx + 1);
            }
            return;
        }

        if (isTypingTarget(e.target)) return;

        const tiles = getRenderedTiles();
        if (!tiles.length) return;

        if (e.key === "Escape") {
            closeContextMenu();
            return;
        }

        if (e.code === "Space") {
            e.preventDefault();
            e.stopPropagation();
            openSelectedTileMetadata();
            return;
        }

        switch (e.key) {
            case "ArrowLeft":
                e.preventDefault();
                moveLinear(-1);
                return;

            case "ArrowRight":
                e.preventDefault();
                moveLinear(1);
                return;

            case "ArrowUp":
                e.preventDefault();
                moveVertical(-1);
                return;

            case "ArrowDown":
                e.preventDefault();
                moveVertical(1);
                return;

            case "PageUp":
                e.preventDefault();
                moveByPage(-1);
                return;

            case "PageDown":
                e.preventDefault();
                moveByPage(1);
                return;

            case "Home":
                e.preventDefault();
                setSingleSelection(tiles[0].dataset.relPath || "", {
                    scroll: true,
                    focus: true
                });
                return;

            case "End":
                e.preventDefault();
                setSingleSelection(tiles[tiles.length - 1].dataset.relPath || "", {
                    scroll: true,
                    focus: true
                });
                return;

            case "Enter":
                e.preventDefault();
                activateSelectedTile();
                return;
        }
    });

    window.addEventListener("scroll", closeContextMenu, true);
    window.addEventListener("resize", closeContextMenu);

    window.PQNAS_PHOTOGALLERY.getFilteredImageItems = () => filteredImageItems().slice();
    window.PQNAS_PHOTOGALLERY.currentRelPathFor = currentRelPathFor;
    window.PQNAS_PHOTOGALLERY.openPreviewFor = openPreviewFor;
    window.PQNAS_PHOTOGALLERY.getPreviewPath = () => state.previewPath;
    window.PQNAS_PHOTOGALLERY.isPreviewOpen = () =>
        !!(previewModal && previewModal.classList.contains("show"));
    window.PQNAS_PHOTOGALLERY.setStatus = setStatus;
    window.PQNAS_PHOTOGALLERY.setBadge = setBadge;
    window.PQNAS_PHOTOGALLERY.getSelectedRelPaths = () => selectedRelPathsList();
    window.PQNAS_PHOTOGALLERY.clearSelection = clearSelection;

    window.PQNAS_PHOTOGALLERY.getCurrentPath = function () {
        return state && typeof state.curPath === "string" ? state.curPath : "";
    };

    window.PQNAS_PHOTOGALLERY.getFilterState = function () {
        return {
            text: filterInput ? String(filterInput.value || "") : "",
            rating: ratingFilter ? String(ratingFilter.value || "-1") : "-1",
            thumbSize: thumbSizeSelect ? String(thumbSizeSelect.value || "160") : "160"
        };
    };

    window.PQNAS_PHOTOGALLERY.reload = async function (forceSearch = false) {
        if (typeof load === "function") {
            return await load(!!forceSearch);
        }
    };

    window.PQNAS_PHOTOGALLERY.api = window.PQNAS_PHOTOGALLERY.api || {};
    window.PQNAS_PHOTOGALLERY.api.statsUrl = function () {
        return "/api/v4/photogallery/stats";
    };

    titleLine.textContent = "Photo Gallery";
    loadRatingFilterPref();
    loadThumbSizePref();
    renderBreadcrumb();
    load();
})();