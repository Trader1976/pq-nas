(() => {
    "use strict";

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
    const filterInput = el("filterInput");
    const refreshBtn = el("refreshBtn");
    const upBtn = el("upBtn");
    const gridEl = el("grid");
    const ctxMenu = el("ctxMenu");

    const metaModal = el("metaModal");
    const metaClose = el("metaClose");
    const metaPath = el("metaPath");
    const metaStars = el("metaStars");
    const metaTags = el("metaTags");
    const metaNotes = el("metaNotes");
    const metaInfo = el("metaInfo");
    const metaStatus = el("metaStatus");
    const metaSaveBtn = el("metaSaveBtn");

    const previewModal = el("previewModal");
    const previewCard = el("previewCard");
    const previewHead = el("previewHead");
    const previewPath = el("previewPath");
    const previewInfo = el("previewInfo");
    const previewImg = el("previewImg");
    const previewPrevBtn = el("previewPrevBtn");
    const previewNextBtn = el("previewNextBtn");
    const previewFitBtn = el("previewFitBtn");
    const previewActualBtn = el("previewActualBtn");
    const previewMetaBtn = el("previewMetaBtn");
    const previewClose = el("previewClose");

    const metaCard = el("metaCard");
    const metaHead = el("metaHead");

    const state = {
        curPath: "",
        items: [],
        filter: "",
        editingPath: "",
        editingRating: 0,
        previewPath: "",
        previewMode: "fit"
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

    function currentRelPathFor(item) {
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

    function escapeAttr(s) {
        return String(s || "").replace(/"/g, "&quot;");
    }

    function fileGetUrl(relPath) {
        return `/api/v4/files/get?path=${encodeURIComponent(relPath || "")}`;
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
            await load();
        } catch (e) {
            setBadge("err", "error");
            setStatus(`Rename failed: ${String(e && e.message ? e.message : e)}`);
        }
    }

    async function deleteImage(item) {
        if (!item || item.type !== "file") return;

        const rel = currentRelPathFor(item);
        const ok = confirm(`Delete image?\n\n${rel}\n\nThis cannot be undone.`);
        if (!ok) return;

        setBadge("warn", "working…");
        setStatus(`Deleting ${item.name}…`);

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
            setStatus(`Deleted: ${item.name}`);
            await load();
        } catch (e) {
            setBadge("err", "error");
            setStatus(`Delete failed: ${String(e && e.message ? e.message : e)}`);
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
            await load();
        } catch (e) {
            setBadge("err", "error");
            setStatus(`Folder rename failed: ${String(e && e.message ? e.message : e)}`);
        }
    }

    async function deleteFolder(item) {
        if (!item || item.type !== "dir") return;

        const rel = currentRelPathFor(item);
        const ok = confirm(`Delete folder?\n\n${rel}\n\nThis removes the folder recursively and cannot be undone.`);
        if (!ok) return;

        setBadge("warn", "working…");
        setStatus(`Deleting folder ${item.name}…`);

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
            setStatus(`Deleted folder: ${item.name}`);
            await load();
        } catch (e) {
            setBadge("err", "error");
            setStatus(`Folder delete failed: ${String(e && e.message ? e.message : e)}`);
        }
    }

    function openFolderContextMenu(x, y, item) {
        if (!ctxMenu || !item || item.type !== "dir") return;

        ctxMenu.innerHTML = "";
        ctxMenu.appendChild(menuItem("Open", () => {
            state.curPath = currentRelPathFor(item);
            load();
        }));
        ctxMenu.appendChild(menuSep());
        ctxMenu.appendChild(menuItem("Rename…", () => renameFolder(item)));
        ctxMenu.appendChild(menuItem("Delete…", () => deleteFolder(item), { danger: true }));

        placeContextMenu(x, y);
    }
    function openImageContextMenu(x, y, item) {
        if (!ctxMenu || !item || item.type !== "file") return;

        ctxMenu.innerHTML = "";
        ctxMenu.appendChild(menuItem("Open preview", () => openPreviewFor(item)));
        ctxMenu.appendChild(menuItem("Edit metadata…", () => openMetaFor(item)));
        ctxMenu.appendChild(menuSep());
        ctxMenu.appendChild(menuItem("Rename…", () => renameImage(item)));
        ctxMenu.appendChild(menuItem("Delete…", () => deleteImage(item), { danger: true }));

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
    function renderBreadcrumb() {
        if (!pathLine) return;
        pathLine.replaceChildren();

        const root = document.createElement("span");
        root.className = "crumb";
        root.textContent = "/";
        root.title = "Go to root";
        root.addEventListener("click", () => {
            state.curPath = "";
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
                    state.curPath = target;
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

    function filteredItems() {
        const q = String(state.filter || "").trim().toLowerCase();
        const items = sortItems(state.items);

        if (!q) return items;

        return items.filter((it) => {
            const hay = [
                it.name || "",
                it.tags_text || "",
                it.notes_text || ""
            ].join(" ").toLowerCase();
            return hay.includes(q);
        });
    }

    function filteredImageItems() {
        return filteredItems().filter((it) => it.type === "file");
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

    function applyPreviewFitMode() {
        state.previewMode = "fit";
        if (!previewImg) return;
        previewImg.style.maxWidth = "100%";
        previewImg.style.maxHeight = "100%";
        previewImg.style.width = "auto";
        previewImg.style.height = "auto";
    }

    function applyPreviewActualMode() {
        state.previewMode = "actual";
        if (!previewImg) return;
        previewImg.style.maxWidth = "none";
        previewImg.style.maxHeight = "none";
        previewImg.style.width = "auto";
        previewImg.style.height = "auto";
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
                const { items, idx } = currentPreviewIndex();
                const pos = (idx >= 0 && items.length > 1) ? ` • ${idx + 1} / ${items.length}` : "";
                if (previewInfo) {
                    previewInfo.textContent = `${previewImg.naturalWidth} × ${previewImg.naturalHeight}${pos}`;
                }
                updatePreviewNav();
            };
            previewImg.onerror = () => {
                if (previewInfo) previewInfo.textContent = "Failed to load preview";
            };
            previewImg.src = fileGetUrl(rel);
        }

        applyPreviewFitMode();
        placePreviewCentered();
        openPreviewModal();
        updatePreviewNav();
    }

    function openPreviewModal() {
        if (!previewModal) return;
        previewModal.classList.add("show");
        previewModal.setAttribute("aria-hidden", "false");
    }

    function closePreviewModal() {
        if (!previewModal) return;
        previewModal.classList.remove("show");
        previewModal.setAttribute("aria-hidden", "true");
        state.previewPath = "";
        if (previewImg) {
            previewImg.removeAttribute("src");
            previewImg.alt = "";
        }
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
        updateMetaStars();
        openMetaModal();

        try {
            const j = await galleryMetaGet(rel);
            const meta = j.meta || {};
            state.editingRating = Number(meta.rating || 0) || 0;
            if (metaTags) metaTags.value = String(meta.tags_text || "");
            if (metaNotes) metaNotes.value = String(meta.notes_text || "");
            if (metaInfo) {
                metaInfo.textContent =
                    `${fmtSize(meta.size_bytes || 0)} • ${fmtTime(meta.mtime_epoch || 0) || "unknown time"}`;
            }
            if (metaStatus) metaStatus.textContent = "Ready.";
            updateMetaStars();
        } catch (e) {
            if (metaInfo) metaInfo.textContent = "Could not load metadata";
            if (metaStatus) metaStatus.textContent = `Error: ${String(e && e.message ? e.message : e)}`;
        }
    }

    async function saveMeta() {
        if (!state.editingPath) return;

        const rel = state.editingPath;
        const payload = {
            rating: Number(state.editingRating || 0),
            tags_text: String(metaTags ? metaTags.value : ""),
            notes_text: String(metaNotes ? metaNotes.value : "")
        };

        if (metaStatus) metaStatus.textContent = "Saving…";

        try {
            const j = await galleryMetaSet(rel, payload);
            const meta = j.meta || {};

            const item = state.items.find((it) => currentRelPathFor(it) === rel);
            if (item) {
                item.rating = Number(meta.rating || 0) || 0;
                item.tags_text = String(meta.tags_text || "");
                item.notes_text = String(meta.notes_text || "");
                if (meta.size_bytes != null) item.size_bytes = Number(meta.size_bytes || 0);
                if (meta.mtime_epoch != null) item.mtime_unix = Number(meta.mtime_epoch || 0);
            }

            if (metaStatus) metaStatus.textContent = "Saved.";
            renderGrid();
            setBadge("ok", "ready");
            setStatus(`Saved metadata: ${rel}`);
        } catch (e) {
            if (metaStatus) metaStatus.textContent = `Save failed: ${String(e && e.message ? e.message : e)}`;
            setBadge("err", "error");
        }
    }

    async function quickRate(item, rating) {
        const rel = currentRelPathFor(item);
        try {
            const j = await galleryMetaSet(rel, { rating });
            const meta = j.meta || {};
            item.rating = Number(meta.rating || 0) || 0;
            item.tags_text = String(meta.tags_text || item.tags_text || "");
            item.notes_text = String(meta.notes_text || item.notes_text || "");
            renderGrid();
            setBadge("ok", "ready");
            setStatus(`Rated ${item.name}: ${item.rating}/5`);
        } catch (e) {
            setBadge("err", "error");
            setStatus(`Rating failed: ${String(e && e.message ? e.message : e)}`);
        }
    }

    function makeTile(item) {
        const tile = document.createElement("div");
        tile.className = "tile";

        const thumbWrap = document.createElement("div");
        thumbWrap.className = "thumbWrap";

        if (item.type === "dir") {
            thumbWrap.appendChild(renderFolderGlyph());
        } else {
            const img = document.createElement("img");
            img.className = "thumb";
            img.loading = "lazy";
            img.alt = item.name || "image";
            img.src = fileGetUrl(currentRelPathFor(item));
            thumbWrap.appendChild(img);
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
            tagLine.textContent = item.tags_text ? shorten(item.tags_text, 60) : "No metadata";
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

            if (item.type === "file") {
                openImageContextMenu(e.clientX, e.clientY, item);
            } else if (item.type === "dir") {
                openFolderContextMenu(e.clientX, e.clientY, item);
            }
        });
        tile.addEventListener("dblclick", () => {
            if (item.type === "dir") {
                state.curPath = currentRelPathFor(item);
                load();
            } else {
                openPreviewFor(item);
            }
        });

        tile.addEventListener("click", () => {
            if (item.type === "dir") {
                state.curPath = currentRelPathFor(item);
                load();
            } else {
                openPreviewFor(item);
            }
        });

        return tile;
    }

    function renderGrid() {
        if (!gridEl) return;
        gridEl.replaceChildren();

        const items = filteredItems();
        if (!items.length) {
            const empty = document.createElement("div");
            empty.className = "emptyState";
            empty.innerHTML = `
        <div class="h">Nothing to show</div>
        <div class="p">This folder has no subfolders or supported images that match the current filter.</div>
      `;
            gridEl.appendChild(empty);
            return;
        }

        for (const item of items) {
            gridEl.appendChild(makeTile(item));
        }
    }

    async function load() {
        closeContextMenu();
        setBadge("warn", "loading…");
        setStatus("Loading gallery…");

        try {
            const j = await fetchJson(galleryListUrl(state.curPath));
            state.items = Array.isArray(j.items) ? j.items.slice() : [];
            renderBreadcrumb();
            renderGrid();

            const count = filteredItems().length;
            setBadge("ok", "ready");
            setStatus(`Items: ${count}`);
        } catch (e) {
            renderBreadcrumb();
            if (gridEl) {
                gridEl.innerHTML = `
          <div class="emptyState">
            <div class="h">Load failed</div>
            <div class="p">${String(e && e.message ? e.message : e)}</div>
          </div>
        `;
            }
            setBadge("err", "error");
            setStatus(`Load failed: ${String(e && e.message ? e.message : e)}`);
        }
    }

    refreshBtn?.addEventListener("click", () => load());

    upBtn?.addEventListener("click", () => {
        state.curPath = parentPath(state.curPath);
        load();
    });

    filterInput?.addEventListener("input", () => {
        state.filter = String(filterInput.value || "");
        renderGrid();
        setStatus(`Items: ${filteredItems().length}`);
    });

    metaClose?.addEventListener("click", closeMetaModal);
    metaModal?.addEventListener("click", (e) => {
        if (e.target === metaModal) closeMetaModal();
    });
    metaSaveBtn?.addEventListener("click", saveMeta);

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

    previewPrevBtn?.addEventListener("click", () => {
        const { idx } = currentPreviewIndex();
        if (idx >= 0) openPreviewByIndex(idx - 1);
    });

    previewNextBtn?.addEventListener("click", () => {
        const { idx } = currentPreviewIndex();
        if (idx >= 0) openPreviewByIndex(idx + 1);
    });

    document.addEventListener("keydown", (e) => {
        const previewOpen = !!(previewModal && previewModal.classList.contains("show"));
        const metaOpen = !!(metaModal && metaModal.classList.contains("show"));

        if (e.key === "Escape") {
            if (metaOpen) {
                e.preventDefault();
                closeMetaModal();
                return;
            }
            if (previewOpen) {
                e.preventDefault();
                closePreviewModal();
            }
            return;
        }

        if (!previewOpen) return;

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
        if (e.key === "Escape") {
            closeContextMenu();
        }
    });

    window.addEventListener("scroll", closeContextMenu, true);
    window.addEventListener("resize", closeContextMenu);
    titleLine.textContent = "Photo Gallery";
    renderBreadcrumb();
    load();
})();