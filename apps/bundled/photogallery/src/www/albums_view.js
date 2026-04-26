(() => {
    "use strict";

    window.PQNAS_PHOTOGALLERY = window.PQNAS_PHOTOGALLERY || {};

    const state = {
        mode: "list", // list | album
        albums: [],
        currentAlbum: null,
        currentItems: [],
        loading: false,
        opts: {}
    };

    function escapeHtml(s) {
        return String(s || "")
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    function shorten(s, n = 64) {
        s = String(s || "");
        return s.length <= n ? s : s.slice(0, Math.max(0, n - 1)) + "…";
    }

    function basename(p) {
        p = String(p || "").replace(/\\/g, "/");
        const i = p.lastIndexOf("/");
        return i >= 0 ? p.slice(i + 1) : p;
    }

    async function fetchJson(url, opts = {}) {
        const r = await fetch(url, {
            credentials: "include",
            cache: "no-store",
            ...opts
        });

        const j = await r.json().catch(() => null);
        if (!r.ok || !j) {
            throw new Error(`HTTP ${r.status}`);
        }

        if (j.ok === false) {
            throw new Error(j.message || j.error || `HTTP ${r.status}`);
        }

        return j;
    }

    async function listAlbums() {
        const j = await fetchJson("/api/v4/gallery/albums/list");
        return Array.isArray(j.albums) ? j.albums : [];
    }

    async function createAlbum(name, description = "") {
        return fetchJson("/api/v4/gallery/albums/create", {
            method: "POST",
            headers: { "Content-Type": "application/json", "Accept": "application/json" },
            body: JSON.stringify({ name, description })
        });
    }

    async function listItems(albumId) {
        const j = await fetchJson(`/api/v4/gallery/albums/items?album_id=${encodeURIComponent(albumId)}`);
        return Array.isArray(j.items) ? j.items : [];
    }

    async function addItems(albumId, paths) {
        return fetchJson("/api/v4/gallery/albums/add_items", {
            method: "POST",
            headers: { "Content-Type": "application/json", "Accept": "application/json" },
            body: JSON.stringify({ album_id: albumId, paths })
        });
    }

    async function removeItems(albumId, paths) {
        return fetchJson("/api/v4/gallery/albums/remove_items", {
            method: "POST",
            headers: { "Content-Type": "application/json", "Accept": "application/json" },
            body: JSON.stringify({ album_id: albumId, paths })
        });
    }

    async function setCover(albumId, path) {
        return fetchJson("/api/v4/gallery/albums/set_cover", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Accept": "application/json"
            },
            body: JSON.stringify({
                album_id: albumId,
                path
            })
        });
    }

    async function deleteAlbum(albumId) {
        return fetchJson("/api/v4/gallery/albums/delete", {
            method: "POST",
            headers: { "Content-Type": "application/json", "Accept": "application/json" },
            body: JSON.stringify({ album_id: albumId })
        });
    }

    function appApi() {
        return window.PQNAS_PHOTOGALLERY?.app || {};
    }

    function setStatus(msg) {
        const app = appApi();
        if (typeof app.setStatus === "function") app.setStatus(msg);
    }

    function setBadge(kind, msg) {
        const app = appApi();
        if (typeof app.setBadge === "function") app.setBadge(kind, msg);
    }

    function thumbUrl(relPath) {
        const app = appApi();
        if (typeof app.galleryThumbUrl === "function") {
            return app.galleryThumbUrl(relPath, 420, 0);
        }

        const qs = new URLSearchParams();
        qs.set("path", relPath || "");
        qs.set("size", "420");
        return `/api/v4/gallery/thumb?${qs.toString()}`;
    }

    function openPreview(relPath) {
        relPath = String(relPath || "");
        if (!relPath) return;

        if (typeof state.opts.openPreviewByRelPath === "function") {
            state.opts.openPreviewByRelPath(relPath);
            return;
        }

        const app = appApi();
        if (typeof app.openPreviewPath === "function") {
            app.openPreviewPath(relPath);
            return;
        }

        setStatus("Preview is not available from Albums view.");
    }

    function toolbarHtml(title, sub, back = false, canDelete = false) {
        return `
        <div class="pgAlbumsToolbar">
            <div class="pgAlbumsTitleBlock">
                <div class="pgAlbumsTitle">${escapeHtml(title)}</div>
                <div class="pgAlbumsSub">${escapeHtml(sub || "")}</div>
            </div>
            <div class="pgAlbumsActions">
                ${back ? `<button class="btn secondary" type="button" data-pg-albums-back="1">Albums</button>` : ""}
                <button class="btn secondary" type="button" data-pg-albums-refresh="1">Refresh</button>
                <button class="btn" type="button" data-pg-albums-create="1">Create album…</button>
                ${canDelete ? `<button class="btn secondary pgAlbumDangerBtn" type="button" data-pg-albums-delete="1">Delete album…</button>` : ""}
            </div>
        </div>
    `;
    }

    function renderEmpty(host, title, msg) {
        host.innerHTML = `
            ${toolbarHtml("Albums", "Saved photo collections")}
            <div class="pgAlbumsEmpty">
                <div class="h">${escapeHtml(title)}</div>
                <div class="p">${escapeHtml(msg)}</div>
            </div>
        `;
        bindCommon(host);
    }

    function albumCardHtml(album) {
        const name = album.name || "Untitled album";
        const desc = album.description || "";
        const count = Number(album.item_count || 0);
        const cover = album.cover_path || album.cover_logical_rel_path || "";

        const coverHtml = cover
            ? `<img class="pgAlbumCoverImg" src="${escapeHtml(thumbUrl(cover))}" alt="">`
            : `<div class="pgAlbumCoverEmpty">
                   <div class="pgAlbumCoverGlyph">▦</div>
                   <div class="pgAlbumCoverHint">No cover yet</div>
               </div>`;

        return `
            <button class="pgAlbumCard" type="button" data-pg-album-id="${escapeHtml(album.album_id)}">
                <div class="pgAlbumCover">
                    ${coverHtml}
                </div>
                <div class="pgAlbumCardBody">
                    <div class="pgAlbumName">${escapeHtml(shorten(name, 80))}</div>
                    <div class="pgAlbumDesc">${escapeHtml(shorten(desc || "No description", 120))}</div>
                    <div class="pgAlbumMeta">${count} photo${count === 1 ? "" : "s"}</div>
                </div>
            </button>
        `;
    }

    function renderList(host) {
        if (!state.albums.length) {
            renderEmpty(host, "No albums yet", "Create an album, then add selected photos into it.");
            return;
        }

        host.innerHTML = `
            ${toolbarHtml("Albums", `${state.albums.length} album${state.albums.length === 1 ? "" : "s"}`)}
            <div class="pgAlbumsGrid">
                ${state.albums.map(albumCardHtml).join("")}
            </div>
        `;

        bindCommon(host);

        host.querySelectorAll("[data-pg-album-id]").forEach((btn) => {
            btn.addEventListener("click", () => {
                const id = btn.getAttribute("data-pg-album-id") || "";
                const album = state.albums.find((a) => a.album_id === id);
                if (album) openAlbum(host, album);
            });
        });
    }

    function albumItemHtml(item, album) {
        const rel = item.logical_rel_path || "";
        const cover = album?.cover_path || album?.cover_logical_rel_path || "";
        const isCover = !!cover && cover === rel;

        return `
            <div class="pgAlbumPhoto" data-pg-album-path="${escapeHtml(rel)}">
                <button class="pgAlbumThumbBtn" type="button" data-pg-open-photo="${escapeHtml(rel)}">
                    <img class="pgAlbumThumb" src="${escapeHtml(thumbUrl(rel))}" alt="">
                    ${isCover ? `<span class="pgAlbumCoverBadge">Cover</span>` : ""}
                </button>
                <div class="pgAlbumPhotoBody">
                    <div class="pgAlbumPhotoName" title="${escapeHtml(rel)}">${escapeHtml(shorten(basename(rel), 48))}</div>
                    <div class="pgAlbumPhotoPath">${escapeHtml(shorten(rel, 80))}</div>
                    <div class="pgAlbumPhotoActions">
                        <button
                            class="btn secondary pgAlbumCoverBtn${isCover ? " isCover" : ""}"
                            type="button"
                            data-pg-set-cover="${escapeHtml(rel)}"
                            ${isCover ? "disabled" : ""}
                        >${isCover ? "Cover photo" : "Set as cover"}</button>
                        <button class="btn secondary pgAlbumRemoveBtn" type="button" data-pg-remove-photo="${escapeHtml(rel)}">Remove</button>
                    </div>
                </div>
            </div>
        `;
    }

    function renderAlbum(host) {
        const album = state.currentAlbum;
        const items = state.currentItems || [];

        if (!album) {
            state.mode = "list";
            renderList(host);
            return;
        }

        host.innerHTML = `
            ${toolbarHtml(album.name || "Album", `${items.length} photo${items.length === 1 ? "" : "s"} · ${album.description || ""}`, true, true)}
            ${
            items.length
                ? `<div class="pgAlbumPhotos">${items.map((item) => albumItemHtml(item, album)).join("")}</div>`
                : `<div class="pgAlbumsEmpty"><div class="h">Album is empty</div><div class="p">Select photos in Grid view and choose “Add selected to album…”.</div></div>`
        }
        `;

        bindCommon(host);

        host.querySelectorAll("[data-pg-open-photo]").forEach((btn) => {
            btn.addEventListener("click", () => openPreview(btn.getAttribute("data-pg-open-photo") || ""));
        });
        host.querySelectorAll("[data-pg-set-cover]").forEach((btn) => {
            btn.addEventListener("click", async (ev) => {
                ev.stopPropagation();

                const rel = btn.getAttribute("data-pg-set-cover") || "";
                if (!rel || !album.album_id) return;

                try {
                    setBadge("warn", "working…");
                    setStatus(`Setting album cover: ${basename(rel)}…`);

                    const r = await setCover(album.album_id, rel);

                    const fresh = await listAlbums();
                    state.albums = fresh;
                    state.currentAlbum =
                        fresh.find((a) => a.album_id === album.album_id) ||
                        r.album ||
                        {
                            ...album,
                            cover_path: rel,
                            cover_logical_rel_path: rel
                        };

                    renderAlbum(host);

                    setBadge("ok", "ready");
                    setStatus(`Album cover set: ${basename(rel)}`);
                } catch (e) {
                    setBadge("err", "error");
                    setStatus(`Set cover failed: ${String(e && e.message ? e.message : e)}`);
                }
            });
        });
        host.querySelectorAll("[data-pg-remove-photo]").forEach((btn) => {
            btn.addEventListener("click", async (ev) => {
                ev.stopPropagation();

                const rel = btn.getAttribute("data-pg-remove-photo") || "";
                if (!rel || !album.album_id) return;

                if (!confirm(`Remove from album?\n\n${rel}`)) return;

                try {
                    setBadge("warn", "working…");
                    setStatus(`Removing ${basename(rel)} from album…`);
                    await removeItems(album.album_id, [rel]);
                    state.currentItems = await listItems(album.album_id);

                    const fresh = await listAlbums();
                    state.albums = fresh;
                    state.currentAlbum = fresh.find((a) => a.album_id === album.album_id) || album;

                    renderAlbum(host);
                    setBadge("ok", "ready");
                    setStatus(`Removed from album: ${basename(rel)}`);
                } catch (e) {
                    setBadge("err", "error");
                    setStatus(`Remove failed: ${String(e && e.message ? e.message : e)}`);
                }
            });
        });
    }
    function openCreateAlbumModal(opts = {}) {
        const defaultName = String(opts.defaultName || "New album");

        return new Promise((resolve) => {
            const backdrop = document.createElement("div");
            backdrop.className = "pgAlbumPickerBackdrop";
            backdrop.innerHTML = `
            <div class="pgAlbumPickerCard" role="dialog" aria-modal="true">
                <div class="pgAlbumPickerHead">
                    <div>
                        <div class="pgAlbumPickerTitle">Create album</div>
                        <div class="pgAlbumPickerSub">Create a new photo collection</div>
                    </div>
                    <button class="btn secondary" type="button" data-pg-create-close>Close</button>
                </div>

                <div class="pgAlbumPickerBody">
                    <div class="formGrid">
                        <div class="label">Name</div>
                        <div>
                            <input
                                class="field"
                                type="text"
                                data-pg-create-name
                                placeholder="Album name"
                                value="${escapeHtml(defaultName)}"
                            >
                        </div>

                        <div class="label">Description</div>
                        <div>
                            <textarea
                                class="textarea"
                                data-pg-create-description
                                placeholder="Optional description"
                                style="min-height:90px;"
                            ></textarea>
                        </div>
                    </div>
                </div>

                <div class="pgAlbumPickerFoot">
                    <button class="btn secondary" type="button" data-pg-create-cancel>Cancel</button>
                    <button class="btn" type="button" data-pg-create-ok>Create album</button>
                </div>
            </div>
        `;

            document.body.appendChild(backdrop);

            const nameInput = backdrop.querySelector("[data-pg-create-name]");
            const descInput = backdrop.querySelector("[data-pg-create-description]");

            function close(value) {
                try {
                    backdrop.remove();
                } catch (_) {}
                resolve(value || null);
            }

            function submit() {
                const name = String(nameInput?.value || "").trim();
                const description = String(descInput?.value || "").trim();

                if (!name) {
                    nameInput?.focus();
                    return;
                }

                close({ name, description });
            }

            backdrop.addEventListener("click", (ev) => {
                const t = ev.target;

                if (
                    t === backdrop ||
                    t.closest("[data-pg-create-close]") ||
                    t.closest("[data-pg-create-cancel]")
                ) {
                    close(null);
                    return;
                }

                if (t.closest("[data-pg-create-ok]")) {
                    submit();
                }
            });

            backdrop.addEventListener("keydown", (ev) => {
                if (ev.key === "Escape") {
                    ev.preventDefault();
                    close(null);
                    return;
                }

                if (ev.key === "Enter" && (ev.ctrlKey || ev.metaKey)) {
                    ev.preventDefault();
                    submit();
                }
            });

            window.setTimeout(() => {
                nameInput?.focus();
                nameInput?.select?.();
            }, 0);
        });
    }
    function bindCommon(host) {
        host.querySelector("[data-pg-albums-create]")?.addEventListener("click", async () => {
            const picked = await openCreateAlbumModal({ defaultName: "New album" });
            if (!picked) return;

            try {
                setBadge("warn", "working…");
                setStatus("Creating album…");

                await createAlbum(picked.name, picked.description);

                state.albums = await listAlbums();
                state.mode = "list";
                state.currentAlbum = null;
                state.currentItems = [];

                renderList(host);

                setBadge("ok", "ready");
                setStatus(`Created album: ${picked.name}`);
            } catch (e) {
                setBadge("err", "error");
                setStatus(`Create album failed: ${String(e && e.message ? e.message : e)}`);
            }
        });

        host.querySelector("[data-pg-albums-refresh]")?.addEventListener("click", () => {
            render(host, { force: true });
        });

        host.querySelector("[data-pg-albums-back]")?.addEventListener("click", () => {
            state.mode = "list";
            state.currentAlbum = null;
            state.currentItems = [];
            renderList(host);
        });
        host.querySelector("[data-pg-albums-delete]")?.addEventListener("click", async () => {
            const album = state.currentAlbum;
            if (!album || !album.album_id) return;

            const name = album.name || album.album_id;
            if (!confirm(`Delete album?\n\n${name}\n\nThis removes the album only. Photos stay in your gallery.`)) {
                return;
            }

            try {
                setBadge("warn", "working…");
                setStatus(`Deleting album: ${name}…`);

                await deleteAlbum(album.album_id);

                state.albums = await listAlbums();
                state.mode = "list";
                state.currentAlbum = null;
                state.currentItems = [];

                renderList(host);

                setBadge("ok", "ready");
                setStatus(`Deleted album: ${name}`);
            } catch (e) {
                setBadge("err", "error");
                setStatus(`Delete album failed: ${String(e && e.message ? e.message : e)}`);
            }
        });
    }

    async function openAlbum(host, album) {
        try {
            setBadge("warn", "loading…");
            setStatus(`Opening album: ${album.name || album.album_id}`);
            state.mode = "album";
            state.currentAlbum = album;
            state.currentItems = await listItems(album.album_id);
            renderAlbum(host);
            setBadge("ok", "ready");
            setStatus(`Album: ${album.name || album.album_id}`);
        } catch (e) {
            setBadge("err", "error");
            setStatus(`Album load failed: ${String(e && e.message ? e.message : e)}`);
        }
    }

    async function render(host, opts = {}) {
        if (!host) return;

        state.opts = opts || {};

        if (state.loading) return;
        state.loading = true;

        host.innerHTML = `
            <div class="pgAlbumsEmpty">
                <div class="h">Loading albums…</div>
                <div class="p">Reading saved photo collections.</div>
            </div>
        `;

        try {
            setBadge("warn", "loading…");

            if (opts.force || !state.albums.length) {
                state.albums = await listAlbums();
            }

            if (state.mode === "album" && state.currentAlbum) {
                state.currentItems = await listItems(state.currentAlbum.album_id);
                renderAlbum(host);
            } else {
                state.mode = "list";
                renderList(host);
            }

            setBadge("ok", "ready");
            setStatus("Albums ready.");
        } catch (e) {
            host.innerHTML = `
                <div class="pgAlbumsEmpty">
                    <div class="h">Albums failed to load</div>
                    <div class="p">${escapeHtml(String(e && e.message ? e.message : e))}</div>
                </div>
            `;
            setBadge("err", "error");
            setStatus(`Albums failed: ${String(e && e.message ? e.message : e)}`);
        } finally {
            state.loading = false;
        }
    }

    async function addSelected(paths) {
        paths = Array.isArray(paths) ? paths.filter(Boolean) : [];
        if (!paths.length) {
            alert("Select one or more photos first.");
            return;
        }

        try {
            let albums = await listAlbums();

            if (!albums.length) {
                const name = prompt("No albums yet. Create album name:", "New album");
                if (!name || !name.trim()) return;

                const created = await createAlbum(name.trim(), "");
                if (created && created.album) {
                    albums = [created.album];
                } else {
                    albums = await listAlbums();
                }
            }

            const lines = albums.map((a, i) => `${i + 1}. ${a.name || a.album_id}`).join("\n");
            const choice = prompt(
                `Add ${paths.length} photo${paths.length === 1 ? "" : "s"} to which album?\n\n${lines}\n\nType number, or type a new album name:`,
                "1"
            );

            if (!choice || !choice.trim()) return;

            let album = null;
            const n = Number(choice.trim());
            if (Number.isInteger(n) && n >= 1 && n <= albums.length) {
                album = albums[n - 1];
            } else {
                const created = await createAlbum(choice.trim(), "");
                album = created.album || null;
            }

            if (!album || !album.album_id) {
                throw new Error("album not selected");
            }

            setBadge("warn", "working…");
            setStatus(`Adding ${paths.length} photo${paths.length === 1 ? "" : "s"} to album…`);

            await addItems(album.album_id, paths);

            state.albums = await listAlbums();
            if (state.currentAlbum && state.currentAlbum.album_id === album.album_id) {
                state.currentAlbum = state.albums.find((a) => a.album_id === album.album_id) || state.currentAlbum;
                state.currentItems = await listItems(album.album_id);
            }

            setBadge("ok", "ready");
            setStatus(`Added ${paths.length} photo${paths.length === 1 ? "" : "s"} to album: ${album.name || album.album_id}`);
        } catch (e) {
            setBadge("err", "error");
            setStatus(`Add to album failed: ${String(e && e.message ? e.message : e)}`);
        }
    }

    function resetToList() {
        state.mode = "list";
        state.currentAlbum = null;
        state.currentItems = [];
    }

    window.PQNAS_PHOTOGALLERY.albumsView = {
        render,
        resetToList,
        refresh(host) {
            return render(host, { force: true });
        }
    };
})();