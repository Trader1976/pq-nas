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

    function albumT(key, params, fallback) {
        try {
            const api = window.PQNAS_I18N;
            if (api && typeof api.t === "function") {
                return api.t(key, params || null, fallback);
            }
        } catch (_) {}

        let out = String(fallback || key || "");
        const p = params || {};
        for (const name of Object.keys(p)) {
            out = out.split(`{${name}}`).join(String(p[name]));
        }
        return out;
    }

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

    let albumCtxMenu = null;
    let albumCtxBound = false;

    function ensureAlbumContextMenu() {
        if (albumCtxMenu) return albumCtxMenu;

        albumCtxMenu = document.createElement("div");
        albumCtxMenu.className = "ctxMenu pgAlbumCtxMenu";
        albumCtxMenu.setAttribute("aria-hidden", "true");
        document.body.appendChild(albumCtxMenu);

        if (!albumCtxBound) {
            albumCtxBound = true;

            document.addEventListener("click", () => closeAlbumContextMenu(), true);
            document.addEventListener("keydown", (ev) => {
                if (ev.key === "Escape") closeAlbumContextMenu();
            }, true);
            window.addEventListener("resize", () => closeAlbumContextMenu());
            window.addEventListener("scroll", () => closeAlbumContextMenu(), true);
        }

        return albumCtxMenu;
    }

    function closeAlbumContextMenu() {
        if (!albumCtxMenu) return;
        albumCtxMenu.classList.remove("show");
        albumCtxMenu.setAttribute("aria-hidden", "true");
        albumCtxMenu.innerHTML = "";
    }

    function albumMenuItem(label, onClick, opts = {}) {
        const b = document.createElement("button");
        b.type = "button";
        b.className = `ctxItem pgAlbumCtxItem${opts.danger ? " danger" : ""}`;
        b.textContent = label;

        if (opts.disabled) {
            b.disabled = true;
            b.classList.add("disabled");
        } else {
            b.addEventListener("click", (ev) => {
                ev.preventDefault();
                ev.stopPropagation();
                closeAlbumContextMenu();
                onClick();
            });
        }

        return b;
    }

    function albumMenuSep() {
        const d = document.createElement("div");
        d.className = "ctxSep pgAlbumCtxSep";
        return d;
    }

    function placeAlbumContextMenu(x, y) {
        const menu = ensureAlbumContextMenu();

        menu.style.left = "0px";
        menu.style.top = "0px";
        menu.classList.add("show");

        const rect = menu.getBoundingClientRect();
        const pad = 8;

        const nx = Math.max(pad, Math.min(x, window.innerWidth - rect.width - pad));
        const ny = Math.max(pad, Math.min(y, window.innerHeight - rect.height - pad));

        menu.style.left = `${nx}px`;
        menu.style.top = `${ny}px`;
        menu.setAttribute("aria-hidden", "false");
    }

    function backToAlbumList(host) {
        state.mode = "list";
        state.currentAlbum = null;
        state.currentItems = [];
        renderList(host);
    }

    async function createAlbumFromUi(host) {
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
    }


    function openAlbumConfirmModal(opts = {}) {
        return new Promise((resolve) => {
            const options = opts || {};
            const backdrop = document.createElement("div");
            backdrop.className = "pgAlbumPickerBackdrop";

            const dangerStyle = options.danger
                ? ' style="border-color:rgba(var(--fail-rgb),0.45);background:rgba(var(--fail-rgb),0.14);"'
                : "";

            backdrop.innerHTML = `
            <div class="pgAlbumPickerCard" role="dialog" aria-modal="true">
                <div class="pgAlbumPickerHead">
                    <div>
                        <div class="pgAlbumPickerTitle">${escapeHtml(options.title || "Confirm action")}</div>
                        <div class="pgAlbumPickerSub">${escapeHtml(options.subtitle || "")}</div>
                    </div>
                    <button class="btn secondary" type="button" data-pg-confirm-close>Close</button>
                </div>

                <div class="pgAlbumPickerBody">
                    <div class="formGrid">
                        ${(Array.isArray(options.rows) ? options.rows : []).map((row) => `
                            <div class="label">${escapeHtml(row.label || "")}</div>
                            <div class="${row.mono ? "mono" : ""}">${escapeHtml(row.value || "")}</div>
                        `).join("")}
                        ${options.note ? `
                            <div class="label">Note</div>
                            <div>${escapeHtml(options.note)}</div>
                        ` : ""}
                    </div>
                </div>

                <div class="pgAlbumPickerFoot">
                    <button class="btn secondary" type="button" data-pg-confirm-cancel>${escapeHtml(options.cancelText || "Cancel")}</button>
                    <button class="btn" type="button" data-pg-confirm-ok${dangerStyle}>${escapeHtml(options.confirmText || "OK")}</button>
                </div>
            </div>
        `;

            document.body.appendChild(backdrop);

            function close(value) {
                try {
                    backdrop.remove();
                } catch (_) {}
                resolve(!!value);
            }

            backdrop.addEventListener("click", (ev) => {
                const t = ev.target;

                if (
                    t === backdrop ||
                    t.closest("[data-pg-confirm-close]") ||
                    t.closest("[data-pg-confirm-cancel]")
                ) {
                    close(false);
                    return;
                }

                if (t.closest("[data-pg-confirm-ok]")) {
                    close(true);
                }
            });

            backdrop.addEventListener("keydown", (ev) => {
                if (ev.key === "Escape") {
                    ev.preventDefault();
                    close(false);
                    return;
                }

                if (ev.key === "Enter") {
                    ev.preventDefault();
                    close(true);
                }
            });

            window.setTimeout(() => {
                const btn = backdrop.querySelector(options.danger ? "[data-pg-confirm-cancel]" : "[data-pg-confirm-ok]");
                btn?.focus?.();
            }, 0);
        });
    }

    async function deleteAlbumFromUi(host, album) {
        if (!album || !album.album_id) return;

        const name = album.name || album.album_id;
        const ok = await openAlbumConfirmModal({
            title: albumT("photogallery.albums.delete_album_title", null, "Delete album?"),
            subtitle: albumT("photogallery.albums.delete_album_subtitle", null, "This removes the album collection only."),
            rows: [
                { label: albumT("photogallery.albums.album", null, "Album"), value: name, mono: true },
            ],
            note: albumT("photogallery.albums.delete_album_note", null, "Photos stay in your gallery. Only the album container is deleted."),
            confirmText: albumT("photogallery.albums.delete_album", null, "Delete album"),
            cancelText: albumT("common.cancel", null, "Cancel"),
            danger: true,
        });
        if (!ok) return;

        try {
            setBadge("warn", "working…");
            setStatus(albumT("photogallery.albums.deleting_album", { album: name }, "Deleting album: {album}…"));

            await deleteAlbum(album.album_id);

            state.albums = await listAlbums();
            state.mode = "list";
            state.currentAlbum = null;
            state.currentItems = [];

            renderList(host);

            setBadge("ok", "ready");
            setStatus(albumT("photogallery.albums.deleted_album", { album: name }, "Deleted album: {album}"));
        } catch (e) {
            setBadge("err", "error");
            setStatus(albumT("photogallery.albums.delete_failed", { error: String(e && e.message ? e.message : e) }, "Delete album failed: {error}"));
        }
    }

    async function setAlbumCoverFromUi(host, album, rel) {
        if (!album || !album.album_id || !rel) return;

        try {
            setBadge("warn", "working…");
            setStatus(albumT("photogallery.albums.setting_cover", { name: basename(rel) }, "Setting album cover: {name}…"));

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
            setStatus(albumT("photogallery.albums.cover_set", { name: basename(rel) }, "Album cover set: {name}"));
        } catch (e) {
            setBadge("err", "error");
            setStatus(albumT("photogallery.albums.set_cover_failed", { error: String(e && e.message ? e.message : e) }, "Set cover failed: {error}"));
        }
    }
    function existingAlbumShare(album) {
        if (!album || !album.album_id) return null;

        const shares =
            window.PQNAS_PHOTOGALLERY?.shares ||
            window.PQNAS_PHOTOGALLERY_SHARES;

        if (!shares || typeof shares.existingShareFor !== "function") {
            return null;
        }

        return shares.existingShareFor(album.album_id, "album");
    }

    function albumShareBadgeHtml(album) {
        const shares =
            window.PQNAS_PHOTOGALLERY?.shares ||
            window.PQNAS_PHOTOGALLERY_SHARES;

        const share = existingAlbumShare(album);
        if (!share) return "";

        const expired =
            shares &&
            typeof shares.isShareExpired === "function" &&
            shares.isShareExpired(share);

        return `
        <div class="pgAlbumSharedBadge ${expired ? "expired" : ""}" title="${escapeHtml(expired ? albumT("photogallery.albums.share_expired_title", null, "Album share link expired") : albumT("photogallery.albums.shared_title", null, "Album is shared"))}">
            ${escapeHtml(expired ? albumT("photogallery.albums.expired", null, "⏰ Expired") : albumT("photogallery.albums.shared", null, "🔗 Shared"))}
        </div>
    `;
    }
    function shareAlbumFromUi(album) {
        if (!album || !album.album_id) return;

        const shares = window.PQNAS_PHOTOGALLERY?.shares;
        if (!shares || typeof shares.openForRelPath !== "function") {
            setStatus(albumT("photogallery.share_module_not_loaded", null, "Share module is not loaded."));
            return;
        }

        shares.openForRelPath(
            album.album_id,
            "album",
            album.name || album.album_id
        );
    }
    async function removeAlbumItemFromUi(host, album, rel) {
        if (!album || !album.album_id || !rel) return;

        const ok = await openAlbumConfirmModal({
            title: albumT("photogallery.albums.remove_from_album_title", null, "Remove from album?"),
            subtitle: albumT("photogallery.albums.remove_from_album_subtitle", null, "This removes the photo from this album only."),
            rows: [
                { label: albumT("photogallery.photo", null, "Photo"), value: rel, mono: true },
            ],
            note: albumT("photogallery.albums.original_stays_note", null, "The original photo stays in your gallery."),
            confirmText: albumT("photogallery.albums.remove_from_album", null, "Remove from album"),
            cancelText: albumT("common.cancel", null, "Cancel"),
            danger: true,
        });
        if (!ok) return;

        try {
            setBadge("warn", "working…");
            setStatus(albumT("photogallery.albums.removing_from_album", { name: basename(rel) }, "Removing {name} from album…"));

            await removeItems(album.album_id, [rel]);
            state.currentItems = await listItems(album.album_id);

            const fresh = await listAlbums();
            state.albums = fresh;
            state.currentAlbum = fresh.find((a) => a.album_id === album.album_id) || album;

            renderAlbum(host);

            setBadge("ok", "ready");
            setStatus(albumT("photogallery.albums.removed_from_album_status", { name: basename(rel) }, "Removed from album: {name}"));
        } catch (e) {
            setBadge("err", "error");
            setStatus(albumT("photogallery.albums.remove_failed", { error: String(e && e.message ? e.message : e) }, "Remove failed: {error}"));
        }
    }

    function openAlbumsListContextMenu(host, x, y) {
        const menu = ensureAlbumContextMenu();
        menu.innerHTML = "";

        menu.appendChild(albumMenuItem(albumT("photogallery.albums.create_album_ellipsis", null, "Create album…"), () => createAlbumFromUi(host)));
        menu.appendChild(albumMenuItem(albumT("photogallery.albums.refresh_albums", null, "Refresh albums"), () => render(host, { force: true })));

        placeAlbumContextMenu(x, y);
    }

    function openAlbumCardContextMenu(host, album, x, y) {
        const menu = ensureAlbumContextMenu();
        menu.innerHTML = "";

        menu.appendChild(albumMenuItem(albumT("photogallery.albums.open_album", null, "Open album"), () => openAlbum(host, album)));
        menu.appendChild(albumMenuItem(albumT("photogallery.albums.share_album", null, "Share album…"), () => shareAlbumFromUi(album)));
        menu.appendChild(albumMenuSep());
        menu.appendChild(albumMenuItem(albumT("photogallery.albums.delete_album_ellipsis", null, "Delete album…"), () => deleteAlbumFromUi(host, album), { danger: true }));

        placeAlbumContextMenu(x, y);
    }

    function openAlbumBackgroundContextMenu(host, album, x, y) {
        const menu = ensureAlbumContextMenu();
        menu.innerHTML = "";

        menu.appendChild(albumMenuItem(albumT("photogallery.albums.back_to_albums", null, "Back to albums"), () => backToAlbumList(host)));
        menu.appendChild(albumMenuItem(albumT("photogallery.albums.refresh_album", null, "Refresh album"), () => render(host, { force: true })));

        if (album && album.album_id) {
            menu.appendChild(albumMenuSep());
            menu.appendChild(albumMenuItem(albumT("photogallery.albums.share_album", null, "Share album…"), () => shareAlbumFromUi(album)));
            menu.appendChild(albumMenuItem(albumT("photogallery.albums.delete_album_ellipsis", null, "Delete album…"), () => deleteAlbumFromUi(host, album), { danger: true }));
        }

        placeAlbumContextMenu(x, y);
    }

    function openAlbumPhotoContextMenu(host, album, rel, x, y) {
        const menu = ensureAlbumContextMenu();
        menu.innerHTML = "";

        const cover = album?.cover_path || album?.cover_logical_rel_path || "";
        const isCover = !!cover && cover === rel;

        menu.appendChild(albumMenuItem(albumT("photogallery.menu.open_preview", null, "Open preview"), () => openPreview(rel)));

        if (isCover) {
            menu.appendChild(albumMenuItem(albumT("photogallery.albums.cover_photo", null, "Cover photo"), () => {}, { disabled: true }));
        } else {
            menu.appendChild(albumMenuItem(albumT("photogallery.albums.set_as_album_cover", null, "Set as album cover"), () => setAlbumCoverFromUi(host, album, rel)));
        }

        menu.appendChild(albumMenuSep());
        menu.appendChild(albumMenuItem(albumT("photogallery.albums.remove_from_album_ellipsis", null, "Remove from album…"), () => removeAlbumItemFromUi(host, album, rel), { danger: true }));

        placeAlbumContextMenu(x, y);
    }

    function bindAlbumListContextMenu(host) {
        host.oncontextmenu = (ev) => {
            const target = ev.target;
            if (!target || !(target instanceof Element)) return;
            if (target.closest("input, textarea, select, button[data-pg-albums-create], button[data-pg-albums-refresh]")) return;

            ev.preventDefault();
            ev.stopPropagation();

            const card = target.closest("[data-pg-album-id]");
            if (card) {
                const id = card.getAttribute("data-pg-album-id") || "";
                const album = state.albums.find((a) => a.album_id === id);
                if (album) {
                    openAlbumCardContextMenu(host, album, ev.clientX, ev.clientY);
                    return;
                }
            }

            openAlbumsListContextMenu(host, ev.clientX, ev.clientY);
        };
    }

    function bindAlbumDetailContextMenu(host, album) {
        host.oncontextmenu = (ev) => {
            const target = ev.target;
            if (!target || !(target instanceof Element)) return;
            if (target.closest("input, textarea, select")) return;

            ev.preventDefault();
            ev.stopPropagation();

            const photo = target.closest("[data-pg-album-path]");
            if (photo) {
                const rel = photo.getAttribute("data-pg-album-path") || "";
                if (rel) {
                    openAlbumPhotoContextMenu(host, album, rel, ev.clientX, ev.clientY);
                    return;
                }
            }

            openAlbumBackgroundContextMenu(host, album, ev.clientX, ev.clientY);
        };
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

        setStatus(albumT("photogallery.albums.preview_not_available", null, "Preview is not available from Albums view."));
    }

    function toolbarHtml(title, sub, back = false, canDelete = false) {
        return `
        <div class="pgAlbumsToolbar">
            <div class="pgAlbumsTitleBlock">
                <div class="pgAlbumsTitle">${escapeHtml(title)}</div>
                <div class="pgAlbumsSub">${escapeHtml(sub || "")}</div>
            </div>
            <div class="pgAlbumsActions">
                ${back ? `<button class="btn secondary" type="button" data-pg-albums-back="1">${escapeHtml(albumT("photogallery.albums.albums", null, "Albums"))}</button>` : ""}
                ${back ? `<button class="btn secondary" type="button" data-pg-albums-share="1">${escapeHtml(albumT("photogallery.albums.share_album", null, "Share album…"))}</button>` : ""}
                <button class="btn secondary" type="button" data-pg-albums-refresh="1">${escapeHtml(albumT("common.refresh", null, "Refresh"))}</button>
                <button class="btn" type="button" data-pg-albums-create="1">${escapeHtml(albumT("photogallery.albums.create_album_ellipsis", null, "Create album…"))}</button>
                ${canDelete ? `<button class="btn secondary pgAlbumDangerBtn" type="button" data-pg-albums-delete="1">${escapeHtml(albumT("photogallery.albums.delete_album_ellipsis", null, "Delete album…"))}</button>` : ""}
            </div>
        </div>
    `;
    }

    function renderEmpty(host, title, msg) {
        host.innerHTML = `
            ${toolbarHtml(albumT("photogallery.albums.albums", null, "Albums"), albumT("photogallery.albums.saved_photo_collections", null, "Saved photo collections"))}
            <div class="pgAlbumsEmpty">
                <div class="h">${escapeHtml(title)}</div>
                <div class="p">${escapeHtml(msg)}</div>
            </div>
        `;
        bindCommon(host);
        bindAlbumListContextMenu(host);

    }

    function albumCardHtml(album) {
        const name = album.name || albumT("photogallery.albums.untitled_album", null, "Untitled album");
        const desc = album.description || "";
        const count = Number(album.item_count || 0);
        const cover = album.cover_path || album.cover_logical_rel_path || "";
        const photoLabel = albumT("photogallery.albums.photo_count", { count }, "{count} photo(s)");

        const emptySvg = `
            <span class="pgAlbumCoverEmpty">
                <svg class="pgAlbumCoverSvg" viewBox="0 0 180 118" aria-hidden="true" focusable="false">
                    <rect class="pgAlbumSvgSheet back" x="48" y="22" width="94" height="66" rx="12" transform="rotate(-7 95 55)"></rect>
                    <rect class="pgAlbumSvgSheet mid" x="38" y="28" width="104" height="70" rx="13" transform="rotate(4 90 63)"></rect>
                    <rect class="pgAlbumSvgSheet front" x="32" y="20" width="108" height="74" rx="14"></rect>
                    <circle class="pgAlbumSvgSun" cx="58" cy="44" r="8"></circle>
                    <path class="pgAlbumSvgMountain" d="M42 82 L68 58 L86 74 L102 52 L130 82 Z"></path>
                    <path class="pgAlbumSvgLine" d="M48 101 H132"></path>
                </svg>
                <span class="pgAlbumCoverHint">${escapeHtml(albumT("photogallery.albums.empty_album", null, "Empty album"))}</span>
            </span>
        `;

        const coverHtml = cover
            ? `<img class="pgAlbumCoverImg" src="${escapeHtml(thumbUrl(cover))}" alt="">`
            : emptySvg;

        return `
        <button class="pgAlbumCard" type="button" data-pg-album-id="${escapeHtml(album.album_id)}">
            ${albumShareBadgeHtml(album)}
            <span class="pgAlbumCardInner">
                <span class="pgAlbumCover">
                    ${coverHtml}
                    <span class="pgAlbumCoverType">${escapeHtml(albumT("photogallery.albums.album", null, "Album"))}</span>
                    <span class="pgAlbumCoverCount">▦ ${escapeHtml(photoLabel)}</span>
                </span>
    
                <span class="pgAlbumCardBody">
                    <span class="pgAlbumKicker">${escapeHtml(albumT("photogallery.albums.photo_album", null, "Photo album"))}</span>
                    <span class="pgAlbumName">${escapeHtml(shorten(name, 80))}</span>
                    <span class="pgAlbumDesc">${escapeHtml(shorten(desc || albumT("photogallery.albums.no_description", null, "No description"), 120))}</span>
                    <span class="pgAlbumMeta">${escapeHtml(albumT("photogallery.albums.meta_collection", { count: photoLabel }, "{count} · collection"))}</span>
                </span>
            </span>
        </button>
    `;
    }

    function renderList(host) {
        if (!state.albums.length) {
            renderEmpty(host, albumT("photogallery.albums.none_yet_title", null, "No albums yet"), albumT("photogallery.albums.none_yet_help", null, "Create an album, then add selected photos into it."));
            return;
        }

        host.innerHTML = `
            ${toolbarHtml(albumT("photogallery.albums.albums", null, "Albums"), albumT("photogallery.albums.album_count", { count: state.albums.length }, "{count} album(s)"))}
            <div class="pgAlbumsGrid">
                ${state.albums.map(albumCardHtml).join("")}
            </div>
        `;

        bindCommon(host);
        bindAlbumListContextMenu(host);

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
                    ${isCover ? `<span class="pgAlbumCoverBadge">${escapeHtml(albumT("photogallery.albums.cover", null, "Cover"))}</span>` : ""}
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
                        >${escapeHtml(isCover ? albumT("photogallery.albums.cover_photo", null, "Cover photo") : albumT("photogallery.albums.set_as_cover", null, "Set as cover"))}</button>
                        <button class="btn secondary pgAlbumRemoveBtn" type="button" data-pg-remove-photo="${escapeHtml(rel)}">${escapeHtml(albumT("photogallery.albums.remove", null, "Remove"))}</button>
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
            ${toolbarHtml(album.name || albumT("photogallery.albums.album", null, "Album"), albumT("photogallery.albums.detail_subtitle", { count: items.length, description: album.description || "" }, "{count} photo(s) · {description}"), true, true)}
            ${
            items.length
                ? `<div class="pgAlbumPhotos">${items.map((item) => albumItemHtml(item, album)).join("")}</div>`
                : `<div class="pgAlbumsEmpty"><div class="h">${escapeHtml(albumT("photogallery.albums.album_is_empty", null, "Album is empty"))}</div><div class="p">${escapeHtml(albumT("photogallery.albums.empty_album_help", null, "Select photos in Grid view and choose “Add selected to album…”."))}</div></div>`
        }
        `;

        bindCommon(host);
        bindAlbumDetailContextMenu(host, album);

        host.querySelectorAll("[data-pg-open-photo]").forEach((btn) => {
            btn.addEventListener("click", () => openPreview(btn.getAttribute("data-pg-open-photo") || ""));
        });
        host.querySelectorAll("[data-pg-set-cover]").forEach((btn) => {
            btn.addEventListener("click", async (ev) => {
                ev.stopPropagation();

                const rel = btn.getAttribute("data-pg-set-cover") || "";
                await setAlbumCoverFromUi(host, album, rel);
            });
        });

        host.querySelectorAll("[data-pg-remove-photo]").forEach((btn) => {
            btn.addEventListener("click", async (ev) => {
                ev.stopPropagation();

                const rel = btn.getAttribute("data-pg-remove-photo") || "";
                await removeAlbumItemFromUi(host, album, rel);
            });
        });
    }
    function openCreateAlbumModal(opts = {}) {
        const defaultName = String(opts.defaultName || albumT("photogallery.albums.new_album", null, "New album"));

        return new Promise((resolve) => {
            const backdrop = document.createElement("div");
            backdrop.className = "pgAlbumPickerBackdrop";
            backdrop.innerHTML = `
            <div class="pgAlbumPickerCard" role="dialog" aria-modal="true">
                <div class="pgAlbumPickerHead">
                    <div>
                        <div class="pgAlbumPickerTitle">${escapeHtml(albumT("photogallery.albums.create_album", null, "Create album"))}</div>
                        <div class="pgAlbumPickerSub">${escapeHtml(albumT("photogallery.albums.create_new_photo_collection", null, "Create a new photo collection"))}</div>
                    </div>
                    <button class="btn secondary" type="button" data-pg-create-close>${escapeHtml(albumT("common.close", null, "Close"))}</button>
                </div>

                <div class="pgAlbumPickerBody">
                    <div class="formGrid">
                        <div class="label">${escapeHtml(albumT("photogallery.albums.name", null, "Name"))}</div>
                        <div>
                            <input
                                class="field"
                                type="text"
                                data-pg-create-name
                                placeholder="${escapeHtml(albumT("photogallery.albums.album_name_placeholder", null, "Album name"))}"
                                value="${escapeHtml(defaultName)}"
                            >
                        </div>

                        <div class="label">${escapeHtml(albumT("photogallery.description", null, "Description"))}</div>
                        <div>
                            <textarea
                                class="textarea"
                                data-pg-create-description
                                placeholder="${escapeHtml(albumT("photogallery.description_placeholder", null, "Optional description"))}"
                                style="min-height:90px;"
                            ></textarea>
                        </div>
                    </div>
                </div>

                <div class="pgAlbumPickerFoot">
                    <button class="btn secondary" type="button" data-pg-create-cancel>${escapeHtml(albumT("common.cancel", null, "Cancel"))}</button>
                    <button class="btn" type="button" data-pg-create-ok>${escapeHtml(albumT("photogallery.albums.create_album", null, "Create album"))}</button>
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
        host.querySelector("[data-pg-albums-create]")?.addEventListener("click", () => {
            createAlbumFromUi(host);
        });

        host.querySelector("[data-pg-albums-refresh]")?.addEventListener("click", () => {
            render(host, { force: true });
        });

        host.querySelector("[data-pg-albums-back]")?.addEventListener("click", () => {
            backToAlbumList(host);
        });
        host.querySelector("[data-pg-albums-share]")?.addEventListener("click", () => {
            if (state.currentAlbum) {
                shareAlbumFromUi(state.currentAlbum);
            }
        });
        host.querySelector("[data-pg-albums-delete]")?.addEventListener("click", () => {
            deleteAlbumFromUi(host, state.currentAlbum);
        });
    }

    async function openAlbum(host, album) {
        try {
            setBadge("warn", "loading…");
            setStatus(albumT("photogallery.albums.opening_album", { album: album.name || album.album_id }, "Opening album: {album}"));
            state.mode = "album";
            state.currentAlbum = album;
            state.currentItems = await listItems(album.album_id);
            renderAlbum(host);
            setBadge("ok", "ready");
            setStatus(albumT("photogallery.albums.album_status", { album: album.name || album.album_id }, "Album: {album}"));
        } catch (e) {
            setBadge("err", "error");
            setStatus(albumT("photogallery.albums.load_failed_status", { error: String(e && e.message ? e.message : e) }, "Album load failed: {error}"));
        }
    }

    async function render(host, opts = {}) {
        if (!host) return;

        state.opts = opts || {};

        if (state.loading) return;
        state.loading = true;

        host.innerHTML = `
            <div class="pgAlbumsEmpty">
                <div class="h">${escapeHtml(albumT("photogallery.albums.loading", null, "Loading albums…"))}</div>
                <div class="p">${escapeHtml(albumT("photogallery.albums.reading_saved_collections", null, "Reading saved photo collections."))}</div>
            </div>
        `;

        try {
            setBadge("warn", "loading…");

            if (opts.force || !state.albums.length) {
                state.albums = await listAlbums();
            }
            try {
                const shares =
                    window.PQNAS_PHOTOGALLERY?.shares ||
                    window.PQNAS_PHOTOGALLERY_SHARES;

                if (shares && typeof shares.refreshSharesCache === "function") {
                    await shares.refreshSharesCache(false);
                }
            } catch (_) {}
            if (state.mode === "album" && state.currentAlbum) {
                state.currentItems = await listItems(state.currentAlbum.album_id);
                try {
                    const shares =
                        window.PQNAS_PHOTOGALLERY?.shares ||
                        window.PQNAS_PHOTOGALLERY_SHARES;

                    if (shares && typeof shares.refreshSharesCache === "function") {
                        await shares.refreshSharesCache(false);
                    }
                } catch (_) {}
                renderAlbum(host);
            } else {
                state.mode = "list";
                renderList(host);
            }

            setBadge("ok", "ready");
            setStatus(albumT("photogallery.albums.ready", null, "Albums ready."));
        } catch (e) {
            host.innerHTML = `
                <div class="pgAlbumsEmpty">
                    <div class="h">${escapeHtml(albumT("photogallery.albums.failed_to_load", null, "Albums failed to load"))}</div>
                    <div class="p">${escapeHtml(String(e && e.message ? e.message : e))}</div>
                </div>
            `;
            setBadge("err", "error");
            setStatus(albumT("photogallery.albums.failed_status", { error: String(e && e.message ? e.message : e) }, "Albums failed: {error}"));
        } finally {
            state.loading = false;
        }
    }

    async function addSelected(paths) {
        paths = Array.isArray(paths) ? paths.filter(Boolean) : [];
        if (!paths.length) {
            setStatus(albumT("photogallery.albums.select_photos_first", null, "Select one or more photos first."));
            return;
        }

        try {
            let album = null;

            if (window.PQNAS_PHOTOGALLERY?.albumsPicker?.open) {
                album = await window.PQNAS_PHOTOGALLERY.albumsPicker.open({
                    photoCount: paths.length
                });
            } else {
                throw new Error(albumT("photogallery.albums.picker_not_loaded", null, "albums picker module not loaded"));
            }

            if (!album) {
                setStatus(albumT("photogallery.albums.add_cancelled", null, "Add to album cancelled."));
                return;
            }

            if (!album || !album.album_id) {
                throw new Error(albumT("photogallery.albums.album_not_selected", null, "album not selected"));
            }

            setBadge("warn", "working…");
            setStatus(albumT("photogallery.albums.adding_to_album", { count: paths.length }, "Adding {count} photo(s) to album…"));

            await addItems(album.album_id, paths);

            state.albums = await listAlbums();
            if (state.currentAlbum && state.currentAlbum.album_id === album.album_id) {
                state.currentAlbum = state.albums.find((a) => a.album_id === album.album_id) || state.currentAlbum;
                state.currentItems = await listItems(album.album_id);
            }

            setBadge("ok", "ready");
            setStatus(albumT("photogallery.albums.added_to_album", { count: paths.length, album: album.name || album.album_id }, "Added {count} photo(s) to album: {album}"));
        } catch (e) {
            setBadge("err", "error");
            setStatus(albumT("photogallery.albums.add_failed", { error: String(e && e.message ? e.message : e) }, "Add to album failed: {error}"));
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