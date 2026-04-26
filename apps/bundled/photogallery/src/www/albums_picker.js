(() => {
    "use strict";

    window.PQNAS_PHOTOGALLERY = window.PQNAS_PHOTOGALLERY || {};

    function escapeHtml(s) {
        return String(s || "")
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
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

    function thumbUrl(relPath, size = 160) {
        const qs = new URLSearchParams();
        qs.set("path", relPath || "");
        qs.set("size", String(size));
        return `/api/v4/gallery/thumb?${qs.toString()}`;
    }

    function closePicker(backdrop, resolve, value) {
        try {
            backdrop.remove();
        } catch (_) {}
        resolve(value || null);
    }

    async function openPicker(opts = {}) {
        const photoCount = Number(opts.photoCount || 0);

        const j = await fetchJson("/api/v4/gallery/albums/list");
        const albums = Array.isArray(j.albums) ? j.albums : [];

        return await new Promise((resolve) => {
            let selectedAlbum = albums[0] || null;

            const backdrop = document.createElement("div");
            backdrop.className = "pgAlbumPickerBackdrop";
            backdrop.innerHTML = `
                <div class="pgAlbumPickerCard" role="dialog" aria-modal="true">
                    <div class="pgAlbumPickerHead">
                        <div>
                            <div class="pgAlbumPickerTitle">Add to album</div>
                            <div class="pgAlbumPickerSub">${photoCount} selected photo(s)</div>
                        </div>
                        <button class="btn secondary" type="button" data-pg-album-close>Close</button>
                    </div>

                    <div class="pgAlbumPickerBody">
                        <div class="pgAlbumPickerCreate">
                            <button class="btn secondary" type="button" data-pg-album-create-open>Create new album…</button>
                        </div>

                        <div class="pgAlbumPickerList" data-pg-album-list></div>
                    </div>

                    <div class="pgAlbumPickerFoot">
                        <button class="btn secondary" type="button" data-pg-album-cancel>Cancel</button>
                        <button class="btn" type="button" data-pg-album-use ${selectedAlbum ? "" : "disabled"}>Add here</button>
                    </div>
                </div>
            `;

            document.body.appendChild(backdrop);

            const listEl = backdrop.querySelector("[data-pg-album-list]");
            const useBtn = backdrop.querySelector("[data-pg-album-use]");

            function renderList() {
                if (!listEl) return;

                if (!albums.length) {
                    listEl.innerHTML = `
                        <div class="pgAlbumPickerEmpty">
                            No albums yet. Create one above.
                        </div>
                    `;
                    return;
                }

                listEl.innerHTML = albums.map((a, idx) => {
                    const active = selectedAlbum && selectedAlbum.album_id === a.album_id;
                    const cover = a.cover_path || a.cover_logical_rel_path || "";
                    const thumbHtml = cover
                        ? `<img class="pgAlbumPickerThumbImg" src="${escapeHtml(thumbUrl(cover, 160))}" alt="">`
                        : `<span class="pgAlbumPickerThumbFallback">▣</span>`;

                    return `
                        <button class="pgAlbumPickerRow ${active ? "active" : ""}" type="button" data-pg-album-idx="${idx}">
                            <div class="pgAlbumPickerThumb">${thumbHtml}</div>
                            <div class="pgAlbumPickerText">
                                <div class="pgAlbumPickerName">${escapeHtml(a.name || a.album_id)}</div>
                                <div class="pgAlbumPickerDesc">${escapeHtml(a.description || "No description")}</div>
                            </div>
                            <div class="pgAlbumPickerCount">${Number(a.item_count || 0)} photo(s)</div>
                        </button>
                    `;
                }).join("");
            }

            renderList();
            function openCreateAlbumModal() {
                return new Promise((resolveCreate) => {
                    const modal = document.createElement("div");
                    modal.className = "pgAlbumCreateBackdrop";
                    modal.innerHTML = `
            <div class="pgAlbumCreateCard" role="dialog" aria-modal="true">
                <div class="pgAlbumCreateHead">
                    <div>
                        <div class="pgAlbumPickerTitle">Create new album</div>
                        <div class="pgAlbumPickerSub">Create an album, then add the selected photos to it.</div>
                    </div>
                    <button class="btn secondary" type="button" data-pg-create-close>Close</button>
                </div>

                <div class="pgAlbumCreateBody">
                    <label class="pgAlbumCreateLabel">
                        <span>Name</span>
                        <input class="field" type="text" data-pg-create-name placeholder="Album name">
                    </label>

                    <label class="pgAlbumCreateLabel">
                        <span>Description</span>
                        <textarea class="textarea pgAlbumCreateTextarea" data-pg-create-desc placeholder="Optional description"></textarea>
                    </label>
                </div>

                <div class="pgAlbumCreateFoot">
                    <button class="btn secondary" type="button" data-pg-create-cancel>Cancel</button>
                    <button class="btn" type="button" data-pg-create-ok>Create album</button>
                </div>
            </div>
        `;

                    document.body.appendChild(modal);

                    const nameEl = modal.querySelector("[data-pg-create-name]");
                    const descEl = modal.querySelector("[data-pg-create-desc]");
                    const okBtn = modal.querySelector("[data-pg-create-ok]");

                    function close(value) {
                        try {
                            modal.remove();
                        } catch (_) {}
                        resolveCreate(value || null);
                    }

                    modal.addEventListener("click", async (ev) => {
                        const t = ev.target;

                        if (t === modal || t.closest("[data-pg-create-close]") || t.closest("[data-pg-create-cancel]")) {
                            close(null);
                            return;
                        }

                        if (t.closest("[data-pg-create-ok]")) {
                            const name = String(nameEl?.value || "").trim();
                            const description = String(descEl?.value || "").trim();

                            if (!name) {
                                nameEl?.focus();
                                return;
                            }

                            if (okBtn) okBtn.disabled = true;

                            try {
                                const created = await fetchJson("/api/v4/gallery/albums/create", {
                                    method: "POST",
                                    headers: {
                                        "Content-Type": "application/json",
                                        "Accept": "application/json"
                                    },
                                    body: JSON.stringify({
                                        name,
                                        description
                                    })
                                });

                                close(created.album || null);
                            } catch (e) {
                                if (okBtn) okBtn.disabled = false;
                                alert(`Create album failed: ${String(e && e.message ? e.message : e)}`);
                            }
                        }
                    });

                    modal.addEventListener("keydown", (ev) => {
                        if (ev.key === "Escape") {
                            ev.preventDefault();
                            close(null);
                            return;
                        }

                        if ((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === "enter") {
                            ev.preventDefault();
                            okBtn?.click();
                        }
                    });

                    window.setTimeout(() => nameEl?.focus(), 0);
                });
            }
            backdrop.addEventListener("click", async (ev) => {
                const t = ev.target;

                if (t === backdrop || t.closest("[data-pg-album-close]") || t.closest("[data-pg-album-cancel]")) {
                    closePicker(backdrop, resolve, null);
                    return;
                }

                const row = t.closest("[data-pg-album-idx]");
                if (row) {
                    const idx = Number(row.getAttribute("data-pg-album-idx"));
                    selectedAlbum = albums[idx] || null;
                    if (useBtn) useBtn.disabled = !selectedAlbum;
                    renderList();
                    return;
                }

                if (t.closest("[data-pg-album-use]")) {
                    if (selectedAlbum) closePicker(backdrop, resolve, selectedAlbum);
                    return;
                }

                if (t.closest("[data-pg-album-create-open]")) {
                    const createdAlbum = await openCreateAlbumModal();

                    if (createdAlbum) {
                        albums.unshift(createdAlbum);
                        selectedAlbum = createdAlbum;
                        if (useBtn) useBtn.disabled = false;
                        renderList();
                    }

                }
            });

            backdrop.addEventListener("keydown", (ev) => {
                if (ev.key === "Escape") {
                    ev.preventDefault();
                    closePicker(backdrop, resolve, null);
                }
            });

            window.setTimeout(() => {
                if (albums.length) {
                    useBtn?.focus();
                } else {
                    backdrop.querySelector("[data-pg-album-create-open]")?.focus();
                }
            }, 0);
        });
    }

    window.PQNAS_PHOTOGALLERY.albumsPicker = {
        open: openPicker
    };
})();