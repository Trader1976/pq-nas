(() => {
    "use strict";

    const PG = window.PQNAS_PHOTOGALLERY;
    if (!PG) return;

    const el = (id) => document.getElementById(id);

    function shareT(key, params, fallback) {
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

    const shareModal = el("shareModal");
    const shareClose = el("shareClose");
    const sharePath = el("sharePath");
    const shareExpiry = el("shareExpiry");
    const shareCreateBtn = el("shareCreateBtn");
    const shareRevokeBtn = el("shareRevokeBtn");
    const shareStatus = el("shareStatus");
    const shareOutWrap = el("shareOutWrap");
    const shareOut = el("shareOut");
    const shareCopyBtn = el("shareCopyBtn");
    const previewShareBtn = el("previewShareBtn");

    let sharesByKey = new Map();
    let sharesLoadedAt = 0;
    const SHARES_TTL_MS = 15000;

    let currentOpen = {
        relPath: "",
        type: "file",
        label: ""
    };

    function normalizeRelPath(rel) {
        return String(rel || "").replace(/\\/g, "/").replace(/^\/+/, "");
    }
    function normalizeShareType(type) {
        if (type === "dir") return "dir";
        if (type === "album") return "album";
        return "file";
    }
    function shareKey(type, relPath) {
        return `${normalizeShareType(type)}:${normalizeRelPath(relPath)}`;
    }
    function existingShareFor(relPath, type) {
        return sharesByKey.get(shareKey(type, relPath)) || null;
    }

    function shareConfirmModal(opts) {
        return new Promise((resolve) => {
            const options = opts || {};

            const modal = document.createElement("div");
            modal.className = "modal show";
            modal.setAttribute("role", "dialog");
            modal.setAttribute("aria-modal", "true");

            const card = document.createElement("div");
            card.className = "modalCard";
            card.style.width = "min(560px, calc(100vw - 24px))";

            const head = document.createElement("div");
            head.className = "modalHead";

            const headText = document.createElement("div");

            const title = document.createElement("div");
            title.className = "modalTitle";
            title.textContent = options.title || shareT("common.confirm", null, "Confirm");

            const sub = document.createElement("div");
            sub.className = "modalSub";
            sub.textContent = options.subtitle || "";

            headText.appendChild(title);
            if (sub.textContent) headText.appendChild(sub);
            head.appendChild(headText);

            const body = document.createElement("div");
            body.className = "modalBody";
            body.style.gridTemplateColumns = "130px 1fr";

            const rows = Array.isArray(options.rows) ? options.rows : [];
            for (const row of rows) {
                const k = document.createElement("div");
                k.className = "k";
                k.textContent = String(row.label || "");

                const v = document.createElement("div");
                v.className = row.mono ? "v mono" : "v";
                v.textContent = String(row.value || "");

                body.appendChild(k);
                body.appendChild(v);
            }

            if (options.note) {
                const note = document.createElement("div");
                note.className = "v";
                note.style.gridColumn = "1 / -1";
                note.style.opacity = "0.9";
                note.style.whiteSpace = "pre-wrap";
                note.textContent = String(options.note || "");
                body.appendChild(note);
            }

            const foot = document.createElement("div");
            foot.className = "modalFoot";

            const spacer = document.createElement("div");
            spacer.style.flex = "1 1 auto";

            const cancelBtn = document.createElement("button");
            cancelBtn.type = "button";
            cancelBtn.className = "btn secondary";
            cancelBtn.textContent = options.cancelText || shareT("common.cancel", null, "Cancel");

            const okBtn = document.createElement("button");
            okBtn.type = "button";
            okBtn.className = "btn";
            okBtn.textContent = options.confirmText || shareT("common.ok", null, "OK");

            if (options.danger) {
                okBtn.style.borderColor = "rgba(var(--fail-rgb),0.45)";
                okBtn.style.background = "rgba(var(--fail-rgb),0.14)";
                okBtn.style.color = "var(--fg)";
            }

            foot.appendChild(spacer);
            foot.appendChild(cancelBtn);
            foot.appendChild(okBtn);

            card.appendChild(head);
            if (rows.length || options.note) card.appendChild(body);
            card.appendChild(foot);
            modal.appendChild(card);
            document.body.appendChild(modal);

            const finish = (value) => {
                document.removeEventListener("keydown", onKey, true);
                modal.remove();
                resolve(!!value);
            };

            const onKey = (ev) => {
                if (ev.key === "Escape") {
                    ev.preventDefault();
                    ev.stopPropagation();
                    finish(false);
                    return;
                }

                if (ev.key === "Enter") {
                    ev.preventDefault();
                    ev.stopPropagation();
                    finish(true);
                }
            };

            document.addEventListener("keydown", onKey, true);
            modal.addEventListener("click", (ev) => {
                if (ev.target === modal) finish(false);
            });
            cancelBtn.addEventListener("click", () => finish(false));
            okBtn.addEventListener("click", () => finish(true));

            window.setTimeout(() => {
                if (options.danger) cancelBtn.focus();
                else okBtn.focus();
            }, 0);
        });
    }

    function isShareExpired(share) {
        if (!share || !share.expires_at) return false;
        const ms = Date.parse(share.expires_at);
        return Number.isFinite(ms) && Date.now() >= ms;
    }

    function fullShareUrl(urlPath, token) {
        if (urlPath && (/^https?:\/\//i).test(urlPath)) return urlPath;
        if (urlPath) return `${window.location.origin}${urlPath}`;
        if (token) return `${window.location.origin}/s/${token}`;
        return "";
    }

    function expiresSecFromPreset(v) {
        if (v === "1h") return 3600;
        if (v === "24h") return 86400;
        if (v === "7d") return 7 * 86400;
        return 0;
    }

    async function copyText(s) {
        try {
            await navigator.clipboard.writeText(String(s || ""));
            return true;
        } catch (_) {
            const ta = document.createElement("textarea");
            ta.value = String(s || "");
            document.body.appendChild(ta);
            ta.select();
            const ok = document.execCommand("copy");
            ta.remove();
            return ok;
        }
    }

    async function refreshSharesCache(force = false) {
        const now = Date.now();
        if (!force && (now - sharesLoadedAt) < SHARES_TTL_MS) return;

        const r = await fetch("/api/v4/shares/list", {
            method: "GET",
            credentials: "include",
            cache: "no-store",
            headers: { "Accept": "application/json" }
        });

        const j = await r.json().catch(() => null);
        if (!r.ok || !j || !j.ok || !Array.isArray(j.shares)) {
            throw new Error((j && (j.message || j.error)) || `HTTP ${r.status}`);
        }

        const next = new Map();
        for (const s of j.shares) {
            if (!s || typeof s !== "object") continue;
            next.set(shareKey(s.type, s.path), s);
        }

        sharesByKey = next;
        sharesLoadedAt = now;
    }

    async function createShare(relPath, type, expiresSec) {
        const r = await fetch("/api/v4/shares/create", {
            method: "POST",
            credentials: "include",
            cache: "no-store",
            headers: {
                "Content-Type": "application/json",
                "Accept": "application/json"
            },
            body: JSON.stringify({
                path: relPath,
                type: normalizeShareType(type),
                expires_sec: expiresSec,
                mode: "standard"
            })
        });

        const j = await r.json().catch(() => null);
        if (!r.ok || !j || !j.ok) {
            const msg = j && (j.detail || j.message || j.error)
                ? [j.error, j.message, j.detail].filter(Boolean).join(" ")
                : `HTTP ${r.status}`;
            throw new Error(msg || "share create failed");
        }
        return j;
    }

    async function revokeShare(token) {
        const r = await fetch("/api/v4/shares/revoke", {
            method: "POST",
            credentials: "include",
            cache: "no-store",
            headers: {
                "Content-Type": "application/json",
                "Accept": "application/json"
            },
            body: JSON.stringify({ token })
        });

        const j = await r.json().catch(() => null);
        if (!r.ok || !j || !j.ok) {
            const msg = j && (j.detail || j.message || j.error)
                ? [j.error, j.message, j.detail].filter(Boolean).join(" ")
                : `HTTP ${r.status}`;
            throw new Error(msg || "share revoke failed");
        }
        return j;
    }

    function openModal() {
        if (!shareModal) return;
        shareModal.classList.add("show");
        shareModal.setAttribute("aria-hidden", "false");
    }

    function closeModal() {
        if (!shareModal) return;
        shareModal.classList.remove("show");
        shareModal.setAttribute("aria-hidden", "true");
    }

    function ensureShareBadge(tileEl, expired) {
        let b = tileEl.querySelector(".shareBadge");
        if (!b) {
            b = document.createElement("div");
            b.className = "shareBadge";
            tileEl.appendChild(b);
        }
        b.className = "shareBadge" + (expired ? " expired" : "");
        b.title = expired
            ? shareT("photogallery.share.expired_badge_title", null, "Share link expired")
            : shareT("photogallery.share.shared_badge_title", null, "Shared");
        b.textContent = expired ? "⏰" : "🔗";
    }

    function removeShareBadge(tileEl) {
        const b = tileEl.querySelector(".shareBadge");
        if (b) b.remove();
    }

    function decorateVisibleShareBadges() {
        const tiles = document.querySelectorAll(".tile[data-rel-path][data-item-type]");
        for (const tile of tiles) {
            const rel = tile.dataset.relPath || "";
            const type = tile.dataset.itemType === "dir" ? "dir" : "file";
            const share = existingShareFor(rel, type);

            if (!share) {
                removeShareBadge(tile);
                continue;
            }

            ensureShareBadge(tile, isShareExpired(share));
        }
    }

    function updatePreviewShareButton() {
        if (!previewShareBtn) return;
        const rel = PG.getPreviewPath ? PG.getPreviewPath() : "";
        if (!rel) {
            previewShareBtn.disabled = true;
            previewShareBtn.textContent = shareT("photogallery.share", null, "Share");
            return;
        }

        previewShareBtn.disabled = false;
        const existing = existingShareFor(rel, "file");
        previewShareBtn.textContent = existing
            ? shareT("photogallery.manage_share", null, "Manage share")
            : shareT("photogallery.share", null, "Share");
    }

    function menuLabelForRelPath(relPath, type) {
        const share = existingShareFor(relPath, type);
        if (!share) {
            return shareT("photogallery.create_share_link_menu", null, "Create share link…");
        }
        return isShareExpired(share)
            ? shareT("photogallery.manage_share_link_expired_menu", null, "Manage share link… (expired)")
            : shareT("photogallery.manage_share_link_menu", null, "Manage share link…");
    }

    function populateModalFromExisting(relPath, type, label = "") {
        const existing = existingShareFor(relPath, type);

        if (sharePath) {
            sharePath.textContent = normalizeShareType(type) === "album"
                ? shareT("photogallery.share.album_path", { album: label || relPath }, "Album: {album}")
                : "/" + relPath;
        }
        if (shareStatus) shareStatus.textContent = "";
        if (shareOut) shareOut.value = "";
        if (shareOutWrap) shareOutWrap.style.display = "none";
        if (shareRevokeBtn) shareRevokeBtn.style.display = "none";
        if (shareExpiry) shareExpiry.value = "24h";

        if (existing) {
            const full = fullShareUrl(existing.url, existing.token);
            if (shareOut) shareOut.value = full;
            if (shareOutWrap) shareOutWrap.style.display = "";
            if (shareRevokeBtn) shareRevokeBtn.style.display = "";
            if (shareCreateBtn) {
                shareCreateBtn.textContent = shareT("photogallery.share.create_new_rotate", null, "Create new link (rotate)…");
            }

            const exp = existing.expires_at
                ? shareT("photogallery.share.already_shared_expires", { expires_at: existing.expires_at }, "Already shared • expires {expires_at}")
                : shareT("photogallery.share.already_shared_no_expiry", null, "Already shared • no expiry");
            if (shareStatus) shareStatus.textContent = exp;
        } else {
            if (shareCreateBtn) {
                shareCreateBtn.textContent = shareT("photogallery.create_link", null, "Create link");
            }
        }
    }

    async function openForRelPath(relPath, type = "file", label = "") {
        const rel = normalizeRelPath(relPath);
        if (!rel) return;

        currentOpen.relPath = rel;
        currentOpen.type = normalizeShareType(type);
        currentOpen.label = String(label || "");

        try {
            await refreshSharesCache(false);
        } catch (_) {}

        populateModalFromExisting(currentOpen.relPath, currentOpen.type, currentOpen.label);
        openModal();
    }

    function openForItem(item) {
        if (!item) return;
        const rel = PG.currentRelPathFor(item);
        openForRelPath(rel, item.type);
    }

    shareClose?.addEventListener("click", closeModal);
    shareModal?.addEventListener("click", (e) => {
        if (e.target === shareModal) closeModal();
    });

    shareCreateBtn?.addEventListener("click", async () => {
        const rel = currentOpen.relPath;
        const type = currentOpen.type;
        if (!rel) return;

        try {
            if (shareStatus) shareStatus.textContent = shareT("photogallery.share.creating", null, "Creating…");

            const existing = existingShareFor(rel, type);
            if (existing && existing.token) {
                await revokeShare(existing.token);
            }

            const expiresSec = expiresSecFromPreset(shareExpiry ? shareExpiry.value : "24h");
            const j = await createShare(rel, type, expiresSec);

            const outUrl = fullShareUrl(j.url, j.token);
            if (shareOut) shareOut.value = outUrl;
            if (shareOutWrap) shareOutWrap.style.display = "";
            if (shareStatus) shareStatus.textContent = existing
                ? shareT("photogallery.share.new_link_created_old_revoked", null, "New link created (old revoked).")
                : shareT("photogallery.share.link_created", null, "Link created.");
            if (shareRevokeBtn) shareRevokeBtn.style.display = "";

            await refreshSharesCache(true);
            decorateVisibleShareBadges();
            updatePreviewShareButton();

            PG.setBadge?.("ok", "ready");
            PG.setStatus?.(shareT("photogallery.share.ready_for_path", { path: rel }, "Share ready: {path}"));
        } catch (e) {
            if (shareStatus) shareStatus.textContent = shareT("common.error_with_message", { error: String(e && e.message ? e.message : e) }, "Error: {error}");
            PG.setBadge?.("err", "error");
        }
    });

    shareRevokeBtn?.addEventListener("click", async () => {
        const rel = currentOpen.relPath;
        const type = currentOpen.type;
        const existing = existingShareFor(rel, type);
        if (!existing || !existing.token) return;

        const ok = await shareConfirmModal({
            title: shareT("photogallery.share.revoke_title", null, "Revoke share link?"),
            note: shareT("photogallery.share.revoke_note", null, "This will invalidate the URL immediately."),
            confirmText: shareT("photogallery.revoke", null, "Revoke"),
            cancelText: shareT("common.cancel", null, "Cancel"),
            danger: true,
        });
        if (!ok) return;

        try {
            if (shareStatus) shareStatus.textContent = shareT("photogallery.share.revoking", null, "Revoking…");
            await revokeShare(existing.token);

            await refreshSharesCache(true);
            decorateVisibleShareBadges();
            updatePreviewShareButton();
            populateModalFromExisting(rel, type);

            PG.setBadge?.("ok", "ready");
            PG.setStatus?.(shareT("photogallery.share.revoked_for_path", { path: rel }, "Share revoked: {path}"));
        } catch (e) {
            if (shareStatus) shareStatus.textContent = shareT("common.error_with_message", { error: String(e && e.message ? e.message : e) }, "Error: {error}");
            PG.setBadge?.("err", "error");
        }
    });

    shareCopyBtn?.addEventListener("click", async () => {
        const ok = await copyText(shareOut ? shareOut.value : "");
        if (shareStatus) shareStatus.textContent = ok
            ? shareT("common.copied", null, "Copied.")
            : shareT("common.copy_failed", null, "Copy failed.");
    });

    previewShareBtn?.addEventListener("click", () => {
        const rel = PG.getPreviewPath ? PG.getPreviewPath() : "";
        if (rel) openForRelPath(rel, "file");
    });

    window.addEventListener("photogallery:view-updated", async () => {
        try {
            await refreshSharesCache(false);
        } catch (_) {}
        decorateVisibleShareBadges();
        updatePreviewShareButton();
    });

    window.addEventListener("photogallery:preview-open", () => {
        updatePreviewShareButton();
    });

    window.addEventListener("photogallery:preview-close", () => {
        updatePreviewShareButton();
    });

    PG.shares = {
        ...(PG.shares || {}),
        openForItem,
        openForRelPath,
        refreshSharesCache,
        decorateVisibleShareBadges,
        menuLabelForRelPath,
        existingShareFor,
        isShareExpired
    };

    window.PQNAS_PHOTOGALLERY_SHARES = {
        openForItem,
        openForRelPath,
        menuLabelForRelPath
    };

    refreshSharesCache(false)
        .then(() => {
            decorateVisibleShareBadges();
            updatePreviewShareButton();
        })
        .catch(() => {});
})();