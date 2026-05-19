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

        const ok = confirm(shareT("photogallery.share.revoke_confirm", null, "Revoke this share link?\n\nThis will invalidate the URL immediately."));
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