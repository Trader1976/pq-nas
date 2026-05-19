function tr(key, vars = null, fallback = "") {
    try {
        if (window.PQNAS_I18N && typeof window.PQNAS_I18N.t === "function") {
            return window.PQNAS_I18N.t(key, vars, fallback || key);
        }
    } catch (_) {}
    return fallback || key;
}

function applyStaticI18n() {
    try {
        if (window.PQNAS_I18N && typeof window.PQNAS_I18N.apply === "function") {
            window.PQNAS_I18N.apply(document);
        }
    } catch (_) {}
}

function statusLabel(status) {
    const s = String(status || "unknown").toLowerCase();
    if (s === "enabled") return tr("admin.users.status.enabled", null, "enabled");
    if (s === "disabled") return tr("admin.users.status.disabled", null, "disabled");
    if (s === "revoked") return tr("admin.users.status.revoked", null, "revoked");
    return tr("admin.users.status.unknown", null, s || "unknown");
}

function roleLabel(role) {
    const r = String(role || "").toLowerCase();
    if (r === "admin") return tr("admin.users.role.admin", null, "admin");
    if (r === "user") return tr("admin.users.role.user", null, "user");
    return String(role || "");
}

function storageStateLabel(state) {
    const s = String(state || "unallocated").toLowerCase();
    if (s === "allocated") return tr("admin.users.storage.allocated", null, "allocated");
    if (s === "unallocated") return tr("admin.users.storage.unallocated", null, "unallocated");
    return s;
}

async function apiGet(path) {
    const r = await fetch(path, { headers: { "Accept": "application/json" }, cache: "no-store" });
    const j = await r.json().catch(() => ({}));
    if (!r.ok || !j.ok) throw new Error(j.message || j.error || ("HTTP " + r.status));
    return j;
}


// for showing quota usage bar
function clamp01(x) {
    x = Number(x);
    if (!isFinite(x)) return 0;
    return Math.max(0, Math.min(1, x));
}

function fmtBytesShort(n) {
    if (!Number.isFinite(n) || n < 0) return "—";
    const units = ["B","KiB","MiB","GiB","TiB"];
    let x = n, i = 0;
    while (x >= 1024 && i < units.length - 1) { x /= 1024; i++; }
    return `${x.toFixed(i === 0 ? 0 : (i === 1 ? 1 : 2))} ${units[i]}`;
}

function quotaUsageText(usedBytes, quotaBytes) {
    const used = Number(usedBytes);
    const quota = Number(quotaBytes);
    if (!isFinite(quota) || quota <= 0) return "—";
    return `${fmtBytesShort(isFinite(used) ? used : NaN)} / ${fmtBytesShort(quota)}`;
}

function quotaUsagePct(usedBytes, quotaBytes) {
    const used = Number(usedBytes);
    const quota = Number(quotaBytes);
    if (!isFinite(used) || !isFinite(quota) || quota <= 0) return 0;
    return clamp01(used / quota);
}


// allow multiple open rows
const openUsers = new Set(); // fingerprints


async function apiPost(path, body) {
    const r = await fetch(path, {
        method: "POST",
        headers: { "Content-Type": "application/json", "Accept": "application/json" },
        body: JSON.stringify(body),
        cache: "no-store",
    });
    const j = await r.json().catch(() => ({}));
    if (!r.ok || !j.ok) throw new Error(j.message || j.error || ("HTTP " + r.status));
    return j;
}

function $(id) { return document.getElementById(id); }

const ADMIN_AVATAR_MAX_BYTES = 256 * 1024;
const ADMIN_AVATAR_TARGET_BYTES = 240 * 1024;
const ADMIN_AVATAR_MAX_DIM = 512;

function fmtBytesForAvatar(n) {
    const x = Number(n || 0);
    if (!Number.isFinite(x) || x <= 0) return "0 B";
    if (x < 1024) return `${x} B`;
    if (x < 1024 * 1024) return `${(x / 1024).toFixed(1)} KiB`;
    return `${(x / (1024 * 1024)).toFixed(2)} MiB`;
}

function blobToBase64(blob) {
    return new Promise((resolve, reject) => {
        const rd = new FileReader();

        rd.onload = () => {
            const s = String(rd.result || "");
            const comma = s.indexOf(",");
            resolve(comma >= 0 ? s.slice(comma + 1) : s);
        };

        rd.onerror = () => reject(new Error(tr("admin.users.failed_read_avatar", null, "failed to read avatar file")));
        rd.readAsDataURL(blob);
    });
}

function canvasToBlobSafe(canvas, type, quality) {
    return new Promise((resolve, reject) => {
        canvas.toBlob((blob) => {
            if (!blob) {
                reject(new Error(tr("admin.users.avatar_conversion_failed", null, "avatar conversion failed")));
                return;
            }
            resolve(blob);
        }, type, quality);
    });
}

function loadImageForAvatar(file) {
    return new Promise((resolve, reject) => {
        const url = URL.createObjectURL(file);
        const img = new Image();

        img.onload = () => {
            URL.revokeObjectURL(url);
            resolve(img);
        };

        img.onerror = () => {
            URL.revokeObjectURL(url);
            reject(new Error(tr("admin.users.avatar_read_failed", null, "Could not read this image. Try PNG, JPEG, or WebP.")));
        };

        img.src = url;
    });
}

async function prepareAdminAvatarUploadBlob(file) {
    if (!file) throw new Error(tr("admin.users.no_avatar_selected", null, "No avatar file selected."));

    const originalMime = String(file.type || "").toLowerCase();

    const directlyAllowed =
        originalMime === "image/png" ||
        originalMime === "image/jpeg" ||
        originalMime === "image/webp";

    if (directlyAllowed && file.size <= ADMIN_AVATAR_MAX_BYTES) {
        return {
            blob: file,
            mime: originalMime,
            note: tr("admin.users.using_original", { size: fmtBytesForAvatar(file.size) }, `Using original image (${fmtBytesForAvatar(file.size)}).`)
        };
    }

    const img = await loadImageForAvatar(file);

    const srcW = img.naturalWidth || img.width || 0;
    const srcH = img.naturalHeight || img.height || 0;

    if (!srcW || !srcH) {
        throw new Error(tr("admin.users.avatar_dims_failed", null, "Could not read image dimensions."));
    }

    const scale = Math.min(1, ADMIN_AVATAR_MAX_DIM / Math.max(srcW, srcH));
    const dstW = Math.max(1, Math.round(srcW * scale));
    const dstH = Math.max(1, Math.round(srcH * scale));

    const canvas = document.createElement("canvas");
    canvas.width = dstW;
    canvas.height = dstH;

    const ctx = canvas.getContext("2d", { alpha: false });
    if (!ctx) throw new Error("Canvas is not available for avatar resize.");

    ctx.fillStyle = "#ffffff";
    ctx.fillRect(0, 0, dstW, dstH);
    ctx.drawImage(img, 0, 0, dstW, dstH);

    const qualities = [0.86, 0.78, 0.70, 0.62, 0.54, 0.46, 0.38];

    let best = null;

    for (const q of qualities) {
        const blob = await canvasToBlobSafe(canvas, "image/jpeg", q);
        best = blob;

        if (blob.size <= ADMIN_AVATAR_TARGET_BYTES) {
            return {
                blob,
                mime: "image/jpeg",
                note: tr("admin.users.resized_avatar", { srcW, srcH, dstW, dstH, oldSize: fmtBytesForAvatar(file.size), newSize: fmtBytesForAvatar(blob.size) }, `Resized ${srcW}×${srcH} → ${dstW}×${dstH}, ${fmtBytesForAvatar(file.size)} → ${fmtBytesForAvatar(blob.size)}.`)
            };
        }
    }

    if (best && best.size <= ADMIN_AVATAR_MAX_BYTES) {
        return {
            blob: best,
            mime: "image/jpeg",
            note: tr("admin.users.resized_avatar", { srcW, srcH, dstW, dstH, oldSize: fmtBytesForAvatar(file.size), newSize: fmtBytesForAvatar(best.size) }, `Resized ${srcW}×${srcH} → ${dstW}×${dstH}, ${fmtBytesForAvatar(file.size)} → ${fmtBytesForAvatar(best.size)}.`)
        };
    }

    throw new Error(
        tr("admin.users.avatar_too_large", { size: fmtBytesForAvatar(best ? best.size : file.size) }, `Avatar is still too large after resizing (${fmtBytesForAvatar(best ? best.size : file.size)}). Try a smaller image.`)
    );
}

function pill(status) {
    const cls = (status || "disabled");
    return `<span class="pill ${cls}">${esc(statusLabel(cls))}</span>`;
}

function esc(s) {
    return (s || "").replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

function avatarSrc(u) {
    const s = String(u?.avatar_url || "").trim();
    return s || "";
}

function fmtGBFromBytes(b) {
    const n = Number(b || 0);
    if (!isFinite(n) || n <= 0) return "";
    const gb = n / (1024 * 1024 * 1024);
    // keep it simple: show up to 2 decimals, trim trailing zeros
    return (Math.round(gb * 100) / 100).toString();
}

function fmtQuotaCell(u) {
    const st = (u.storage_state || "unallocated");
    if (st !== "allocated") return `<span class="muted">—</span>`;
    const gb = fmtGBFromBytes(u.quota_bytes);
    return gb ? `${esc(gb)} GB` : `<span class="muted">0</span>`;
}
function shortFp(fp) {
    fp = String(fp || "");
    if (fp.length <= 20) return fp;
    return fp.slice(0, 12) + "…" + fp.slice(-12);
}
function avatarThumb(u) {
    const src = avatarSrc(u);
    if (!src) return `<div class="muted">—</div>`;
    return `
      <img
        src="${esc(src)}"
        alt="${esc(tr("admin.users.avatar_alt", null, "avatar"))}"
        style="width:26px;height:26px;border-radius:8px;object-fit:cover;border:1px solid var(--border);background:var(--panel2);"
        title="Avatar"
        onerror="this.style.opacity='0.35'; this.title='${esc(tr("admin.users.avatar_failed", null, "Avatar failed to load"))}';"
      />
    `.trim();
}
let avatarModalFp = "";
let avatarModalUrl = "";

function openAvatarModal(fp, url) {
    avatarModalFp = String(fp || "");
    avatarModalUrl = String(url || "");

    const m = $("avatarModal");
    const img = $("avatarModalImg");
    const rm = $("avatarRemoveBtn");

    if (!m || !img || !rm) return;

    img.src = avatarModalUrl || "";
    rm.disabled = !avatarModalFp;

    m.classList.add("open");
    m.setAttribute("aria-hidden", "false");
}

function closeAvatarModal() {
    const m = $("avatarModal");
    const img = $("avatarModalImg");
    if (img) img.src = ""; // stop loading / free memory
    avatarModalFp = "";
    avatarModalUrl = "";

    if (m) {
        m.classList.remove("open");
        m.setAttribute("aria-hidden", "true");
    }
}

function storagePill(state) {
    const s = (state || "unallocated");
    const cls = (s === "allocated") ? "enabled" : "disabled"; // reuse pill CSS classes
    return `<span class="pill ${cls}">${esc(storageStateLabel(s))}</span>`;
}
function storagePoolIdForUser(u) {
    const raw =
        (u?.pool_id != null ? String(u.pool_id) :
            (u?.pool != null ? String(u.pool) :
                (u?.storage_pool_id != null ? String(u.storage_pool_id) : "")));

    const v = raw.trim();
    return v ? v : "default";
}

function storageCellHtml(u) {
    const state = String(u?.storage_state || "unallocated").toLowerCase();
    const main = storagePill(state);

    if (state !== "allocated") return main;

    const poolId = storagePoolIdForUser(u);
    return `${main} <span class="pill poolpill">${esc(poolId)}</span>`;
}
function fmtBytes(n) {
    n = Number(n || 0);
    const units = ["B","KiB","MiB","GiB","TiB"];
    let u = 0;
    while (n >= 1024 && u < units.length - 1) { n /= 1024; u++; }
    return `${n.toFixed(u === 0 ? 0 : 2)} ${units[u]}`;
}

function showToast(msg, ms = 10000) {
    let t = document.getElementById("toast");
    if (!t) {
        t = document.createElement("div");
        t.id = "toast";
        t.style.position = "fixed";
        t.style.right = "18px";
        t.style.bottom = "18px";
        t.style.zIndex = "99999";

        /* sizing */
        t.style.maxWidth = "520px";
        t.style.width = "min(520px, calc(100vw - 36px))";

        t.style.padding = "12px 14px";
        t.style.borderRadius = "12px";
        t.style.border = "1px solid var(--border)";
        t.style.background = "linear-gradient(180deg, var(--panel2), var(--panel))";
        t.style.color = "var(--fg)";
        t.style.boxShadow = "var(--shadow)";
        t.style.font = "14px system-ui, -apple-system, Segoe UI, Roboto, sans-serif";

        /* wrapping + scroll */
        t.style.whiteSpace = "pre-wrap";
        t.style.wordBreak = "break-all";
        t.style.overflowWrap = "anywhere";
        t.style.maxHeight = "60vh";
        t.style.overflow = "auto";

        /* allow selection */
        t.style.userSelect = "text";
        t.style.cursor = "text";

        t.style.display = "none";
        document.body.appendChild(t);
    }

    t.textContent = msg;
    t.onclick = () => {
        navigator.clipboard.writeText(msg).catch(() => {});
    };

    t.style.display = "block";
    clearTimeout(t._hideTimer);
    t._hideTimer = setTimeout(() => { t.style.display = "none"; }, ms);
}

function gbToBytes(gb) {
    const x = Number(gb);
    if (!isFinite(x) || x < 0) return null;
    // allow 0
    return Math.floor(x * 1024 * 1024 * 1024);
}

function setAllocError(msg) {
    const el = $("allocErr");
    if (!el) return;
    if (!msg) {
        el.textContent = "";
        el.classList.remove("show");
        return;
    }
    el.textContent = String(msg);
    el.classList.add("show");
}
function renderAllocPreview(preview, requestedQuotaBytes = null) {
    const box = $("allocPreview");
    if (!box) return;

    if (!preview || !preview.ok) {
        box.innerHTML = `<div class="muted">${esc(tr("admin.users.no_pool_preview", null, "No pool preview available."))}</div>`;
        return;
    }

    const used = Number(preview.used_bytes || 0);
    const currentQuota = Number(preview.current_quota_bytes || 0);
    const poolTotal = Number(preview.pool_total_bytes || 0);
    const poolFree = Number(preview.pool_free_bytes || 0);
    const allocatedOther = Number(preview.allocated_other_bytes || 0);
    const remainingAlloc = Number(preview.remaining_allocatable_bytes || 0);

    const rq = Number(requestedQuotaBytes);
    const haveRq = Number.isFinite(rq) && rq >= 0;

    const overAlloc = haveRq && rq > remainingAlloc;
    const belowUsed = haveRq && rq < used;

    const warnHtml = (overAlloc || belowUsed)
        ? `
          <div class="allocPreviewWarn">
            ${belowUsed ? `${esc(tr("admin.users.warn_below_used", null, "Requested quota is below current used space."))}` : ``}
            ${belowUsed && overAlloc ? `<br>` : ``}
            ${overAlloc ? `${esc(tr("admin.users.warn_over_alloc", null, "Requested quota exceeds remaining allocatable capacity on this pool."))}` : ``}
          </div>
        `
        : ``;

    box.innerHTML = `
      <div class="allocPreviewGrid">
        <div class="detailKV"><div class="k">${esc(tr("admin.users.user_used", null, "User used"))}</div><div class="v mono">${esc(fmtBytes(used))}</div></div>
        <div class="detailKV"><div class="k">${esc(tr("admin.users.current_quota", null, "Current quota"))}</div><div class="v mono">${esc(currentQuota ? fmtBytes(currentQuota) : "—")}</div></div>
        <div class="detailKV"><div class="k">${esc(tr("admin.users.pool_total", null, "Pool total"))}</div><div class="v mono">${esc(fmtBytes(poolTotal))}</div></div>
        <div class="detailKV"><div class="k">${esc(tr("admin.users.pool_free", null, "Pool free (fs)"))}</div><div class="v mono">${esc(fmtBytes(poolFree))}</div></div>
        <div class="detailKV"><div class="k">${esc(tr("admin.users.allocated_to_others", null, "Allocated to others"))}</div><div class="v mono">${esc(fmtBytes(allocatedOther))}</div></div>
        <div class="detailKV"><div class="k">${esc(tr("admin.users.remaining_allocatable", null, "Remaining allocatable"))}</div><div class="v mono">${esc(fmtBytes(remainingAlloc))}</div></div>
        ${haveRq ? `<div class="detailKV"><div class="k">${esc(tr("admin.users.requested_quota", null, "Requested quota"))}</div><div class="v mono">${esc(fmtBytes(rq))}</div></div>` : ``}
      </div>
      ${warnHtml}
    `;
}
function normalizePoolsFromResponse(j) {
    const arr = Array.isArray(j?.pools) ? j.pools : [];

    const out = [];
    for (const p of arr) {
        if (!p || typeof p !== "object") continue;

        const rawId = String(p.pool_id || "").trim();
        if (!rawId) continue;

        const mount = String(p.mount || "").trim();
        const disp = String(p.display_name || "").trim();

        const isDefault =
            rawId === "default" ||
            mount === "/srv/pqnas" ||
            mount === "/srv/pqnas/data";

        const id = isDefault ? "default" : rawId;
        const name = isDefault ? tr("admin.users.default_pool", null, "Default pool") : (disp || rawId);

        const hintParts = [];
        if (mount) hintParts.push(mount);
        if (p.profile_data) hintParts.push(`data:${String(p.profile_data)}`);
        if (p.profile_metadata) hintParts.push(`meta:${String(p.profile_metadata)}`);
        const hint = hintParts.join(" • ");

        out.push({ id, name, hint, mount });
    }
    return out;
}

async function apiGetPoolsBestEffort() {
    // Prefer raidmgr pools endpoint (most likely already exists)
    const candidates = [
        "/api/v4/storage/pools",
        "/api/v4/raid/pools",
        "/api/v4/pools",
        "/api/v4/admin/pools",
    ];

    let lastErr = null;
    for (const url of candidates) {
        try {
            const j = await apiGet(url);
            return normalizePoolsFromResponse(j);
        } catch (e) {
            lastErr = e;
        }
    }
    console.warn("Pools load failed, falling back to default pool:", lastErr?.message || lastErr);
    return [];
}

async function ensurePoolsLoaded() {
    const pools = await apiGetPoolsBestEffort();
    const out = Array.isArray(pools) ? [...pools] : [];

    if (!out.some(p => String(p.id) === "default")) {
        out.unshift({
            id: "default",
            name: "Default pool",
            hint: "/srv/pqnas/data"
        });
    }

    gPools = out;
    return gPools;
}
async function refreshAllocPreview() {
    const fp = gAllocFp;
    const poolSel = $("allocPoolSel");
    const gbInp = $("allocGb");

    if (!fp || !poolSel) return;

    const poolId = String(poolSel.value || "default");
    const quotaGb = Number(String(gbInp?.value || "").trim());
    const requestedQuotaBytes = isFinite(quotaGb) && quotaGb >= 0 ? gbToBytes(quotaGb) : null;

    const j = await apiGetStoragePreview(fp, poolId);
    gAllocPreview = j;
    renderAllocPreview(j, requestedQuotaBytes);
}
function openAllocModal(fp, curUser) {
    gAllocFp = String(fp || "");
    gAllocForce = false;

    const m = $("allocModal");
    const fpLabel = $("allocFpLabel");
    const poolSel = $("allocPoolSel");
    const poolHint = $("allocPoolHint");
    const gbInp = $("allocGb");

    if (!m || !fpLabel || !poolSel || !poolHint || !gbInp) return;

    setAllocError("");

    fpLabel.textContent = gAllocFp || "—";

    const suggested = fmtGBFromBytes(curUser?.quota_bytes) || "10";
    gbInp.value = suggested;

    m.classList.add("open");
    m.setAttribute("aria-hidden", "false");

    (async () => {
        const pools = await ensurePoolsLoaded();

        poolSel.innerHTML = "";
        for (const p of pools) {
            const opt = document.createElement("option");
            opt.value = p.id;
            opt.textContent = p.name;
            poolSel.appendChild(opt);
        }

        const curPool =
            (curUser?.pool_id != null ? String(curUser.pool_id) :
                (curUser?.pool != null ? String(curUser.pool) :
                    (curUser?.storage_pool_id != null ? String(curUser.storage_pool_id) :
                        "")));

        if (curPool) {
            const match = Array.from(poolSel.options).find(o => o.value === curPool);
            if (match) poolSel.value = curPool;
        }

        const selected = pools.find(x => x.id === poolSel.value) || pools[0];
        poolHint.textContent = selected?.hint ? selected.hint : "—";

        poolSel.onchange = async () => {
            const s = (gPools || []).find(x => x.id === poolSel.value);
            poolHint.textContent = s?.hint ? s.hint : "—";
            try {
                await refreshAllocPreview();
            } catch (e) {
                setAllocError("Failed to refresh pool preview: " + (e?.message || e));
            }
        };

        gbInp.addEventListener("input", () => {
            const quotaGb = Number(String(gbInp.value || "").trim());
            const requestedQuotaBytes = isFinite(quotaGb) && quotaGb >= 0 ? gbToBytes(quotaGb) : null;
            renderAllocPreview(gAllocPreview, requestedQuotaBytes);
        }, { passive: true });

        try {
            await refreshAllocPreview();
        } catch (e) {
            setAllocError("Failed to load pool preview: " + (e?.message || e));
        }

        gbInp.focus();
        gbInp.select();

    })().catch(e => {
        setAllocError("Failed to load pools: " + (e?.message || e));
    });
}


function closeAllocModal() {
    const m = $("allocModal");
    if (!m) return;
    m.classList.remove("open");
    m.setAttribute("aria-hidden", "true");
    setAllocError("");
    gAllocFp = "";
    gAllocPreview = null;

    const box = $("allocPreview");
    if (box) {
        box.innerHTML = `<div class="muted">${esc(tr("admin.users.loading_pool_preview", null, "Loading pool preview…"))}</div>`;
    }
}

function setMigrateError(msg) {
    const el = $("migrateErr");
    if (!el) return;
    if (!msg) {
        el.textContent = "";
        el.classList.remove("show");
        return;
    }
    el.textContent = String(msg);
    el.classList.add("show");
}



function currentPoolNameFromList(poolId, pools) {
    const p = (pools || []).find(x => x.id === poolId);
    return p?.name || poolId || "default";
}

function openMigrateModal(fp, curUser) {
    gMigrateFp = String(fp || "");
    gPools = null;
    const m = $("migrateModal");
    const fpLabel = $("migrateFpLabel");
    const curPoolInp = $("migrateCurPool");
    const curHint = $("migrateCurHint");
    const poolSel = $("migratePoolSel");
    const poolHint = $("migratePoolHint");

    if (!m || !fpLabel || !curPoolInp || !curHint || !poolSel || !poolHint) return;

    setMigrateError("");
    fpLabel.textContent = gMigrateFp || "—";

    m.classList.add("open");
    m.setAttribute("aria-hidden", "false");

    (async () => {
        const pools = await ensurePoolsLoaded();
        const curPoolId = storagePoolIdForUser(curUser);

        curPoolInp.value = currentPoolNameFromList(curPoolId, pools);
        const curPoolObj = pools.find(x => x.id === curPoolId);
        curHint.textContent = curPoolObj?.hint || "—";

        const candidates = pools.filter(p => p.id !== curPoolId);


        poolSel.innerHTML = "";
        if (candidates.length === 0) {
            const opt = document.createElement("option");
            opt.value = "";
            opt.textContent = tr("admin.users.no_other_pools", null, "No other pools available");
            poolSel.appendChild(opt);
            poolSel.disabled = true;
            poolHint.textContent = tr("admin.users.create_pool_first", null, "Create another pool first.");
            return;
        }

        poolSel.disabled = false;
        for (const p of candidates) {
            const opt = document.createElement("option");
            opt.value = p.id;
            opt.textContent = p.name;
            poolSel.appendChild(opt);
        }

        const selected = candidates[0];
        poolSel.value = selected.id;
        poolHint.textContent = selected?.hint || "—";

        poolSel.onchange = () => {
            const s = candidates.find(x => x.id === poolSel.value);
            poolHint.textContent = s?.hint || "—";
        };
    })().catch(e => {
        setMigrateError("Failed to load pools: " + (e?.message || e));
    });
}

function closeMigrateModal() {
    const m = $("migrateModal");
    if (!m) return;
    m.classList.remove("open");
    m.setAttribute("aria-hidden", "true");
    setMigrateError("");
    gMigrateFp = "";
}
async function apiGetMigrationStatus(jobId) {
    const q = encodeURIComponent(String(jobId || "").trim());
    return await apiGet(`/api/v4/admin/users/migrate_storage_status?job_id=${q}`);
}
async function apiGetStoragePreview(fp, poolId) {
    const qfp = encodeURIComponent(String(fp || "").trim());
    const qpool = encodeURIComponent(String(poolId || "default").trim() || "default");
    return await apiGet(`/api/v4/admin/users/storage_preview?fingerprint=${qfp}&pool_id=${qpool}`);
}

function injectAdminUsersPromptCss() {
    if (document.getElementById("adminUsersPromptCss")) return;

    const style = document.createElement("style");
    style.id = "adminUsersPromptCss";
    style.textContent = `
.adminUsersPromptBackdrop{
    position:fixed;
    inset:0;
    z-index:100000;
    display:flex;
    align-items:center;
    justify-content:center;
    padding:18px;
    background:rgba(0,0,0,0.55);
    backdrop-filter:blur(6px);
    -webkit-backdrop-filter:blur(6px);
}
.adminUsersPromptCard{
    width:min(660px, calc(100vw - 24px));
    max-height:min(84vh, 900px);
    display:flex;
    flex-direction:column;
    overflow:hidden;
    border:1px solid var(--border2, rgba(120,120,120,0.45));
    border-radius:18px;
    background:linear-gradient(180deg, var(--panel2, #f8f8f8), var(--panel, #eeeeee));
    box-shadow:0 18px 70px rgba(0,0,0,0.42);
    color:var(--fg, #111);
}
.adminUsersPromptHead{
    padding:14px 16px;
    border-bottom:1px solid var(--border2, rgba(120,120,120,0.35));
    background:rgba(0,0,0,0.08);
}
.adminUsersPromptTitle{
    font-weight:950;
    letter-spacing:.2px;
    font-size:16px;
}
.adminUsersPromptSub{
    margin-top:4px;
    font-size:12px;
    color:var(--fg-dim, rgba(0,0,0,0.65));
}
.adminUsersPromptBody{
    padding:16px;
    display:grid;
    grid-template-columns:140px minmax(0, 1fr);
    gap:10px 14px;
    overflow:auto;
    min-height:0;
}
.adminUsersPromptKey{
    color:var(--fg-dim, rgba(0,0,0,0.68));
    font-weight:850;
}
.adminUsersPromptValue{
    color:var(--fg, #111);
    overflow-wrap:anywhere;
    white-space:pre-wrap;
}
.adminUsersPromptValue.mono{
    font-family:var(--mono, ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace);
    font-size:12px;
}
.adminUsersPromptInput{
    width:100%;
    padding:10px 12px;
    border-radius:12px;
    border:1px solid var(--border2, rgba(120,120,120,0.45));
    background:rgba(0,0,0,0.18);
    color:var(--fg, #111);
    font:inherit;
    font-family:var(--mono, ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace);
}
.adminUsersPromptNote{
    grid-column:1 / -1;
    padding:10px 12px;
    border:1px solid rgba(var(--warn-rgb, 180,120,20),0.35);
    border-radius:14px;
    background:rgba(var(--warn-rgb, 180,120,20),0.10);
    color:var(--fg, #111);
    font-weight:850;
}
.adminUsersPromptErr{
    grid-column:1 / -1;
    display:none;
    padding:8px 10px;
    border:1px solid rgba(var(--fail-rgb, 180,40,40),0.35);
    border-radius:12px;
    background:rgba(var(--fail-rgb, 180,40,40),0.10);
    color:var(--fg, #111);
    font-weight:850;
}
.adminUsersPromptFoot{
    display:flex;
    align-items:center;
    gap:12px;
    padding:12px 16px;
    border-top:1px solid var(--border2, rgba(120,120,120,0.35));
    background:rgba(0,0,0,0.08);
}
.adminUsersPromptBtn{
    border:1px solid var(--border2, rgba(120,120,120,0.45));
    border-radius:14px;
    padding:9px 14px;
    font:inherit;
    font-weight:850;
    color:var(--fg, #111);
    background:linear-gradient(180deg, rgba(255,255,255,0.20), rgba(0,0,0,0.04));
    cursor:pointer;
}
.adminUsersPromptBtn.warn{
    border-color:rgba(var(--warn-rgb, 180,120,20),0.48);
    background:rgba(var(--warn-rgb, 180,120,20),0.16);
}
html[data-theme="bright"] .adminUsersPromptBackdrop{
    background:rgba(0,0,0,0.30);
}
html[data-theme="bright"] .adminUsersPromptCard{
    background:linear-gradient(180deg, #ffffff, #f2f4f7) !important;
    border-color:rgba(70,80,95,0.32) !important;
    color:#111827 !important;
    box-shadow:0 22px 80px rgba(0,0,0,0.28) !important;
}
html[data-theme="bright"] .adminUsersPromptHead,
html[data-theme="bright"] .adminUsersPromptFoot{
    background:rgba(15,23,42,0.045) !important;
    border-color:rgba(70,80,95,0.22) !important;
}
html[data-theme="bright"] .adminUsersPromptTitle,
html[data-theme="bright"] .adminUsersPromptValue,
html[data-theme="bright"] .adminUsersPromptBtn,
html[data-theme="bright"] .adminUsersPromptInput{
    color:#111827 !important;
}
html[data-theme="bright"] .adminUsersPromptSub,
html[data-theme="bright"] .adminUsersPromptKey{
    color:rgba(17,24,39,0.68) !important;
}
html[data-theme="bright"] .adminUsersPromptInput{
    background:#fff !important;
}
html[data-theme="win_classic"] .adminUsersPromptBackdrop{
    background:rgba(0,0,0,0.38);
}
`;
    document.head.appendChild(style);
}

function openAdminUsersPromptModal(opts = {}) {
    injectAdminUsersPromptCss();

    return new Promise((resolve) => {
        const options = opts || {};

        const modal = document.createElement("div");
        modal.className = "adminUsersPromptBackdrop";
        modal.setAttribute("role", "dialog");
        modal.setAttribute("aria-modal", "true");

        const card = document.createElement("div");
        card.className = "adminUsersPromptCard";

        const head = document.createElement("div");
        head.className = "adminUsersPromptHead";

        const title = document.createElement("div");
        title.className = "adminUsersPromptTitle";
        title.textContent = options.title || tr("admin.users.prompt.enter_value", null, "Enter value");

        const sub = document.createElement("div");
        sub.className = "adminUsersPromptSub";
        sub.textContent = options.subtitle || "";

        head.appendChild(title);
        if (sub.textContent) head.appendChild(sub);

        const body = document.createElement("div");
        body.className = "adminUsersPromptBody";

        for (const row of Array.isArray(options.rows) ? options.rows : []) {
            const k = document.createElement("div");
            k.className = "adminUsersPromptKey";
            k.textContent = String(row.label || "");

            const v = document.createElement("div");
            v.className = row.mono ? "adminUsersPromptValue mono" : "adminUsersPromptValue";
            v.textContent = String(row.value || "");

            body.appendChild(k);
            body.appendChild(v);
        }

        const label = document.createElement("label");
        label.className = "adminUsersPromptKey";
        label.textContent = options.label || tr("admin.users.prompt.value", null, "Value");

        const input = document.createElement("input");
        input.type = "text";
        input.className = "adminUsersPromptInput";
        input.value = options.value || "";
        input.placeholder = options.placeholder || "";
        input.autocomplete = "off";
        input.spellcheck = false;

        body.appendChild(label);
        body.appendChild(input);

        if (options.note) {
            const note = document.createElement("div");
            note.className = "adminUsersPromptNote";
            note.textContent = String(options.note || "");
            body.appendChild(note);
        }

        const err = document.createElement("div");
        err.className = "adminUsersPromptErr";
        body.appendChild(err);

        const foot = document.createElement("div");
        foot.className = "adminUsersPromptFoot";

        const spacer = document.createElement("div");
        spacer.style.flex = "1 1 auto";

        const cancelBtn = document.createElement("button");
        cancelBtn.type = "button";
        cancelBtn.className = "adminUsersPromptBtn";
        cancelBtn.textContent = options.cancelText || tr("admin.users.cancel", null, "Cancel");

        const okBtn = document.createElement("button");
        okBtn.type = "button";
        okBtn.className = options.warn ? "adminUsersPromptBtn warn" : "adminUsersPromptBtn";
        okBtn.textContent = options.confirmText || tr("admin.users.ok", null, "OK");

        foot.appendChild(spacer);
        foot.appendChild(cancelBtn);
        foot.appendChild(okBtn);

        card.appendChild(head);
        card.appendChild(body);
        card.appendChild(foot);
        modal.appendChild(card);
        document.body.appendChild(modal);

        const showError = (text) => {
            err.textContent = text || "";
            err.style.display = text ? "block" : "none";
        };

        const finish = (value) => {
            document.removeEventListener("keydown", onKey, true);
            modal.remove();
            resolve(value);
        };

        const submit = () => {
            const value = String(input.value || "").trim();

            if (options.required !== false && !value) {
                showError(tr("admin.users.prompt.value_required", null, "Value is required."));
                input.focus();
                return;
            }

            if (typeof options.validate === "function") {
                const msg = options.validate(value);
                if (msg) {
                    showError(msg);
                    input.focus();
                    input.select();
                    return;
                }
            }

            finish(value);
        };

        const onKey = (ev) => {
            if (ev.key === "Escape") {
                ev.preventDefault();
                ev.stopPropagation();
                finish(null);
                return;
            }

            if (ev.key === "Enter") {
                ev.preventDefault();
                ev.stopPropagation();
                submit();
            }
        };

        document.addEventListener("keydown", onKey, true);

        modal.addEventListener("click", (ev) => {
            if (ev.target === modal) finish(null);
        });

        cancelBtn.addEventListener("click", () => finish(null));
        okBtn.addEventListener("click", submit);

        window.setTimeout(() => {
            input.focus();
            input.select();
        }, 0);
    });
}



function openAdminUsersConfirmModal(opts = {}) {
    injectAdminUsersPromptCss();

    return new Promise((resolve) => {
        const options = opts || {};

        const modal = document.createElement("div");
        modal.className = "adminUsersPromptBackdrop";
        modal.setAttribute("role", "dialog");
        modal.setAttribute("aria-modal", "true");

        const card = document.createElement("div");
        card.className = "adminUsersPromptCard";

        const head = document.createElement("div");
        head.className = "adminUsersPromptHead";

        const title = document.createElement("div");
        title.className = "adminUsersPromptTitle";
        title.textContent = options.title || tr("admin.users.confirm_action", null, "Confirm action");

        const sub = document.createElement("div");
        sub.className = "adminUsersPromptSub";
        sub.textContent = options.subtitle || "";

        head.appendChild(title);
        if (sub.textContent) head.appendChild(sub);

        const body = document.createElement("div");
        body.className = "adminUsersPromptBody";

        for (const row of Array.isArray(options.rows) ? options.rows : []) {
            const k = document.createElement("div");
            k.className = "adminUsersPromptKey";
            k.textContent = String(row.label || "");

            const v = document.createElement("div");
            v.className = row.mono ? "adminUsersPromptValue mono" : "adminUsersPromptValue";
            v.textContent = String(row.value || "");

            body.appendChild(k);
            body.appendChild(v);
        }

        if (options.note) {
            const note = document.createElement("div");
            note.className = "adminUsersPromptNote";
            note.textContent = String(options.note || "");
            body.appendChild(note);
        }

        const foot = document.createElement("div");
        foot.className = "adminUsersPromptFoot";

        const spacer = document.createElement("div");
        spacer.style.flex = "1 1 auto";

        const cancelBtn = document.createElement("button");
        cancelBtn.type = "button";
        cancelBtn.className = "adminUsersPromptBtn";
        cancelBtn.textContent = options.cancelText || tr("admin.users.cancel", null, "Cancel");

        const okBtn = document.createElement("button");
        okBtn.type = "button";
        okBtn.className = options.danger ? "adminUsersPromptBtn warn" : "adminUsersPromptBtn";
        okBtn.textContent = options.confirmText || tr("admin.users.ok", null, "OK");

        if (options.danger) {
            okBtn.style.borderColor = "rgba(var(--fail-rgb, 180,40,40),0.48)";
            okBtn.style.background = "rgba(var(--fail-rgb, 180,40,40),0.14)";
        }

        foot.appendChild(spacer);
        foot.appendChild(cancelBtn);
        foot.appendChild(okBtn);

        card.appendChild(head);
        card.appendChild(body);
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


async function apiGetCleanupStatus(jobId) {
    const q = encodeURIComponent(String(jobId || "").trim());
    return await apiGet(`/api/v4/admin/users/cleanup_old_storage_status?job_id=${q}`);
}

function kvLine(key, value) {
    return `${key}: ${value}`;
}

function fmtMigText(job) {
    const state = String(job?.state || "unknown");
    const phase = String(job?.phase || "");
    const percent = Number(job?.percent);
    const msg = String(job?.message || "");

    let out = kvLine(tr("admin.users.state", null, "State"), state);
    if (phase) out += "\n" + kvLine(tr("admin.users.phase", null, "Phase"), phase);
    if (Number.isFinite(percent)) out += "\n" + kvLine(tr("admin.users.progress", null, "Progress"), `${percent}%`);
    if (msg) out += "\n" + kvLine(tr("admin.users.message", null, "Message"), msg);

    const src = job?.resolved_source_pool_id || "default";
    const dst = job?.resolved_dest_pool_id || job?.requested_target_pool_id || "default";

    if (src) out += "\n" + kvLine(tr("admin.users.from", null, "From"), src);
    if (dst) out += "\n" + kvLine(tr("admin.users.to", null, "To"), dst);

    if (job?.error) out += "\n" + kvLine(tr("admin.users.error", null, "Error"), job.error);

    return out;
}

async function pollMigrationJob(jobId, fp) {
    const startedAt = Date.now();
    const timeoutMs = 10 * 60 * 1000; // 10 min safety cap for UI polling
    let lastShownState = "";

    for (;;) {
        const j = await apiGetMigrationStatus(jobId);
        const job = j?.job || {};

        const state = String(job.state || "");
        const phase = String(job.phase || "");
        const percent = Number(job.percent);

        const progressBits = [];
        if (phase) progressBits.push(phase);
        if (Number.isFinite(percent)) progressBits.push(`${percent}%`);
        setMsg(progressBits.length ? tr("admin.users.migration_progress", { progress: progressBits.join(" · ") }, `Migration ${progressBits.join(" · ")}`) : tr("admin.users.migration_state", { state: state || "running" }, `Migration ${state || "running"}…`));

        // Optional small toast on first visible transition
        const stateKey = `${state}:${phase}:${percent}`;
        if (lastShownState !== stateKey && (state === "queued" || state === "running")) {
            lastShownState = stateKey;
        }

        if (state === "done") {
            closeMigrateModal();
            await refresh();
            showToast(tr("admin.users.migration_completed_toast", { details: fmtMigText(job) }, "Storage migration completed\n" + fmtMigText(job)));
            setMsg(tr("admin.users.migration_completed", null, "Migration completed"));
            return;
        }

        if (state === "failed") {
            await refresh();
            const text = fmtMigText(job);
            setMigrateError(job?.message || job?.error || tr("admin.users.migration_failed", null, "Migration failed"));
            showToast(tr("admin.users.migration_failed_toast", { details: text }, "Storage migration failed\n" + text), 15000);
            setMsg(tr("admin.users.migration_failed", null, "Migration failed"));
            return;
        }

        if ((Date.now() - startedAt) > timeoutMs) {
            setMigrateError(tr("admin.users.migration_timeout_detail", null, "Migration polling timed out. Job is still on server; reopen status later."));
            showToast(tr("admin.users.migration_timeout_toast", { job: jobId }, `Migration still in progress\nJob: ${jobId}`), 15000);
            setMsg(tr("admin.users.migration_timeout", null, "Migration polling timed out"));
            return;
        }

        await new Promise(resolve => setTimeout(resolve, 1200));
    }
}

function fmtCleanupText(job) {
    const state = String(job?.state || "unknown");
    const phase = String(job?.phase || "");
    const percent = Number(job?.percent);
    const msg = String(job?.message || "");

    let out = kvLine(tr("admin.users.state", null, "State"), state);
    if (phase) out += "\n" + kvLine(tr("admin.users.phase", null, "Phase"), phase);
    if (Number.isFinite(percent)) out += "\n" + kvLine(tr("admin.users.progress", null, "Progress"), `${percent}%`);
    if (msg) out += "\n" + kvLine(tr("admin.users.message", null, "Message"), msg);

    const activePool = job?.resolved_active_pool_id || job?.expected_active_pool_id || "default";
    const oldPool = job?.resolved_old_pool_id || job?.old_pool_id || "?";

    out += "\n" + kvLine(tr("admin.users.active_pool", null, "Active pool"), activePool);
    out += "\n" + kvLine(tr("admin.users.old_pool", null, "Old pool"), oldPool);

    if (job?.result?.removed_entries != null) {
        out += "\n" + kvLine(tr("admin.users.removed_entries", null, "Removed entries"), job.result.removed_entries);
    }

    if (job?.error) out += "\n" + kvLine(tr("admin.users.error", null, "Error"), job.error);
    return out;
}

async function pollCleanupJob(jobId, fp) {
    const startedAt = Date.now();
    const timeoutMs = 10 * 60 * 1000;

    for (;;) {
        const j = await apiGetCleanupStatus(jobId);
        const job = j?.job || {};

        const state = String(job.state || "");
        const phase = String(job.phase || "");
        const percent = Number(job.percent);

        const progressBits = [];
        if (phase) progressBits.push(phase);
        if (Number.isFinite(percent)) progressBits.push(`${percent}%`);
        setMsg(progressBits.length ? tr("admin.users.cleanup_progress", { progress: progressBits.join(" · ") }, `Cleanup ${progressBits.join(" · ")}`) : tr("admin.users.cleanup_state", { state: state || "running" }, `Cleanup ${state || "running"}…`));

        if (state === "done") {
            await refresh();
            showToast(tr("admin.users.cleanup_completed_toast", { details: fmtCleanupText(job) }, "Old storage cleanup completed\n" + fmtCleanupText(job)));
            setMsg(tr("admin.users.cleanup_completed", null, "Cleanup completed"));
            return;
        }

        if (state === "failed") {
            await refresh();

            const err = String(job?.error || "");
            if (err.includes("cleanup_not_needed")) {
                showToast(tr("admin.users.cleanup_not_needed_toast", null, "Old storage cleanup not needed\nNo old inactive copy was found."));
                setMsg(tr("admin.users.cleanup_not_needed", null, "Cleanup not needed"));
                return;
            }

            showToast(tr("admin.users.cleanup_failed_toast", { details: fmtCleanupText(job) }, "Old storage cleanup failed\n" + fmtCleanupText(job)), 15000);
            setMsg(tr("admin.users.cleanup_failed", null, "Cleanup failed"));
            return;
        }

        if ((Date.now() - startedAt) > timeoutMs) {
            showToast(tr("admin.users.cleanup_timeout_toast", { job: jobId }, `Cleanup still in progress\nJob: ${jobId}`), 15000);
            setMsg(tr("admin.users.cleanup_timeout", null, "Cleanup polling timed out"));
            return;
        }

        await new Promise(resolve => setTimeout(resolve, 1200));
    }
}

async function submitMigrationFromModal() {
    const fp = gMigrateFp;
    if (!fp) return;

    const poolSel = $("migratePoolSel");
    const pool_id = String(poolSel?.value || "").trim();

    if (!pool_id) {
        setMigrateError(tr("admin.users.no_destination_pool", null, "No destination pool selected."));
        return;
    }

    const cur = allUsers.find(x => String(x.fingerprint || "") === fp) || {};
    const curPoolId = storagePoolIdForUser(cur);

    if (pool_id === curPoolId) {
        setMigrateError(tr("admin.users.destination_diff", null, "Destination pool must differ from current pool."));
        return;
    }

    const dstPool = (gPools || []).find(x => x.id === pool_id);
    const dstName = dstPool?.name || pool_id;
    const userLabel = String(cur.name || cur.email || cur.username || fp || "");

    const ok = await openAdminUsersConfirmModal({
        title: tr("admin.users.migrate_confirm_title", { pool: dstName }, `Migrate user storage to pool "${dstName}"?`),
        subtitle: tr("admin.users.migrate_confirm_subtitle", null, "This will create an async storage migration job."),
        rows: [
            { label: tr("admin.users.user", null, "User"), value: userLabel || fp, mono: true },
            { label: tr("admin.users.from", null, "From"), value: curPoolId || "default", mono: true },
            { label: tr("admin.users.to", null, "To"), value: dstName, mono: true },
        ],
        note: tr(
            "admin.users.migrate_confirm_note",
            null,
            "The worker will copy data, verify it, then switch the user's storage mapping. The old copy is kept until cleanup."
        ),
        confirmText: tr("admin.users.start_migration", null, "Start migration"),
        cancelText: tr("admin.users.cancel", null, "Cancel"),
        danger: false
    });

    if (!ok) return;

    try {
        setMigrateError("");
        setMsg(tr("admin.users.queuing_migration", null, "Queuing migration…"));

        const j = await apiPost("/api/v4/admin/users/migrate_storage", {
            fingerprint: fp,
            pool_id,
        });

        const jobId = String(j?.job_id || "").trim();
        if (!jobId) {
            throw new Error(tr("admin.users.migration_job_missing", null, "Migration job_id missing from server response"));
        }

        showToast(
            tr("admin.users.migration_queued_toast", { job: jobId, user: fp, to: dstName }, `Storage migration queued\nJob: ${jobId}\nUser: ${fp}\nTo: ${dstName}`)
        );

        setMsg(tr("admin.users.migration_queued", null, "Migration queued"));
        await pollMigrationJob(jobId, fp);
    } catch (e) {
        setMigrateError(String(e?.message || e));
        setMsg("Error: " + (e?.message || e));
    }
}

async function submitCleanupOldCopy(fp) {
    const cur = allUsers.find(x => String(x.fingerprint || "") === String(fp)) || {};
    if (String(cur.storage_state || "").toLowerCase() !== "allocated") {
        showToast(tr("admin.users.storage_required_migration", null, "Storage must be allocated before cleanup."), 7000);
        return;
    }

    const activePoolId = storagePoolIdForUser(cur);

    let oldPoolId = "";
    if (activePoolId === "default") {
                const cleanupUser =
            (typeof u !== "undefined" && u) ? u :
            (typeof user !== "undefined" && user) ? user :
            (typeof curUser !== "undefined" && curUser) ? curUser :
            (typeof selectedUser !== "undefined" && selectedUser) ? selectedUser :
            null;
        const cleanupActivePool = cleanupUser ? storagePoolIdForUser(cleanupUser) : "default";
        const cleanupUserLabel = cleanupUser
            ? String(cleanupUser.name || cleanupUser.email || cleanupUser.fingerprint || tr("admin.users.selected_user", null, "Selected user"))
            : ((typeof fp !== "undefined" && fp) ? String(fp) : tr("admin.users.selected_user", null, "Selected user"));

        oldPoolId = await openAdminUsersPromptModal({
            title: tr("admin.users.cleanup_title", null, "Cleanup old storage copy?"),
            subtitle: tr("admin.users.cleanup_sub", null, "Choose the old pool copy to remove for this user."),
            rows: [
                { label: tr("admin.users.user", null, "User"), value: cleanupUserLabel, mono: true },
                { label: tr("admin.users.active_pool", null, "Active pool"), value: cleanupActivePool, mono: true },
            ],
            label: tr("admin.users.old_pool_id", null, "Old pool id"),
            value: "raidtest",
            placeholder: tr("admin.users.old_pool_placeholder", null, "old pool id, for example raidtest"),
            note: tr("admin.users.cleanup_note", null, "Only the old inactive storage copy should be removed. The active pool is protected."),
            confirmText: tr("admin.users.continue_cleanup", null, "Continue cleanup"),
            cancelText: tr("admin.users.cancel", null, "Cancel"),
            warn: true,
            validate(value) {
                if (value === cleanupActivePool) return tr("admin.users.old_pool_active_error", null, "Old pool id cannot be the active pool.");
                if (value.includes("/") || value.includes("\\")) return tr("admin.users.pool_id_not_path", null, "Use a pool id, not a path.");
                return "";
            },
        }) || "";
    } else {
        oldPoolId = await openAdminUsersPromptModal({
            title: tr("admin.users.cleanup_title", null, "Cleanup old storage copy?"),
            subtitle: tr("admin.users.cleanup_prompt_subtitle", { pool: activePoolId }, `User is currently active on ${activePoolId}. Choose the old pool copy to remove.`),
            rows: [
                { label: tr("admin.users.user", null, "User"), value: String(cur.name || cur.email || cur.username || fp || ""), mono: true },
                { label: tr("admin.users.active_pool", null, "Active pool"), value: activePoolId, mono: true },
            ],
            label: tr("admin.users.old_pool_id", null, "Old pool id"),
            value: "default",
            placeholder: tr("admin.users.old_pool_placeholder_default", null, "default or old pool id"),
            note: tr("admin.users.cleanup_prompt_note", null, "Enter the inactive old pool id to delete. The active pool is protected."),
            confirmText: tr("admin.users.continue_cleanup", null, "Continue cleanup"),
            cancelText: tr("admin.users.cancel", null, "Cancel"),
            warn: true,
            validate(value) {
                if (value === activePoolId) return tr("admin.users.old_pool_active_error", null, "Old pool id cannot be the active pool.");
                if (value.includes("/") || value.includes("\\")) return tr("admin.users.pool_id_not_path", null, "Use a pool id, not a path.");
                return "";
            },
        }) || "";
    }

    oldPoolId = String(oldPoolId).trim();
    if (!oldPoolId) return;

    if (oldPoolId === activePoolId) {
        showToast(tr("admin.users.old_pool_must_differ", null, "Old pool must differ from the active pool."), 7000);
        return;
    }

    const cleanupUserLabel = String(cur.name || cur.email || cur.username || fp || "");

    const ok = await openAdminUsersConfirmModal({
        title: tr("admin.users.cleanup_confirm_title", null, "Delete old inactive storage copy?"),
        subtitle: tr("admin.users.cleanup_confirm_subtitle", null, "This removes the old passive copy after a successful storage migration."),
        rows: [
            { label: tr("admin.users.user", null, "User"), value: cleanupUserLabel || fp, mono: true },
            { label: tr("admin.users.active_pool", null, "Active pool"), value: activePoolId, mono: true },
            { label: tr("admin.users.old_pool", null, "Old pool"), value: oldPoolId, mono: true },
        ],
        note: tr(
            "admin.users.cleanup_confirm_note",
            null,
            "This deletes the old user subtree from the old pool. The currently active pool is protected."
        ),
        confirmText: tr("admin.users.delete_old_copy", null, "Delete old copy"),
        cancelText: tr("admin.users.cancel", null, "Cancel"),
        danger: true
    });

    if (!ok) return;

    try {
        setMsg(tr("admin.users.queuing_cleanup", null, "Queuing cleanup…"));

        const j = await apiPost("/api/v4/admin/users/cleanup_old_storage", {
            fingerprint: fp,
            expected_active_pool_id: activePoolId,
            old_pool_id: oldPoolId,
        });

        const jobId = String(j?.job_id || "").trim();
        if (!jobId) throw new Error(tr("admin.users.cleanup_job_missing", null, "Cleanup job_id missing from server response"));

        showToast(
            tr("admin.users.cleanup_queued_toast", { job: jobId, user: fp, active: activePoolId, old: oldPoolId }, `Old storage cleanup queued\nJob: ${jobId}\nUser: ${fp}\nActive pool: ${activePoolId}\nOld pool: ${oldPoolId}`)
        );

        setMsg(tr("admin.users.cleanup_queued", null, "Cleanup queued"));
        await pollCleanupJob(jobId, fp);
    } catch (e) {
        showToast(tr("admin.users.cleanup_failed_detail", { error: e?.message || e }, "Cleanup failed: " + (e?.message || e)), 15000);
        setMsg("Error: " + (e?.message || e));
    }
}

async function submitAllocationFromModal() {
    const fp = gAllocFp;
    if (!fp) return;

    const poolSel = $("allocPoolSel");
    const gbInp = $("allocGb");

    const pool_id = String(poolSel?.value || "default");
    const quota_gb = Number(String(gbInp?.value || "").trim());

    if (!isFinite(quota_gb) || quota_gb < 0) {
        setAllocError(tr("admin.users.invalid_amount", null, "Invalid amount. Enter a number ≥ 0."));
        return;
    }

    const cur = allUsers.find(x => String(x.fingerprint || "") === fp) || {};
    const isAllocated = String(cur.storage_state || "").toLowerCase() === "allocated";
    const force = isAllocated;

    if (isAllocated) {
        const targetUser = allUsers.find(x => String(x.fingerprint || "") === fp) || {};
        const ok = await openAdminUsersConfirmModal({
            title: tr("admin.users.already_allocated_title", null, "Storage is already allocated"),
            subtitle: tr("admin.users.already_allocated_subtitle", null, "Change this user's storage pool or quota anyway?"),
            rows: [
                { label: tr("admin.users.user", null, "User"), value: String(targetUser.name || targetUser.email || fp), mono: true },
                { label: tr("admin.users.current_pool", null, "Current pool"), value: storagePoolIdForUser(targetUser), mono: true },
                { label: tr("admin.users.new_pool", null, "New pool"), value: pool_id || "default", mono: true },
            ],
            note: tr("admin.users.already_allocated_note", null, "This updates an existing storage allocation instead of creating a new one."),
            confirmText: tr("admin.users.change_storage", null, "Change storage"),
            cancelText: tr("admin.users.cancel", null, "Cancel"),
            danger: false,
        });
        if (!ok) return;
    }

    try {
        setAllocError("");
        setMsg(isAllocated ? tr("admin.users.updating_storage", null, "Updating storage…") : tr("admin.users.allocating", null, "Allocating…"));

        // Reuse your existing endpoint; we add pool_id
        const j = await apiPost("/api/v4/admin/users/storage", {
            fingerprint: fp,
            quota_gb,
            force,
            pool_id,
        });

        closeAllocModal();
        await refresh();

        const qb = Number(j.quota_bytes || 0);
        const quotaText = qb ? fmtBytes(qb) : `${quota_gb} GB`;
        const root = j.root_rel || "";
        const at = j.storage_set_at || "";

        showToast(
            tr(
                isAllocated ? "admin.users.storage_updated_toast" : "admin.users.storage_allocated_toast",
                {
                    pool: pool_id,
                    path: root ? tr("admin.users.path", { path: root }, `Path: ${root}\n`) : "",
                    quota: quotaText,
                    setAt: at ? tr("admin.users.set_at", { time: at }, `Set at: ${at}`) : ""
                },
                (isAllocated ? "Storage updated (click to copy)\n" : "Storage allocated\n") +
                `Pool: ${pool_id}\n` +
                (root ? `Path: ${root}\n` : "") +
                `Quota: ${quotaText}\n` +
                (at ? `Set at: ${at}` : "")
            )
        );

        setMsg(isAllocated ? tr("admin.users.storage_updated", null, "Storage updated") : tr("admin.users.allocated", null, "Allocated"));
    } catch (e) {
        setAllocError(String(e?.message || e));
        setMsg("Error: " + (e?.message || e));
    }
}

let allUsers = [];
let actorFp = "";
// ----- pools + allocation modal state -----
let gPools = null; // array of { id, name, hint }
let gAllocFp = "";
let gMigrateFp = "";
let gAllocPreview = null;

function setMsg(text) {
    const el = $("msg");
    if (el) el.textContent = text || "";
}

function render() {
    const f = ($("filter")?.value || "").toLowerCase().trim();
    const rows = allUsers.filter(u => {
        const hay = [
            u.fingerprint, u.name, u.notes, u.role, u.status,
            u.group, u.email, u.storage_state,
            String(u.quota_bytes || "")
        ].join(" ").toLowerCase();
        return !f || hay.includes(f);
    });

    const tb = $("tbody");
    if (!tb) return;

    tb.innerHTML = rows.map(u => {

        const fp = String(u.fingerprint || "");
        const isOpen = openUsers.has(fp);
        const isSelf = actorFp && fp === actorFp;

        const selfTag = isSelf
            ? `<span class="pill enabled" title="${esc(tr("admin.users.this_is_you", null, "This is you"))}" style="margin-left:8px;">${esc(tr("admin.users.you", null, "you"))}</span>`
            : "";

        // Disallow self-modification (Allocate is allowed for self)
        // Allow self profile editing, but block dangerous self-actions
        const disEditAttr = "";
        const disEditClass = "";

        const disDangerAttr = isSelf
            ? ` disabled title="${esc(tr("admin.users.refuse_self", null, "Refusing to modify your own admin entry"))}"`
            : "";

        const disDangerClass = isSelf
            ? ` style="opacity:0.45; cursor:not-allowed;"`
            : "";


        // detail content
        const quotaBytes = Number(u.quota_bytes || 0);
        const quotaText = quotaBytes ? fmtBytes(quotaBytes) : "—";

        const usedBytes = Number(u.used_bytes ?? u.storage_used_bytes ?? 0);
        const quotaBytes2 = Number(u.quota_bytes ?? 0);

        const pct = quotaBytes2 > 0 ? clamp01(usedBytes / quotaBytes2) : 0;
        const pct100 = (pct * 100).toFixed(1);

        const quotaCls =
            pct >= 0.90 ? "danger" :
                pct >= 0.70 ? "warn" :
                    "";

        const detailRow = isOpen ? `

<tr class="detailRow" data-fp="${esc(fp)}">
  <td colspan="10">
    <div class="detailGrid">
      <div class="detailBox">
        <h3>${esc(tr("admin.users.profile", null, "Profile"))}</h3>
        ${avatarSrc(u) ? `
          <div style="display:flex; gap:12px; align-items:center; margin:10px 0 14px;">
            <img
              src="${esc(avatarSrc(u))}"
              alt="${esc(tr("admin.users.avatar_alt", null, "avatar"))}"
              data-avatar-open="1"
              data-fp="${esc(fp)}"
              style="width:128px; height:128px; border-radius:22px; object-fit:cover; border:1px solid var(--border); background:var(--panel2); cursor:pointer;"
              title="${esc(tr("admin.users.click_preview", null, "Click to preview"))}"
              onerror="this.style.borderColor='red'; this.title='${esc(tr("admin.users.avatar_failed", null, "Avatar failed to load"))}';"
            />


            <div class="muted" style="line-height:1.25;">
              ${esc(tr("admin.users.avatar", null, "Avatar"))}<br/>
              <span class="mono" style="font-size:12px;">${esc(avatarSrc(u))}</span>
            </div>
          </div>
        ` : `
          <div class="muted" style="margin:8px 0 14px;">
            ${esc(tr("admin.users.avatar", null, "Avatar"))}: <span class="mono">—</span>
          </div>
        `}

        <div class="detailActions">
            <button class="btn secondary" data-edit="${esc(fp)}" type="button" title="${esc(tr("admin.users.load_edit_title", null, "Load this user into the edit form"))}" ${disEditAttr}${disEditClass}>${esc(tr("admin.users.edit", null, "Edit"))}</button>
        </div>

        <div class="detailKV"><div class="k">${esc(tr("admin.users.fingerprint", null, "Fingerprint"))}</div><div class="v mono">${esc(fp)}</div></div>
        <div class="detailKV"><div class="k">${esc(tr("admin.users.name_placeholder", null, "Name"))}</div><div class="v">${esc(u.name || "—")}</div></div>
        <div class="detailKV"><div class="k">${esc(tr("admin.users.role", null, "Role"))}</div><div class="v">${esc(u.role || "—")}</div></div>
        <div class="detailKV"><div class="k">${esc(tr("admin.users.status", null, "Status"))}</div><div class="v">${pill(u.status)}</div></div>
        <div class="detailKV"><div class="k">${esc(tr("admin.users.group", null, "Group"))}</div><div class="v">${esc(u.group || "—")}</div></div>
        <div class="detailKV"><div class="k">${esc(tr("admin.users.email", null, "Email"))}</div><div class="v">${esc(u.email || "—")}</div></div>
        <div class="detailKV"><div class="k">${esc(tr("admin.users.storage", null, "Storage"))}</div><div class="v">${storageCellHtml(u)}</div></div>
        <div class="detailKV"><div class="k">${esc(tr("admin.users.quota", null, "Quota"))}</div><div class="v mono">${esc(quotaText)}</div></div>
        <div class="detailKV"><div class="k">${esc(tr("admin.users.added", null, "Added"))}</div><div class="v mono">${esc(u.added_at || "—")}</div></div>
        <div class="detailKV"><div class="k">${esc(tr("admin.users.last_seen", null, "Last seen"))}</div><div class="v mono">${esc(u.last_seen || "—")}</div></div>
      </div>

      <div class="detailBox">
        <h3>${esc(tr("admin.users.notes", null, "Notes"))}</h3>
        <pre class="detailPre">${esc(u.notes || "—")}</pre>

        <div class="quotaBox">
          <div class="quotaTop">
            <div class="quotaLabel">${esc(tr("admin.users.storage_usage", null, "Storage usage"))}</div>
            <div class="quotaNum mono">${esc(quotaUsageText(u.used_bytes ?? u.storage_used_bytes, u.quota_bytes))}</div>
          </div>
            <div class="quotaBar" title="${esc(quotaUsageText(usedBytes, quotaBytes2))}">
                <div class="quotaFill ${quotaCls}" style="width:${pct100}%"></div>
          </div>
        </div>
      </div>

<div class="detailBox">
  <h3>${esc(tr("admin.users.actions", null, "Actions"))}</h3>
  <div class="detailActions">
    <button class="btn secondary"
            data-act="enable"
            data-fp="${esc(fp)}"
            type="button"
            title="${esc(tr("admin.users.enable_title", null, "Allow this fingerprint to log in again"))}"
            ${disDangerAttr}${disDangerClass}>${esc(tr("admin.users.enable", null, "Enable"))}</button>

    <button class="btn secondary"
            data-act="disable"
            data-fp="${esc(fp)}"
            type="button"
            title="${esc(tr("admin.users.disable_title", null, "Disable login until an admin enables it again"))}"
            ${disDangerAttr}${disDangerClass}>${esc(tr("admin.users.disable", null, "Disable"))}</button>

    <button class="btn secondary"
            data-act="revoke"
            data-fp="${esc(fp)}"
            type="button"
            title="${esc(tr("admin.users.revoke_title", null, "Hard-block this fingerprint from logging in"))}"
            ${disDangerAttr}${disDangerClass}>${esc(tr("admin.users.revoke", null, "Revoke"))}</button>

    <button class="btn secondary"
            data-act="allocate"
            data-fp="${esc(fp)}"
            type="button"
            title="${esc(tr("admin.users.allocate_title", null, "Allocate storage and set quota for this user"))}">${esc(tr("admin.users.allocate", null, "Allocate"))}</button>
            
    ${String(u.storage_state || "").toLowerCase() === "allocated" ? `
        <button class="btn secondary"
            data-act="migrate"
            data-fp="${esc(fp)}"
            type="button"
            title="${esc(tr("admin.users.migrate_title", null, "Move user storage to another pool with async copy and verify"))}">${esc(tr("admin.users.migrate", null, "Migrate"))}</button>

        <button class="btn secondary"
            data-act="cleanup-old-copy"
            data-fp="${esc(fp)}"
            type="button"
            title="${esc(tr("admin.users.cleanup_title", null, "Delete the old inactive storage copy left behind after migration"))}">${esc(tr("admin.users.cleanup_old_copy", null, "Cleanup old copy"))}</button>
    ` : ``}
    
    <button class="btn danger"
            data-act="delete"
            data-fp="${esc(fp)}"
            type="button"
            title="${esc(tr("admin.users.delete_title", null, "Remove this entry from users.json; the user can reappear if they scan again"))}"
            ${disDangerAttr}${disDangerClass}>${esc(tr("admin.users.delete", null, "Delete"))}</button>
  </div>

  ${isSelf
            ? `<div class="muted" style="margin-top:10px;">
         ${esc(tr("admin.users.self_protection", null, "Self-protection: enable / disable / revoke / delete are blocked for your own fingerprint."))}
       </div>`
            : ``}
</div>

    </div>
  </td>
</tr>

    `.trim() : "";

        return `
<tr class="userRow" data-fp="${esc(fp)}" aria-expanded="${isOpen ? "true" : "false"}">
  <td>${avatarThumb(u)}</td>

  <td class="mono">
    <button class="expBtn" data-exp="${esc(fp)}" type="button" aria-expanded="${isOpen ? "true" : "false"}" title="${esc(tr("admin.users.expand_collapse", null, "Expand/collapse"))}">
      ${isOpen ? "▾" : "▸"}
    </button>
    <span style="margin-left:8px;" title="${esc(fp)}">${esc(shortFp(fp))}</span>
  </td>

  <td>
    <div><b>${esc(u.name || "")}</b>${selfTag}</div>
    <div class="muted" style="white-space:pre-wrap;">${esc(u.notes || "")}</div>
  </td>

  <td>${esc(roleLabel(u.role || ""))}</td>
  <td>${pill(u.status)}</td>
  <td>${esc(u.group || "")}</td>
    <td>${storageCellHtml(u)}</td>
  <td class="mono">${fmtQuotaCell(u)}</td>
  <td class="mono">${esc(u.added_at || "")}</td>

  <td class="row-actions">
    <span class="muted">${esc(tr("admin.users.open", null, "Open ▸"))}</span>
  </td>
</tr>
${detailRow}
`.trim();

    }).join("");

    // ✅ Attach avatar modal click via delegation (works across rerenders)
    tb.onclick = (ev) => {
        const img = ev.target?.closest?.('img[data-avatar-open="1"]');
        if (!img) return;
        ev.stopPropagation();
        const fp = img.getAttribute("data-fp") || "";
        const src = img.getAttribute("src") || "";
        if (!src) return;
        openAvatarModal(fp, src);
    };


// -------------------- Edit button: load user into form --------------------
    tb.querySelectorAll("button[data-edit]").forEach(btn => {
        btn.addEventListener("click", (ev) => {
            ev.stopPropagation();

            const fp = btn.getAttribute("data-edit");
            if (!fp) return;

            const u = allUsers.find(x => String(x.fingerprint || "") === fp);
            if (!u) return;

            // Fill the edit form
            $("fp").value = fp;
            $("name").value = u.name || "";
            $("role").value = (u.role || "user");
            $("notes").value = u.notes || "";
            $("email").value = u.email || "";
            $("avatar_url").value = u.avatar_url || "";

            // bring it into view + focus
            $("fp").scrollIntoView({ behavior: "smooth", block: "center" });
            $("name").focus();
        });
    });


    // Expand/collapse handlers
    tb.querySelectorAll("button[data-exp]").forEach(btn => {
        btn.addEventListener("click", (ev) => {
            ev.stopPropagation();
            const fp = btn.getAttribute("data-exp");
            if (!fp) return;
            if (openUsers.has(fp)) openUsers.delete(fp);
            else openUsers.add(fp);
            render(); // re-render keeps multiple open
        });
    });

    // Optional: clicking the row toggles (but don't toggle when clicking action buttons)
    tb.querySelectorAll("tr.userRow").forEach(tr => {
        tr.addEventListener("click", (ev) => {
            const t = ev.target;
            if (t && (t.closest("button") || t.closest("a") || t.closest("input") || t.closest("select") || t.closest("textarea"))) {
                return; // let controls work normally
            }
            const fp = tr.getAttribute("data-fp");
            if (!fp) return;
            if (openUsers.has(fp)) openUsers.delete(fp);
            else openUsers.add(fp);
            render();
        });
    });

    // Existing action buttons (enable/disable/revoke/allocate/delete)
    tb.querySelectorAll("button[data-act]").forEach(b => {
        b.addEventListener("click", async () => {
            const fp = b.getAttribute("data-fp");
            const act = b.getAttribute("data-act");
            if (!fp || !act) return;

            const isSelf = actorFp && fp === actorFp;
            if (isSelf && (act === "enable" || act === "disable" || act === "revoke" || act === "delete")) {
                showToast(tr("admin.users.refuse_self", null, "Refusing to modify your own admin entry (prevents lockout or role change)."), 9000);
                return;
            }

            if (act === "delete") {
                const targetUser = allUsers.find(x => String(x.fingerprint || "") === String(fp)) || {};
                const ok = await openAdminUsersConfirmModal({
                    title: tr("admin.users.delete_confirm_title", null, "Delete user entry?"),
                    subtitle: tr("admin.users.delete_confirm_sub", null, "This removes the entry from users.json."),
                    rows: [
                        { label: tr("admin.users.user", null, "User"), value: String(targetUser.name || targetUser.email || fp), mono: true },
                        { label: tr("admin.users.fingerprint", null, "Fingerprint"), value: fp, mono: true },
                        { label: tr("admin.users.status", null, "Status"), value: statusLabel(targetUser.status || "—") },
                    ],
                    note: tr("admin.users.delete_confirm_note", null, "This removes the entry entirely as cleanup. If they scan again, they will re-appear as disabled."),
                    confirmText: tr("admin.users.delete_user", null, "Delete user"),
                    cancelText: tr("admin.users.cancel", null, "Cancel"),
                    danger: true,
                });
                if (!ok) return;

                try {
                    setMsg(tr("admin.users.deleting", null, "Deleting…"));
                    await apiPost("/api/v4/admin/users/delete", { fingerprint: fp });
                    await refresh();
                    setMsg(tr("admin.users.delete_ok", null, "Delete OK"));
                    showToast(tr("admin.users.user_deleted", null, "User deleted"));
                } catch (e) {
                    setMsg(tr("admin.users.error", { error: e.message }, "Error: " + e.message));
                    showToast(tr("admin.users.delete_failed", { error: e.message }, "Delete failed: " + e.message), 15000);
                }
                return;
            }

            if (act === "enable") {
                try {
                    setMsg(tr("admin.users.enabling", null, "Enabling…"));
                    await apiPost("/api/v4/admin/users/enable", { fingerprint: fp });
                    await refresh();
                    setMsg(tr("admin.users.enabled", null, "Enabled"));
                    showToast(tr("admin.users.user_enabled", null, "User enabled"));
                } catch (e) {
                    showToast(tr("admin.users.failed", { error: e.message }, "Failed: " + e.message), 15000);
                    setMsg(tr("admin.users.error", { error: e.message }, "Error: " + e.message));
                }
                return;
            }

            if (act === "allocate") {
                const cur = allUsers.find(x => String(x.fingerprint || "") === String(fp)) || {};
                openAllocModal(fp, cur);
                return;
            }
            if (act === "migrate") {
                const cur = allUsers.find(x => String(x.fingerprint || "") === String(fp)) || {};
                if (String(cur.storage_state || "").toLowerCase() !== "allocated") {
                    showToast(tr("admin.users.storage_required_migration", null, "Storage must be allocated before migration."), 7000);
                    return;
                }
                openMigrateModal(fp, cur);
                return;
            }
            if (act === "cleanup-old-copy") {
                await submitCleanupOldCopy(fp);
                return;
            }
            const status =
                (act === "disable") ? "disabled" :
                    (act === "revoke") ? "revoked" : "";

            if (!status) return;

            if (act === "revoke") {
                const targetUser = allUsers.find(x => String(x.fingerprint || "") === String(fp)) || {};
                const ok = await openAdminUsersConfirmModal({
                    title: tr("admin.users.revoke_confirm_title", null, "Revoke user?"),
                    subtitle: tr("admin.users.revoke_confirm_sub", null, "This hard-blocks login for this fingerprint."),
                    rows: [
                        { label: tr("admin.users.user", null, "User"), value: String(targetUser.name || targetUser.email || fp), mono: true },
                        { label: tr("admin.users.fingerprint", null, "Fingerprint"), value: fp, mono: true },
                        { label: tr("admin.users.current_status", null, "Current status"), value: statusLabel(targetUser.status || "—") },
                    ],
                    note: tr("admin.users.revoke_confirm_note", null, "Use this when this identity should not be allowed to log in again."),
                    confirmText: tr("admin.users.revoke_user", null, "Revoke user"),
                    cancelText: tr("admin.users.cancel", null, "Cancel"),
                    danger: true,
                });
                if (!ok) return;
            }

            try {
                setMsg(tr("admin.users.saving", null, "Saving…"));
                await apiPost("/api/v4/admin/users/status", { fingerprint: fp, status });
                await refresh();
                setMsg(tr("admin.users.saved", null, "Saved"));
                showToast(tr("admin.users.status_saved", { status: statusLabel(status) }, `User status: ${status}`));
            } catch (e) {
                showToast(tr("admin.users.failed", { error: e.message }, "Failed: " + e.message), 15000);
                setMsg(tr("admin.users.error", { error: e.message }, "Error: " + e.message));
            }
        });
    });
}

async function refresh() {
    setMsg(tr("admin.users.loading_users", null, "Loading users…"));
    const j = await apiGet("/api/v4/admin/users");
    actorFp = String(j.actor_fp || "");
    allUsers = (j.users || []).sort((a,b) => (a.fingerprint||"").localeCompare(b.fingerprint||""));
    render();
    setMsg(tr("admin.users.loaded_users", { count: allUsers.length }, `Loaded ${allUsers.length} users`));
}

async function upsertFromForm() {
    const fp = ($("fp")?.value || "").trim();
    const name = ($("name")?.value || "").trim();
    const role = ($("role")?.value || "user").trim();
    const notes = ($("notes")?.value || "").trim();

    const email = ($("email")?.value || "").trim();
    const avatar_url = ($("avatar_url")?.value || "").trim(); // only if you add this input

    if (!fp || fp.length < 32) throw new Error(tr("admin.users.fp_invalid", null, "fingerprint looks invalid"));

    await apiPost("/api/v4/admin/users/upsert", {
        fingerprint: fp,
        name,
        role,
        notes,
        email,
        avatar_url,
    });

    await refresh();
    setMsg(tr("admin.users.upsert_ok", null, "Upsert OK"));
    showToast(tr("admin.users.user_upserted", null, "User upserted"));
}


window.addEventListener("load", async () => {
    $("btnRefresh")?.addEventListener("click", refresh);
    $("filter")?.addEventListener("input", render);

    $("btnAdd")?.addEventListener("click", async () => {
        setMsg("");
        try { await upsertFromForm(); }
        catch (e) { setMsg(tr("admin.users.error", { error: e.message }, "Error: " + e.message)); }
    });

    // ---------------- Avatar picker wiring ----------------
    // Avatar modal wiring
    $("avatarCloseBtn")?.addEventListener("click", closeAvatarModal);
    $("avatarModal")?.addEventListener("click", (ev) => {
        // click on backdrop closes; click inside card does not
        if (ev.target && ev.target.id === "avatarModal") closeAvatarModal();
    });
    document.addEventListener("keydown", (ev) => {
        if (ev.key === "Escape") closeAvatarModal();
    });

    // ---------- Allocate modal wiring ----------
    $("allocCancelBtn")?.addEventListener("click", closeAllocModal);
    $("allocSaveBtn")?.addEventListener("click", submitAllocationFromModal);

    $("allocModal")?.addEventListener("click", (ev) => {
        if (ev.target && ev.target.id === "allocModal") closeAllocModal(); // backdrop
    });
    $("migrateCancelBtn")?.addEventListener("click", closeMigrateModal);
    $("migrateSaveBtn")?.addEventListener("click", submitMigrationFromModal);

    $("migrateModal")?.addEventListener("click", (ev) => {
        if (ev.target && ev.target.id === "migrateModal") closeMigrateModal();
    });
    document.addEventListener("keydown", (ev) => {
        if (ev.key === "Escape") {
            const m1 = $("allocModal");
            if (m1 && m1.classList.contains("open")) closeAllocModal();

            const m2 = $("migrateModal");
            if (m2 && m2.classList.contains("open")) closeMigrateModal();
        }
    });
    $("avatarRemoveBtn")?.addEventListener("click", async () => {
        if (!avatarModalFp) return;

        const ok = await openAdminUsersConfirmModal({
            title: tr("admin.users.avatar_remove_confirm_title", null, "Remove this user's avatar?"),
            subtitle: tr("admin.users.avatar_remove_confirm_subtitle", null, "The profile will return to the default generated avatar."),
            rows: [
                { label: tr("admin.users.fingerprint", null, "Fingerprint"), value: avatarModalFp, mono: true },
            ],
            note: tr("admin.users.avatar_remove_confirm_note", null, "This removes the uploaded avatar image reference from this user profile."),
            confirmText: tr("admin.users.remove_avatar", null, "Remove avatar"),
            cancelText: tr("admin.users.cancel", null, "Cancel"),
            danger: true,
        });
        if (!ok) return;

        try {
            setMsg(tr("admin.users.removing_avatar", null, "Removing avatar…"));
            await apiPost("/api/v4/admin/users/avatar_remove", { fingerprint: avatarModalFp });
            closeAvatarModal();
            await refresh();
            setMsg(tr("admin.users.avatar_removed", null, "Avatar removed"));
            showToast(tr("admin.users.avatar_removed", null, "Avatar removed"));
        } catch (e) {
            setMsg(tr("admin.users.error", { error: e.message }, "Error: " + e.message));
            showToast(tr("admin.users.remove_failed", { error: e.message }, "Remove failed: " + e.message), 15000);
        }
    });

    $("avatar_url")?.addEventListener("click", () => {
        $("avatar_file")?.click();
    });

    $("avatar_file")?.addEventListener("change", async () => {
        const file = $("avatar_file").files?.[0];
        if (!file) return;

        const fp = ($("fp")?.value || "").trim();
        if (!fp || fp.length < 32) {
            showToast(tr("admin.users.select_user_first", null, "Select a user first (fingerprint missing)."));
            $("avatar_file").value = "";
            return;
        }

        try {
            setMsg(tr("admin.users.preparing_avatar", null, "Preparing avatar…"));

            const prepared = await prepareAdminAvatarUploadBlob(file);
            const data_b64 = await blobToBase64(prepared.blob);

            setMsg(tr("admin.users.uploading_avatar", null, "Uploading avatar…"));

            const body = {
                fingerprint: fp,
                filename: file.name || "avatar.jpg",
                mime: prepared.mime,
                data_b64,
            };

            const j = await apiPost("/api/v4/admin/users/avatar_upload", body);

            $("avatar_url").value = j.avatar_url || "";

            setMsg(tr("admin.users.avatar_uploaded_save", null, "Avatar uploaded (click Upsert to save)"));
            showToast(
                tr("admin.users.avatar_uploaded_toast", { note: prepared.note ? prepared.note + "\n" : "" }, "Avatar uploaded\n" + (prepared.note ? prepared.note + "\n" : "") + "Click Upsert to save this avatar URL into the user profile.")
            );
        } catch (e) {
            const msg = tr("admin.users.upload_failed", { error: e?.message || e }, "Upload failed: " + (e?.message || e));
            setMsg("Error: " + (e?.message || e));
            showToast(msg, 15000);
        } finally {
            $("avatar_file").value = "";
        }
    });


    // ------------------------------------------------------

    try { await refresh(); }
    catch (e) { setMsg(tr("admin.users.failed", { error: e.message }, "Failed: " + e.message)); }
});



window.addEventListener("pqnas-language-changed", () => {
    applyStaticI18n();
    try { render(); } catch (_) {}
});
