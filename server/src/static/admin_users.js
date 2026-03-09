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

function pill(status) {
    const cls = (status || "disabled");
    return `<span class="pill ${cls}">${cls}</span>`;
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
        alt="avatar"
        style="width:26px;height:26px;border-radius:8px;object-fit:cover;border:1px solid var(--border);background:var(--panel2);"
        title="Avatar"
        onerror="this.style.opacity='0.35'; this.title='Avatar failed to load';"
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
    return `<span class="pill ${cls}">${esc(s)}</span>`;
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
        const name = isDefault ? "Default pool" : (disp || rawId);

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

        poolSel.onchange = () => {
            const s = (gPools || []).find(x => x.id === poolSel.value);
            poolHint.textContent = s?.hint ? s.hint : "—";
        };

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
            opt.textContent = "No other pools available";
            poolSel.appendChild(opt);
            poolSel.disabled = true;
            poolHint.textContent = "Create another pool first.";
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

async function apiGetCleanupStatus(jobId) {
    const q = encodeURIComponent(String(jobId || "").trim());
    return await apiGet(`/api/v4/admin/users/cleanup_old_storage_status?job_id=${q}`);
}

function fmtMigText(job) {
    const state = String(job?.state || "unknown");
    const phase = String(job?.phase || "");
    const percent = Number(job?.percent);
    const msg = String(job?.message || "");

    let out = `State: ${state}`;
    if (phase) out += `\nPhase: ${phase}`;
    if (Number.isFinite(percent)) out += `\nProgress: ${percent}%`;
    if (msg) out += `\nMessage: ${msg}`;

    const src = job?.resolved_source_pool_id || "default";
    const dst = job?.resolved_dest_pool_id || job?.requested_target_pool_id || "default";

    if (src) out += `\nFrom: ${src}`;
    if (dst) out += `\nTo: ${dst}`;

    if (job?.error) out += `\nError: ${job.error}`;

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
        setMsg(progressBits.length ? `Migration ${progressBits.join(" · ")}` : `Migration ${state || "running"}…`);

        // Optional small toast on first visible transition
        const stateKey = `${state}:${phase}:${percent}`;
        if (lastShownState !== stateKey && (state === "queued" || state === "running")) {
            lastShownState = stateKey;
        }

        if (state === "done") {
            closeMigrateModal();
            await refresh();
            showToast("Storage migration completed\n" + fmtMigText(job));
            setMsg("Migration completed");
            return;
        }

        if (state === "failed") {
            await refresh();
            const text = fmtMigText(job);
            setMigrateError(job?.message || job?.error || "Migration failed");
            showToast("Storage migration failed\n" + text, 15000);
            setMsg("Migration failed");
            return;
        }

        if ((Date.now() - startedAt) > timeoutMs) {
            setMigrateError("Migration polling timed out. Job is still on server; reopen status later.");
            showToast(`Migration still in progress\nJob: ${jobId}`, 15000);
            setMsg("Migration polling timed out");
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

    let out = `State: ${state}`;
    if (phase) out += `\nPhase: ${phase}`;
    if (Number.isFinite(percent)) out += `\nProgress: ${percent}%`;
    if (msg) out += `\nMessage: ${msg}`;

    const activePool = job?.resolved_active_pool_id || job?.expected_active_pool_id || "default";
    const oldPool = job?.resolved_old_pool_id || job?.old_pool_id || "?";

    out += `\nActive pool: ${activePool}`;
    out += `\nOld pool: ${oldPool}`;

    if (job?.result?.removed_entries != null) {
        out += `\nRemoved entries: ${job.result.removed_entries}`;
    }

    if (job?.error) out += `\nError: ${job.error}`;
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
        setMsg(progressBits.length ? `Cleanup ${progressBits.join(" · ")}` : `Cleanup ${state || "running"}…`);

        if (state === "done") {
            await refresh();
            showToast("Old storage cleanup completed\n" + fmtCleanupText(job));
            setMsg("Cleanup completed");
            return;
        }

        if (state === "failed") {
            await refresh();
            showToast("Old storage cleanup failed\n" + fmtCleanupText(job), 15000);
            setMsg("Cleanup failed");
            return;
        }

        if ((Date.now() - startedAt) > timeoutMs) {
            showToast(`Cleanup still in progress\nJob: ${jobId}`, 15000);
            setMsg("Cleanup polling timed out");
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
        setMigrateError("No destination pool selected.");
        return;
    }

    const cur = allUsers.find(x => String(x.fingerprint || "") === fp) || {};
    const curPoolId = storagePoolIdForUser(cur);

    if (pool_id === curPoolId) {
        setMigrateError("Destination pool must differ from current pool.");
        return;
    }

    if (!confirm(`Migrate user storage to pool "${pool_id}"?\n\nThis will create an async job. The worker will copy data, verify it, then switch the user's storage mapping.`)) {
        return;
    }

    try {
        setMigrateError("");
        setMsg("Queuing migration…");

        const j = await apiPost("/api/v4/admin/users/migrate_storage", {
            fingerprint: fp,
            pool_id,
        });

        const jobId = String(j?.job_id || "").trim();
        if (!jobId) {
            throw new Error("Migration job_id missing from server response");
        }

        const dstPool = (gPools || []).find(x => x.id === pool_id);
        const dstName = dstPool?.name || pool_id;

        showToast(
            "Storage migration queued\n" +
            `Job: ${jobId}\n` +
            `User: ${fp}\n` +
            `To: ${dstName}`
        );

        setMsg("Migration queued");
        await pollMigrationJob(jobId, fp);
    } catch (e) {
        setMigrateError(String(e?.message || e));
        setMsg("Error: " + (e?.message || e));
    }
}

async function submitCleanupOldCopy(fp) {
    const cur = allUsers.find(x => String(x.fingerprint || "") === String(fp)) || {};
    if (String(cur.storage_state || "").toLowerCase() !== "allocated") {
        alert("Storage must be allocated before cleanup.");
        return;
    }

    const activePoolId = currentPoolIdForUser(cur);

    let oldPoolId = "";
    if (activePoolId === "default") {
        oldPoolId = prompt(
            "Cleanup old copy from which pool?\n\nUser is currently active on default.\nEnter old pool id to delete, for example: raidtest",
            "raidtest"
        ) || "";
    } else {
        oldPoolId = prompt(
            `Cleanup old copy from which pool?\n\nUser is currently active on ${activePoolId}.\nEnter old pool id to delete, or use "default" if the stale copy is there.`,
            "default"
        ) || "";
    }

    oldPoolId = String(oldPoolId).trim();
    if (!oldPoolId) return;

    if (oldPoolId === activePoolId) {
        alert("Old pool must differ from the active pool.");
        return;
    }

    const ok = confirm(
        `Delete old inactive storage copy?\n\n` +
        `User: ${fp}\n` +
        `Active pool: ${activePoolId}\n` +
        `Old pool to delete: ${oldPoolId}\n\n` +
        `This deletes the old user subtree from the old pool.`
    );
    if (!ok) return;

    try {
        setMsg("Queuing cleanup…");

        const j = await apiPost("/api/v4/admin/users/cleanup_old_storage", {
            fingerprint: fp,
            expected_active_pool_id: activePoolId,
            old_pool_id: oldPoolId,
        });

        const jobId = String(j?.job_id || "").trim();
        if (!jobId) throw new Error("Cleanup job_id missing from server response");

        showToast(
            "Old storage cleanup queued\n" +
            `Job: ${jobId}\n` +
            `User: ${fp}\n` +
            `Active pool: ${activePoolId}\n` +
            `Old pool: ${oldPoolId}`
        );

        setMsg("Cleanup queued");
        await pollCleanupJob(jobId, fp);
    } catch (e) {
        alert("Cleanup failed: " + (e?.message || e));
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
        setAllocError("Invalid amount. Enter a number ≥ 0.");
        return;
    }

    const cur = allUsers.find(x => String(x.fingerprint || "") === fp) || {};
    const isAllocated = String(cur.storage_state || "").toLowerCase() === "allocated";
    const force = isAllocated;

    if (isAllocated) {
        if (!confirm("Storage is already allocated for this user.\n\nChange pool/quota anyway?")) return;
    }

    try {
        setAllocError("");
        setMsg(isAllocated ? "Updating storage…" : "Allocating…");

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
            (isAllocated ? "Storage updated (click to copy)\n" : "Storage allocated\n") +
            `Pool: ${pool_id}\n` +
            (root ? `Path: ${root}\n` : "") +
            `Quota: ${quotaText}\n` +
            (at ? `Set at: ${at}` : "")
        );

        setMsg(isAllocated ? "Storage updated" : "Allocated");
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
            ? `<span class="pill enabled" title="This is you" style="margin-left:8px;">you</span>`
            : "";

        // Disallow self-modification (Allocate is allowed for self)
        // Allow self profile editing, but block dangerous self-actions
        const disEditAttr = "";
        const disEditClass = "";

        const disDangerAttr = isSelf
            ? ` disabled title="Refusing to modify your own admin entry"`
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
        <h3>Profile</h3>
        ${avatarSrc(u) ? `
          <div style="display:flex; gap:12px; align-items:center; margin:10px 0 14px;">
            <img
              src="${esc(avatarSrc(u))}"
              alt="avatar"
              data-avatar-open="1"
              data-fp="${esc(fp)}"
              style="width:128px; height:128px; border-radius:22px; object-fit:cover; border:1px solid var(--border); background:var(--panel2); cursor:pointer;"
              title="Click to preview"
              onerror="this.style.borderColor='red'; this.title='Avatar failed to load';"
            />


            <div class="muted" style="line-height:1.25;">
              Avatar<br/>
              <span class="mono" style="font-size:12px;">${esc(avatarSrc(u))}</span>
            </div>
          </div>
        ` : `
          <div class="muted" style="margin:8px 0 14px;">
            Avatar: <span class="mono">—</span>
          </div>
        `}

        <div class="detailActions">
            <button class="btn secondary" data-edit="${esc(fp)}" type="button" ${disEditAttr}${disEditClass}>Edit</button>
        </div>

        <div class="detailKV"><div class="k">Fingerprint</div><div class="v mono">${esc(fp)}</div></div>
        <div class="detailKV"><div class="k">Name</div><div class="v">${esc(u.name || "—")}</div></div>
        <div class="detailKV"><div class="k">Role</div><div class="v">${esc(u.role || "—")}</div></div>
        <div class="detailKV"><div class="k">Status</div><div class="v">${pill(u.status)}</div></div>
        <div class="detailKV"><div class="k">Group</div><div class="v">${esc(u.group || "—")}</div></div>
        <div class="detailKV"><div class="k">Email</div><div class="v">${esc(u.email || "—")}</div></div>
        <div class="detailKV"><div class="k">Storage</div><div class="v">${storageCellHtml(u)}</div></div>
        <div class="detailKV"><div class="k">Quota</div><div class="v mono">${esc(quotaText)}</div></div>
        <div class="detailKV"><div class="k">Added</div><div class="v mono">${esc(u.added_at || "—")}</div></div>
        <div class="detailKV"><div class="k">Last seen</div><div class="v mono">${esc(u.last_seen || "—")}</div></div>
      </div>

      <div class="detailBox">
        <h3>Notes</h3>
        <pre class="detailPre">${esc(u.notes || "—")}</pre>

        <div class="quotaBox">
          <div class="quotaTop">
            <div class="quotaLabel">Storage usage</div>
            <div class="quotaNum mono">${esc(quotaUsageText(u.used_bytes ?? u.storage_used_bytes, u.quota_bytes))}</div>
          </div>
            <div class="quotaBar" title="${esc(quotaUsageText(usedBytes, quotaBytes2))}">
                <div class="quotaFill ${quotaCls}" style="width:${pct100}%"></div>
          </div>
        </div>
      </div>

<div class="detailBox">
  <h3>Actions</h3>
  <div class="detailActions">
    <button class="btn secondary"
            data-act="enable"
            data-fp="${esc(fp)}"
            type="button"
            ${disDangerAttr}${disDangerClass}>Enable</button>

    <button class="btn secondary"
            data-act="disable"
            data-fp="${esc(fp)}"
            type="button"
            ${disDangerAttr}${disDangerClass}>Disable</button>

    <button class="btn secondary"
            data-act="revoke"
            data-fp="${esc(fp)}"
            type="button"
            ${disDangerAttr}${disDangerClass}>Revoke</button>

    <button class="btn secondary"
            data-act="allocate"
            data-fp="${esc(fp)}"
            type="button">Allocate</button>
            
    ${String(u.storage_state || "").toLowerCase() === "allocated" ? `
        <button class="btn secondary"
            data-act="migrate"
            data-fp="${esc(fp)}"
            type="button">Migrate</button>

        <button class="btn secondary"
            data-act="cleanup-old-copy"
            data-fp="${esc(fp)}"
            type="button">Cleanup old copy</button>
    ` : ``}
    
    <button class="btn danger"
            data-act="delete"
            data-fp="${esc(fp)}"
            type="button"
            ${disDangerAttr}${disDangerClass}>Delete</button>
  </div>

  ${isSelf
            ? `<div class="muted" style="margin-top:10px;">
         Self-protection: enable / disable / revoke / delete are blocked for your own fingerprint.
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
    <button class="expBtn" data-exp="${esc(fp)}" type="button" aria-expanded="${isOpen ? "true" : "false"}" title="Expand/collapse">
      ${isOpen ? "▾" : "▸"}
    </button>
    <span style="margin-left:8px;" title="${esc(fp)}">${esc(shortFp(fp))}</span>
  </td>

  <td>
    <div><b>${esc(u.name || "")}</b>${selfTag}</div>
    <div class="muted" style="white-space:pre-wrap;">${esc(u.notes || "")}</div>
  </td>

  <td>${esc(u.role || "")}</td>
  <td>${pill(u.status)}</td>
  <td>${esc(u.group || "")}</td>
    <td>${storageCellHtml(u)}</td>
  <td class="mono">${fmtQuotaCell(u)}</td>
  <td class="mono">${esc(u.added_at || "")}</td>

  <td class="row-actions">
    <span class="muted">Open ▸</span>
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
                alert("Refusing to modify your own admin entry (prevents lockout or role change).");
                return;
            }

            if (act === "delete") {
                const msg =
                    "Delete this user from users.json?\n\n" +
                    "This removes the entry entirely (cleanup). " +
                    "If they scan again, they will re-appear as disabled.";
                if (!confirm(msg)) return;

                try {
                    setMsg("Deleting…");
                    await apiPost("/api/v4/admin/users/delete", { fingerprint: fp });
                    await refresh();
                    setMsg("Delete OK");
                    showToast("User deleted");
                } catch (e) {
                    alert("Failed: " + e.message);
                    setMsg("Error: " + e.message);
                }
                return;
            }

            if (act === "enable") {
                try {
                    setMsg("Enabling…");
                    await apiPost("/api/v4/admin/users/enable", { fingerprint: fp });
                    await refresh();
                    setMsg("Enabled");
                    showToast("User enabled");
                } catch (e) {
                    alert("Failed: " + e.message);
                    setMsg("Error: " + e.message);
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
                    alert("Storage must be allocated before migration.");
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
                if (!confirm("Revoke this user? This hard-blocks login for that fingerprint.")) return;
            }

            try {
                setMsg("Saving…");
                await apiPost("/api/v4/admin/users/status", { fingerprint: fp, status });
                await refresh();
                setMsg("Saved");
                showToast(`User status: ${status}`);
            } catch (e) {
                alert("Failed: " + e.message);
                setMsg("Error: " + e.message);
            }
        });
    });
}

async function refresh() {
    setMsg("Loading users…");
    const j = await apiGet("/api/v4/admin/users");
    actorFp = String(j.actor_fp || "");
    allUsers = (j.users || []).sort((a,b) => (a.fingerprint||"").localeCompare(b.fingerprint||""));
    render();
    setMsg(`Loaded ${allUsers.length} users`);
}

async function upsertFromForm() {
    const fp = ($("fp")?.value || "").trim();
    const name = ($("name")?.value || "").trim();
    const role = ($("role")?.value || "user").trim();
    const notes = ($("notes")?.value || "").trim();

    const email = ($("email")?.value || "").trim();
    const avatar_url = ($("avatar_url")?.value || "").trim(); // only if you add this input

    if (!fp || fp.length < 32) throw new Error("fingerprint looks invalid");

    await apiPost("/api/v4/admin/users/upsert", {
        fingerprint: fp,
        name,
        role,
        notes,
        email,
        avatar_url,
    });

    await refresh();
    setMsg("Upsert OK");
    showToast("User upserted");
}


window.addEventListener("load", async () => {
    $("btnRefresh")?.addEventListener("click", refresh);
    $("filter")?.addEventListener("input", render);

    $("btnAdd")?.addEventListener("click", async () => {
        setMsg("");
        try { await upsertFromForm(); }
        catch (e) { setMsg("Error: " + e.message); }
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
        if (!confirm("Remove this user's avatar?")) return;

        try {
            setMsg("Removing avatar…");
            await apiPost("/api/v4/admin/users/avatar_remove", { fingerprint: avatarModalFp });
            closeAvatarModal();
            await refresh();
            setMsg("Avatar removed");
            showToast("Avatar removed");
        } catch (e) {
            setMsg("Error: " + e.message);
            alert("Remove failed: " + e.message);
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
            showToast("Select a user first (fingerprint missing).");
            return;
        }

        try {
            setMsg("Uploading avatar…");

            const buf = await file.arrayBuffer();
            const bytes = new Uint8Array(buf);

            let bin = "";
            for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
            const data_b64 = btoa(bin);

            const body = {
                fingerprint: fp,
                filename: file.name || "avatar",
                mime: file.type || "application/octet-stream",
                data_b64,
            };

            const j = await apiPost("/api/v4/admin/users/avatar_upload", body);

            $("avatar_url").value = j.avatar_url || "";
            setMsg("Avatar uploaded (click Upsert to save)");
            showToast("Avatar uploaded");
        } catch (e) {
            setMsg("Error: " + e.message);
            alert("Upload failed: " + e.message);
        } finally {
            $("avatar_file").value = "";
        }
    });


    // ------------------------------------------------------

    try { await refresh(); }
    catch (e) { setMsg("Failed to load users: " + e.message); }
});

