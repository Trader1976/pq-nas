/* server/src/static/admin_settings.js
 *
 * PQ-NAS Admin Settings UI
 * - Loads/saves: audit_min_level, audit_retention, audit_rotation, ui_theme
 * - Uses /api/v4/admin/settings (+ audit retention/rotation endpoints)
 *
 * IMPORTANT:
 * - This file intentionally has ONE theme system:
 *   applyTheme() prefers window.pqnasSetTheme() from /static/theme.js.
 * - No duplicate const declarations (previous breakage).
 */

(function () {
    const $ = (id) => document.getElementById(id);

    // --- audit level controls ---
    const statusPill = $("statusPill");
    const persistedVal = $("persistedVal");
    const runtimeVal = $("runtimeVal");
    const levelSelect = $("levelSelect");
    const btnSave = $("btnSave");
    const btnReload = $("btnReload");

    // --- retention controls ---
    const retentionPill = $("retentionPill");
    const retMode = $("retMode");
    const retDays = $("retDays");
    const retMaxFiles = $("retMaxFiles");
    const retMaxMB = $("retMaxMB");

    const btnRetentionSave = $("btnRetentionSave");
    const btnRetentionPreview = $("btnRetentionPreview");
    const btnRetentionPrune = $("btnRetentionPrune");

    const retPreviewPill = $("retPreviewPill");
    const retSummaryPill = $("retSummaryPill");
    const retTbody = $("retTbody");

    // --- toast ---
    const toast = $("toast");
    const toastTitle = $("toastTitle");
    const toastMsg = $("toastMsg");

    // --- rotation (manual) ---
    const activeSizePill = $("activeSizePill");
    const btnRotateNow = $("btnRotateNow");

    // --- rotation policy (automatic) ---
    const rotatePolicyPill = $("rotatePolicyPill");
    const rotMode = $("rotMode");
    const rotMaxMB = $("rotMaxMB");
    const btnRotatePolicySave = $("btnRotatePolicySave");

    // --- theme ---
    const themePill = $("themePill");
    const themeSelect = $("themeSelect");
    const btnThemeSave = $("btnThemeSave");
    const btnThemeApply = $("btnThemeApply");

    // --- snapshots ---
    const snapPill = $("snapPill");
    const snapEnabled = $("snapEnabled");
    const snapPerVolume = $("snapPerVolume");
    const snapTimesPerDay = $("snapTimesPerDay");
    const snapJitter = $("snapJitter");
    const snapRoot = $("snapRoot");
    const btnSnapSave = $("btnSnapSave");
    const btnSnapReload = $("btnSnapReload");



    const ALLOWED_THEMES = new Set(["dark", "bright", "cpunk_orange", "win_classic"]);
    const ALLOWED_ROT_MODES = new Set(["manual", "daily", "size_mb", "daily_or_size_mb"]);
    let gStorageRoots = null; // populated from GET /api/v4/admin/settings
    function serverDataRootOrFallback() {
        const dr = gStorageRoots && typeof gStorageRoots.data_root === "string" ? gStorageRoots.data_root.trim() : "";
        return dr || "/srv/pqnas/data";
    }
    function escapeHtml(s) {
        return String(s ?? "")
            .replaceAll("&", "&amp;")
            .replaceAll("<", "&lt;")
            .replaceAll(">", "&gt;")
            .replaceAll('"', "&quot;")
            .replaceAll("'", "&#39;");
    }
    function setSnapshotsPill(kind, text) {
        if (!snapPill) return;
        snapPill.className = "pill " + (kind || "");
        snapPill.innerHTML = `<span class="k">Status:</span> <span class="v">${escapeHtml(text)}</span>`;
    }

    function showToast(kind, title, msg) {
        if (!toast) return;
        toast.className = "toast show " + (kind || "");
        if (toastTitle) toastTitle.textContent = title || "";
        if (toastMsg) toastMsg.textContent = msg || "";
        window.clearTimeout(showToast._t);
        showToast._t = window.setTimeout(() => {
            toast.className = "toast";
        }, 2600);
    }

    function setStatusPill(kind, text) {
        if (!statusPill) return;
        statusPill.className = "pill " + (kind || "");
        statusPill.innerHTML = `<span class="k">Status:</span> <span class="v">${escapeHtml(
            text
        )}</span>`;
    }

    function setSimplePill(el, kind, k, v) {
        if (!el) return;
        el.className = "pill " + (kind || "");
        el.innerHTML = `<span class="k">${escapeHtml(k)}:</span> <span class="v">${escapeHtml(
            v
        )}</span>`;
    }

    function fmtBytes(n) {
        if (n === null || n === undefined) return "—";
        const x = Number(n);
        if (!Number.isFinite(x)) return "—";
        if (x < 0) return "unknown";
        if (x < 1024) return `${Math.trunc(x)} B`;
        if (x < 1024 * 1024) return `${(x / 1024).toFixed(1)} KB`;
        if (x < 1024 * 1024 * 1024) return `${(x / 1024 / 1024).toFixed(1)} MB`;
        return `${(x / 1024 / 1024 / 1024).toFixed(2)} GB`;
    }

    function setOptions(allowed, selected) {
        if (!levelSelect) return;
        levelSelect.innerHTML = "";
        for (const lvl of allowed) {
            const opt = document.createElement("option");
            opt.value = lvl;
            opt.textContent = lvl;
            if (lvl === selected) opt.selected = true;
            levelSelect.appendChild(opt);
        }
    }

    // ---------------------------
    // Theme (single clean implementation)
    // ---------------------------
    function normalizeTheme(t) {
        t = String(t || "").trim();
        return ALLOWED_THEMES.has(t) ? t : "dark";
    }

    function applyTheme(theme) {
        const t = normalizeTheme(theme);

        // Preferred: centralized theme.js (shared across pages)
        try {
            if (typeof window.pqnasSetTheme === "function") {
                window.pqnasSetTheme(t);
            } else {
                document.documentElement.dataset.theme = t;
                try {
                    localStorage.setItem("pqnas_theme", t);
                } catch (_) {}
            }
        } catch (_) {}

        if (themeSelect) themeSelect.value = t;
        if (themePill) setSimplePill(themePill, "info", "Theme", t);
        return t;
    }

    // ---------------------------
    // HTTP helper (robust JSON parsing)
    // ---------------------------
    async function fetchJsonOrThrow(url, opts) {
        const r = await fetch(url, opts);

        // Always read as text first, then JSON.parse (works even if server lies about content-type)
        const text = await r.text().catch(() => "");
        let j = null;
        try {
            j = text ? JSON.parse(text) : null;
        } catch (_) {}

        if (!r.ok) {
            const msg =
                j && (j.message || j.error)
                    ? [
                        j.message || j.error,
                        j.detail ? `detail: ${j.detail}` : "",
                        j.body_snip ? `body: ${j.body_snip}` : "",
                    ]
                        .filter(Boolean)
                        .join(" • ")
                    : text && text.trim()
                        ? text.trim().slice(0, 200)
                        : `${url} failed (HTTP ${r.status})`;
            throw new Error(msg);
        }

        // Expect JSON with ok:true from these endpoints
        if (!j || j.ok !== true) {
            const msg =
                j && (j.message || j.error)
                    ? [
                        j.message || j.error,
                        j.detail ? `detail: ${j.detail}` : "",
                        j.body_snip ? `body: ${j.body_snip}` : "",
                    ]
                        .filter(Boolean)
                        .join(" • ")
                    : text && text.trim()
                        ? text.trim().slice(0, 200)
                        : `${url}: invalid JSON response`;
            throw new Error(msg);
        }

        return j;
    }

    // ---------------------------
    // Settings API
    // ---------------------------
    async function apiSettingsGet() {
        return await fetchJsonOrThrow("/api/v4/admin/settings", { cache: "no-store" });
    }

    async function apiSettingsPost(payload) {
        // Never allow an empty/undefined body: JSON.stringify(undefined) -> undefined -> fetch sends no body.
        let body = "{}";
        try {
            const s = JSON.stringify(payload ?? {});
            body = typeof s === "string" && s.length ? s : "{}";
        } catch (_) {
            body = "{}";
        }

        return await fetchJsonOrThrow("/api/v4/admin/settings", {
            method: "POST",
            cache: "no-store",
            headers: { "Content-Type": "application/json" },
            body,
        });
    }

    // ---------------------------
    // Retention API
    // ---------------------------
    async function apiPreviewPrune(policy) {
        // server expects { audit_retention: { ... } }
        return await fetchJsonOrThrow("/api/v4/admin/audit/preview-prune", {
            method: "POST",
            cache: "no-store",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ audit_retention: policy }),
        });
    }

    async function apiRotateAudit() {
        return await fetchJsonOrThrow("/api/v4/admin/rotate-audit", {
            method: "POST",
            cache: "no-store",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({}),
        });
    }

    async function apiRunPrune() {
        return await fetchJsonOrThrow("/api/v4/admin/audit/prune", {
            method: "POST",
            cache: "no-store",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({}),
        });
    }
    function serverDataRootOrFallback() {
        const dr = gStorageRoots && typeof gStorageRoots.data_root === "string" ? gStorageRoots.data_root.trim() : "";
        return dr || "/srv/pqnas/data";
    }

    function defaultSnapshots() {
        return {
            enabled: false,
            per_volume_policy: false,
            backend: "btrfs",
            volumes: [{
                name: "data",
                source_subvolume: serverDataRootOrFallback(),

                snap_root: "/srv/pqnas/.snapshots/data"
            }],
            schedule: { mode: "times_per_day", times_per_day: 6, jitter_seconds: 120 },
            retention: { keep_days: 7, keep_min: 12, keep_max: 500 }
        };
    }
    function applySnapshotsToUi(sn) {
        const s = sn && typeof sn === "object" ? sn : defaultSnapshots();
        const enabled = !!s.enabled;

        if (snapEnabled) snapEnabled.checked = enabled;
        if (snapPerVolume) snapPerVolume.checked = !!s.per_volume_policy;

        const sched = s.schedule || {};
        const tpd = Number(sched.times_per_day ?? 6);
        const jit = Number(sched.jitter_seconds ?? 120);

        if (snapTimesPerDay) snapTimesPerDay.value = String(Math.min(24, Math.max(1, tpd)));
        if (snapJitter) snapJitter.value = String(Math.min(3600, Math.max(0, jit)));

        // v1: one volume "data"
        let root = "/srv/pqnas/.snapshots/data";
        let src = serverDataRootOrFallback();

        try {
            const vols = Array.isArray(s.volumes) ? s.volumes : [];
            if (vols[0] && typeof vols[0] === "object") {
                if (typeof vols[0].snap_root === "string") root = vols[0].snap_root;
                if (typeof vols[0].source_subvolume === "string") src = vols[0].source_subvolume;
            }
        } catch (_) {}

        if (snapRoot) snapRoot.value = root;

        // Store src on the checkbox as data- so currentSnapshotsFromUi() can reuse it
        if (snapEnabled) snapEnabled.dataset.src = src;

        syncSnapshotsEnabledUi();
    }
    function currentSnapshotsFromUi() {
        const enabled = !!snapEnabled?.checked;

        const tpd = Math.min(24, Math.max(1, parseInt(snapTimesPerDay?.value || "6", 10) || 6));
        const jitter = Math.min(3600, Math.max(0, parseInt(snapJitter?.value || "120", 10) || 120));

        const root = String(snapRoot?.value || "/srv/pqnas/.snapshots/data").trim();

        // Use source_subvolume from server if we have it, otherwise sane default
        const src = String(snapEnabled?.dataset?.src || serverDataRootOrFallback());

        return {
            enabled,
            per_volume_policy: !!snapPerVolume?.checked,
            backend: "btrfs",
            volumes: [{
                name: "data",
                source_subvolume: src,
                snap_root: root
            }],
            schedule: { mode: "times_per_day", times_per_day: tpd, jitter_seconds: jitter },
            retention: { keep_days: 7, keep_min: 12, keep_max: 500 }
        };
    }

    function syncSnapshotsEnabledUi() {
        const enabled = !!snapEnabled?.checked;

        // Grey out the section visually when disabled
        const card = snapEnabled?.closest?.(".card");
        const bd = card ? card.querySelector(".bd") : null;
        if (bd) bd.classList.toggle("disabled-ui", !enabled);

        // Always allow toggling + saving + reload
        if (snapEnabled) snapEnabled.disabled = false;
        if (btnSnapSave) btnSnapSave.disabled = false;
        if (btnSnapReload) btnSnapReload.disabled = false;

        // Disable only “detail” inputs when disabled
        const detailEls = [snapTimesPerDay, snapJitter, snapRoot];
        for (const el of detailEls) {
            if (!el) continue;
            el.disabled = !enabled;
        }
        const pv = !!snapPerVolume?.checked;
        const label = enabled
            ? (pv ? "Enabled • per-volume" : "Enabled")
            : "Disabled";
        setSnapshotsPill(enabled ? "ok" : "warn", label);
        return;

        setSnapshotsPill(enabled ? "ok" : "warn", enabled ? "Enabled" : "Disabled");
    }

    snapEnabled?.addEventListener("change", () => {
        syncSnapshotsEnabledUi();
    });

    snapPerVolume?.addEventListener("change", () => {
        syncSnapshotsEnabledUi();
    });


    // ---------------------------
    // Retention UI helpers
    // ---------------------------
    function currentRetentionPolicyFromUi() {
        const mode = retMode?.value || "never";

        let days = 90;
        let max_files = 50;
        let max_total_mb = 20480;

        if (retDays && retDays.value) days = parseInt(retDays.value, 10) || days;
        if (retMaxFiles && retMaxFiles.value) max_files = parseInt(retMaxFiles.value, 10) || max_files;
        if (retMaxMB && retMaxMB.value) max_total_mb = parseInt(retMaxMB.value, 10) || max_total_mb;

        return { mode, days, max_files, max_total_mb };
    }

    function syncRetentionModeUi() {
        const mode = retMode?.value || "never";
        if (!retDays || !retMaxFiles || !retMaxMB) return;

        retDays.classList.add("hidden");
        retMaxFiles.classList.add("hidden");
        retMaxMB.classList.add("hidden");

        if (mode === "days") retDays.classList.remove("hidden");
        if (mode === "files") retMaxFiles.classList.remove("hidden");
        if (mode === "size_mb") retMaxMB.classList.remove("hidden");

        updateRetentionPill();
    }

    function applyRetentionToUi(pol) {
        const mode = pol && pol.mode ? String(pol.mode) : "never";
        if (retMode) retMode.value = mode;

        if (retDays && pol && pol.days != null) retDays.value = String(pol.days);
        if (retMaxFiles && pol && pol.max_files != null) retMaxFiles.value = String(pol.max_files);
        if (retMaxMB && pol && pol.max_total_mb != null) retMaxMB.value = String(pol.max_total_mb);

        syncRetentionModeUi();
        updateRetentionPill();
    }

    function updateRetentionPill() {
        if (!retentionPill) return;
        const p = currentRetentionPolicyFromUi();

        let label = "Never";
        if (p.mode === "days") label = `Keep ${p.days} days`;
        if (p.mode === "files") label = `Keep ${p.max_files} files`;
        if (p.mode === "size_mb") label = `Keep ≤ ${p.max_total_mb} MB`;

        setSimplePill(retentionPill, "info", "Policy", label);
    }

    function clearPreview() {
        if (retTbody) retTbody.innerHTML = "";
        setSimplePill(retPreviewPill, "warn", "Preview", "—");
        setSimplePill(retSummaryPill, "info", "Summary", "—");
    }

    function renderPreview(j) {
        // Expected:
        // { ok:true, candidates:[{name,size_bytes,mtime_iso,reason}], summary:{candidate_files,candidate_bytes,total_archives,total_bytes} }
        const cands = Array.isArray(j.candidates) ? j.candidates : [];
        const sum = j.summary || {};

        const files = Number(sum.candidate_files ?? cands.length ?? 0);
        const bytes = Number(sum.candidate_bytes ?? 0);

        setSimplePill(
            retPreviewPill,
            files > 0 ? "warn" : "ok",
            "Preview",
            files > 0 ? `${files} file(s)` : "Nothing to delete"
        );

        setSimplePill(
            retSummaryPill,
            "info",
            "Summary",
            `Would free ${fmtBytes(bytes)} • archives total ${fmtBytes(Number(sum.total_bytes || 0))}`
        );

        if (!retTbody) return;
        retTbody.innerHTML = "";

        for (const it of cands) {
            const tr = document.createElement("tr");
            const name = String(it.name || "—");
            const size = fmtBytes(it.size_bytes);
            const mtime = String(it.mtime_iso || "—");
            const reason = String(it.reason || "—");

            tr.innerHTML = `
        <td class="col-name mono" title="${escapeHtml(name)}">${escapeHtml(name)}</td>
        <td class="col-size mono" title="${escapeHtml(size)}">${escapeHtml(size)}</td>
        <td class="col-age mono" title="${escapeHtml(mtime)}">${escapeHtml(mtime)}</td>
        <td class="col-reason" title="${escapeHtml(reason)}">${escapeHtml(reason)}</td>
      `;
            retTbody.appendChild(tr);
        }
    }

    // ---------------------------
    // Rotation UI helpers (AUTOMATIC policy)
    // Server modes: manual | daily | size_mb | daily_or_size_mb
    // ---------------------------
    function normalizeRotateMode(m) {
        m = String(m || "").trim();
        return ALLOWED_ROT_MODES.has(m) ? m : "manual";
    }

    function currentRotatePolicyFromUi() {
        const mode = normalizeRotateMode(rotMode?.value || "manual");
        let max_active_mb = 256; // UI default
        if (rotMaxMB && rotMaxMB.value) {
            max_active_mb = parseInt(rotMaxMB.value, 10) || max_active_mb;
        }
        return { mode, max_active_mb };
    }

    function syncRotateModeUi() {
        const mode = normalizeRotateMode(rotMode?.value || "manual");
        if (!rotMaxMB) return;

        // show max MB only for size-based modes
        rotMaxMB.classList.add("hidden");
        if (mode === "size_mb" || mode === "daily_or_size_mb") {
            rotMaxMB.classList.remove("hidden");
        }

        updateRotatePolicyPill();
    }

    function applyRotatePolicyToUi(pol) {
        const mode = normalizeRotateMode(pol && pol.mode ? String(pol.mode) : "manual");
        if (rotMode) rotMode.value = mode;

        if (rotMaxMB && pol && pol.max_active_mb != null) {
            rotMaxMB.value = String(pol.max_active_mb);
        }

        syncRotateModeUi();
        updateRotatePolicyPill();
    }

    function updateRotatePolicyPill() {
        if (!rotatePolicyPill) return;

        const p = currentRotatePolicyFromUi();
        let label = "Manual only";
        if (p.mode === "daily") label = "Daily (UTC)";
        if (p.mode === "size_mb") label = `When > ${p.max_active_mb} MB`;
        if (p.mode === "daily_or_size_mb") label = `> ${p.max_active_mb} MB OR daily (UTC)`;

        setSimplePill(rotatePolicyPill, "info", "Policy", label);
    }

    // ---------------------------
    // Active file info pill
    // ---------------------------
    function updateActiveSizePill(j) {
        if (!activeSizePill) return;
        const bytes = j && typeof j.audit_active_bytes === "number" ? j.audit_active_bytes : null;
        const path = j && j.audit_active_path ? String(j.audit_active_path) : "";

        const label = bytes == null || bytes < 0 ? "—" : `${fmtBytes(bytes)}${path ? " • " + path : ""}`;
        setSimplePill(activeSizePill, "info", "Active log", label);
    }

    // ---------------------------
    // Main refresh: load all settings
    // ---------------------------
    async function refreshAll() {
        setStatusPill("warn", "loading…");
        try {
            const j = await apiSettingsGet();

            gStorageRoots = (j && typeof j.storage_roots === "object" && j.storage_roots) ? j.storage_roots : null;

            const allowed = Array.isArray(j.allowed) ? j.allowed : ["SECURITY", "ADMIN", "INFO", "DEBUG"];
            const persisted = j.audit_min_level || "ADMIN";
            const runtime = j.audit_min_level_runtime || persisted;

            if (persistedVal) persistedVal.textContent = persisted;
            if (runtimeVal) runtimeVal.textContent = runtime;

            setOptions(allowed, persisted);

            // retention
            const ret = j.audit_retention || { mode: "never", days: 90, max_files: 50, max_total_mb: 20480 };
            applyRetentionToUi(ret);

            // rotation policy (automatic)
            const rp = j.audit_rotation || { mode: "manual", max_active_mb: 256, rotate_utc_day: "" };
            applyRotatePolicyToUi(rp);

            // theme (server -> apply)
            const serverTheme = j && j.ui_theme ? String(j.ui_theme) : "dark";
            applyTheme(serverTheme);
            // snapshots
            applySnapshotsToUi(j.snapshots || defaultSnapshots());

            // active audit file info
            updateActiveSizePill(j);

            clearPreview();
            setStatusPill("ok", "ready");
        } catch (e) {
            console.error(e);
            setStatusPill("error", "error");
            setSimplePill(activeSizePill, "warn", "Active log", "—");
            showToast("fail", "Failed to load settings", String(e.message || e));
        }
    }

    // ---------------------------
    // Wire audit level
    // ---------------------------
    if (btnReload) {
        btnReload.addEventListener("click", (ev) => {
            ev.preventDefault();
            refreshAll();
        });
    }

    if (btnSave) {
        btnSave.addEventListener("click", async (ev) => {
            ev.preventDefault();
            const lvl = levelSelect ? levelSelect.value : "";
            btnSave.disabled = true;
            setStatusPill("warn", "saving…");
            try {
                await apiSettingsPost({ audit_min_level: lvl });
                showToast("ok", "Saved", `audit_min_level = ${lvl}`);
                await refreshAll();
            } catch (e) {
                console.error(e);
                showToast("fail", "Save failed", String(e.message || e));
                setStatusPill("error", "error");
            } finally {
                btnSave.disabled = false;
            }
        });
    }

    // ---------------------------
    // Wire retention
    // ---------------------------
    retMode?.addEventListener("change", () => {
        syncRetentionModeUi();
        clearPreview();
    });

    retDays?.addEventListener("change", () => {
        updateRetentionPill();
        clearPreview();
    });
    retMaxFiles?.addEventListener("input", () => {
        updateRetentionPill();
        clearPreview();
    });
    retMaxMB?.addEventListener("input", () => {
        updateRetentionPill();
        clearPreview();
    });

    btnRetentionSave?.addEventListener("click", async (ev) => {
        ev.preventDefault();
        const pol = currentRetentionPolicyFromUi();

        btnRetentionSave.disabled = true;
        setStatusPill("warn", "saving…");
        try {
            await apiSettingsPost({ audit_retention: pol });
            showToast("ok", "Saved", "Retention policy updated");
            await refreshAll();
        } catch (e) {
            console.error(e);
            showToast("fail", "Save failed", String(e.message || e));
            setStatusPill("error", "error");
        } finally {
            btnRetentionSave.disabled = false;
        }
    });

    btnRetentionPreview?.addEventListener("click", async (ev) => {
        ev.preventDefault();
        const pol = currentRetentionPolicyFromUi();

        btnRetentionPreview.disabled = true;
        setSimplePill(retPreviewPill, "warn", "Preview", "checking…");

        try {
            const j = await apiPreviewPrune(pol);
            renderPreview(j);
            showToast("ok", "Preview ready", `${(j.summary && j.summary.candidate_files) || 0} candidate file(s)`);
        } catch (e) {
            console.error(e);
            setSimplePill(retPreviewPill, "fail", "Preview", "error");
            showToast("fail", "Preview failed", String(e.message || e));
        } finally {
            btnRetentionPreview.disabled = false;
        }
    });

    btnRetentionPrune?.addEventListener("click", async (ev) => {
        ev.preventDefault();

        if (
            !confirm(
                "Run prune now?\n\nThis deletes rotated audit archives according to the saved retention policy.\nActive pqnas_audit.jsonl is never deleted."
            )
        ) {
            return;
        }

        btnRetentionPrune.disabled = true;
        setSimplePill(retPreviewPill, "warn", "Preview", "pruning…");

        try {
            const j = await apiRunPrune();
            showToast(
                "ok",
                "Prune complete",
                `Deleted ${(j.deleted_files || 0)} file(s) • freed ${fmtBytes(j.deleted_bytes || 0)}`
            );
            const pol = currentRetentionPolicyFromUi();
            const pv = await apiPreviewPrune(pol);
            renderPreview(pv);
        } catch (e) {
            console.error(e);
            setSimplePill(retPreviewPill, "fail", "Preview", "error");
            showToast("fail", "Prune failed", String(e.message || e));
        } finally {
            btnRetentionPrune.disabled = false;
        }
    });
    // ---------------------------
    // Wire snapshot buttons
    // ---------------------------
    btnSnapReload?.addEventListener("click", (ev) => {
        ev.preventDefault();
        refreshAll();
    });

    btnSnapSave?.addEventListener("click", async (ev) => {
        ev.preventDefault();
        const sn = currentSnapshotsFromUi();
        btnSnapSave.disabled = true;
        setSnapshotsPill("warn", "Saving…");
        try {
            const j = await apiSettingsPost({ snapshots: sn });
            applySnapshotsToUi(j.snapshots || sn);
            showToast("ok", "Saved", "Snapshots settings updated");
        } catch (e) {
            console.error(e);
            setSnapshotsPill("fail", "Error");
            showToast("fail", "Save failed", String(e.message || e));
        } finally {
            btnSnapSave.disabled = false;
        }
    });

    // ---------------------------
    // Wire manual rotation
    // ---------------------------
    btnRotateNow?.addEventListener("click", async (ev) => {
        ev.preventDefault();

        if (
            !confirm(
                "Rotate audit log now?\n\nThis renames the active pqnas_audit.jsonl into a timestamped archive and starts a fresh active log.\nHash chain continuity is preserved via the rotate header."
            )
        ) {
            return;
        }

        btnRotateNow.disabled = true;
        setStatusPill("warn", "rotating…");

        try {
            await apiRotateAudit();
            showToast("ok", "Rotated", "New active audit log started");
            await refreshAll();
        } catch (e) {
            console.error(e);
            showToast("fail", "Rotate failed", String(e.message || e));
            setStatusPill("error", "error");
        } finally {
            btnRotateNow.disabled = false;
        }
    });

    // ---------------------------
    // Wire theme
    // ---------------------------
    themeSelect?.addEventListener("change", () => {
        // Update pill and preview instantly
        applyTheme(themeSelect.value);
    });

    btnThemeApply?.addEventListener("click", (ev) => {
        ev.preventDefault();
        const t = normalizeTheme(themeSelect?.value || "dark");
        applyTheme(t);
        showToast("ok", "Theme applied", `Theme: ${t}`);
    });

    btnThemeSave?.addEventListener("click", async (ev) => {
        ev.preventDefault();
        const t = normalizeTheme(themeSelect?.value || "dark");
        try {
            const j = await apiSettingsPost({ ui_theme: t });
            applyTheme(j && j.ui_theme ? j.ui_theme : t);
            showToast("ok", "Theme saved", `Theme: ${t}`);
        } catch (e) {
            showToast("fail", "Save failed", String(e && e.message ? e.message : e));
        }
    });

    // ---------------------------
    // Wire rotation policy (automatic)
    // ---------------------------
    rotMode?.addEventListener("change", () => {
        syncRotateModeUi();
    });

    rotMaxMB?.addEventListener("input", () => {
        updateRotatePolicyPill();
    });

    btnRotatePolicySave?.addEventListener("click", async (ev) => {
        ev.preventDefault();

        const pol = currentRotatePolicyFromUi();
        btnRotatePolicySave.disabled = true;
        setStatusPill("warn", "saving…");

        try {
            await apiSettingsPost({ audit_rotation: pol });
            showToast("ok", "Saved", "Rotation policy updated");
            await refreshAll();
        } catch (e) {
            console.error(e);
            showToast("fail", "Save failed", String(e.message || e));
            setStatusPill("error", "error");
        } finally {
            btnRotatePolicySave.disabled = false;
        }
    });

    // init
    syncRotateModeUi();
    syncRetentionModeUi();
    refreshAll();
})();
