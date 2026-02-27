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
    const snapTimesPerDay = $("snapTimesPerDay");
    const snapJitter = $("snapJitter");
    const snapRoot = $("snapRoot");
    const btnSnapSave = $("btnSnapSave");
    const btnSnapReload = $("btnSnapReload");
    const snapPerVolume = $("snapPerVolume");
    const snapVolTbody = $("snapVolTbody");

    // --- uploads ---
    const uploadPill = $("uploadPill");
    const uploadSoftMax = $("uploadSoftMax");
    const btnUploadSave = $("btnUploadSave");
    const btnUploadReload = $("btnUploadReload");
    const uploadSoftPill = $("uploadSoftPill");
    const uploadHardPill = $("uploadHardPill");
    const uploadEffectivePill = $("uploadEffectivePill");

    const ALLOWED_THEMES = new Set(["dark", "bright", "cpunk_orange", "win_classic"]);
    const ALLOWED_ROT_MODES = new Set(["manual", "daily", "size_mb", "daily_or_size_mb"]);
    let gStorageRoots = null; // populated from GET /api/v4/admin/settings
    let gSnapshotsLast = null; // last snapshots object received from server (prevents wiping volumes)

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
    function tpdOptionsHtml(selected) {
        const vals = [1,2,4,6,12,24];
        return vals.map(v => `<option value="${v}" ${String(v)===String(selected)?"selected":""}>${v}</option>`).join("");
    }

    function renderSnapshotVolumesTable(sn) {
        if (!snapVolTbody) return;
        snapVolTbody.innerHTML = "";

        const vols = Array.isArray(sn?.volumes) ? sn.volumes : [];
        const globalSched = sn?.schedule && typeof sn.schedule === "object" ? sn.schedule : {};
        const globalTpd = Number(globalSched.times_per_day ?? 6);
        const globalJit = Number(globalSched.jitter_seconds ?? 120);

        const perVol = !!(snapPerVolume && snapPerVolume.checked);

        for (let i = 0; i < vols.length; i++) {
            const v = vols[i] && typeof vols[i] === "object" ? vols[i] : {};
            const name = String(v.name || `vol${i}`);
            const src  = String(v.source_subvolume || "");

            const vs = (v.schedule && typeof v.schedule === "object") ? v.schedule : {};
            const tpd = perVol ? Number(vs.times_per_day ?? globalTpd) : globalTpd;
            const jit = perVol ? Number(vs.jitter_seconds ?? globalJit) : globalJit;

            const tr = document.createElement("tr");
            tr.innerHTML = `
          <td class="mono" title="${escapeHtml(name)}">${escapeHtml(name)}</td>
          <td class="mono" title="${escapeHtml(src)}">${escapeHtml(src)}</td>
          <td>
            <select class="snapVolTpd" data-i="${i}" ${perVol ? "" : "disabled"}>
              ${tpdOptionsHtml(Math.min(24, Math.max(1, tpd || 6)))}
            </select>
          </td>
          <td>
            <input class="input mono snapVolJit"
                   style="min-width:120px"
                   type="number" min="0" max="3600"
                   data-i="${i}"
                   value="${String(Math.min(3600, Math.max(0, jit || 120)))}"
                   ${perVol ? "" : "disabled"} />
          </td>
        `;
            snapVolTbody.appendChild(tr);
        }
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

    function defaultSnapshots() {
        return {
            enabled: false,
            backend: "btrfs",
            per_volume_policy: false,
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
        gSnapshotsLast = s;
        const enabled = !!s.enabled;

        if (snapEnabled) snapEnabled.checked = enabled;
        const vols = Array.isArray(s.volumes) ? s.volumes : [];
        const inferredPerVol = (typeof s.per_volume_policy === "boolean")
            ? s.per_volume_policy
            : vols.some(v => v && typeof v === "object" && v.schedule && typeof v.schedule === "object");

        if (snapPerVolume) snapPerVolume.checked = !!inferredPerVol;


        const sched = s.schedule || {};
        const tpd = Number(sched.times_per_day ?? 6);
        const jit = Number(sched.jitter_seconds ?? 120);

        if (snapTimesPerDay) snapTimesPerDay.value = String(Math.min(24, Math.max(1, tpd)));
        if (snapJitter) snapJitter.value = String(Math.min(3600, Math.max(0, jit)));

        // v1: one volume "data"
        let root = "/srv/pqnas/.snapshots/data";
        let src  = serverDataRootOrFallback();

        try {
            if (vols[0] && typeof vols[0] === "object") {
                if (typeof vols[0].snap_root === "string") root = vols[0].snap_root;
                if (typeof vols[0].source_subvolume === "string") src = vols[0].source_subvolume;
            }
        } catch (_) {}


        if (snapRoot) snapRoot.value = root;

        // Store src on the checkbox as data- so currentSnapshotsFromUi() can reuse it
        if (snapEnabled) snapEnabled.dataset.src = src;

        renderSnapshotVolumesTable(s);
        syncSnapshotsEnabledUi();
    }

    function currentSnapshotsFromUi() {
        const enabled = !!snapEnabled?.checked;

        const global_tpd = Math.min(24, Math.max(1, parseInt(snapTimesPerDay?.value || "6", 10) || 6));
        const global_jitter = Math.min(3600, Math.max(0, parseInt(snapJitter?.value || "120", 10) || 120));

        const root0 = String(snapRoot?.value || "/srv/pqnas/.snapshots/data").trim();
        const src0 = String(snapEnabled?.dataset?.src || serverDataRootOrFallback());

        const perVol = !!snapPerVolume?.checked;

        // Start from last server snapshots if available so we don't wipe multi-volume configs
        const base = (gSnapshotsLast && typeof gSnapshotsLast === "object") ? gSnapshotsLast : defaultSnapshots();
        const baseVols = Array.isArray(base.volumes) ? base.volumes : [];

        // Clone volumes so we can edit safely
        const volumes = baseVols.map(v => (v && typeof v === "object") ? { ...v } : {}).filter(v => !!v);

        // If server had no volumes, keep at least one
        if (volumes.length === 0) {
            volumes.push({ name: "data", source_subvolume: src0, snap_root: root0 });
        }

        // Always keep volume[0] wired to the simple UI root + src (for now)
        volumes[0].name = String(volumes[0].name || "data");
        volumes[0].source_subvolume = String(volumes[0].source_subvolume || src0);
        volumes[0].snap_root = root0;

        // Global schedule is always present (A mode)
        const out = {
            enabled,
            backend: "btrfs",
            per_volume_policy: perVol,
            volumes,
            schedule: { mode: "times_per_day", times_per_day: global_tpd, jitter_seconds: global_jitter },
            retention: base.retention && typeof base.retention === "object"
                ? base.retention
                : { keep_days: 7, keep_min: 12, keep_max: 500 }
        };

        // If per-volume enabled, apply table values to each volume schedule
        if (perVol && snapVolTbody) {
            for (let i = 0; i < volumes.length; i++) {
                const tpdSel = snapVolTbody.querySelector(`.snapVolTpd[data-i="${i}"]`);
                const jitInp = snapVolTbody.querySelector(`.snapVolJit[data-i="${i}"]`);

                const vtpd = Math.min(24, Math.max(1, parseInt(tpdSel?.value || String(global_tpd), 10) || global_tpd));
                const vjit = Math.min(3600, Math.max(0, parseInt(jitInp?.value || String(global_jitter), 10) || global_jitter));

                volumes[i].schedule = { mode: "times_per_day", times_per_day: vtpd, jitter_seconds: vjit };
            }
        } else {
            // If per-volume disabled, remove per-volume schedules to keep config clean
            for (const v of volumes) {
                if (v && typeof v === "object") delete v.schedule;
            }
        }

        return out;
    }


    function syncSnapshotsEnabledUi() {
        const enabled = !!snapEnabled?.checked;
        const perVol = !!snapPerVolume?.checked;

        // Grey out the section visually when disabled
        const card = snapEnabled?.closest?.(".card");
        const bd = card ? card.querySelector(".bd") : null;
        if (bd) bd.classList.toggle("disabled-ui", !enabled);

        // Always allow toggling + saving + reload
        if (snapEnabled) snapEnabled.disabled = false;
        if (btnSnapSave) btnSnapSave.disabled = false;
        if (btnSnapReload) btnSnapReload.disabled = false;

        // Disable only “detail” inputs when disabled
        const detailEls = [snapTimesPerDay, snapJitter, snapRoot, snapPerVolume];
        for (const el of detailEls) {
            if (!el) continue;
            el.disabled = !enabled;
        }

        // Enable/disable the per-volume table inputs based on enabled + perVol
        if (snapVolTbody) {
            const rowControls = snapVolTbody.querySelectorAll(".snapVolTpd, .snapVolJit");
            for (const el of rowControls) {
                el.disabled = !(enabled && perVol);
            }
        }

        const label = enabled ? (perVol ? "Enabled • per-volume" : "Enabled") : "Disabled";
        setSnapshotsPill(enabled ? "ok" : "warn", label);

        // Re-render table using latest loaded config (or current UI)
        renderSnapshotVolumesTable(gSnapshotsLast || currentSnapshotsFromUi());
    }


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
    // Upload limits UI helpers
    // ---------------------------
    function clampU64(n) {
        const x = Number(n);
        if (!Number.isFinite(x)) return null;
        if (x <= 0) return null;
        // JS can represent up to 2^53-1 safely; your caps are well below that
        return Math.floor(x);
    }

    function applyUploadLimitsToUi(j) {
        const hard = (j && typeof j.payload_max_upload_bytes === "number") ? j.payload_max_upload_bytes : null;
        const soft = (j && typeof j.transport_max_upload_bytes === "number") ? j.transport_max_upload_bytes : null;

        const eff = (hard != null && soft != null) ? Math.min(hard, soft)
            : (hard != null) ? hard
                : (soft != null) ? soft
                    : null;

        if (uploadSoftMax && soft != null) uploadSoftMax.value = String(Math.floor(soft));

        // Pills
        if (uploadSoftPill) setSimplePill(uploadSoftPill, "info", "Soft cap", soft != null ? fmtBytes(soft) : "—");
        if (uploadHardPill) setSimplePill(uploadHardPill, "info", "Hard cap", hard != null ? fmtBytes(hard) : "—");
        if (uploadEffectivePill) setSimplePill(uploadEffectivePill, "info", "Effective", eff != null ? fmtBytes(eff) : "—");

        // Header pill shows effective
        if (uploadPill) {
            const kind = (eff != null) ? "info" : "warn";
            uploadPill.className = "pill " + kind;
            uploadPill.innerHTML = `<span class="k">Effective:</span> <span class="v">${escapeHtml(eff != null ? fmtBytes(eff) : "—")}</span>`;
        }
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
            // active audit file info
            updateActiveSizePill(j);

            // upload limits
            applyUploadLimitsToUi(j);
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

    snapPerVolume?.addEventListener("change", () => {
        renderSnapshotVolumesTable(gSnapshotsLast || currentSnapshotsFromUi());
        syncSnapshotsEnabledUi();
    });
    // ---------------------------
    // Wire upload limits
    // ---------------------------
    btnUploadReload?.addEventListener("click", (ev) => {
        ev.preventDefault();
        refreshAll();
    });

    btnUploadSave?.addEventListener("click", async (ev) => {
        ev.preventDefault();

        const v = clampU64(uploadSoftMax?.value);
        if (v == null) {
            showToast("fail", "Invalid value", "transport_max_upload_bytes must be a positive integer (bytes).");
            return;
        }

        btnUploadSave.disabled = true;
        setStatusPill("warn", "saving…");
        try {
            await apiSettingsPost({ transport_max_upload_bytes: v });
            showToast("ok", "Saved", `Max upload = ${fmtBytes(v)} (${v} bytes)`);
            await refreshAll();
        } catch (e) {
            console.error(e);
            showToast("fail", "Save failed", String(e.message || e));
            setStatusPill("error", "error");
        } finally {
            btnUploadSave.disabled = false;
        }
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

            // Merge: server may omit per_volume_policy and/or schedules; don’t let that reset UI.
            const merged = (j && j.snapshots && typeof j.snapshots === "object")
                ? {
                    ...sn,
                    ...j.snapshots,
                    per_volume_policy: (typeof j.snapshots.per_volume_policy === "boolean")
                        ? j.snapshots.per_volume_policy
                        : sn.per_volume_policy,
                    volumes: Array.isArray(j.snapshots.volumes) ? j.snapshots.volumes : sn.volumes
                }
                : sn;

            applySnapshotsToUi(merged);
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
