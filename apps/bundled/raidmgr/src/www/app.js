(() => {
    "use strict";

    // Embedded mode (same pattern as filemgr)
    try {
        if (window.self !== window.top) document.body.classList.add("embedded");
    } catch (_) {
        document.body.classList.add("embedded");
    }

    const el = (id) => document.getElementById(id);

    const badge = el("badge");
    const subLine = el("subLine");
    const titleLine = el("titleLine");
    const refreshBtn = el("refreshBtn");
    const rawOut = el("rawOut");
    const actionsOut = el("actionsOut");
    const userStatusEl = el("userStatus");
    const devModeChk = el("devModeChk");
    const probeCard = el("probeCard");
    const topologyCard = el("topologyCard");
    const rawCard = el("rawCard");
    const poolSelTop = el("poolSelTop");

    const poolsTab = el("poolsTab");
    const poolsOut = el("poolsOut");
    const raidTab = el("raidTab");

    const tabRaidBtn  = el("tabRaidBtn");
    const tabPoolsBtn = el("tabPoolsBtn");
    const TAB_KEY = "pqnas_storagemgr_tab";
    let g_tab = "pools"; // "drives" | "pools"  (we keep variable name g_tab but change values below)

    function loadTab() {
        try {
            const v = String(window.localStorage.getItem(TAB_KEY) || "pools");
            const ok = (v === "drives" || v === "pools") ? v : "pools";

            // Defensive fix: if RAID tab no longer exists, never allow "drives".
            const hasRaidTab = !!document.getElementById("raidTab");
            if (!hasRaidTab && ok === "drives") {
                window.localStorage.setItem(TAB_KEY, "pools");
                return "pools";
            }

            return ok;
        } catch (_) {
            return "pools";
        }
    }

    function saveTab(v) {
        try {
            window.localStorage.setItem(TAB_KEY, String(v || "pools"));
        } catch (_) {}
    }

    function applyTabToUi() {
        if (poolsTab) poolsTab.style.display = "";
        if (raidTab)  raidTab.style.display = "none";
        if (tabRaidBtn)  tabRaidBtn.style.display = "none";
        if (tabPoolsBtn) tabPoolsBtn.style.display = "none";
    }
    const DEV_MODE_KEY = "pqnas_storagemgr_dev_mode";

    function setBadge(kind, text) {
        if (!badge) return;
        badge.className = `badge ${kind || ""}`.trim();
        badge.textContent = text || "";
    }

    // Multi-pool selection
    const POOL_SEL_KEY = "pqnas_storagemgr_pool_mount";
    let g_pools = [];
    let g_selectedMount = "";

    // Persist last outputs across probe() refresh (probe rebuilds DOM)
    let g_lastAction = null;
    let g_lastProgress = null;

    let g_tieringPrev = null;
    let g_tieringTimer = null;
    let g_tieringLastRate = 0;


    // ----------------------------------------------------------------------------
    // Global timer/poller state (so probe() can stop old intervals created by
    // previous renderActions() closures)
    // ----------------------------------------------------------------------------
    const GSTATE_KEY = "__pqnas_storagemgr_state_v1__";
    function gstate() {
        if (!window[GSTATE_KEY]) {
            window[GSTATE_KEY] = {
                pollTimer: null,
                execTimer: null,
                execPlanId: "",
                execLastState: "",
                execLastStep: -1,
            };
        }
        return window[GSTATE_KEY];
    }

    function stopMountPolling() {
        const st = gstate();
        if (st.pollTimer) {
            clearInterval(st.pollTimer);
            st.pollTimer = null;
        }
    }

    function stopAllPolling() {
        stopMountPolling();
        stopExecPolling(); // keep this as the “full reset”
    }
// ---------------------------------------------------------------------------
// Exec-record polling (GLOBAL, plan_id-based)
// Allows Pools tab and RAID tab to reuse exec polling.
// UI updates are "best effort" (only if the elements exist on the page).
// ---------------------------------------------------------------------------

    function fmtExecState(s) {
        s = String(s || "");
        return s || "(unknown)";
    }

    function setExecUiGlobal(state, stepIndex, stepTotal, planId) {
        // Best-effort: these exist in RAID tab action UI. In Pools tab they may not exist.
        const execPill = document.getElementById("execPill");
        const execMeta = document.getElementById("execMeta");
        const execPbarFill = document.getElementById("execPbarFill");

        const st = String(state || "idle");
        const si = Number.isFinite(stepIndex) ? stepIndex : -1;
        const tot = Number.isFinite(stepTotal) ? stepTotal : -1;

        if (execPill) {
            let cls = "pill warn";
            if (st === "done") cls = "pill ok";
            else if (st === "failed") cls = "pill err";
            else if (st === "error") cls = "pill err";
            execPill.className = cls;
            execPill.textContent = st;
        }

        if (execMeta) {
            if (planId) {
                if (si >= 0 && tot > 0) execMeta.textContent = `plan_id=${planId.slice(0, 12)}…  ${si}/${tot}`;
                else execMeta.textContent = `plan_id=${planId.slice(0, 12)}…`;
            } else {
                execMeta.textContent = "(no job)";
            }
        }

        if (execPbarFill) {
            let pct = 0;
            if (si >= 0 && tot > 0) pct = Math.max(0, Math.min(100, Math.round((si / tot) * 100)));
            execPbarFill.style.width = `${pct}%`;
        }
    }

    function setProgressTextGlobal(lines) {
        const progressOut = document.getElementById("progressOut");
        const txt = Array.isArray(lines) ? lines.join("\n") : String(lines || "");

        // ✅ persist for rebuilds
        g_lastProgress = txt;

        if (progressOut) progressOut.textContent = txt;

        try { window.__pqnas_last_progress_text = txt; } catch (_) {}
    }

    function stopExecPolling() {
        const st = gstate();
        if (st.execTimer) {
            clearInterval(st.execTimer);
            st.execTimer = null;
        }
        st.execPlanId = "";
        st.execLastState = "";
        st.execLastStep = -1;

        setExecUiGlobal("idle", -1, -1, "");
    }
    async function addPoolSlot(mount) {
        return await postJson("/api/v4/poolmgr/add-slot", { mount });
    }

    async function removePoolSlot(mount) {
        return await postJson("/api/v4/poolmgr/remove-slot", { mount });
    }

    async function setPoolLayout(body) {
        return await postJson("/api/v4/poolmgr/set-layout", body);
    }
    async function planPoolLayout(mount) {
        return await postJson("/api/v4/poolmgr/plan-layout", { mount });
    }
    async function pollExecOnce() {
        const st = gstate();
        if (!st.execPlanId) return;

        let rec = null;
        let http = 0;
        let errTxt = "";

        try {
            const q = await fetchJson(`/api/v4/raid/exec-record?plan_id=${encodeURIComponent(st.execPlanId)}`);
            http = q.r ? q.r.status : 0;
            rec = q.j;
            if (!rec || rec.ok !== true) errTxt = prettyError(q.j, q.r, q.txt);
        } catch (e) {
            errTxt = String(e && e.message ? e.message : e);
        }

        const lines = [];
        lines.push(`Exec record: plan_id=${st.execPlanId}`);
        if (http) lines.push(`HTTP: ${http}`);

        if (!rec || rec.ok !== true) {
            lines.push(`State: error`);
            if (errTxt) lines.push(`Error: ${errTxt}`);
            setExecUiGlobal("error", -1, -1, st.execPlanId);
            setProgressTextGlobal(lines);
            return;
        }

        const state = fmtExecState(rec.state);
        const busy = !!rec.busy;
        const si = Number.isFinite(rec.step_index) ? rec.step_index : -1;
        const tot = Number.isFinite(rec.step_total) ? rec.step_total : -1;

        setExecUiGlobal(state, si, tot, st.execPlanId);

        lines.push(`State: ${state} (busy=${busy})`);
        if (si >= 0 && tot > 0) {
            const pct = Math.max(0, Math.min(100, Math.round((si / tot) * 100)));
            lines.push(`Progress: ${si}/${tot} (${pct}%)`);
        } else {
            lines.push(`Progress: (unknown)`);
        }

        if (rec.ts_start) lines.push(`Started: ${rec.ts_start}`);
        if (rec.ts_last) lines.push(`Last:    ${rec.ts_last}`);
        if (rec.ts_end)  lines.push(`Ended:   ${rec.ts_end}`);

        if (rec.message) lines.push(`Message: ${String(rec.message)}`);
        if (rec.error)   lines.push(`Error: ${String(rec.error)}`);

        try {
            const stepsArr = Array.isArray(rec.steps) ? rec.steps : (Array.isArray(rec.results) ? rec.results : []);
            if (stepsArr.length) {
                const last = stepsArr[stepsArr.length - 1];
                if (last && typeof last === "object") {
                    if (last.cmd) lines.push(`Last cmd: ${String(last.cmd)}`);
                    if (last.ok != null) lines.push(`Last ok: ${String(last.ok)}`);
                    if (last.rc != null) lines.push(`Last rc: ${String(last.rc)}`);
                    if (last.out) {
                        lines.push("Last out:");
                        lines.push(String(last.out).slice(0, 4000));
                    }
                }
            }
        } catch (_) {}

        setProgressTextGlobal(lines);

        const done = state === "done" || state === "failed";
        if (done) {
            stopExecPolling();
            if (done) {
                stopExecPolling();

                // Refresh pools list (best effort)
                try {
                    setTimeout(async () => {
                        await refreshPoolsState();
                        renderPoolSelectorTop();
                        if (g_tab === "pools") await renderPoolsTab();
                        probe();
                    }, 350);
                } catch (_) {}

                return;
            }// stop first (avoids progress UI lockout)
            try { setTimeout(() => probe(), 350); } catch (_) {}
            return;
        }

        st.execLastState = state;
        st.execLastStep = si;
    }

    function startExecPolling(plan_id) {
        const pid = String(plan_id || "").trim();
        if (!/^[0-9a-f]{64}$/.test(pid)) {
            setProgressTextGlobal([`Exec record: invalid plan_id: ${pid}`]);
            return;
        }

        const st = gstate();
        st.execPlanId = pid;
        st.execLastState = "";
        st.execLastStep = -1;

        if (st.execTimer) {
            clearInterval(st.execTimer);
            st.execTimer = null;
        }

        pollExecOnce();
        st.execTimer = setInterval(pollExecOnce, 700);
    }
    function isDevMode() {
        try {
            return window.localStorage.getItem(DEV_MODE_KEY) === "1";
        } catch (_) {
            return false;
        }
    }
    async function apiGetJson(url) {
        const r = await fetch(url, { credentials: "same-origin" });
        const t = await r.text();
        let j;
        try { j = JSON.parse(t); } catch { throw new Error(`Bad JSON from ${url}: ${t.slice(0,200)}`); }
        if (!r.ok || j.ok === false) throw new Error(j.error || `HTTP ${r.status}`);
        return j;
    }

    async function loadAllDisks() {
        return await apiGetJson("/api/v4/storage/disks");
    }

    async function loadDiscovery(mount) {
        const qs = new URLSearchParams({ mount });
        return await apiGetJson(`/api/v4/raid/discovery?${qs.toString()}`);
    }


    function isEligibleDisk(d) {
        const path = String(d?.path || "");
        const name = String(d?.name || "");

        if (!path.startsWith("/dev/")) return false;

        // Exclude mounted disks
        const mps = Array.isArray(d?.mountpoints) ? d.mountpoints.filter(Boolean) : [];
        if (mps.length) return false;

        // Exclude devices that already have partitions/children.
        // This blocks parent disks like /dev/nvme1n1 where /dev/nvme1n1p1 is in use.
        const children = Number(d?.children || 0);
        if (children > 0) return false;

        const fstype = String(d?.fstype || "").toLowerCase();
        if (fstype === "squashfs") return false;

        const isLoop = name.startsWith("loop") || path.startsWith("/dev/loop");
        if (isLoop && !isDevMode()) return false;

        return true;
    }
    function fillSelect(selectEl, disks, { allowMultiple=false, filterFn=isEligibleDisk, preselect=[] } = {}) {
        selectEl.innerHTML = "";
        selectEl.multiple = !!allowMultiple;

        const eligible = disks.filter(filterFn);

        for (const d of eligible) {
            const opt = document.createElement("option");
            opt.value = d.path || d.dev;
            opt.textContent = diskLabel(d);
            if (preselect.includes(opt.value)) opt.selected = true;
            selectEl.appendChild(opt);
        }

        // If nothing eligible, show a disabled placeholder
        if (!eligible.length) {
            const opt = document.createElement("option");
            opt.value = "";
            opt.textContent = "(No eligible disks found)";
            opt.disabled = true;
            opt.selected = true;
            selectEl.appendChild(opt);
        }
    }
    function poolDevicePaths(discoveryJson) {
        const devs = discoveryJson?.btrfs?.devices;
        if (!Array.isArray(devs)) return [];
        return devs.map(x => x?.path).filter(Boolean);
    }

    function filterAddDevice(poolPaths) {
        const set = new Set(poolPaths);
        return (d) => isEligibleDisk(d) && !set.has(d.path || d.dev);
    }
    function setDevMode(on) {
        try {
            window.localStorage.setItem(DEV_MODE_KEY, on ? "1" : "0");
        } catch (_) {}
        applyDevModeToUi();
    }

    function applyDevModeToUi() {
        const on = isDevMode();

        const devModeChk = document.getElementById("devModeChk");
        if (devModeChk) devModeChk.checked = on;

        // Dev-only cards:
        const probeCard = document.getElementById("probeCard");
        const topologyCard = document.getElementById("topologyCard");
        const rawCard = document.getElementById("rawCard");
        if (probeCard) probeCard.style.display = on ? "" : "none";
        if (topologyCard) topologyCard.style.display = on ? "" : "none";
        if (rawCard) rawCard.style.display = on ? "" : "none";

        // Dev-only details inside dynamic Actions UI:
        const adv = document.getElementById("advancedDetails");
        if (adv) adv.style.display = on ? "" : "none";
    }

    function poolDisplayName(p) {
        const disp  = String(p?.display_name || "").trim();
        const label = String(p?.label || "").trim();     // btrfs label
        const mount = String(p?.mount || "").trim();

        if (disp) return disp;   // PQ-NAS display name (user-friendly)
        if (label) return label; // fallback to btrfs label
        if (mount) {
            const parts = mount.replace(/\/+$/, "").split("/");
            return parts[parts.length - 1] || mount;
        }
        return "(pool)";
    }

    function loadSelectedMount() {
        try {
            return String(localStorage.getItem(POOL_SEL_KEY) || "");
        } catch (_) {
            return "";
        }
    }

    function saveSelectedMount(m) {
        try {
            localStorage.setItem(POOL_SEL_KEY, String(m || ""));
        } catch (_) {}
    }

    function detectVersionFromUrl() {
        const p = String(location.pathname || "");
        const m = p.match(/\/apps\/[^/]+\/([^/]+)\/www\//);
        return m ? m[1] : "";
    }

    const appVer = detectVersionFromUrl();
    if (titleLine && appVer) titleLine.textContent = `Storage Manager • ${appVer}`;

    async function fetchJson(url) {
        const r = await fetch(url, { credentials: "include", cache: "no-store" });

        const ct = (r.headers.get("content-type") || "").toLowerCase();
        const txt = await r.text();

        // Try JSON first if it looks like JSON or content-type says JSON
        if (ct.includes("application/json") || txt.trim().startsWith("{") || txt.trim().startsWith("[")) {
            try {
                const j = JSON.parse(txt);
                return { r, j, txt };
            } catch (_) {
                return { r, j: null, txt };
            }
        }

        // Non-JSON (plain text / html)
        return { r, j: null, txt };
    }
    function randHex(bytes) {
        const a = new Uint8Array(bytes);
        crypto.getRandomValues(a);
        return Array.from(a).map((b) => b.toString(16).padStart(2, "0")).join("");
    }

    function parseDevicesInput(s) {
        return String(s || "")
            .split(/[\s,]+/g)
            .map((x) => x.trim())
            .filter(Boolean)
            .filter((x) => x.startsWith("/dev/"));
    }
    async function postJson(url, body) {
        const r = await fetch(url, {
            method: "POST",
            credentials: "include",
            cache: "no-store",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body || {}),
        });
        const txt = await r.text();
        let j = null;
        try { j = JSON.parse(txt); } catch (_) {}
        return { r, j, txt };
    }
    async function loadPools() {
        const q = await fetchJson("/api/v4/storage/pools");

        const http = q?.r?.status || 0;
        if (!q.r) return { ok: false, http: 0, error: "no_response", txt: q?.txt || "" };

        if (http !== 200) {
            return { ok: false, http, error: "http_error", txt: q.txt || "", j: q.j || null };
        }

        if (!q.j || q.j.ok !== true || !Array.isArray(q.j.pools)) {
            return { ok: false, http, error: "bad_payload", txt: q.txt || "", j: q.j || null };
        }

        return { ok: true, http, pools: q.j.pools };
    }

    async function refreshTieringCard() {
        try {
            const res = await loadTieringStatus();
            if (!res.ok || !res.data) return;

            const d = res.data;
            const bytes = d.bytes || {};
            const counts = d.counts || {};

            const landingBytes = Number(bytes.landing_bytes || 0);
            const migratingBytes = Number(bytes.migrating_bytes || 0);
            const capacityBytes = Number(bytes.capacity_bytes || 0);
            const totalBytes = Number(bytes.total_bytes || 0);

            const landingFiles = Number(counts.landing_files || 0);
            const migratingFiles = Number(counts.migrating_files || 0);
            const capacityFiles = Number(counts.capacity_files || 0);
            const totalFiles = Number(counts.total_files || 0);

            const landingEl = document.getElementById("tierLandingBytes");
            const migratingEl = document.getElementById("tierMigratingBytes");
            const capacityEl = document.getElementById("tierCapacityBytes");
            const totalBytesEl = document.getElementById("tierTotalBytes");
            const totalFilesEl = document.getElementById("tierTotalFiles");
            const landingFilesEl = document.querySelector("#tierLandingCard .pqTierStatValue");
            const migratingFilesEl = document.getElementById("tierMigratingFiles");
            const capacityFilesEl = document.querySelector("#tierCapacityCard .pqTierStatValue");
            const rateEl = document.getElementById("tierMigratingRate");

            if (landingEl) landingEl.textContent = fmtBytes(landingBytes);
            if (migratingEl) migratingEl.textContent = fmtBytes(migratingBytes);
            if (capacityEl) capacityEl.textContent = fmtBytes(capacityBytes);
            if (totalBytesEl) totalBytesEl.textContent = fmtBytes(totalBytes);

            if (landingFilesEl) landingFilesEl.textContent = `${landingFiles} files`;
            if (migratingFilesEl) migratingFilesEl.textContent = `${migratingFiles} files`;
            if (capacityFilesEl) capacityFilesEl.textContent = `${capacityFiles} files`;
            if (totalFilesEl) totalFilesEl.textContent = `${totalFiles} files`;

            let rate = 0;
            if (g_tieringPrev) {
                const dt = (Date.now() - g_tieringPrev.ts) / 1000;
                const db = capacityBytes - (g_tieringPrev.capacity_bytes || 0);
                if (dt > 0 && db > 0) rate = db / dt;
            }

            g_tieringPrev = {
                ts: Date.now(),
                capacity_bytes: capacityBytes
            };
            g_tieringLastRate = rate;

            if (rateEl) {
                rateEl.textContent = rate > 0 ? fmtBytes(rate) + "/s" : "";
            }

            const landingCard = document.getElementById("tierLandingCard");
            const migratingCard = document.getElementById("tierMigratingCard");
            const capacityCard = document.getElementById("tierCapacityCard");

            if (landingCard) {
                landingCard.classList.remove("pqTierNeutral", "pqTierInfo", "pqTierWarn", "pqTierOk");
                landingCard.classList.add(tierToneClass("landing", landingFiles));
            }
            if (migratingCard) {
                migratingCard.classList.remove("pqTierNeutral", "pqTierInfo", "pqTierWarn", "pqTierOk");
                const migratingActive = migratingFiles > 0 || rate > 0;

                migratingCard.classList.remove("pqTierNeutral","pqTierWarn","pqTierOk","pqTierInfo");

                if (migratingActive) {
                    migratingCard.classList.add("pqTierWarn");
                } else {
                    migratingCard.classList.add("pqTierNeutral");
                }
            }
            if (capacityCard) {
                capacityCard.classList.remove("pqTierNeutral", "pqTierInfo", "pqTierWarn", "pqTierOk");
                capacityCard.classList.add(tierToneClass("capacity", capacityFiles));
            }

            const barEl = document.getElementById("tierFlowBar");
            const landingBarEl = document.getElementById("tierFlowLanding");
            const capacityBarEl = document.getElementById("tierFlowCapacity");
            const flowLeftEl = document.getElementById("tierFlowLeft");
            const flowRightEl = document.getElementById("tierFlowRight");
            const flowStatusEl = document.getElementById("tierFlowStatus");

            if (landingBarEl) landingBarEl.style.width = `${pctOf(landingBytes, totalBytes)}%`;
            if (capacityBarEl) capacityBarEl.style.width = `${pctOf(capacityBytes, totalBytes)}%`;

            if (flowLeftEl) flowLeftEl.textContent = `Landing ${fmtBytes(landingBytes)}`;
            if (flowRightEl) flowRightEl.textContent = `Capacity ${fmtBytes(capacityBytes)}`;

            if (barEl) barEl.classList.toggle("pqTierFlowActive", rate > 0);

            if (flowStatusEl) {
                if (rate > 0) {
                    flowStatusEl.textContent =
                        `Migrating ${migratingFiles} file${migratingFiles === 1 ? "" : "s"} at ${fmtBytes(rate)}/s`;
                } else if (landingBytes > 0) {
                    flowStatusEl.textContent = `Waiting in landing: ${fmtBytes(landingBytes)}`;
                } else {
                    flowStatusEl.textContent = "No landing backlog";
                }
            }
        } catch (_) {}
    }

    async function loadTieringStatus() {
        const q = await fetchJson("/api/v4/admin/storage/tiering/status");

        const http = q?.r?.status || 0;
        if (!q.r) return { ok: false, http: 0, error: "no_response", txt: q?.txt || "" };

        if (http !== 200) {
            return { ok: false, http, error: "http_error", txt: q.txt || "", j: q.j || null };
        }

        if (!q.j || q.j.ok !== true) {
            return { ok: false, http, error: "bad_payload", txt: q.txt || "", j: q.j || null };
        }

        return { ok: true, http, data: q.j };
    }

    
    async function refreshPoolsState() {
        const lp = await loadPools();
        if (lp && lp.ok && Array.isArray(lp.pools)) {
            g_pools = lp.pools;
            return true;
        }
        g_pools = [];
        return false;
    }
    function prettyError(j, r, txt) {
        const msgFromJson =
            j && (j.message || j.error) ? `${j.error || ""} ${j.message || ""}`.trim() : "";

        if (msgFromJson) return msgFromJson;

        const t = String(txt || "").trim();
        if (t) return t;

        return r ? `HTTP ${r.status}` : "error";
    }

    function clearNode(n) {
        if (!n) return;
        n.innerHTML = "";
    }
    async function planConvertMode(mount, mode) {
        return await postJson("/api/v4/raid/plan/convert-mode", { mount, mode });
    }

    async function execConvertMode(mount, mode, plan_id) {
        return await postJson("/api/v4/raid/execute/convert-mode", {
            mount,
            mode,
            plan_id,
            dry_run: false,
            confirm: true
        });
    }
    function ensureConvertRaidOverlay() {
        let ov = document.getElementById("poolConvertRaidOverlay");
        if (ov) return ov;

        ov = document.createElement("div");
        ov.id = "poolConvertRaidOverlay";
        ov.style.position = "fixed";
        ov.style.inset = "0";
        ov.style.display = "none";
        ov.style.alignItems = "center";
        ov.style.justifyContent = "center";
        ov.style.background = isDarkThemeNow() ? "rgba(0,0,0,0.55)" : "rgba(0,0,0,0.25)";
        ov.style.zIndex = "9999";

        ov.innerHTML = `
<div style="
  width:min(860px, 94vw);
  max-height:90vh;
  overflow:auto;
  border-radius:18px;
  border:1px solid rgba(255,255,255,0.14);
  background: var(--panel, rgba(0,0,0,0.35));
  color: var(--fg);
  padding:14px;
  box-shadow: 0 20px 60px rgba(0,0,0,0.45);
">
  <div style="display:flex; align-items:center; justify-content:space-between; gap:10px; margin-bottom:10px;">
    <div id="poolConvertRaidTitle" style="font-weight:950;">Convert RAID</div>
    <button id="poolConvertRaidCloseBtn" class="btn secondary" type="button">Close</button>
  </div>

  <div class="card" style="margin-top:10px;">
    <div class="formGrid3">
      <div class="formField">
        <div class="k">Current mode</div>
        <input id="poolConvertCurrentModeInp" type="text" readonly>
        <div class="formHelp">Detected from current pool state</div>
      </div>

      <div class="formField">
        <div class="k">Target mode</div>
        <select id="poolConvertTargetModeSel">
          <option value="single">single</option>
          <option value="raid1">raid1</option>
        </select>
        <div class="formHelp" id="poolConvertModeHint"></div>
      </div>

      <div class="formField">
        <div class="k">Devices</div>
        <input id="poolConvertDevicesInp" type="text" readonly>
        <div class="formHelp">Current member count</div>
      </div>
    </div>

    <div class="card" style="margin-top:12px;">
      <h3 style="margin:0 0 8px 0;">Summary</h3>
      <div id="poolConvertSummary" class="v" style="white-space:pre-line;"></div>
    </div>

    <div class="row" style="gap:10px; margin-top:12px; align-items:center;">
      <button id="poolConvertPreviewBtn" class="btn secondary" type="button">Preview</button>
      <button id="poolConvertApplyBtn" class="btn danger" type="button" disabled>Apply</button>
    </div>

    <details class="card" style="margin-top:12px;">
      <summary style="cursor:pointer; font-weight:900;">Advanced</summary>
      <pre id="poolConvertDebug" style="margin-top:10px; max-height:45vh; overflow:auto;">(idle)</pre>
    </details>
  </div>
</div>`;
        document.body.appendChild(ov);
        return ov;
    }

    async function openConvertRaidModal(pool) {
        const ov = ensureConvertRaidOverlay();

        const titleEl = ov.querySelector("#poolConvertRaidTitle");
        const closeBtn = ov.querySelector("#poolConvertRaidCloseBtn");
        const currentModeInp = ov.querySelector("#poolConvertCurrentModeInp");
        const targetModeSel = ov.querySelector("#poolConvertTargetModeSel");
        const devicesInp = ov.querySelector("#poolConvertDevicesInp");
        const modeHint = ov.querySelector("#poolConvertModeHint");
        const summaryEl = ov.querySelector("#poolConvertSummary");
        const previewBtn = ov.querySelector("#poolConvertPreviewBtn");
        const applyBtn = ov.querySelector("#poolConvertApplyBtn");
        const dbg = ov.querySelector("#poolConvertDebug");

        const mount = String(pool?.mount || "");
        const currentMode = String(
            String(pool?.runtime_mode || "").trim()
                ? pool.runtime_mode
                : (fmtPoolMode(pool).toLowerCase().includes("raid1") ? "raid1" : "single")
        );
        const totalDevices = Number(pool?.devices || pool?.member_parent_disks?.length || 0);

        let lastPlan = null;

        function updateSummary() {
            const targetMode = String(targetModeSel.value || "single");

            if (modeHint) {
                if (targetMode === currentMode) {
                    modeHint.textContent = "Target mode is the same as current mode.";
                } else if (targetMode === "raid1" && totalDevices < 2) {
                    modeHint.textContent = "RAID1 requires at least 2 current member devices.";
                } else if (targetMode === "raid1") {
                    modeHint.textContent = "Converts current data/metadata profiles to RAID1.";
                } else {
                    modeHint.textContent = "Converts current data/metadata/system profiles to SINGLE.";
                }
            }

            let text =
                `Pool: ${mount}\n` +
                `Current mode: ${currentMode}\n` +
                `Target mode: ${targetMode}\n` +
                `Current devices: ${totalDevices}\n\n`;

            if (targetMode === currentMode) {
                text += "No conversion needed.";
            } else if (targetMode === "raid1" && totalDevices < 2) {
                text += "Cannot convert to RAID1 because the pool currently has fewer than 2 devices.";
            } else if (targetMode === "raid1") {
                text += "This will run a Btrfs balance to convert data/metadata profiles to RAID1.";
            } else {
                text += "This will run a Btrfs balance to convert data/metadata/system profiles to SINGLE.";
            }

            if (summaryEl) summaryEl.textContent = text;
            applyBtn.disabled = true;
            lastPlan = null;
        }

        async function doPreview() {
            const targetMode = String(targetModeSel.value || "single");

            if (targetMode === currentMode) {
                showToast("warn", "Target mode is already current mode.", 3200);
                return;
            }
            if (targetMode === "raid1" && totalDevices < 2) {
                showToast("err", "RAID1 requires at least 2 current member devices.", 4200);
                return;
            }

            dbg.textContent = JSON.stringify({
                request: { mount, mode: targetMode }
            }, null, 2);

            showToast("info", "Preparing convert preview…", 1200);

            const { r, j, txt } = await planConvertMode(mount, targetMode);

            dbg.textContent = JSON.stringify({
                http: r.status,
                response: j ?? txt,
                request: { mount, mode: targetMode }
            }, null, 2);

            if (!r.ok || !j || j.ok !== true || !j.plan || !j.plan.plan_id) {
                showToast("err", `Convert preview failed: ${prettyError(j, r, txt)}`, 5200);
                applyBtn.disabled = true;
                lastPlan = null;
                return;
            }

            lastPlan = j.plan;
            applyBtn.disabled = false;
            showToast("ok", "Preview ready ✓", 1800);
        }

        async function doApply() {
            if (!lastPlan || !lastPlan.plan_id) {
                showToast("warn", "Preview first.", 2200);
                return;
            }

            const targetMode = String(targetModeSel.value || "single");

            const pseudoPlan = {
                ...lastPlan,
                mode: targetMode,
                mount
            };

            ov.style.display = "none";

            const ok = await confirmExecute(pseudoPlan, {
                kind: "add",
                mount,
                new_disk: targetMode === "raid1"
                    ? "Convert existing pool to RAID1"
                    : "Convert existing pool to SINGLE",
                mode: targetMode,
                pool_device_label: String(pool?.resolved_disk || pool?.resolved_source || "")
            });

            if (!ok) {
                ov.style.display = "flex";
                showToast("info", "Apply cancelled.", 1800);
                return;
            }

            if (!ok) {
                showToast("info", "Apply cancelled.", 1800);
                return;
            }

            showToast("info", "Applying RAID conversion…", 1200);

            const { r, j, txt } = await execConvertMode(mount, targetMode, String(lastPlan.plan_id));

            dbg.textContent = JSON.stringify({
                http: r.status,
                response: j ?? txt,
                request: {
                    mount,
                    mode: targetMode,
                    plan_id: String(lastPlan.plan_id),
                    dry_run: false,
                    confirm: true
                }
            }, null, 2);

            if (!r.ok || !j || j.ok !== true) {
                showToast("err", `Convert apply failed: ${prettyError(j, r, txt)}`, 5200);
                return;
            }

            const pid = String(j?.plan_id || j?.plan?.plan_id || lastPlan.plan_id || "");
            if (pid) startExecPolling(pid);

            showToast("ok", "RAID conversion started ✓", 2200);
            ov.style.display = "none";
        }

        titleEl.textContent = `Convert RAID • ${poolDisplayName(pool)}`;
        currentModeInp.value = currentMode;
        targetModeSel.value = currentMode === "raid1" ? "single" : "raid1";
        devicesInp.value = String(totalDevices);

        closeBtn.onclick = () => (ov.style.display = "none");
        previewBtn.onclick = doPreview;
        applyBtn.onclick = doApply;
        targetModeSel.onchange = updateSummary;

        updateSummary();
        dbg.textContent = "(idle)";
        ov.style.display = "flex";
    }
    // --- Toast (non-layout-shifting notifications) ---
    let g_toastTimer = null;

    function ensureToastHost() {
        let host = document.getElementById("pqnasToastHost");
        if (host) return host;

        host = document.createElement("div");
        host.id = "pqnasToastHost";
        host.style.position = "fixed";
        host.style.left = "50%";
        host.style.bottom = "18px";
        host.style.transform = "translateX(-50%)";
        host.style.zIndex = "10000";
        host.style.pointerEvents = "none"; // clicks pass through
        host.style.display = "flex";
        host.style.flexDirection = "column";
        host.style.gap = "10px";
        host.style.alignItems = "center";
        document.body.appendChild(host);
        return host;
    }

    function showToast(kind, text, ms) {
        const host = ensureToastHost();

        // remove any previous toast to keep it simple
        host.innerHTML = "";
        if (g_toastTimer) {
            clearTimeout(g_toastTimer);
            g_toastTimer = null;
        }

        const t = document.createElement("div");
        t.style.pointerEvents = "auto";
        t.style.maxWidth = "min(820px, 92vw)";
        t.style.padding = "10px 14px";
        t.style.borderRadius = "14px";
        t.style.border = "1px solid var(--toast-border, rgba(255,255,255,0.18))";
        t.style.background = "var(--toast-bg, rgba(0,0,0,0.78))";
        t.style.boxShadow = "var(--toast-shadow, 0 10px 30px rgba(0,0,0,0.35))";
        t.style.color = "var(--toast-fg, var(--fg))";

        t.style.fontSize = "13px";
        t.style.lineHeight = "1.35";
        t.style.whiteSpace = "pre-line";

        const color =
            kind === "ok"
                ? "var(--ok)"
                : kind === "warn"
                    ? "var(--warn)"
                    : kind === "err"
                        ? "var(--fail)"
                        : "var(--toast-fg, var(--fg))";

        t.style.color = color;
        t.textContent = text || "";

        host.appendChild(t);

        g_toastTimer = setTimeout(() => {
            host.innerHTML = "";
            g_toastTimer = null;
        }, Number.isFinite(ms) ? ms : 3200);
    }

    function svgAddPreview({ poolLabel, poolDevLabel, newDevLabel, mode }) {
        const title = mode === "raid1" ? "Mirror (RAID 1)" : "No redundancy (Single)";
        const subtitle =
            mode === "raid1"
                ? "Two copies across both drives (Btrfs converts data + metadata via balance)."
                : "Adds the drive for capacity (no mirror).";

        const left = poolDevLabel || "Drive in pool";
        const right = newDevLabel || "Selected drive";

        return `
<svg viewBox="0 0 920 180" width="100%" height="180" role="img" aria-label="Add drive visual preview"
     style="display:block; border-radius:16px;
            border:1px solid var(--raid-border, rgba(0,0,0,0.14));
            background:var(--raid-bg, rgba(0,0,0,0.05));">
  <defs>
<linearGradient id="g_add" x1="0" y1="0" x2="1" y2="1">
<stop offset="0" stop-color="var(--raid-paper-hi, rgba(255,255,255,0.10))"/>
<stop offset="1" stop-color="var(--raid-paper-lo, rgba(255,255,255,0.04))"/>
</linearGradient>
    <marker id="arrow_add" markerWidth="8" markerHeight="8" refX="7" refY="4"
            orient="auto" markerUnits="strokeWidth">
      <path d="M0,0 L8,4 L0,8 z" fill="var(--raid-arrow, rgba(0,140,255,0.65))"></path>
    </marker>
  </defs>

  <text x="24" y="34" font-size="22" font-weight="800" fill="var(--fg)">Add drive to storage pool</text>
  <text x="24" y="60" font-size="14" fill="var(--fg)" opacity="0.75">${esc(poolLabel || "")}</text>

  <rect x="24" y="84" width="260" height="70" rx="16"
        fill="url(#g_add)" stroke="var(--raid-border, rgba(0,0,0,0.14))"/>
  <text x="44" y="112" font-size="14" fill="var(--fg)" opacity="0.75">Drive in pool</text>
  <text x="44" y="137" font-size="16" font-weight="700" fill="var(--fg)">${esc(left)}</text>

  <rect x="330" y="84" width="260" height="70" rx="16"
        fill="var(--raid-mid, rgba(0,0,0,0.06))"
        stroke="var(--raid-border, rgba(0,0,0,0.14))"/>
  <rect x="330" y="84" width="260" height="8" rx="16"
        fill="var(--raid-accent, rgba(0,140,255,0.35))" opacity="0.95"/>

  <text x="350" y="112" font-size="14" fill="var(--fg)" opacity="0.75">Protection level</text>
  <text x="350" y="137" font-size="18" font-weight="800" fill="var(--fg)">${esc(title)}</text>

  <rect x="636" y="84" width="260" height="70" rx="16"
        fill="url(#g_add)" stroke="var(--raid-border, rgba(0,0,0,0.14))"/>
  <text x="656" y="112" font-size="14" fill="var(--fg)" opacity="0.75">Selected drive</text>
  <text x="656" y="137" font-size="16" font-weight="700" fill="var(--fg)">${esc(right)}</text>

  ${
            mode === "raid1"
                ? `
    <line x1="294" y1="119" x2="330" y2="119"
          stroke="var(--raid-arrow, rgba(0,140,255,0.65))" stroke-width="2"
          marker-end="url(#arrow_add)"/>
    <line x1="590" y1="119" x2="636" y2="119"
          stroke="var(--raid-arrow, rgba(0,140,255,0.65))" stroke-width="2"
          marker-end="url(#arrow_add)"/>

    <line x1="636" y1="139" x2="590" y2="139"
          stroke="var(--raid-arrow-soft, rgba(0,140,255,0.35))" stroke-width="1.5"
          marker-end="url(#arrow_add)"/>
    <line x1="330" y1="139" x2="294" y2="139"
          stroke="var(--raid-arrow-soft, rgba(0,140,255,0.35))" stroke-width="1.5"
          marker-end="url(#arrow_add)"/>
  `
                : `
    <line x1="294" y1="129" x2="330" y2="129"
          stroke="var(--raid-arrow, rgba(0,140,255,0.65))" stroke-width="2"
          marker-end="url(#arrow_add)"/>
    <line x1="590" y1="129" x2="636" y2="129"
          stroke="var(--raid-arrow, rgba(0,140,255,0.65))" stroke-width="2"
          marker-end="url(#arrow_add)"/>
  `
        }

  <text x="24" y="173" font-size="13" fill="var(--fg)" opacity="0.75">${esc(subtitle)}</text>
</svg>`;
    }

    function svgRemovePreview({ poolLabel, removeDevLabel }) {
        return `
<svg viewBox="0 0 920 180" width="100%" height="180" role="img" aria-label="Remove drive visual preview"
     style="display:block; border-radius:16px;
            border:1px solid var(--raid-border, rgba(0,0,0,0.14));
            background:var(--raid-bg, rgba(0,0,0,0.12));">
  <defs>
    <marker id="arrow_rm" markerWidth="8" markerHeight="8" refX="7" refY="4"
            orient="auto" markerUnits="strokeWidth">
      <path d="M0,0 L8,4 L0,8 z" fill="var(--raid-arrow, rgba(0,140,255,0.65))"></path>
    </marker>
  </defs>

  <text x="24" y="34" font-size="22" font-weight="800" fill="var(--fg)">Remove drive from storage pool</text>
  <text x="24" y="60" font-size="14" fill="var(--fg)" opacity="0.75">${esc(poolLabel || "")}</text>

  <rect x="24" y="84" width="320" height="70" rx="16"
        fill="rgba(255,255,255,0.10)" stroke="var(--raid-border, rgba(0,0,0,0.14))"/>
  <text x="44" y="112" font-size="14" fill="var(--fg)" opacity="0.75">Drive to remove</text>
  <text x="44" y="137" font-size="16" font-weight="800" fill="var(--fg)">${esc(removeDevLabel || "Select a drive")}</text>

  <line x1="360" y1="119" x2="560" y2="119"
        stroke="var(--raid-arrow, rgba(0,140,255,0.65))" stroke-width="2"
        marker-end="url(#arrow_rm)"/>

  <rect x="576" y="84" width="320" height="70" rx="16"
        fill="var(--raid-mid, rgba(0,0,0,0.06))"
        stroke="var(--raid-border, rgba(0,0,0,0.14))"/>

  <rect x="576" y="84" width="320" height="8" rx="16"
        fill="var(--raid-accent, rgba(0,140,255,0.35))" opacity="0.95"/>

  <text x="596" y="112" font-size="14" fill="var(--fg)" opacity="0.75">What happens</text>
  <text x="596" y="137" font-size="16" font-weight="800" fill="var(--fg)">Data migrates off → drive removed</text>

  <text x="24" y="173" font-size="13" fill="var(--fg)" opacity="0.75">This may take a long time depending on how much data must move.</text>
</svg>`;
    }

    function ensureConfirmOverlay() {
        let ov = document.getElementById("confirmOverlay");
        if (ov) return ov;

        ov = document.createElement("div");
        ov.id = "confirmOverlay";
        ov.style.position = "fixed";
        ov.style.inset = "0";
        ov.style.display = "none";
        ov.style.alignItems = "center";
        ov.style.justifyContent = "center";
        ov.style.backdropFilter = "none";
        ov.style.webkitBackdropFilter = "none";
        ov.style.background = "rgba(0,0,0,0.45)";
        ov.style.zIndex = "9999";

        const dark = isDarkThemeNow();
        ov.style.background = dark ? "rgba(0,0,0,0.55)" : "rgba(0,0,0,0.25)";

        ov.style.setProperty("--confirm-surface", dark ? "rgba(18,18,18,0.92)" : "rgba(255,255,255,0.92)");
        ov.style.setProperty("--confirm-border", dark ? "rgba(255,255,255,0.14)" : "rgba(0,0,0,0.14)");
        ov.style.setProperty("--confirm-fg", dark ? "var(--fg, rgba(255,255,255,0.92))" : "rgba(20,20,20,0.92)");
        ov.style.setProperty("--confirm-shadow", dark ? "0 20px 60px rgba(0,0,0,0.55)" : "0 20px 60px rgba(0,0,0,0.25)");

        ov.innerHTML = `
<div style="
  width:min(720px, 92vw);
  max-height:90vh;
  overflow:auto;
  border-radius:18px;
  border:1px solid var(--confirm-border);
  background:var(--confirm-surface);
  color:var(--confirm-fg);
  padding:14px;
  box-shadow:var(--confirm-shadow);
">
  <div style="display:flex; align-items:center; justify-content:space-between; gap:10px; margin-bottom:10px;">
    <div id="confirmTitle" style="font-weight:950;">Confirm storage pool change</div>
    <button id="confirmCloseBtn" class="btn secondary" type="button">Close</button>
  </div>

  <div id="confirmBody" style="
    background: var(--panel, rgba(255,255,255,0.06));
    border: 1px solid var(--confirm-border);
    border-radius: 16px;
    padding: 12px;
  ">
    <div id="confirmViz" style="margin:10px 0;"></div>

    <div id="confirmSummary" class="v" style="margin-bottom:10px;"></div>

    <details id="confirmDetails" style="
      margin-top:10px;
      background: rgba(0,0,0,0.04);
      border: 1px solid rgba(0,0,0,0.10);
      border-radius: 14px;
      padding: 10px 12px;
    ">
      <summary style="cursor:pointer; font-weight:900;">Advanced details (plan)</summary>
      <pre id="confirmPre" style="
        max-height:46vh;
        margin-top:10px;
        background: var(--panel2, rgba(0,0,0,0.04));
        border: 1px solid var(--confirm-border);
        border-radius: 12px;
        padding: 10px;
        color: var(--confirm-fg);
        overflow:auto;
      "></pre>
    </details>

    <div style="display:flex; gap:10px; justify-content:flex-end; margin-top:12px;">
      <button id="confirmCancelBtn" class="btn secondary" type="button">Cancel</button>
      <button id="confirmOkBtn" class="btn danger" type="button">Apply now</button>
    </div>
  </div>
</div>
`;
        document.body.appendChild(ov);
        return ov;
    }

    function confirmExecute(plan, opts) {
        const o = opts && typeof opts === "object" ? opts : {};

        return new Promise((resolve) => {
            const ov = ensureConfirmOverlay();
            const closeBtn = ov.querySelector("#confirmCloseBtn");
            const cancelBtn = ov.querySelector("#confirmCancelBtn");
            const okBtn = ov.querySelector("#confirmOkBtn");

            const titleEl = ov.querySelector("#confirmTitle");
            const summaryEl = ov.querySelector("#confirmSummary");
            const vizEl = ov.querySelector("#confirmViz");
            const preEl = ov.querySelector("#confirmPre");

            const pid = plan?.plan_id || "";
            const mnt = plan?.mount || o.mount || "";
            const kind = o.kind || "add"; // "add" | "remove"
            const mode = o.mode || plan?.mode || "";

            let summary = "";
            if (kind === "remove") {
                summary =
                    `You are about to remove a drive from the storage pool.\n` +
                    `Pool: ${mnt}\n` +
                    `Remove: ${o.remove_device || plan?.remove_device || "(drive)"}\n` +
                    `This migrates data and can take a long time.`;
            } else {
                summary =
                    `You are about to add a drive to the storage pool.\n` +
                    `Pool: ${mnt}\n` +
                    `Add: ${o.new_disk || plan?.new_disk || "(drive)"}\n` +
                    `Protection: ${mode === "raid1" ? "Mirror (RAID 1)" : "No redundancy (Single)"}\n`;

                if (plan?.force || o.force) summary += `\n⚠ WARNING: This will permanently erase the selected drive.`;
            }

            if (titleEl) titleEl.textContent = kind === "remove" ? "Confirm remove drive" : "Confirm add drive";

            if (summaryEl) {
                summaryEl.textContent = summary;
                summaryEl.style.whiteSpace = "pre-line";
                summaryEl.style.color = "var(--confirm-fg)";
                summaryEl.style.background = "var(--panel, rgba(255,255,255,0.06))";
                summaryEl.style.border = "1px solid var(--confirm-border)";
                summaryEl.style.borderRadius = "14px";
                summaryEl.style.padding = "10px 12px";
            }

            if (vizEl) {
                try {
                    const dark = isDarkThemeNow();
                    if (kind === "remove") {
                        const svg = svgRemovePreview({
                            poolLabel: mnt ? `Storage pool: ${mnt}` : "",
                            removeDevLabel: o.remove_device || "",
                        });
                        vizEl.innerHTML = `<div style="
  --raid-bg: var(--panel, ${dark ? "rgba(0,0,0,0.10)" : "rgba(255,255,255,0.92)"});
  --raid-mid: ${dark ? "rgba(255,255,255,0.06)" : "rgba(0,0,0,0.06)"};
  --raid-border: ${dark ? "rgba(255,255,255,0.14)" : "rgba(0,0,0,0.14)"};
  --raid-paper-hi: ${dark ? "rgba(255,255,255,0.10)" : "rgba(0,0,0,0.04)"};
  --raid-paper-lo: ${dark ? "rgba(255,255,255,0.06)" : "rgba(0,0,0,0.02)"};
  --raid-accent: rgba(var(--info-rgb, 0,140,255), 0.65);
  --raid-arrow: rgba(var(--info-rgb, 0,140,255), 0.85);
  --raid-arrow-soft: rgba(var(--info-rgb, 0,140,255), 0.45);
">${svg}</div>`;
                    } else {
                        const poolDev =
                            String(o.pool_device_label || "") ||
                            String(plan?.resolved_disk || "") ||
                            String(plan?.resolved_source || "") ||
                            "Drive in pool";

                        const svg = svgAddPreview({
                            poolLabel: mnt ? `Storage pool: ${mnt}` : "",
                            poolDevLabel: poolDev,
                            newDevLabel: o.new_disk || plan?.new_disk || "",
                            mode: mode || "single",
                        });

                        vizEl.innerHTML = `<div style="
  --raid-bg: var(--panel, ${dark ? "rgba(0,0,0,0.10)" : "rgba(255,255,255,0.92)"});
  --raid-mid: ${dark ? "rgba(255,255,255,0.06)" : "rgba(0,0,0,0.06)"};
  --raid-border: ${dark ? "rgba(255,255,255,0.14)" : "rgba(0,0,0,0.14)"};
  --raid-paper-hi: ${dark ? "rgba(255,255,255,0.10)" : "rgba(0,0,0,0.04)"};
  --raid-paper-lo: ${dark ? "rgba(255,255,255,0.06)" : "rgba(0,0,0,0.02)"};
  --raid-accent: rgba(var(--info-rgb, 0,140,255), 0.65);
  --raid-arrow: rgba(var(--info-rgb, 0,140,255), 0.85);
  --raid-arrow-soft: rgba(var(--info-rgb, 0,140,255), 0.45);
">${svg}</div>`;
                    }
                } catch (_) {
                    vizEl.innerHTML = "";
                }
            }

            const summaryPlan = {
                plan_id: pid,
                mount: mnt,
                kind,
                ...(kind === "remove"
                    ? { remove_device: o.remove_device || plan?.remove_device || "" }
                    : { new_disk: o.new_disk || plan?.new_disk || "", mode }),
                requires_downtime: !!plan?.requires_downtime,
                busy: !!plan?.busy,
                busy_lock: plan?.busy_lock || "",
                warnings: Array.isArray(plan?.warnings) ? plan.warnings : [],
                steps: Array.isArray(plan?.steps) ? plan.steps : [],
                commands: Array.isArray(plan?.commands) ? plan.commands : [],
            };

            if (preEl) preEl.textContent = JSON.stringify(summaryPlan, null, 2);

            const cleanup = () => {
                ov.style.display = "none";
                closeBtn?.removeEventListener("click", onCancel);
                cancelBtn?.removeEventListener("click", onCancel);
                okBtn?.removeEventListener("click", onOk);
                ov?.removeEventListener("click", onBackdrop);
            };

            const onCancel = () => {
                cleanup();
                resolve(false);
            };
            const onOk = () => {
                cleanup();
                resolve(true);
            };
            const onBackdrop = (e) => {
                if (e.target === ov) onCancel();
            };

            closeBtn?.addEventListener("click", onCancel);
            cancelBtn?.addEventListener("click", onCancel);
            okBtn?.addEventListener("click", onOk);
            ov?.addEventListener("click", onBackdrop);

            ov.style.display = "flex";
        });
    }
    function kvRow(k, v) {
        const row = document.createElement("div");
        row.className = "row";
        const kEl = document.createElement("div");
        kEl.className = "k";
        kEl.textContent = k;
        const vEl = document.createElement("div");
        vEl.className = "v";
        vEl.textContent = v == null ? "" : String(v);
        row.appendChild(kEl);
        row.appendChild(vEl);
        return row;
    }

    function isDarkThemeNow() {
        const cs = getComputedStyle(document.documentElement);
        const v = (cs.getPropertyValue("--ui_is_dark") || "").trim();
        if (v === "1") return true;
        if (v === "0") return false;

        // fallback only if token missing
        const theme = document.documentElement.getAttribute("data-theme") || "";
        if (theme === "bright" || theme === "win_classic") return false;
        if (theme) return true;

        return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
    }

    function setUserStatusLines(lines) {
        if (!userStatusEl) return;
        userStatusEl.textContent = (Array.isArray(lines) ? lines : [String(lines || "")]).join("\n");
    }

    function fmtBytes(b) {
        if (!Number.isFinite(b)) return "?";
        const u = ["B", "KiB", "MiB", "GiB", "TiB"];
        let i = 0;
        while (b >= 1024 && i < u.length - 1) {
            b /= 1024;
            i++;
        }
        return b.toFixed(2) + " " + u[i];
    }
    function tierToneClass(kind, files) {
        const n = Number(files || 0);
        if (kind === "migrating") return g_tieringLastRate > 0 ? "pqTierWarn" : "pqTierNeutral";
        if (kind === "landing") return n > 0 ? "pqTierInfo" : "pqTierNeutral";
        if (kind === "capacity") return n > 0 ? "pqTierOk" : "pqTierNeutral";
        return "pqTierNeutral";
    }

    function tierPill(text, cls) {
        return `<span class="pqPill ${cls || ""}">${esc(text)}</span>`;
    }
    function yesNo(v) {
        return v ? "Yes" : "No";
    }
    function pctOf(part, total) {
        const p = Number(part || 0);
        const t = Number(total || 0);
        if (!Number.isFinite(p) || !Number.isFinite(t) || t <= 0) return 0;
        return Math.max(0, Math.min(100, (p / t) * 100));
    }
    function esc(s) {
        return String(s ?? "").replace(/[&<>"']/g, (m) => ({
            "&": "&amp;",
            "<": "&lt;",
            ">": "&gt;",
            "\"": "&quot;",
            "'": "&#39;",
        })[m]);
    }

    function renderUserStatusFrom(statusJ, mountRequested, mountResolved, discoveryObj) {
        const lines = [];

        // High-level
        const fs = String(statusJ?.fstype || "").toLowerCase();
        const isBtrfs = fs === "btrfs";

        lines.push(`Mount: ${mountResolved || mountRequested || "-"}`);
        lines.push(`Filesystem: ${statusJ?.fstype || "(unknown)"}`);
        lines.push(`Btrfs features: ${isBtrfs ? "Enabled" : "Disabled"}`);

        // If server provides parsed topology via /status
        const sum = statusJ?.parsed?.summary || null;
        const usage = statusJ?.parsed?.usage || null;

        if (sum && typeof sum === "object") {
            if (sum.label) lines.push(`Pool label: ${sum.label}`);
            if (sum.uuid) lines.push(`UUID: ${sum.uuid}`);
            if (sum.total_devices != null) lines.push(`Devices: ${sum.total_devices}`);
        }

        if (usage && typeof usage === "object") {
            if (Number.isFinite(usage.used_bytes) && Number.isFinite(usage.size_bytes)) {
                const pct = usage.used_percent_1dp != null ? `${usage.used_percent_1dp}%` : "";
                lines.push(
                    `Used: ${fmtBytes(usage.used_bytes)} / ${fmtBytes(usage.size_bytes)} ${pct ? `(${pct})` : ""}`.trim()
                );
            }
        }

        // Optional: discovery hints (safe, user-friendly)
        const bdevs = Array.isArray(discoveryObj?.btrfs?.devices) ? discoveryObj.btrfs.devices : null;
        if (bdevs) lines.push(`Member drives: ${bdevs.length}`);

        setUserStatusLines(lines);
    }

    function isLoopDisk(d) {
        const name = String(d?.name || "");
        const path = String(d?.path || "");
        return name.startsWith("loop") || path.startsWith("/dev/loop");
    }

    function diskLabel(d) {
        const name = String(d?.name || "");
        const path = String(d?.path || "");
        const model = String(d?.model || "").trim();
        const size = fmtBytes(Number(d?.size_bytes) || 0);
        const serial = String(d?.serial || "").trim();
        const bits = [];
        bits.push(name ? name : path);
        if (model) bits.push(model);
        bits.push(size);
        if (serial) bits.push(serial);
        return bits.join(" • ");
    }

    function currentMemberParentDisks(parsed) {
        const set = new Set();
        const devs = parsed?.btrfs?.devices;
        if (!Array.isArray(devs)) return set;
        for (const d of devs) {
            const pd = String(d?.parent_disk || "");
            if (pd) set.add(pd);
        }
        return set;
    }

    function candidateDisks(parsed, opts) {
        const all = Array.isArray(parsed?.disks) ? parsed.disks : [];
        const members = currentMemberParentDisks(parsed);

        const mnt = String(parsed?.resolved_mount || parsed?.mount || "").trim();
        const allowLoops = mnt.startsWith("/srv/pqnas-test");

        const o = opts && typeof opts === "object" ? opts : {};
        const usbOnly = !!o.usbOnly;
        const showInternal = !!o.showInternal;

        return all
            .filter((d) => (allowLoops ? true : !isLoopDisk(d)))
            .filter((d) => String(d?.path || "").startsWith("/dev/"))
            .filter((d) => !members.has(String(d?.path || "")))
            .filter((d) => {
                const tran = String(d?.tran || "").toLowerCase();
                const rm = !!d?.rm;
                const children = Number(d?.children || 0);

                if (usbOnly) return tran === "usb";

                // Default safe: show removable/USB or blank/unpartitioned disks
                if (!showInternal) {
                    if (rm || tran === "usb") return true;
                    if (children === 0) return true;
                    return false;
                }

                return true;
            });
    }

    function renderActions(parsed, mount, targetEl, opts) {
        const o = (opts && typeof opts === "object") ? opts : {};
        const focus = String(o.focus || "drives"); // "drives" | "remove"
        const out = targetEl || actionsOut;
        if (!out) return;

        const cands = candidateDisks(parsed, { showInternal: false, usbOnly: false });
        const disabled = !(
            parsed &&
            parsed.ok === true &&
            String(parsed.fstype || "").toLowerCase() === "btrfs"
        );


        let html = "";

        html += `<div style="font-weight:900; margin: 6px 0 8px;">Add drive</div>`;

        if (disabled) {
            html += `<div class="v" style="opacity:.8;">Storage pool actions are disabled (filesystem is not Btrfs or probe failed).</div>`;
            out.innerHTML = html;
            applyDevModeToUi();
            return;
        }

        if (!cands.length) {
            html += `<div class="v" style="opacity:.8;">No available drives found. (All disks are already members, or only loop devices exist.)</div>`;
        } else {
            html += `
  <div class="row" style="gap:10px; align-items:flex-start;">
    <div style="flex:1 1 520px; min-width:260px;">
      <div class="k" style="margin-bottom:6px;">Available drive</div>

      <div class="row" style="gap:10px; align-items:center; margin-bottom:8px;">
        <label style="display:flex; gap:10px; align-items:center; padding:8px 10px; border-radius:12px; border:1px solid rgba(255,255,255,0.14); background:rgba(0,0,0,0.14);">
          <input id="showInternalChk" type="checkbox" style="transform:scale(1.1);">
          <span class="v" style="opacity:.9;">Show internal disks (advanced)</span>
        </label>

        <label style="display:flex; gap:10px; align-items:center; padding:8px 10px; border-radius:12px; border:1px solid rgba(255,255,255,0.14); background:rgba(0,0,0,0.14);">
          <input id="usbOnlyChk" type="checkbox" style="transform:scale(1.1);">
          <span class="v" style="opacity:.9;">USB-only (testing)</span>
        </label>
      </div>

      <select id="addDiskSel" style="width:100%; padding:10px 12px; border-radius:14px; border:1px solid rgba(255,255,255,0.14); background:rgba(0,0,0,0.18); color:var(--fg);">
        ${cands.map((d) => `<option value="${String(d.path)}">${diskLabel(d)}</option>`).join("")}
      </select>

      <div class="row" style="margin-top:10px; gap:10px;">
        <div style="flex:1 1 240px; min-width:220px;">
          <div class="k" style="margin-bottom:6px;">Protection level</div>
          <select id="modeSel" style="width:100%; padding:10px 12px; border-radius:14px; border:1px solid rgba(255,255,255,0.14); background:rgba(0,0,0,0.18); color:var(--fg);">
            <option value="single">No redundancy (Single)</option>
            <option value="raid1">Mirror (RAID 1)</option>
          </select>
          <div class="v" style="opacity:.75; margin-top:6px;">
            Single = capacity-focused. Mirror = redundancy-focused (conversion can take time).
          </div>
        </div>

        <div style="flex:1 1 240px; min-width:220px;">
          <div class="k" style="margin-bottom:6px;">Erase drive</div>
          <label style="display:flex; gap:10px; align-items:center; padding:10px 12px; border-radius:14px; border:1px solid rgba(255,255,255,0.14); background:rgba(0,0,0,0.18);">
            <input id="forceChk" type="checkbox" style="transform:scale(1.1);">
            <span class="v" style="opacity:.9;">Allow destructive wipe if the drive has partitions</span>
          </label>
          <div class="v" id="forceWarn" style="opacity:.75; margin-top:6px;">
            Keep OFF unless you are OK with wiping the selected drive.
          </div>
        </div>
      </div>

      <div class="card" style="margin-top:12px;">
        <h3 style="margin:0 0 8px 0;">Visual preview</h3>
        <div id="addViz"></div>
      </div>

      <div class="v" style="opacity:.75; margin-top:10px;">
        Note: this modifies the existing storage pool. It does not create a brand-new pool from scratch.
      </div>
    </div>

    <div style="display:flex; flex-direction:column; gap:10px; flex:0 0 auto;">
      <button class="btn" id="planAddBtn" type="button">Preview</button>
      <button class="btn secondary" id="execAddBtn" type="button" disabled>Apply</button>
    </div>
  </div>`;
        }

        html += `
  <div class="row" style="gap:10px; align-items:flex-start;">
    <div style="flex:1 1 520px; min-width:260px;">
      <div class="k" style="margin-bottom:6px;">Available drive</div>

      <div class="row" style="gap:10px; align-items:center; margin-bottom:8px;">
        <label style="display:flex; gap:10px; align-items:center; padding:8px 10px; border-radius:12px; border:1px solid rgba(255,255,255,0.14); background:rgba(0,0,0,0.14);">
          <input id="showInternalChk" type="checkbox" style="transform:scale(1.1);">
          <span class="v" style="opacity:.9;">Show internal disks (advanced)</span>
        </label>

        <label style="display:flex; gap:10px; align-items:center; padding:8px 10px; border-radius:12px; border:1px solid rgba(255,255,255,0.14); background:rgba(0,0,0,0.14);">
          <input id="usbOnlyChk" type="checkbox" style="transform:scale(1.1);">
          <span class="v" style="opacity:.9;">USB-only (testing)</span>
        </label>
      </div>

      <select id="addDiskSel" style="width:100%; padding:10px 12px; border-radius:14px; border:1px solid rgba(255,255,255,0.14); background:rgba(0,0,0,0.18); color:var(--fg);">
        ${cands.map((d) => `<option value="${String(d.path)}">${diskLabel(d)}</option>`).join("")}
      </select>

      <div class="row" style="margin-top:10px; gap:10px;">
        <div style="flex:1 1 240px; min-width:220px;">
          <div class="k" style="margin-bottom:6px;">Protection level</div>
          <select id="modeSel" style="width:100%; padding:10px 12px; border-radius:14px; border:1px solid rgba(255,255,255,0.14); background:rgba(0,0,0,0.18); color:var(--fg);">
            <option value="single">No redundancy (Single)</option>
            <option value="raid1">Mirror (RAID 1)</option>
          </select>
          <div class="v" style="opacity:.75; margin-top:6px;">
            Single = capacity-focused. Mirror = redundancy-focused (conversion can take time).
          </div>
        </div>

        <div style="flex:1 1 240px; min-width:220px;">
          <div class="k" style="margin-bottom:6px;">Erase drive</div>
          <label style="display:flex; gap:10px; align-items:center; padding:10px 12px; border-radius:14px; border:1px solid rgba(255,255,255,0.14); background:rgba(0,0,0,0.18);">
            <input id="forceChk" type="checkbox" style="transform:scale(1.1);">
            <span class="v" style="opacity:.9;">Allow destructive wipe if the drive has partitions</span>
          </label>
          <div class="v" id="forceWarn" style="opacity:.75; margin-top:6px;">
            Keep OFF unless you are OK with wiping the selected drive.
          </div>
        </div>
      </div>

      <div class="card" style="margin-top:12px;">
        <h3 style="margin:0 0 8px 0;">Visual preview</h3>
        <div id="addViz"></div>
      </div>

      <div class="v" style="opacity:.75; margin-top:10px;">
        Note: this modifies the existing storage pool. It does not create a brand-new pool from scratch.
      </div>
    </div>

    <div style="display:flex; flex-direction:column; gap:10px; flex:0 0 auto;">
      <button class="btn" id="planAddBtn" type="button">Preview</button>
      <button class="btn secondary" id="execAddBtn" type="button" disabled>Apply</button>
    </div>
  </div>

  <hr style="opacity:.15; margin-top:14px;">

  <div style="font-weight:900; margin: 6px 0 8px;">Remove drive</div>
  <div id="rmBlock"></div>

  <details class="card" id="advancedDetails" style="margin-top:12px;">
    <summary style="cursor:pointer; font-weight:900;">Preview / Apply output (advanced)</summary>
    <pre id="actionOut" style="margin-top:10px;">(no actions yet)</pre>
  </details>

  <details class="card" style="margin-top:12px;" open>
    <summary style="cursor:pointer; font-weight:900;">Progress</summary>

    <div class="pbarWrap" style="margin-top:10px;">
      <div class="pbarRow">
        <div class="pill warn" id="execPill">idle</div>
        <div class="pbarMeta" id="execMeta">(no job)</div>
      </div>
      <div class="pbar" aria-label="Execution progress">
        <div class="pbarFill" id="execPbarFill"></div>
      </div>
    </div>

    <pre id="progressOut">(idle)</pre>
  </details>
`;

        out.innerHTML = html;

        applyDevModeToUi(); // hide advancedDetails when dev mode is off

        const addSel = document.getElementById("addDiskSel");
        const planBtn = document.getElementById("planAddBtn");
        const execBtn = document.getElementById("execAddBtn");
        const actionOut = document.getElementById("actionOut");
        const modeSel = document.getElementById("modeSel");
        const forceChk = document.getElementById("forceChk");
        const forceWarn = document.getElementById("forceWarn");
        const progressOut = document.getElementById("progressOut");
        const execPill = document.getElementById("execPill");
        const execMeta = document.getElementById("execMeta");
        const execPbarFill = document.getElementById("execPbarFill");
        const addViz = document.getElementById("addViz");
        const showInternalChk = document.getElementById("showInternalChk");
        const usbOnlyChk = document.getElementById("usbOnlyChk");

        // Restore last outputs (probe() rebuilds HTML)
        if (actionOut && g_lastAction) actionOut.textContent = JSON.stringify(g_lastAction, null, 2);
        if (progressOut && g_lastProgress) progressOut.textContent = g_lastProgress;

        function setActionOut(obj) {
            g_lastAction = obj;
            if (!actionOut) return;
            actionOut.textContent = JSON.stringify(obj, null, 2);
        }
        
        function looksLikePlanMismatch(r, j, txt) {
            const st = Number(r?.status || 0);
            if (st === 409 || st === 412) return true;

            const s = j && (j.error || j.message) ? `${j.error || ""} ${j.message || ""}` : "";
            const t = `${s} ${txt || ""}`.toLowerCase();
            return t.includes("plan") && (t.includes("mismatch") || t.includes("stale") || t.includes("changed") || t.includes("expired"));
        }

        function showPlanMismatchHint(kind, extra) {
            showToast("warn", "Plan changed — please Preview again (auto refresh).", 4200);

            const msg = {
                ok: false,
                error: "plan_changed",
                message:
                    kind === "remove"
                        ? "The storage pool changed since your Preview. Please Preview again (we will do it automatically)."
                        : "The storage pool changed since your Preview. Please Preview again (we will do it automatically).",
                ...extra,
            };
            setActionOut(msg);
        }

        function refillAddCandidates() {
            const cands2 = candidateDisks(parsed, {
                showInternal: !!showInternalChk?.checked,
                usbOnly: !!usbOnlyChk?.checked,
            });

            if (!addSel) return;

            if (!cands2.length) {
                addSel.innerHTML = `<option value="">(no eligible drives)</option>`;
                execBtn.disabled = true;
                return;
            }

            const current = String(addSel.value || "");
            addSel.innerHTML = cands2.map((d) => `<option value="${String(d.path)}">${diskLabel(d)}</option>`).join("");

            const still = cands2.some((d) => String(d.path) === current);
            if (still) addSel.value = current;

            updateAddViz();
            execBtn.disabled = true; // require new Preview after list changes
            lastPlan = null;
            lastPlanId = "";
            lastPlanNonce = "";
        }

        showInternalChk?.addEventListener("change", refillAddCandidates);
        usbOnlyChk?.addEventListener("change", refillAddCandidates);


        // --- Progress polling (balance/scrub/health) ---
        function setProgress(obj) {
            // If exec-record polling is active, don't overwrite progressOut with mount polling.
            const st = gstate();
            if (st.execPlanId && st.execTimer) return;

            if (!progressOut) return;

            const o = obj && typeof obj === "object" ? obj : {};
            const lines = [];

            if (o.note) lines.push(String(o.note));

            const bal = o.balance || o.balance_status || null;
            if (bal && typeof bal === "object") {
                if (bal.found === false || bal.running === false) {
                    lines.push("Balance: idle (no balance running)");
                } else {
                    lines.push(`Balance: running=${!!bal.running} found=${!!bal.found} paused=${!!bal.paused} rc=${bal.rc ?? "?"}`);
                    if (bal.status_raw) lines.push(`  ${String(bal.status_raw).trim()}`);
                    else if (bal.out) lines.push(`  ${String(bal.out).trim()}`);
                }
            } else {
                lines.push("Balance: (unknown)");
            }

            const scrub = o.scrub || o.scrub_status || null;
            if (scrub && typeof scrub === "object") {
                lines.push(`Scrub: running=${!!scrub.running} found=${!!scrub.found} rc=${scrub.rc ?? "?"}`);
                if (scrub.error_summary) lines.push(`  errors: ${scrub.error_summary}`);
                if (scrub.raw) lines.push(`  ${String(scrub.raw).trim()}`);
                else if (scrub.out) lines.push(`  ${String(scrub.out).trim()}`);
            } else {
                lines.push("Scrub: (unknown)");
            }

            const health = o.health || null;
            if (health && typeof health === "object") {
                lines.push(`Health: ok=${health.ok === true}`);
                if (health.scrub && typeof health.scrub === "object") {
                    lines.push(`  scrub.state=${health.scrub.state || "?"} running=${!!health.scrub.running}`);
                    if (health.scrub.error_summary) lines.push(`  scrub.errors=${health.scrub.error_summary}`);
                }
            } else {
                lines.push("Health: (unknown)");
            }

            const txt = lines.join("\n");
            g_lastProgress = txt;
            progressOut.textContent = txt;
        }

        async function pollOnce() {
            const out = { mount, ts: new Date().toISOString() };

            try {
                const b = await fetchJson(`/api/v4/raid/balance-status?mount=${encodeURIComponent(mount)}`);
                out.balance = b.j ?? b.txt ?? { http: b.r?.status };
            } catch (e) {
                out.balance = { error: String(e && e.message ? e.message : e) };
            }

            try {
                const s = await fetchJson(`/api/v4/raid/scrub-status?mount=${encodeURIComponent(mount)}`);
                out.scrub = s.j ?? s.txt ?? { http: s.r?.status };
            } catch (e) {
                out.scrub = { error: String(e && e.message ? e.message : e) };
            }

            try {
                const h = await fetchJson(`/api/v4/raid/health?mount=${encodeURIComponent(mount)}`);
                out.health = h.j ?? h.txt ?? { http: h.r?.status };
            } catch (e) {
                out.health = { error: String(e && e.message ? e.message : e) };
            }

            setProgress(out);

            const balRunning = !!(out.balance && (out.balance.running || out.balance.in_progress || out.balance.state === "running"));
            const scrubRunning = !!(out.scrub && (out.scrub.running || out.scrub.in_progress || out.scrub.state === "running"));
            const st = gstate();

            if (!balRunning && !scrubRunning && st.pollTimer) {
                clearInterval(st.pollTimer);
                st.pollTimer = null;
            }
        }

        function startPolling() {
            const st = gstate();
            if (st.pollTimer) return;
            pollOnce();
            st.pollTimer = setInterval(pollOnce, 2000);
        }


        // Initial progress snapshot (before any apply)
        (async () => {
            if (!mount) {
                setProgress({ note: "Progress: no storage pool selected yet." });
                return;
            }
            try {
                const [bal, scr, h] = await Promise.all([
                    fetchJson(`/api/v4/raid/balance-status?mount=${encodeURIComponent(mount)}`),
                    fetchJson(`/api/v4/raid/scrub-status?mount=${encodeURIComponent(mount)}`),
                    fetchJson(`/api/v4/raid/health?mount=${encodeURIComponent(mount)}`),
                ]);
                setProgress({ note: "Progress (initial):", balance: bal.j || null, scrub: scr.j || null, health: h.j || null });
            } catch (e) {
                setProgress({ note: `Progress (initial) error: ${String(e)}` });
            }
        })();

        // Add visual preview
        function updateAddViz() {
            if (!addViz) return;
            const dev = String(addSel?.value || "");
            const mode = String(modeSel?.value || "single");
            const poolLabel = mount ? `Storage pool: ${mount}` : "";

            const bdevs = Array.isArray(parsed?.btrfs?.devices) ? parsed.btrfs.devices : [];
            const poolDev = bdevs && bdevs[0] && bdevs[0].path ? String(bdevs[0].path) : "Drive in pool";

            addViz.innerHTML = svgAddPreview({
                poolLabel,
                poolDevLabel: poolDev,
                newDevLabel: dev,
                mode,
            });
        }
        if (addSel && modeSel && addViz) updateAddViz();
        addSel?.addEventListener("change", updateAddViz);
        modeSel?.addEventListener("change", updateAddViz);

        forceChk?.addEventListener("change", () => {
            if (!forceWarn) return;
            forceWarn.textContent = forceChk.checked
                ? "WARNING: erase enabled — the selected drive may be wiped."
                : "Keep OFF unless you are OK with wiping the selected drive.";
        });

        // ----- Remove-drive UI -----
        const rmHost = document.getElementById("rmBlock");
        if (rmHost) {
            const bdevs = Array.isArray(parsed?.btrfs?.devices) ? parsed.btrfs.devices : [];
            const totalDevs = Number(parsed?.btrfs?.total_devices) || bdevs.length || 0;

            if (totalDevs <= 1) {
                rmHost.innerHTML = `<div class="v" style="opacity:.8;">Cannot remove a drive: storage pool has ${totalDevs} drive(s). Add a second drive first.</div>`;
            } else if (!bdevs.length) {
                rmHost.innerHTML = `<div class="v" style="opacity:.8;">No member drives found in discovery output.</div>`;
            } else {
                rmHost.innerHTML = `
  <div class="row" style="gap:10px; align-items:flex-start; margin-top:6px;">
    <div style="flex:1 1 520px; min-width:260px;">
      <div class="k" style="margin-bottom:6px;">Drive in pool</div>
      <select id="rmDevSel" style="width:100%; padding:10px 12px; border-radius:14px; border:1px solid rgba(255,255,255,0.14); background:rgba(0,0,0,0.18); color:var(--fg);">
        ${bdevs
                    .map((d) => {
                        const mp = String(d?.path || "");
                        const pd = String(d?.parent_disk || "");
                        const size = d?.size_bytes ? fmtBytes(Number(d.size_bytes)) : "";
                        const used = d?.used_bytes ? fmtBytes(Number(d.used_bytes)) : "";
                        const label = [mp, pd && pd !== mp ? `(${pd})` : "", size ? `• ${size}` : "", used ? `• used ${used}` : ""]
                            .filter(Boolean)
                            .join(" ");
                        return `<option value="${mp}">${label}</option>`;
                    })
                    .join("")}
      </select>

      <div style="margin-top:10px;">
        <label style="display:flex; gap:10px; align-items:center; padding:10px 12px; border-radius:14px; border:1px solid rgba(255,255,255,0.14); background:rgba(0,0,0,0.18);">
          <input id="rmForceChk" type="checkbox" style="transform:scale(1.1);">
          <span class="v" style="opacity:.9;">Force (allow removing the currently-used pool drive)</span>
        </label>
        <div class="v" id="rmForceWarn" style="opacity:.75; margin-top:6px;">
          Keep OFF unless you know exactly why you need it.
        </div>
      </div>

      <div class="card" style="margin-top:12px;">
        <h3 style="margin:0 0 8px 0;">Visual preview</h3>
        <div id="rmViz"></div>
      </div>

      <div class="v" style="opacity:.75; margin-top:10px;">
        Removing a drive migrates data off that drive and can take a long time.
      </div>
    </div>

    <div style="display:flex; flex-direction:column; gap:10px; flex:0 0 auto;">
      <button class="btn" id="planRmBtn" type="button">Preview</button>
      <button class="btn secondary" id="execRmBtn" type="button" disabled>Apply</button>
    </div>
  </div>
`;

                const rmSel = document.getElementById("rmDevSel");
                const rmPlanBtn = document.getElementById("planRmBtn");
                const rmExecBtn = document.getElementById("execRmBtn");
                const rmForceChk = document.getElementById("rmForceChk");
                const rmForceWarn = document.getElementById("rmForceWarn");
                const rmViz = document.getElementById("rmViz");

                function updateRmViz() {
                    if (!rmViz) return;
                    const poolLabel = mount ? `Storage pool: ${mount}` : "";
                    const removeDev = String(rmSel?.value || "");
                    rmViz.innerHTML = svgRemovePreview({ poolLabel, removeDevLabel: removeDev });
                }
                updateRmViz();

                rmSel?.addEventListener("change", () => {
                    updateRmViz();
                    if (rmExecBtn) rmExecBtn.disabled = true;
                    lastRmPlan = null;
                    lastRmPlanId = "";
                });

                rmForceChk?.addEventListener("change", () => {
                    if (!rmForceWarn) return;
                    rmForceWarn.textContent = rmForceChk.checked
                        ? "WARNING: force enabled — you may be removing the drive currently hosting the pool."
                        : "Keep OFF unless you know exactly why you need it.";

                    if (rmExecBtn) rmExecBtn.disabled = true;
                    lastRmPlan = null;
                    lastRmPlanId = "";
                });

                let lastRmPlan = null;
                let lastRmPlanId = "";

                rmPlanBtn?.addEventListener("click", async () => {
                    try {
                        setActionOut({ note: "Preview remove clicked…", ts: new Date().toISOString() });

                        if (rmExecBtn) rmExecBtn.disabled = true;
                        lastRmPlan = null;
                        lastRmPlanId = "";

                        const remove_device = String(rmSel?.value || "").trim();
                        if (!remove_device) {
                            setActionOut({ error: "pick a drive in the pool first" });
                            return;
                        }
                        if (!remove_device.startsWith("/dev/")) {
                            setActionOut({ error: "invalid remove_device (expected /dev/...)", remove_device });
                            return;
                        }

                        const force = !!rmForceChk?.checked;
                        const body = { mount, remove_device, force };
                        const { r, j, txt } = await postJson("/api/v4/raid/plan/remove-device", body);

                        setActionOut({ endpoint: "plan/remove-device", http: r.status, request: body, response: j ?? txt });

                        if (r.status === 401 || r.status === 403) return;
                        if (!j || j.ok !== true || !j.plan) {
                            showToast("err", "Preview failed. See advanced output.", 4500);
                            return;
                        }

                        if (j && j.error === "already_executed") {
                            showToast("warn", "This exact plan was already executed. Click Preview again to generate a new plan.", 5200);
                        }

                        lastRmPlan = j.plan;
                        lastRmPlanId = String(lastRmPlan?.plan_id || "");
                        if (rmExecBtn) rmExecBtn.disabled = !(lastRmPlan && lastRmPlanId);

                        showToast("ok", "Preview ready ✓", 2200);
                    } catch (e) {
                        setActionOut({ error: `Preview remove error: ${String(e && e.stack ? e.stack : e)}` });
                        showToast("err", "Preview crashed. See advanced output.", 5000);
                    }
                });

                rmExecBtn?.addEventListener("click", async () => {
                    try {
                        const remove_device = String(rmSel?.value || "").trim();
                        if (!remove_device) return;

                        // 🔒 HARD SAFETY GUARD
                        if (mount !== g_selectedMount) {
                            showToast("err", "Storage pool changed. Please Preview again.", 4000);
                            rmExecBtn.disabled = true;
                            return;
                        }

                        if (!lastRmPlan || !lastRmPlanId) {
                            setActionOut({ error: "no valid remove preview loaded — click Preview first" });
                            return;
                        }

                        const ok = await confirmExecute(lastRmPlan, {
                            kind: "remove",
                            mount,
                            remove_device,
                            force: !!rmForceChk?.checked,
                        });
                        if (!ok) {
                            showToast("info", "Apply cancelled.", 1800);
                            return;
                        }

                        showToast("info", "Applying…", 2000);

                        const body = {
                            mount,
                            remove_device,
                            force: !!rmForceChk?.checked,
                            plan_id: lastRmPlanId,
                            dry_run: false,
                            confirm: true,
                        };

                        setActionOut({ note: "Applying remove…", ts: new Date().toISOString(), request: body });

                        const { r, j, txt } = await postJson("/api/v4/raid/execute/remove-device", body);

                        setActionOut({
                            endpoint: "execute/remove-device",
                            http: r.status,
                            request: body,
                            response: j ?? txt,
                        });

                        if (r.ok) showToast("ok", "Applied ✓ Watching exec record…", 2400);
                        else showToast("err", "Apply failed. See advanced output.", 4500);

                        const pid = j && (j.plan_id || (j.plan && j.plan.plan_id)) ? (j.plan_id || j.plan.plan_id) : "";
                        if (pid) startExecPolling(pid);

                        startPolling();
                        setTimeout(() => probe(), 900);
                    } catch (e) {
                        setActionOut({ error: `Apply remove error: ${String(e && e.stack ? e.stack : e)}` });
                        showToast("err", "Apply crashed. See advanced output.", 5000);
                    }
                });
            }
        }

        // ----- Add-drive flow -----
        let lastPlanId = "";
        let lastPlanNonce = "";
        let lastPlan = null;

        async function runAddPreviewSilently() {
            execBtn.disabled = true;
            lastPlanId = "";
            lastPlanNonce = "";
            lastPlan = null;

            const device = String(addSel?.value || "").trim();
            if (!device || !device.startsWith("/dev/")) return false;

            const mode = String(modeSel?.value || "single").trim();
            const force = !!forceChk?.checked;

            const body = { mount, new_disk: device, mode, force };
            const { r, j, txt } = await postJson("/api/v4/raid/plan/add-device", body);

            const planObj = j && j.plan ? j.plan : null;
            const pid = String(planObj?.plan_id || "");
            const pnonce = String(planObj?.plan_nonce || "");

            if (r.ok && planObj && pid && pnonce) {
                lastPlan = planObj;
                lastPlanId = pid;
                lastPlanNonce = pnonce;
                execBtn.disabled = false;
                setActionOut({ note: "Preview refreshed automatically.", endpoint: "plan/add-device", http: r.status, request: body, response: j });
                showToast("ok", "Preview refreshed ✓", 1800);
                return true;
            }

            setActionOut({
                error: "auto_preview_failed",
                endpoint: "plan/add-device",
                http: r.status,
                request: body,
                response: j ?? txt,
                note: "missing plan_id or plan_nonce",
            });
            showToast("err", "Preview failed. See advanced output.", 4500);
            return false;
        }

        function extractPlan(j) {
            if (!j || typeof j !== "object") return null;
            if (j.plan && typeof j.plan === "object") return j.plan;
            if (j.result && j.result.plan && typeof j.result.plan === "object") return j.result.plan;
            if (j.data && j.data.plan && typeof j.data.plan === "object") return j.data.plan;
            if (j.plan_id || j.id) return j;
            return null;
        }

        planBtn?.addEventListener("click", async () => {
            try {
                setActionOut({ note: "Preview clicked…", ts: new Date().toISOString() });

                execBtn.disabled = true;
                lastPlanId = "";
                lastPlanNonce = "";
                lastPlan = null;

                const device = String(addSel?.value || "").trim();
                if (!device) {
                    setActionOut({ error: "no drive selected" });
                    return;
                }
                if (!device.startsWith("/dev/")) {
                    setActionOut({ error: "invalid drive (expected /dev/...)", device });
                    return;
                }

                const mode = String(modeSel?.value || "single").trim();
                const force = !!forceChk?.checked;

                const body = { mount, new_disk: device, mode, force };
                const { r, j, txt } = await postJson("/api/v4/raid/plan/add-device", body);

                setActionOut({
                    endpoint: "plan/add-device",
                    http: r.status,
                    request: body,
                    response: j ?? txt,
                });

                if (r.status === 401 || r.status === 403) return;

                const planObj = extractPlan(j);
                const pid = String(planObj?.plan_id || planObj?.id || "");
                const pnonce = String(planObj?.plan_nonce || "");

                if (r.ok && planObj && pid && pnonce) {
                    lastPlan = planObj;
                    lastPlanId = pid;
                    lastPlanNonce = pnonce;
                    execBtn.disabled = false;
                    showToast("ok", "Preview ready ✓", 2200);
                } else {
                    showToast("err", "Preview failed. See advanced output.", 4500);
                    execBtn.disabled = true;
                }
            } catch (e) {
                setActionOut({ error: "Preview handler crashed", detail: String(e && e.stack ? e.stack : e) });
                showToast("err", "Preview crashed. See advanced output.", 5000);
            }
        });

        execBtn?.addEventListener("click", async () => {
            try {
                const device = String(addSel?.value || "").trim();
                if (!device) return;

                // 🔒 HARD SAFETY GUARD
                if (mount !== g_selectedMount) {
                    showToast("err", "Storage pool changed. Please Preview again.", 4000);
                    execBtn.disabled = true;
                    return;
                }

                if (!device.startsWith("/dev/")) {
                    setActionOut({ error: "invalid drive (expected /dev/...)", device });
                    return;
                }

                if (!lastPlan || !lastPlanId || !lastPlanNonce) {
                    setActionOut({
                        error: "no valid preview loaded — click Preview first",
                        have_plan: !!lastPlan,
                        plan_id: lastPlanId,
                        plan_nonce: lastPlanNonce,
                    });
                    return;
                }

                const ok = await confirmExecute(lastPlan, {
                    kind: "add",
                    mount,
                    new_disk: device,
                    mode: String(modeSel?.value || "single"),
                    pool_device_label: String((Array.isArray(parsed?.btrfs?.devices) && parsed.btrfs.devices[0]?.path) || "")
                });

                if (!ok) {
                    showToast("info", "Apply cancelled.", 1800);
                    return;
                }

                const body = {
                    mount,
                    new_disk: device,
                    mode: String(modeSel?.value || "single"),
                    force: !!forceChk?.checked,
                    plan_id: lastPlanId,
                    plan_nonce: lastPlanNonce,
                    dry_run: false,
                    confirm: true,
                };

                showToast("info", "Applying…", 2000);
                setActionOut({ note: "Applying add…", ts: new Date().toISOString(), request: body });

                const { r, j, txt } = await postJson("/api/v4/raid/execute/add-device", body);

                if (!r.ok && looksLikePlanMismatch(r, j, txt)) {
                    showPlanMismatchHint("add", { http: r.status, response: j ?? txt });
                    showToast("warn", "Plan changed. Refreshing preview…", 3200);
                    await runAddPreviewSilently();
                    return;
                }

                setActionOut({
                    note: "EXEC add returned",
                    endpoint: "execute/add-device",
                    http: r.status,
                    request: body,
                    response: j ?? txt,
                });

                if (r.ok) showToast("ok", "Applied ✓ Watching exec record…", 2400);
                else showToast("err", "Apply failed. See advanced output.", 4500);

                const pid = j && (j.plan_id || (j.plan && j.plan.plan_id)) ? (j.plan_id || j.plan.plan_id) : "";
                if (pid) startExecPolling(pid);

                startPolling();
                setTimeout(() => probe(), 900);
            } catch (e) {
                setActionOut({ error: `Apply add error: ${String(e && e.stack ? e.stack : e)}` });
                showToast("err", "Apply crashed. See advanced output.", 5000);
            }
        });
    }

    function renderTopology(parsed) {
        const elx = document.getElementById("topology");
        if (!elx) return;

        const p =
            parsed && parsed.summary
                ? parsed
                : parsed && parsed.btrfs && parsed.btrfs.summary
                    ? { summary: parsed.btrfs.summary, usage: parsed.btrfs.usage || {} }
                    : null;

        if (!p || !p.summary) {
            elx.textContent = "No topology info.";
            return;
        }

        const s = p.summary;
        const usage = p.usage || {};

        let html = "";

        html += `
        <div><b>Label:</b> ${esc(s.label || "-")}</div>
        <div><b>UUID:</b> ${esc(s.uuid || "-")}</div>
        <div><b>Total devices:</b> ${esc(s.total_devices ?? "-")}</div>
        <div><b>FS used:</b>
            ${fmtBytes(usage.used_bytes || 0)} /
            ${fmtBytes(usage.size_bytes || 0)}
            (${usage.used_percent_1dp ?? 0}%)
        </div>
        <hr>
    `;

        if (Array.isArray(s.devices)) {
            s.devices.forEach((d, i) => {
                html += `
          <div class="device">
            <b>Device ${i}</b><br>
            Path: ${esc(d.path)}<br>
            Size: ${fmtBytes(d.size_bytes)}<br>
            Used: ${fmtBytes(d.used_bytes)}
          </div>
          <br>
        `;
            });
        }

        elx.innerHTML = html;
    }

    function renderPoolSelectorTop() {
        if (!poolSelTop) return;

        if (!g_pools.length) {
            poolSelTop.innerHTML = `<option value="">(no pools found)</option>`;
            poolSelTop.disabled = true;
            return;
        }

        const opts = g_pools
            .map((p) => {
                const m = String(p?.mount || "");
                const name = poolDisplayName(p);
                const label = name ? `${name} — ${m}` : m;
                const sel = m === g_selectedMount ? "selected" : "";
                return `<option value="${esc(m)}" ${sel}>${esc(label)}</option>`;
            })
            .join("");

        poolSelTop.innerHTML = opts;
        poolSelTop.disabled = false;
    }
    async function renderPoolsTab() {
        if (!poolsOut) return;
        function ensureEditSlotsOverlay() {
            let ov = document.getElementById("poolEditSlotsOverlay");
            if (ov) return ov;

            ov = document.createElement("div");
            ov.id = "poolEditSlotsOverlay";
            ov.style.position = "fixed";
            ov.style.inset = "0";
            ov.style.display = "none";
            ov.style.alignItems = "center";
            ov.style.justifyContent = "center";
            ov.style.background = isDarkThemeNow() ? "rgba(0,0,0,0.55)" : "rgba(0,0,0,0.25)";
            ov.style.zIndex = "9999";

            ov.innerHTML = `
<div style="
  width:min(980px, 96vw);
  max-height:90vh;
  overflow:auto;
  border-radius:18px;
  border:1px solid rgba(255,255,255,0.14);
  background: var(--panel, rgba(0,0,0,0.35));
  color: var(--fg);
  padding:14px;
  box-shadow: 0 20px 60px rgba(0,0,0,0.45);
">
  <div style="display:flex; align-items:center; justify-content:space-between; gap:10px; margin-bottom:10px;">
    <div id="poolEditSlotsTitle" style="font-weight:950;">Edit pool slots</div>
    <button id="poolEditSlotsCloseBtn" class="btn secondary" type="button">Close</button>
  </div>

  <div class="card" style="margin-top:10px;">
    <div class="formGrid3">
      <div class="formField">
        <div class="k">Display name</div>
        <input id="poolEditDisplayNameInp" type="text">
        <div class="formHelp">Optional user-facing name</div>
      </div>

      <div class="formField">
        <div class="k">Mode</div>
        <select id="poolEditModeSel">
          <option value="single">single</option>
          <option value="raid1">raid1</option>
        </select>
        <div class="formHelp" id="poolEditModeHint"></div>
      </div>

      <div class="formField">
        <div class="k">Slot count</div>
        <input id="poolEditSlotCountInp" type="number" min="1" max="16" step="1">
        <div class="formHelp">Adjust visible slots, then update</div>
      </div>
    </div>

    <div class="row" style="gap:10px; margin-top:12px; align-items:flex-end; flex-wrap:wrap;">
      <button id="poolEditSlotsApplyCountBtn" class="btn secondary" type="button">Update slots</button>
      <button id="poolEditSlotsRefreshBtn" class="btn secondary" type="button">Refresh devices</button>
      <div style="flex:1 1 auto;"></div>
      <button id="poolEditSlotsSaveBtn" class="btn danger" type="button">Save layout</button>
    </div>

    <div class="card" style="margin-top:12px;">
      <h3 style="margin:0 0 8px 0;">Slots</h3>
      <div id="poolEditSlotsHost"></div>
      <div class="v" id="poolEditSlotHint" style="opacity:.75; margin-top:8px;"></div>
    </div>

    <details class="card" style="margin-top:12px;">
      <summary style="cursor:pointer; font-weight:900;">Advanced</summary>
      <pre id="poolEditSlotsDebug" style="margin-top:10px; max-height:45vh; overflow:auto;">(idle)</pre>
    </details>
  </div>
</div>`;
            document.body.appendChild(ov);
            return ov;
        }

        async function openEditSlotsModal(pool) {
            const ov = ensureEditSlotsOverlay();

            const titleEl = ov.querySelector("#poolEditSlotsTitle");
            const closeBtn = ov.querySelector("#poolEditSlotsCloseBtn");
            const displayNameInp = ov.querySelector("#poolEditDisplayNameInp");
            const modeSel = ov.querySelector("#poolEditModeSel");
            const modeHint = ov.querySelector("#poolEditModeHint");
            const slotCountInp = ov.querySelector("#poolEditSlotCountInp");
            const applyCountBtn = ov.querySelector("#poolEditSlotsApplyCountBtn");
            const refreshBtn = ov.querySelector("#poolEditSlotsRefreshBtn");
            const saveBtn = ov.querySelector("#poolEditSlotsSaveBtn");
            const slotsHost = ov.querySelector("#poolEditSlotsHost");
            const slotHint = ov.querySelector("#poolEditSlotHint");
            const dbg = ov.querySelector("#poolEditSlotsDebug");

            const mount = String(pool?.mount || "");
            let disks = [];
            let slotValues = [];
            let slotCount = Math.max(1, Number(pool?.slot_count || 1) || 1);

            function eligibleDisks() {
                let arr = Array.isArray(disks) ? disks.slice() : [];
                if (isDevMode()) {
                    arr.sort((a, b) => (isLoopDisk(a) ? 0 : 1) - (isLoopDisk(b) ? 0 : 1));
                }

                const latestPool = Array.isArray(g_pools)
                    ? g_pools.find(x => String(x?.mount || "") === String(mount || ""))
                    : null;

                const runtimeMembers = Array.isArray(latestPool?.member_parent_disks)
                    ? latestPool.member_parent_disks
                    : (Array.isArray(pool?.member_parent_disks) ? pool.member_parent_disks : []);

                const eligible = arr.filter(isEligibleDisk);
                const byPath = new Map(eligible.map(d => [String(d.path || d.dev || ""), d]));

                // Keep saved slot devices selectable
                for (const v of slotValues) {
                    const dev = String(v || "").trim();
                    if (!dev) continue;
                    if (byPath.has(dev)) continue;

                    const found = arr.find(d => String(d.path || d.dev || "") === dev);
                    if (found) {
                        byPath.set(dev, found);
                    } else {
                        byPath.set(dev, {
                            path: dev,
                            name: dev.replace("/dev/", ""),
                            model: "Saved slot device",
                            size_bytes: 0
                        });
                    }
                }

                // Keep runtime member devices selectable
                for (const v of runtimeMembers) {
                    const dev = String(v || "").trim();
                    if (!dev) continue;
                    if (byPath.has(dev)) continue;

                    const found = arr.find(d => String(d.path || d.dev || "") === dev);
                    if (found) {
                        byPath.set(dev, found);
                    } else {
                        byPath.set(dev, {
                            path: dev,
                            name: dev.replace("/dev/", ""),
                            model: "Runtime member",
                            size_bytes: 0
                        });
                    }
                }

                return Array.from(byPath.values());
            }

            function syncSlotValuesFromPool() {
                const slots = Array.isArray(pool?.slots) ? pool.slots : [];
                slotValues = [];
                for (let i = 0; i < slotCount; i++) {
                    const s = slots[i];
                    slotValues[i] = s && s.device ? String(s.device) : "";
                }
            }

            function syncSlotValuesFromDom() {
                const sels = slotsHost.querySelectorAll("select[data-slot-index]");
                const next = [];
                sels.forEach((sel) => {
                    const idx = Number(sel.getAttribute("data-slot-index") || "0");
                    next[idx] = String(sel.value || "").trim();
                });
                slotValues = next;
            }

            function updateHints() {
                const devices = slotValues.filter(Boolean);
                modeHint.textContent = modeSel.value === "raid1"
                    ? "RAID1 needs at least 2 assigned slots."
                    : "Single uses one or more drives without redundancy.";
                slotHint.textContent = `Assigned devices: ${devices.length}. Empty slots stay as placeholders.`;
            }

            function renderSlotSelectors() {
                while (slotValues.length < slotCount) slotValues.push("");
                if (slotValues.length > slotCount) slotValues = slotValues.slice(0, slotCount);

                const eligible = eligibleDisks();
                const selectedSet = new Set(slotValues.filter(Boolean));
                console.log("[edit-slots] renderSlotSelectors eligible =", eligible.map(d => d.path || d.dev));
                slotsHost.innerHTML = `
<div style="display:flex; flex-direction:column; gap:10px;">
  ${Array.from({ length: slotCount }, (_, i) => {
                    const current = String(slotValues[i] || "");
                    const options = [
                        `<option value="">(empty)</option>`,
                        ...eligible.map((d) => {
                            const val = String(d.path || d.dev || "");
                            const selected = val === current ? "selected" : "";
                            const usedElsewhere = val && selectedSet.has(val) && val !== current;
                            const disabled = usedElsewhere ? "disabled" : "";
                            const suffix = usedElsewhere ? " — already selected" : "";
                            const latestPool = Array.isArray(g_pools)
                                ? g_pools.find(x => String(x?.mount || "") === String(mount || ""))
                                : null;

                            const runtimeMembers = Array.isArray(latestPool?.member_parent_disks)
                                ? latestPool.member_parent_disks
                                : (Array.isArray(pool?.member_parent_disks) ? pool.member_parent_disks : []);

                            const isCurrentAssigned = slotValues.includes(val);
                            const isRuntimeMember = runtimeMembers.includes(val);

                            const marks = [];
                            if (isCurrentAssigned) marks.push("saved");
                            if (isRuntimeMember) marks.push("member");

                            const markText = marks.length ? " — " + marks.join(", ") : "";
                            return `<option value="${esc(val)}" ${selected} ${disabled}>${esc(diskLabel(d) + markText + suffix)}</option>`;
                        })
                    ].join("");

                    return `
<div class="pqSlotRow pqSlotRowEditable" style="align-items:flex-start;">
  <div class="pqSlotLeft" style="min-width:120px;">
    <div class="pqSlotTitle">Slot ${i + 1}</div>
    <div class="pqSlotDev">Choose disk or leave empty</div>
  </div>
  <div style="flex:1 1 auto;">
    <select data-slot-index="${i}" style="width:100%; min-height:44px; padding:10px 12px; border-radius:14px; border:1px solid rgba(255,255,255,0.14); background:rgba(0,0,0,0.18); color:var(--fg);">
      ${options}
    </select>
  </div>
</div>`;
                }).join("")}
</div>`;

                slotsHost.querySelectorAll("select[data-slot-index]").forEach((sel) => {
                    sel.addEventListener("change", () => {
                        syncSlotValuesFromDom();
                        renderSlotSelectors();
                        updateHints();
                    });
                });

                updateHints();
            }

            async function refreshDisks() {
                try {
                    dbg.textContent = "(loading /api/v4/storage/disks …)";
                    const j = await loadAllDisks();
                    disks = Array.isArray(j?.disks) ? j.disks.slice() : [];
                    dbg.textContent = JSON.stringify({
                        ok: true,
                        disks_total: disks.length,
                        eligible_total: eligibleDisks().length,
                        mount
                    }, null, 2);
                    renderSlotSelectors();
                } catch (e) {
                    dbg.textContent = JSON.stringify({ ok: false, error: String(e && e.message ? e.message : e) }, null, 2);
                    showToast("err", "Failed to load disks (see Advanced).", 5200);
                }
            }

            async function saveLayout() {
                syncSlotValuesFromDom();

                const mode = String(modeSel.value || "single");
                const display_name = String(displayNameInp.value || "").trim();
                const slots = Array.from({ length: slotCount }, (_, i) => ({
                    index: i,
                    device: slotValues[i] ? String(slotValues[i]) : null
                }));
                const devices = slots.map(s => s.device).filter(Boolean);

                if (mode === "raid1" && devices.length < 2) {
                    showToast("err", "raid1 requires at least 2 assigned slots.", 5200);
                    return;
                }
                const unique = new Set(devices);
                if (unique.size !== devices.length) {
                    showToast("err", "The same disk cannot be selected in multiple slots.", 5200);
                    return;
                }

                const body = {
                    mount,
                    display_name,
                    mode,
                    slot_count: slotCount,
                    slots
                };

                dbg.textContent = JSON.stringify({ request: body }, null, 2);
                showToast("info", "Saving layout…", 1200);

                const { r, j, txt } = await setPoolLayout(body);

                dbg.textContent = JSON.stringify({
                    http: r.status,
                    response: j ?? txt,
                    request: body
                }, null, 2);

                if (!r.ok || !j || j.ok !== true) {
                    showToast("err", `Save layout failed: ${prettyError(j, r, txt)}`, 5200);
                    return;
                }

                showToast("ok", "Layout saved ✓", 1800);
                ov.style.display = "none";
                await refreshPoolsState();
                renderPoolSelectorTop();
                await renderPoolsTab();
            }

            titleEl.textContent = `Edit slots • ${mount}`;
            displayNameInp.value = String(pool?.display_name || "");
            modeSel.value = String(pool?.mode || "single");
            slotCountInp.value = String(slotCount);
            syncSlotValuesFromPool();

            closeBtn.onclick = () => (ov.style.display = "none");
            refreshBtn.onclick = refreshDisks;
            applyCountBtn.onclick = () => {
                syncSlotValuesFromDom();
                slotCount = Math.max(1, Math.min(16, Number(slotCountInp.value || slotCount) || slotCount));
                slotCountInp.value = String(slotCount);
                renderSlotSelectors();
            };
            modeSel.onchange = () => {
                syncSlotValuesFromDom();
                renderSlotSelectors();
            };
            saveBtn.onclick = saveLayout;

            ov.style.display = "flex";
            await refreshDisks();
        }
        function slotBadge(slot) {
            const assigned = !!slot?.assigned;
            const present = !!slot?.present;

            if (!assigned) return `<span class="badge info">empty</span>`;
            if (present) return `<span class="badge ok">present</span>`;
            return `<span class="badge warn">missing</span>`;
        }

        function fmtPoolMode(p) {
            const runtimeMode = String(p?.runtime_mode || "").trim().toLowerCase();
            const data = String(p?.profile_data || "").trim().toLowerCase();
            const meta = String(p?.profile_metadata || "").trim().toLowerCase();
            const cfg = String(p?.mode || "").trim().toLowerCase();

            if (runtimeMode === "raid1") return "RAID1";
            if (runtimeMode === "single") return "Single";

            if (data.includes("raid1") || meta.includes("raid1")) return "RAID1";
            if (data.includes("single")) return "Single";

            if (cfg === "raid1") return "RAID1";
            if (cfg === "single") return "Single";

            return cfg || runtimeMode || data || meta || "?";
        }
        function modePillOpts(p) {
            const m = String(fmtPoolMode(p) || "").toLowerCase();
            if (m.includes("raid1")) {
                return {
                    border: "rgba(0,180,120,0.55)",
                    bg: "rgba(0,180,120,0.18)"
                };
            }
            if (m.includes("single")) {
                return {
                    border: "rgba(var(--info-rgb,0,140,255),0.35)",
                    bg: "rgba(var(--info-rgb,0,140,255),0.10)"
                };
            }
            return {};
        }
        function fmtPoolHealth(p) {
            const st = p?.status || {};
            if (!st.mounted) return `<span class="badge warn">offline</span>`;
            if (st.busy) return `<span class="badge warn">busy</span>`;
            if (st.degraded) return `<span class="badge warn">degraded</span>`;
            if (st.layout_drift) return `<span class="badge warn">layout drift</span>`;
            return `<span class="badge ok">online</span>`;
        }
        function poolPendingState(p) {
            const slots = Array.isArray(p?.slots) ? p.slots : [];
            const desired = new Set(
                slots
                    .map(s => (s && s.device ? String(s.device).trim() : ""))
                    .filter(Boolean)
            );

            const runtime = new Set(
                Array.isArray(p?.member_parent_disks)
                    ? p.member_parent_disks.map(x => String(x || "").trim()).filter(Boolean)
                    : []
            );

            const toAdd = [];
            const toRemove = [];

            for (const d of desired) {
                if (!runtime.has(d)) toAdd.push(d);
            }
            for (const d of runtime) {
                if (!desired.has(d)) toRemove.push(d);
            }

            if (toAdd.length && toRemove.length) {
                return `<span class="badge warn">pending change</span>`;
            }
            if (toAdd.length) {
                return `<span class="badge warn">pending add</span>`;
            }
            if (toRemove.length) {
                return `<span class="badge warn">pending remove</span>`;
            }
            return "";
        }
        function slotRowHtml(slot, editable) {
            const idx = Number(slot?.index || 0) + 1;
            const dev = slot?.device ? String(slot.device) : "";
            const stateHtml = slotBadge(slot);

            return `
<div class="pqSlotRow ${editable ? "pqSlotRowEditable" : ""}">
  <div class="pqSlotLeft">
    <div class="pqSlotTitle">Slot ${idx}</div>
    <div class="pqSlotDev">${dev ? esc(dev) : "(empty)"}</div>
  </div>
  <div class="pqSlotRight">
    ${stateHtml}
  </div>
</div>`;
        }

        function poolSummaryHtml(p) {
            const used = Number(p?.used_bytes || 0);
            const freeEstimated = Number(p?.free_estimated_bytes || 0);
            const usableTotal = Number(p?.usable_total_bytes || 0);

            const free = freeEstimated > 0
                ? freeEstimated
                : Math.max(0, Number(p?.size_bytes || 0) - used);

            return `
<div class="pqPoolSummaryGrid">
  <div class="pqPoolStat">
    <div class="k">Mode</div>
    <div class="pqPoolStatValue">${esc(fmtPoolMode(p))}</div>
  </div>
  <div class="pqPoolStat">
    <div class="k">Devices</div>
    <div class="pqPoolStatValue">${esc(String(p?.devices ?? 0))}</div>
  </div>
  <div class="pqPoolStat">
    <div class="k">Used</div>
    <div class="pqPoolStatValue">${esc(fmtBytes(used))}</div>
  </div>
  <div class="pqPoolStat">
    <div class="k">Free</div>
    <div class="pqPoolStatValue">${esc(fmtBytes(free))}</div>
  </div>
</div>`;
        }

        const pools = Array.isArray(g_pools) ? g_pools : [];
        const tier = await loadTieringStatus().catch(() => ({ ok: false, error: "fetch_failed" }));
        if (!pools.length) {
            poolsOut.innerHTML = `<div class="v" style="opacity:.8;">No pools found.</div>`;
            return;
        }
        function svgSingleDrive({ label = "" } = {}) {
            const L = esc(label);

            return `
<svg viewBox="0 0 220 92" width="100%" height="92" role="img" aria-label="Drive ${L}" style="display:block;">
  <defs>
    <linearGradient id="pqDrvG" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="rgba(var(--info-rgb, 0,140,255), 0.45)"/>
      <stop offset="1" stop-color="rgba(var(--info-rgb, 0,140,255), 0.14)"/>
    </linearGradient>
  </defs>

  <!-- chassis -->
  <rect x="10" y="14" width="200" height="56" rx="14"
        fill="var(--panel2)"
        stroke="var(--border)" stroke-width="2"/>

  <!-- accent top strip -->
  <rect x="10" y="14" width="200" height="10" rx="14"
        fill="rgba(var(--info-rgb, 0,140,255), 0.28)"/>

  <!-- tray -->
  <rect x="20" y="28" width="180" height="34" rx="10"
        fill="url(#pqDrvG)"
        stroke="var(--border2)" stroke-width="2"/>

  <!-- leds -->
  <rect x="32" y="41" width="10" height="8" rx="2" fill="rgba(var(--fg-rgb),0.72)"/>
  <rect x="46" y="41" width="10" height="8" rx="2" fill="rgba(var(--fg-rgb),0.42)"/>

  <!-- label -->
  <text x="64" y="49" font-size="12" font-family="var(--mono)"
        fill="var(--fg)" opacity="0.92">${L}</text>
</svg>`;
        }
        function pill(text, opts = {}) {
            const border = opts.border || "rgba(255,255,255,0.14)";
            const bg = opts.bg || "rgba(0,0,0,0.10)";

            return `<span style="
      display:inline-block; padding:3px 8px; border-radius:999px;
      border:1px solid ${border};
      background:${bg};
      font-size:12px; opacity:.9;
    ">${esc(text)}</span>`;
        }
        function svgDiskIcon() {
            // Theme-aware icon (no hard-coded colors)
            // Uses --fg and --info-rgb if available
            return `
<svg viewBox="0 0 48 48" width="42" height="42" aria-hidden="true" style="display:block">
  <defs>
    <linearGradient id="pqDiskG" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="rgba(var(--info-rgb, 0,140,255), 0.40)"/>
      <stop offset="1" stop-color="rgba(var(--info-rgb, 0,140,255), 0.14)"/>
    </linearGradient>
  </defs>

  <rect x="6" y="6" width="36" height="14" rx="3"
        fill="url(#pqDiskG)" stroke="rgba(0,0,0,0.22)" stroke-width="1"/>
  <rect x="6" y="28" width="36" height="14" rx="3"
        fill="url(#pqDiskG)" stroke="rgba(0,0,0,0.22)" stroke-width="1"/>

  <rect x="11" y="11" width="4" height="4" rx="1" fill="rgba(255,255,255,0.75)"/>
  <rect x="18" y="11" width="4" height="4" rx="1" fill="rgba(255,255,255,0.75)"/>

  <rect x="11" y="33" width="4" height="4" rx="1" fill="rgba(255,255,255,0.75)"/>
  <rect x="18" y="33" width="4" height="4" rx="1" fill="rgba(255,255,255,0.75)"/>
</svg>`;
        }

        function driveTileHtml(d) {
            const dev = String(d?.path || "");
            const parent = String(d?.parent_disk || "");
            const size = Number(d?.size_bytes || 0);
            const used = Number(d?.used_bytes || 0);

            const sub =
                parent && parent !== dev
                    ? parent
                    : "";

            const metaBits = [];
            if (Number.isFinite(size) && size > 0) metaBits.push(`size ${fmtBytes(size)}`);
            if (Number.isFinite(used) && used > 0) metaBits.push(`used ${fmtBytes(used)}`);

            const meta = metaBits.join(" • ");

            return `
<div class="pqDriveTile" data-dev="${esc(dev)}" title="${esc(dev)}">
  <div class="pqDriveIcon">${svgDiskIcon()}</div>
  <div style="min-width:0;">
    <div class="pqDriveDev">${esc(dev || "(device)")}</div>
    ${sub ? `<div class="pqDriveSub">${esc(sub)}</div>` : ``}
    ${meta ? `<div class="pqDriveMeta">${esc(meta)}</div>` : ``}
  </div>
</div>`;
        }
        async function openRemoveDriveModal(pool) {
            const ov = ensureRemoveDriveOverlay();

            const title = ov.querySelector("#poolRemoveDriveTitle");
            const closeBtn = ov.querySelector("#poolRemoveDriveCloseBtn");
            const body = ov.querySelector("#poolRemoveDriveBody");

            const mount = String(pool?.mount || "").trim();
            if (!mount) return;

            title.textContent = `Remove drive • ${mount}`;
            body.innerHTML = `<div class="v" style="opacity:.8;">Loading…</div>`;
            closeBtn.onclick = () => { ov.style.display = "none"; };
            ov.style.display = "flex";

            const disc = await loadPoolDiscoveryOnce(mount);
            if (!disc) {
                body.innerHTML = `<div class="v" style="opacity:.85;">Discovery failed.</div>`;
                return;
            }

            const bdevs = Array.isArray(disc?.btrfs?.devices) ? disc.btrfs.devices : [];
            const totalDevs = Number(disc?.btrfs?.total_devices) || bdevs.length || 0;

            if (totalDevs <= 1) {
                body.innerHTML = `<div class="v" style="opacity:.85;">Cannot remove a drive: pool has only ${totalDevs} device(s).</div>`;
                return;
            }

            body.innerHTML = `
<div class="card">
  <h3 style="margin:0 0 8px 0;">Remove drive</h3>

  <div class="k" style="margin-bottom:6px;">Drive in pool</div>
  <select id="poolRemoveDevSel" style="width:100%; padding:10px 12px; border-radius:14px; border:1px solid rgba(255,255,255,0.14); background:rgba(0,0,0,0.18); color:var(--fg);">
    ${bdevs.map((d) => {
                const mp = String(d?.path || "");
                const pd = String(d?.parent_disk || "");
                const size = d?.size_bytes ? fmtBytes(Number(d.size_bytes)) : "";
                const used = d?.used_bytes ? fmtBytes(Number(d.used_bytes)) : "";
                const label = [mp, pd && pd !== mp ? `(${pd})` : "", size ? `• ${size}` : "", used ? `• used ${used}` : ""]
                    .filter(Boolean)
                    .join(" ");
                return `<option value="${mp}">${label}</option>`;
            }).join("")}
  </select>

  <div style="margin-top:12px;">
    <label style="display:flex; gap:10px; align-items:center; padding:10px 12px; border-radius:14px; border:1px solid rgba(255,255,255,0.14); background:rgba(0,0,0,0.18);">
      <input id="poolRemoveForceChk" type="checkbox" style="transform:scale(1.1);">
      <span class="v" style="opacity:.9;">Force (allow removing the currently-used pool drive)</span>
    </label>
    <div id="poolRemoveForceWarn" class="v" style="opacity:.75; margin-top:6px;">
      Keep OFF unless you know exactly why you need it.
    </div>
  </div>

  <div class="card" style="margin-top:12px;">
    <h3 style="margin:0 0 8px 0;">Visual preview</h3>
    <div id="poolRemoveViz"></div>
  </div>

<div class="row" style="margin-top:12px; gap:10px;">
  <button class="btn secondary" id="poolRemovePreviewBtn" type="button">Preview</button>
  <button class="btn danger" id="poolRemoveApplyBtn" type="button" disabled>Apply</button>
</div>

<div class="v" style="opacity:.75; margin-top:8px;">
  Click Preview first to enable Apply.
</div>

<details class="card" style="margin-top:12px;">

  <details class="card" style="margin-top:12px;">
    <summary style="cursor:pointer; font-weight:900;">Advanced</summary>
    <pre id="poolRemoveDebug" style="margin-top:10px; max-height:45vh; overflow:auto;">(idle)</pre>
  </details>
</div>
`;

            const rmSel = document.getElementById("poolRemoveDevSel");
            const rmForceChk = document.getElementById("poolRemoveForceChk");
            const rmForceWarn = document.getElementById("poolRemoveForceWarn");
            const rmViz = document.getElementById("poolRemoveViz");
            const previewBtn = document.getElementById("poolRemovePreviewBtn");
            const applyBtn = document.getElementById("poolRemoveApplyBtn");
            const dbg = document.getElementById("poolRemoveDebug");

            let lastPlan = null;
            let lastPlanId = "";
            applyBtn.disabled = true;

            function updateViz() {
                const removeDev = String(rmSel?.value || "");
                rmViz.innerHTML = svgRemovePreview({
                    poolLabel: mount ? `Storage pool: ${mount}` : "",
                    removeDevLabel: removeDev
                });
            }

            updateViz();

            rmSel?.addEventListener("change", () => {
                updateViz();
                lastPlan = null;
                lastPlanId = "";
                applyBtn.disabled = true;
            });

            rmForceChk?.addEventListener("change", () => {
                rmForceWarn.textContent = rmForceChk.checked
                    ? "WARNING: force enabled — you may be removing the drive currently hosting the pool."
                    : "Keep OFF unless you know exactly why you need it.";
                lastPlan = null;
                lastPlanId = "";
                applyBtn.disabled = true;
            });

            previewBtn.onclick = async () => {
                const remove_device = String(rmSel?.value || "").trim();
                if (!remove_device) return;

                const bodyReq = {
                    mount,
                    remove_device,
                    force: !!rmForceChk?.checked
                };

                dbg.textContent = JSON.stringify({ request: bodyReq }, null, 2);

                const { r, j, txt } = await postJson("/api/v4/raid/plan/remove-device", bodyReq);

                dbg.textContent = JSON.stringify({
                    http: r.status,
                    response: j ?? txt,
                    request: bodyReq
                }, null, 2);

                if (!r.ok || !j || j.ok !== true || !j.plan || !j.plan.plan_id) {
                    showToast("err", `Preview failed: ${prettyError(j, r, txt)}`, 5200);
                    applyBtn.disabled = true;
                    lastPlan = null;
                    lastPlanId = "";
                    return;
                }

                lastPlan = j.plan;
                lastPlanId = String(j.plan.plan_id || "");
                applyBtn.disabled = !lastPlanId;
                showToast("ok", "Preview ready ✓", 1800);
            };

            applyBtn.onclick = async () => {
                if (!lastPlan || !lastPlanId) {
                    showToast("warn", "Preview first. Click Preview before Apply.", 2800);
                    return;
                }

                const remove_device = String(rmSel?.value || "").trim();
                ov.style.display = "none";

                const ok = await confirmExecute(lastPlan, {
                    kind: "remove",
                    mount,
                    remove_device,
                    force: !!rmForceChk?.checked
                });

                if (!ok) {
                    ov.style.display = "flex";
                    showToast("info", "Apply cancelled.", 1800);
                    return;
                }

                const bodyReq = {
                    mount,
                    remove_device,
                    force: !!rmForceChk?.checked,
                    plan_id: lastPlanId,
                    dry_run: false,
                    confirm: true
                };

                const { r, j, txt } = await postJson("/api/v4/raid/execute/remove-device", bodyReq);

                dbg.textContent = JSON.stringify({
                    http: r.status,
                    response: j ?? txt,
                    request: bodyReq
                }, null, 2);

                if (!r.ok || !j || j.ok !== true) {
                    showToast("err", `Apply failed: ${prettyError(j, r, txt)}`, 5200);
                    ov.style.display = "flex";
                    return;
                }

                const pid = String(j?.plan_id || j?.plan?.plan_id || lastPlanId || "");
                if (pid) startExecPolling(pid);

                showToast("ok", "Drive removal started ✓", 2200);
            };
        }
        async function loadPoolDiscoveryOnce(mount) {
            const m = String(mount || "").trim();
            if (!m) return null;
            try {
                const q = await fetchJson(`/api/v4/raid/discovery?mount=${encodeURIComponent(m)}`);
                if (!q.r || q.r.status !== 200) return null;
                if (!q.j || q.j.ok !== true) return null;
                return q.j;
            } catch (_) {
                return null;
            }
        }

        async function renderSelectedPoolGraphics() {
            const host = document.getElementById("poolGraphics");
            if (!host) return;

            const mnt = String(g_selectedMount || "").trim();
            const p = pools.find(x => String(x?.mount || "") === mnt);

            if (!p || !mnt) {
                host.innerHTML = `<div class="v" style="opacity:.8;">Select a pool to see its member drives.</div>`;
                return;
            }

            host.innerHTML = `<div class="v" style="opacity:.8;">Loading member drives…</div>`;

            const disc = await loadPoolDiscoveryOnce(mnt);
            const bdevs = Array.isArray(disc?.btrfs?.devices) ? disc.btrfs.devices : [];

            if (!bdevs.length) {
                host.innerHTML = `
<div class="v" style="opacity:.85;">No member devices found from discovery.</div>
<div class="v" style="opacity:.7; margin-top:6px;">(Pool may be non-btrfs or discovery schema differs.)</div>`;
                return;
            }

            // Optional: show pool “mount points” as the mount itself + member /dev paths (what user expects visually)
            host.innerHTML = `
<div class="row" style="align-items:center; justify-content:space-between; gap:10px;">
  <div style="min-width:0;">
    <div style="font-weight:950;">${esc(poolDisplayName(p))}</div>
    <div class="v" style="opacity:.8; margin-top:2px;">${esc(mnt)}</div>
  </div>
  <div style="display:flex; gap:8px; flex-wrap:wrap; justify-content:flex-end;">
    <span class="pqPill">${esc(`drives: ${bdevs.length}`)}</span>
    ${p?.fstype ? `<span class="pqPill">${esc(`fs: ${String(p.fstype)}`)}</span>` : ``}
  </div>
</div>

<div class="pqDriveGrid" style="margin-top:12px;">
  ${bdevs.map(driveTileHtml).join("")}
</div>

<div class="v" style="opacity:.70; margin-top:10px;">
Tip: these are the Btrfs member devices that form this pool.
</div>
`;

            // (Optional) click-to-copy /dev/… to clipboard
            host.querySelectorAll(".pqDriveTile").forEach((tile) => {
                tile.addEventListener("click", async () => {
                    const dev = tile.getAttribute("data-dev") || "";
                    if (!dev) return;
                    try {
                        await navigator.clipboard.writeText(dev);
                        showToast("ok", `Copied: ${dev}`, 1400);
                    } catch (_) {
                        showToast("info", dev, 1600);
                    }
                });
            });
        }
        function driveTileSvgHtml(d) {
            const dev  = String(d?.path || "");
            const size = Number(d?.size_bytes || 0);
            const used = Number(d?.used_bytes || 0);

            const metaBits = [];
            if (size > 0) metaBits.push(`size ${fmtBytes(size)}`);
            if (used > 0) metaBits.push(`used ${fmtBytes(used)}`);

            // short label inside SVG so it stays tidy
            const short = dev.replace("/dev/", "");

            return `
<div class="pqDriveSvgTile" data-dev="${esc(dev)}" title="${esc(dev)}">
  <div class="pqDriveSvgWrap">
    ${svgSingleDrive({ label: short })}
  </div>
  <div class="pqDriveSvgDev">${esc(dev)}</div>
  ${metaBits.length ? `<div class="pqDriveSvgMeta">${esc(metaBits.join(" • "))}</div>` : ``}
</div>`;
        }
        const tieringCardHtml = (() => {
            if (!tier || !tier.ok || !tier.data) {
                return `
<div class="card" style="margin-top:12px;">
  <div style="font-weight:950; margin-bottom:8px;">Tiering</div>
  <div class="v" style="opacity:.8;">Tiering status unavailable.</div>
</div>`;
            }

            const d = tier.data || {};
            const counts = d.counts || {};
            const bytes = d.bytes || {};
            const worker = d.worker || {};

            return `
<div class="card" style="margin-top:12px;">
  <div class="row" style="align-items:flex-start; justify-content:space-between; gap:12px;">
    <div style="min-width:260px;">
      <div style="font-weight:950;">Tiering</div>
      <div class="v" style="opacity:.8; margin-top:2px;">
        Landing pool: ${esc(String(d.landing_pool_id || "-"))}
      </div>
      <div style="margin-top:8px; display:flex; gap:8px; flex-wrap:wrap;">
        ${tierPill(`enabled: ${yesNo(!!d.tiering_enabled)}`, !!d.tiering_enabled ? "pqTierOk" : "pqTierWarn")}
        ${tierPill(`worker: ${yesNo(!!worker.enabled)}`, !!worker.enabled ? "pqTierOk" : "pqTierWarn")}
        ${tierPill(`interval: ${Number(worker.interval_sec || 0)}s`, "pqTierNeutral")}
        ${tierPill(`min age: ${Number(worker.min_age_sec || 0)}s`, "pqTierNeutral")}
        ${tierPill(`max/pass: ${Number(worker.max_candidates_per_pass || 0)}`, "pqTierNeutral")}
      </div>
    </div>

    <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap:10px; flex:1 1 auto;">
      <div id="tierLandingCard" class="card pqTierStat ${tierToneClass("landing", counts.landing_files)}">
        <div class="k">Landing</div>
        <div class="pqTierStatValue">${Number(counts.landing_files || 0)} files</div>
        <div id="tierLandingBytes" class="v pqTierStatSub">${fmtBytes(Number(bytes.landing_bytes || 0))}</div>
      </div>

      <div id="tierMigratingCard" class="card pqTierStat ${tierToneClass("migrating", counts.migrating_files)}">
        <div class="k">Migrating</div>
        <div id="tierMigratingFiles" class="pqTierStatValue">${Number(counts.migrating_files || 0)} files</div>
        <div id="tierMigratingBytes" class="v pqTierStatSub">${fmtBytes(Number(bytes.migrating_bytes || 0))}</div>
        <div id="tierMigratingRate" class="v pqTierRate"></div>
      </div>

      <div id="tierCapacityCard" class="card pqTierStat ${tierToneClass("capacity", counts.capacity_files)}">
        <div class="k">Capacity</div>
        <div class="pqTierStatValue">${Number(counts.capacity_files || 0)} files</div>
        <div id="tierCapacityBytes" class="v pqTierStatSub">${fmtBytes(Number(bytes.capacity_bytes || 0))}</div>
      </div>

      <div class="card pqTierStat pqTierNeutral">
        <div class="k">Total</div>
        <div id="tierTotalFiles" class="pqTierStatValue">${Number(counts.total_files || 0)} files</div>
        <div id="tierTotalBytes" class="v pqTierStatSub">${fmtBytes(Number(bytes.total_bytes || 0))}</div>
      </div>
    </div>
  </div>

  <div class="pqTierFlowWrap">
    <div id="tierFlowBar" class="pqTierFlowBar">
      <div id="tierFlowLanding" class="pqTierFlowLanding" style="width:${pctOf(bytes.landing_bytes, bytes.total_bytes)}%;"></div>
      <div id="tierFlowCapacity" class="pqTierFlowCapacity" style="width:${pctOf(bytes.capacity_bytes, bytes.total_bytes)}%;"></div>
    </div>

    <div class="pqTierFlowMeta">
      <div id="tierFlowLeft">Landing ${fmtBytes(Number(bytes.landing_bytes || 0))}</div>
      <div id="tierFlowRight">Capacity ${fmtBytes(Number(bytes.capacity_bytes || 0))}</div>
    </div>

    <div id="tierFlowStatus" class="pqTierFlowStatus">
      ${Number(bytes.landing_bytes || 0) > 0
                ? `Waiting in landing: ${fmtBytes(Number(bytes.landing_bytes || 0))}`
                : `No landing backlog`}
    </div>
  </div>
</div>`;
        })();

        const rows = pools.map((p) => {
            const mount = String(p?.mount || "");
            const label = poolDisplayName(p);
            const fstype = String(p?.fstype || p?.fs || "").trim();
            const uuid = String(p?.uuid || "").trim();
            const editable = !!p?.is_editable_pool;
            const statusHtml = fmtPoolHealth(p);
            const pendingHtml = poolPendingState(p);

            const hostId = "poolMembers__" + btoa(unescape(encodeURIComponent(mount))).replace(/[^a-z0-9]/gi, "_");
            const slots = Array.isArray(p?.slots) ? p.slots : [];

            const slotHtml = slots.length
                ? slots.map((slot) => slotRowHtml(slot, editable)).join("")
                : `<div class="v" style="opacity:.75;">No slots defined.</div>`;

            return `
<div class="card pqPoolCard ${editable ? "" : "pqPoolReadonly"}">
  <div class="pqPoolHeader">
    <div style="min-width:260px; flex:1 1 auto;">
      <div class="pqPoolTitle">${esc(label)}</div>
      <div class="pqPoolMount">${esc(mount)}</div>

<div class="pqPoolMetaPills">
  ${fstype ? pill(`fs: ${fstype}`) : ""}
  ${pill(`mode: ${fmtPoolMode(p)}`, modePillOpts(p))}
  ${pill(`slots: ${String(p?.slot_count ?? slots.length ?? 0)}`)}
  ${uuid ? pill(`uuid: ${uuid.slice(0, 12)}…`) : ""}
  ${statusHtml}
  ${pendingHtml}
  ${editable ? `<span class="badge ok">editable</span>` : `<span class="badge info">system volume</span>`}
</div>
    </div>

    <div class="pqPoolActions">
      ${editable ? `<button class="btn secondary" type="button" data-pool-action="drives" data-mount="${esc(mount)}">Manage drives</button>` : ``}
      ${editable ? `<button class="btn secondary" type="button" data-pool-action="remove" data-mount="${esc(mount)}">Remove drive</button>` : ``}
      ${editable ? `<button class="btn secondary" type="button" data-pool-action="rename" data-mount="${esc(mount)}">Rename</button>` : ``}
      ${editable ? `<button class="btn secondary" type="button" data-pool-action="convert" data-mount="${esc(mount)}">Convert RAID</button>` : ``}
      ${editable ? `<button class="btn danger" type="button" data-pool-action="destroy" data-mount="${esc(mount)}">Destroy</button>` : ``}
    </div>
  </div>

<div class="pqPoolSection">
  <div class="pqPoolSectionTitle">Slots</div>
  <div class="pqSlotList">${slotHtml}</div>

  ${
                editable ? `
<div class="pqSlotActionRow">
  <button class="btn secondary" type="button" data-pool-action="edit-slots" data-mount="${esc(mount)}">Edit slots</button>
  <button class="btn secondary" type="button" data-pool-action="add-slot" data-mount="${esc(mount)}">Add slot</button>
  <button class="btn secondary" type="button" data-pool-action="remove-slot" data-mount="${esc(mount)}">Remove empty slot</button>
  <button class="btn" type="button" data-pool-action="apply-layout" data-mount="${esc(mount)}">Apply layout</button>
</div>
      <div class="pqPoolNote">
  ${pendingHtml ? "Saved slot layout differs from current pool membership. Use Apply layout to make Btrfs match the saved layout." : "Saved slot layout matches the current pool membership."}
</div>
    ` : `
      <div class="pqPoolNote">This is a detected Btrfs system volume. It is shown for visibility, not managed as a normal pool.</div>
    `
            }
</div>

    <div class="pqPoolSection">
      <div class="pqPoolSectionTitle">Summary</div>
      ${poolSummaryHtml(p)}

      <div style="margin-top:12px;">
        <div class="pqPoolSectionTitle" style="margin-bottom:6px;">Member drives</div>
        <div id="${hostId}" class="pqPoolMembersHost">
          <span class="v" style="opacity:.75;">(loading…)</span>
        </div>
      </div>
    </div>
  </div>
</div>`;
        }).join("");

        poolsOut.innerHTML = `
<style>
.pqPill{
  border:1px solid var(--border2);
  background: var(--panel);
}
  .pqDriveGrid{
    display:grid;
    grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
    gap:10px;
  }
  .pqDriveTile{
    display:flex;
    gap:10px;
    align-items:center;
    padding:10px 12px;
    border-radius:16px;
    border:1px solid rgba(255,255,255,0.14);
    background: rgba(0,0,0,0.10);
    cursor:pointer;
    user-select:none;
    transition: transform .06s ease, filter .06s ease;
  }
  .pqDriveTile:hover{ filter: brightness(1.06); }
  .pqDriveTile:active{ transform: translateY(1px); }

  .pqDriveIcon{
    flex:0 0 auto;
    width:46px; height:46px;
    display:flex; align-items:center; justify-content:center;
    border-radius:14px;
    border:1px solid rgba(0,0,0,0.10);
    background: rgba(255,255,255,0.06);
  }
  .pqDriveDev{
    font-family: var(--mono);
    font-weight:900;
    font-size:13px;
    white-space:nowrap;
    overflow:hidden;
    text-overflow:ellipsis;
  }
  .pqDriveSub{
    font-family: var(--mono);
    font-size:12px;
    opacity:.72;
    white-space:nowrap;
    overflow:hidden;
    text-overflow:ellipsis;
    margin-top:2px;
  }
  .pqDriveMeta{
    font-size:12px;
    opacity:.78;
    margin-top:4px;
  }
.pqDriveSvgGrid{
  display:grid;
  grid-template-columns: repeat(auto-fill, 210px);
  gap:10px;
  justify-content:flex-start;
  align-items:start;              /* important */
}
.pqDriveSvgTile{ height: auto; }
.pqPoolMembersHost{ min-height: 0 !important; }
/* Compact tile */
.pqDriveSvgTile{
  width:210px;
  padding:8px 10px;
  background: var(--panel);
  border:1px solid var(--border2);
  border-radius:16px;
}
.pqDriveSvgTile:hover{ filter: brightness(1.06); }
.pqDriveSvgTile:active{ transform: translateY(1px); }
/* Keep the SVG small so it doesn't create vertical bulk */
.pqDriveSvgWrap{
  width:150px;
  height:58px;                    /* important */
  border-radius: 14px;
  background: var(--panel2);
  border: 1px solid var(--border2);
  padding: 6px;
}
.pqDriveSvgWrap svg{
  width:150px;
  height:58px;                    /* important */
  display:block;
}

/* Text tighter */
.pqDriveSvgDev{
  margin-top:6px;
  font-family: var(--mono);
  font-weight:900;
  font-size:12px;
  white-space:nowrap;
  overflow:hidden;
  text-overflow:ellipsis;
}
.pqDriveSvgMeta{
  margin-top:2px;
  font-size:12px;
  opacity:.78;
  white-space:nowrap;
  overflow:hidden;
  text-overflow:ellipsis;
}
/* Member drives section should not create a tall empty area */
.pqPoolMembersHost{
  display:block;
  margin:0;
  min-height:0 !important;
  height:auto !important;
  padding: 8px;
  border-radius: 16px;
  background: var(--panel2);
  border: 1px solid var(--border2);
}

.pqTierRate{
  font-size:12px;
  opacity:.8;
  margin-top:2px;
}
.pqTierFlowWrap{
  margin-top:10px;
}

.pqTierFlowBar{
  position:relative;
  height:14px;
  border-radius:999px;
  overflow:hidden;
  border:1px solid var(--border2);
  background: var(--panel2);
}

.pqTierFlowLanding,
.pqTierFlowCapacity{
  position:absolute;
  top:0;
  bottom:0;
}

.pqTierFlowLanding{
  left:0;
  background: rgba(var(--info-rgb, 0,140,255), 0.40);
}

.pqTierFlowCapacity{
  right:0;
  background: rgba(var(--ok-rgb, 0,180,120), 0.35);
}

.pqTierFlowActive{
  box-shadow: inset 0 0 0 1px rgba(255,180,0,0.28), 0 0 0 1px rgba(255,180,0,0.10);
}

.pqTierFlowActive::after{
  content:"";
  position:absolute;
  inset:0;
  background:
    repeating-linear-gradient(
      -45deg,
      rgba(255,180,0,0.18) 0 10px,
      rgba(255,180,0,0.05) 10px 20px
    );
  animation: pqTierFlowStripe 1.1s linear infinite;
  pointer-events:none;
}

@keyframes pqTierFlowStripe {
  from { transform: translateX(0); }
  to   { transform: translateX(20px); }
}

.pqTierFlowMeta{
  display:flex;
  justify-content:space-between;
  gap:12px;
  margin-top:6px;
  font-size:12px;
  opacity:.85;
}

.pqTierFlowStatus{
  margin-top:4px;
  font-size:12px;
  opacity:.9;
}
.pqTierNeutral{
  opacity:.95;
}

.pqPoolCard{
  margin-top:10px;
}

.pqPoolHeader{
  display:flex;
  align-items:flex-start;
  justify-content:space-between;
  gap:12px;
  flex-wrap:wrap;
}

.pqPoolTitle{
  font-weight:950;
  font-size:15px;
}

.pqPoolMount{
  opacity:.8;
  margin-top:2px;
  font-family:var(--mono);
  font-size:12px;
  word-break:break-all;
}

.pqPoolMetaPills{
  margin-top:8px;
  display:flex;
  gap:8px;
  flex-wrap:wrap;
}

.pqPoolBody{
  display:grid;
  grid-template-columns: minmax(260px, 420px) 1fr;
  gap:12px;
  margin-top:12px;
}

@media (max-width: 980px){
  .pqPoolBody{
    grid-template-columns: 1fr;
  }
}

.pqPoolSection{
  border:1px solid var(--border2);
  background:var(--panel2);
  border-radius:16px;
  padding:10px;
}

.pqPoolSectionTitle{
  font-weight:900;
  margin-bottom:8px;
}

.pqSlotList{
  display:flex;
  flex-direction:column;
  gap:8px;
}

.pqSlotRow{
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:10px;
  border:1px solid var(--border2);
  background:var(--panel);
  border-radius:14px;
  padding:10px 12px;
}

.pqSlotLeft{
  min-width:0;
}

.pqSlotTitle{
  font-weight:900;
  font-size:12px;
  opacity:.78;
}

.pqSlotDev{
  font-family:var(--mono);
  font-size:12px;
  margin-top:2px;
  word-break:break-all;
}

.pqPoolSummaryGrid{
  display:grid;
  grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
  gap:8px;
}

.pqPoolStat{
  border:1px solid var(--border2);
  background:var(--panel);
  border-radius:14px;
  padding:10px;
}

.pqPoolStatValue{
  font-weight:900;
  margin-top:4px;
}

.pqPoolActions{
  display:flex;
  flex-direction:column;
  gap:8px;
  flex:0 0 auto;
}

.pqPoolNote{
  margin-top:10px;
  font-size:12px;
  opacity:.78;
}

.pqPoolReadonly{
  border-color: rgba(var(--info-rgb,0,140,255),0.28) !important;
}

.pqSlotRowEditable{
  border-style:dashed;
}

.pqSlotRowEditable:hover{
  filter: brightness(1.04);
}

.pqSlotActionRow{
  display:flex;
  gap:8px;
  flex-wrap:wrap;
  margin-top:10px;
}

.pqSlotRowEditable{
  border-style:dashed;
}

.pqSlotRowEditable:hover{
  filter: brightness(1.04);
}

.pqSlotActionRow{
  display:flex;
  gap:8px;
  flex-wrap:wrap;
  margin-top:10px;
}

.pqTierInfo{
  border:1px solid rgba(var(--info-rgb,0,140,255),0.55) !important;
  background:rgba(var(--info-rgb,0,140,255),0.18) !important;
}

.pqTierWarn{
  border:1px solid rgba(255,180,0,0.65) !important;
  background:rgba(255,180,0,0.20) !important;
}

.pqTierOk{
  border:1px solid rgba(0,180,120,0.65) !important;
  background:rgba(0,180,120,0.20) !important;
}

.pqTierStat{
  margin:0;
}

.pqTierStatValue{
  font-weight:900;
  margin-top:4px;
}

.pqTierStatSub{
  opacity:.8;
  margin-top:2px;
}

html[data-theme="win_classic"] .pqTierInfo{
  border: 1px solid #2b579a !important;
  background: #dbe9ff !important;
}

html[data-theme="win_classic"] .pqTierWarn{
  border: 1px solid #a66b00 !important;
  background: #fff1cc !important;
}

html[data-theme="win_classic"] .pqTierOk{
  border: 1px solid #2f7d32 !important;
  background: #dff3df !important;
}

html[data-theme="win_classic"] .pqTierInfo .pqTierStatValue{
  color: #1f4f99 !important;
}

html[data-theme="win_classic"] .pqTierWarn .pqTierStatValue{
  color: #8a5a00 !important;
}

html[data-theme="win_classic"] .pqTierOk .pqTierStatValue{
  color: #256628 !important;
}
/* Make grid compact (no vertical expansion) */
.pqDriveSvgGrid{
  align-content:start;
}
/* If your global .card has min-height, kill it for pool cards in Pools tab */
#poolsOut .card{
  min-height:0 !important;
  height:auto !important;
}
</style>

<div class="row" style="align-items:center; justify-content:space-between; gap:10px;">
  <div style="font-weight:950;">Storage pools</div>
  <button class="btn" id="poolCreateBtn" type="button">Create new pool</button>
</div>

${tieringCardHtml}

${rows}

<details class="card" style="margin-top:12px;">
  <summary style="cursor:pointer; font-weight:900;">Raw pools JSON (debug)</summary>
  <pre style="margin-top:10px; max-height:45vh; overflow:auto;">${esc(JSON.stringify(pools, null, 2))}</pre>
</details>
`;

        if (g_tieringTimer) clearInterval(g_tieringTimer);
        g_tieringTimer = setInterval(refreshTieringCard, 2000);
        refreshTieringCard().catch(() => {});

        // Wire actions (scaffold for now)
        const createBtn = document.getElementById("poolCreateBtn");
        function ensureCreatePoolOverlay() {
            let ov = document.getElementById("poolCreateOverlay");
            if (ov) return ov;

            ov = document.createElement("div");
            ov.id = "poolCreateOverlay";
            ov.style.position = "fixed";
            ov.style.inset = "0";
            ov.style.display = "none";
            ov.style.alignItems = "center";
            ov.style.justifyContent = "center";
            ov.style.background = isDarkThemeNow() ? "rgba(0,0,0,0.55)" : "rgba(0,0,0,0.25)";
            ov.style.zIndex = "9999";

            ov.innerHTML = `
<div style="
  width:min(980px, 96vw);
  max-height:90vh;
  overflow:auto;
  border-radius:18px;
  border:1px solid rgba(255,255,255,0.14);
  background: var(--panel, rgba(0,0,0,0.35));
  color: var(--fg);
  padding:14px;
  box-shadow: 0 20px 60px rgba(0,0,0,0.45);
">
  <div style="display:flex; align-items:center; justify-content:space-between; gap:10px; margin-bottom:10px;">
    <div style="font-weight:950;">Create storage pool</div>
    <button id="poolCreateCloseBtn" class="btn secondary" type="button">Close</button>
  </div>

  <div class="card" style="margin-top:10px;">
    <div class="formGrid3">
      <div class="formField">
        <div class="k">pool_id</div>
        <input id="poolIdInp" type="text" placeholder="raidtest">
        <div class="formHelp">Allowed: a-z 0-9 _ - (max 32)</div>
      </div>

      <div class="formField">
        <div class="k">Display name</div>
        <input id="poolDisplayNameInp" type="text" placeholder="Raid test">
        <div class="formHelp">Optional user-facing name</div>
      </div>

      <div class="formField">
        <div class="k">Mode</div>
        <select id="poolModeSel">
          <option value="single">single</option>
          <option value="raid1">raid1</option>
        </select>
        <div class="formHelp" id="poolModeHint"></div>
      </div>
    </div>

    <div class="row" style="gap:10px; margin-top:12px; align-items:flex-end; flex-wrap:wrap;">
      <div class="formField" style="min-width:180px; max-width:220px;">
        <div class="k">Slot count</div>
        <input id="poolSlotCountInp" type="number" min="1" max="16" step="1" value="1">
        <div class="formHelp">How many drive slots this pool should show</div>
      </div>

      <button id="poolSlotsApplyBtn" class="btn secondary" type="button">Update slots</button>
      <button id="poolDevsRefreshBtn" class="btn secondary" type="button">Refresh devices</button>

      <label style="display:flex; gap:10px; align-items:center; padding:10px 12px; border-radius:14px; border:1px solid rgba(255,255,255,0.14); background:rgba(0,0,0,0.18);">
        <input id="poolForceChk" type="checkbox" style="transform:scale(1.1);">
        <span class="v" style="opacity:.9;">Force wipe (destructive)</span>
      </label>

      <div style="flex:1 1 auto;"></div>

      <button id="poolCreateDoBtn" class="btn danger" type="button">Create</button>
    </div>

    <div class="card" style="margin-top:12px;">
      <h3 style="margin:0 0 8px 0;">Slots</h3>
      <div id="poolSlotsHost"></div>
      <div class="v" id="poolSlotHint" style="opacity:.75; margin-top:8px;"></div>
    </div>

    <details class="card" style="margin-top:12px;">
      <summary style="cursor:pointer; font-weight:900;">Advanced</summary>
      <pre id="poolCreateDebug" style="margin-top:10px; max-height:45vh; overflow:auto;">(idle)</pre>
    </details>
  </div>
</div>
`;
            document.body.appendChild(ov);
            return ov;
        }
        function ensurePoolDrivesOverlay() {
            let ov = document.getElementById("poolDrivesOverlay");
            if (ov) return ov;

            ov = document.createElement("div");
            ov.id = "poolDrivesOverlay";
            ov.style.position = "fixed";
            ov.style.inset = "0";
            ov.style.display = "none";
            ov.style.alignItems = "center";
            ov.style.justifyContent = "center";
            ov.style.background = isDarkThemeNow() ? "rgba(0,0,0,0.55)" : "rgba(0,0,0,0.25)";
            ov.style.zIndex = "9999";

            ov.innerHTML = `
<div style="
  width:min(980px, 96vw);
  max-height:90vh;
  overflow:auto;
  border-radius:18px;
  border:1px solid rgba(255,255,255,0.14);
  background: var(--panel, rgba(0,0,0,0.35));
  color: var(--fg);
  padding:14px;
  box-shadow: 0 20px 60px rgba(0,0,0,0.45);
">
  <div style="display:flex; align-items:center; justify-content:space-between; gap:10px; margin-bottom:10px;">
    <div id="poolDrivesTitle" style="font-weight:950;">Pool drives</div>
    <button id="poolDrivesCloseBtn" class="btn secondary" type="button">Close</button>
  </div>

  <div id="poolDrivesBody"></div>
</div>`;
            document.body.appendChild(ov);
            return ov;
        }
        function ensureRemoveDriveOverlay() {
            let ov = document.getElementById("poolRemoveDriveOverlay");
            if (ov) return ov;

            ov = document.createElement("div");
            ov.id = "poolRemoveDriveOverlay";
            ov.style.position = "fixed";
            ov.style.inset = "0";
            ov.style.display = "none";
            ov.style.alignItems = "center";
            ov.style.justifyContent = "center";
            ov.style.background = isDarkThemeNow() ? "rgba(0,0,0,0.55)" : "rgba(0,0,0,0.25)";
            ov.style.zIndex = "9999";

            ov.innerHTML = `
<div style="
  width:min(860px, 94vw);
  max-height:90vh;
  overflow:auto;
  border-radius:18px;
  border:1px solid rgba(255,255,255,0.14);
  background: var(--panel, rgba(0,0,0,0.35));
  color: var(--fg);
  padding:14px;
  box-shadow: 0 20px 60px rgba(0,0,0,0.45);
">
  <div style="display:flex; align-items:center; justify-content:space-between; gap:10px; margin-bottom:10px;">
    <div id="poolRemoveDriveTitle" style="font-weight:950;">Remove drive</div>
    <button id="poolRemoveDriveCloseBtn" class="btn secondary" type="button">Close</button>
  </div>

  <div id="poolRemoveDriveBody"></div>
</div>`;
            document.body.appendChild(ov);
            return ov;
        }
        async function openPoolDrivesModal(mount, opts) {
            const mnt = String(mount || "").trim();
            if (!mnt) return;

            const ov = ensurePoolDrivesOverlay();
            const title = ov.querySelector("#poolDrivesTitle");
            const closeBtn = ov.querySelector("#poolDrivesCloseBtn");
            const body = ov.querySelector("#poolDrivesBody");

            if (title) title.textContent = `Drives • ${mnt}`;
            const o = (opts && typeof opts === "object") ? opts : {};
            const focus = String(o.focus || "drives"); // "drives" | "remove"

            if (title) title.textContent = (focus === "remove") ? `Remove drive • ${mnt}` : `Drives • ${mnt}`;
            if (body) body.innerHTML = `<div class="v" style="opacity:.8;">Loading…</div>`;

            closeBtn.onclick = () => { ov.style.display = "none"; };

            ov.style.display = "flex";

            // load discovery once and reuse your existing UI
            const disc = await loadPoolDiscoveryOnce(mnt);
            if (!disc) {
                body.innerHTML = `<div class="v" style="opacity:.85;">Discovery failed.</div>`;
                return;
            }

            // IMPORTANT: set the current selection so your hard guard matches
            g_selectedMount = mnt;
            saveSelectedMount(mnt);
            renderPoolSelectorTop();

            // render add/remove UI into modal body
            renderActions(disc, mnt, body, { focus });
            // If opened from "Remove drive" button, jump to the Remove section.
            if (focus === "remove") {
                // renderActions uses fixed ids like rmBlock, rmDevSel; wait one tick.
                setTimeout(() => {
                    const rm = document.getElementById("rmBlock");
                    const sel = document.getElementById("rmDevSel");
                    if (rm && rm.scrollIntoView) {
                        rm.scrollIntoView({ block: "start", behavior: "smooth" });
                    }
                    if (sel && sel.focus) {
                        try { sel.focus(); } catch (_) {}
                    }
                }, 0);
            }
        }



        // ------------------------------------------------------------
        // Destroy Pool UI
        // ------------------------------------------------------------

        // ---- Destroy pool modal + execute ----
        function ensureDestroyPoolOverlay() {
            let ov = document.getElementById("poolDestroyOverlay");
            if (ov) return ov;

            ov = document.createElement("div");
            ov.id = "poolDestroyOverlay";
            ov.style.position = "fixed";
            ov.style.inset = "0";
            ov.style.display = "none";
            ov.style.alignItems = "center";
            ov.style.justifyContent = "center";
            ov.style.background = isDarkThemeNow() ? "rgba(0,0,0,0.55)" : "rgba(0,0,0,0.25)";
            ov.style.zIndex = "9999";

            ov.innerHTML = `
<div style="
  width:min(860px, 94vw);
  max-height:90vh;
  overflow:auto;
  border-radius:18px;
  border:1px solid rgba(255,255,255,0.14);
  background: var(--panel, rgba(0,0,0,0.35));
  color: var(--fg);
  padding:14px;
  box-shadow: 0 20px 60px rgba(0,0,0,0.45);
">
  <div style="display:flex; align-items:center; justify-content:space-between; gap:10px; margin-bottom:10px;">
    <div style="font-weight:950;">Destroy storage pool</div>
    <button id="poolDestroyCloseBtn" class="btn secondary" type="button">Close</button>
  </div>

  <div class="card" style="margin-top:10px;">
    <div class="v" style="opacity:.9; white-space:pre-line;">
This will unmount the pool and remove it from PQ-NAS pools config.
Optionally it can wipe member disks (VERY destructive).
    </div>

    <div style="margin-top:12px;">
      <div class="k" style="margin-bottom:6px;">Mount</div>
      <input id="poolDestroyMountInp" type="text" readonly
             style="width:100%; padding:10px 12px; border-radius:14px; border:1px solid rgba(255,255,255,0.14);
                    background:rgba(0,0,0,0.18); color:var(--fg); font-family:var(--mono);">
    </div>

    <div style="margin-top:12px;">
      <label style="display:flex; gap:10px; align-items:center; padding:10px 12px; border-radius:14px;
                    border:1px solid rgba(255,255,255,0.14); background:rgba(0,0,0,0.18);">
        <input id="poolDestroyWipeChk" type="checkbox" style="transform:scale(1.1);">
        <span class="v" style="opacity:.95;">Wipe member disks (destructive)</span>
      </label>
      <div class="v" style="opacity:.75; margin-top:6px;">
        When ON, PQ-NAS will wipefs/sgdisk each member device after unmount.
      </div>
    </div>

    <div style="margin-top:12px;">
      <div class="k" style="margin-bottom:6px;">Type DESTROY to confirm</div>
      <input id="poolDestroyTypeInp" type="text" placeholder="DESTROY"
             style="width:100%; padding:10px 12px; border-radius:14px; border:1px solid rgba(255,255,255,0.14);
                    background:rgba(0,0,0,0.18); color:var(--fg); font-family:var(--mono);">
    </div>

    <div style="display:flex; gap:10px; justify-content:flex-end; margin-top:14px;">
      <button id="poolDestroyCancelBtn" class="btn secondary" type="button">Cancel</button>
      <button id="poolDestroyDoBtn" class="btn danger" type="button" disabled>Destroy</button>
    </div>

    <details class="card" style="margin-top:12px;">
      <summary style="cursor:pointer; font-weight:900;">Advanced</summary>
      <pre id="poolDestroyDebug" style="margin-top:10px; max-height:45vh; overflow:auto;">(idle)</pre>
    </details>
  </div>
</div>
`;
            document.body.appendChild(ov);
            return ov;
        }

        async function openDestroyPoolModal(mount) {
            const ov = ensureDestroyPoolOverlay();

            const closeBtn = ov.querySelector("#poolDestroyCloseBtn");
            const cancelBtn = ov.querySelector("#poolDestroyCancelBtn");
            const doBtn = ov.querySelector("#poolDestroyDoBtn");
            const mountInp = ov.querySelector("#poolDestroyMountInp");
            const wipeChk = ov.querySelector("#poolDestroyWipeChk");
            const typeInp = ov.querySelector("#poolDestroyTypeInp");
            const dbg = ov.querySelector("#poolDestroyDebug");

            mountInp.value = String(mount || "");
            wipeChk.checked = false;
            typeInp.value = "";
            dbg.textContent = "(idle)";

            const refreshDoEnabled = () => {
                const okType = String(typeInp.value || "").trim().toUpperCase() === "DESTROY";
                doBtn.disabled = !okType;
            };
            typeInp.oninput = refreshDoEnabled;
            refreshDoEnabled();

            const close = () => { ov.style.display = "none"; };

            closeBtn.onclick = close;
            cancelBtn.onclick = close;

            doBtn.onclick = async () => {
                // 🔒 Hard guard: only allow pools under /srv/pqnas/pools
                const mnt = String(mountInp.value || "").trim();
                if (!mnt.startsWith("/srv/pqnas/pools/")) {
                    showToast("err", "Refusing: mount is not under /srv/pqnas/pools/", 6500);
                    return;
                }

                const okType = String(typeInp.value || "").trim().toUpperCase() === "DESTROY";
                if (!okType) {
                    showToast("warn", "Type DESTROY to confirm.", 4200);
                    return;
                }

                const plan_id = randHex(32);
                const plan_nonce = randHex(16);
                const force_wipe = !!wipeChk.checked;

                const body = { mount: mnt, plan_id, plan_nonce, confirm: true, force_wipe };

                dbg.textContent = JSON.stringify({ note: "POST destroy-pool", request: body }, null, 2);
                showToast("info", "Destroy started…", 2200);

                const { r, j, txt } = await postJson("/api/v4/raid/execute/destroy-pool", body);

                dbg.textContent = JSON.stringify({ http: r.status, response: j ?? txt, request: body }, null, 2);

                if (!r.ok || !j || j.ok !== true) {
                    showToast("err", `Destroy failed: ${prettyError(j, r, txt)}`, 6500);
                    return;
                }

                // Start exec polling using server-returned plan_id (preferred)
                const pid = (j && j.plan_id) ? String(j.plan_id) : String(plan_id);
                startExecPolling(pid);

                close();

                // Best-effort: refresh pools list soon (exec polling will also refresh on done)
                setTimeout(async () => {
                    await refreshPoolsState();
                    renderPoolSelectorTop();
                    if (g_tab === "pools") await renderPoolsTab();
                }, 800);
            };

            ov.style.display = "flex";
        }
        async function openCreatePoolModal() {
            const ov = ensureCreatePoolOverlay();

            const closeBtn = ov.querySelector("#poolCreateCloseBtn");
            const poolIdInp = ov.querySelector("#poolIdInp");
            const poolDisplayNameInp = ov.querySelector("#poolDisplayNameInp");
            const modeSel = ov.querySelector("#poolModeSel");
            const modeHint = ov.querySelector("#poolModeHint");
            const slotCountInp = ov.querySelector("#poolSlotCountInp");
            const slotsApplyBtn = ov.querySelector("#poolSlotsApplyBtn");
            const slotsHost = ov.querySelector("#poolSlotsHost");
            const slotHint = ov.querySelector("#poolSlotHint");
            const forceChk = ov.querySelector("#poolForceChk");
            const refreshBtn = ov.querySelector("#poolDevsRefreshBtn");
            const doBtn = ov.querySelector("#poolCreateDoBtn");
            const dbg = ov.querySelector("#poolCreateDebug");

            let disks = [];
            let slotValues = [];

            function eligibleDisks() {
                let arr = Array.isArray(disks) ? disks.slice() : [];
                if (isDevMode()) {
                    arr.sort((a, b) => (isLoopDisk(a) ? 0 : 1) - (isLoopDisk(b) ? 0 : 1));
                }

                const eligible = arr.filter(isEligibleDisk);
                const byPath = new Map(eligible.map(d => [String(d.path || d.dev || ""), d]));

                // Keep currently assigned slot devices selectable
                for (const v of slotValues) {
                    const dev = String(v || "").trim();
                    if (!dev) continue;
                    if (byPath.has(dev)) continue;

                    const found = arr.find(d => String(d.path || d.dev || "") === dev);
                    if (found) {
                        byPath.set(dev, found);
                    } else {
                        byPath.set(dev, {
                            path: dev,
                            name: dev.replace("/dev/", ""),
                            model: "Current slot device",
                            size_bytes: 0
                        });
                    }
                }

                // Keep current runtime member disks selectable too,
                // even if they are mounted / not generically eligible.
                const runtimeMembers = Array.isArray(pool?.member_parent_disks) ? pool.member_parent_disks : [];
                for (const v of runtimeMembers) {
                    const dev = String(v || "").trim();
                    if (!dev) continue;
                    if (byPath.has(dev)) continue;

                    const found = arr.find(d => String(d.path || d.dev || "") === dev);
                    if (found) {
                        byPath.set(dev, found);
                    } else {
                        byPath.set(dev, {
                            path: dev,
                            name: dev.replace("/dev/", ""),
                            model: "Runtime member",
                            size_bytes: 0
                        });
                    }
                }
                console.log("[edit-slots] pool.mount =", pool?.mount);
                console.log("[edit-slots] slotValues =", slotValues);
                console.log("[edit-slots] runtimeMembers =", Array.isArray(pool?.member_parent_disks) ? pool.member_parent_disks : []);
                console.log("[edit-slots] all disks =", disks.map(d => ({ path: d.path, mountpoints: d.mountpoints, children: d.children })));
                console.log("[edit-slots] final eligible =", Array.from(byPath.values()).map(d => d.path || d.dev));
                return Array.from(byPath.values());
            }

            function diskOptionLabel(d) {
                return diskLabel(d);
            }

            function selectedDevicesFromSlots() {
                return slotValues.map(v => String(v || "").trim()).filter(Boolean);
            }

            function syncSlotValuesFromDom() {
                const sels = slotsHost.querySelectorAll("select[data-slot-index]");
                const next = [];
                sels.forEach((sel) => {
                    const idx = Number(sel.getAttribute("data-slot-index") || "0");
                    next[idx] = String(sel.value || "").trim();
                });
                slotValues = next;
            }

            function renderSlotSelectors() {
                const countRaw = Number(slotCountInp?.value || 1);
                const count = Math.max(1, Math.min(16, Number.isFinite(countRaw) ? Math.trunc(countRaw) : 1));

                while (slotValues.length < count) slotValues.push("");
                if (slotValues.length > count) slotValues = slotValues.slice(0, count);

                const eligible = eligibleDisks();

                const selectedSet = new Set(slotValues.filter(Boolean));

                slotsHost.innerHTML = `
<div style="display:flex; flex-direction:column; gap:10px;">
  ${Array.from({ length: count }, (_, i) => {
                    const current = String(slotValues[i] || "");
                    const options = [
                        `<option value="">(empty)</option>`,
                        ...eligible.map((d) => {
                            const val = String(d.path || d.dev || "");
                            const selected = (val === current) ? "selected" : "";
                            const usedElsewhere = val && selectedSet.has(val) && val !== current;
                            const disabled = usedElsewhere ? "disabled" : "";
                            const suffix = usedElsewhere ? " — already selected" : "";
                            return `<option value="${esc(val)}" ${selected} ${disabled}>${esc(diskOptionLabel(d) + suffix)}</option>`;
                        })
                    ].join("");

                    return `
<div class="pqSlotRow" style="align-items:flex-start;">
  <div class="pqSlotLeft" style="min-width:120px;">
    <div class="pqSlotTitle">Slot ${i + 1}</div>
    <div class="pqSlotDev">Choose disk or leave empty</div>
  </div>
  <div style="flex:1 1 auto;">
    <select data-slot-index="${i}" style="width:100%; min-height:44px; padding:10px 12px; border-radius:14px; border:1px solid rgba(255,255,255,0.14); background:rgba(0,0,0,0.18); color:var(--fg);">
      ${options}
    </select>
  </div>
</div>`;
                }).join("")}
</div>
`;

                slotsHost.querySelectorAll("select[data-slot-index]").forEach((sel) => {
                    sel.addEventListener("change", () => {
                        syncSlotValuesFromDom();
                        renderSlotSelectors();
                        updateHints();
                    });
                });

                updateHints();
            }

            function updateHints() {
                const mode = String(modeSel.value || "single");
                const devices = selectedDevicesFromSlots();

                if (modeHint) {
                    modeHint.textContent =
                        mode === "raid1"
                            ? "RAID1 needs at least 2 assigned slots."
                            : "Single uses one or more drives without redundancy.";
                }

                if (slotHint) {
                    slotHint.textContent =
                        `Assigned devices: ${devices.length}. Empty slots are allowed and become visible placeholders in Pool Manager.`;
                }
            }

            async function refreshDisks() {
                try {
                    dbg.textContent = "(loading /api/v4/storage/disks …)";
                    const j = await loadAllDisks();

                    let arr = Array.isArray(j?.disks) ? j.disks : [];
                    if (isDevMode()) {
                        arr = arr.slice().sort((a, b) => (isLoopDisk(a) ? 0 : 1) - (isLoopDisk(b) ? 0 : 1));
                    } else {
                        arr = arr.slice();
                    }

                    disks = arr;
                    dbg.textContent = JSON.stringify({
                        ok: true,
                        disks_total: disks.length,
                        eligible_total: eligibleDisks().length
                    }, null, 2);

                    renderSlotSelectors();
                } catch (e) {
                    dbg.textContent = JSON.stringify({
                        ok: false,
                        error: String(e && e.message ? e.message : e)
                    }, null, 2);
                    showToast("err", "Failed to load disks (see Advanced).", 5200);
                }
            }

            async function doCreate() {
                syncSlotValuesFromDom();

                const pool_id = String(poolIdInp.value || "").trim();
                const display_name = String(poolDisplayNameInp.value || "").trim();
                const mode = String(modeSel.value || "single");
                const force = !!forceChk.checked;
                const slot_count = Math.max(1, Math.min(16, Number(slotCountInp.value || 1) || 1));

                const slots = Array.from({ length: slot_count }, (_, i) => ({
                    index: i,
                    device: slotValues[i] ? String(slotValues[i]) : null
                }));

                const devices = slots.map(s => s.device).filter(Boolean);

                if (!/^[a-z0-9_-]{1,32}$/.test(pool_id)) {
                    showToast("err", "bad pool_id (allowed: a-z 0-9 _ - , max 32)", 5200);
                    return;
                }

                if (mode !== "single" && mode !== "raid1") {
                    showToast("err", "mode must be single or raid1", 5200);
                    return;
                }

                if (!devices.length) {
                    showToast("err", "Assign at least one disk to a slot.", 4200);
                    return;
                }

                if (mode === "raid1" && devices.length < 2) {
                    showToast("err", "raid1 requires at least 2 assigned slots.", 5200);
                    return;
                }

                const unique = new Set(devices);
                if (unique.size !== devices.length) {
                    showToast("err", "The same disk cannot be selected in multiple slots.", 5200);
                    return;
                }

                const plan_id = randHex(32);
                const plan_nonce = randHex(16);

                const body = {
                    plan_id,
                    plan_nonce,
                    confirm: true,
                    pool_id,
                    display_name,
                    mode,
                    force,
                    slot_count,
                    slots,
                    devices
                };

                dbg.textContent = JSON.stringify({ request: body }, null, 2);
                showToast("info", "Creating pool…", 2200);

                const { r, j, txt } = await postJson("/api/v4/raid/execute/create-pool", body);

                dbg.textContent = JSON.stringify({
                    http: r.status,
                    response: j ?? txt,
                    request: body
                }, null, 2);

                if (!r.ok || !j || j.ok !== true) {
                    showToast("err", `Create pool failed: ${prettyError(j, r, txt)}`, 6500);
                    return;
                }

                showToast("ok", "Create started ✓ Watching exec record…", 2600);
                const pid = (j && j.plan_id) ? String(j.plan_id) : String(plan_id);
                startExecPolling(pid);

                ov.style.display = "none";

                setTimeout(async () => {
                    await refreshPoolsState();
                    renderPoolSelectorTop();
                    await renderPoolsTab();
                }, 1200);
            }

            closeBtn.onclick = () => (ov.style.display = "none");
            refreshBtn.onclick = refreshDisks;
            slotsApplyBtn.onclick = () => {
                syncSlotValuesFromDom();
                renderSlotSelectors();
            };
            modeSel.onchange = () => {
                syncSlotValuesFromDom();
                renderSlotSelectors();
            };
            doBtn.onclick = doCreate;

            if (!poolIdInp.value) poolIdInp.value = "raidtest";
            if (!poolDisplayNameInp.value) poolDisplayNameInp.value = "Raid test";
            if (!slotCountInp.value) slotCountInp.value = "1";
            forceChk.checked = false;

            ov.style.display = "flex";
            await refreshDisks();
        }
        createBtn?.addEventListener("click", () => {
            openCreatePoolModal().catch(e => {
                showToast("err", `Create pool UI crashed: ${String(e && e.stack ? e.stack : e)}`, 6500);
            });
        });

        (async () => {
            // render member drives into each pool card
            const tasks = pools.map(async (p) => {
                const mount = String(p?.mount || "");
                if (!mount) return;

                const hostId = "poolMembers__" + btoa(unescape(encodeURIComponent(mount))).replace(/[^a-z0-9]/gi, "_");
                const host = document.getElementById(hostId);
                if (!host) return;

                try {
                    const disc = await loadPoolDiscoveryOnce(mount);
                    const bdevs = Array.isArray(disc?.btrfs?.devices) ? disc.btrfs.devices : [];

                    if (!bdevs.length) {
                        host.innerHTML = `<span class="v" style="opacity:.75;">(no devices found)</span>`;
                        return;
                    }

                    host.innerHTML = `<div class="pqDriveSvgGrid" data-mount="${esc(mount)}">
                        ${bdevs.map(driveTileSvgHtml).join("")}
                    </div>`;

                    const grid = host.querySelector(".pqDriveSvgGrid");
                    if (grid) {
                        // Click anywhere on drives area → open Drives modal for that pool
                        grid.addEventListener("click", async (e) => {
                            const mnt = grid.getAttribute("data-mount") || "";
                            if (!mnt) return;

                            // If user clicked a tile, still open modal (primary action)
                            try {
                                await openPoolDrivesModal(mnt);
                            } catch (err) {
                                showToast("err", `Drives UI crashed: ${String(err && (err.stack || err.message) ? (err.stack || err.message) : err)}`, 6500);
                            }
                        });

                        // Optional: right-click on a tile copies /dev/... (secondary action)
                        grid.querySelectorAll(".pqDriveSvgTile").forEach((tile) => {
                            tile.addEventListener("contextmenu", async (ev) => {
                                ev.preventDefault();
                                const dev = tile.getAttribute("data-dev") || "";
                                if (!dev) return;
                                try { await navigator.clipboard.writeText(dev); showToast("ok", `Copied: ${dev}`, 1400); }
                                catch { showToast("info", dev, 1600); }
                            });
                        });
                    }

                } catch (_) {
                    host.innerHTML = `<span class="v" style="opacity:.75;">(discovery failed)</span>`;
                }
            });

            await Promise.all(tasks);
        })();

        poolsOut.querySelectorAll("button[data-pool-action]").forEach((btn) => {
            btn.addEventListener("click", async () => {
                const action = btn.getAttribute("data-pool-action");
                const mount = btn.getAttribute("data-mount") || "";
                if (!mount) return;

                const p = pools.find((x) => String(x?.mount || "") === String(mount));
                const editable = !!p?.is_editable_pool;

                if (!editable) {
                    showToast("info", "This volume is informational only in Pool Manager.", 2600);
                    return;
                }

                if (action === "apply-layout") {
                    try {
                        showToast("info", "Planning layout changes…", 1200);

                        const { r, j, txt } = await planPoolLayout(mount);
                        if (!r.ok || !j || j.ok !== true) {
                            showToast("err", `Plan layout failed: ${prettyError(j, r, txt)}`, 5200);
                            return;
                        }

                        const toAdd = Array.isArray(j.to_add) ? j.to_add : [];
                        const toRemove = Array.isArray(j.to_remove) ? j.to_remove : [];

                        if (!toAdd.length && !toRemove.length) {
                            showToast("ok", "No layout changes to apply.", 2200);
                            return;
                        }

                        if (toAdd.length === 1) {
                            const p = pools.find((x) => String(x?.mount || "") === String(mount));
                            const mode = String(p?.mode || "single");
                            const new_disk = String(toAdd[0] || "").trim();

                            showToast("info", "Preparing add-device plan…", 1200);

                            const planResp = await postJson("/api/v4/raid/plan/add-device", {
                                mount,
                                new_disk,
                                mode,
                                force: false
                            });

                            const planJ = planResp.j;
                            const plan = planJ?.plan;
                            if (!planResp.r.ok || !planJ || planJ.ok !== true || !plan || !plan.plan_id || !plan.plan_nonce) {
                                showToast("err", `Add-device plan failed: ${prettyError(planJ, planResp.r, planResp.txt)}`, 5200);
                                return;
                            }

                            const ok = await confirmExecute(plan, {
                                kind: "add",
                                mount,
                                new_disk,
                                mode
                            });
                            if (!ok) {
                                showToast("info", "Apply cancelled.", 1800);
                                return;
                            }

                            showToast("info", "Applying add-device…", 1200);

                            const execResp = await postJson("/api/v4/raid/execute/add-device", {
                                mount,
                                new_disk,
                                mode,
                                force: false,
                                plan_id: String(plan.plan_id),
                                plan_nonce: String(plan.plan_nonce),
                                dry_run: false,
                                confirm: true
                            });

                            if (!execResp.r.ok || !execResp.j || execResp.j.ok !== true) {
                                showToast("err", `Apply add-device failed: ${prettyError(execResp.j, execResp.r, execResp.txt)}`, 5200);
                                return;
                            }

                            const pid = String(execResp.j?.plan_id || execResp.j?.plan?.plan_id || plan.plan_id || "");
                            if (pid) startExecPolling(pid);

                            showToast("ok", "Layout apply started ✓", 2200);
                            return;
                        }

                        if (toRemove.length === 1) {
                            const remove_device = String(toRemove[0] || "").trim();

                            showToast("info", "Preparing remove-device plan…", 1200);

                            const planResp = await postJson("/api/v4/raid/plan/remove-device", {
                                mount,
                                remove_device,
                                force: false
                            });

                            const planJ = planResp.j;
                            const plan = planJ?.plan;
                            if (!planResp.r.ok || !planJ || planJ.ok !== true || !plan || !plan.plan_id) {
                                showToast("err", `Remove-device plan failed: ${prettyError(planJ, planResp.r, planResp.txt)}`, 5200);
                                return;
                            }

                            const ok = await confirmExecute(plan, {
                                kind: "remove",
                                mount,
                                remove_device,
                                force: false
                            });
                            if (!ok) {
                                showToast("info", "Apply cancelled.", 1800);
                                return;
                            }

                            showToast("info", "Applying remove-device…", 1200);

                            const execResp = await postJson("/api/v4/raid/execute/remove-device", {
                                mount,
                                remove_device,
                                force: false,
                                plan_id: String(plan.plan_id),
                                dry_run: false,
                                confirm: true
                            });

                            if (!execResp.r.ok || !execResp.j || execResp.j.ok !== true) {
                                showToast("err", `Apply remove-device failed: ${prettyError(execResp.j, execResp.r, execResp.txt)}`, 5200);
                                return;
                            }

                            const pid = String(execResp.j?.plan_id || execResp.j?.plan?.plan_id || plan.plan_id || "");
                            if (pid) startExecPolling(pid);

                            showToast("ok", "Layout apply started ✓", 2200);
                            return;
                        }

                        showToast("err", "Only one add or one remove can be applied at a time right now.", 5200);
                    } catch (e) {
                        showToast("err", `Apply layout crashed: ${String(e && e.message ? e.message : e)}`, 5200);
                    }
                    return;
                }

                if (action === "edit-slots") {
                    try {
                        const p = pools.find((x) => String(x?.mount || "") === String(mount));
                        if (!p) {
                            showToast("err", "Pool not found.", 3200);
                            return;
                        }
                        await openEditSlotsModal(p);
                    } catch (e) {
                        showToast("err", `Edit slots crashed: ${String(e && e.message ? e.message : e)}`, 5200);
                    }
                    return;
                }

                if (action === "add-slot") {
                    try {
                        showToast("info", "Adding slot…", 1200);
                        const { r, j, txt } = await addPoolSlot(mount);
                        if (!r.ok || !j || j.ok !== true) {
                            showToast("err", `Add slot failed: ${prettyError(j, r, txt)}`, 5200);
                            return;
                        }

                        showToast("ok", "Slot added ✓", 1800);
                        await refreshPoolsState();
                        renderPoolSelectorTop();
                        await renderPoolsTab();
                    } catch (e) {
                        showToast("err", `Add slot crashed: ${String(e && e.message ? e.message : e)}`, 5200);
                    }
                    return;
                }

                if (action === "remove-slot") {
                    try {
                        showToast("info", "Removing empty slot…", 1200);
                        const { r, j, txt } = await removePoolSlot(mount);
                        if (!r.ok || !j || j.ok !== true) {
                            showToast("err", `Remove slot failed: ${prettyError(j, r, txt)}`, 5200);
                            return;
                        }

                        showToast("ok", "Empty slot removed ✓", 1800);
                        await refreshPoolsState();
                        renderPoolSelectorTop();
                        await renderPoolsTab();
                    } catch (e) {
                        showToast("err", `Remove slot crashed: ${String(e && e.message ? e.message : e)}`, 5200);
                    }
                    return;
                }

                if (action === "edit-slots") {
                    showToast("info", `Slot editor for ${mount} is coming next.`, 2600);
                    return;
                }

                if (action === "add-slot") {
                    showToast("info", `Add-slot action for ${mount} is coming next.`, 2600);
                    return;
                }

                if (action === "remove-slot") {
                    showToast("info", `Remove-empty-slot action for ${mount} is coming next.`, 2600);
                    return;
                }

                if (action === "destroy") {
                    try {
                        await openDestroyPoolModal(mount);
                    } catch (e) {
                        showToast("err", `Destroy UI crashed: ${String(e && (e.stack || e.message) ? (e.stack || e.message) : e)}`, 6500);
                    }
                    return;
                }

                if (action === "drives") {
                    try {
                        await openPoolDrivesModal(mount);
                    } catch (e) {
                        showToast("err", `Drives UI crashed: ${String(e && (e.stack || e.message) ? (e.stack || e.message) : e)}`, 6500);
                    }
                    return;
                }

                if (action === "remove") {
                    try {
                        const p = pools.find((x) => String(x?.mount || "") === String(mount));
                        if (!p) {
                            showToast("err", "Pool not found.", 3200);
                            return;
                        }
                        await openRemoveDriveModal(p);
                    } catch (e) {
                        showToast(
                            "err",
                            `Remove drive UI crashed: ${String(e && (e.stack || e.message) ? (e.stack || e.message) : e)}`,
                            6500
                        );
                    }
                    return;
                }

                if (action === "convert") {
                    try {
                        const p = pools.find((x) => String(x?.mount || "") === String(mount));
                        if (!p) {
                            showToast("err", "Pool not found.", 3200);
                            return;
                        }
                        await openConvertRaidModal(p);
                    } catch (e) {
                        showToast("err", `Convert RAID UI crashed: ${String(e && e.message ? e.message : e)}`, 5200);
                    }
                    return;
                }

                if (action !== "rename") {
                    showToast("info", `${action} pool (${mount}): UI coming next.`, 2600);
                    return;
                }

                const current = String(p?.display_name || "").trim();

                const name = window.prompt(
                    `Rename pool:\n${mount}\n\nEnter a display name (empty = reset to label):`,
                    current
                );

                if (name === null) return;

                const newName = String(name).trim();

                try {
                    showToast("info", "Saving…", 1200);

                    const { r, j, txt } = await postJson("/api/v4/storage/pools/set-name", {
                        mount,
                        display_name: newName,
                    });

                    if (!r.ok || !j || j.ok !== true) {
                        showToast("err", `Rename failed: ${prettyError(j, r, txt)}`, 5200);
                        return;
                    }

                    showToast("ok", "Renamed ✓", 2000);

                    await refreshPoolsState();

                    const exists = g_pools.some((pp) => String(pp?.mount || "") === String(g_selectedMount || ""));
                    if (!exists && g_pools.length) g_selectedMount = String(g_pools[0]?.mount || "");

                    renderPoolSelectorTop();
                    await renderPoolsTab();
                } catch (e) {
                    showToast("err", `Rename crashed: ${String(e && e.message ? e.message : e)}`, 5200);
                }
            });
        });
    }
    async function probe() {
        if (!raidTab) {
            g_tab = "pools";
            saveTab(g_tab);
            applyTabToUi();
        }
        setBadge("info", "pools");
        stopMountPolling();

        if (subLine) subLine.textContent = "Manage storage pools (create/rename/convert/destroy).";
        if (rawOut) rawOut.textContent = "";
        if (actionsOut) actionsOut.textContent = "";

        const lp = await loadPools();

        if (!lp.ok) {
            g_pools = [];
            g_selectedMount = "";
            renderPoolSelectorTop();

            // show WHY in UI (so you immediately see 401/403 etc.)
            if (poolsOut) {
                poolsOut.innerHTML = `
        <div class="v" style="opacity:.9;">Failed to load pools.</div>
        <pre style="margin-top:10px; max-height:45vh; overflow:auto;">
${esc(JSON.stringify({ http: lp.http, error: lp.error, json: lp.j || null, txt: (lp.txt || "").slice(0, 2000) }, null, 2))}
        </pre>`;
            }
            return;
        }

        g_pools = lp.pools || [];

        const saved = loadSelectedMount();
        if (g_pools.length) {
            const existsSaved = g_pools.some(p => String(p?.mount||"") === String(saved||""));
            g_selectedMount = existsSaved ? String(saved||"") : String(g_pools[0]?.mount||"");
            saveSelectedMount(g_selectedMount);
        } else {
            g_selectedMount = "";
        }

        renderPoolSelectorTop();
        await renderPoolsTab();
        applyDevModeToUi();
    }

    refreshBtn?.addEventListener("click", probe);

    poolSelTop?.addEventListener("change", () => {
        const m = String(poolSelTop.value || "").trim();
        if (!m) return;

        stopAllPolling();

        // clear cached output so Apply cannot accidentally carry across pools
        g_lastAction = null;
        g_lastProgress = null;

        saveSelectedMount(m);
        g_selectedMount = m;
        probe();
    });



    function initStoragemgr() {
        // Dev mode init
        applyDevModeToUi();
        devModeChk?.addEventListener("change", () => setDevMode(!!devModeChk.checked));

        // Initial
        g_tab = loadTab();
        applyTabToUi();
        probe();
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", initStoragemgr);
    } else {
        initStoragemgr();
    }
})();