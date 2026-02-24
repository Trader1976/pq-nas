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
    const probeOut = el("probeOut");
    const rawOut = el("rawOut");
    const topologyOut = el("topology");
    const actionsOut = el("actionsOut");
    const userStatusEl = el("userStatus");
    const devModeChk = el("devModeChk");

    const probeCard = el("probeCard");
    const topologyCard = el("topologyCard");
    const rawCard = el("rawCard");
    const poolSelTop = el("poolSelTop");

    const DEV_MODE_KEY = "pqnas_raidmgr_dev_mode";

    // Multi-pool selection
    const POOL_SEL_KEY = "pqnas_raidmgr_pool_mount";
    let g_pools = [];
    let g_selectedMount = "";

    // Persist last outputs across probe() refresh (probe rebuilds DOM)
    let g_lastAction = null;
    let g_lastProgress = null;

    // Legacy fallback mounts (used only if /api/v4/storage/pools returns empty)
    const mountsToTry = ["/srv/pqnas-test", "/srv/pqnas/data", "/srv/pqnas"];

    // ----------------------------------------------------------------------------
    // Global timer/poller state (so probe() can stop old intervals created by
    // previous renderActions() closures)
    // ----------------------------------------------------------------------------
    const GSTATE_KEY = "__pqnas_raidmgr_state_v1__";
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

    function stopAllPolling() {
        const st = gstate();
        if (st.pollTimer) {
            clearInterval(st.pollTimer);
            st.pollTimer = null;
        }
        if (st.execTimer) {
            clearInterval(st.execTimer);
            st.execTimer = null;
        }
        st.execPlanId = "";
        st.execLastState = "";
        st.execLastStep = -1;
    }

    function isDevMode() {
        try {
            return window.localStorage.getItem(DEV_MODE_KEY) === "1";
        } catch (_) {
            return false;
        }
    }

    function setDevMode(on) {
        try {
            window.localStorage.setItem(DEV_MODE_KEY, on ? "1" : "0");
        } catch (_) {}
        applyDevModeToUi();
    }

    function applyDevModeToUi() {
        const on = isDevMode();

        if (devModeChk) devModeChk.checked = on;

        // Dev-only cards:
        if (probeCard) probeCard.style.display = on ? "" : "none";
        if (topologyCard) topologyCard.style.display = on ? "" : "none";
        if (rawCard) rawCard.style.display = on ? "" : "none";

        // Dev-only details inside dynamic Actions UI:
        const adv = document.getElementById("advancedDetails");
        if (adv) adv.style.display = on ? "" : "none";
    }

    function poolDisplayName(p) {
        const label = String(p?.label || "").trim();
        const mount = String(p?.mount || "").trim();
        if (label) return label;
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

    function setBadge(kind, text) {
        if (!badge) return;
        badge.className = `badge ${kind}`;
        badge.textContent = text || "";
    }

    function detectVersionFromUrl() {
        const p = String(location.pathname || "");
        const m = p.match(/\/apps\/[^/]+\/([^/]+)\/www\//);
        return m ? m[1] : "";
    }

    const appVer = detectVersionFromUrl();
    if (titleLine && appVer) titleLine.textContent = `RAID Manager • ${appVer}`;

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

    async function loadPools() {
        // Returns [] on any failure (don’t break RAID tab)
        try {
            const q = await fetchJson("/api/v4/storage/pools");
            if (!q.r || q.r.status !== 200 || !q.j || q.j.ok !== true || !Array.isArray(q.j.pools)) return [];
            return q.j.pools;
        } catch (_) {
            return [];
        }
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
        lines.push(`RAID features: ${isBtrfs ? "Enabled" : "Disabled"}`);

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

    function renderActions(parsed, mount) {
        if (!actionsOut) return;

        const cands = candidateDisks(parsed, { showInternal: false, usbOnly: false });
        const disabled = !(
            parsed &&
            parsed.ok === true &&
            String(parsed.fstype || "").toLowerCase() === "btrfs"
        );

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

        let html = "";

        // Pool selector (multi-pool)
        const pools = Array.isArray(g_pools) ? g_pools : [];
        const selMount = String(mount || "");
        const poolOptions = pools.length
            ? pools
                .map((p) => {
                    const m = String(p?.mount || "");
                    const name = poolDisplayName(p);
                    const extra = m ? ` — ${m}` : "";
                    const sel = m === selMount ? "selected" : "";
                    return `<option value="${esc(m)}" ${sel}>${esc(name)}${esc(extra)}</option>`;
                })
                .join("")
            : `<option value="${esc(selMount)}" selected>${esc(selMount || "(none)")}</option>`;

        html += `<div class="row" style="margin-bottom:10px; align-items:center; gap:10px;">
      <div class="k" style="min-width:110px;">Storage pool</div>
      <div class="v" style="flex:1 1 auto;">
        <select id="poolSel" style="width:100%; padding:10px 12px; border-radius:14px; border:1px solid rgba(255,255,255,0.14); background:rgba(0,0,0,0.18); color:var(--fg);">
          ${poolOptions}
        </select>
        <div class="v" style="opacity:.75; margin-top:6px;">
          Changing pool reloads RAID status and actions.
        </div>
      </div>
    </div>`;

        html += `<hr style="opacity:.15;">`;
        html += `<div style="font-weight:900; margin: 6px 0 8px;">Add drive</div>`;

        if (disabled) {
            html += `<div class="v" style="opacity:.8;">Storage pool actions are disabled (filesystem is not Btrfs or probe failed).</div>`;
            actionsOut.innerHTML = html;
            applyDevModeToUi();
            return;
        }

        if (!cands.length) {
            html += `<div class="v" style="opacity:.8;">No available drives found. (All disks are already members, or only loop devices exist.)</div>`;
            actionsOut.innerHTML = html;
            applyDevModeToUi();
            return;
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

        actionsOut.innerHTML = html;

        // IMPORTANT: stop old timers when switching pool from inside Actions block
        const poolSel = document.getElementById("poolSel");
        poolSel?.addEventListener("change", () => {
            const m = String(poolSel.value || "");
            if (!m) return;

            stopAllPolling();

            saveSelectedMount(m);
            g_selectedMount = m;

            probe();
        });

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

        function setExecUi(state, stepIndex, stepTotal, planId) {
            const st = String(state || "idle");
            const si = Number.isFinite(stepIndex) ? stepIndex : -1;
            const tot = Number.isFinite(stepTotal) ? stepTotal : -1;

            if (execPill) {
                let cls = "pill warn";
                if (st === "done") cls = "pill ok";
                else if (st === "failed") cls = "pill err";
                else if (st === "running") cls = "pill warn";
                else if (st === "queued") cls = "pill warn";
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

        function setProgressText(lines) {
            const txt = lines.join("\n");
            g_lastProgress = txt;
            if (progressOut) progressOut.textContent = txt;
        }

        function stopExecPollingUiOnly() {
            // UI reset only; actual interval is stopped by stopAllPolling() / stopExecPolling()
            setExecUi("idle", -1, -1, "");
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
            stopExecPollingUiOnly();
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
            try {
                j = JSON.parse(txt);
            } catch (_) {}
            return { r, j, txt };
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
                            const bdevs = Array.isArray(parsed?.btrfs?.devices) ? parsed.btrfs.devices : [];
                            const poolDev = bdevs && bdevs[0] && bdevs[0].path ? String(bdevs[0].path) : "Drive in pool";
                            const svg = svgAddPreview({
                                poolLabel: mnt ? `Storage pool: ${mnt}` : "",
                                poolDevLabel: poolDev,
                                newDevLabel: o.new_disk || "",
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

        // --- Exec-record polling (plan_id-based) ---
        function fmtExecState(s) {
            s = String(s || "");
            return s || "(unknown)";
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
                setExecUi("error", -1, -1, st.execPlanId);
                setProgressText(lines);
                return;
            }

            const state = fmtExecState(rec.state);
            const busy = !!rec.busy;
            const si = Number.isFinite(rec.step_index) ? rec.step_index : -1;
            const tot = Number.isFinite(rec.step_total) ? rec.step_total : -1;

            setExecUi(state, si, tot, st.execPlanId);

            lines.push(`State: ${state} (busy=${busy})`);
            if (si >= 0 && tot > 0) {
                const pct = Math.max(0, Math.min(100, Math.round((si / tot) * 100)));
                lines.push(`Progress: ${si}/${tot} (${pct}%)`);
            } else {
                lines.push(`Progress: (unknown)`);
            }

            if (rec.ts_start) lines.push(`Started: ${rec.ts_start}`);
            if (rec.ts_last) lines.push(`Last:    ${rec.ts_last}`);
            if (rec.ts_end) lines.push(`Ended:   ${rec.ts_end}`);

            if (rec.message) lines.push(`Message: ${String(rec.message)}`);
            if (rec.error) lines.push(`Error: ${String(rec.error)}`);

            try {
                if (Array.isArray(rec.steps) && rec.steps.length) {
                    const last = rec.steps[rec.steps.length - 1];
                    if (last && typeof last === "object") {
                        if (last.cmd) lines.push(`Last cmd: ${String(last.cmd)}`);
                        if (last.ok != null) lines.push(`Last ok: ${String(last.ok)}`);
                        if (last.rc != null) lines.push(`Last rc: ${String(last.rc)}`);
                        if (last.out) {
                            lines.push("Last out:");
                            lines.push(String(last.out).slice(0, 4000));
                        }
                    }
                } else if (Array.isArray(rec.results) && rec.results.length) {
                    const last = rec.results[rec.results.length - 1];
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

            setProgressText(lines);

            const done = state === "done" || state === "failed";
            if (done) {
                setTimeout(() => probe(), 800);
                stopExecPolling();
                return;
            }

            st.execLastState = state;
            st.execLastStep = si;
        }

        function startExecPolling(plan_id) {
            const pid = String(plan_id || "").trim();
            if (!/^[0-9a-f]{64}$/.test(pid)) {
                setProgressText([`Exec record: invalid plan_id: ${pid}`]);
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
        updateAddViz();
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
            const device = String(addSel?.value || "").trim();
            if (!device) return;

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

    async function probe() {
        setBadge("warn", "loading…");

        // kill any old intervals from the previous view of actions/progress
        stopAllPolling();

        if (subLine) subLine.textContent = "Detecting RAID capabilities…";
        if (rawOut) rawOut.textContent = "(loading)";
        if (actionsOut) actionsOut.textContent = "(loading…)";
        setUserStatusLines(["(loading)"]);
        clearNode(probeOut);
        clearNode(topologyOut);

        // 1) Load pools once
        g_pools = await loadPools();

        // 2) Choose selected mount
        const saved = loadSelectedMount();
        if (g_pools.length) {
            const exists = g_pools.some((p) => String(p?.mount || "") === saved);
            g_selectedMount = exists ? saved : String(g_pools[0]?.mount || "");
            if (g_selectedMount) saveSelectedMount(g_selectedMount);
        } else {
            g_selectedMount = "";
        }

        // 3) Render top selector
        renderPoolSelectorTop();

        // 4) Decide mounts to try
        const mountsTry = g_selectedMount ? [g_selectedMount] : mountsToTry;

        for (const m of mountsTry) {
            const url = `/api/v4/raid/status?mount=${encodeURIComponent(m)}`;
            const { r, j, txt } = await fetchJson(url);

            if (r.status === 401 || r.status === 403) {
                setBadge("warn", "admin required");
                if (subLine) subLine.textContent = "Requires admin session.";

                setUserStatusLines([`Mount: ${m}`, `Access: Denied (admin required)`, `RAID features: Unknown`]);

                if (probeOut) {
                    probeOut.appendChild(kvRow("Access", "Denied (not signed in / not admin)"));
                    probeOut.appendChild(kvRow("Endpoint", url));
                }
                if (rawOut) rawOut.textContent = JSON.stringify({ http: r.status, body: j ?? txt }, null, 2);

                applyDevModeToUi();
                return;
            }

            if (j && j.ok === true) {
                const fs = String(j.fstype || "");
                const resolved = String(j.resolved_mount || m);
                const isBtrfs = fs.toLowerCase() === "btrfs";

                if (isBtrfs) {
                    setBadge("ok", "enabled");
                    if (subLine) subLine.textContent = "RAID endpoints available (Btrfs detected).";
                } else {
                    setBadge("warn", "disabled");
                    if (subLine) subLine.textContent = "Filesystem is not Btrfs (RAID disabled).";
                }

                if (probeOut) {
                    probeOut.appendChild(kvRow("Mount (requested)", m));
                    probeOut.appendChild(kvRow("Mount (resolved)", resolved));
                    probeOut.appendChild(kvRow("Filesystem", fs || "(unknown)"));
                    if (j.mode) probeOut.appendChild(kvRow("Mode", j.mode));
                    if (j.message) probeOut.appendChild(kvRow("Message", j.message));
                }

                if (isBtrfs && j.parsed) {
                    renderTopology(j.parsed);
                } else if (topologyOut) {
                    topologyOut.textContent = isBtrfs ? "No parsed topology from server." : "Topology not available (non-btrfs).";
                }

                // Single discovery fetch: use it for actions + raw output
                let discObj = null;
                try {
                    const discUrl = `/api/v4/raid/discovery?mount=${encodeURIComponent(m)}`;
                    const d = await fetchJson(discUrl);
                    if (d && d.j && d.j.ok === true) {
                        discObj = d.j;
                        renderActions(d.j, resolved);
                    } else {
                        discObj = d?.j ?? d?.txt ?? { http: d?.r?.status };
                    }
                } catch (e) {
                    discObj = { error: String(e && e.message ? e.message : e) };
                }

                renderUserStatusFrom(j, m, resolved, discObj);

                if (rawOut) {
                    rawOut.textContent = JSON.stringify(
                        {
                            chosen_mount: m,
                            status: { endpoint: "status", mount: m, response: j },
                            discovery: discObj,
                        },
                        null,
                        2
                    );
                }

                applyDevModeToUi();
                return;
            }
        }

        // Fallback: /discovery across mounts
        let last = null;
        for (const m of mountsTry) {
            const url = `/api/v4/raid/discovery?mount=${encodeURIComponent(m)}`;
            const { r, j, txt } = await fetchJson(url);

            if (r.status === 401 || r.status === 403) {
                setBadge("warn", "admin required");
                if (subLine) subLine.textContent = "Requires admin session.";

                setUserStatusLines([`Mount: ${m}`, `Access: Denied (admin required)`, `RAID features: Unknown`]);

                if (probeOut) {
                    probeOut.appendChild(kvRow("Access", "Denied (not signed in / not admin)"));
                    probeOut.appendChild(kvRow("Endpoint", url));
                }
                if (rawOut) rawOut.textContent = JSON.stringify({ http: r.status, body: j ?? txt }, null, 2);

                applyDevModeToUi();
                return;
            }

            if (j && j.ok === true) {
                const fs = String(j.fstype || "");
                const resolved = String(j.resolved_mount || m);

                if (fs.toLowerCase() === "btrfs") {
                    setBadge("ok", "enabled");
                    if (subLine) subLine.textContent = "Discovery succeeded (Btrfs detected).";
                } else {
                    setBadge("warn", "disabled");
                    if (subLine) subLine.textContent = "Discovery succeeded, but filesystem is not Btrfs.";
                }

                if (probeOut) {
                    probeOut.appendChild(kvRow("Mount (requested)", m));
                    probeOut.appendChild(kvRow("Mount (resolved)", resolved));
                    probeOut.appendChild(kvRow("Filesystem", fs || "(unknown)"));
                    if (j.devices_count != null) probeOut.appendChild(kvRow("Devices", String(j.devices_count)));
                    if (j.arrays_count != null) probeOut.appendChild(kvRow("Arrays", String(j.arrays_count)));
                }

                if (rawOut) rawOut.textContent = JSON.stringify({ endpoint: "discovery", mount: m, response: j }, null, 2);

                try {
                    if (j && j.ok === true && j.btrfs) {
                        if (j.btrfs.summary) renderTopology({ summary: j.btrfs.summary, usage: j.btrfs.usage || {} });
                        else if (topologyOut) topologyOut.textContent = "Topology available but schema differs (no btrfs.summary). See raw output.";
                    }
                } catch (_) {}

                renderActions(j, resolved);
                return;
            }

            last = { r, j, txt, mount: m, url };
        }

        setBadge("warn", "disabled");

        const errText = last ? prettyError(last.j, last.r, last.txt) : "RAID not available";
        if (subLine) subLine.textContent = `RAID Manager is disabled: ${errText}`;

        if (probeOut) {
            probeOut.appendChild(kvRow("Result", "Disabled"));
            if (last) {
                probeOut.appendChild(kvRow("Mount (last tried)", last.mount));
                probeOut.appendChild(kvRow("Endpoint", last.url));
                probeOut.appendChild(kvRow("Reason", errText));
            }
        }

        if (rawOut) rawOut.textContent = JSON.stringify(last ? { http: last.r.status, body: last.j ?? last.txt } : {}, null, 2);
    }

    refreshBtn?.addEventListener("click", probe);

    poolSelTop?.addEventListener("change", () => {
        const m = String(poolSelTop.value || "").trim();
        if (!m) return;
        stopAllPolling();
        saveSelectedMount(m);
        g_selectedMount = m;
        probe();
    });

    // Dev mode init
    applyDevModeToUi();
    devModeChk?.addEventListener("change", () => setDevMode(!!devModeChk.checked));

    // Initial
    probe();
})();