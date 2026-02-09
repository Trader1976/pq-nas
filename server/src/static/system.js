(() => {
    const el = (id) => document.getElementById(id);

    function cssVar(name, fallback) {
        try {
            const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
            return v || fallback;
        } catch (_) {
            return fallback;
        }
    }

    function setPill(pill, kind, text) {
        if (!pill) return;
        pill.className = "pill " + (kind || "");
        const v = pill.querySelector(".v");
        if (v) v.textContent = text;
    }

    function fmtBytes(n) {
        if (!Number.isFinite(n)) return "—";
        const units = ["B","KiB","MiB","GiB","TiB"];
        let x = n, i = 0;
        while (x >= 1024 && i < units.length - 1) { x /= 1024; i++; }
        return `${x.toFixed(i === 0 ? 0 : 2)} ${units[i]}`;
    }

    function fmtBps(n) {
        if (!Number.isFinite(n)) return "—";
        return fmtBytes(n) + "/s";
    }

    function fmtUptime(sec) {
        if (!Number.isFinite(sec)) return "—";
        sec = Math.max(0, Math.floor(sec));
        const d = Math.floor(sec / 86400); sec -= d * 86400;
        const h = Math.floor(sec / 3600); sec -= h * 3600;
        const m = Math.floor(sec / 60);
        if (d > 0) return `${d}d ${h}h ${m}m`;
        if (h > 0) return `${h}h ${m}m`;
        return `${m}m`;
    }

    function pct(used, total) {
        if (!Number.isFinite(used) || !Number.isFinite(total) || total <= 0) return 0;
        return Math.max(0, Math.min(100, (used / total) * 100));
    }

    function setBar(barEl, used, total) {
        if (!barEl) return;
        const p = pct(used, total);
        barEl.style.width = `${p.toFixed(1)}%`;
    }

    async function fetchSystem() {
        const r = await fetch("/api/v4/system", { cache: "no-store", credentials: "include" });
        const txt = await r.text();
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        let j = null;
        try { j = JSON.parse(txt); } catch {}
        if (!j) throw new Error("bad JSON");
        return j;
    }
    async function fetchStorage() {
        const r = await fetch("/api/v4/system/storage", { cache: "no-store", credentials: "include" });
        const txt = await r.text();
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        let j = null;
        try { j = JSON.parse(txt); } catch {}
        if (!j || !j.ok) throw new Error((j && (j.message || j.error)) || "bad JSON");
        return j;
    }

    function renderStorage(s) {
        const set = (id, v) => { const x = el(id); if (x) x.textContent = (v == null || v === "") ? "—" : String(v); };

        set("fsType", s.fstype);
        set("fsRoot", s.root);
        set("fsMount", s.mountpoint);
        set("fsSource", s.source);
        set("fsOptions", s.options);

        const on = !!s.prjquota_enabled;
        set("fsQuota", on ? "ON" : "OFF");

        const qp = el("fsQuotaPill");
        if (qp) {
            qp.classList.remove("ok", "warn", "fail");
            qp.classList.add(on ? "ok" : "warn");
        }

        const warn = el("fsWarn");
        if (warn) warn.textContent = s.warning ? ("Note: " + s.warning) : "";
    }



    // ---------------- Network graph (local deltas) ----------------
    const netState = {
        iface: null,
        lastT: 0,
        lastRx: 0,
        lastTx: 0,
        histRx: [],
        histTx: [],
        maxPoints: 120,
    };

    function pickIface(counters) {
        if (!counters) return null;

        // Prefer a real NIC with any traffic; else fall back to lo.
        const names = Object.keys(counters);

        // skip obvious zero / docker by preference order
        const preferred = names.filter(n => n !== "lo" && !n.startsWith("docker"));
        for (const n of preferred) {
            const c = counters[n];
            if (c && (c.rx_bytes > 0 || c.tx_bytes > 0)) return n;
        }
        if (counters.eno1) return "eno1";
        if (counters.eth0) return "eth0";
        if (counters.wlan0) return "wlan0";
        if (counters.lo) return "lo";
        return names[0] || null;
    }

    function pushHist(arr, v, maxPoints) {
        arr.push(v);
        while (arr.length > maxPoints) arr.shift();
    }
    function cpuKind(pct) {
        if (!Number.isFinite(pct)) return "warn";
        if (pct >= 92) return "fail";
        if (pct >= 80) return "warn";
        return "ok";
    }

    function kindColor(kind) {
        // Use theme vars when present; fall back to sane defaults.
        if (kind === "fail") return cssVar("--fail-rgb", "255,80,80");     // red
        if (kind === "warn") return cssVar("--warn-rgb", "255,205,70");    // yellow/amber
        // ok:
        return cssVar("--ok-rgb", "80,220,140");                           // green
    }

    function drawCpuGauge(canvas, pct) {
        if (!canvas) return;
        const ctx = canvas.getContext("2d");
        if (!ctx) return;

        const cssW = canvas.clientWidth || 84;
        const cssH = canvas.clientHeight || 84;
        const dpr = window.devicePixelRatio || 1;
        canvas.width  = Math.floor(cssW * dpr);
        canvas.height = Math.floor(cssH * dpr);
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

        ctx.clearRect(0, 0, cssW, cssH);

        const w = cssW, h = cssH;
        const cx = w / 2, cy = h / 2 + 6;
        const r = Math.min(w, h) * 0.36;

        // Gauge arc from 210° to -30° (240° sweep)
        const start = (210 * Math.PI) / 180;
        const end   = (-30 * Math.PI) / 180;
        const sweep = end - start;

        // Clamp value
        const p = Math.max(0, Math.min(100, Number(pct)));

        // Segment thresholds (traffic light)
        const t1 = 60;  // green up to 60%
        const t2 = 85;  // yellow 60..85, red 85..100

        // Theme colors (fallbacks included)
        const rgbG = cssVar("--ok-rgb",   "80,220,140");
        const rgbY = cssVar("--warn-rgb", "255,205,70");
        const rgbR = cssVar("--fail-rgb", "255,80,80");

        function arcTo(valPct) {
            return start + sweep * (valPct / 100);
        }

        // Background track (subtle)
        ctx.lineWidth = 10;
        ctx.lineCap = "round";
        ctx.strokeStyle = cssVar("--border2", "rgba(255,255,255,0.18)");
        ctx.beginPath();
        ctx.arc(cx, cy, r, start, end, false);
        ctx.stroke();

        // Traffic light segments (slightly translucent, sit on top of track)
        ctx.lineWidth = 10;
        ctx.lineCap = "round";

        // green segment
        ctx.strokeStyle = `rgba(${rgbG},0.55)`;
        ctx.beginPath();
        ctx.arc(cx, cy, r, arcTo(0), arcTo(t1), false);
        ctx.stroke();

        // yellow segment
        ctx.strokeStyle = `rgba(${rgbY},0.55)`;
        ctx.beginPath();
        ctx.arc(cx, cy, r, arcTo(t1), arcTo(t2), false);
        ctx.stroke();

        // red segment
        ctx.strokeStyle = `rgba(${rgbR},0.55)`;
        ctx.beginPath();
        ctx.arc(cx, cy, r, arcTo(t2), arcTo(100), false);
        ctx.stroke();

        // Value arc overlay (solid, color by current zone)
        let rgb = rgbG;
        if (p >= t2) rgb = rgbR;
        else if (p >= t1) rgb = rgbY;

        ctx.strokeStyle = `rgba(${rgb},0.98)`;
        ctx.beginPath();
        ctx.arc(cx, cy, r, start, start + sweep * (p / 100), false);
        ctx.stroke();

        // Center text (percent) with halo
        ctx.font = "12px ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace";
        ctx.textAlign = "center";
        ctx.textBaseline = "middle";

        const txt = `${p.toFixed(0)}%`;

        ctx.fillStyle = cssVar("--fg", "#111");
        ctx.fillText(txt, cx, cy);
    }


    function renderCpuGauges(perCorePct) {
        const host = el("cpuGaugeGrid");
        if (!host) return;

        const arr = Array.isArray(perCorePct) ? perCorePct : [];
        if (!arr.length) {
            host.innerHTML = "";
            return;
        }

        // Build DOM once then draw
        host.innerHTML = arr.map((_, i) => `
        <div class="cpuGauge">
            <canvas id="cpuGauge_${i}" width="84" height="84" style="width:84px;height:84px;display:block;"></canvas>
            <div class="lbl">core ${i}</div>
            <div class="val" id="cpuGaugeVal_${i}">—</div>
        </div>
    `).join("");

        for (let i = 0; i < arr.length; i++) {
            const p = Number(arr[i]);
            const valEl = el(`cpuGaugeVal_${i}`);
            if (valEl) valEl.textContent = Number.isFinite(p) ? `${p.toFixed(1)}%` : "—";
            drawCpuGauge(el(`cpuGauge_${i}`), p);
        }
    }

    function drawNet(canvas, rxArr, txArr) {
        if (!canvas) return;
        const ctx = canvas.getContext("2d");
        if (!ctx) return;

        // Make canvas match CSS size (retina-safe)
        const cssW = canvas.clientWidth || 600;
        const cssH = canvas.clientHeight || 240;
        const dpr = window.devicePixelRatio || 1;
        canvas.width = Math.floor(cssW * dpr);
        canvas.height = Math.floor(cssH * dpr);
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

        ctx.clearRect(0, 0, cssW, cssH);

        // Find scale
        const all = rxArr.concat(txArr).filter(Number.isFinite);
        const max = all.length ? Math.max(1, ...all) : 1;

        // Grid
        ctx.globalAlpha = 0.35;
        ctx.lineWidth = 1;
        ctx.beginPath();
        for (let i = 0; i <= 4; i++) {
            const y = (cssH * i) / 4;
            ctx.moveTo(0, y);
            ctx.lineTo(cssW, y);
        }
        ctx.strokeStyle = cssVar("--border2", "rgba(0,240,248,0.12)");
        ctx.stroke();
        ctx.globalAlpha = 1;

        function drawLine(arr, stroke) {
            if (!arr.length) return;
            ctx.beginPath();
            const n = arr.length;
            for (let i = 0; i < n; i++) {
                const x = (cssW * i) / Math.max(1, n - 1);
                const y = cssH - (cssH * (arr[i] / max));
                if (i === 0) ctx.moveTo(x, y);
                else ctx.lineTo(x, y);
            }
            ctx.strokeStyle = stroke;
            ctx.lineWidth = 2;
            ctx.stroke();
        }

        // RX = cyan-ish, TX = amber-ish (works with your theme)
        drawLine(rxArr, cssVar("--chart_rx", "rgba(0,240,248,0.95)"));
        drawLine(txArr, cssVar("--chart_tx", "rgba(var(--warn-rgb),0.95)"));



        // Labels
        ctx.font = "12px ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace";
        ctx.fillStyle = cssVar("--fg-dim", "rgba(0,240,248,0.74)");
        ctx.fillText(`max ${fmtBps(max)}`, 10, 18);
    }

    function renderNet(j) {
        const net = j.net || {};
        const c = net.counters || {};
        console.log("net counters", c.rx_bytes, c.tx_bytes);
        const series = Array.isArray(net.series) ? net.series : [];
        if (!series.length) {
            el("netIf") && (el("netIf").textContent = "—");
            el("netRx") && (el("netRx").textContent = "—");
            el("netTx") && (el("netTx").textContent = "—");
            drawNet(el("netCanvas"), [], []);
            return;
        }

        // Use server-sampled series directly
        const rxArr = [];
        const txArr = [];
        for (const p of series) {
            rxArr.push(Number(p.rx_bps));
            txArr.push(Number(p.tx_bps));
        }

        // Update “current” numbers from last point
        const last = series[series.length - 1] || {};
        el("netRx") && (el("netRx").textContent = fmtBps(Number(last.rx_bps)));
        el("netTx") && (el("netTx").textContent = fmtBps(Number(last.tx_bps)));

        // Interface label: backend is total-across-ifaces now
        el("netIf") && (el("netIf").textContent = "total");

        drawNet(el("netCanvas"), rxArr, txArr);
    }

    function isNoisyMount(mp) {
        if (!mp) return true;
        if (mp === "/") return false;

        // defense-in-depth (backend should already filter most of these)
        if (mp.startsWith("/proc")) return true;
        if (mp.startsWith("/sys")) return true;
        if (mp.startsWith("/dev")) return true;
        if (mp.startsWith("/run")) return true;
        if (mp.startsWith("/snap")) return true;
        if (mp.startsWith("/var/snap")) return true;
        if (mp.startsWith("/var/lib/snapd")) return true;
        if (mp.startsWith("/var/lib/flatpak")) return true;

        // boot partitions are usually not useful in NAS UI
        if (mp === "/boot" || mp === "/boot/efi") return true;

        return false;
    }

    function findBestMountForPath(mountpoints, path) {
        if (!path || !Array.isArray(mountpoints) || !mountpoints.length) return null;

        // best match = longest mountpoint prefix of path
        let best = null;
        for (const mp of mountpoints) {
            if (!mp) continue;
            if (mp === "/") {
                if (path.startsWith("/")) best = best || mp;
                continue;
            }
            // ensure prefix boundary: "/mnt/data" matches "/mnt/data/..." too
            if (path === mp || path.startsWith(mp.endsWith("/") ? mp : (mp + "/"))) {
                if (!best || mp.length > best.length) best = mp;
            }
        }
        return best;
    }

    function diskKindFromPct(p) {
        if (!Number.isFinite(p)) return "warn";
        if (p >= 92) return "fail";
        if (p >= 80) return "warn";
        return "ok";
    }

    function escapeHtml(s) {
        return String(s ?? "")
            .replaceAll("&", "&amp;")
            .replaceAll("<", "&lt;")
            .replaceAll(">", "&gt;")
            .replaceAll('"', "&quot;")
            .replaceAll("'", "&#39;");
    }

    function shortSource(src) {
        if (!src) return "—";
        src = String(src);
        if (src.length <= 42) return src;
        return src.slice(0, 18) + "…" + src.slice(-18);
    }

    function renderDiskFilesystems(j) {
        const host = el("diskMulti");
        if (!host) return;

        const fsArr0 = j && j.disk && Array.isArray(j.disk.filesystems) ? j.disk.filesystems : [];
        if (!fsArr0.length) { host.innerHTML = ""; return; }

        // filter noisy mounts
        const fsArr = fsArr0.filter(fs => !isNoisyMount(fs.mountpoint));

        const repoRoot = j && j.disk && j.disk.repo_root ? j.disk.repo_root : null;
        // If you didn’t add disk.repo_root to JSON, we can still try:
        // prefer dp.path if you keep it; otherwise use global REPO_ROOT exposed elsewhere.
        const repoPath = repoRoot || (j.disk && j.disk.repo && j.disk.repo.path) || null;

        const mountpoints = fsArr.map(x => x.mountpoint);
        const repoMp = findBestMountForPath(mountpoints, repoPath);

        // tag + sort
        const tagged = fsArr.map(fs => {
            const mp = fs.mountpoint || "";
            const isSystem = (mp === "/");
            const isData = (!!repoMp && mp === repoMp && mp !== "/");
            return { fs, mp, isSystem, isData };
        }).sort((a, b) => {
            // system first, then data, then alphabetical
            if (a.isSystem !== b.isSystem) return a.isSystem ? -1 : 1;
            if (a.isData !== b.isData) return a.isData ? -1 : 1;
            return (a.mp || "").localeCompare(b.mp || "");
        });

        const cards = [];
        const single = (tagged.length === 1);
        for (const t of tagged) {
            const fs = t.fs;
            const mp = fs.mountpoint || "—";
            const fstype = fs.fstype || "—";
            const src = fs.source || "";

            const total = Number(fs.total_bytes);
            const used  = Number(fs.used_bytes);
            const free  = Number(fs.free_bytes);

            const p = pct(used, total);
            const pillKind = diskKindFromPct(p);

            const label = t.isSystem ? "System volume" : (t.isData ? "Data volume" : "Volume");

            const key = "mp_" + mp.replace(/[^a-zA-Z0-9]+/g, "_");

            cards.push(`
<section class="card ${single ? "span-12" : "span-6"}">
  <div class="hd">
    <div class="h">
      ${escapeHtml(label)} •
      <span class="mono"
            title="${escapeHtml(mp)}">${escapeHtml(mp)}</span>
    </div>
    <span class="pill ${pillKind}">
      <span class="k">Used:</span>
      <span class="v">${p.toFixed(1)}%</span>
    </span>
  </div>

  <div class="bd">
    <div class="kv">
      <div class="k">FS type</div>
      <div class="v mono">${escapeHtml(fstype)}</div>
    </div>

    <div class="kv">
      <div class="k">Source</div>
      <div class="v mono"
           title="${escapeHtml(src)}">${escapeHtml(shortSource(src))}</div>
    </div>

    <div class="kv">
      <div class="k">Total</div>
      <div class="v">${fmtBytes(total)}</div>
    </div>

    <div class="kv">
      <div class="k">Free</div>
      <div class="v">${fmtBytes(free)}</div>
    </div>

    <div class="kv">
      <div class="k">Used</div>
      <div class="v">${fmtBytes(used)}</div>
    </div>

    <div class="bar" title="Disk used">
      <div id="bar_${key}"
           style="width:${p.toFixed(1)}%"></div>
    </div>
  </div>
</section>

        `.trim());
        }

        host.innerHTML = `<div class="grid">${cards.join("\n")}</div>`;
    }


    // ---------------- Existing render ----------------
    function render(j) {

            // OS (top card)
            el("osHost").textContent   = j.host || "—";
            el("osPretty").textContent = (j.os && j.os.pretty) ? j.os.pretty : "—";
            el("osKernel").textContent = j.kernel || "—";
            el("cpuModel").textContent = (j.cpu && j.cpu.model) ? j.cpu.model : "—";
            setPill(el("osPill"), "ok", j.kernel || "—");


            // CPU
        const load = j.cpu && j.cpu.load ? j.cpu.load : null;
        const loadText = load ? `${load.one.toFixed(2)}  ${load.five.toFixed(2)}  ${load.fifteen.toFixed(2)}` : "—";
        el("cpuCores").textContent = (j.cpu && j.cpu.cores) ? String(j.cpu.cores) : "—";
        el("cpuLoad").textContent = loadText;
        el("uptime").textContent = (j.uptime_s != null) ? fmtUptime(j.uptime_s) : "—";
        setPill(el("cpuPill"), "ok", load ? load.one.toFixed(2) : "—");
        // CPU usage (from /proc/stat deltas computed on server)
        const u = (j.cpu && j.cpu.usage) ? j.cpu.usage : null;

        if (u && u.ok) {
            const tp = Number(u.total_pct);
            el("cpuUsageTotal").textContent = Number.isFinite(tp) ? `${tp.toFixed(1)}%` : "—";

            const arr = Array.isArray(u.per_core_pct) ? u.per_core_pct : [];
            const parts = [];
            for (let i = 0; i < arr.length; i++) {
                const p = Number(arr[i]);
                if (Number.isFinite(p)) parts.push(`c${i} ${p.toFixed(0)}%`);
            }
            el("cpuUsageCores").textContent = parts.length ? parts.join("  ") : "—";

            renderCpuGauges(arr);

        } else {
            el("cpuUsageTotal").textContent = "—";
            el("cpuUsageCores").textContent = "—";

            renderCpuGauges([]);
        }

        // Memory
        const mt = j.mem ? j.mem.total_bytes : null;
        const ma = j.mem ? j.mem.available_bytes : null;
        const mu = (Number.isFinite(mt) && Number.isFinite(ma)) ? (mt - ma) : null;
        el("memTotal").textContent = fmtBytes(mt);
        el("memAvail").textContent = fmtBytes(ma);
        el("memUsed").textContent = fmtBytes(mu);
        setBar(el("memBar"), mu, mt);
        setPill(el("memPill"), "ok", `${pct(mu, mt).toFixed(1)}%`);

        renderDiskFilesystems(j);
        // Process
        const p = j.process || null;
        if (p) {
            el("procExe").textContent = p.exe || "—";
            el("procRss").textContent = fmtBytes(p.rss_bytes);
            el("procStart").textContent = p.started_iso || "—";
            setPill(el("procPill"), "ok", p.pid != null ? String(p.pid) : "—");
        }

        // Network (local)
        renderNet(j);

        // Sidebar live
        setPill(el("livePill"), "ok", "OK");
        el("liveText").textContent =
            `Host: ${j.host || "—"}\n` +
            `Time: ${j.now_iso || "—"}\n` +
            `OS: ${(j.os && j.os.pretty) ? j.os.pretty : "—"}\n` +
            `Kernel: ${j.kernel || "—"}\n` +
            `CPU: ${(j.cpu && j.cpu.model) ? j.cpu.model : "—"}`;

        // Updated pill
        setPill(el("lastPill"), "ok", j.now_iso || "now");
    }

    async function refreshOnce() {
        setPill(el("livePill"), "warn", "loading…");
        el("liveText").textContent = "Fetching /api/v4/system…";

        try {
            const j = await fetchSystem();
            try {
                render(j);
            } catch (e2) {
                // Frontend render error (NOT API)
                setPill(el("livePill"), "fail", "UI ERROR");
                el("liveText").textContent = String(e2 && e2.message ? e2.message : e2);
                // keep lastPill as-is or mark warn
                return;
            }

        } catch (e) {
            setPill(el("livePill"), "fail", "ERROR");
            el("liveText").textContent = String(e && e.message ? e.message : e);
            setPill(el("lastPill"), "fail", "failed");
        }
    }

    el("btnRefresh").addEventListener("click", refreshOnce);



    let _storageTimer = null;

    async function refreshStorageOnce() {
        try {
            const s = await fetchStorage();
            renderStorage(s);
        } catch (e) {
            const warn = el("fsWarn");
            if (warn) warn.textContent = "Failed to probe storage: " + (e && e.message ? e.message : e);
            const qp = el("fsQuotaPill");
            if (qp) {
                qp.classList.remove("ok");
                qp.classList.add("fail");
            }
            el("fsQuota") && (el("fsQuota").textContent = "ERROR");
        }
    }
    refreshOnce();
    setInterval(refreshOnce, 3000);

// Storage probe: slower cadence is enough
    refreshStorageOnce();
    _storageTimer = setInterval(refreshStorageOnce, 30000);

})();
