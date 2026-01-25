(() => {
    const el = (id) => document.getElementById(id);

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
        ctx.strokeStyle = "rgba(0,240,248,0.25)";
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
        drawLine(rxArr, "rgba(0,240,248,0.85)");
        drawLine(txArr, "rgba(255,190,0,0.85)");

        // Labels
        ctx.font = "12px ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace";
        ctx.fillStyle = "rgba(0,240,248,0.75)";
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

        // Memory
        const mt = j.mem ? j.mem.total_bytes : null;
        const ma = j.mem ? j.mem.available_bytes : null;
        const mu = (Number.isFinite(mt) && Number.isFinite(ma)) ? (mt - ma) : null;
        el("memTotal").textContent = fmtBytes(mt);
        el("memAvail").textContent = fmtBytes(ma);
        el("memUsed").textContent = fmtBytes(mu);
        setBar(el("memBar"), mu, mt);
        setPill(el("memPill"), "ok", `${pct(mu, mt).toFixed(1)}%`);

        // Disk /
        const dr = j.disk && j.disk.root ? j.disk.root : null;
        if (dr) {
            el("diskRootTotal").textContent = fmtBytes(dr.total_bytes);
            el("diskRootFree").textContent = fmtBytes(dr.free_bytes);
            el("diskRootUsed").textContent = fmtBytes(dr.used_bytes);
            setBar(el("diskRootBar"), dr.used_bytes, dr.total_bytes);
            setPill(el("diskRootPill"), "ok", `${pct(dr.used_bytes, dr.total_bytes).toFixed(1)}%`);
        }

        // Disk repo
        const dp = j.disk && j.disk.repo ? j.disk.repo : null;
        if (dp) {
            el("repoPath").textContent = dp.path || "—";
            el("diskRepoTotal").textContent = fmtBytes(dp.total_bytes);
            el("diskRepoFree").textContent = fmtBytes(dp.free_bytes);
            el("diskRepoUsed").textContent = fmtBytes(dp.used_bytes);
            setBar(el("diskRepoBar"), dp.used_bytes, dp.total_bytes);
        }

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
            render(j);
        } catch (e) {
            setPill(el("livePill"), "fail", "ERROR");
            el("liveText").textContent = String(e && e.message ? e.message : e);
            setPill(el("lastPill"), "fail", "failed");
        }
    }

    el("btnRefresh").addEventListener("click", refreshOnce);

    refreshOnce();
    setInterval(refreshOnce, 3000);
})();
