(() => {
    const el = (id) => document.getElementById(id);

    let lastSystemPayload = null;
    let lastStoragePayload = null;
    let lastDrivesPayload = null;

    function tr(key, vars, fallback) {
        const api = window.PQNAS_I18N;
        if (api && typeof api.t === "function") {
            return api.t(key, vars || null, fallback);
        }
        return String(fallback ?? key);
    }


    function ensureSystemModalCss() {
        if (document.getElementById("systemModalCss")) return;

        const style = document.createElement("style");
        style.id = "systemModalCss";
        style.textContent = `
.systemModalBackdrop{
    position:fixed;
    inset:0;
    z-index:100000;
    display:flex;
    align-items:center;
    justify-content:center;
    padding:18px;
    background:rgba(0,0,0,.55);
    backdrop-filter:blur(6px);
    -webkit-backdrop-filter:blur(6px);
}
.systemModalCard{
    width:min(620px, calc(100vw - 24px));
    border:1px solid var(--border2, rgba(120,120,120,.42));
    border-radius:18px;
    overflow:hidden;
    background:linear-gradient(180deg, var(--panel2, #f8f8f8), var(--panel, #eeeeee));
    color:var(--fg, #111);
    box-shadow:0 18px 70px rgba(0,0,0,.42);
}
.systemModalHead{
    padding:14px 16px;
    border-bottom:1px solid var(--border2, rgba(120,120,120,.32));
    background:rgba(0,0,0,.08);
}
.systemModalTitle{
    font-weight:950;
    letter-spacing:.2px;
}
.systemModalSub{
    margin-top:4px;
    font-size:12px;
    color:var(--fg-dim, rgba(0,0,0,.66));
    overflow-wrap:anywhere;
}
.systemModalBody{
    padding:16px;
    display:grid;
    gap:10px;
}
.systemModalNote{
    padding:10px 12px;
    border-radius:14px;
    border:1px solid rgba(var(--warn-rgb, 180,120,20),.35);
    background:rgba(var(--warn-rgb, 180,120,20),.10);
    white-space:pre-wrap;
}
.systemModalFoot{
    display:flex;
    justify-content:flex-end;
    gap:10px;
    padding:12px 16px;
    border-top:1px solid var(--border2, rgba(120,120,120,.32));
    background:rgba(0,0,0,.08);
}
html[data-theme="bright"] .systemModalCard{
    background:linear-gradient(180deg, #fff, #f2f4f7) !important;
    color:#111827 !important;
}
`;
        document.head.appendChild(style);
    }

    function openSystemInfoModal(opts = {}) {
        ensureSystemModalCss();

        return new Promise((resolve) => {
            const options = opts || {};
            const modal = document.createElement("div");
            modal.className = "systemModalBackdrop";
            modal.setAttribute("role", "dialog");
            modal.setAttribute("aria-modal", "true");

            const card = document.createElement("div");
            card.className = "systemModalCard";

            const head = document.createElement("div");
            head.className = "systemModalHead";

            const title = document.createElement("div");
            title.className = "systemModalTitle";
            title.textContent = options.title || tr("system.modal.notice", null, "Notice");

            const sub = document.createElement("div");
            sub.className = "systemModalSub";
            sub.textContent = options.subtitle || "";

            head.appendChild(title);
            if (sub.textContent) head.appendChild(sub);

            const body = document.createElement("div");
            body.className = "systemModalBody";

            const note = document.createElement("div");
            note.className = "systemModalNote";
            note.textContent = options.message || "";
            body.appendChild(note);

            const foot = document.createElement("div");
            foot.className = "systemModalFoot";

            const okBtn = document.createElement("button");
            okBtn.type = "button";
            okBtn.className = "btn";
            okBtn.textContent = options.okText || tr("system.modal.ok", null, "OK");
            foot.appendChild(okBtn);

            card.appendChild(head);
            card.appendChild(body);
            card.appendChild(foot);
            modal.appendChild(card);
            document.body.appendChild(modal);

            const finish = () => {
                document.removeEventListener("keydown", onKey, true);
                modal.remove();
                resolve();
            };

            const onKey = (ev) => {
                if (ev.key === "Escape" || ev.key === "Enter") {
                    ev.preventDefault();
                    ev.stopPropagation();
                    finish();
                }
            };

            document.addEventListener("keydown", onKey, true);
            modal.addEventListener("click", (ev) => {
                if (ev.target === modal) finish();
            });
            okBtn.addEventListener("click", finish);
            window.setTimeout(() => okBtn.focus(), 0);
        });
    }

    function openSystemConfirmModal(opts = {}) {
        ensureSystemModalCss();

        return new Promise((resolve) => {
            const options = opts || {};
            const modal = document.createElement("div");
            modal.className = "systemModalBackdrop";
            modal.setAttribute("role", "dialog");
            modal.setAttribute("aria-modal", "true");

            const card = document.createElement("div");
            card.className = "systemModalCard";

            const head = document.createElement("div");
            head.className = "systemModalHead";

            const title = document.createElement("div");
            title.className = "systemModalTitle";
            title.textContent = options.title || tr("system.modal.confirm", null, "Confirm action");

            const sub = document.createElement("div");
            sub.className = "systemModalSub";
            sub.textContent = options.subtitle || "";

            head.appendChild(title);
            if (sub.textContent) head.appendChild(sub);

            const body = document.createElement("div");
            body.className = "systemModalBody";

            const note = document.createElement("div");
            note.className = "systemModalNote";
            note.textContent = options.message || "";
            body.appendChild(note);

            const foot = document.createElement("div");
            foot.className = "systemModalFoot";

            const cancelBtn = document.createElement("button");
            cancelBtn.type = "button";
            cancelBtn.className = "btn secondary";
            cancelBtn.textContent = options.cancelText || tr("system.modal.cancel", null, "Cancel");

            const okBtn = document.createElement("button");
            okBtn.type = "button";
            okBtn.className = "btn";
            okBtn.textContent = options.confirmText || tr("system.modal.continue", null, "Continue");

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

            window.setTimeout(() => cancelBtn.focus(), 0);
        });
    }


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
    async function fetchDrives() {
        const r = await fetch("/api/v4/system/drives", { cache: "no-store", credentials: "include" });
        const txt = await r.text();
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        let j = null;
        try { j = JSON.parse(txt); } catch {}
        if (!j || !j.ok) throw new Error((j && (j.message || j.error)) || "bad JSON");
        return j;
    }
    async function startDriveSelftest(dev, type) {
        const r = await fetch("/api/v4/system/drives/selftest/start", {
            method: "POST",
            cache: "no-store",
            credentials: "include",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ dev, type })
        });
        const txt = await r.text();
        let j = null;
        try { j = JSON.parse(txt); } catch {}
        if (!r.ok || !j || !j.ok) {
            throw new Error((j && (j.message || j.error)) || `HTTP ${r.status}`);
        }
        return j;
    }


    // drive-health-refresh-now: frontend: backend-triggered SMART/NVMe refresh.
    async function refreshDriveSmartNow() {
        const r = await fetch("/api/v4/system/drives/refresh-now", {
            method: "POST",
            cache: "no-store",
            credentials: "include",
            headers: { "Content-Type": "application/json" },
            body: "{}"
        });
        const txt = await r.text();
        let j = null;
        try { j = JSON.parse(txt); } catch {}
        if (!r.ok || !j || !j.ok) {
            throw new Error((j && (j.message || j.error || j.last_error)) || `HTTP ${r.status}`);
        }
        return j;
    }

    function healthKind(s) {
        if (s === "fail") return "fail";
        if (s === "warn") return "warn";
        return "ok";
    }

    function fmtTempC(n) {
        return Number.isFinite(n) ? `${n}°C` : "—";
    }

    // drive-health-refresh-now: frontend: small manual refresh control for the Drive Health card.
    function fmtSmartAge(sec) {
        if (!Number.isFinite(sec) || sec < 0) return "—";
        sec = Math.floor(sec);
        if (sec < 60) return `${sec}s`;
        const min = Math.floor(sec / 60);
        if (min < 60) return `${min}m`;
        const h = Math.floor(min / 60);
        const m = min % 60;
        if (h < 48) return m ? `${h}h ${m}m` : `${h}h`;
        const d = Math.floor(h / 24);
        const rh = h % 24;
        return rh ? `${d}d ${rh}h` : `${d}d`;
    }

    function ensureDriveRefreshControls() {
        const upd = el("driveHealthUpdated");
        if (!upd || !upd.parentNode) return;
        if (el("btnDriveHealthRefreshNow")) return;

        const row = document.createElement("div");
        row.className = "driveHealthRefreshControls";
        row.style.display = "flex";
        row.style.alignItems = "center";
        row.style.gap = "8px";
        row.style.flexWrap = "wrap";
        row.style.margin = "8px 0 12px 0";
        row.innerHTML = `
            <button class="btn" id="btnDriveHealthRefreshNow" type="button" data-i18n="system.refresh_smart_now">
                ${escapeHtml(tr("system.refresh_smart_now", null, "Refresh SMART now"))}
            </button>
            <span class="note mono" id="driveHealthRefreshStatus"></span>
        `;
        upd.parentNode.insertBefore(row, upd.nextSibling);

        if (window.PQNAS_I18N && typeof window.PQNAS_I18N.apply === "function") {
            window.PQNAS_I18N.apply(row);
        }
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
        const set = (id, v) => {
            const x = el(id);
            if (x) x.textContent = (v == null || v === "") ? "—" : String(v);
        };

        set("fsType", s.fstype);
        set("fsRoot", s.root);
        set("fsMount", s.mountpoint);
        set("fsSource", s.source);
        set("fsOptions", s.options);

        const warn = el("fsWarn");
        if (warn) warn.textContent = s.warning ? tr("system.note_with_value", { value: s.warning }, "Note: " + s.warning) : "";
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

    function nvmeDataUnitsToBytes(units) {
        if (!Number.isFinite(units) || units < 0) return NaN;
        return units * 512000; // NVMe data unit = 1000 * 512 bytes
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
            <div class="lbl">${escapeHtml(tr("system.core_n", { n: i }, `core ${i}`))}</div>
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

            const label = t.isSystem ? tr("system.system_volume", null, "System volume") : (t.isData ? tr("system.data_volume", null, "Data volume") : tr("system.volume", null, "Volume"));

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
      <span class="k">${escapeHtml(tr("system.used", null, "Used:"))}</span>
      <span class="v">${p.toFixed(1)}%</span>
    </span>
  </div>

  <div class="bd">
    <div class="kv">
      <div class="k">${escapeHtml(tr("system.fs_type", null, "FS type"))}</div>
      <div class="v mono">${escapeHtml(fstype)}</div>
    </div>

    <div class="kv">
      <div class="k">${escapeHtml(tr("system.source", null, "Source"))}</div>
      <div class="v mono"
           title="${escapeHtml(src)}">${escapeHtml(shortSource(src))}</div>
    </div>

    <div class="kv">
      <div class="k">${escapeHtml(tr("system.total", null, "Total"))}</div>
      <div class="v">${fmtBytes(total)}</div>
    </div>

    <div class="kv">
      <div class="k">${escapeHtml(tr("system.free", null, "Free"))}</div>
      <div class="v">${fmtBytes(free)}</div>
    </div>

    <div class="kv">
      <div class="k">${escapeHtml(tr("system.used_plain", null, "Used"))}</div>
      <div class="v">${fmtBytes(used)}</div>
    </div>

    <div class="bar" title="${escapeHtml(tr("system.disk_used", null, "Disk used"))}">
      <div id="bar_${key}"
           style="width:${p.toFixed(1)}%"></div>
    </div>
  </div>
</section>

        `.trim());
        }

        host.innerHTML = `<div class="grid">${cards.join("\n")}</div>`;
    }

    function renderDrives(j) {
        const upd = el("driveHealthUpdated");
        if (upd) {
            if (j.updated_iso) {
                const d = new Date(j.updated_iso);
                const ageSec = Math.max(0, Math.floor((Date.now() - d.getTime()) / 1000));
                upd.textContent = tr("system.last_smart_refresh_age", { time: d.toLocaleTimeString(), age: fmtSmartAge(ageSec) }, `Last SMART refresh: ${d.toLocaleTimeString()} UTC (${fmtSmartAge(ageSec)} ago)`);
                upd.title = j.updated_iso;
            } else {
                upd.textContent = tr("system.last_smart_refresh_empty", null, "Last SMART refresh: —");
                upd.title = "";
            }
        }
        ensureDriveRefreshControls();


        const host = el("driveHealthList");
        const pill = el("driveHealthPill");
        if (!host || !pill) return;

        const arr = Array.isArray(j.drives) ? j.drives : [];
        if (!arr.length) {
            host.innerHTML = `<div class="note">${escapeHtml(tr("system.no_supported_drives", null, "No supported internal drives detected."))}</div>`;
            setPill(pill, "warn", tr("system.none", null, "none"));
            return;
        }

        let worst = "ok";
        for (const d of arr) {
            const hs = String(d.health_status || "unknown");
            if (hs === "fail") worst = "fail";
            else if (hs === "warn" && worst !== "fail") worst = "warn";
        }

        const label =
            worst === "fail" ? tr("system.health.attention", null, "attention") :
                worst === "warn" ? tr("system.health.warning", null, "warning") :
                    tr("system.health.healthy", null, "healthy");

        setPill(
            pill,
            worst === "fail" ? "fail" : (worst === "warn" ? "warn" : "ok"),
            `${label} (${arr.length})`
        );

        host.innerHTML = arr.map(d => {
            const model = escapeHtml(d.model || d.dev || tr("system.drive", null, "Drive"));
            const dev = escapeHtml(d.dev || "—");
            const bus = escapeHtml((d.transport || d.kind || "unknown").toUpperCase());
            const size = fmtBytes(Number(d.size_bytes));
            const healthText = escapeHtml(d.health_text || tr("system.unknown", null, "Unknown"));
            const temp = fmtTempC(Number(d.temperature_c));
            const pUsed = Number(d.percentage_used);
            const spare = Number(d.available_spare);
            const media = Number(d.media_errors);
            const poh = Number(d.power_on_hours);
            const selfText = d.selftest_text || "—";
            const warning = escapeHtml(d.warning || "");
            const realloc = Number(d.reallocated_sectors);
            const pending = Number(d.current_pending_sectors);
            const offunc  = Number(d.offline_uncorrectable);
            const repunc  = Number(d.reported_uncorrect);
            const crc     = Number(d.udma_crc_errors);

            const status = String(d.health_status || "unknown");
            const selftestState = String(d.selftest_status || "unknown");
            const selftestProgress = Number.isFinite(Number(d.selftest_progress_pct))
                ? Number(d.selftest_progress_pct)
                : -1;

            let rowCls = "";
            if (selftestState === "running") {
                rowCls = "test";
            } else if (status === "fail") {
                rowCls = "fail";
            } else if (status === "warn") {
                rowCls = "warn";
            }

            const noteCls = rowCls;
            const canRunSelftest =
                !!d.selftest_supported &&
                selftestState !== "running";

            const dur = Number(d.data_units_read);
            const duw = Number(d.data_units_written);
            const readBytes = nvmeDataUnitsToBytes(dur);
            const writtenBytes = nvmeDataUnitsToBytes(duw);

            const extras = [];
            if (Number.isFinite(pUsed) && pUsed >= 0) extras.push(tr("system.drive.wear", { value: pUsed }, `Wear: ${pUsed}%`));
            if (Number.isFinite(spare) && spare >= 0) extras.push(tr("system.drive.spare", { value: spare }, `Spare: ${spare}%`));
            if (Number.isFinite(media) && media >= 0) extras.push(tr("system.drive.media_errors", { value: media }, `Media errors: ${media}`));
            if (Number.isFinite(poh) && poh >= 0) extras.push(tr("system.drive.power_on", { value: poh }, `Power-on: ${poh} h`));
            if (Number.isFinite(readBytes)) extras.push(tr("system.drive.read", { value: fmtBytes(readBytes) }, `Read: ${fmtBytes(readBytes)}`));
            if (Number.isFinite(writtenBytes)) extras.push(tr("system.drive.written", { value: fmtBytes(writtenBytes) }, `Written: ${fmtBytes(writtenBytes)}`));
            if (Number.isFinite(realloc) && realloc >= 0) extras.push(tr("system.drive.realloc", { value: realloc }, `Realloc: ${realloc}`));
            if (Number.isFinite(pending) && pending >= 0) extras.push(tr("system.drive.pending", { value: pending }, `Pending: ${pending}`));
            if (Number.isFinite(offunc) && offunc >= 0) extras.push(tr("system.drive.offline_unc", { value: offunc }, `Offline unc: ${offunc}`));
            if (Number.isFinite(repunc) && repunc >= 0) extras.push(tr("system.drive.reported_unc", { value: repunc }, `Reported unc: ${repunc}`));
            if (Number.isFinite(crc) && crc >= 0) extras.push(tr("system.drive.crc", { value: crc }, `CRC: ${crc}`));

            return `
            <div class="kv driveRow ${rowCls}">
                <div class="k">
                    ${model}<br>
                    <span class="mono">${dev} • ${bus} • ${size}</span>
                </div>
                <div class="v">${healthText} • 🌡 ${temp}</div>
            </div>
            <div class="note mono driveNote ${noteCls}" style="margin-top:6px; margin-bottom:8px;">
                ${escapeHtml(extras.join(" • ") || tr("system.drive.no_extra_counters", null, "No extra health counters"))}
                <br>
                ${escapeHtml(tr("system.self_test", null, "Self-test"))}: ${
                selftestState === "running"
                    ? `<b style="color:rgba(var(--warn-rgb),1)">${escapeHtml(tr("system.running", null, "RUNNING"))}${
                        selftestProgress >= 0 ? " " + selftestProgress + "%" : ""
                    }</b> • ${escapeHtml(selfText)}`
                    : escapeHtml(selfText)
            }
                ${
                selftestState === "running" && selftestProgress >= 0
                    ? `<div style="margin-top:8px; height:8px; border-radius:999px; overflow:hidden; background:rgba(var(--warn-rgb),0.18); border:1px solid rgba(var(--warn-rgb),0.30);">
                               <div style="height:100%; width:${selftestProgress}%; background:rgba(var(--warn-rgb),0.92);"></div>
                           </div>`
                    : ``
            }
                ${warning ? `<br>${warning}` : ``}
            </div>
            <div class="driveActions" style="display:flex; gap:8px; margin:0 0 14px 0; flex-wrap:wrap;">
                ${
                d.selftest_supported
                    ? `
                    <button class="btn js-drive-selftest"
                            type="button"
                            data-dev="${escapeHtml(d.dev || "")}"
                            data-type="short"
                            ${canRunSelftest ? "" : "disabled"}>
                        ${escapeHtml(tr("system.run_short_test", null, "Run short test"))}
                    </button>
                    <button class="btn js-drive-selftest"
                            type="button"
                            data-dev="${escapeHtml(d.dev || "")}"
                            data-type="extended"
                            ${canRunSelftest ? "" : "disabled"}>
                        ${escapeHtml(tr("system.run_extended_test", null, "Run extended test"))}
                    </button>
                    `
                    : `
                    <span class="note">${escapeHtml(tr("system.selftest_unavailable", null, "Self-test start not available for this drive."))}</span>
                    `
            }
            </div>
        `;
        }).join("");
    }
    let _driveTimer = null;

    async function refreshDrivesOnce() {
        try {
            const j = await fetchDrives();
            lastDrivesPayload = j;
            renderDrives(j);
        } catch (e) {
            const host = el("driveHealthList");
            if (host) {
                host.innerHTML = `<div class="note">${escapeHtml(tr("system.drive_probe_failed", { error: String(e && e.message ? e.message : e) }, `Failed to probe drive health: ${String(e && e.message ? e.message : e)}`))}</div>`;
            }
            setPill(el("driveHealthPill"), "fail", tr("admin.common.error", null, "error"));
        }
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
        el("liveText").textContent = [
            tr("system.live.host", { value: j.host || "—" }, `Host: ${j.host || "—"}`),
            tr("system.live.time", { value: j.now_iso || "—" }, `Time: ${j.now_iso || "—"}`),
            tr("system.live.os", { value: (j.os && j.os.pretty) ? j.os.pretty : "—" }, `OS: ${(j.os && j.os.pretty) ? j.os.pretty : "—"}`),
            tr("system.live.kernel", { value: j.kernel || "—" }, `Kernel: ${j.kernel || "—"}`),
            tr("system.live.cpu", { value: (j.cpu && j.cpu.model) ? j.cpu.model : "—" }, `CPU: ${(j.cpu && j.cpu.model) ? j.cpu.model : "—"}`)
        ].join("\n");

        // Updated pill
        setPill(el("lastPill"), "ok", j.now_iso || tr("admin.stats.now", null, "now"));
    }

    async function refreshOnce() {
        setPill(el("livePill"), "warn", tr("common.loading", null, "loading…"));
        el("liveText").textContent = tr("system.fetching_api", null, "Fetching /api/v4/system…");

        try {
            const j = await fetchSystem();
            lastSystemPayload = j;
            try {
                render(j);
            } catch (e2) {
                // Frontend render error (NOT API)
                setPill(el("livePill"), "fail", tr("system.ui_error", null, "UI ERROR"));
                el("liveText").textContent = String(e2 && e2.message ? e2.message : e2);
                // keep lastPill as-is or mark warn
                return;
            }

        } catch (e) {
            setPill(el("livePill"), "fail", tr("admin.common.error", null, "ERROR"));
            el("liveText").textContent = String(e && e.message ? e.message : e);
            setPill(el("lastPill"), "fail", tr("system.failed", null, "failed"));
        }
    }

    el("btnRefresh").addEventListener("click", async () => {
        await refreshOnce();
        await refreshStorageOnce();
        await refreshDrivesOnce();
    });


    // drive-health-refresh-now: frontend: manual refresh button for cached SMART data.
    document.addEventListener("click", async (ev) => {
        const btn = ev.target && ev.target.closest && ev.target.closest("#btnDriveHealthRefreshNow");
        if (!btn) return;

        const status = el("driveHealthRefreshStatus");
        const oldText = btn.textContent;
        btn.disabled = true;
        btn.textContent = tr("system.refreshing", null, "Refreshing…");
        if (status) status.textContent = tr("system.running_smartctl", null, "Running smartctl probe…");

        try {
            await refreshDriveSmartNow();
            await refreshDrivesOnce();
            if (status) status.textContent = tr("system.refreshed", null, "Refreshed.");
        } catch (e) {
            const msg = String(e && e.message ? e.message : e);
            if (status) status.textContent = tr("system.refresh_failed", { error: msg }, "Refresh failed: " + msg);
            await openSystemInfoModal({
                title: tr("system.smart_refresh_failed_title", null, "SMART refresh failed"),
                message: tr("system.smart_refresh_failed", { error: msg }, "Failed to refresh SMART data: " + msg),
                okText: tr("system.modal.ok", null, "OK")
            });
        } finally {
            btn.disabled = false;
            btn.textContent = oldText;
        }
    });

    document.addEventListener("click", async (ev) => {
        const btn = ev.target && ev.target.closest && ev.target.closest(".js-drive-selftest");
        if (!btn) return;

        const dev = btn.getAttribute("data-dev") || "";
        const type = btn.getAttribute("data-type") || "short";
        if (!dev) return;

        if (type === "extended") {
            const ok = await openSystemConfirmModal({
                title: tr("system.selftest_extended_title", null, "Start extended self-test?"),
                subtitle: dev,
                message: tr("system.confirm_extended_selftest", { dev }, `Start extended self-test for ${dev}? This may take a long time.`),
                confirmText: tr("system.start_selftest", null, "Start self-test"),
                cancelText: tr("system.modal.cancel", null, "Cancel")
            });
            if (!ok) return;
        }

        const oldText = btn.textContent;
        btn.disabled = true;
        btn.textContent = tr("system.starting", null, "Starting…");

        try {
            await startDriveSelftest(dev, type);
            await refreshDrivesOnce();
        } catch (e) {
            await openSystemInfoModal({
                title: tr("system.selftest_start_failed_title", null, "Self-test start failed"),
                message: tr("system.selftest_start_failed", { error: String(e && e.message ? e.message : e) }, "Failed to start self-test: " + String(e && e.message ? e.message : e)),
                okText: tr("system.modal.ok", null, "OK")
            });
        } finally {
            btn.disabled = false;
            btn.textContent = oldText;
        }
    });



    let _storageTimer = null;

    async function refreshStorageOnce() {
        try {
            const s = await fetchStorage();
            lastStoragePayload = s;
            renderStorage(s);
        } catch (e) {
            const warn = el("fsWarn");
            if (warn) warn.textContent = tr("system.storage_probe_failed", { error: String(e && e.message ? e.message : e) }, "Failed to probe storage: " + (e && e.message ? e.message : e));
        }
    }
    window.addEventListener("pqnas-language-changed", () => {
        if (window.PQNAS_I18N && typeof window.PQNAS_I18N.apply === "function") {
            window.PQNAS_I18N.apply(document);
        }
        ensureDriveRefreshControls();
        if (lastSystemPayload) render(lastSystemPayload);
        if (lastStoragePayload) renderStorage(lastStoragePayload);
        if (lastDrivesPayload) renderDrives(lastDrivesPayload);
    });

    if (window.PQNAS_I18N && typeof window.PQNAS_I18N.ready === "function") {
        window.PQNAS_I18N.ready().then(() => window.PQNAS_I18N.apply(document)).catch(() => {});
    }

    refreshOnce();
    setInterval(refreshOnce, 3000);

// Storage probe: slower cadence is enough
    refreshStorageOnce();
    _storageTimer = setInterval(refreshStorageOnce, 30000);

// Drive health probe
    refreshDrivesOnce();
    _driveTimer = setInterval(refreshDrivesOnce, 30000);

})();
