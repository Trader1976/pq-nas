(() => {
    "use strict";

    const $ = (id) => document.getElementById(id);

    let currentTrendPeriod = "7d";

    function esc(s) {
        return String(s ?? "").replace(/[&<>"']/g, c => ({
            "&": "&amp;",
            "<": "&lt;",
            ">": "&gt;",
            '"': "&quot;",
            "'": "&#39;"
        }[c]));
    }

    function cssVar(name, fallback) {
        try {
            const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
            return v || fallback;
        } catch (_) {
            return fallback;
        }
    }

    function fmtNum(n) {
        const v = Number(n || 0);
        return Number.isFinite(v) ? v.toLocaleString() : "0";
    }

    function fmtBytes(bytes) {
        const n = Number(bytes || 0);
        if (!Number.isFinite(n) || n <= 0) return "0 B";
        const units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
        let v = n;
        let i = 0;
        while (v >= 1024 && i < units.length - 1) {
            v /= 1024;
            i++;
        }
        const digits = i === 0 ? 0 : (v >= 100 ? 1 : 2);
        return `${v.toFixed(digits)} ${units[i]}`;
    }

    function fmtShortBytes(bytes) {
        const n = Number(bytes || 0);
        if (!Number.isFinite(n) || n <= 0) return "0";
        const units = ["B", "K", "M", "G", "T"];
        let v = n;
        let i = 0;
        while (v >= 1024 && i < units.length - 1) {
            v /= 1024;
            i++;
        }
        const digits = i === 0 ? 0 : (v >= 100 ? 0 : 1);
        return `${v.toFixed(digits)} ${units[i]}`;
    }

    function setText(id, value) {
        const el = $(id);
        if (el) el.textContent = value;
    }

    function rowsHtml(rows, nameKey, emptyText) {
        if (!Array.isArray(rows) || rows.length === 0) {
            return `<tr><td colspan="3">${esc(emptyText || "No data")}</td></tr>`;
        }

        return rows.map(r => `
            <tr>
                <td class="mono">${esc(r[nameKey] || "—")}</td>
                <td class="num">${fmtNum(r.count)}</td>
                <td class="num">${fmtBytes(r.bytes)}</td>
            </tr>
        `).join("");
    }

    function trendBucketForPeriod(period) {
        if (period === "24h" || period === "7d") return "hour";
        if (period === "all") return "day";
        return "day";
    }

    function setTrendStatus(text) {
        const el = $("trendStatus");
        if (!el) return;
        const v = el.querySelector(".v");
        if (v) v.textContent = text;
        else el.textContent = text;
    }

    function activeTrendButton(period) {
        document.querySelectorAll(".trendBtn").forEach(btn => {
            btn.classList.toggle("active", btn.dataset.period === period);
        });
    }

    function chartColor(alpha = 0.95) {
        const info = cssVar("--info-rgb", "0,240,248");
        return `rgba(${info},${alpha})`;
    }

    function gridColor(alpha = 0.18) {
        const fg = cssVar("--fg-rgb", "255,255,255");
        return `rgba(${fg},${alpha})`;
    }

    function textColor(alpha = 0.70) {
        const fg = cssVar("--fg-rgb", "255,255,255");
        return `rgba(${fg},${alpha})`;
    }

    function drawLineChart(canvas, points, valueFn, labelFn) {
        if (!canvas) return;

        const ctx = canvas.getContext("2d");
        if (!ctx) return;

        const cssW = canvas.clientWidth || 520;
        const cssH = canvas.clientHeight || 160;
        const dpr = window.devicePixelRatio || 1;

        canvas.width = Math.floor(cssW * dpr);
        canvas.height = Math.floor(cssH * dpr);
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        ctx.clearRect(0, 0, cssW, cssH);

        const padL = 46;
        const padR = 12;
        const padT = 14;
        const padB = 24;
        const plotW = Math.max(1, cssW - padL - padR);
        const plotH = Math.max(1, cssH - padT - padB);

        const arr = Array.isArray(points) ? points : [];
        const values = arr.map(valueFn).map(Number).filter(Number.isFinite);

        ctx.font = "11px ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace";
        ctx.fillStyle = textColor(0.62);

        if (!arr.length || !values.length) {
            ctx.fillText("No trend data yet", padL, padT + 24);
            return;
        }

        let min = Math.min(...values);
        let max = Math.max(...values);

        if (min === max) {
            const bump = Math.max(1, Math.abs(max) * 0.05);
            min -= bump;
            max += bump;
        }

        const range = max - min;

        ctx.strokeStyle = gridColor(0.20);
        ctx.lineWidth = 1;
        ctx.beginPath();
        for (let i = 0; i <= 4; i++) {
            const y = padT + (plotH * i / 4);
            ctx.moveTo(padL, y);
            ctx.lineTo(padL + plotW, y);
        }
        ctx.stroke();

        ctx.fillStyle = textColor(0.64);
        ctx.textAlign = "right";
        ctx.textBaseline = "middle";
        ctx.fillText(labelFn(max), padL - 8, padT);
        ctx.fillText(labelFn((min + max) / 2), padL - 8, padT + plotH / 2);
        ctx.fillText(labelFn(min), padL - 8, padT + plotH);

        function xAt(i) {
            if (arr.length <= 1) return padL + plotW;
            return padL + (plotW * i / (arr.length - 1));
        }

        function yAt(v) {
            return padT + plotH - ((v - min) / range) * plotH;
        }

        ctx.strokeStyle = chartColor(0.98);
        ctx.lineWidth = 2.25;
        ctx.lineJoin = "round";
        ctx.lineCap = "round";
        ctx.beginPath();

        arr.forEach((p, i) => {
            const v = Number(valueFn(p));
            if (!Number.isFinite(v)) return;
            const x = xAt(i);
            const y = yAt(v);
            if (i === 0) ctx.moveTo(x, y);
            else ctx.lineTo(x, y);
        });

        ctx.stroke();

        ctx.fillStyle = chartColor(0.98);
        for (const i of [0, arr.length - 1]) {
            const v = Number(valueFn(arr[i]));
            if (!Number.isFinite(v)) continue;
            ctx.beginPath();
            ctx.arc(xAt(i), yAt(v), 3.2, 0, Math.PI * 2);
            ctx.fill();
        }

        const first = arr[0];
        const last = arr[arr.length - 1];

        ctx.fillStyle = textColor(0.62);
        ctx.textAlign = "left";
        ctx.textBaseline = "alphabetic";

        const firstDate = first && first.iso ? new Date(first.iso) : null;
        const lastDate = last && last.iso ? new Date(last.iso) : null;

        const firstLabel = firstDate && !Number.isNaN(firstDate.getTime())
            ? firstDate.toLocaleDateString()
            : "start";
        const lastLabel = lastDate && !Number.isNaN(lastDate.getTime())
            ? lastDate.toLocaleDateString()
            : "now";

        ctx.fillText(firstLabel, padL, cssH - 7);
        ctx.textAlign = "right";
        ctx.fillText(lastLabel, cssW - padR, cssH - 7);
    }

    function renderTrends(j) {
        const points = Array.isArray(j.points) ? j.points : [];

        if (!points.length) {
            setTrendStatus("No samples");
            ["trendStorageValue", "trendFilesValue", "trendUsersValue", "trendWorkspacesValue"].forEach(id => setText(id, "—"));
            drawLineChart($("trendStorageCanvas"), [], p => p.files_total_bytes, fmtShortBytes);
            drawLineChart($("trendFilesCanvas"), [], p => p.files_total_count, fmtNum);
            drawLineChart($("trendUsersCanvas"), [], p => p.users_total, fmtNum);
            drawLineChart($("trendWorkspacesCanvas"), [], p => p.workspaces_total, fmtNum);
            return;
        }

        const last = points[points.length - 1] || {};
        setText("trendStorageValue", fmtBytes(last.files_total_bytes));
        setText("trendFilesValue", `${fmtNum(last.files_total_count)} files`);
        setText("trendUsersValue", `${fmtNum(last.users_enabled)} enabled / ${fmtNum(last.users_total)} total`);
        setText("trendWorkspacesValue", `${fmtNum(last.workspaces_enabled)} enabled / ${fmtNum(last.workspaces_total)} total`);

        drawLineChart($("trendStorageCanvas"), points, p => p.files_total_bytes, fmtShortBytes);
        drawLineChart($("trendFilesCanvas"), points, p => p.files_total_count, fmtNum);
        drawLineChart($("trendUsersCanvas"), points, p => p.users_total, fmtNum);
        drawLineChart($("trendWorkspacesCanvas"), points, p => p.workspaces_total, fmtNum);

        const bucket = j.bucket || "raw";
        setTrendStatus(`${fmtNum(points.length)} point${points.length === 1 ? "" : "s"} · ${bucket}`);
    }

    async function loadTrends(period = currentTrendPeriod) {
        currentTrendPeriod = period;
        activeTrendButton(period);

        const bucket = trendBucketForPeriod(period);
        const url = `/api/v4/admin/stats/trends?period=${encodeURIComponent(period)}&bucket=${encodeURIComponent(bucket)}`;

        setTrendStatus("Loading…");

        try {
            const r = await fetch(url, {
                headers: { "Accept": "application/json" },
                credentials: "include",
                cache: "no-store"
            });

            const j = await r.json().catch(() => ({}));
            if (!r.ok || !j.ok) {
                throw new Error(j.message || j.error || `HTTP ${r.status}`);
            }

            renderTrends(j);
        } catch (e) {
            setTrendStatus(`Failed: ${e.message || e}`);
            renderTrends({ points: [] });
        }
    }

    async function loadStats(force = false) {
        const url = force ? "/api/v4/admin/stats/summary?refresh=1" : "/api/v4/admin/stats/summary";
        const btn = $("refreshBtn");
        const status = $("status");

        if (btn) btn.disabled = true;
        if (status) status.textContent = force ? "Scanning live storage…" : "Loading statistics…";

        try {
            const r = await fetch(url, {
                headers: { "Accept": "application/json" },
                credentials: "include",
                cache: "no-store"
            });

            const j = await r.json().catch(() => ({}));
            if (!r.ok || !j.ok) {
                throw new Error(j.message || j.error || `HTTP ${r.status}`);
            }

            const users = j.users || {};
            const workspaces = j.workspaces || {};
            const files = j.files || {};

            setText("cardUsers", fmtNum(users.total));
            setText(
                "cardUsersMini",
                `${fmtNum(users.enabled)} enabled · ${fmtNum(users.disabled)} disabled · ${fmtNum(users.admins)} admin`
            );

            setText("cardFiles", fmtNum(files.total_count));
            setText(
                "cardFilesMini",
                `${fmtNum(files.scanned_roots)} roots scanned · ${fmtNum(files.skipped_roots)} skipped`
            );

            setText("cardBytes", fmtBytes(files.total_bytes));
            setText("cardBytesMini", `Largest file ${fmtBytes(files.largest_bytes)}`);

            setText("cardWorkspaces", fmtNum(workspaces.total));
            setText(
                "cardWorkspacesMini",
                `${fmtNum(workspaces.enabled)} enabled · ${fmtNum(workspaces.user_created)} user-created · avg file ${fmtBytes(files.average_bytes)}`
            );

            $("mimeRows").innerHTML = rowsHtml(j.top_mime_types, "mime", "No MIME data");
            $("extRows").innerHTML = rowsHtml(j.top_extensions, "extension", "No extension data");
            $("scopeRows").innerHTML = rowsHtml(j.files_by_scope, "scope", "No scope data");

            const warnings = Array.isArray(j.warnings) ? j.warnings : [];
            const warningHtml = warnings.length
                ? `<tr><th>Warnings</th><td class="warn">${warnings.map(esc).join("<br>")}</td></tr>`
                : `<tr><th>Warnings</th><td>None</td></tr>`;

            $("detailRows").innerHTML = `
                <tr><th>Generated</th><td class="mono">${esc(j.generated_at_iso || "—")}</td></tr>
                <tr><th>Method</th><td>${esc(j.method || "—")}</td></tr>
                <tr><th>Notes</th><td>${esc(j.note || "—")}</td></tr>
                ${warningHtml}
            `;

            if (status) {
                status.textContent = `Updated ${j.generated_at_iso || "now"}`;
            }
        } catch (e) {
            if (status) status.textContent = `Failed: ${e.message || e}`;
            ["mimeRows", "extRows", "scopeRows"].forEach(id => {
                const el = $(id);
                if (el) el.innerHTML = `<tr><td colspan="3">Failed to load statistics.</td></tr>`;
            });
        } finally {
            if (btn) btn.disabled = false;
        }
    }

    document.addEventListener("DOMContentLoaded", () => {
        const btn = $("refreshBtn");
        if (btn) {
            btn.addEventListener("click", async () => {
                await loadStats(true);
                await loadTrends(currentTrendPeriod);
            });
        }

        document.querySelectorAll(".trendBtn").forEach(btn => {
            btn.addEventListener("click", () => {
                loadTrends(btn.dataset.period || "7d");
            });
        });

        loadStats(false);
        loadTrends(currentTrendPeriod);

        window.addEventListener("resize", () => {
            loadTrends(currentTrendPeriod);
        });
    });
})();
