(() => {
    "use strict";

    const $ = (id) => document.getElementById(id);

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

    let currentTrendPeriod = "7d";
    let latestSummary = null;
    let latestTrendPayload = null;

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

    function setInsight(id, value, mini, kind = "") {
        const valueEl = $(id);
        const miniEl = $(id + "Mini");

        if (valueEl) {
            valueEl.textContent = value;
            valueEl.classList.remove("good", "warn", "bad");
            if (kind) valueEl.classList.add(kind);
        }

        if (miniEl) miniEl.textContent = mini;
    }

    function signedBytes(delta) {
        const n = Number(delta || 0);
        const sign = n > 0 ? "+" : (n < 0 ? "−" : "");
        return sign + fmtBytes(Math.abs(n));
    }

    function signedNum(delta) {
        const n = Number(delta || 0);
        const sign = n > 0 ? "+" : (n < 0 ? "−" : "");
        return sign + fmtNum(Math.abs(n));
    }

    function daysBetween(first, last) {
        const a = Number(first?.t || 0);
        const b = Number(last?.t || 0);
        if (!Number.isFinite(a) || !Number.isFinite(b) || b <= a) return 0;
        return (b - a) / 86400.0;
    }

    function fmtDays(days) {
        if (!Number.isFinite(days) || days < 0) return "—";
        if (days < 1) return tr("admin.stats.less_than_day", null, "less than 1 day");
        if (days < 60) return tr("admin.stats.days", { count: Math.round(days) }, `${Math.round(days)} days`);
        if (days < 730) return tr("admin.stats.months", { count: Math.round(days / 30.4375) }, `${Math.round(days / 30.4375)} months`);
        return tr("admin.stats.years", { count: (days / 365.25).toFixed(1) }, `${(days / 365.25).toFixed(1)} years`);
    }

    function renderGrowthInsights() {
        const points = latestTrendPayload && Array.isArray(latestTrendPayload.points)
            ? latestTrendPayload.points
            : [];

        if (points.length < 2) {
            setInsight("insightStorageChange", "—", tr("admin.stats.need_2_samples", null, "Need at least 2 samples"));
            setInsight("insightFilesChange", "—", tr("admin.stats.need_2_samples", null, "Need at least 2 samples"));
            setInsight("insightGrowthPerDay", "—", tr("admin.stats.need_2_samples", null, "Need at least 2 samples"));
            setInsight("insightQuotaHorizon", "—", tr("admin.stats.need_more_trend", null, "Need more trend data"));
            return;
        }

        const first = points[0];
        const last = points[points.length - 1];
        const days = daysBetween(first, last);

        const firstBytes = Number(first.files_total_bytes || 0);
        const lastBytes = Number(last.files_total_bytes || 0);
        const deltaBytes = lastBytes - firstBytes;

        const firstFiles = Number(first.files_total_count || 0);
        const lastFiles = Number(last.files_total_count || 0);
        const deltaFiles = lastFiles - firstFiles;

        const byteKind = deltaBytes > 0 ? "warn" : (deltaBytes < 0 ? "good" : "");
        const fileKind = deltaFiles > 0 ? "warn" : (deltaFiles < 0 ? "good" : "");

        setInsight(
            "insightStorageChange",
            signedBytes(deltaBytes),
            `${fmtBytes(firstBytes)} → ${fmtBytes(lastBytes)}`,
            byteKind
        );

        setInsight(
            "insightFilesChange",
            signedNum(deltaFiles),
            tr("admin.stats.files_count", { count: `${fmtNum(firstFiles)} → ${fmtNum(lastFiles)}` }, `${fmtNum(firstFiles)} → ${fmtNum(lastFiles)} files`),
            fileKind
        );

        if (days > 0) {
            const perDay = deltaBytes / days;
            const perDayKind = perDay > 0 ? "warn" : (perDay < 0 ? "good" : "");
            setInsight(
                "insightGrowthPerDay",
                signedBytes(perDay),
                tr("admin.stats.based_on_points", { points: points.length, days: days.toFixed(days < 2 ? 1 : 0) }, `Based on ${points.length} points / ${days.toFixed(days < 2 ? 1 : 0)} days`),
                perDayKind
            );

            const usersQuota = Number(latestSummary?.users?.quota_bytes || 0);
            const workspacesQuota = Number(latestSummary?.workspaces?.quota_bytes || 0);
            const totalQuota = usersQuota + workspacesQuota;

            if (totalQuota > 0 && perDay > 0) {
                const remaining = totalQuota - lastBytes;
                if (remaining <= 0) {
                    setInsight(
                        "insightQuotaHorizon",
                        tr("admin.stats.over_quota", null, "over quota"),
                        tr("admin.stats.used_of_allocated", { used: fmtBytes(lastBytes), total: fmtBytes(totalQuota) }, `${fmtBytes(lastBytes)} used of ${fmtBytes(totalQuota)} allocated`),
                        "bad"
                    );
                } else {
                    const daysLeft = remaining / perDay;
                    setInsight(
                        "insightQuotaHorizon",
                        fmtDays(daysLeft),
                        tr("admin.stats.remaining_allocated", { remaining: fmtBytes(remaining) }, `${fmtBytes(remaining)} remaining of allocated quota`),
                        daysLeft < 30 ? "bad" : (daysLeft < 90 ? "warn" : "good")
                    );
                }
            } else if (totalQuota > 0) {
                setInsight(
                    "insightQuotaHorizon",
                    tr("admin.stats.stable", null, "stable"),
                    tr("admin.stats.used_of_allocated", { used: fmtBytes(lastBytes), total: fmtBytes(totalQuota) }, `${fmtBytes(lastBytes)} used of ${fmtBytes(totalQuota)} allocated`),
                    "good"
                );
            } else {
                setInsight("insightQuotaHorizon", "—", tr("admin.stats.no_allocated_quota", null, "No allocated quota total"));
            }
        } else {
            setInsight("insightGrowthPerDay", "—", tr("admin.stats.samples_too_close", null, "Samples too close together"));
            setInsight("insightQuotaHorizon", "—", tr("admin.stats.samples_too_close", null, "Samples too close together"));
        }
    }


    function rowsHtml(rows, nameKey, emptyText) {
        if (!Array.isArray(rows) || rows.length === 0) {
            return `<tr><td colspan="3">${esc(emptyText || tr("admin.stats.no_data", null, "No data"))}</td></tr>`;
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

    function trendBucketLabel(bucket) {
        const b = String(bucket || "raw");
        if (b === "hour") return tr("admin.stats.bucket.hour", null, "hour");
        if (b === "day") return tr("admin.stats.bucket.day", null, "day");
        return tr("admin.stats.bucket.raw", null, b);
    }

    function trendPointWord(count) {
        return Number(count) === 1
            ? tr("admin.stats.point_one", null, "point")
            : tr("admin.stats.point_many", null, "points");
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
            ctx.fillText(tr("admin.stats.no_trend_data", null, "No trend data yet"), padL, padT + 24);
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
            : tr("admin.stats.start", null, "start");
        const lastLabel = lastDate && !Number.isNaN(lastDate.getTime())
            ? lastDate.toLocaleDateString()
            : tr("admin.stats.now", null, "now");

        ctx.fillText(firstLabel, padL, cssH - 7);
        ctx.textAlign = "right";
        ctx.fillText(lastLabel, cssW - padR, cssH - 7);
    }

    function renderTrends(j) {
        latestTrendPayload = j;
        const points = Array.isArray(j.points) ? j.points : [];

        if (!points.length) {
            setTrendStatus(tr("admin.stats.no_samples", null, "No samples"));
            ["trendStorageValue", "trendFilesValue", "trendUsersValue", "trendWorkspacesValue"].forEach(id => setText(id, "—"));
            drawLineChart($("trendStorageCanvas"), [], p => p.files_total_bytes, fmtShortBytes);
            drawLineChart($("trendFilesCanvas"), [], p => p.files_total_count, fmtNum);
            drawLineChart($("trendUsersCanvas"), [], p => p.users_total, fmtNum);
            drawLineChart($("trendWorkspacesCanvas"), [], p => p.workspaces_total, fmtNum);
            renderGrowthInsights();
            return;
        }

        const last = points[points.length - 1] || {};
        setText("trendStorageValue", fmtBytes(last.files_total_bytes));
        setText("trendFilesValue", tr("admin.stats.files_count", { count: fmtNum(last.files_total_count) }, `${fmtNum(last.files_total_count)} files`));
        setText("trendUsersValue", tr("admin.stats.enabled_total", { enabled: fmtNum(last.users_enabled), total: fmtNum(last.users_total) }, `${fmtNum(last.users_enabled)} enabled / ${fmtNum(last.users_total)} total`));
        setText("trendWorkspacesValue", tr("admin.stats.enabled_total", { enabled: fmtNum(last.workspaces_enabled), total: fmtNum(last.workspaces_total) }, `${fmtNum(last.workspaces_enabled)} enabled / ${fmtNum(last.workspaces_total)} total`));

        drawLineChart($("trendStorageCanvas"), points, p => p.files_total_bytes, fmtShortBytes);
        drawLineChart($("trendFilesCanvas"), points, p => p.files_total_count, fmtNum);
        drawLineChart($("trendUsersCanvas"), points, p => p.users_total, fmtNum);
        drawLineChart($("trendWorkspacesCanvas"), points, p => p.workspaces_total, fmtNum);

        const bucket = j.bucket || "raw";
        setTrendStatus(tr(
            "admin.stats.trend_points",
            {
                count: fmtNum(points.length),
                pointWord: trendPointWord(points.length),
                bucket: trendBucketLabel(bucket)
            },
            `${fmtNum(points.length)} ${points.length === 1 ? "point" : "points"} · ${bucket}`
        ));

        renderGrowthInsights();
    }

    async function loadTrends(period = currentTrendPeriod) {
        currentTrendPeriod = period;
        activeTrendButton(period);

        const bucket = trendBucketForPeriod(period);
        const url = `/api/v4/admin/stats/trends?period=${encodeURIComponent(period)}&bucket=${encodeURIComponent(bucket)}`;

        setTrendStatus(tr("admin.stats.loading", null, "Loading…"));

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
            latestTrendPayload = { points: [] };

            ["trendStorageValue", "trendFilesValue", "trendUsersValue", "trendWorkspacesValue"].forEach(id => {
                setText(id, "—");
            });

            setInsight("insightStorageChange", "—", tr("admin.stats.trend_failed", null, "Trend request failed"));
            setInsight("insightFilesChange", "—", tr("admin.stats.trend_failed", null, "Trend request failed"));
            setInsight("insightGrowthPerDay", "—", tr("admin.stats.trend_failed", null, "Trend request failed"));
            setInsight("insightQuotaHorizon", "—", tr("admin.stats.trend_failed", null, "Trend request failed"));

            drawLineChart($("trendStorageCanvas"), [], p => p.files_total_bytes, fmtShortBytes);
            drawLineChart($("trendFilesCanvas"), [], p => p.files_total_count, fmtNum);
            drawLineChart($("trendUsersCanvas"), [], p => p.users_total, fmtNum);
            drawLineChart($("trendWorkspacesCanvas"), [], p => p.workspaces_total, fmtNum);

            setTrendStatus(tr("admin.stats.failed", { error: e.message || e }, `Failed: ${e.message || e}`));
        }
    }

    async function loadStats(force = false) {
        const url = force ? "/api/v4/admin/stats/summary?refresh=1" : "/api/v4/admin/stats/summary";
        const btn = $("refreshBtn");
        const status = $("status");

        if (btn) btn.disabled = true;
        if (status) status.textContent = force ? tr("admin.stats.scanning_live", null, "Scanning live storage…") : tr("admin.stats.loading_statistics", null, "Loading statistics…");

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

            latestSummary = j;

            const users = j.users || {};
            const workspaces = j.workspaces || {};
            const files = j.files || {};

            setText("cardUsers", fmtNum(users.total));
            setText(
                "cardUsersMini",
                tr("admin.stats.enabled_disabled_admin", { enabled: fmtNum(users.enabled), disabled: fmtNum(users.disabled), admins: fmtNum(users.admins) }, `${fmtNum(users.enabled)} enabled · ${fmtNum(users.disabled)} disabled · ${fmtNum(users.admins)} admin`)
            );

            setText("cardFiles", fmtNum(files.total_count));
            setText(
                "cardFilesMini",
                tr("admin.stats.roots_scanned", { scanned: fmtNum(files.scanned_roots), skipped: fmtNum(files.skipped_roots) }, `${fmtNum(files.scanned_roots)} roots scanned · ${fmtNum(files.skipped_roots)} skipped`)
            );

            setText("cardBytes", fmtBytes(files.total_bytes));
            setText("cardBytesMini", tr("admin.stats.largest_file", { size: fmtBytes(files.largest_bytes) }, `Largest file ${fmtBytes(files.largest_bytes)}`));

            setText("cardWorkspaces", fmtNum(workspaces.total));
            setText(
                "cardWorkspacesMini",
                tr("admin.stats.workspace_mini", { enabled: fmtNum(workspaces.enabled), userCreated: fmtNum(workspaces.user_created), avg: fmtBytes(files.average_bytes) }, `${fmtNum(workspaces.enabled)} enabled · ${fmtNum(workspaces.user_created)} user-created · avg file ${fmtBytes(files.average_bytes)}`)
            );

            $("mimeRows").innerHTML = rowsHtml(j.top_mime_types, "mime", tr("admin.stats.no_mime", null, "No MIME data"));
            $("extRows").innerHTML = rowsHtml(j.top_extensions, "extension", tr("admin.stats.no_extension", null, "No extension data"));
            $("scopeRows").innerHTML = rowsHtml(j.files_by_scope, "scope", tr("admin.stats.no_scope", null, "No scope data"));

            const warnings = Array.isArray(j.warnings) ? j.warnings : [];
            const warningHtml = warnings.length
                ? `<tr><th>${esc(tr("admin.stats.warnings", null, "Warnings"))}</th><td class="warn">${warnings.map(esc).join("<br>")}</td></tr>`
                : `<tr><th>${esc(tr("admin.stats.warnings", null, "Warnings"))}</th><td>${esc(tr("admin.stats.none", null, "None"))}</td></tr>`;

            $("detailRows").innerHTML = `
                <tr><th>${esc(tr("admin.stats.generated", null, "Generated"))}</th><td class="mono">${esc(j.generated_at_iso || "—")}</td></tr>
                <tr><th>${esc(tr("admin.stats.method", null, "Method"))}</th><td>${esc(j.method || "—")}</td></tr>
                <tr><th>${esc(tr("admin.stats.notes", null, "Notes"))}</th><td>${esc(j.note || "—")}</td></tr>
                ${warningHtml}
            `;

            if (status) {
                status.textContent = tr("admin.stats.updated_at", { time: j.generated_at_iso || tr("admin.stats.now", null, "now") }, `Updated ${j.generated_at_iso || "now"}`);
            }

            renderGrowthInsights();
        } catch (e) {
            if (status) status.textContent = tr("admin.stats.failed", { error: e.message || e }, `Failed: ${e.message || e}`);
            ["mimeRows", "extRows", "scopeRows"].forEach(id => {
                const el = $(id);
                if (el) el.innerHTML = `<tr><td colspan="3">${esc(tr("admin.stats.failed_load", null, "Failed to load statistics."))}</td></tr>`;
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

        applyStaticI18n();
        loadStats(false);
        loadTrends(currentTrendPeriod);

        window.addEventListener("pqnas-language-changed", () => {
            applyStaticI18n();
            renderGrowthInsights();
            if (latestTrendPayload) renderTrends(latestTrendPayload);
        });

        window.addEventListener("resize", () => {
            loadTrends(currentTrendPeriod);
        });
    });
})();
